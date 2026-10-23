"""Regression tests for bugs found in the 0.1.0 review: find, loaders, analysis, annotations, MCP and shell."""

import io
import json
from contextlib import redirect_stdout

import pytest

from assemsearch import api, database
from assemsearch.analysis import _track_x86, analyze, branch_target
from assemsearch.cfg import ControlFlow
from assemsearch.cli import Shell, find_all, main
from assemsearch.document import Document
from assemsearch.find import (Cancelled, FindContext, FindMode, SearchEngine,
                              build_section_search_range_from_address)
from assemsearch.hexregex import HexRegexError, compile_hex_regex
from assemsearch.loaders import load_file, load_raw, macho
from assemsearch.loaders.elf import name_plt_stubs
from assemsearch.mcp import MCPServer
from assemsearch.model import BasicBlock, DisassembledFile, Instruction, Procedure, Section, Segment
from assemsearch.objc import ObjCMetadata
from assemsearch.preferences import Preferences
from assemsearch.types import BAD_ADDRESS
from assemsearch.workspace import Workspace

from conftest import MACHO, raw_document


def _shell(arch="arm64") -> Shell:
    shell = Shell(Workspace(Preferences.in_memory()))
    shell.ws.open(MACHO, arch=arch)
    return shell


def _run(shell: Shell, line: str) -> str:
    out = io.StringIO()
    with redirect_stdout(out):
        shell.onecmd(line)
    return out.getvalue()


class TestFind:
    def test_find_all_reports_every_match_inside_one_string(self, arm_doc):
        text = "AsmSearchSecretKey"
        start = next(a for a, s in arm_doc.file.strings.items() if s == text)
        hits = find_all(arm_doc, FindContext.from_string("e", FindMode.ASCII_STRING, True, False))
        inside = [h.location for h in hits if start <= h.location < start + len(text)]
        assert inside == [start + i for i, ch in enumerate(text) if ch == "e"]

    def test_overlapping_byte_matches(self):
        doc = raw_document(b"\x00aaaa\x00")
        hits = find_all(doc, FindContext.from_string("aa", FindMode.ASCII_STRING, True, False))
        assert [h.location for h in hits] == [0x1001, 0x1002, 0x1003]

    @pytest.mark.parametrize("mode, text", [(FindMode.ASCII_STRING, "ABCD"), (FindMode.HEX_REGEXP, "4142..44")])
    def test_find_previous_finds_a_match_straddling_the_cursor(self, mode, text):
        doc = raw_document(b"\x00" * 16 + b"ABCD" + b"\x00" * 16)
        doc.cursor = 0x1012  # inside the match at 0x1010
        doc.set_find(text, mode, True, True)
        hit = doc.move_cursor_at_previous_occurrence()
        assert hit is not None and hit.location == 0x1010

    def test_regexp_search_checks_cancellation_even_without_candidates(self):
        doc = raw_document(b"\x00" * 100_003 + b"\xfe\x01")
        item = build_section_search_range_from_address(doc.file, 0x1000, False)[0]
        with pytest.raises(Cancelled):
            SearchEngine(doc.file)._search_regexp(item, compile_hex_regex("fe01"), False, lambda: True)

    def test_reversed_hex_regex_range_is_invalid(self):
        with pytest.raises(HexRegexError, match="invalid range"):
            compile_hex_regex("[0f-a]0")


class TestAnalysis:
    def test_raw_files_get_strings(self):
        doc = raw_document(b"\x90" * 32 + b"Hello, this is a long string\x00" + b"\x90" * 32, analyse=True)
        assert list(doc.file.strings.values()) == ["Hello, this is a long string"]
        assert 0x1000 + 32 not in doc.file.instructions  # the string is not disassembled
        assert 0x1000 + 32 + 29 in doc.file.instructions  # decoding resumes after it

    def test_arm32_bit_operations_are_not_branches(self):
        data = bytes.fromhex("0400c1e3") + bytes.fromhex("0000a0e1") * 3  # bic r0, r1, #4; nops
        doc = load_raw("arm.bin", data, "arm", 0)
        analyze(doc)
        assert branch_target("arm", doc.instructions[0]) is None
        assert doc.references_from(0) == []

    @pytest.mark.parametrize("mnemonic, size, expected", [
        ("cvtsd2ss", "qword", (8, True, False)), ("cvttsd2si", "qword", (8, True, False)),
        ("cvtss2sd", "dword", (4, True, False)), ("cvtsi2sd", "qword", (8, False, False)),
        ("movss", "dword", (4, True, False)), ("vcvtsd2ss", "qword", (8, True, False)),
    ])
    def test_x86_access_width_follows_the_memory_operand(self, x86, mnemonic, size, expected):
        start = x86.section_named("__text").start
        accesses = {}
        ins = Instruction(start, 8, mnemonic, f"xmm0, xmm1, {size} ptr [rip + 0x10]")
        _track_x86(x86, start, ins, False, {}, accesses)
        assert accesses[start + 8 + 0x10] == expected

    def test_elf_calls_to_noreturn_functions(self):
        doc = DisassembledFile("x", "x86_64", "ELF")
        doc.set_name(0x100, "imp___stubs_abort")
        doc.set_name(0x110, "__stack_chk_fail")
        doc.set_name(0x120, "puts")
        flow = ControlFlow(doc)
        assert flow.noreturn(0x100) and flow.noreturn(0x110) and not flow.noreturn(0x120)

    @pytest.mark.parametrize("plt, names", [(".plt", [(0x410, "abort"), (0x420, "puts")]),
                                            (".plt.sec", [(0x400, "abort"), (0x410, "puts")])])
    def test_elf_plt_stubs_are_named(self, plt, names):
        doc = DisassembledFile("x", "x86_64", "ELF")
        doc.add_segment(Segment("LOAD0", 0x400, 0x100, bytes(0x100), 0, executable=True))
        name_plt_stubs(doc, [{"sname": plt, "addr": 0x400, "size": 0x30}], ["abort", "puts"])
        assert [(a, n) for a, n in doc.names.items()] == [(a, f"imp___stubs_{n}") for a, n in names]

    def test_32bit_macho_symbol_pointers_use_4_byte_slots(self):
        doc = DisassembledFile("x", "x86", "Mach-O")
        segment = Segment("__DATA", 0x2000, 0x100, bytes(0x100), 0x1000)
        section = Section("__nl_symbol_ptr", 0x2000, 16, 0x1000, flags=macho.S_NON_LAZY_SYMBOL_POINTERS)
        section.reserved1, section.reserved2 = 0, 0
        segment.add_section(section)
        doc.add_segment(segment)
        table = b"".join(i.to_bytes(4, "little") for i in range(4))
        dysymtab = [0] * 18
        dysymtab[13] = 4
        macho._load_indirect_symbols(doc, table, dysymtab, ["_a", "_b", "_c", "_d"], [section], is64=False)
        assert [n for _, n in doc.names.items()] == ["_a_2000", "_b_2004", "_c_2008", "_d_200c"]

    def test_java_class_files_load_as_raw(self, tmp_path):
        path = tmp_path / "Main.class"
        path.write_bytes(bytes.fromhex("cafebabe00000034") + b"\x00" * 200)
        assert not macho.is_macho(path.read_bytes())
        assert load_file(path).file_type == "Raw"

    def test_objc_category_on_an_unresolved_class(self):
        image = bytearray(0x400)

        def pointer(offset, value):
            image[offset:offset + 8] = value.to_bytes(8, "little")

        pointer(0x000, 0x1200)  # category_t: name, cls = 0 (unresolved), instance methods
        pointer(0x010, 0x1100)
        image[0x100:0x108] = (24).to_bytes(4, "little") + (1).to_bytes(4, "little")  # method_list_t
        pointer(0x108, 0x1210)  # method_t: name, types, imp
        pointer(0x110, 0x1210)
        pointer(0x118, 0x1300)
        image[0x200:0x204], image[0x210:0x215] = b"Cat\0", b"doIt\0"
        doc = DisassembledFile("x", "arm64", "Mach-O")
        doc.add_segment(Segment("__DATA", 0x1000, 0x400, bytes(image), 0))
        doc.instructions.add(0x1300, 4, "ret", "")
        ObjCMetadata(doc).category(0x1000)
        assert doc.name_for_virtual_address(0x1300) == "-[?(Cat) doIt]"
        assert not any("None" in n for _, n in doc.names.items())

    def test_segments_record_writability(self, arm64):
        flags = {s.name: s.writable for s in arm64.segments}
        assert flags["__TEXT"] is False and flags["__LINKEDIT"] is False and flags["__DATA"] is True


class TestNavigation:
    def test_procedure_offset_stays_inside_a_non_contiguous_procedure(self):
        file = load_raw("m.bin", b"\x90" * 0x3000, "x86_64", 0x1000)
        analyze(file)
        file.procedures.clear()
        file.procedures[0x2000] = Procedure(0x2000, 0x2010, [BasicBlock(0x1800, 0x1810), BasicBlock(0x2000, 0x2010)])
        file.rebuild_object_index()
        doc = Document(file, Preferences.in_memory())
        doc.cursor = 0x2000
        assert not doc.goto_offset_in_procedure(0x18) and doc.cursor == 0x2000
        assert doc.goto_offset_in_procedure(0x8) and doc.cursor == 0x2008

    def test_segment_next_address_stays_in_the_segment(self, arm_doc):
        document = api.Document(arm_doc)
        text = document.getSegmentByName("__TEXT")
        end = text.getStartingAddress() + text.getLength() - 1
        assert text.getNextAddressWithType(end, api.TYPE_DATA) == BAD_ADDRESS


class TestDatabase:
    def test_database_of_another_build_is_not_restored(self, tmp_path):
        path = tmp_path / "target.bin"
        path.write_bytes(b"\x90" * 64)
        doc = Workspace(Preferences.in_memory()).open(path)
        doc.file.set_comment(0x10, "decrypts the license key")
        database.save(doc.file)
        path.write_bytes(b"\xcc" * 32 + b"a different build" + b"\x00" * 64)
        reopened = Workspace(Preferences.in_memory()).open(path)
        assert reopened.file.comment_at_virtual_address(0x10) is None
        assert "different version" in reopened.database_warning

    def test_database_without_digest_is_still_restored(self, tmp_path):
        path = tmp_path / "target.bin"
        path.write_bytes(b"\x90" * 64)
        (tmp_path / "target.bin.asdb").write_text(json.dumps({"version": 1, "comments": {"10": "old format"},
                                                              "tags": {"": ["10"], "keep": ["10"]}}))
        doc = Workspace(Preferences.in_memory()).open(path)
        assert doc.file.comment_at_virtual_address(0x10) == "old format"
        assert doc.file.all_tags() == ["keep"]


class TestPreferences:
    @pytest.mark.parametrize("stored", ["[]", '"text"', json.dumps({"last_find_mode": 9}),
                                        json.dumps({"enable_fuzzy_search": "yes", "last_find_number_length": 12})])
    def test_invalid_preferences_fall_back_to_defaults(self, tmp_path, stored):
        path = tmp_path / "prefs.json"
        path.write_text(stored)
        assert Preferences.load(path) == Preferences()

    def test_valid_preferences_are_kept(self, tmp_path):
        path = tmp_path / "prefs.json"
        path.write_text(json.dumps({"last_find_mode": 3, "enable_fuzzy_search": False,
                                    "recent_searches": {"f": ["a"]}}))
        prefs = Preferences.load(path)
        assert (prefs.last_find_mode, prefs.enable_fuzzy_search, prefs.recent_searches) == (3, False, {"f": ["a"]})


class TestMCP:
    @pytest.fixture
    def server(self):
        server = MCPServer(Workspace(Preferences.in_memory()))
        server.workspace.open(MACHO, arch="arm64")
        return server

    def test_list_segments_reports_real_writability(self, server):
        segments = json.loads(server.call_tool("list_segments", {})["content"][0]["text"])
        assert {s["name"]: s["writable"] for s in segments}["__LINKEDIT"] is False

    @pytest.mark.parametrize("arguments, message", [({"address": 4096}, "address must be a string"),
                                                     ({"nope": "x"}, "unknown nope"), ({}, "missing address")])
    def test_bad_arguments_are_tool_errors(self, server, arguments, message):
        result = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                "params": {"name": "goto_address", "arguments": arguments}})["result"]
        assert result["isError"] and message in result["content"][0]["text"]

    def test_internal_errors_are_not_blamed_on_the_arguments(self, server):
        description, schema, _ = server.tools["list_strings"]
        server.tools["list_strings"] = (description, schema, lambda document=None: sorted([1, "a"]))
        result = server.call_tool("list_strings", {})
        assert result["isError"] and result["content"][0]["text"].startswith("Internal error: TypeError")


class TestShell:
    def test_tag_needs_a_name_and_removed_tags_disappear(self):
        shell = _shell()
        assert "usage" in _run(shell, "tag")
        _run(shell, "tag foo")
        _run(shell, "tag -foo")
        assert shell.doc.file.all_tags() == ["entrypoint"]

    def test_palette_keeps_a_bang_that_is_not_a_pick(self):
        shell = _shell()
        assert _run(shell, "palette Next!x").startswith("Commands: 0 results")
        assert _run(shell, "palette Next").startswith("Commands: 7 results")

    def test_refsto_rejects_an_unknown_address(self):
        assert "invalid address" in _run(_shell(), "refsto no_such_symbol")

    def test_xrefs_command_fails_on_an_unknown_address(self, capsys):
        assert main(["xrefs", str(MACHO), "no_such_symbol"]) == 1
        assert "invalid address" in capsys.readouterr().err

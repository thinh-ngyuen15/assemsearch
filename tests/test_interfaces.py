"""Loaders, MCP server, scripting API, CLI."""

import io
import json

import pytest

from assemsearch import cli
from assemsearch.api import TYPE_PROCEDURE, Document
from assemsearch.loaders import load_file
from assemsearch.mcp import MCPServer
from assemsearch.preferences import Preferences
from assemsearch.workspace import Workspace

from conftest import ELF, MACHO, OBJC


class TestLoaders:
    def test_macho_slices(self, arm64, x86):
        for doc, cpu in ((arm64, "arm64"), (x86, "x86_64")):
            assert doc.cpu == cpu and doc.file_type == "Mach-O"
            assert doc.entry_point == doc.find_virtual_address_named("_main")
            assert set(doc.strings.values()) >= {"AsmSearchSecretKey", "Invalid license", "Welcome to the sample binary"}
            assert {i.name for i in doc.imports} == {"_printf", "_puts", "_strcmp"}
        assert arm64.container_file_offset != x86.container_file_offset

    def test_elf_object(self):
        doc = load_file(ELF)
        assert doc.file_type == "ELF" and doc.cpu == "x86_64"
        assert {"main", "validate_license", "compute_checksum", "secret_key"} <= set(doc.all_names())
        assert "Invalid license" in doc.strings.values()
        assert {"main", "print_banner"} <= {doc.name_for_virtual_address(p.entry) for p in doc.procedure_list()}

    def test_raw(self, tmp_path):
        path = tmp_path / "blob.bin"
        path.write_bytes(b"\x90" * 8 + b"hello world\x00")
        doc = load_file(path, raw=True, base=0x4000)
        assert doc.file_type == "Raw" and doc.min_address == 0x4000


@pytest.fixture
def server():
    workspace = Workspace(Preferences.in_memory())
    workspace.open(MACHO, arch="arm64", restore=False)
    workspace.open(ELF, restore=False)
    workspace.current = workspace.documents[0]
    return MCPServer(workspace)


def call(server, tool, **arguments):
    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": tool, "arguments": arguments}})
    result = response["result"]
    text = result["content"][0]["text"]
    if result.get("isError"):
        return ("error", text)
    try:
        return json.loads(text)
    except ValueError:
        return text


class TestMCP:
    def test_handshake_over_stdio(self, server):
        requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                    {"jsonrpc": "2.0", "method": "notifications/initialized"},
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        out = io.StringIO()
        server.serve(io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n"), out)
        responses = [json.loads(line) for line in out.getvalue().splitlines()]
        assert len(responses) == 2
        assert responses[0]["result"]["protocolVersion"] == "2025-03-26"
        assert responses[0]["result"]["serverInfo"]["name"] == "assemsearch"
        tools = {t["name"] for t in responses[1]["result"]["tools"]}
        assert {"search_strings", "search_procedures", "search_name", "xrefs", "list_bookmarks",
                "procedure_address", "goto_address"} <= tools

    def test_batches_and_invalid_messages(self, server):
        batch = [{"jsonrpc": "2.0", "id": 1, "method": "ping"},
                 {"jsonrpc": "2.0", "method": "notifications/initialized"},
                 "junk",
                 {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                  "params": {"name": "current_document", "arguments": {}}}]
        lines = [json.dumps(batch), json.dumps([{"jsonrpc": "2.0", "method": "notifications/initialized"}]),
                 "[]", '"hello"', json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"})]
        out = io.StringIO()
        server.serve(io.StringIO("\n".join(lines) + "\n"), out)
        replies, empty, scalar, last = [json.loads(line) for line in out.getvalue().splitlines()]
        assert [r["id"] for r in replies] == [1, None, 2]  # nothing for the notification-only batch
        assert replies[1]["error"]["code"] == -32600 and replies[2]["result"]["content"][0]["text"] == "sample_macho"
        assert empty["error"]["code"] == scalar["error"]["code"] == -32600
        assert last == {"jsonrpc": "2.0", "id": 3, "result": {}}  # still serving

    def test_regex_searches(self, server):
        assert list(call(server, "search_strings", pattern="licen[cs]e").values()) == ["License OK: %u\n", "Invalid license"]
        assert list(call(server, "search_strings", pattern="^Invalid", case_sensitive=True).values()) == ["Invalid license"]
        assert call(server, "search_strings", pattern="^invalid", case_sensitive=True) == {}
        assert sorted(call(server, "search_procedures", pattern="^_[cv]").values()) == ["_compute_checksum", "_validate_license"]
        assert list(call(server, "search_name", pattern="secret").values()) == ["_secret_key"]
        assert call(server, "search_name", pattern="main", document="sample_elf.o") == {"0x90": "main"}

    def test_errors(self, server):
        assert call(server, "search_name", pattern="(") == ("error", "Invalid regular expression provided")
        assert call(server, "search_name", pattern="x", document="nope") == ("error", "Document not found.")

    def test_procedure_lookups(self, server):
        main = call(server, "procedure_address", procedure="_main")
        inside = hex(int(main, 16) + 8)
        assert call(server, "procedure_address", procedure=inside) == main
        info = call(server, "procedure_info", procedure="_main")
        assert info["name"] == "_main" and info["basicblock_count"] > 1
        assert sorted(call(server, "procedure_callers", procedure="imp___stubs__strcmp")) == ["_main", "_validate_license"]
        assert "b imp___stubs__puts" in call(server, "procedure_assembly", procedure="_print_banner")  # tail call

    def test_navigation_and_annotations(self, server):
        call(server, "goto_address", address="_print_banner")
        assert call(server, "current_procedure") == "_print_banner"
        call(server, "set_comment", comment="prints the banner")
        assert call(server, "comment") == "prints the banner"
        call(server, "set_bookmark", name="banner")
        assert list(call(server, "list_bookmarks").values()) == ["banner"]
        call(server, "unset_bookmark")
        assert call(server, "list_bookmarks") == {}
        call(server, "set_address_name", address="_print_banner", name="show_banner")
        assert call(server, "address_name") == "show_banner"
        assert call(server, "set_current_document", document="sample_elf.o") == "OK"
        assert call(server, "current_document") == "sample_elf.o"

    def test_xrefs(self, server):
        assert len(call(server, "xrefs", address="imp___stubs__puts")) == 3  # two calls and one tail call


class TestScriptingAPI:
    def test_api_style_lookups(self):
        doc = Document.open(str(MACHO), arch="arm64")
        main = doc.getAddressForName("_main")
        assert doc.getNameAtAddress(main) == "_main"
        assert doc.getCurrentAddress() == main
        segment = doc.getSegmentAtAddress(main)
        assert segment.getName() == "__TEXT"
        strings = dict(segment.getStringsList())
        assert "Invalid license" in strings
        assert segment.getNextAddressWithType(main, TYPE_PROCEDURE) == main
        assert doc.getAddressFromFileOffset(doc.getFileOffsetFromAddress(main)) == main
        assert doc.getProcedureAtAddress(main + 4).getEntryPoint() == main
        assert doc.getSectionByName("__cstring").getName() == "__cstring"
        doc.setBookmarkAtAddress(main, "here")
        assert doc.findBookmarkWithName("here") == [main]
        tag = doc.getTagWithName("entrypoint")
        assert doc.hasTagAtAddress(tag, main) and doc.getCurrentProcedure().hasTag(tag)
        assert len(doc.getReferencesOfAddress(doc.getAddressForName("_banner"))) == 2


def test_api_saves_and_restores_annotations(tmp_path):
    binary = tmp_path / "sample"
    binary.write_bytes(MACHO.read_bytes())
    doc = Document.open(str(binary), arch="arm64")
    main = doc.getAddressForName("_main")
    doc.setCommentAtAddress(main, "start")
    assert doc.saveDatabase() == str(binary) + ".asdb"
    assert Document.open(str(binary), arch="arm64").getCommentAtAddress(main) == "start"
    assert Document.open(str(binary), arch="arm64", restore=False).getCommentAtAddress(main) is None


class TestCLI:
    def test_find_symbols_goto(self, capsys):
        assert cli.main(["find", str(MACHO), "--arch", "arm64", "--mode", "ascii", "invalid LICENSE"]) == 0
        assert len(capsys.readouterr().out.splitlines()) == 1
        assert cli.main(["symbols", str(MACHO), "--mode", "proc", "chk"]) == 0
        assert "_compute_checksum" in capsys.readouterr().out
        assert cli.main(["goto", str(MACHO), "_main"]) == 0
        assert "_main" in capsys.readouterr().out
        assert cli.main(["find", str(MACHO), "--mode", "hex", "zz"]) == 1

    def test_find_lists_every_match_unless_limited(self, capsys):
        assert cli.main(["find", str(MACHO), "--arch", "arm64", "--mode", "hex", "00"]) == 0
        total = len(capsys.readouterr().out.splitlines())
        assert total > 200  # no hidden cap
        assert cli.main(["find", str(MACHO), "--arch", "arm64", "--mode", "hex", "00", "--limit", "5"]) == 0
        assert len(capsys.readouterr().out.splitlines()) == 5
        assert cli.main(["open", str(MACHO), "--arch", "arm64", "-c", "find --all --limit 3 --mode hex 00"]) == 0
        assert "stopped after 3 matches" in capsys.readouterr().out

    def test_shell_script(self, capsys):
        assert cli.main(["open", str(MACHO), "-j", "zz", "-c", "goto _main", "-c", "find --mode asm --all bl",
                         "-c", "symbols proc lic", "-c", "palette @valid"]) == 0
        out = capsys.readouterr()
        assert "invalid --jump-to" in out.err
        assert "_validate_license" in out.out and "String in Assembly" in out.out

    def test_find_options_can_be_switched_back(self, capsys):
        workspace = Workspace(Preferences.in_memory())
        workspace.open(MACHO, arch="arm64", restore=False)
        shell = cli.Shell(workspace)
        shell.onecmd("find --mode number --case --nowrap --big 42")
        prefs = workspace.prefs
        assert prefs.last_find_case_sensitive and not prefs.last_find_wrapping
        assert not prefs.last_find_number_little_endian
        shell.onecmd("find 42")  # options left out keep their last value
        assert prefs.last_find_case_sensitive and not prefs.last_find_wrapping
        shell.onecmd("find --nocase --wrap --little 42")
        assert not prefs.last_find_case_sensitive and prefs.last_find_wrapping
        assert prefs.last_find_number_little_endian

    def test_shell_keeps_backslashes(self, capsys):
        assert cli._split(r"--regex 'bl\s+\w+' x\d #0x2a") == ["--regex", r"bl\s+\w+", r"x\d", "#0x2a"]
        assert cli.main(["open", str(MACHO), "--arch", "arm64", "-c", r"textfind --regex bl\s+\w+"]) == 0
        assert "4 matches" in capsys.readouterr().out

    def test_shell_survives_errors(self, capsys):
        mistakes = ["find", "find --mode bogus x", "open /nonexistent/file", "goto [99]", "bookmarks rename",
                    "textfind --regex (", "save /nonexistent/dir/db.asdb"]
        assert cli.main(["open", str(MACHO), *(a for m in mistakes for a in ("-c", m)), "-c", "docs"]) == 0
        out = capsys.readouterr().out
        assert out.count("error:") == len(mistakes) and "[0] sample_macho" in out  # `docs` still ran

    def test_ctrl_c_interrupts_the_command_not_the_shell(self, monkeypatch, capsys):
        workspace = Workspace(Preferences.in_memory())
        workspace.open(MACHO, arch="arm64", restore=False)
        shell = cli.Shell(workspace)

        def interrupt(*args):
            raise KeyboardInterrupt

        monkeypatch.setattr(workspace.current, "move_cursor_at_next_occurrence", interrupt)
        assert shell.onecmd("n") is False
        lines = iter([None, "quit"])  # Ctrl-C at the prompt, then quit

        def read_line(prompt=""):
            line = next(lines)
            if line is None:
                raise KeyboardInterrupt
            return line

        monkeypatch.setattr("builtins.input", read_line)
        shell.cmdloop()
        out = capsys.readouterr().out
        assert "interrupted" in out and "^C" in out

    def test_missing_binary_is_an_error_message(self, capsys):
        assert cli.main(["symbols", "/nonexistent/binary"]) == 1
        assert "No such file" in capsys.readouterr().err

    def test_export(self, capsys, tmp_path):
        out = tmp_path / "proc.txt"
        assert cli.main(["export", str(MACHO), str(out), "--procedure", "_compute_checksum"]) == 0
        assert "_compute_checksum:" in out.read_text() and "wrote" in capsys.readouterr().out
        assert cli.main(["export", str(MACHO), str(tmp_path / "no" / "dir.txt")]) == 1
        shell_out = tmp_path / "shell.txt"
        assert cli.main(["open", str(MACHO), "-c", f"export {shell_out}", "-c", "export --procedure --selection x"]) == 0
        assert "; Segment __TEXT" in shell_out.read_text()
        assert "not allowed with argument" in capsys.readouterr().out

    def test_objective_c_method_references_command(self, capsys):
        assert cli.main(["open", str(OBJC), "-c", "goto -[Counter scaled:]", "-c", "objcrefs"]) == 0
        assert "References to scaled: (2/2)" in capsys.readouterr().out

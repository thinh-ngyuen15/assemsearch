"""Go To, XREFs, structural navigation, bookmarks."""

import pytest

from assemsearch import database
from assemsearch.document import Document
from assemsearch.find import FindMode
from assemsearch.goto import GotoError, GotoType, parse_address_string, parse_offset_number
from assemsearch.loaders import load_file
from assemsearch.model import DisassembledFile, Section, Segment
from assemsearch.preferences import Preferences
from assemsearch.types import BAD_ADDRESS, AddressRange, ByteType

from conftest import CFG, MACHO, OBJC


class TestGoto:
    def test_resolution_order(self, arm64):
        main = arm64.find_virtual_address_named("_main")
        assert parse_address_string(arm64, "_main") == main
        assert parse_address_string(arm64, "$_main") == main
        assert parse_address_string(arm64, f"{main:x}") == main
        assert parse_address_string(arm64, f"0x{main:X}") == main
        assert parse_address_string(arm64, "nothing") == BAD_ADDRESS
        assert parse_address_string(arm64, "10") == BAD_ADDRESS  # neither 0x10 nor 10 is mapped

    def test_name_wins_over_hex(self, arm64):
        arm64.set_name(arm64.find_virtual_address_named("_main"), "add")  # "add" is also valid hex
        assert parse_address_string(arm64, "add") == arm64.find_virtual_address_named("add")

    def test_decimal_fallback(self, arm64):
        main = arm64.find_virtual_address_named("_main")
        assert parse_address_string(arm64, str(main)) == main  # hex reading is unmapped

    def test_offset_number_parsing(self):
        assert parse_offset_number("0x10") == 16
        assert parse_offset_number("1f") == 31
        assert parse_offset_number("100") == 100
        with pytest.raises(GotoError, match="Invalid number."):
            parse_offset_number("0xzz")

    def test_file_offset_modes(self, arm_doc):
        text = arm_doc.file.section_named("__text")
        assert arm_doc.goto(hex(text.file_offset + 8), GotoType.FILE_OFFSET)
        assert arm_doc.cursor == text.start + 8
        global_offset = arm_doc.file.container_file_offset + text.file_offset
        assert arm_doc.goto(hex(global_offset), GotoType.GLOBAL_FILE_OFFSET)
        assert arm_doc.cursor == text.start
        assert arm_doc.prefs.last_goto_file_offset_mode == GotoType.GLOBAL_FILE_OFFSET
        with pytest.raises(GotoError, match="No addresses match this file offset."):
            arm_doc.goto("0x7fffffff", GotoType.FILE_OFFSET)

    def test_file_offset_outside_every_section(self, arm_doc):
        text = arm_doc.file.segment_named("__TEXT")  # offset 0 is the Mach-O header, before __text
        assert arm_doc.goto("0", GotoType.FILE_OFFSET) and arm_doc.cursor == text.start
        assert arm_doc.file.file_offset_for_virtual_address(text.start) == 0

    def test_back_and_forward(self, arm_doc):
        start = arm_doc.cursor
        assert arm_doc.goto("_compute_checksum")
        assert arm_doc.goto("_print_banner")
        assert arm_doc.go_back() and arm_doc.cursor == arm_doc.file.find_virtual_address_named("_compute_checksum")
        assert arm_doc.go_back() and arm_doc.cursor == start
        assert not arm_doc.go_back() and arm_doc.last_beep == "navigation stack is empty"
        assert arm_doc.go_forward() and arm_doc.cursor == arm_doc.file.find_virtual_address_named("_compute_checksum")

    def test_invalid_goto_beeps(self, arm_doc):
        assert not arm_doc.goto("not_a_symbol")
        assert arm_doc.last_beep == "invalid address"

    def test_procedure_offset_and_top(self, arm_doc):
        main = arm_doc.file.find_virtual_address_named("_main")
        assert arm_doc.goto_offset_in_procedure(8) and arm_doc.cursor == main + 8
        assert not arm_doc.goto_offset_in_procedure(0x10000)
        assert arm_doc.goto_top_of_procedure() and arm_doc.cursor == main

    def test_follow_address(self, arm_doc):
        main = arm_doc.file.find_virtual_address_named("_main")
        call = next(a for a in sorted(arm_doc.file.instructions) if a > main
                    and arm_doc.file.instructions[a].mnemonic == "bl")
        arm_doc.move_cursor_to_virtual_address(call)
        target = arm_doc.file.references_from(call)[0]
        assert arm_doc.follow_address() and arm_doc.cursor == target


class TestXrefs:
    def test_references_to_string(self, arm64, x86):
        for doc in (arm64, x86):
            banner = doc.find_virtual_address_named("_banner")
            callers = {doc.procedure_at(r).entry for r in doc.references_to(banner)}
            assert callers == {doc.find_virtual_address_named("_print_banner"), doc.find_virtual_address_named("_main")}

    def test_callers_and_callees(self, arm64):
        main = arm64.procedures[arm64.find_virtual_address_named("_main")]
        names = {arm64.name_for_virtual_address(a) for a in main.callees}
        assert names == {"imp___stubs__puts", "imp___stubs__printf", "imp___stubs__strcmp"}
        strcmp = arm64.procedures[arm64.find_virtual_address_named("imp___stubs__strcmp")]
        assert {arm64.name_for_virtual_address(a) for a in strcmp.callers} == {"_main", "_validate_license"}

    def test_next_and_previous_xref(self, arm_doc):
        puts = arm_doc.file.find_virtual_address_named("imp___stubs__puts")
        refs = arm_doc.file.references_to(puts)
        assert len(refs) == 3  # _print_banner tail-calls puts, _main calls it twice
        arm_doc.move_cursor_to_virtual_address(refs[0])
        assert arm_doc.move_to_next_xref() and arm_doc.cursor == refs[1]
        assert arm_doc.move_to_next_xref() and arm_doc.cursor == refs[2]
        assert arm_doc.move_to_next_xref() and arm_doc.cursor == refs[0]  # wraps
        assert arm_doc.move_to_next_xref(backwards=True) and arm_doc.cursor == refs[2]

    def test_reference_lists_are_filterable(self, arm_doc):
        arm_doc.goto("imp___stubs__strcmp")
        callers = arm_doc.show_places_calling_this_procedure()
        assert [r["comment"].split(" (in ")[1] for r in callers.update_search("")] == ["_validate_license)", "_main)"]
        assert [r["comment"].split("+")[0] for r in callers.update_search("vldt")] == ["_validate_license"]
        assert callers.update_search("zzz") == []
        arm_doc.move_cursor_to_virtual_address(arm_doc.file.references_to(arm_doc.file.find_virtual_address_named("_banner"))[0])
        refs = arm_doc.show_references_to_here()
        assert refs.label.startswith("References to 0x") and len(refs.rows) == 2

    @pytest.mark.parametrize("arch", ["arm64", "x86_64"])
    def test_metadata_names(self, arch):
        doc = load_file(OBJC.with_name("sample_objc_stripped"), arch=arch)  # like BetterDisplay: no local symbols
        names = set(doc.all_names())
        assert {"__objc_class_Counter_data", "__objc_class_Counter_methods", "__objc_metaclass_Counter_data",
                "-[Counter scaled:]", "aScaled"} <= names
        assert "_OBJC_CLASS_$_Counter" in names  # an exported symbol wins over the generated label
        external = doc.segment_named("External Symbols")
        assert doc.find_virtual_address_named("_objc_msgSend") in range(external.start, external.end)
        got = [n for n in names if n.startswith("_objc_msgSend_")]  # GOT slot: "<symbol>_<address>"
        assert got and int(got[0].rsplit("_", 1)[1], 16) == doc.find_virtual_address_named(got[0])
        if arch == "arm64":  # one procedure per objc_msgSend stub, plus each brk padding
            stubs = doc.section_named("__objc_stubs")
            assert sum(1 for p in doc.procedures if stubs.contains(p)) == 4 * (stubs.length // 32)

    @pytest.mark.parametrize("arch, places", [("arm64", 2), ("x86_64", 1)])
    def test_places_referencing_objective_c_method(self, arch, places):
        # arm64 calls the objc_msgSend$scaled: stub twice; x86_64 loads the selector once.
        doc = Document(load_file(OBJC, arch=arch), Preferences.in_memory())
        selector = next(a for a, s in doc.file.strings.items() if s == "scaled:")
        assert "__objc_selrefs" in {doc.file.section_at_virtual_address(r).name for r in doc.file.references_to(selector)}
        doc.goto("-[Counter scaled:]")
        found = doc.show_references_to_objective_c_method()
        main = doc.file.find_virtual_address_named("_main")
        assert found.label == "References to scaled:" and len(found.rows) == places
        assert {doc.file.procedure_at(r["address"]).entry for r in found.rows} == {main}
        doc.goto("_main")
        assert doc.show_references_to_objective_c_method() is None and doc.last_beep == "not an Objective-C method"


class TestStructuralNavigation:
    def test_next_procedure_code_data(self, arm_doc):
        doc = arm_doc
        doc.goto("_compute_checksum")
        assert doc.next_procedure() and doc.cursor == doc.file.find_virtual_address_named("_validate_license")
        assert doc.next_data() and doc.file.type_for_virtual_address(doc.cursor) == ByteType.ASCII
        doc.move_cursor_to_virtual_address(doc.file.min_address)
        assert doc.next_code() and doc.cursor == min(doc.file.instructions)

    def test_type_search_primitive(self, arm_doc):
        doc = arm_doc
        main = doc.file.find_virtual_address_named("_main")
        assert doc.find_next_address_of_type(main, ByteType.PROCEDURE) == main  # inclusive
        last = max(doc.file.procedures)
        assert doc.find_next_address_of_type(last + 1, ByteType.PROCEDURE) == BAD_ADDRESS
        assert doc.find_next_address_of_type(last + 1, ByteType.PROCEDURE, wrapping=True) == min(doc.file.procedures)

    def test_sections_and_unexplored(self, arm_doc):
        doc = arm_doc
        text = doc.file.section_named("__text")
        doc.move_cursor_to_virtual_address(text.start)
        assert doc.next_section() and doc.cursor == doc.file.section_named("__stubs").start
        assert doc.previous_section() and doc.cursor == text.start
        assert doc.next_unexplored()
        assert doc.file.type_for_virtual_address(doc.cursor) == ByteType.UNDEFINED


class TestControlFlow:
    """Procedures are built by following control flow (cfg.py)."""

    @pytest.mark.parametrize("arch", ["arm64", "x86_64"])
    def test_jump_table_cases_belong_to_the_procedure(self, arch):
        doc = load_file(CFG, arch=arch)
        dispatch = doc.procedures[doc.find_virtual_address_named("_dispatch")]
        assert len(dispatch.basic_blocks) >= 8  # entry, dispatch, six cases (some may share), default
        for block in dispatch.basic_blocks:
            assert doc.procedure_at(block.start) is dispatch
        assert doc.name_for_virtual_address(next(iter(dispatch.callees))) == "imp___stubs__puts"
        assert dispatch.length == sum(b.end - b.start for b in dispatch.basic_blocks)

    @pytest.mark.parametrize("arch", ["arm64", "x86_64"])
    def test_call_to_abort_ends_the_block(self, arch):
        doc = load_file(CFG, arch=arch)
        checked = doc.procedures[doc.find_virtual_address_named("_checked")]
        abort = doc.find_virtual_address_named("imp___stubs__abort")
        calls = [i for b in checked.basic_blocks for i in doc.instructions.between(b.start, b.end)
                 if abort in doc.references_from(i.address)]
        assert len(calls) == 1  # the call is in the procedure, and nothing after it is
        assert max(b.end for b in checked.basic_blocks) == calls[0].address + calls[0].size

    @pytest.mark.parametrize("fixture", [MACHO, OBJC, CFG])
    @pytest.mark.parametrize("arch", ["arm64", "x86_64"])
    def test_every_compiler_listed_function_is_a_procedure(self, fixture, arch):
        from assemsearch.loaders.macho import _unwind_function_starts
        doc = load_file(fixture, arch=arch)
        listed = {a for a in doc.function_starts if a in doc.instructions}
        assert listed and listed <= set(doc.procedures)
        assert _unwind_function_starts(doc, doc.segment_named("__TEXT").start) <= doc.function_starts

    def test_arm32_calls_and_returns(self):
        from assemsearch.analysis import analyze
        from assemsearch.loaders import load_raw
        # f1: mov r0, #1; bx lr     f2: push {lr}; bl f1; pop {pc}
        doc = load_raw("arm.bin", bytes.fromhex("0100a0e3 1eff2fe1 04e02de5 fbffffeb 04f09de4"), "arm", 0x1000)
        doc.function_starts |= {0x1000, 0x1008}
        analyze(doc)
        assert doc.procedures[0x1000].end == 0x1008 and doc.procedures[0x1008].end == 0x1014
        assert doc.procedures[0x1008].callees == {0x1000} and doc.procedures[0x1000].callers == {0x1008}

    def test_comment_search_only_visits_comments(self, arm_doc):
        main = arm_doc.file.find_virtual_address_named("_main")
        arm_doc.file.set_inline_comment(main + 4, "needle here")
        arm_doc.file.set_comment(arm_doc.file.find_virtual_address_named("_print_banner"), "another needle")
        arm_doc.move_cursor_to_virtual_address(main)
        arm_doc.set_find("NEEDLE", FindMode.STRING_IN_COMMENTS)
        first = arm_doc.move_cursor_at_next_occurrence()
        second = arm_doc.move_cursor_at_next_occurrence()
        assert {first.location, second.location} == {main + 4, arm_doc.file.find_virtual_address_named("_print_banner")}
        assert arm_doc.move_cursor_at_previous_occurrence().location == first.location

    def test_noreturn_names(self):
        from assemsearch.cfg import ControlFlow
        doc = load_file(CFG, arch="arm64")
        flow = ControlFlow(doc)
        assert flow.noreturn(doc.find_virtual_address_named("imp___stubs__abort"))
        assert not flow.noreturn(doc.find_virtual_address_named("imp___stubs__puts"))


class TestTextExport:
    def test_whole_file(self, arm_doc, tmp_path):
        out = tmp_path / "all.txt"
        count = arm_doc.produce_text_file(out)
        text = out.read_text()
        assert count == len(text.splitlines())
        assert "; Segment __TEXT" in text and "; Section __cstring" in text
        assert "_main:" in text and "bl imp___stubs__strcmp" in text and '"Invalid license' in text

    def test_current_procedure_and_selection(self, arm_doc, tmp_path):
        arm_doc.goto("_print_banner")
        assert arm_doc.produce_text_file_for_current_procedure(tmp_path / "proc.txt")
        text = (tmp_path / "proc.txt").read_text()
        assert "_print_banner:" in text and "_main:" not in text and "b imp___stubs__puts" in text
        assert arm_doc.produce_text_file_for_current_selection(tmp_path / "sel.txt") is None
        assert arm_doc.last_beep == "no selection"
        main = arm_doc.file.find_virtual_address_named("_main")
        arm_doc.move_cursor_to_virtual_address_range(AddressRange(main, 8))
        assert arm_doc.produce_text_file_for_current_selection(tmp_path / "sel.txt")
        assert len([l for l in (tmp_path / "sel.txt").read_text().splitlines() if l.startswith("0000")]) == 2

    def test_no_procedure_beeps(self, arm_doc, tmp_path):
        arm_doc.move_cursor_to_virtual_address(arm_doc.file.section_named("__cstring").start)
        assert arm_doc.produce_text_file_for_current_procedure(tmp_path / "x.txt") is None

    def test_zero_fill_sections_are_summarised(self, tmp_path):
        doc = DisassembledFile("mem.bin", "x86_64", "Mach-O")
        segment = Segment("__DATA", 0x1000, 0x100000, b"", 0)
        segment.add_section(Section("__bss", 0x1000, 0x100000, None))
        doc.add_segment(segment)
        doc.rebuild_object_index()
        Document(doc, Preferences.in_memory()).produce_text_file(tmp_path / "bss.txt")
        assert "; zero-fill, 1048576 bytes" in (tmp_path / "bss.txt").read_text()


class TestBookmarks:
    def test_toggle_find_and_jump(self, arm_doc):
        doc = arm_doc
        assert doc.bookmarks_menu() == ["No bookmarks"]
        doc.goto("_main")
        assert doc.toggle_bookmark("check")
        doc.goto("_print_banner")
        assert doc.toggle_bookmark("check")
        found = doc.file.find_bookmarks_named("check")
        assert [b.address for b in found] == sorted(b.address for b in found) and len(found) == 2
        assert doc.file.find_bookmarks_named("Check") == []  # exact and case-sensitive
        assert doc.file.find_bookmarks_named("chec") == []
        assert doc.bookmark_clicked(1) and doc.cursor == doc.file.find_virtual_address_named("_main")
        assert not doc.toggle_bookmark()  # removes the one at the cursor
        assert len(doc.file.bookmarks) == 1

    def test_database_round_trip(self, arm64, tmp_path):
        main = arm64.find_virtual_address_named("_main")
        arm64.set_comment(main, "entry")
        arm64.set_inline_comment(main + 4, "inline")
        arm64.set_name(main + 8, "renamed_label")
        arm64.add_tag("interesting", main)
        arm64.toggle_bookmark_at_virtual_address(main, "start here")
        path = database.save(arm64, tmp_path / "db.asdb")
        fresh = load_file(MACHO, arch="arm64")
        assert database.load(fresh, path)
        assert fresh.comment_at_virtual_address(main) == "entry"
        assert fresh.inline_comment_at_virtual_address(main + 4) == "inline"
        assert fresh.find_virtual_address_named("renamed_label") == main + 8
        assert fresh.has_tag("interesting", main) and fresh.procedures[main].has_tag("interesting")
        assert [b.name for b in fresh.find_bookmarks_named("start here")] == ["start here"]

    def test_database_falls_back_when_the_binary_folder_is_not_writable(self, arm64, tmp_path):
        arm64.path = str(tmp_path / "folder" / "sample_macho")  # folder missing: BINARY.asdb can't be written
        main = arm64.find_virtual_address_named("_main")
        arm64.set_comment(main, "kept")
        path = database.save(arm64)
        assert path == database.fallback_database_path(arm64) and path.is_relative_to(tmp_path / "data")
        fresh = load_file(MACHO, arch="arm64")
        fresh.path = arm64.path
        assert database.load(fresh) and fresh.comment_at_virtual_address(main) == "kept"

        (tmp_path / "folder").mkdir()  # writable again: the newer database next to the binary wins
        arm64.set_comment(main, "newer")
        assert database.save(arm64) == database.default_database_path(arm64)
        fresh = load_file(MACHO, arch="arm64")
        fresh.path = arm64.path
        assert database.load(fresh) and fresh.comment_at_virtual_address(main) == "newer"


def test_missing_slice_is_an_error():
    with pytest.raises(ValueError, match="no armv7 slice .*x86_64, arm64"):
        load_file(MACHO, arch="armv7")

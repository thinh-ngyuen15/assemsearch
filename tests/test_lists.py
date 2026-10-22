"""Sidebar, palette, list dialogs, text finder, debugger."""

from assemsearch.analysis import analyze
from assemsearch.debugger import DebuggerSession
from assemsearch.listing import lines_for_virtual_address
from assemsearch.lists import ListOfAddresses, exports_window, imports_window, sections_list, segments_list
from assemsearch.model import DisassembledFile, Section, Segment
from assemsearch.palette import Command, CommandPalette, EntryType
from assemsearch.preferences import Preferences
from assemsearch.sidebar import DisplayMode, Sidebar
from assemsearch.textfinder import TextFinder
from assemsearch.types import BAD_ADDRESS


class TestSidebar:
    def test_modes(self, arm64):
        sidebar = Sidebar(arm64)
        assert "_main" in [r.name for r in sidebar.update_search("")]
        procedures = [r.name for r in sidebar.set_mode(DisplayMode.PROCEDURES)]
        assert "_main" in procedures and "_banner" not in procedures
        strings = [r.name for r in sidebar.set_mode(DisplayMode.STRINGS)]
        assert "Invalid license" in strings

    def test_utf8_strings_are_decoded(self):
        data = "café crème".encode() + b"\0" + b"\xff\xfe raw\0"
        doc = DisassembledFile("mem.bin", "x86_64", "Mach-O")
        segment = Segment("__TEXT", 0x1000, len(data), data, 0)
        segment.add_section(Section("__cstring", 0x1000, len(data), 0))
        doc.add_segment(segment)
        analyze(doc)
        assert doc.all_strings() == ["café crème", "\xff\xfe raw"]  # invalid UTF-8 stays byte for byte
        assert [r.name for r in Sidebar(doc, mode=DisplayMode.STRINGS).update_search("café")] == ["café crème"]
        assert lines_for_virtual_address(doc, 0x1000)[-1].endswith('db "café crème", 0')

    def test_ranking_puts_substrings_first(self, arm64):
        sidebar = Sidebar(arm64, mode=DisplayMode.PROCEDURES)
        rows = sidebar.update_search("lic")
        assert rows[0].name == "_validate_license" and rows[0].score == 1
        assert [r.score for r in rows] == sorted(r.score for r in rows)

    def test_fuzzy_preference(self, arm64):
        # The string "Invalid license" is a label too (aInvalidLicense).
        assert [r.name for r in Sidebar(arm64).update_search("vlic")] == ["_validate_license", "aInvalidLicense"]
        assert Sidebar(arm64, Preferences(enable_fuzzy_search=False)).update_search("vlic") == []

    def test_tag_scope(self, arm64):
        sidebar = Sidebar(arm64, mode=DisplayMode.PROCEDURES)
        sidebar.select_tags("entrypoint")
        assert [r.name for r in sidebar.update_search("")] == ["_main"]
        sidebar.hide_search_scope_option()
        assert len(sidebar.update_search("")) == len(arm64.procedures)

    def test_tag_scope_matches_labels_inside_tagged_procedures(self, arm64):
        main = arm64.find_virtual_address_named("_main")
        arm64.set_name(main + 8, "inner_label")
        sidebar = Sidebar(arm64)
        sidebar.select_tags("entrypoint")
        assert {r.name for r in sidebar.update_search("")} == {"_main", "inner_label"}

    def test_tag_scope_has_no_effect_on_strings(self, arm64):
        sidebar = Sidebar(arm64, mode=DisplayMode.STRINGS)
        sidebar.select_tags("entrypoint")
        assert len(sidebar.update_search("")) == len(arm64.strings)

    def test_sort_descriptor_overrides_score(self, arm64):
        sidebar = Sidebar(arm64, sort_descriptor=("address", False))
        rows = sidebar.update_search("")
        assert [r.address for r in rows] == sorted((r.address for r in rows), reverse=True)

    def test_recent_searches(self, arm64):
        sidebar = Sidebar(arm64, Preferences.load())
        for term in ("main", "lic", "main"):
            sidebar.search = term
            sidebar.add_current_search_value_to_search_history()
        assert Sidebar(arm64, Preferences.load()).recent_searches() == ["main", "lic"]
        sidebar.clear_recent_searches()
        assert sidebar.recent_searches() == []


class TestPalette:
    def make(self, arm_doc):
        ran = []
        commands = [Command("Next Procedure", lambda: ran.append("next")), Command("Go Back", lambda: ran.append("back"))]
        return CommandPalette(commands, [arm_doc], arm_doc), ran

    def test_prefix_parsing(self):
        assert CommandPalette.parse("@main") == (EntryType.SYMBOL, "main")
        assert CommandPalette.parse('"lic') == (EntryType.STRING, "lic")
        assert CommandPalette.parse("#sample") == (EntryType.DOCUMENT, "sample")
        assert CommandPalette.parse("next") == (EntryType.COMMAND, "next")

    def test_commands(self, arm_doc):
        palette, ran = self.make(arm_doc)
        results = palette.search("nxtproc")
        assert [r.title for r in results] == ["Next Procedure"] and palette.window_title == "Commands"
        palette.execute(results[0])
        assert ran == ["next"]

    def test_symbols_strings_documents(self, arm_doc):
        palette, _ = self.make(arm_doc)
        symbol = palette.search("@compute")[0]
        palette.execute(symbol)
        assert arm_doc.cursor == arm_doc.file.find_virtual_address_named("_compute_checksum")
        assert [e.title for e in palette.search('"invalid')] == ["Invalid license"]
        assert palette.search("#sample")[0].payload is arm_doc
        assert palette.window_title == "Documents"

    def test_toggle(self, arm_doc):
        palette, _ = self.make(arm_doc)
        assert palette.toggle() and not palette.toggle()


class TestListDialogs:
    def test_matches_address_text_or_comment(self):
        rows = [{"address": 0x1000, "addressRepresentation": "0x1000", "comment": "alpha"},
                {"address": 0x2000, "addressRepresentation": "0x2000", "comment": "beta"}]
        lst = ListOfAddresses(rows, "test")
        assert [r["address"] for r in lst.update_search("0x2")] == [0x2000]
        assert [r["address"] for r in lst.update_search("alp")] == [0x1000]
        assert lst.address_at(0) == 0x1000 and lst.address_at(5) is None

    def test_segments_and_sections(self, arm64):
        assert [r["comment"].split(maxsplit=1)[-1] for r in segments_list(arm64).results()] == \
            ["__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT", "External Symbols"]
        assert [r["comment"].split()[-1] for r in sections_list(arm64).update_search("cstr")] == ["__cstring"]

    def test_imports_exports(self, arm64):
        assert [s.name for s in imports_window(arm64).search_field_changed("put")] == ["_puts"]
        assert [s.name for s in imports_window(arm64).search_field_changed("pf")] == ["_printf"]
        assert [s.name for s in exports_window(arm64).search_field_changed("main")][0] == "_main"


class TestTextFinder:
    def test_find_next_previous_and_wrap(self):
        finder = TextFinder("one two\nTwo three\ntwo")
        assert finder.find_next("two") == (4, 7)
        assert finder.find_next() == (8, 11)
        assert finder.find_next() == (18, 21)
        assert finder.find_next() == (4, 7)  # wraps
        assert finder.find_previous() == (18, 21)
        assert finder.line_of(18) == 3

    def test_options(self):
        assert len(TextFinder("Two two", case_sensitive=True).find_all("two")) == 1
        assert TextFinder("network two", whole_word=True).find_all("two") == [(8, 11)]
        assert TextFinder("foobar baz", whole_word=True, regex=True).find_all("foo|baz") == [(7, 10)]
        assert TextFinder("a1 b22", regex=True).find_all(r"\d+") == [(1, 2), (4, 6)]
        assert TextFinder("two", wrap=False, position=2).find_next("two") is None

    def test_replace_only_in_editable_views(self):
        finder = TextFinder("a.b.c")
        finder.find_next(".")
        assert not finder.replace("-")
        editable = TextFinder("a.b.c", editable=True)
        editable.find_next(".")
        assert editable.replace("-") and editable.text == "a-b.c"
        assert editable.replace_all("+") == 1 and editable.text == "a-b+c"


class TestDebugger:
    def test_completion_and_history(self):
        session = DebuggerSession()
        assert session.completions("thread s") == ["thread select", "thread step-in", "thread step-out"]
        for command in ("run", "bt", "bt"):
            session.send_command(command)
        assert session.history == ["run", "bt"] and session.last_command() == "bt"
        assert session.history_up() == "bt" and session.history_up() == "run"
        assert session.history_down() == "bt"

    def test_translation_modules_breakpoints_memory(self, arm64):
        session = DebuggerSession()
        module = session.load_module(arm64, 0x104000000)
        main = arm64.find_virtual_address_named("_main")
        runtime = session.translate_address_to_loaded_process(main, arm64)
        assert runtime == main + module.slide
        assert session.translate_address_from_loaded_process(runtime) == (main, arm64)
        assert session.translate_address_from_loaded_process(0x10) == (BAD_ADDRESS, None)
        assert session.loaded_module_containing_absolute_address(runtime) is module
        bp = session.set_breakpoint(runtime)
        assert session.breakpoint_id_at_absolute_address(runtime) == bp.identifier
        assert session.address_of_breakpoint_at_index(0) == runtime
        assert session.set_memory_address(f"{runtime:x}") and not session.set_memory_address("main")
        assert session.refresh_memory(4) == arm64.read_bytes(main, 4)

"""Find sheet input parsing and the address-space search engine."""

import threading

import pytest

from assemsearch.document import FindPanelAction
from assemsearch.find import (INVALID_HEX, INVALID_NUMBER, INVALID_REGEXP, Cancelled, FindContext, FindInputError,
                            FindMode, SearchEngine, Searcher, build_section_search_range_from_address,
                            data_to_find_from_string)
from assemsearch.hexregex import FastDFA
from assemsearch.types import AddressRange

from conftest import raw_document

DATA = b"\x00" * 16 + b"Secret" + b"\x00" * 10 + bytes.fromhex("efbeadde") + b"\x00" * 4 + b"secret" + b"\x00" * 8
BASE = 0x1000


class TestInputParsing:
    def test_hex_value_strips_spaces_quotes_and_prefix(self):
        assert data_to_find_from_string("0x DE 'AD' \"BE\"\tEF", FindMode.HEX_VALUE) == b"\xde\xad\xbe\xef"

    @pytest.mark.parametrize("text", ["", "abc", "xyz1", "12 3"])
    def test_invalid_hex(self, text):
        with pytest.raises(FindInputError, match=INVALID_HEX):
            data_to_find_from_string(text, FindMode.HEX_VALUE)

    def test_numbers_truncate_and_swap(self):
        assert data_to_find_from_string("0xdeadbeef", FindMode.NUMBER, 32, True) == b"\xef\xbe\xad\xde"
        assert data_to_find_from_string("0xdeadbeef", FindMode.NUMBER, 32, False) == b"\xde\xad\xbe\xef"
        assert data_to_find_from_string("0x1234", FindMode.NUMBER, 8) == b"\x34"
        assert data_to_find_from_string("258", FindMode.NUMBER, 16) == b"\x02\x01"
        assert data_to_find_from_string("1", FindMode.NUMBER, 64) == b"\x01" + b"\x00" * 7

    def test_invalid_number_and_regexp(self):
        with pytest.raises(FindInputError, match=INVALID_NUMBER):
            data_to_find_from_string("twelve", FindMode.NUMBER)
        with pytest.raises(FindInputError, match=INVALID_REGEXP):
            data_to_find_from_string("(4", FindMode.HEX_REGEXP)

    def test_regexp_needle_is_a_dfa(self):
        assert isinstance(data_to_find_from_string("90", FindMode.HEX_REGEXP), FastDFA)


class TestEngineOnRawBytes:
    def setup_method(self):
        self.doc = raw_document(DATA, BASE)
        self.engine = SearchEngine(self.doc.file)

    def find(self, text, mode, start=BASE, **kw):
        context = FindContext.from_string(text, mode, **kw)
        return self.engine.find_next(start, context)

    def test_ascii_case_insensitive_and_sensitive(self):
        assert self.find("SECRET", FindMode.ASCII_STRING) == AddressRange(BASE + 16, 6)
        assert self.find("secret", FindMode.ASCII_STRING, case_sensitive=True) == AddressRange(BASE + 40, 6)

    def test_hex_value_ignores_case_option(self):
        assert self.find("efbeadde", FindMode.HEX_VALUE) == AddressRange(BASE + 32, 4)

    def test_number(self):
        assert self.find("0xdeadbeef", FindMode.NUMBER) == AddressRange(BASE + 32, 4)
        assert self.find("0xdeadbeef", FindMode.NUMBER, little_endian=False) is None

    def test_regexp(self):
        assert self.find("ef..ad", FindMode.HEX_REGEXP) == AddressRange(BASE + 32, 3)

    def test_search_starts_after_cursor(self):
        assert self.find("secret", FindMode.ASCII_STRING, start=BASE + 16, wrapping=False) == AddressRange(BASE + 40, 6)

    def test_wrapping(self):
        start = BASE + 41
        assert self.find("Secret", FindMode.ASCII_STRING, start=start, case_sensitive=True, wrapping=False) is None
        assert self.find("Secret", FindMode.ASCII_STRING, start=start, case_sensitive=True) == AddressRange(BASE + 16, 6)

    def test_find_previous(self):
        context = FindContext.from_string("secret", FindMode.ASCII_STRING)
        assert self.engine.find_previous(BASE + 40, context) == AddressRange(BASE + 16, 6)
        assert self.engine.find_previous(BASE + 16, context) == AddressRange(BASE + 40, 6)  # wraps
        context.wrapping = False
        assert self.engine.find_previous(BASE + 16, context) is None

    def test_cancellation(self):
        context = FindContext.from_string("nothere", FindMode.ASCII_STRING)
        with pytest.raises(Cancelled):
            self.engine.find_next(BASE, context, cancelation=lambda: True)

    def test_range_rotation(self):
        ranges = build_section_search_range_from_address(self.doc.file, BASE + 10, wrapping=True)
        assert [(r.range.location, r.range.length) for r in ranges] == [(BASE + 10, len(DATA) - 10), (BASE, 10)]

    def test_searcher_runs_on_background_queue(self):
        searcher = Searcher(self.engine)
        names = []
        original = self.engine.find_next

        def spy(*args):
            names.append(threading.current_thread().name)
            return original(*args)

        self.engine.find_next = spy
        result = searcher.submit(BASE, FindContext.from_string("secret", FindMode.ASCII_STRING)).result(5)
        searcher.shutdown()
        assert result == AddressRange(BASE + 16, 6)
        assert names[0].startswith("assemsearch.searching")


class TestDocumentFind:
    def test_assembly_text_mode(self, arm_doc):
        arm_doc.move_cursor_to_virtual_address(arm_doc.file.min_address)
        arm_doc.set_find("imp___stubs__strcmp", FindMode.STRING_IN_ASSEMBLY)
        hit = arm_doc.move_cursor_at_next_occurrence()
        assert arm_doc.file.procedure_at(hit.location).entry == arm_doc.file.find_virtual_address_named("_validate_license")
        assert hit.length == 4 and arm_doc.selection == hit

    def test_assembly_text_respects_case(self, arm_doc):
        arm_doc.set_find("IMP___STUBS__STRCMP", FindMode.STRING_IN_ASSEMBLY, case_sensitive=True)
        hit = arm_doc.move_cursor_at_next_occurrence()
        assert hit is None and arm_doc.last_beep == "not found"

    def test_comment_mode_searches_comments_and_inline_comments(self, arm_doc):
        main = arm_doc.file.find_virtual_address_named("_main")
        arm_doc.file.set_inline_comment(main + 8, "Check The Key")
        arm_doc.set_find("the key", FindMode.STRING_IN_COMMENTS)
        assert arm_doc.move_cursor_at_next_occurrence().location == main + 8
        arm_doc.set_find("the key", FindMode.STRING_IN_COMMENTS, case_sensitive=True)
        assert arm_doc.move_cursor_at_next_occurrence() is None

    def test_options_persist_in_preferences(self, arm_doc):
        arm_doc.set_find("0x10", FindMode.NUMBER, case_sensitive=True, wrapping=False, number_length=16,
                         little_endian=False)
        prefs = arm_doc.prefs
        assert (prefs.last_find_mode, prefs.last_find_case_sensitive, prefs.last_find_wrapping,
                prefs.last_find_number_length, prefs.last_find_number_little_endian) == (4, True, False, 16, False)
        assert prefs.find_pasteboard == "0x10"

    def test_next_and_previous_repeat_the_context(self, arm_doc):
        arm_doc.set_find("bl ", FindMode.STRING_IN_ASSEMBLY)
        first = arm_doc.perform_find_panel_action(FindPanelAction.NEXT)
        second = arm_doc.perform_find_panel_action(FindPanelAction.NEXT)
        assert second.location > first.location
        assert arm_doc.perform_find_panel_action(FindPanelAction.PREVIOUS) == first

    def test_use_selection_for_find(self, arm_doc):
        string = arm_doc.file.find_virtual_address_named("_banner")
        arm_doc.move_cursor_to_virtual_address_range(AddressRange(string, 7))
        context = arm_doc.perform_find_panel_action(FindPanelAction.SET_FIND_STRING)
        assert context.text == "Welcome" and arm_doc.prefs.find_pasteboard == "Welcome"

    def test_use_selection_in_code_reads_the_instruction(self, arm_doc):
        arm_doc.move_cursor_to_virtual_address(arm_doc.file.min_address)
        arm_doc.set_find("imp___stubs__strcmp", FindMode.STRING_IN_ASSEMBLY)
        arm_doc.move_cursor_at_next_occurrence()  # selects the call in _validate_license
        context = arm_doc.perform_find_panel_action(FindPanelAction.SET_FIND_STRING)
        assert context.text == "bl imp___stubs__strcmp" and context.mode == FindMode.STRING_IN_ASSEMBLY
        hit = arm_doc.move_cursor_at_next_occurrence()
        assert arm_doc.file.procedure_at(hit.location).entry == arm_doc.file.find_virtual_address_named("_main")

    def test_use_selection_without_selection_reads_the_cursor(self, arm_doc):
        arm_doc.goto("_main")
        context = arm_doc.use_selection_for_find()
        assert context.text == "sub sp, sp, #0x30" and context.mode == FindMode.STRING_IN_ASSEMBLY

    def test_no_context_beeps(self, arm_doc):
        assert arm_doc.move_cursor_at_next_occurrence() is None
        assert arm_doc.last_beep == "no find context"

    def test_pasteboard_seeds_a_new_document(self, arm_doc):
        arm_doc.prefs.find_pasteboard = "Invalid license"
        arm_doc.find_context = None
        assert arm_doc.move_cursor_at_next_occurrence() is not None

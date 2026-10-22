"""Fuzzy scorer, name index, byte matcher, hex regexps."""

import pytest

from assemsearch import bytesearch, fuzzy
from assemsearch.analysis import display_escaped, string_label
from assemsearch.model import Instruction, InstructionTable
from assemsearch.hexregex import EARLY_ACCEPT, NIBBLE_MODE, HexRegexError, compile_hex_regex
from assemsearch.nametree import NameTree
from assemsearch.types import BAD_ADDRESS, NOT_FOUND


class TestFuzzy:
    def test_substring_and_empty_pattern_score_one(self):
        assert fuzzy.score("_validate_license", "") == 1
        assert fuzzy.score("_validate_license", "LICENSE") == 1

    def test_score_counts_contiguous_runs(self):
        assert fuzzy.score("_validate_license", "vlic") == 3  # V | LI | C
        assert fuzzy.score("abcdef", "abef") == 2
        assert fuzzy.score("abcdef", "ace") == 3

    def test_no_match_is_zero(self):
        assert fuzzy.score("abc", "abd") == 0
        assert fuzzy.score("abc", "cba") == 0

    def test_strict_mode_only_accepts_substrings(self):
        assert fuzzy.score("abcdef", "abef", fuzzy=False) == 0
        assert fuzzy.score("abcdef", "CDE", fuzzy=False) == 1

    def test_rank_orders_ascending(self):
        names = ["a_x_b_x_c", "abc_suffix", "zzz", "ab_c"]
        ranked = [n for _, n in fuzzy.rank(names, "abc", key=lambda s: s)]
        assert ranked == ["abc_suffix", "ab_c", "a_x_b_x_c"]

    def test_colorized_marks_matched_characters(self):
        assert fuzzy.matched_positions("abcdef", "bd") == [1, 3]
        assert fuzzy.colorized("abc", "b", "<", ">") == "a<b>c"

    def test_predicate(self):
        predicate = fuzzy.FuzzyPredicate(lambda s: s, "ml")
        assert predicate("_main_loop") and not predicate("xyz")
        assert predicate.filter(["xyz", "m_l", "ml"]) == ["ml", "m_l"]


class TestLabels:
    """Label rules for strings."""

    @pytest.mark.parametrize("text, label", [
        ("When a Window is Open", "aWhenAWindowIsO"),
        ("DCPDPDeviceProxy", "aDcpdpdevicepro"),
        ("CEC command: skipped; no HDMI", "aCecCommandSkip"),
        ("Secondary on-demand socket", "aSecondaryOndem"),
        ("FL/FR", "aFlfr"),
        ("=0.8`\n\n`betterdisplaycli", "a08nnbetterdisp"),  # built from the escaped text
        ("%@", "asc"),
    ])
    def test_string_labels(self, text, label):
        assert string_label(text) == label

    def test_escaped(self):
        assert display_escaped('Import "LUT"…\n') == 'Import \\"LUT\\"\\xE2\\x80\\xA6\\n'


class TestInstructionTable:
    def test_behaves_like_an_ordered_dict(self):
        table = InstructionTable()
        table.add(0x20, 4, "ret", "")
        table.add(0x10, 4, "mov", "x0, x1")  # out of order: sorted on the next read
        table[0x14] = Instruction(0x14, 4, "add", "x0, x0, #1")
        assert list(table) == [0x10, 0x14, 0x20] and len(table) == 3
        assert 0x14 in table and 0x15 not in table and "x" not in table
        assert table[0x10].text == "mov x0, x1" and table.get(0x18) is None
        assert [i.mnemonic for i in table.between(0x11, 0x21)] == ["add", "ret"]
        table.add(0x10, 4, "nop", "")  # re-adding an address replaces it
        assert table[0x10].mnemonic == "nop" and len(table) == 3


class TestNameTree:
    def test_lookups_both_ways_and_nearest(self):
        tree = NameTree()
        tree.set_name("start", 0x100)
        tree.set_name("loop", 0x180)
        assert tree.address_for_name("loop") == 0x180
        assert tree.name_for_address(0x100) == "start"
        assert tree.nearest_named_address_before(0x17F) == 0x100
        assert tree.nearest_named_address_before(0x180) == 0x180
        assert tree.nearest_named_address_superior_to(0x100) == 0x180
        assert tree.nearest_named_address_before(0x50) == BAD_ADDRESS
        assert tree.address_for_name("nope") == BAD_ADDRESS

    def test_rename_and_unique_names(self):
        tree = NameTree()
        tree.set_name("a", 1)
        tree.set_name("b", 1)  # renaming the address drops "a"
        tree.set_name("b", 2)  # moving the name frees address 1
        assert tree.all_addresses() == [2] and not tree.has_name("a")

    def test_shift(self):
        tree = NameTree()
        tree.set_name("a", 0x10)
        tree.shift_addresses_by(0x1000)
        assert tree.address_for_name("a") == 0x1010


class TestByteMatcher:
    data = b"xxHelloxxhelloxxHELLO?"

    def test_plain_forward_and_backward(self):
        assert bytesearch.locate_data(self.data, b"Hello") == 2
        assert bytesearch.locate_data(self.data, b"Hello", options=bytesearch.BACKWARDS) == 2
        assert bytesearch.locate_data(self.data, b"nope") == NOT_FOUND

    def test_case_insensitive_folds_ascii_letters_only(self):
        assert bytesearch.locate_data(self.data, b"hello", 3, options=1) == 9
        assert bytesearch.locate_data(self.data, b"hello", options=1 | 4) == 16
        assert bytesearch.locate_data(b"\x40", b"\x60", options=1) == NOT_FOUND  # '@' is not a letter

    def test_wildcard_bit(self):
        assert bytesearch.locate_data(self.data, b"h?llo", options=2) == 9
        assert bytesearch.locate_data(self.data, b"h?llo") == NOT_FOUND

    def test_range_limits(self):
        assert bytesearch.locate_data(self.data, b"Hello", 3, 20) == NOT_FOUND
        assert bytesearch.locate_data(self.data, b"HELLO", 0, 21) == 16
        assert bytesearch.locate_data(self.data, b"HELLO", 0, 20) == NOT_FOUND


class TestHexRegex:
    def test_xor_example_from_help(self):
        dfa = compile_hex_regex("(48|66)?(30|31)C0")
        assert dfa.recognize(bytes.fromhex("4831c0")) == 3
        assert dfa.recognize(bytes.fromhex("31c0")) == 2
        assert dfa.recognize(bytes.fromhex("6630c0")) == 3
        assert dfa.recognize(bytes.fromhex("4832c0")) is None

    def test_any_byte_sets_and_ranges(self):
        assert compile_hex_regex("e8........").recognize(bytes.fromhex("e801020304")) == 5
        dfa = compile_hex_regex("[2-8cd]0")
        assert dfa.recognize(b"\x50") == 1 and dfa.recognize(b"\xc0") == 1
        assert dfa.recognize(b"\x90") is None

    def test_postfix_applies_to_previous_word(self):
        dfa = compile_hex_regex("(90)*c3")
        assert dfa.recognize(bytes.fromhex("909090c3")) == 4
        assert dfa.recognize(bytes.fromhex("c3")) == 1
        assert compile_hex_regex("(90)+c3").recognize(bytes.fromhex("c3")) is None

    def test_longest_versus_early_accept(self):
        dfa = compile_hex_regex("(90)+")
        assert dfa.recognize(bytes.fromhex("909090")) == 3
        assert dfa.recognize(bytes.fromhex("909090"), options=NIBBLE_MODE | EARLY_ACCEPT) == 1

    def test_match_must_end_on_byte_boundary(self):
        assert compile_hex_regex("9").recognize(b"\x90") is None

    def test_whitespace_and_case_are_ignored(self):
        assert compile_hex_regex("C3 90").recognize(b"\xc3\x90") == 2

    @pytest.mark.parametrize("bad", ["", "zz", "(90", "[]", "[9-]", "90|", "*90", "g"])
    def test_invalid_patterns(self, bad):
        with pytest.raises(HexRegexError):
            compile_hex_regex(bad)

    def test_first_bytes_prefilter(self):
        assert set(compile_hex_regex("4[8-9]").first_bytes()) == {0x48, 0x49}

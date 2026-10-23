"""Find dialog model and the address-space search engine.

Mode numbers are the Find sheet's popup tags::

    0 ASCII String   1 Hexadecimal Value   2 String in Assembly
    3 Hexadecimal Regular Expression        4 Find Number
    5 String in User Comments
"""

from __future__ import annotations

import enum
import struct
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

from assemsearch import bytesearch
from assemsearch.hexregex import FastDFA, HexRegexError, compile_hex_regex
from assemsearch.listing import lines_for_virtual_address
from assemsearch.model import DisassembledFile, Section, Segment
from assemsearch.types import NOT_FOUND, AddressRange


class FindMode(enum.IntEnum):
    ASCII_STRING = 0
    HEX_VALUE = 1
    STRING_IN_ASSEMBLY = 2
    HEX_REGEXP = 3
    NUMBER = 4
    STRING_IN_COMMENTS = 5


MODE_TITLES = {
    FindMode.ASCII_STRING: "ASCII String",
    FindMode.HEX_VALUE: "Hexadecimal Value",
    FindMode.STRING_IN_ASSEMBLY: "String in Assembly",
    FindMode.HEX_REGEXP: "Hexadecimal Regular Expression",
    FindMode.NUMBER: "Find Number",
    FindMode.STRING_IN_COMMENTS: "String in User Comments",
}

INVALID_HEX = "You entered an invalid hexadecimal string."
INVALID_NUMBER = "You entered an invalid number."
INVALID_REGEXP = "You entered an invalid hexadecimal regular expression string."


# How far past a search range a hex-regex match that starts in it may extend.
REGEXP_OVERLAP = 0x10000


class FindInputError(ValueError):
    pass


class Cancelled(Exception):
    pass


def data_to_find_for_text_search(text: str) -> bytes:
    return text.encode("utf-8")


def data_to_find_from_string(text: str, mode: int, number_length: int = 32,
                             little_endian: bool = True) -> bytes | FastDFA:
    """``+dataToFindFromString:forMode:numberLength:numberLittleEndian:``."""
    mode = FindMode(mode)
    if mode == FindMode.HEX_REGEXP:
        try:
            return compile_hex_regex(text)
        except HexRegexError as error:
            raise FindInputError(INVALID_REGEXP) from error
    if mode == FindMode.HEX_VALUE:
        cleaned = text
        for junk in (" ", "\t", '"', "'"):
            cleaned = cleaned.replace(junk, "")
        if cleaned[:2] in ("0x", "0X"):
            cleaned = cleaned[2:]
        if not cleaned or len(cleaned) % 2 or any(c not in "0123456789abcdefABCDEF" for c in cleaned):
            raise FindInputError(INVALID_HEX)
        return bytes.fromhex(cleaned)
    if mode == FindMode.NUMBER:
        text = text.strip()
        try:
            value = int(text, 0)
        except ValueError:
            try:
                value = int(text, 10)  # int(x, 0) rejects leading zeros ("010")
            except ValueError as error:
                raise FindInputError(INVALID_NUMBER) from error
        bits = number_length if number_length in (8, 16, 32, 64) else 32
        if not -(1 << (bits - 1)) <= value < 1 << bits:  # negative values are two's complement
            raise FindInputError(INVALID_NUMBER)
        value &= (1 << bits) - 1
        fmt = {8: "B", 16: "H", 32: "I", 64: "Q"}[bits]
        return struct.pack(("<" if little_endian else ">") + fmt, value)
    if not text:
        raise FindInputError("Nothing to find.")
    return data_to_find_for_text_search(text)


@dataclass
class FindContext:
    """One per document so Find Next/Previous can repeat the search."""

    mode: FindMode = FindMode.STRING_IN_ASSEMBLY
    case_sensitive: bool = False
    wrapping: bool = True
    data: bytes | FastDFA | None = None
    text: str = ""

    @classmethod
    def from_string(cls, text: str, mode: int, case_sensitive: bool = False, wrapping: bool = True,
                    number_length: int = 32, little_endian: bool = True) -> "FindContext":
        return cls(FindMode(mode), case_sensitive, wrapping,
                   data_to_find_from_string(text, mode, number_length, little_endian), text)


# --- Search ranges -------------------------------------------------------------

@dataclass
class SectionAndRange:
    segment: Segment
    section: Section | None
    range: AddressRange


def build_all_search_ranges(doc: DisassembledFile) -> list[SectionAndRange]:
    return [SectionAndRange(seg, sec, rng) for seg, sec, rng in doc.iter_section_ranges() if rng.length]


def build_section_search_range_from_address(doc: DisassembledFile, address: int, wrapping: bool,
                                            backwards: bool = False) -> list[SectionAndRange]:
    """Ranges in search order starting at ``address`` (exclusive of it when backwards)."""
    ranges = build_all_search_ranges(doc)
    if backwards:
        ranges = ranges[::-1]
    head, tail = [], []
    for item in ranges:
        rng = item.range
        if not backwards:
            if rng.end <= address:
                tail.append(item)
            elif rng.location >= address:
                head.append(item)
            else:
                head.append(SectionAndRange(item.segment, item.section, AddressRange(address, rng.end - address)))
                tail.append(SectionAndRange(item.segment, item.section, AddressRange(rng.location, address - rng.location)))
        else:
            if rng.location >= address:
                tail.append(item)
            elif rng.end <= address:
                head.append(item)
            else:
                head.append(SectionAndRange(item.segment, item.section, AddressRange(rng.location, address - rng.location)))
                tail.append(SectionAndRange(item.segment, item.section, AddressRange(address, rng.end - address)))
    if wrapping:
        if not backwards:
            tail = sorted(tail, key=lambda r: r.range.location)
        else:
            tail = sorted(tail, key=lambda r: r.range.location, reverse=True)
        return head + tail
    return head


# --- Engine -------------------------------------------------------------------------

CancelCheck = Callable[[], bool]
Dispatcher = Callable[[Callable[[], None]], None]


class SearchEngine:
    """``DisassembledFile findNext/PreviousAddress:lookingFor:…`` on a document."""

    def __init__(self, doc: DisassembledFile, show_hex_column: bool = False) -> None:
        self.doc = doc
        self.show_hex_column = show_hex_column

    def find_next(self, address: int, context: FindContext, cancelation: CancelCheck | None = None,
                  dispatcher: Dispatcher | None = None) -> AddressRange | None:
        if FindMode(context.mode) in (FindMode.STRING_IN_ASSEMBLY, FindMode.STRING_IN_COMMENTS):
            start = self.doc.next_address_of_virtual_address(address)
        else:  # byte matches can sit anywhere inside an object, and several in the same one
            start = address + 1
        return self._find(start, context, False, cancelation or (lambda: False), dispatcher)

    def find_previous(self, address: int, context: FindContext, cancelation: CancelCheck | None = None,
                      dispatcher: Dispatcher | None = None) -> AddressRange | None:
        return self._find(address, context, True, cancelation or (lambda: False), dispatcher)

    def _find(self, start, context, backwards, cancelled, dispatcher):
        mode = FindMode(context.mode)
        if context.data is None:
            return None
        ranges = build_section_search_range_from_address(self.doc, start, context.wrapping, backwards)
        for index, item in enumerate(ranges):
            if cancelled():
                raise Cancelled()
            if dispatcher is not None:
                dispatcher(lambda i=index: None)
            if mode == FindMode.HEX_REGEXP:
                hit = self._search_regexp(item, context.data, backwards, cancelled)
            elif mode in (FindMode.STRING_IN_ASSEMBLY, FindMode.STRING_IN_COMMENTS):
                hit = self._search_text(item, context, backwards, cancelled)
            else:
                hit = self._search_bytes(item, context, backwards)
            if hit is not None:
                return hit
        return None

    @staticmethod
    def _read_with_overlap(item: SectionAndRange, overlap: int) -> bytes:
        """The range's bytes plus up to ``overlap`` bytes after it (within the segment), so a match
        that starts in the range but ends past it (the cursor, a section boundary) is still seen."""
        segment, rng = item.segment, item.range
        return segment.read(rng.location, rng.length + max(0, min(overlap, segment.end - rng.end)))

    # Raw bytes: ASCII String, Hexadecimal Value, Find Number
    def _search_bytes(self, item: SectionAndRange, context: FindContext, backwards: bool) -> AddressRange | None:
        rng = item.range
        # With len(needle) - 1 extra bytes, only matches starting inside the range fit.
        data = self._read_with_overlap(item, len(context.data) - 1)
        options = 0
        if context.mode == FindMode.ASCII_STRING and not context.case_sensitive:
            options |= bytesearch.CASE_INSENSITIVE
        if backwards:
            options |= bytesearch.BACKWARDS
        found = bytesearch.locate_data(data, context.data, 0, len(data), options)
        if found == NOT_FOUND:
            return None
        return AddressRange(rng.location + found, len(context.data))

    def _search_regexp(self, item, dfa: FastDFA, backwards, cancelled) -> AddressRange | None:
        rng = item.range
        data = self._read_with_overlap(item, REGEXP_OVERLAP)
        first = dfa.first_bytes()
        allowed = bytearray(256)
        for byte in first:
            allowed[byte] = 1
        positions = range(rng.length - 1, -1, -1) if backwards else range(rng.length)
        for count, offset in enumerate(positions):
            if count & 0xFFF == 0 and cancelled():
                raise Cancelled()
            if not allowed[data[offset]]:
                continue
            length = dfa.recognize(data, offset)
            if length:
                return AddressRange(rng.location + offset, length)
        return None

    def _search_text(self, item, context: FindContext, backwards, cancelled) -> AddressRange | None:
        doc = self.doc
        needle = context.data.decode("utf-8", "replace") if isinstance(context.data, bytes) else ""
        if not context.case_sensitive:
            needle = needle.casefold()
        rng = item.range
        if context.mode == FindMode.STRING_IN_COMMENTS:  # only addresses that carry a comment
            commented = (a for a in set(doc.comments) | set(doc.inline_comments) if a in rng)
            addresses = sorted(commented, reverse=backwards)
        else:
            addresses = self._object_addresses(rng, backwards)
        for count, address in enumerate(addresses):
            if count & 0x3FF == 0 and cancelled():
                raise Cancelled()
            if context.mode == FindMode.STRING_IN_COMMENTS:
                texts = [t for t in (doc.comment_at_virtual_address(address),
                                     doc.inline_comment_at_virtual_address(address)) if t]
            else:
                texts = lines_for_virtual_address(doc, address, hex_column=self.show_hex_column)
            for text in texts:
                haystack = text if context.case_sensitive else text.casefold()
                if needle in haystack:
                    return AddressRange(address, doc.byte_length_at(address))
        return None

    def _object_addresses(self, rng: AddressRange, backwards: bool):
        doc = self.doc
        if not backwards:
            address = doc.object_start_containing(rng.location)
            if address is None:
                address = rng.location
            elif address < rng.location:
                address = doc.next_address_of_virtual_address(address)
            while address < rng.end:
                yield address
                address = doc.next_address_of_virtual_address(address)
        else:
            address = rng.end
            while address > rng.location:
                address = doc.previous_address_of_virtual_address(address)
                if address < rng.location:
                    break
                yield address


class Searcher:
    """Runs searches on the serial "searching" queue with cancel support."""

    def __init__(self, engine: SearchEngine) -> None:
        self.engine = engine
        self._queue = ThreadPoolExecutor(max_workers=1, thread_name_prefix="assemsearch.searching")
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def submit(self, address: int, context: FindContext, backwards: bool = False) -> Future:
        self._cancel.clear()
        method = self.engine.find_previous if backwards else self.engine.find_next
        return self._queue.submit(method, address, context, self._cancel.is_set)

    def shutdown(self) -> None:
        self._queue.shutdown(wait=False, cancel_futures=True)

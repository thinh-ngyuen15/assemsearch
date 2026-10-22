"""Text export: the listing written out for offline ``grep``.

Writes the whole disassembly, the current procedure or the current selection
to a text file.  The lines are the ones *String in Assembly* searches.  assemsearch has no
decompiler, so there is no pseudo-code variant.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from assemsearch.listing import lines_for_virtual_address
from assemsearch.model import DisassembledFile, Procedure
from assemsearch.types import AddressRange, format_address


def range_lines(doc: DisassembledFile, rng: AddressRange, hex_column: bool = False) -> Iterator[str]:
    """Listing lines of every object starting in ``rng``."""
    start = doc.object_start_containing(rng.location)
    address = rng.location if start is None else start
    while address < rng.end:
        yield from lines_for_virtual_address(doc, address, hex_column=hex_column)
        address = doc.next_address_of_virtual_address(address)


def procedure_lines(doc: DisassembledFile, procedure: Procedure, hex_column: bool = False) -> Iterator[str]:
    """Listing lines of a procedure's basic blocks (which need not be contiguous)."""
    for address in doc.procedure_object_addresses(procedure):
        yield from lines_for_virtual_address(doc, address, hex_column=hex_column)


def file_lines(doc: DisassembledFile, hex_column: bool = False) -> Iterator[str]:
    """The whole document, segment by segment; zero-fill sections are summarised."""
    for segment in doc.segments:
        yield f"; Segment {segment.name}  {format_address(segment.start)}-{format_address(segment.end)}"
        for seg, section, rng in doc.iter_section_ranges():
            if seg is not segment or not rng.length:
                continue
            if section is not None:
                yield ""
                yield f"; Section {section.name}  {format_address(rng.location)}-{format_address(rng.end)}"
                if section.file_offset is None:
                    yield f"; zero-fill, {rng.length} bytes"
                    continue
            yield from range_lines(doc, rng, hex_column)
        yield ""


def write_lines(path: str | Path, lines: Iterator[str]) -> int:
    """Writes the lines and returns how many there were."""
    count = 0
    with open(path, "w", encoding="utf-8") as out:
        for line in lines:
            out.write(line + "\n")
            count += 1
    return count

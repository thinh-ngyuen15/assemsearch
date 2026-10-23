"""Document model: segments, sections, procedures, names, comments, tags, bookmarks.

``DisassembledFile`` holds everything known about one binary.
Search features live in their own modules and operate on this object.
"""

from __future__ import annotations

import bisect
import heapq
from array import array
from dataclasses import dataclass, field
from typing import Iterator

from assemsearch.nametree import NameTree
from assemsearch.types import BAD_ADDRESS, DATA_TYPES, AddressRange, ByteType, format_address


@dataclass
class Section:
    name: str
    start: int
    length: int
    file_offset: int | None  # None for zero-fill sections
    segment: "Segment" = field(repr=False, compare=False, default=None)  # type: ignore[assignment]
    flags: int = 0

    @property
    def end(self) -> int:
        return self.start + self.length

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass
class Segment:
    name: str
    start: int
    length: int
    data: bytes  # mapped bytes; may be shorter than length (zero-fill tail)
    file_offset: int | None
    sections: list[Section] = field(default_factory=list)
    executable: bool = False
    writable: bool = False
    references_to: dict[int, set[int]] = field(default_factory=dict, repr=False)
    references_from: dict[int, set[int]] = field(default_factory=dict, repr=False)
    data_references: set[tuple[int, int]] = field(default_factory=set, repr=False)

    @property
    def end(self) -> int:
        return self.start + self.length

    @property
    def mapped_data(self) -> bytes:
        return self.data

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end

    def add_section(self, section: Section) -> None:
        section.segment = self
        self.sections.append(section)
        self.sections.sort(key=lambda s: s.start)

    def read(self, address: int, length: int) -> bytes:
        offset = address - self.start
        chunk = self.data[offset:offset + length]
        if len(chunk) < length:  # zero-fill past the mapped part
            chunk += bytes(min(length, self.end - address) - len(chunk))
        return chunk

    def section_at(self, address: int) -> Section | None:
        for section in self.sections:
            if section.contains(address):
                return section
        return None

    # References ------------------------------------------------------

    def add_reference(self, source: int, target: int, data: bool = False) -> None:
        self.references_from.setdefault(source, set()).add(target)
        if data:
            self.data_references.add((source, target))

    def references_from_address(self, address: int) -> list[int]:
        return sorted(self.references_from.get(address, ()))

    def references_to_address(self, address: int) -> list[int]:
        return sorted(self.references_to.get(address, ()))


@dataclass(slots=True)
class Instruction:
    address: int
    size: int
    mnemonic: str
    op_str: str

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".rstrip()


class InstructionTable:
    """Address -> Instruction, stored as typed arrays (a few bytes per instruction instead of
    a few hundred); ``Instruction`` objects are created when read.

    Behaves like a dict whose iteration is in address order. Instructions are normally added
    in ascending address order; anything else is sorted on the next read.
    """

    def __init__(self) -> None:
        self._addresses = array("Q")
        self._sizes = array("B")
        self._mnemonic_ids = array("H")
        self._mnemonics: list[str] = []
        self._mnemonic_index: dict[str, int] = {}
        self._operands: list[str] = []
        self._sorted = True

    def add(self, address: int, size: int, mnemonic: str, op_str: str) -> None:
        if self._addresses and address <= self._addresses[-1]:
            self._sorted = False
        mnemonic_id = self._mnemonic_index.get(mnemonic)
        if mnemonic_id is None:
            mnemonic_id = self._mnemonic_index[mnemonic] = len(self._mnemonics)
            self._mnemonics.append(mnemonic)
        self._addresses.append(address)
        self._sizes.append(size)
        self._mnemonic_ids.append(mnemonic_id)
        self._operands.append(op_str)

    def __setitem__(self, address: int, ins: Instruction) -> None:
        self.add(address, ins.size, ins.mnemonic, ins.op_str)

    def _sort(self) -> None:
        if self._sorted:
            return
        order = sorted(range(len(self._addresses)), key=self._addresses.__getitem__)
        keep = [i for n, i in enumerate(order)  # a re-added address replaces the earlier one
                if n + 1 == len(order) or self._addresses[order[n + 1]] != self._addresses[i]]
        self._addresses = array("Q", (self._addresses[i] for i in keep))
        self._sizes = array("B", (self._sizes[i] for i in keep))
        self._mnemonic_ids = array("H", (self._mnemonic_ids[i] for i in keep))
        self._operands = [self._operands[i] for i in keep]
        self._sorted = True

    def _index(self, address: int) -> int:
        self._sort()
        i = bisect.bisect_left(self._addresses, address)
        return i if i < len(self._addresses) and self._addresses[i] == address else -1

    def index(self, address: int) -> int:
        """Position of the instruction at ``address`` in address order, -1 if there is none."""
        return self._index(address)

    def row(self, i: int) -> tuple[int, int, str, str]:
        """(address, size, mnemonic, operands) of the i-th instruction, without building an object."""
        return self._addresses[i], self._sizes[i], self._mnemonics[self._mnemonic_ids[i]], self._operands[i]

    def sizes(self) -> array:
        self._sort()
        return self._sizes

    def _make(self, i: int) -> Instruction:
        return Instruction(self._addresses[i], self._sizes[i], self._mnemonics[self._mnemonic_ids[i]],
                           self._operands[i])

    def __contains__(self, address: object) -> bool:
        return isinstance(address, int) and self._index(address) >= 0

    def __getitem__(self, address: int) -> Instruction:
        i = self._index(address)
        if i < 0:
            raise KeyError(address)
        return self._make(i)

    def get(self, address: int, default: Instruction | None = None) -> Instruction | None:
        i = self._index(address) if isinstance(address, int) else -1
        return default if i < 0 else self._make(i)

    def __len__(self) -> int:
        return len(self._addresses)

    def __iter__(self) -> Iterator[int]:
        self._sort()
        return iter(self._addresses)

    def addresses(self) -> array:
        self._sort()
        return self._addresses

    def items(self) -> Iterator[tuple[int, Instruction]]:
        self._sort()
        return ((self._addresses[i], self._make(i)) for i in range(len(self._addresses)))

    def between(self, start: int, end: int) -> Iterator[Instruction]:
        """Instructions starting in [start, end), in address order."""
        self._sort()
        i = bisect.bisect_left(self._addresses, start)
        while i < len(self._addresses) and self._addresses[i] < end:
            yield self._make(i)
            i += 1

    def values(self) -> Iterator[Instruction]:
        return (ins for _, ins in self.items())


@dataclass(slots=True)
class BasicBlock:
    start: int
    end: int

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass
class Procedure:
    entry: int
    end: int
    basic_blocks: list[BasicBlock] = field(default_factory=list)
    callers: set[int] = field(default_factory=set)  # entry points of calling procedures
    callees: set[int] = field(default_factory=set)
    local_labels: dict[int, str] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)

    @property
    def length(self) -> int:
        """Bytes of code: the sum of the basic blocks (a procedure need not be contiguous)."""
        if not self.basic_blocks:
            return self.end - self.entry
        return sum(b.end - b.start for b in self.basic_blocks)

    def contains(self, address: int) -> bool:
        if not self.basic_blocks:
            return self.entry <= address < self.end
        return self.basic_block_at(address) is not None

    def basic_block_at(self, address: int) -> BasicBlock | None:
        """Blocks are kept sorted by address."""
        i = bisect.bisect_right(self.basic_blocks, address, key=lambda b: b.start)
        block = self.basic_blocks[i - 1] if i else None
        return block if block is not None and block.contains(address) else None

    def address_of_local_label(self, label: str) -> int:
        for address, name in self.local_labels.items():
            if name == label:
                return address
        return BAD_ADDRESS

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags


@dataclass
class Bookmark:
    address: int
    name: str

    def formatted_string(self) -> str:
        return f"{format_address(self.address)}: {self.name}" if self.name else format_address(self.address)


@dataclass
class ImportedSymbol:
    name: str
    address: int | None  # stub or pointer address, when known
    library: str = ""


@dataclass
class ExportedSymbol:
    name: str
    address: int


@dataclass(slots=True)
class DataItem:
    type: ByteType
    length: int


class DisassembledFile:
    """The analysed binary plus the user's annotations."""

    def __init__(self, path: str, cpu: str, file_type: str) -> None:
        self.path = path
        self.cpu = cpu
        self.file_type = file_type
        self.segments: list[Segment] = []
        self.entry_point: int = BAD_ADDRESS
        self.container_file_offset: int = 0  # offset of this slice inside a fat file
        self.names = NameTree()
        self.comments: dict[int, str] = {}
        self.inline_comments: dict[int, str] = {}
        self.instructions = InstructionTable()
        self.data_items: dict[int, DataItem] = {}
        self.strings: dict[int, str] = {}
        self.procedures: dict[int, Procedure] = {}
        self._procedure_starts: list[int] = []
        self._object_starts = array("Q")
        self._block_starts, self._block_ends, self._block_owners = array("Q"), array("Q"), array("Q")
        self.tags: dict[str, set[int]] = {}  # tag name -> tagged addresses
        self.bookmarks: list[Bookmark] = []
        self.imports: list[ImportedSymbol] = []
        self.exports: list[ExportedSymbol] = []
        self.function_starts: set[int] = set()
        self.pointer_targets: dict[int, int] = {}  # chained-fixup rebases: pointer slot -> target
        self.pointer_imports: dict[int, str] = {}  # chained-fixup binds: pointer slot -> imported symbol
        self.header_strings: dict[int, str] = {}  # Mach-O load-command paths (dylibs, rpaths), named like strings
        self.relocatable = False  # unrelocated object file: call targets are meaningless

    # Segments / sections ---------------------------------------------------

    def add_segment(self, segment: Segment) -> None:
        self.segments.append(segment)
        self.segments.sort(key=lambda s: s.start)

    def segment_for_virtual_address(self, address: int) -> Segment | None:
        for segment in self.segments:
            if segment.contains(address):
                return segment
        return None

    def has_segment_at(self, address: int) -> bool:
        return self.segment_for_virtual_address(address) is not None

    def section_at_virtual_address(self, address: int) -> Section | None:
        segment = self.segment_for_virtual_address(address)
        return segment.section_at(address) if segment else None

    def all_sections(self) -> list[Section]:
        return [s for seg in self.segments for s in seg.sections]

    def segment_named(self, name: str) -> Segment | None:
        return next((s for s in self.segments if s.name == name), None)

    def section_named(self, name: str) -> Section | None:
        return next((s for s in self.all_sections() if s.name == name), None)

    def read_bytes(self, address: int, length: int) -> bytes:
        segment = self.segment_for_virtual_address(address)
        return segment.read(address, length) if segment else b""

    @property
    def min_address(self) -> int:
        return self.segments[0].start if self.segments else 0

    # File offsets ----------------------------------------------------

    def virtual_address_from_file_offset(self, offset: int) -> int:
        for segment in self.segments:
            for section in segment.sections:
                if section.file_offset is not None and section.file_offset <= offset < section.file_offset + section.length:
                    return section.start + (offset - section.file_offset)
        # Mapped bytes outside every section (e.g. the Mach-O header at the start of __TEXT).
        for segment in self.segments:
            length = min(len(segment.data), segment.length)
            if segment.file_offset is not None and segment.file_offset <= offset < segment.file_offset + length:
                return segment.start + (offset - segment.file_offset)
        return BAD_ADDRESS

    def file_offset_for_virtual_address(self, address: int) -> int | None:
        segment = self.segment_for_virtual_address(address)
        if segment is None:
            return None
        section = segment.section_at(address)
        if section is not None and section.file_offset is not None:
            return section.file_offset + (address - section.start)
        if segment.file_offset is not None and address - segment.start < len(segment.data):
            return segment.file_offset + (address - segment.start)
        return None

    # Objects (instructions and data) ---------------------------------------

    def rebuild_object_index(self) -> None:
        starts = array("Q")
        for address in heapq.merge(self.instructions.addresses(), sorted(self.data_items)):
            if not starts or starts[-1] != address:
                starts.append(address)
        self._object_starts = starts
        self._procedure_starts = sorted(self.procedures)
        blocks = sorted((b.start, b.end, p.entry) for p in self.procedures.values()
                        for b in (p.basic_blocks or [BasicBlock(p.entry, p.end)]))
        self._block_starts = array("Q", (b[0] for b in blocks))
        self._block_ends = array("Q", (b[1] for b in blocks))
        self._block_owners = array("Q", (b[2] for b in blocks))

    def object_start_containing(self, address: int) -> int | None:
        i = bisect.bisect_right(self._object_starts, address)
        if not i:
            return None
        start = self._object_starts[i - 1]
        return start if address < start + self.byte_length_at(start) else None

    def byte_length_at(self, address: int) -> int:
        if address in self.instructions:
            return self.instructions[address].size
        if address in self.data_items:
            return self.data_items[address].length
        return 1

    def type_for_virtual_address(self, address: int) -> ByteType:
        if not self.has_segment_at(address):
            return ByteType.OUTSIDE
        if address in self.instructions:
            return ByteType.CODE
        if address in self.data_items:
            return self.data_items[address].type
        if self.object_start_containing(address) is not None:
            return ByteType.NEXT
        return ByteType.UNDEFINED

    def next_address_of_virtual_address(self, address: int) -> int:
        """Address of the object that follows the one at ``address``."""
        start = self.object_start_containing(address)
        if start is not None:
            return start + self.byte_length_at(start)
        return address + 1

    def previous_address_of_virtual_address(self, address: int) -> int:
        candidate = address - 1
        start = self.object_start_containing(candidate)
        return start if start is not None else candidate

    def matches_type(self, address: int, wanted: ByteType) -> bool:
        actual = self.type_for_virtual_address(address)
        if wanted == ByteType.DATA:
            return actual in DATA_TYPES
        if wanted == ByteType.PROCEDURE:
            return address in self.procedures
        return actual == wanted

    # Procedures -------------------------------------------------------------

    def procedure_at(self, address: int) -> Procedure | None:
        """The procedure whose basic blocks include ``address``."""
        i = bisect.bisect_right(self._block_starts, address)
        if not i or address >= self._block_ends[i - 1]:
            return None
        return self.procedures.get(self._block_owners[i - 1])

    def procedure_object_addresses(self, procedure: Procedure) -> Iterator[int]:
        """The objects (instructions) of a procedure, block by block in address order."""
        for block in procedure.basic_blocks or [BasicBlock(procedure.entry, procedure.end)]:
            address = block.start
            while address < block.end:
                yield address
                address = self.next_address_of_virtual_address(address)

    def procedure_index_at(self, address: int) -> int:
        procedure = self.procedure_at(address)
        return self._procedure_starts.index(procedure.entry) if procedure else -1

    def procedure_list(self) -> list[Procedure]:
        return [self.procedures[a] for a in self._procedure_starts]

    # Names ------------------------------------------------------------

    def name_for_virtual_address(self, address: int) -> str | None:
        return self.names.name_for_address(address)

    def set_name(self, address: int, name: str) -> None:
        self.names.set_name(name, address)

    def find_virtual_address_named(self, name: str) -> int:
        return self.names.address_for_name(name)

    def all_names(self) -> list[str]:
        return self.names.all_names()

    def all_named_addresses(self) -> list[int]:
        return self.names.all_addresses()

    def nearest_name_before_virtual_address(self, address: int) -> str | None:
        named = self.names.nearest_named_address_before(address)
        return None if named == BAD_ADDRESS else self.names.name_for_address(named)

    def friendly_name_for_virtual_address(self, address: int) -> str:
        """``name`` or ``name+offset`` or the bare address."""
        named = self.names.nearest_named_address_before(address)
        if named == BAD_ADDRESS:
            return format_address(address)
        name = self.names.name_for_address(named)
        procedure = self.procedure_at(address)
        if named != address and (procedure is None or not procedure.contains(named)):
            return format_address(address)
        return name if named == address else f"{name}+{address - named}"

    # Comments ---------------------------------------------------------------

    def comment_at_virtual_address(self, address: int) -> str | None:
        return self.comments.get(address)

    def inline_comment_at_virtual_address(self, address: int) -> str | None:
        return self.inline_comments.get(address)

    def set_comment(self, address: int, text: str) -> None:
        if text:
            self.comments[address] = text
        else:
            self.comments.pop(address, None)

    def set_inline_comment(self, address: int, text: str) -> None:
        if text:
            self.inline_comments[address] = text
        else:
            self.inline_comments.pop(address, None)

    # Strings ----------------------------------------------------------------

    def all_string_addresses(self) -> list[int]:
        return sorted(self.strings)

    def all_strings(self) -> list[str]:
        return [self.strings[a] for a in self.all_string_addresses()]

    # Tags -------------------------------------------------------------------

    def all_tags(self) -> list[str]:
        return sorted(self.tags)

    def add_tag(self, tag: str, address: int) -> None:
        if not tag:
            raise ValueError("a tag needs a name")
        self.tags.setdefault(tag, set()).add(address)
        procedure = self.procedures.get(address)
        if procedure is not None:
            procedure.tags.add(tag)

    def remove_tag(self, tag: str, address: int) -> None:
        addresses = self.tags.get(tag)
        if addresses is not None:
            addresses.discard(address)
            if not addresses:  # a tag on nothing is gone
                del self.tags[tag]
        procedure = self.procedures.get(address)
        if procedure is not None:
            procedure.tags.discard(tag)

    def has_tag(self, tag: str, address: int) -> bool:
        return address in self.tags.get(tag, ())

    def tags_at(self, address: int) -> list[str]:
        return sorted(t for t, addresses in self.tags.items() if address in addresses)

    # Bookmarks --------------------------------------------------------

    def bookmark_at(self, address: int) -> Bookmark | None:
        return next((b for b in self.bookmarks if b.address == address), None)

    def has_bookmark_at_virtual_address(self, address: int) -> bool:
        return self.bookmark_at(address) is not None

    def toggle_bookmark_at_virtual_address(self, address: int, name: str = "") -> bool:
        """Returns True when a bookmark was added, False when removed."""
        existing = self.bookmark_at(address)
        if existing is not None:
            self.bookmarks.remove(existing)
            return False
        self.bookmarks.append(Bookmark(address, name or self.friendly_name_for_virtual_address(address)))
        self.bookmarks.sort(key=lambda b: b.address)
        return True

    def rename_bookmark(self, address: int, name: str) -> bool:
        bookmark = self.bookmark_at(address)
        if bookmark is None:
            return False
        bookmark.name = name
        return True

    def find_bookmarks_named(self, name: str) -> list[Bookmark]:
        """Exact, case-sensitive, linear scan (can return several)."""
        return [b for b in self.bookmarks if b.name == name]

    def index_of_bookmark_at_address(self, address: int) -> int:
        return next((i for i, b in enumerate(self.bookmarks) if b.address == address), -1)

    def address_of_bookmark_at_index(self, index: int) -> int:
        return self.bookmarks[index].address if 0 <= index < len(self.bookmarks) else BAD_ADDRESS

    def name_of_bookmark_at_index(self, index: int) -> str | None:
        return self.bookmarks[index].name if 0 <= index < len(self.bookmarks) else None

    def all_bookmark_addresses(self) -> list[int]:
        return [b.address for b in self.bookmarks]

    # References --------------------------------------------------------

    def references_to(self, address: int) -> list[int]:
        segment = self.segment_for_virtual_address(address)
        return segment.references_to_address(address) if segment else []

    def references_from(self, address: int) -> list[int]:
        segment = self.segment_for_virtual_address(address)
        return segment.references_from_address(address) if segment else []

    def add_reference(self, source: int, target: int, data: bool = False) -> None:
        source_segment = self.segment_for_virtual_address(source)
        target_segment = self.segment_for_virtual_address(target)
        if source_segment is None or target_segment is None:
            return
        source_segment.add_reference(source, target, data)
        target_segment.references_to.setdefault(target, set()).add(source)

    def remove_reference(self, source: int, target: int) -> None:
        for segment in self.segments:
            segment.references_from.get(source, set()).discard(target)
            segment.references_to.get(target, set()).discard(source)
            segment.data_references.discard((source, target))

    def reference_is_data_reference(self, source: int, target: int) -> bool:
        segment = self.segment_for_virtual_address(source)
        return bool(segment and (source, target) in segment.data_references)

    def iter_section_ranges(self) -> Iterator[tuple[Segment, Section | None, AddressRange]]:
        for segment in self.segments:
            if not segment.sections:
                yield segment, None, AddressRange(segment.start, segment.length)
                continue
            cursor = segment.start
            for section in segment.sections:
                if section.start > cursor:  # gap between sections
                    yield segment, None, AddressRange(cursor, section.start - cursor)
                yield segment, section, AddressRange(section.start, section.length)
                cursor = max(cursor, section.end)
            if cursor < segment.end:
                yield segment, None, AddressRange(cursor, segment.end - cursor)

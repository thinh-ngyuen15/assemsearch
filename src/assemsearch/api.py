"""Scripting API with camelCase method names.

    from assemsearch.api import Document
    doc = Document.open("a.out")
    addr = doc.getAddressForName("_main")

It has no text/byte/regex search of its own: scripts filter
``getStringsList()`` / ``getLabelsList()`` themselves.
"""

from __future__ import annotations

from assemsearch.document import Document as _Document
from assemsearch.goto import parse_address_string
from assemsearch.model import DisassembledFile
from assemsearch.model import Procedure as _Procedure
from assemsearch.model import Section as _Section
from assemsearch.model import Segment as _Segment
from assemsearch.types import BAD_ADDRESS, AddressRange, ByteType

TYPE_UNDEFINED = ByteType.UNDEFINED
TYPE_CODE = ByteType.CODE
TYPE_PROCEDURE = ByteType.PROCEDURE
TYPE_ASCII = ByteType.ASCII
TYPE_DATA = ByteType.DATA


class Tag:
    def __init__(self, name: str) -> None:
        self.name = name

    def getName(self) -> str:
        return self.name

    def __eq__(self, other) -> bool:
        return isinstance(other, Tag) and other.name == self.name

    def __repr__(self) -> str:
        return f"Tag({self.name!r})"


class Section:
    def __init__(self, document: "Document", section: _Section) -> None:
        self._doc, self._section = document, section

    def getName(self) -> str:
        return self._section.name

    def getStartingAddress(self) -> int:
        return self._section.start

    def getLength(self) -> int:
        return self._section.length


class Procedure:
    def __init__(self, document: "Document", procedure: _Procedure) -> None:
        self._doc, self._procedure = document, procedure

    def getEntryPoint(self) -> int:
        return self._procedure.entry

    def getBasicBlockCount(self) -> int:
        return len(self._procedure.basic_blocks)

    def getBasicBlockAtAddress(self, addr: int):
        block = self._procedure.basic_block_at(addr)
        return (block.start, block.end) if block else None

    def getAllCallerProcedures(self) -> list["Procedure"]:
        return [Procedure(self._doc, self._doc._file.procedures[a]) for a in sorted(self._procedure.callers)]

    def getAllCalleeProcedures(self) -> list["Procedure"]:
        return [Procedure(self._doc, self._doc._file.procedures[a]) for a in sorted(self._procedure.callees)]

    def localLabelAtAddress(self, addr: int) -> str | None:
        return self._procedure.local_labels.get(addr)

    def addressOfLocalLabel(self, label: str) -> int:
        return self._procedure.address_of_local_label(label)

    def hasTag(self, tag: Tag) -> bool:
        return self._procedure.has_tag(tag.name)


class Segment:
    def __init__(self, document: "Document", segment: _Segment) -> None:
        self._doc, self._segment = document, segment
        self._file: DisassembledFile = document._file

    def _in(self, addr: int) -> bool:
        return self._segment.contains(addr)

    def getName(self) -> str:
        return self._segment.name

    def getStartingAddress(self) -> int:
        return self._segment.start

    def getLength(self) -> int:
        return self._segment.length

    def getSectionsList(self) -> list[Section]:
        return [Section(self._doc, s) for s in self._segment.sections]

    def _labels(self) -> list[tuple[int, str]]:
        return [(a, n) for a, n in self._file.names.items() if self._in(a)]

    def getLabelCount(self) -> int:
        return len(self._labels())

    def labelIterator(self):
        return iter(n for _, n in self._labels())

    def getLabelsList(self) -> list[str]:
        return [n for _, n in self._labels()]

    def getNamedAddresses(self) -> list[int]:
        return [a for a, _ in self._labels()]

    def getNameAtAddress(self, addr: int) -> str | None:
        return self._file.name_for_virtual_address(addr)

    def getDemangledNameAtAddress(self, addr: int) -> str | None:
        return self.getNameAtAddress(addr)

    def _strings(self) -> list[tuple[int, str]]:
        return [(a, self._file.strings[a]) for a in self._file.all_string_addresses() if self._in(a)]

    def getStringCount(self) -> int:
        return len(self._strings())

    def getStringAtIndex(self, index: int) -> str | None:
        strings = self._strings()
        return strings[index][1] if 0 <= index < len(strings) else None

    def getStringAddressAtIndex(self, index: int) -> int:
        strings = self._strings()
        return strings[index][0] if 0 <= index < len(strings) else BAD_ADDRESS

    def getStringsList(self) -> list[tuple[str, int]]:
        return [(s, a) for a, s in self._strings()]

    def getNextAddressWithType(self, addr: int, typeValue: int) -> int:
        """The search begins at the given address and stays in this segment; BAD_ADDRESS when nothing is found."""
        found = self._doc._document.find_next_address_of_type(addr, ByteType(typeValue))
        return found if found != BAD_ADDRESS and self._in(found) else BAD_ADDRESS

    def getReferencesOfAddress(self, addr: int) -> list[int]:
        return self._file.references_to(addr)

    def getReferencesFromAddress(self, addr: int) -> list[int]:
        return self._file.references_from(addr)

    def getTypeAtAddress(self, addr: int) -> int:
        return int(self._file.type_for_virtual_address(addr))

    def getProcedureAtAddress(self, addr: int) -> Procedure | None:
        return self._doc.getProcedureAtAddress(addr)

    def getProcedureIndexAtAddress(self, addr: int) -> int:
        return self._file.procedure_index_at(addr)

    def getCommentAtAddress(self, addr: int) -> str | None:
        return self._file.comment_at_virtual_address(addr)

    def getInlineCommentAtAddress(self, addr: int) -> str | None:
        return self._file.inline_comment_at_virtual_address(addr)


class Document:
    def __init__(self, document: _Document) -> None:
        self._document = document
        self._file = document.file

    @classmethod
    def open(cls, path: str, restore: bool = True, **options) -> "Document":
        """Loads and analyses ``path``; ``restore`` reapplies a saved ``.asdb`` like the shell does.

        A database saved for different contents of the binary is not applied (a warning is issued).
        """
        import warnings

        from assemsearch import database
        from assemsearch.loaders import load_file
        file = load_file(path, **options)
        if restore:
            try:
                database.load(file)
            except database.DatabaseMismatch as error:
                warnings.warn(str(error), stacklevel=2)
        return cls(_Document(file))

    def saveDatabase(self, path: str | None = None) -> str:
        """Saves names, comments, tags and bookmarks (assemsearch addition); returns the file written."""
        from assemsearch import database
        return str(database.save(self._file, path))

    # Names
    def getAddressForName(self, name: str) -> int:
        return self._file.find_virtual_address_named(name)

    def getNameAtAddress(self, addr: int) -> str | None:
        return self._file.name_for_virtual_address(addr)

    def getDemangledNameAtAddress(self, addr: int) -> str | None:
        return self.getNameAtAddress(addr)

    def setNameAtAddress(self, addr: int, name: str) -> None:
        self._file.set_name(addr, name)

    def parseAddressString(self, text: str) -> int:
        return parse_address_string(self._file, text)

    # Segments / sections / containment
    def getSegmentCount(self) -> int:
        return len(self._file.segments)

    def getSegment(self, index: int) -> Segment | None:
        return Segment(self, self._file.segments[index]) if 0 <= index < len(self._file.segments) else None

    def getSegmentsList(self) -> list[Segment]:
        return [Segment(self, s) for s in self._file.segments]

    def getSegmentByName(self, name: str) -> Segment | None:
        segment = self._file.segment_named(name)
        return Segment(self, segment) if segment else None

    def getSectionByName(self, name: str) -> Section | None:
        section = self._file.section_named(name)
        return Section(self, section) if section else None

    def getSegmentAtAddress(self, addr: int) -> Segment | None:
        segment = self._file.segment_for_virtual_address(addr)
        return Segment(self, segment) if segment else None

    def getSegmentIndexAtAddress(self, addr: int) -> int:
        segment = self._file.segment_for_virtual_address(addr)
        return self._file.segments.index(segment) if segment else -1

    def getSectionAtAddress(self, addr: int) -> Section | None:
        section = self._file.section_at_virtual_address(addr)
        return Section(self, section) if section else None

    def getSectionIndexAtAddress(self, addr: int) -> int:
        section = self._file.section_at_virtual_address(addr)
        return self._file.all_sections().index(section) if section else -1

    def getProcedureAtAddress(self, addr: int) -> Procedure | None:
        procedure = self._file.procedure_at(addr)
        return Procedure(self, procedure) if procedure else None

    def getProcedureIndexAtAddress(self, addr: int) -> int:
        return self._file.procedure_index_at(addr)

    # File offsets
    def getAddressFromFileOffset(self, offset: int) -> int:
        return self._file.virtual_address_from_file_offset(offset)

    def getFileOffsetFromAddress(self, addr: int) -> int:
        offset = self._file.file_offset_for_virtual_address(addr)
        return -1 if offset is None else offset

    # Cursor
    def getCurrentAddress(self) -> int:
        return self._document.cursor

    def getCurrentProcedure(self) -> Procedure | None:
        return self.getProcedureAtAddress(self._document.cursor)

    def getHighlightedWord(self) -> str | None:
        target = self._document.address_written_at_cursor()
        return self._file.name_for_virtual_address(target) if target != BAD_ADDRESS else None

    def getSelectionAddressRange(self) -> tuple[int, int]:
        sel = self._document.selection
        return (sel.location, sel.end) if sel else (self._document.cursor, self._document.cursor)

    def moveCursorAtAddress(self, addr: int) -> bool:
        return self._document.move_cursor_to_virtual_address(addr)

    def moveCursorAtEntryPoint(self) -> bool:
        return self._document.move_cursor_to_virtual_address(self._file.entry_point)

    def selectAddressRange(self, addrRange) -> None:
        start, end = addrRange
        self._document.move_cursor_to_virtual_address_range(AddressRange(start, end - start))

    def gotoVirtualAddressString(self, text: str) -> bool:
        return self._document.goto_virtual_address_string(text)

    # Comments
    def getCommentAtAddress(self, addr: int) -> str | None:
        return self._file.comment_at_virtual_address(addr)

    def getInlineCommentAtAddress(self, addr: int) -> str | None:
        return self._file.inline_comment_at_virtual_address(addr)

    def setCommentAtAddress(self, addr: int, text: str) -> None:
        self._file.set_comment(addr, text)

    def setInlineCommentAtAddress(self, addr: int, text: str) -> None:
        self._file.set_inline_comment(addr, text)

    # Tags
    def getTagWithName(self, name: str) -> Tag | None:
        return Tag(name) if name in self._file.tags else None

    def buildTag(self, name: str) -> Tag:
        self._file.tags.setdefault(name, set())
        return Tag(name)

    def addTagAtAddress(self, tag: Tag, addr: int) -> None:
        self._file.add_tag(tag.name, addr)

    def hasTagAtAddress(self, tag: Tag, addr: int) -> bool:
        return self._file.has_tag(tag.name, addr)

    def getTagListAtAddress(self, addr: int) -> list[Tag]:
        return [Tag(t) for t in self._file.tags_at(addr)]

    # Bookmarks
    def getBookmarks(self) -> list[int]:
        return self._file.all_bookmark_addresses()

    def hasBookmarkAtAddress(self, addr: int) -> bool:
        return self._file.has_bookmark_at_virtual_address(addr)

    def getBookmarkName(self, addr: int) -> str | None:
        bookmark = self._file.bookmark_at(addr)
        return bookmark.name if bookmark else None

    def setBookmarkAtAddress(self, addr: int, name: str = "") -> None:
        if not self._file.has_bookmark_at_virtual_address(addr):
            self._file.toggle_bookmark_at_virtual_address(addr, name)
        elif name:
            self._file.rename_bookmark(addr, name)

    def removeBookmarkAtAddress(self, addr: int) -> None:
        if self._file.has_bookmark_at_virtual_address(addr):
            self._file.toggle_bookmark_at_virtual_address(addr)

    def findBookmarkWithName(self, name: str) -> list[int]:
        """All bookmarks with exactly this name (case-sensitive)."""
        return [b.address for b in self._file.find_bookmarks_named(name)]

    # References
    def getReferencesOfAddress(self, addr: int) -> list[int]:
        return self._file.references_to(addr)

    def getReferencesFromAddress(self, addr: int) -> list[int]:
        return self._file.references_from(addr)

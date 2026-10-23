"""Document: cursor, navigation history and the menu-level search actions.

Covers Find actions, Go To / Back, XREF navigation, structural navigation
and bookmark jumps.  Failures that a GUI would
signal with a beep return ``False``/``None`` and record ``last_beep``.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from assemsearch.analysis import decode_string
from assemsearch.find import FindContext, FindMode, SearchEngine, data_to_find_for_text_search
from assemsearch.goto import GotoType, parse_address_string, resolve_goto
from assemsearch.listing import instruction_text
from assemsearch.model import DisassembledFile, Procedure
from assemsearch.preferences import Preferences
from assemsearch.types import BAD_ADDRESS, AddressRange, ByteType, format_address


class FindPanelAction(enum.IntEnum):
    """NSFindPanelAction tags."""

    SHOW = 1
    NEXT = 2
    PREVIOUS = 3
    SET_FIND_STRING = 7


@dataclass
class NavigationStack:
    back: list[int] = field(default_factory=list)
    forward: list[int] = field(default_factory=list)

    def push(self, address: int) -> None:
        if not self.back or self.back[-1] != address:
            self.back.append(address)
        self.forward.clear()

    @property
    def is_empty(self) -> bool:
        return not self.back


class Document:
    def __init__(self, disassembled_file: DisassembledFile, prefs: Preferences | None = None) -> None:
        self.file = disassembled_file
        self.prefs = prefs or Preferences.in_memory()
        self.navigation = NavigationStack()
        self.find_context: FindContext | None = None
        self.selection: AddressRange | None = None
        self.last_beep = ""
        self.database_warning = ""  # set when a saved database was not restored (see database.load)
        start = disassembled_file.entry_point
        if start == BAD_ADDRESS:
            start = disassembled_file.min_address
        self.cursor = start

    @property
    def display_name(self) -> str:
        from pathlib import Path
        return Path(self.file.path).name

    def beep(self, reason: str = "") -> None:
        self.last_beep = reason or "beep"

    # Cursor -------------------------------------------------------------------

    def move_cursor_to_virtual_address(self, address: int) -> bool:
        if not self.file.has_segment_at(address):
            self.beep("address outside of the file")
            return False
        start = self.file.object_start_containing(address)
        self.cursor = start if start is not None else address
        self.selection = None
        return True

    def move_cursor_to_virtual_address_range(self, rng: AddressRange) -> None:
        self.cursor = rng.location
        self.selection = rng

    @property
    def current_procedure(self) -> Procedure | None:
        return self.file.procedure_at(self.cursor)

    # Go To ------------------------------------------------------------------

    def goto_virtual_address(self, address: int) -> bool:
        if address == BAD_ADDRESS or not self.file.has_segment_at(address):
            self.beep("invalid address")
            return False
        self.navigation.push(self.cursor)
        return self.move_cursor_to_virtual_address(address)

    def goto_virtual_address_string(self, text: str) -> bool:
        return self.goto_virtual_address(parse_address_string(self.file, text))

    def goto(self, text: str, goto_type: int = GotoType.ADDRESS) -> bool:
        """The Go To sheet's proceed button (raises GotoError for alerts)."""
        if goto_type != GotoType.ADDRESS:
            self.prefs.update(last_goto_file_offset_mode=int(goto_type))
        address = resolve_goto(self.file, text, goto_type)
        if goto_type == GotoType.ADDRESS:
            return self.goto_virtual_address(address)
        return self.goto_virtual_address_string(format_address(address))

    def go_back(self) -> bool:
        if self.navigation.is_empty:
            self.beep("navigation stack is empty")
            return False
        self.navigation.forward.append(self.cursor)
        return self.move_cursor_to_virtual_address(self.navigation.back.pop())

    def go_forward(self) -> bool:
        if not self.navigation.forward:
            self.beep("no forward history")
            return False
        self.navigation.back.append(self.cursor)
        return self.move_cursor_to_virtual_address(self.navigation.forward.pop())

    def goto_offset_in_procedure(self, offset: int) -> bool:
        """``entry + offset``, which must be inside the procedure (whose blocks need not be contiguous)."""
        procedure = self.current_procedure
        if procedure is None or offset < 0 or not procedure.contains(procedure.entry + offset):
            self.beep("no procedure / offset out of range")
            return False
        return self.goto_virtual_address(procedure.entry + offset)

    def goto_top_of_procedure(self) -> bool:
        procedure = self.current_procedure
        if procedure is None:
            self.beep("no procedure")
            return False
        return self.goto_virtual_address(procedure.entry)

    def address_written_at_cursor(self) -> int:
        """The operand target under the cursor (first reference from it)."""
        targets = self.file.references_from(self.cursor)
        return targets[0] if targets else BAD_ADDRESS

    def follow_address(self) -> bool:
        """Go To Address at Cursor."""
        return self.goto_virtual_address(self.address_written_at_cursor())

    # Find ---------------------------------------------------------------------

    def set_find(self, text: str, mode: int | None = None, case_sensitive: bool | None = None,
                 wrapping: bool | None = None, number_length: int | None = None,
                 little_endian: bool | None = None) -> FindContext:
        """The Find sheet's proceed button: validate, persist options, store the context."""
        prefs = self.prefs
        mode = prefs.last_find_mode if mode is None else int(mode)
        case_sensitive = prefs.last_find_case_sensitive if case_sensitive is None else case_sensitive
        wrapping = prefs.last_find_wrapping if wrapping is None else wrapping
        number_length = prefs.last_find_number_length if number_length is None else number_length
        little_endian = prefs.last_find_number_little_endian if little_endian is None else little_endian
        context = FindContext.from_string(text, mode, case_sensitive, wrapping, number_length, little_endian)
        prefs.update(last_find_mode=mode, last_find_case_sensitive=case_sensitive, last_find_wrapping=wrapping,
                     last_find_number_length=number_length, last_find_number_little_endian=little_endian,
                     find_pasteboard=text)
        self.find_context = context
        return context

    def use_selection_for_find(self, text: str | None = None) -> FindContext | None:
        """Use Selection for Find: seeds a text search from the selection (or given word).

        A selection in code reads as its instruction text, searched as *String in
        Assembly*; elsewhere the selected bytes are read as a string.  Without a
        selection the item under the cursor counts.
        """
        mode = self.find_context.mode if self.find_context else FindMode.STRING_IN_ASSEMBLY
        if mode not in (FindMode.ASCII_STRING, FindMode.STRING_IN_ASSEMBLY, FindMode.STRING_IN_COMMENTS):
            mode = FindMode.STRING_IN_ASSEMBLY
        if text is None:
            selection = self.selection or AddressRange(self.cursor, self.file.byte_length_at(self.cursor))
            start = self.file.object_start_containing(selection.location)
            if start in self.file.instructions:
                text, mode = instruction_text(self.file, start), FindMode.STRING_IN_ASSEMBLY
            else:
                text = decode_string(self.file.read_bytes(selection.location, selection.length))
            if not text:
                self.beep("nothing to find in the selection")
                return None
        self.prefs.update(find_pasteboard=text)
        self.find_context = FindContext(mode, self.prefs.last_find_case_sensitive, self.prefs.last_find_wrapping,
                                        data_to_find_for_text_search(text), text)
        return self.find_context

    def _context_or_pasteboard(self) -> FindContext | None:
        if self.find_context is None and self.prefs.find_pasteboard:
            self.use_selection_for_find(self.prefs.find_pasteboard)
        return self.find_context

    def move_cursor_at_next_occurrence(self, cancelation=None) -> AddressRange | None:
        return self._occurrence(False, cancelation)

    def move_cursor_at_previous_occurrence(self, cancelation=None) -> AddressRange | None:
        return self._occurrence(True, cancelation)

    def _occurrence(self, backwards: bool, cancelation) -> AddressRange | None:
        context = self._context_or_pasteboard()
        if context is None:
            self.beep("no find context")
            return None
        engine = SearchEngine(self.file, self.prefs.show_hex_column)
        finder = engine.find_previous if backwards else engine.find_next
        hit = finder(self.cursor, context, cancelation)
        if hit is None:
            self.beep("not found")
            return None
        self.move_cursor_to_virtual_address_range(hit)
        return hit

    def perform_find_panel_action(self, tag: int, text: str | None = None) -> AddressRange | FindContext | None:
        tag = FindPanelAction(tag)
        if tag == FindPanelAction.NEXT:
            return self.move_cursor_at_next_occurrence()
        if tag == FindPanelAction.PREVIOUS:
            return self.move_cursor_at_previous_occurrence()
        if tag == FindPanelAction.SET_FIND_STRING:
            return self.use_selection_for_find(text)
        if text is None:
            return None
        self.set_find(text)
        return self.move_cursor_at_next_occurrence()

    # XREFs ----------------------------------------------------------------------

    def next_reference_to_address_referenced_at(self, address: int, backwards: bool = False) -> int:
        targets = self.file.references_from(address)
        if not targets:
            return BAD_ADDRESS
        refs = self.file.references_to(targets[0])
        if not refs:
            return BAD_ADDRESS
        if backwards:
            earlier = [r for r in refs if r < address]
            return earlier[-1] if earlier else refs[-1]
        later = [r for r in refs if r > address]
        return later[0] if later else refs[0]

    def move_to_next_xref(self, backwards: bool = False) -> bool:
        target = self.next_reference_to_address_referenced_at(self.cursor, backwards)
        if target == BAD_ADDRESS or target == self.cursor:
            self.beep("no other reference")
            return False
        return self.move_cursor_to_virtual_address(target)

    def references_to_rows(self, address: int) -> list[dict]:
        return self._reference_rows(self.file.references_to(address))

    def _reference_rows(self, references: list[int]) -> list[dict]:
        rows = []
        for ref in references:
            procedure = self.file.procedure_at(ref)
            comment = self.file.name_for_virtual_address(procedure.entry) if procedure else ""
            rows.append({"address": ref, "addressRepresentation": format_address(ref),
                         "comment": f"{self.file.friendly_name_for_virtual_address(ref)}"
                                    + (f" (in {comment})" if comment else "")})
        return rows

    def references_from_rows(self, address: int) -> list[dict]:
        return [{"address": t, "addressRepresentation": format_address(t),
                 "comment": self.file.friendly_name_for_virtual_address(t)}
                for t in self.file.references_from(address)]

    def show_references_to_here(self):
        from assemsearch.lists import ListOfAddresses
        address = self.address_written_at_cursor()
        if address == BAD_ADDRESS:
            address = self.cursor
        return ListOfAddresses(self.references_to_rows(address), f"References to {format_address(address)}",
                               self.prefs)

    def show_references_from_here(self):
        from assemsearch.lists import ListOfAddresses
        return ListOfAddresses(self.references_from_rows(self.cursor),
                               f"References from {format_address(self.cursor)}", self.prefs)

    def show_places_calling_this_procedure(self):
        from assemsearch.lists import ListOfAddresses
        procedure = self.current_procedure
        if procedure is None:
            self.beep("no procedure")
            return None
        return ListOfAddresses(self.references_to_rows(procedure.entry),
                               f"References to {format_address(procedure.entry)}", self.prefs)

    def show_references_to_objective_c_method(self):
        """Places referencing the selector implemented by the current method.

        Code reaches a selector through its ``__objc_selrefs`` slot: directly
        (``adrp``+``ldr``, RIP-relative ``mov``) or through an ``objc_msgSend$sel``
        stub in ``__objc_stubs``, whose callers are then the places.
        """
        from assemsearch.lists import ListOfAddresses
        doc = self.file
        procedure = self.current_procedure
        name = doc.name_for_virtual_address(procedure.entry) if procedure else None
        if not name or name[:2] not in ("-[", "+[") or " " not in name:
            self.beep("not an Objective-C method")
            return None
        selector = name[name.index(" ") + 1:-1]
        places: set[int] = set()
        for string in (a for a, s in doc.strings.items() if s == selector):
            for slot in doc.references_to(string):
                loads = [slot] if slot in doc.instructions else doc.references_to(slot)
                for load in (a for a in loads if a in doc.instructions):
                    section = doc.section_at_virtual_address(load)
                    stub = doc.procedure_at(load) if section and section.name == "__objc_stubs" else None
                    places.update(doc.references_to(stub.entry) if stub else [load])
        return ListOfAddresses(self._reference_rows(sorted(places)), f"References to {selector}", self.prefs)

    # structural navigation ------------------------------------------------------

    def find_next_address_of_type(self, address: int, wanted: ByteType, wrapping: bool = False) -> int:
        """``findNextAddress:ofTypeOrMetaType:wrapping:`` (includes ``address``)."""
        doc = self.file
        candidates: list[int]
        if wanted == ByteType.PROCEDURE:
            candidates = sorted(doc.procedures)
        elif wanted == ByteType.CODE:
            candidates = sorted(doc.instructions)
        elif wanted == ByteType.UNDEFINED:
            return self._next_undefined(address, wrapping)
        else:
            candidates = sorted(a for a in doc.data_items if doc.matches_type(a, wanted))
        later = [a for a in candidates if a >= address]
        if later:
            return later[0]
        return candidates[0] if wrapping and candidates else BAD_ADDRESS

    def _next_undefined(self, address: int, wrapping: bool) -> int:
        doc = self.file
        for _segment, _section, rng in doc.iter_section_ranges():
            if rng.end <= address:
                continue
            current = max(address, rng.location)
            while current < rng.end:
                if doc.type_for_virtual_address(current) == ByteType.UNDEFINED:
                    return current
                current = doc.next_address_of_virtual_address(current)
        return self._next_undefined(doc.min_address, False) if wrapping and address > doc.min_address else BAD_ADDRESS

    def move_cursor_at_next_address_of_type(self, wanted: ByteType) -> bool:
        start = self.file.next_address_of_virtual_address(self.cursor)
        if wanted != ByteType.UNDEFINED:
            # Skip the run we are in (e.g. Next Code from code goes past the current block of code).
            while self.file.has_segment_at(start) and self.file.matches_type(start, wanted) and wanted != ByteType.PROCEDURE:
                start = self.file.next_address_of_virtual_address(start)
        else:
            while self.file.has_segment_at(start) and self.file.type_for_virtual_address(start) == ByteType.UNDEFINED:
                start = self.file.next_address_of_virtual_address(start)
        target = self.find_next_address_of_type(start, wanted)
        if target == BAD_ADDRESS:
            self.beep("nothing found")
            return False
        return self.move_cursor_to_virtual_address(target)

    def next_code(self) -> bool:
        return self.move_cursor_at_next_address_of_type(ByteType.CODE)

    def next_data(self) -> bool:
        return self.move_cursor_at_next_address_of_type(ByteType.DATA)

    def next_procedure(self) -> bool:
        return self.move_cursor_at_next_address_of_type(ByteType.PROCEDURE)

    def next_unexplored(self) -> bool:
        return self.move_cursor_at_next_address_of_type(ByteType.UNDEFINED)

    def next_section(self) -> bool:
        sections = [s for s in self.file.all_sections() if s.start > self.cursor]
        if not sections:
            self.beep("no next section")
            return False
        return self.move_cursor_to_virtual_address(sections[0].start)

    def previous_section(self) -> bool:
        current = self.file.section_at_virtual_address(self.cursor)
        limit = current.start if current else self.cursor
        sections = [s for s in self.file.all_sections() if s.start < limit]
        if not sections:
            self.beep("no previous section")
            return False
        return self.move_cursor_to_virtual_address(sections[-1].start)

    # Text export ---------------------------------------------------------------------

    def produce_text_file(self, path) -> int:
        from assemsearch.export import file_lines, write_lines
        return write_lines(path, file_lines(self.file, self.prefs.show_hex_column))

    def produce_text_file_for_current_procedure(self, path) -> int | None:
        from assemsearch.export import procedure_lines, write_lines
        procedure = self.current_procedure
        if procedure is None:
            self.beep("no procedure")
            return None
        return write_lines(path, procedure_lines(self.file, procedure, self.prefs.show_hex_column))

    def produce_text_file_for_current_selection(self, path) -> int | None:
        from assemsearch.export import range_lines, write_lines
        if self.selection is None:
            self.beep("no selection")
            return None
        return write_lines(path, range_lines(self.file, self.selection, self.prefs.show_hex_column))

    # bookmarks -------------------------------------------------------------------

    def toggle_bookmark(self, name: str = "") -> bool:
        return self.file.toggle_bookmark_at_virtual_address(self.cursor, name)

    def bookmarks_menu(self) -> list[str]:
        return [b.formatted_string() for b in self.file.bookmarks] or ["No bookmarks"]

    def bookmark_clicked(self, index: int) -> bool:
        return self.goto_virtual_address(self.file.address_of_bookmark_at_index(index))

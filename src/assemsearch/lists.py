"""Filterable list dialogs: list of addresses, segments, sections, imports, exports."""

from __future__ import annotations

from dataclasses import dataclass, field

from assemsearch import fuzzy
from assemsearch.model import DisassembledFile
from assemsearch.preferences import Preferences
from assemsearch.types import format_address


@dataclass
class ListOfAddresses:
    """``ListOfAddressesWindowController``: rows are {address, addressRepresentation, comment}."""

    rows: list[dict]
    label: str
    prefs: Preferences = field(default_factory=Preferences.in_memory)
    search: str = ""
    filtered: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.update_search(self.search)

    def update_search(self, text: str) -> list[dict]:
        """``listUpdateSearch:``: score address text and comment, keep the best, sort ascending."""
        self.search = text
        fuzzy_on = self.prefs.enable_fuzzy_search
        scored = []
        for index, row in enumerate(self.rows):
            scores = [s for s in (fuzzy.score(row.get("addressRepresentation", ""), text, fuzzy_on),
                                  fuzzy.score(row.get("comment", ""), text, fuzzy_on)) if s]
            if scores:
                scored.append({"score": min(scores), "object": index})
        scored.sort(key=lambda d: d["score"])
        self.filtered = [d["object"] for d in scored]
        return self.results()

    def results(self) -> list[dict]:
        return [self.rows[i] for i in self.filtered]

    def address_at(self, index: int) -> int | None:
        results = self.results()
        return results[index]["address"] if 0 <= index < len(results) else None


def segments_list(doc: DisassembledFile, prefs: Preferences | None = None) -> ListOfAddresses:
    rows = [{"address": s.start, "addressRepresentation": format_address(s.start),
             "comment": f"{doc.friendly_name_for_virtual_address(s.start)} {s.name or 'unnamed segment'}"}
            for s in doc.segments]
    return ListOfAddresses(rows, "Segments", prefs or Preferences.in_memory())


def sections_list(doc: DisassembledFile, prefs: Preferences | None = None) -> ListOfAddresses:
    rows = [{"address": s.start, "addressRepresentation": format_address(s.start),
             "comment": f"{doc.friendly_name_for_virtual_address(s.start)} {s.name or 'unnamed section'}"}
            for s in doc.all_sections()]
    return ListOfAddresses(rows, "Sections", prefs or Preferences.in_memory())


@dataclass
class SymbolTable:
    """Imports/Exports windows: an ArrayFilterPredicate over the symbol name."""

    symbols: list
    label: str
    prefs: Preferences = field(default_factory=Preferences.in_memory)
    search: str = ""

    def search_field_changed(self, text: str) -> list:
        self.search = text
        predicate = fuzzy.FuzzyPredicate(lambda s: s.name, text, self.prefs.enable_fuzzy_search)
        return predicate.filter(self.symbols)

    def results(self) -> list:
        return self.search_field_changed(self.search)


def imports_window(doc: DisassembledFile, prefs: Preferences | None = None) -> SymbolTable:
    return SymbolTable(sorted(doc.imports, key=lambda s: s.name), "Imports", prefs or Preferences.in_memory())


def exports_window(doc: DisassembledFile, prefs: Preferences | None = None) -> SymbolTable:
    return SymbolTable(sorted(doc.exports, key=lambda s: s.name), "Exports", prefs or Preferences.in_memory())

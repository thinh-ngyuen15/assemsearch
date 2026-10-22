"""Sidebar Labels | Proc. | Str list with search field and Tag Scope."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from assemsearch import fuzzy
from assemsearch.model import DisassembledFile
from assemsearch.preferences import Preferences

SEARCH_FIELD = "staticNamesSearchField"


class DisplayMode(enum.IntEnum):
    LABELS = 0
    PROCEDURES = 1
    STRINGS = 2


@dataclass
class Row:
    address: int
    name: str
    score: int = 1


@dataclass
class Sidebar:
    file: DisassembledFile
    prefs: Preferences = field(default_factory=Preferences.in_memory)
    mode: DisplayMode = DisplayMode.LABELS
    search: str = ""
    tag_scope_visible: bool = False
    selected_tags: set[str] = field(default_factory=set)
    sort_descriptor: tuple[str, bool] | None = None  # (column "address"|"name", ascending)

    def rows_for_mode(self) -> list[Row]:
        doc = self.file
        if self.mode == DisplayMode.PROCEDURES:
            return [Row(p.entry, doc.name_for_virtual_address(p.entry) or f"sub_{p.entry:x}")
                    for p in doc.procedure_list()]
        if self.mode == DisplayMode.STRINGS:
            return [Row(a, doc.strings[a]) for a in doc.all_string_addresses()]
        return [Row(a, n) for a, n in doc.names.items()]

    # Tag Scope ------------------------------------------------------------------

    def show_search_scope_option(self) -> None:
        self.tag_scope_visible = True

    def hide_search_scope_option(self) -> None:
        """Closing the Tag Scope resets the filter to all tags."""
        self.tag_scope_visible = False
        self.selected_tags.clear()

    def select_tags(self, *tags: str) -> None:
        self.show_search_scope_option()
        self.selected_tags = set(tags)

    def _passes_tags(self, address: int) -> bool:
        if not self.tag_scope_visible or not self.selected_tags or self.mode == DisplayMode.STRINGS:
            return True
        doc = self.file
        if any(doc.has_tag(tag, address) for tag in self.selected_tags):
            return True
        procedure = doc.procedure_at(address)
        return procedure is not None and any(procedure.has_tag(tag) for tag in self.selected_tags)

    # Search ---------------------------------------------------------------------

    def update_search(self, text: str | None = None) -> list[Row]:
        """``staticNamesUpdateSearch:``."""
        if text is not None:
            self.search = text
        fuzzy_on = self.prefs.enable_fuzzy_search
        rows = []
        for row in self.rows_for_mode():
            score = fuzzy.score(row.name, self.search, fuzzy_on)
            if score and self._passes_tags(row.address):
                row.score = score
                rows.append(row)
        if self.sort_descriptor is not None:
            column, ascending = self.sort_descriptor
            key = (lambda r: r.address) if column == "address" else (lambda r: r.name.lower())
            rows.sort(key=key, reverse=not ascending)
        else:
            rows.sort(key=lambda r: r.score)
        return rows

    def set_mode(self, mode: DisplayMode) -> list[Row]:
        self.mode = DisplayMode(mode)
        return self.update_search()

    def add_current_search_value_to_search_history(self) -> None:
        self.prefs.add_recent_search(SEARCH_FIELD, self.search)

    def recent_searches(self) -> list[str]:
        return list(self.prefs.recent_searches.get(SEARCH_FIELD, []))

    def clear_recent_searches(self) -> None:
        self.prefs.clear_recent_searches(SEARCH_FIELD)

"""Command palette ("Search Anything").

No prefix searches commands, ``@`` symbols, ``"`` strings and ``#`` documents.
Filtering uses the fuzzy predicate on the entry title.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable

from assemsearch import fuzzy
from assemsearch.preferences import Preferences

PLACEHOLDER = "Search Anything"
TOOLTIP = 'Prefix search string with @ to restrict to symbols, " for strings and # for documents'


class EntryType(enum.Enum):
    COMMAND = "command"
    SYMBOL = "symbol"
    STRING = "string"
    DOCUMENT = "document"


PREFIXES = {"@": EntryType.SYMBOL, '"': EntryType.STRING, "#": EntryType.DOCUMENT}
TITLES = {EntryType.COMMAND: "Commands", EntryType.SYMBOL: "Symbols", EntryType.STRING: "Strings",
          EntryType.DOCUMENT: "Documents"}


@dataclass
class CommandPaletteEntry:
    title: str
    type: EntryType
    payload: Any = None  # command callable, address, or document
    shortcut: str = ""
    display_title: str = ""

    def __post_init__(self) -> None:
        self.display_title = self.display_title or self.title


@dataclass
class Command:
    title: str
    action: Callable[[], Any]
    shortcut: str = ""


@dataclass
class CommandPalette:
    commands: list[Command]
    documents: list = field(default_factory=list)  # assemsearch.document.Document
    current_document: Any = None
    prefs: Preferences = field(default_factory=Preferences.in_memory)
    visible: bool = False
    window_title: str = PLACEHOLDER

    def toggle(self) -> bool:
        self.visible = not self.visible
        return self.visible

    @staticmethod
    def parse(text: str) -> tuple[EntryType, str]:
        """``PaletteSearchFieldValueTransformer``: strip the prefix and pick the mode."""
        if text and text[0] in PREFIXES:
            return PREFIXES[text[0]], text[1:]
        return EntryType.COMMAND, text

    def content(self, kind: EntryType) -> list[CommandPaletteEntry]:
        """Rebuilt when the window becomes key."""
        if kind == EntryType.DOCUMENT:
            return [CommandPaletteEntry(d.display_name, kind, d) for d in self.documents]
        doc = self.current_document
        if kind == EntryType.SYMBOL:
            return [CommandPaletteEntry(n, kind, a) for a, n in doc.file.names.items()] if doc else []
        if kind == EntryType.STRING:
            return [CommandPaletteEntry(doc.file.strings[a], kind, a) for a in doc.file.all_string_addresses()] if doc else []
        return [CommandPaletteEntry(c.title, kind, c.action, c.shortcut) for c in self.commands]

    def search(self, text: str) -> list[CommandPaletteEntry]:
        kind, pattern = self.parse(text)
        self.window_title = TITLES[kind]
        predicate = fuzzy.FuzzyPredicate(lambda e: e.title, pattern, self.prefs.enable_fuzzy_search)
        return predicate.filter(self.content(kind))

    def execute(self, entry: CommandPaletteEntry) -> Any:
        self.visible = False
        if entry.type == EntryType.COMMAND:
            return entry.payload()
        if entry.type == EntryType.DOCUMENT:
            self.current_document = entry.payload
            return entry.payload
        return self.current_document.goto_virtual_address(entry.payload)

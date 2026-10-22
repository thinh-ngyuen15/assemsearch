"""NSTextFinder-style find bar over a text buffer.

Used for any text view: a procedure listing, a script, a comment or the
debugger console.  Supports incremental highlighting (``find_all``), Next/
Previous with wrap-around, and Replace in editable buffers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class TextFinder:
    text: str
    editable: bool = False
    case_sensitive: bool = False
    whole_word: bool = False
    regex: bool = False
    wrap: bool = True
    position: int = 0
    selection: tuple[int, int] | None = None
    find_string: str = ""
    history: list[str] = field(default_factory=list)

    def _pattern(self, needle: str) -> re.Pattern[str]:
        body = needle if self.regex else re.escape(needle)
        if self.whole_word:
            body = rf"\b(?:{body})\b"
        return re.compile(body, 0 if self.case_sensitive else re.IGNORECASE)

    def find_all(self, needle: str | None = None) -> list[tuple[int, int]]:
        """Incremental search: every match range (start, end)."""
        needle = self.find_string if needle is None else needle
        if not needle:
            return []
        return [m.span() for m in self._pattern(needle).finditer(self.text) if m.end() > m.start()]

    def set_find_string(self, needle: str) -> None:
        self.find_string = needle
        if needle and (not self.history or self.history[0] != needle):
            self.history.insert(0, needle)

    def find_next(self, needle: str | None = None) -> tuple[int, int] | None:
        if needle is not None:
            self.set_find_string(needle)
        matches = self.find_all()
        if not matches:
            return None
        start = self.selection[1] if self.selection else self.position
        hit = next((m for m in matches if m[0] >= start), matches[0] if self.wrap else None)
        return self._select(hit)

    def find_previous(self, needle: str | None = None) -> tuple[int, int] | None:
        if needle is not None:
            self.set_find_string(needle)
        matches = self.find_all()
        if not matches:
            return None
        start = self.selection[0] if self.selection else self.position
        earlier = [m for m in matches if m[0] < start]
        hit = earlier[-1] if earlier else (matches[-1] if self.wrap else None)
        return self._select(hit)

    def _select(self, hit):
        if hit is not None:
            self.selection = hit
            self.position = hit[0]
        return hit

    def replace(self, replacement: str) -> bool:
        if not self.editable or self.selection is None:
            return False
        start, end = self.selection
        self.text = self.text[:start] + replacement + self.text[end:]
        self.selection = (start, start + len(replacement))
        return True

    def replace_all(self, replacement: str) -> int:
        if not self.editable or not self.find_string:
            return 0
        self.text, count = self._pattern(self.find_string).subn(
            replacement if self.regex else replacement.replace("\\", "\\\\"), self.text)
        self.selection = None
        return count

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1

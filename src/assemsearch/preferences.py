"""Preferences: persisted search options (a JSON file).

Also holds the shared "Find pasteboard" string and the search-field recents.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

MAX_RECENTS = 10


def default_path() -> Path:
    env = os.environ.get("ASSEMSEARCH_PREFS")
    if env:
        return Path(env)
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "assemsearch" / "preferences.json"


# Allowed values of the numeric options (Find modes, number widths, Go To offset modes).
_CHOICES = {"last_find_mode": range(6), "last_find_number_length": (8, 16, 32, 64),
            "last_goto_file_offset_mode": range(3)}


def _valid(key: str, value, default) -> bool:
    """A stored value is kept only if it has the default's type (and an allowed value)."""
    if isinstance(default, bool) or isinstance(value, bool):
        return isinstance(value, bool) and isinstance(default, bool)
    if not isinstance(value, type(default)):
        return False
    if key in _CHOICES:
        return value in _CHOICES[key]
    if key == "recent_searches":
        return all(isinstance(terms, list) and all(isinstance(t, str) for t in terms) for terms in value.values())
    return True


@dataclass
class Preferences:
    enable_fuzzy_search: bool = True
    last_find_mode: int = 2
    last_find_case_sensitive: bool = False
    last_find_wrapping: bool = True
    last_find_number_length: int = 32
    last_find_number_little_endian: bool = True
    last_goto_file_offset_mode: int = 1
    show_hex_column: bool = False
    find_pasteboard: str = ""
    recent_searches: dict[str, list[str]] = field(default_factory=dict)
    path: Path | None = field(default=None, repr=False, compare=False)

    @classmethod
    def load(cls, path: Path | None = None) -> "Preferences":
        path = path or default_path()
        prefs = cls(path=path)
        try:
            stored = json.loads(path.read_text())
        except (OSError, ValueError):
            return prefs
        if not isinstance(stored, dict):
            return prefs
        defaults = cls()
        for key, value in stored.items():
            if key in cls.__dataclass_fields__ and key != "path" and _valid(key, value, getattr(defaults, key)):
                setattr(prefs, key, value)
        return prefs

    @classmethod
    def in_memory(cls) -> "Preferences":
        return cls(path=None)

    def save(self) -> None:
        if self.path is None:
            return
        data = asdict(self)
        data.pop("path")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data, indent=2))
        except OSError:
            pass

    def add_recent_search(self, field_name: str, term: str) -> None:
        if not term:
            return
        recents = [t for t in self.recent_searches.get(field_name, []) if t != term]
        self.recent_searches[field_name] = ([term] + recents)[:MAX_RECENTS]
        self.save()

    def clear_recent_searches(self, field_name: str) -> None:
        self.recent_searches.pop(field_name, None)
        self.save()

    def update(self, **values) -> None:
        for key, value in values.items():
            setattr(self, key, value)
        self.save()

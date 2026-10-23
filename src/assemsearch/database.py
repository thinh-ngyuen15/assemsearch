"""Saving and restoring the user's annotations (the ``.hop`` database analogue).

Names, comments, tags and bookmarks are what several searches run over
(comment search, tag scope, bookmarks, renamed labels), so they persist across sessions.
The database sits next to the binary (``BINARY.asdb``), or in a per-user folder
when the binary's folder is not writable (``/bin/ls``).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from assemsearch.model import Bookmark, DisassembledFile

VERSION = 1


class DatabaseMismatch(ValueError):
    """The database was saved for different contents than the binary now at its path."""


def binary_digest(doc: DisassembledFile) -> str | None:
    """SHA-256 of the binary file, None when it cannot be read."""
    digest = hashlib.sha256()
    try:
        with open(doc.path, "rb") as binary:
            while chunk := binary.read(1 << 20):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def default_database_path(doc: DisassembledFile) -> Path:
    return Path(doc.path + ".asdb")


def fallback_database_path(doc: DisassembledFile) -> Path:
    binary = Path(doc.path).resolve()
    digest = hashlib.sha256(str(binary).encode()).hexdigest()[:16]
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / "assemsearch" / f"{binary.name}-{digest}.asdb"


def _modified(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def save(doc: DisassembledFile, path: str | Path | None = None) -> Path:
    data = {
        "version": VERSION,
        "binary": doc.path,
        "sha256": binary_digest(doc),
        "names": {f"{a:x}": n for a, n in doc.names.items()},
        "comments": {f"{a:x}": t for a, t in doc.comments.items()},
        "inline_comments": {f"{a:x}": t for a, t in doc.inline_comments.items()},
        "tags": {tag: [f"{a:x}" for a in sorted(addresses)] for tag, addresses in doc.tags.items()},
        "bookmarks": [{"address": f"{b.address:x}", "name": b.name} for b in doc.bookmarks],
    }
    text = json.dumps(data, indent=1)
    if path:
        path = Path(path)
        path.write_text(text)
        return path
    path = default_database_path(doc)
    try:
        path.write_text(text)
    except OSError:  # read-only folder: keep the database in the per-user folder
        path = fallback_database_path(doc)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return path


def _read(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def load(doc: DisassembledFile, path: str | Path | None = None) -> bool:
    """Restores from ``path``, or from the newer of the two default locations that matches the binary.

    Databases record the binary's SHA-256 (older ones without it are trusted). Raises
    DatabaseMismatch, without changing ``doc``, when every candidate was saved for other contents.
    """
    if path:
        candidates = [Path(path)]
    else:
        found = [(m, p) for p in (default_database_path(doc), fallback_database_path(doc))
                 if (m := _modified(p)) is not None]
        candidates = [p for _, p in sorted(found, key=lambda pair: pair[0], reverse=True)]
    digest = binary_digest(doc)
    mismatched = None
    for candidate in candidates:
        data = _read(candidate)
        if data is None:
            continue
        saved = data.get("sha256")
        if saved and digest and saved != digest:
            mismatched = candidate
            continue
        _apply(doc, data)
        return True
    if mismatched is not None:
        raise DatabaseMismatch(f"{mismatched} was saved for a different version of {doc.path}; not restored "
                               "(saving will replace it)")
    return False


def _apply(doc: DisassembledFile, data: dict) -> None:
    for address, name in data.get("names", {}).items():
        doc.set_name(int(address, 16), name)
    doc.comments.update({int(a, 16): t for a, t in data.get("comments", {}).items()})
    doc.inline_comments.update({int(a, 16): t for a, t in data.get("inline_comments", {}).items()})
    for tag, addresses in data.get("tags", {}).items():
        for address in addresses if tag else ():  # older versions could save an empty tag name
            doc.add_tag(tag, int(address, 16))
    doc.bookmarks = [Bookmark(int(b["address"], 16), b["name"]) for b in data.get("bookmarks", [])]

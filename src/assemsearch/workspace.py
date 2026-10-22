"""The set of open documents and the current one."""

from __future__ import annotations

from pathlib import Path

from assemsearch.document import Document
from assemsearch.loaders import load_file
from assemsearch.preferences import Preferences


class Workspace:
    def __init__(self, prefs: Preferences | None = None) -> None:
        self.prefs = prefs or Preferences.load()
        self.documents: list[Document] = []
        self.current: Document | None = None

    def open(self, path: str | Path, arch: str | None = None, raw: bool = False, base: int | None = None,
             restore: bool = True) -> Document:
        from assemsearch import database

        disassembled = load_file(path, arch=arch, raw=raw, base=base)
        if restore:
            database.load(disassembled)
        document = Document(disassembled, self.prefs)
        self.documents.append(document)
        self.current = document
        return document

    def add(self, document: Document) -> Document:
        self.documents.append(document)
        self.current = self.current or document
        return document

    def find(self, name: str | None) -> Document | None:
        """By display name, path or index; ``None`` means the current document."""
        if not name:
            return self.current
        for document in self.documents:
            if name in (document.display_name, document.file.path):
                return document
        if name.isdigit() and int(name) < len(self.documents):
            return self.documents[int(name)]
        return None

    def set_current(self, name: str) -> Document | None:
        document = self.find(name)
        if document is not None:
            self.current = document
        return document

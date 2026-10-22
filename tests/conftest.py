from __future__ import annotations

from pathlib import Path

import pytest

from assemsearch.document import Document
from assemsearch.loaders import load_file, load_raw
from assemsearch.analysis import analyze
from assemsearch.preferences import Preferences

FIXTURES = Path(__file__).parent / "fixtures"
MACHO = FIXTURES / "sample_macho"
ELF = FIXTURES / "sample_elf.o"
OBJC = FIXTURES / "sample_objc"
CFG = FIXTURES / "sample_cfg"


@pytest.fixture(autouse=True)
def isolated_prefs(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSEMSEARCH_PREFS", str(tmp_path / "prefs.json"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))  # fallback database folder


@pytest.fixture
def arm64():
    return load_file(MACHO, arch="arm64")


@pytest.fixture
def x86():
    return load_file(MACHO, arch="x86_64")


@pytest.fixture
def arm_doc(arm64):
    return Document(arm64, Preferences.in_memory())


def raw_document(data: bytes, base: int = 0x1000, analyse: bool = False) -> Document:
    doc = load_raw("mem.bin", data, "x86_64", base)
    if analyse:
        analyze(doc)
    else:
        doc.rebuild_object_index()
    return Document(doc, Preferences.in_memory())

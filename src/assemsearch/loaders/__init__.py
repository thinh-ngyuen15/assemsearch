"""File loaders.  ``load_file`` detects the format and runs the analysis."""

from __future__ import annotations

import struct
from pathlib import Path

from assemsearch.loaders.elf import is_elf, load_elf
from assemsearch.loaders.macho import is_macho, load_macho
from assemsearch.model import DisassembledFile, Section, Segment


def load_raw(path: str, data: bytes, cpu: str = "x86_64", base: int = 0) -> DisassembledFile:
    doc = DisassembledFile(path, cpu, "Raw")
    segment = Segment("RAW", base, len(data), data, 0, executable=True)
    segment.add_section(Section("raw", base, len(data), 0))
    doc.add_segment(segment)
    return doc


def load_file(path: str | Path, arch: str | None = None, base: int | None = None,
              raw: bool = False, analyze: bool = True) -> DisassembledFile:
    from assemsearch.analysis import analyze as run_analysis

    path = str(path)
    data = Path(path).read_bytes()
    try:
        if raw or not (is_macho(data) or is_elf(data)):
            doc = load_raw(path, data, arch or "x86_64", base or 0)
        elif is_macho(data):
            doc = load_macho(path, data, arch)
        else:
            doc = load_elf(path, data)
    except (struct.error, IndexError) as error:  # truncated or malformed headers
        raise ValueError(f"{path}: malformed or truncated file ({error})") from error
    if analyze:
        run_analysis(doc)
    else:
        doc.rebuild_object_index()
    return doc

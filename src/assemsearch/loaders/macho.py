"""Minimal Mach-O loader: thin/fat 64-bit images, symbols, stubs, function starts."""

from __future__ import annotations

import struct

from assemsearch.model import DisassembledFile, ExportedSymbol, ImportedSymbol, Section, Segment

FAT_MAGIC = 0xCAFEBABE
MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC = 0xFEEDFACE

CPU_TYPES = {0x01000007: "x86_64", 0x0100000C: "arm64", 7: "x86", 12: "arm"}

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_SEGMENT_64 = 0x19
LC_FUNCTION_STARTS = 0x26
LC_MAIN = 0x80000028
LC_DYLD_CHAINED_FIXUPS = 0x80000034
# Load commands whose body holds a path at the offset stored in body[8:12]: dylibs, dylinker, rpath.
PATH_COMMANDS = {LC_LOAD_DYLIB, 0xD, 0xE, 0x20, 0x80000018, 0x8000001C, 0x8000001F, 0x80000023}

DYLD_CHAINED_PTR_START_NONE = 0xFFFF
# DYLD_CHAINED_PTR_* formats: (stride, arm64e layout, rebase targets are offsets from the image base)
CHAINED_POINTER_FORMATS = {1: (8, True, False), 2: (4, False, False), 6: (4, False, True),
                           9: (8, True, True), 12: (8, True, True)}

S_ZEROFILL = 0x1
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_SYMBOL_STUBS = 0x8
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

N_STAB = 0xE0
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x0
N_SECT = 0xE

INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000


def is_macho(data: bytes) -> bool:
    return len(data) >= 4 and struct.unpack(">I", data[:4])[0] in (FAT_MAGIC, 0xCFFAEDFE, 0xCEFAEDFE)


def fat_slices(data: bytes) -> list[tuple[str, int, int]]:
    """(cpu, offset, size) of each slice, or a single slice for a thin file."""
    magic = struct.unpack(">I", data[:4])[0]
    if magic != FAT_MAGIC:
        cputype = struct.unpack("<I", data[4:8])[0]
        return [(CPU_TYPES.get(cputype, hex(cputype)), 0, len(data))]
    count = struct.unpack(">I", data[4:8])[0]
    slices = []
    for i in range(count):
        cputype, _sub, offset, size, _align = struct.unpack(">iiIII", data[8 + 20 * i:28 + 20 * i])
        slices.append((CPU_TYPES.get(cputype & 0xFFFFFFFF, hex(cputype)), offset, size))
    return slices


def _cstr(blob: bytes, offset: int = 0) -> str:
    end = blob.find(b"\0", offset)
    return blob[offset:end if end >= 0 else len(blob)].decode("utf-8", "replace")


def _uleb(data: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return result, pos


def load_macho(path: str, data: bytes, arch: str | None = None) -> DisassembledFile:
    slices = fat_slices(data)
    chosen = next((s for s in slices if s[0] == arch), None) if arch else None
    if chosen is None and arch and len(slices) > 1:  # a thin file has no choice to make
        raise ValueError(f"no {arch} slice in {path} (it has {', '.join(s[0] for s in slices)})")
    if chosen is None:
        chosen = next((s for s in slices if s[0] == "arm64"), slices[0])
    cpu, offset, size = chosen
    image = data[offset:offset + size]
    magic = struct.unpack("<I", image[:4])[0]
    if magic not in (MH_MAGIC_64, MH_MAGIC):
        raise ValueError("unsupported Mach-O image")
    is64 = magic == MH_MAGIC_64
    _, _cputype, _sub, _filetype, ncmds, _sizeofcmds, _flags = struct.unpack("<IiiIIII", image[:28])
    doc = DisassembledFile(path, cpu, "Mach-O")
    doc.container_file_offset = offset

    sections_by_index: list[Section] = []
    segment_commands: list[tuple[int, int]] = []  # (vmaddr, fileoff) of every segment, in load-command order
    symtab = dysymtab = None
    function_starts = None
    chained_fixups = None
    entry_offset = None
    libraries: list[str] = []
    header_paths: dict[int, str] = {}  # offset in the image -> path
    pos = 32 if is64 else 28
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", image[pos:pos + 8])
        body = image[pos:pos + cmdsize]
        if cmd in (LC_SEGMENT_64, LC_SEGMENT):
            vmaddr, fileoff, sections = _load_segment(doc, image, body, cmd == LC_SEGMENT_64)
            segment_commands.append((vmaddr, fileoff))
            sections_by_index.extend(sections)
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            chained_fixups = body
        elif cmd == LC_SYMTAB:
            symtab = struct.unpack("<IIII", body[8:24])
        elif cmd == LC_DYSYMTAB:
            dysymtab = struct.unpack("<18I", body[8:80])
        elif cmd == LC_FUNCTION_STARTS:
            function_starts = struct.unpack("<II", body[8:16])
        elif cmd == LC_MAIN:
            entry_offset = struct.unpack("<Q", body[8:16])[0]
        if cmd == LC_LOAD_DYLIB:
            libraries.append(_cstr(body, struct.unpack("<I", body[8:12])[0]))
        if cmd in PATH_COMMANDS:  # the header is mapped at the start of __TEXT
            name_offset = struct.unpack("<I", body[8:12])[0]
            header_paths[pos + name_offset] = _cstr(body, name_offset)
        pos += cmdsize

    text = doc.segment_named("__TEXT")
    text_base = text.start if text else 0
    if text is not None and text.file_offset == 0:
        doc.header_strings = {text_base + offset: path for offset, path in header_paths.items()}
    if entry_offset is not None:
        doc.entry_point = text_base + entry_offset
    if chained_fixups is not None:
        try:
            doc.pointer_targets, doc.pointer_imports = _chained_fixups(image, chained_fixups, segment_commands,
                                                                       text_base)
        except struct.error:  # truncated fixup data: keep the raw pointer values
            pass
    if function_starts is not None:
        blob = image[function_starts[0]:function_starts[0] + function_starts[1]]
        address, p = text_base, 0
        while p < len(blob):
            delta, p = _uleb(blob, p)
            if delta == 0:
                break
            address += delta
            doc.function_starts.add(address)
    doc.function_starts |= _unwind_function_starts(doc, text_base)

    symbols = _load_symbols(doc, image, symtab, sections_by_index, is64) if symtab else []
    if dysymtab is not None:
        _load_indirect_symbols(doc, image, dysymtab, symbols, sections_by_index)
    if len(libraries) == 1:
        for imported in doc.imports:
            imported.library = libraries[0]
    _external_symbols(doc)
    return doc


def _unwind_function_starts(doc: DisassembledFile, text_base: int) -> set[int]:
    """Every function the compiler emitted unwind info for (``__TEXT,__unwind_info``, compact
    unwind). Usually the same list as LC_FUNCTION_STARTS, but present in binaries without it."""
    section = doc.section_named("__unwind_info")
    if section is None or section.file_offset is None or section.length < 28:
        return set()
    data = doc.read_bytes(section.start, section.length)
    starts: set[int] = set()
    try:
        index_offset, index_count = struct.unpack_from("<II", data, 20)
        for k in range(index_count):
            function_offset, page_offset, _lsda = struct.unpack_from("<III", data, index_offset + 12 * k)
            if not page_offset:
                continue
            kind, entries_offset, count = struct.unpack_from("<IHH", data, page_offset)
            for e in range(count):
                if kind == 2:  # regular page: (function offset, encoding) pairs
                    offset = struct.unpack_from("<I", data, page_offset + entries_offset + 8 * e)[0]
                elif kind == 3:  # compressed page: 24-bit offsets from the index entry
                    offset = function_offset + (struct.unpack_from("<I", data, page_offset + entries_offset + 4 * e)[0]
                                                & 0xFFFFFF)
                else:
                    break
                starts.add(text_base + offset)
    except struct.error:  # truncated: keep what was read
        pass
    return {a for a in starts if doc.has_segment_at(a)}


def _external_symbols(doc: DisassembledFile) -> None:
    """A synthetic "External Symbols" segment, one 8-byte slot per imported symbol (by name)."""
    names = sorted({imported.name for imported in doc.imports})
    if not names or not doc.segments:
        return
    start = (max(s.end for s in doc.segments) + 0xFFF) & ~0xFFF
    doc.add_segment(Segment("External Symbols", start, 8 * len(names), b"", None))
    for index, name in enumerate(names):
        doc.set_name(start + 8 * index, name)


def _chained_import_names(blob: bytes) -> list[str]:
    """Symbol names of the chained-fixup import table, by bind ordinal."""
    imports_offset, symbols_offset, count, import_format = struct.unpack("<IIII", blob[8:24])
    size = {1: 4, 2: 8, 3: 16}.get(import_format)
    if size is None:
        return []
    names = []
    for index in range(count):
        entry = blob[imports_offset + index * size:imports_offset + (index + 1) * size]
        if import_format == 3:
            name_offset = struct.unpack("<Q", entry[:8])[0] >> 32
        else:
            name_offset = struct.unpack("<I", entry[:4])[0] >> 9
        names.append(_cstr(blob, symbols_offset + name_offset))
    return names


def _chained_fixups(image: bytes, body: bytes, segments: list[tuple[int, int]],
                    base: int) -> tuple[dict[int, int], dict[int, str]]:
    """Walks the LC_DYLD_CHAINED_FIXUPS chains.

    Returns slot address -> target of every rebase, and slot address -> symbol name of every bind.
    """
    dataoff, datasize = struct.unpack("<II", body[8:16])
    blob = image[dataoff:dataoff + datasize]
    starts = struct.unpack("<I", blob[4:8])[0]
    seg_count = struct.unpack("<I", blob[starts:starts + 4])[0]
    import_names = _chained_import_names(blob)
    targets: dict[int, int] = {}
    imports: dict[int, str] = {}
    for index in range(min(seg_count, len(segments))):
        info = struct.unpack("<I", blob[starts + 4 + 4 * index:starts + 8 + 4 * index])[0]
        if not info:
            continue
        pos = starts + info
        _size, page_size, pointer_format, _offset, _max, page_count = struct.unpack("<IHHQIH", blob[pos:pos + 22])
        if pointer_format not in CHAINED_POINTER_FORMATS:
            continue
        stride, arm64e, offset_targets = CHAINED_POINTER_FORMATS[pointer_format]
        vmaddr, fileoff = segments[index]
        page_starts = struct.unpack(f"<{page_count}H", blob[pos + 22:pos + 22 + 2 * page_count])
        for page, start in enumerate(page_starts):
            if start == DYLD_CHAINED_PTR_START_NONE:
                continue
            delta = page * page_size + start
            while fileoff + delta + 8 <= len(image):
                value = struct.unpack("<Q", image[fileoff + delta:fileoff + delta + 8])[0]
                if arm64e:
                    auth, bind = value >> 63, value >> 62 & 1
                    target = value & (0xFFFFFFFF if auth else 0x7FFFFFFFFFF)
                    from_base = bool(auth) or offset_targets
                    ordinal = value & (0xFFFFFF if pointer_format == 12 else 0xFFFF)
                    step = value >> 51 & 0x7FF
                else:
                    bind, target, from_base = value >> 63, value & 0xFFFFFFFFF, offset_targets
                    ordinal = value & 0xFFFFFF
                    step = value >> 51 & 0xFFF
                if not bind:
                    targets[vmaddr + delta] = base + target if from_base else target
                elif ordinal < len(import_names):
                    imports[vmaddr + delta] = import_names[ordinal]
                if not step:
                    break
                delta += step * stride
    return targets, imports


def _load_segment(doc: DisassembledFile, image: bytes, body: bytes, is64: bool) -> tuple[int, int, list[Section]]:
    if is64:
        segname, vmaddr, vmsize, fileoff, filesize, _maxp, initprot, nsects, _fl = struct.unpack(
            "<16sQQQQiiII", body[8:72])
        sect_pos, sect_size = 72, 80
    else:
        segname, vmaddr, vmsize, fileoff, filesize, _maxp, initprot, nsects, _fl = struct.unpack(
            "<16sIIIIiiII", body[8:56])
        sect_pos, sect_size = 56, 68
    name = segname.rstrip(b"\0").decode()
    sections: list[Section] = []
    keep = vmsize > 0 and initprot != 0  # __LINKEDIT is kept (as a segment without sections)
    segment = Segment(name, vmaddr, vmsize, image[fileoff:fileoff + filesize], fileoff,
                      executable=bool(initprot & 4))
    for i in range(nsects):
        raw = body[sect_pos + i * sect_size:sect_pos + (i + 1) * sect_size]
        if is64:
            sectname, _seg, addr, size, offset, _al, _ro, _nr, flags, r1, r2, _r3 = struct.unpack(
                "<16s16sQQIIIIIIII", raw)
        else:
            sectname, _seg, addr, size, offset, _al, _ro, _nr, flags, r1, r2 = struct.unpack(
                "<16s16sIIIIIIIII", raw)
        zerofill = (flags & 0xFF) in (S_ZEROFILL, 0xC, 0x12)
        section = Section(sectname.rstrip(b"\0").decode(), addr, size, None if zerofill else offset, flags=flags)
        section.reserved1, section.reserved2 = r1, r2  # type: ignore[attr-defined]
        sections.append(section)
        if keep:
            segment.add_section(section)
    if keep:
        doc.add_segment(segment)
    return vmaddr, fileoff, sections


def _load_symbols(doc, image, symtab, sections_by_index, is64):
    symoff, nsyms, stroff, strsize = symtab
    strings = image[stroff:stroff + strsize]
    entry_size = 16 if is64 else 12
    symbols = []
    for i in range(nsyms):
        raw = image[symoff + i * entry_size:symoff + (i + 1) * entry_size]
        if is64:
            strx, ntype, nsect, _desc, value = struct.unpack("<IBBhQ", raw)
        else:
            strx, ntype, nsect, _desc, value = struct.unpack("<IBBhI", raw)
        name = _cstr(strings, strx)
        symbols.append(name)
        if ntype & N_STAB or not name:
            continue
        kind = ntype & N_TYPE
        if kind == N_SECT and doc.has_segment_at(value):
            if not doc.names.has_name(name):
                doc.set_name(value, name)
            if ntype & N_EXT:
                doc.exports.append(ExportedSymbol(name, value))
            section = sections_by_index[nsect - 1] if 0 < nsect <= len(sections_by_index) else None
            if section is not None and section.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS):
                doc.function_starts.add(value)
        elif kind == N_UNDF and ntype & N_EXT and value == 0:
            if not any(imp.name == name for imp in doc.imports):
                doc.imports.append(ImportedSymbol(name, None))
    return symbols


def _load_indirect_symbols(doc, image, dysymtab, symbols, sections_by_index):
    indirectsymoff, nindirectsyms = dysymtab[12], dysymtab[13]
    table = struct.unpack(f"<{nindirectsyms}I", image[indirectsymoff:indirectsymoff + 4 * nindirectsyms])
    imports_by_name = {imp.name: imp for imp in doc.imports}
    for section in sections_by_index:
        kind = section.flags & 0xFF
        if kind == S_SYMBOL_STUBS:
            stride = section.reserved2  # type: ignore[attr-defined]
        elif kind in (S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS):
            stride = 8
        else:
            continue
        if not stride or not doc.has_segment_at(section.start):
            continue
        first = section.reserved1  # type: ignore[attr-defined]
        for i in range(section.length // stride):
            if first + i >= len(table):
                break
            index = table[first + i]
            if index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) or index >= len(symbols):
                continue
            name = symbols[index]
            address = section.start + i * stride
            # Names: stubs "imp___stubs_<symbol>", pointers "<symbol>_<address>"
            # (the plain name belongs to the External Symbols slot).
            doc.set_name(address, f"imp___stubs_{name}" if kind == S_SYMBOL_STUBS else f"{name}_{address:x}")
            imported = imports_by_name.get(name)
            if imported is not None and (imported.address is None or kind == S_SYMBOL_STUBS):
                imported.address = address
            if kind == S_SYMBOL_STUBS:
                doc.function_starts.add(address)

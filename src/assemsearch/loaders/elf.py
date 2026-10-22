"""Minimal ELF loader: executables, shared objects and relocatable objects."""

from __future__ import annotations

import struct

from assemsearch.model import DisassembledFile, ExportedSymbol, ImportedSymbol, Section, Segment

MACHINES = {3: "x86", 62: "x86_64", 40: "arm", 183: "arm64"}
SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS, SHT_DYNSYM, SHT_REL = 2, 3, 4, 8, 11, 9
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4
PT_LOAD = 1
STT_FUNC, STT_OBJECT, STT_SECTION, STT_FILE = 2, 1, 3, 4
STB_LOCAL = 0
ET_REL = 1


def is_elf(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def load_elf(path: str, data: bytes) -> DisassembledFile:
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    if is64:
        (e_type, e_machine, _v, e_entry, e_phoff, e_shoff, _f, _eh, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack(end + "HHIQQQIHHHHHH", data[16:64])
    else:
        (e_type, e_machine, _v, e_entry, e_phoff, e_shoff, _f, _eh, e_phentsize, e_phnum,
         e_shentsize, e_shnum, e_shstrndx) = struct.unpack(end + "HHIIIIIHHHHHH", data[16:52])
    doc = DisassembledFile(path, MACHINES.get(e_machine, f"elf-{e_machine}"), "ELF")
    doc.relocatable = e_type == ET_REL

    headers = []
    for i in range(e_shnum):
        raw = data[e_shoff + i * e_shentsize:e_shoff + (i + 1) * e_shentsize]
        if is64:
            fields = struct.unpack(end + "IIQQQQIIQQ", raw[:64])
        else:
            fields = struct.unpack(end + "IIIIIIIIII", raw[:40])
        headers.append(dict(zip(("name", "type", "flags", "addr", "offset", "size", "link", "info",
                                 "align", "entsize"), fields)))
    shstr = data[headers[e_shstrndx]["offset"]:][:headers[e_shstrndx]["size"]] if headers else b""
    for h in headers:
        h["sname"] = shstr[h["name"]:shstr.find(b"\0", h["name"])].decode()

    # Relocatable objects have all sections at address 0: lay them out one after another.
    if e_type == ET_REL:
        cursor = 0
        for h in headers:
            if h["flags"] & SHF_ALLOC and h["size"]:
                align = max(h["align"], 1)
                cursor = (cursor + align - 1) // align * align
                h["addr"] = cursor
                cursor += h["size"]

    sections: dict[int, Section] = {}
    if e_type != ET_REL and e_phnum:
        for i in range(e_phnum):
            raw = data[e_phoff + i * e_phentsize:e_phoff + (i + 1) * e_phentsize]
            if is64:
                p_type, p_flags, p_off, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack(end + "IIQQQQQQ", raw[:56])
            else:
                p_type, p_off, p_vaddr, _pa, p_filesz, p_memsz, p_flags, _al = struct.unpack(end + "IIIIIIII", raw[:32])
            if p_type != PT_LOAD or not p_memsz:
                continue
            doc.add_segment(Segment(f"LOAD{len(doc.segments)}", p_vaddr, p_memsz,
                                    data[p_off:p_off + p_filesz], p_off, executable=bool(p_flags & 1)))
        for index, h in enumerate(headers):
            if not h["flags"] & SHF_ALLOC or not h["size"]:
                continue
            segment = doc.segment_for_virtual_address(h["addr"])
            if segment is None:
                continue
            section = Section(h["sname"], h["addr"], h["size"],
                              None if h["type"] == SHT_NOBITS else h["offset"], flags=h["flags"])
            segment.add_section(section)
            sections[index] = section
    else:
        for index, h in enumerate(headers):
            if not h["flags"] & SHF_ALLOC or not h["size"]:
                continue
            nobits = h["type"] == SHT_NOBITS
            body = b"" if nobits else data[h["offset"]:h["offset"] + h["size"]]
            segment = Segment(h["sname"], h["addr"], h["size"], body, None if nobits else h["offset"],
                              executable=bool(h["flags"] & SHF_EXECINSTR))
            section = Section(h["sname"], h["addr"], h["size"], None if nobits else h["offset"], flags=h["flags"])
            segment.add_section(section)
            doc.add_segment(segment)
            sections[index] = section

    doc.entry_point = e_entry if e_entry and doc.has_segment_at(e_entry) else doc.entry_point
    for h in headers:
        if h["type"] in (SHT_SYMTAB, SHT_DYNSYM):
            _load_symbols(doc, data, h, headers, sections, is64, end, relocatable=e_type == ET_REL)
    _load_plt_relocations(doc, data, headers, is64, end)
    return doc


def _load_symbols(doc, data, h, headers, sections, is64, end, relocatable):
    strtab = headers[h["link"]]
    strings = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
    size = 24 if is64 else 16
    for i in range(1, h["size"] // size):
        raw = data[h["offset"] + i * size:h["offset"] + (i + 1) * size]
        if is64:
            st_name, st_info, _o, st_shndx, st_value, _sz = struct.unpack(end + "IBBHQQ", raw)
        else:
            st_name, st_value, _sz, st_info, _o, st_shndx = struct.unpack(end + "IIIBBH", raw)
        name = strings[st_name:strings.find(b"\0", st_name)].decode("utf-8", "replace")
        kind, bind = st_info & 0xF, st_info >> 4
        if not name or kind in (STT_SECTION, STT_FILE):
            continue
        if st_shndx == 0:
            if bind != STB_LOCAL and not any(imp.name == name for imp in doc.imports):
                doc.imports.append(ImportedSymbol(name, None))
            continue
        section = sections.get(st_shndx)
        if section is None:
            continue
        address = section.start + st_value if relocatable else st_value
        if not doc.names.has_name(name) and not doc.names.has_name_at_address(address):
            doc.set_name(address, name)
        if kind == STT_FUNC:
            doc.function_starts.add(address)
        if bind != STB_LOCAL:
            if not any(e.name == name for e in doc.exports):
                doc.exports.append(ExportedSymbol(name, address))


def _load_plt_relocations(doc, data, headers, is64, end):
    """Name GOT slots after the imported symbol they hold (.rela.plt / .rela.dyn)."""
    for h in headers:
        if h["type"] not in (SHT_RELA, SHT_REL) or not h["sname"].startswith((".rela.plt", ".rel.plt")):
            continue
        symtab = headers[h["link"]]
        strtab = headers[symtab["link"]]
        strings = data[strtab["offset"]:strtab["offset"] + strtab["size"]]
        entsize = h["entsize"] or (24 if is64 else 8)
        symsize = 24 if is64 else 16
        for i in range(h["size"] // entsize):
            raw = data[h["offset"] + i * entsize:h["offset"] + (i + 1) * entsize]
            if is64:
                offset, info = struct.unpack(end + "QQ", raw[:16])
                symindex = info >> 32
            else:
                offset, info = struct.unpack(end + "II", raw[:8])
                symindex = info >> 8
            sym = data[symtab["offset"] + symindex * symsize:][:symsize]
            st_name = struct.unpack(end + "I", sym[:4])[0]
            name = strings[st_name:strings.find(b"\0", st_name)].decode()
            if name and doc.has_segment_at(offset):
                doc.set_name(offset, f"imp___got_{name}")
                for imported in doc.imports:
                    if imported.name == name and imported.address is None:
                        imported.address = offset

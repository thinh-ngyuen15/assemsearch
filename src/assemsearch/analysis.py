"""Auto-analysis: linear-sweep disassembly, strings, procedures, references, tags."""

from __future__ import annotations

import re
import struct

import capstone

from assemsearch.model import DataItem, DisassembledFile, Instruction, Section
from assemsearch.cfg import build_procedures
from assemsearch.objc import parse_objc_metadata
from assemsearch.types import BAD_ADDRESS, ByteType

_ARCHS = {
    "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64, 1),
    "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32, 1),
    "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, 4),
    "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM, 4),
}

_DISASSEMBLY_CHUNK = 0x10000
_IMM = re.compile(r"#?(-?0x[0-9a-f]+|-?\d+)\b")
_RIP = re.compile(r"\[rip ([+-]) (0x[0-9a-f]+|\d+)\]")
_ARM64_BRANCHES = {"b", "bl", "cbz", "cbnz", "tbz", "tbnz"}
_X86_JUMPS = {"jmp", "call"}
POINTER_SECTIONS = {"__got", "__auth_got", "__la_symbol_ptr", "__nl_symbol_ptr", ".got", ".got.plt",
                    "__objc_classrefs", "__objc_selrefs", "__const", ".data.rel.ro"}
CSTRING_SECTIONS = {"__cstring", "__objc_methname", "__objc_classname", "__objc_methtype", "__oslogstring",
                    "__swift5_reflstr"}
STRING_SECTIONS = CSTRING_SECTIONS | {".rodata", ".rodata.str1.1", ".rodata.str1.8", ".data", "__data", "__const",
                                      ".rodata.cst16"}
# Mach-O sections where a string exists only at an address something references
# (scanning them for printable runs finds the insides of Swift mangled names).
REFERENCED_STRING_SECTIONS = {"__const", "__data", "__swift5_reflstr"}
_OBJC_METHOD = re.compile(r"^[-+]\[(\w+)(?:\((\w+)\))? ")
_PRINTABLE = re.compile(rb"[\x20-\x7e\t\n\r]{4,}\x00")
_GPR = re.compile(r"[xw](\d+)|w?sp")
_INDEXED = re.compile(r"\[(\w+), [xw]\d+")  # [base, index…]
_MEMORY = re.compile(r"\[(\w+)(?:, #(-?0x[0-9a-f]+|-?\d+))?\](!?)(, #)?")
# arm64 mnemonics whose first operand is read, not written.
_NO_WRITE = ("cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz", "b.", "prfm", "fcmp", "ccmp", "ccmn", "msr",
             "nop", "brk", "hint", "dmb", "dsb", "isb", "bti", "st")
_CALLER_SAVED = [f"x{i}" for i in range(19)] + ["x30"]


def is_code_section(doc: DisassembledFile, section: Section) -> bool:
    if doc.file_type == "Mach-O":
        return bool(section.flags & 0x80000400)
    if doc.file_type == "ELF":
        return bool(section.flags & 0x4)
    return True


def is_call(cpu: str, mnemonic: str) -> bool:
    return mnemonic in ("bl", "blr") if cpu.startswith("arm") else mnemonic == "call"


def is_branch(cpu: str, mnemonic: str) -> bool:
    if cpu == "arm64":
        return mnemonic in _ARM64_BRANCHES or mnemonic.startswith("b.") or mnemonic in ("br", "blr", "ret")
    if cpu == "arm":
        return mnemonic in ("b", "bl", "bx", "blx") or (mnemonic.startswith("b") and len(mnemonic) == 3)
    return mnemonic in _X86_JUMPS or mnemonic.startswith("j") or mnemonic.startswith("ret")


def ends_flow(cpu: str, mnemonic: str) -> bool:
    if cpu.startswith("arm"):
        return mnemonic in ("b", "br", "ret", "bx")
    return mnemonic.startswith(("jmp", "ret", "hlt", "ud2"))


def branch_target(cpu: str, ins: Instruction) -> int | None:
    if not is_branch(cpu, ins.mnemonic) or not ins.op_str:
        return None
    last = ins.op_str.split(",")[-1].strip()
    match = _IMM.fullmatch(last)
    return int(match.group(1), 0) & 0xFFFFFFFFFFFFFFFF if match else None


def analyze(doc: DisassembledFile) -> None:
    code_sections = [s for s in doc.all_sections() if is_code_section(doc, s)]
    for section in code_sections:
        _disassemble_section(doc, section)
    for section in doc.all_sections():
        if section not in code_sections and section.file_offset is not None:
            _find_strings(doc, section)
            _mark_pointers(doc, section)
    doc.rebuild_object_index()
    _mark_rebased_pointers(doc)
    _relative_method_lists(doc)
    _swift_field_descriptors(doc)
    _swift_context_descriptors(doc)
    parse_objc_metadata(doc)
    doc.rebuild_object_index()
    _find_references(doc)
    _referenced_strings(doc)
    _build_procedures(doc, code_sections)
    _auto_tags(doc)
    _label_strings(doc)
    _eh_frame_strings(doc)
    doc.rebuild_object_index()


def _disassemble_section(doc: DisassembledFile, section: Section) -> None:
    arch = _ARCHS.get(doc.cpu)
    if arch is None or section.file_offset is None:
        return
    md = capstone.Cs(arch[0], arch[1])
    md.skipdata = False
    data = section.segment.read(section.start, section.length)
    # Decoding restarts at every known function start, so data or padding before a function
    # cannot shift the decoding of variable-length (x86) code past its first instruction.
    known = sorted({a - section.start for a in doc.function_starts | {doc.entry_point} if section.contains(a)})
    bounds = [0] + [b for b in known if b] + [len(data)]
    for run_start, run_end in zip(bounds, bounds[1:]):
        offset = run_start
        while offset < run_end:
            last = offset
            # In chunks: capstone keeps every instruction of a call in memory until the call returns.
            chunk = data[offset:min(offset + _DISASSEMBLY_CHUNK, run_end)]
            for address, size, mnemonic, op_str in md.disasm_lite(chunk, section.start + offset):
                doc.instructions.add(address, size, mnemonic, op_str)
                last = address - section.start + size
            offset = last + arch[2] if last == offset else last  # skip one undecodable unit
            offset = (offset + arch[2] - 1) // arch[2] * arch[2] if arch[2] > 1 else offset


def _find_strings(doc: DisassembledFile, section: Section) -> None:
    if section.name not in STRING_SECTIONS and doc.file_type != "Raw":
        return
    if doc.file_type == "Mach-O" and section.name in REFERENCED_STRING_SECTIONS:
        return  # only where something points: see _referenced_strings
    data = section.segment.read(section.start, section.length)
    cstring = section.name in CSTRING_SECTIONS or section.name.startswith(".rodata.str")
    if cstring:
        pos = 0
        while pos < len(data):
            end = data.find(b"\0", pos)
            if end < 0:
                break
            if end > pos:
                _add_string(doc, section.start + pos, data[pos:end])
            pos = end + 1
        return
    for match in _PRINTABLE.finditer(data):
        _add_string(doc, section.start + match.start(), match.group()[:-1])


def decode_string(raw: bytes) -> str:
    """C strings are UTF-8 in practice; bytes that are not valid UTF-8 are kept one char per byte."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _add_string(doc: DisassembledFile, address: int, raw: bytes) -> None:
    if address in doc.instructions:
        return
    doc.strings[address] = decode_string(raw)
    doc.data_items[address] = DataItem(ByteType.ASCII, len(raw) + 1)


def _mark_pointers(doc: DisassembledFile, section: Section) -> None:
    if section.name not in POINTER_SECTIONS or section.name == "__const" and doc.file_type != "Mach-O":
        return
    size = 8 if doc.cpu in ("x86_64", "arm64") else 4
    data = section.segment.read(section.start, section.length)
    for offset in range(0, len(data) - size + 1, size):
        address = section.start + offset
        if address in doc.data_items:
            continue
        # Chained-fixup slots hold an encoded rebase; the loader decoded its target.
        target = doc.pointer_targets.get(address, int.from_bytes(data[offset:offset + size], "little"))
        if section.name == "__const" and not (doc.has_segment_at(target) and target):
            continue
        doc.data_items[address] = DataItem(ByteType.INT64 if size == 8 else ByteType.INT32, size)
        if target and doc.has_segment_at(target):
            doc.add_reference(address, target, data=True)


def _mark_rebased_pointers(doc: DisassembledFile) -> None:
    """Every chained-fixup rebase is a pointer, whatever its section (``__cfstring``, ``__objc_const``…).

    A CFString's characters pointer is credited to the 32-byte CFString itself.
    """
    cfstrings = doc.section_named("__cfstring") if doc.file_type == "Mach-O" else None
    for slot, target in doc.pointer_targets.items():
        if cfstrings is not None and cfstrings.contains(slot) and (slot - cfstrings.start) % 32 == 16:
            doc.add_reference(slot - 16, target, data=True)
            continue
        if slot in doc.instructions or not doc.has_segment_at(target):
            continue
        item = doc.data_items.get(slot)
        if item is None:
            if doc.object_start_containing(slot) is not None:
                continue  # inside a string or another object
            doc.data_items[slot] = DataItem(ByteType.INT64, 8)
        elif item.type != ByteType.INT64:
            continue
        doc.add_reference(slot, target, data=True)
    for slot, symbol in doc.pointer_imports.items():  # binds point at the symbol's External Symbols slot
        external = doc.find_virtual_address_named(symbol)
        if external != BAD_ADDRESS and slot not in doc.instructions:
            doc.data_items.setdefault(slot, DataItem(ByteType.INT64, 8))
            doc.add_reference(slot, external, data=True)


def _relative_field(doc: DisassembledFile, field: int, structure: int) -> None:
    """A 32-bit offset relative to its own address (ObjC relative method lists, Swift metadata).

    The reference comes from the start of the enclosing structure.
    """
    raw = doc.read_bytes(field, 4)
    offset = int.from_bytes(raw, "little", signed=True) if len(raw) == 4 else 0
    doc.data_items.setdefault(field, DataItem(ByteType.INT32, 4))
    if offset and doc.has_segment_at(field + offset):
        doc.add_reference(structure, field + offset, data=True)


def _relative_method_lists(doc: DisassembledFile) -> None:
    """``__objc_methlist``: back-to-back method lists of (name, types, imp) relative offsets."""
    section = doc.section_named("__objc_methlist")
    if section is None or section.file_offset is None:
        return
    position = section.start
    while position + 8 <= section.end:
        flags = int.from_bytes(doc.read_bytes(position, 4), "little")
        count = int.from_bytes(doc.read_bytes(position + 4, 4), "little")
        entry_size = flags & 0xFFFC
        if not entry_size or position + 8 + entry_size * count > section.end:
            break
        if flags & 0x80000000 and entry_size == 12:
            for entry in range(position + 8, position + 8 + 12 * count, 12):
                for field in (entry, entry + 4, entry + 8):
                    _relative_field(doc, field, entry)
        position = (position + 8 + entry_size * count + 7) & ~7  # lists are 8-byte aligned


def _swift_field_descriptors(doc: DisassembledFile) -> None:
    """``__swift5_fieldmd``: field descriptors whose records point at their type and field names."""
    section = doc.section_named("__swift5_fieldmd")
    if section is None or section.file_offset is None:
        return
    position = section.start
    while position + 16 <= section.end:
        header = doc.read_bytes(position, 16)
        record_size = int.from_bytes(header[10:12], "little")
        count = int.from_bytes(header[12:16], "little")
        end = position + 16 + record_size * count
        if record_size < 12 or end > section.end:
            break
        _relative_field(doc, position, position)  # mangled type name
        _relative_field(doc, position + 4, position)  # superclass
        for record in range(position + 16, end, record_size):
            _relative_field(doc, record + 4, record)  # mangled type name
            _relative_field(doc, record + 8, record)  # field name
        position = end


def _swift_context_descriptors(doc: DisassembledFile) -> None:
    """``__swift5_types`` / ``__swift5_protos``: relative pointers to Swift context descriptors.

    Each descriptor (and its parents: modules, extensions) references its name, which is
    then read as a string. Protocols' associated-type names are not followed.
    """
    seen: set[int] = set()

    def s32(address: int) -> int:
        raw = doc.read_bytes(address, 4)
        return int.from_bytes(raw, "little", signed=True) if len(raw) == 4 else 0

    def descriptor(address: int) -> None:
        while address not in seen and doc.has_segment_at(address):
            seen.add(address)
            kind = int.from_bytes(doc.read_bytes(address, 4), "little") & 0x1F
            if kind not in (0, 1, 2, 3, 16, 17, 18):  # module, extension, anonymous, protocol, class/struct/enum
                return
            if kind != 2:
                _relative_field(doc, address + 8, address)  # name (extension: extended type)
            if kind >= 16:
                _relative_field(doc, address + 12, address)  # access function
                _relative_field(doc, address + 16, address)  # field descriptor
            parent = s32(address + 4)
            if not parent or parent & 1:  # none, or indirect through a GOT slot
                return
            _relative_field(doc, address + 4, address)
            address += 4 + parent

    for name in ("__swift5_types", "__swift5_protos"):
        section = doc.section_named(name)
        if section is None or section.file_offset is None:
            continue
        for entry in range(section.start, section.end, 4):
            offset = s32(entry)
            if offset and not offset & 1:
                descriptor(entry + (offset & ~3))


SWIFT_METADATA_SECTIONS = {"__swift5_fieldmd", "__constg_swiftt"}


def _referenced_strings(doc: DisassembledFile) -> None:
    """Strings in REFERENCED_STRING_SECTIONS, at referenced addresses.

    These are names that Swift metadata points at, and text that code points at
    when it is printable ASCII of at least 4 characters (shorter or binary data is not a string).
    """
    if doc.file_type != "Mach-O":
        return
    for section in doc.all_sections():
        if section.name not in REFERENCED_STRING_SECTIONS or section.file_offset is None:
            continue
        targets = {t: sources for t, sources in section.segment.references_to.items()
                   if sources and section.contains(t)}
        for address in sorted(targets):
            if address in doc.data_items or doc.object_start_containing(address) is not None:
                continue
            raw = doc.read_bytes(address, min(4096, section.end - address)).split(b"\0", 1)
            if len(raw) < 2 or not raw[0]:
                continue  # no terminator, or empty
            text = decode_string(raw[0])
            if not all(char.isprintable() or char in "\t\n\r" for char in text):
                continue
            sources = {getattr(doc.section_at_virtual_address(s), "name", None) for s in targets[address]}
            from_swift = bool(sources & SWIFT_METADATA_SECTIONS)
            from_code = any(s in doc.instructions for s in targets[address])
            if from_swift or from_code and len(text) >= 4 and all(" " <= char <= "~" for char in text):
                _add_string(doc, address, raw[0])


def _operands(op_str: str) -> list[str]:
    """Operands split on top-level commas (memory operands keep theirs)."""
    out, depth, current = [], 0, ""
    for char in op_str:
        depth += char == "["
        depth -= char == "]"
        if char == "," and not depth:
            out.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        out.append(current.strip())
    return out


def _register(operand: str) -> str | None:
    match = _GPR.fullmatch(operand)
    if not match:
        return None
    return f"x{match.group(1)}" if match.group(1) else "sp"


def _access(mnemonic: str, register: str) -> tuple[int, bool] | None:
    """(width in bytes, floating point) of a load/store, from its mnemonic and first register."""
    if mnemonic.endswith("b") and mnemonic.startswith(("ldr", "str", "ldur", "stur")):
        return 1, False
    if mnemonic.endswith("h") and mnemonic.startswith(("ldr", "str", "ldur", "stur")):
        return 2, False
    return {"x": (8, False), "w": (4, False), "d": (8, True), "s": (4, True), "q": (16, False)}.get(register[:1])


def _note_access(accesses: dict[int, tuple[int, bool, bool]], location: int,
                 access: tuple[int, bool, bool]) -> None:
    """Read at several widths, a location is labelled by the narrowest."""
    known = accesses.get(location)
    if known is None or access[0] < known[0]:
        accesses[location] = access


def _track_arm64(doc: DisassembledFile, address: int, ins: Instruction, regs: dict[str, tuple[int, int | None]],
                 accesses: dict[int, tuple[int, bool, bool]], switch_tables: set[int]) -> None:
    """Constant propagation through adrp/adr/add/sub/mov, with a reference at every resolved address.

    ``regs`` maps a register to (value, address of the ``adrp`` that produced it, if unchanged).
    An ``adrp`` references its page unless an ``add``/``sub`` turns the page into
    another address (then only that instruction references the result).
    """
    mnemonic = ins.mnemonic
    if mnemonic in ("bl", "blr"):
        for reg in _CALLER_SAVED:
            regs.pop(reg, None)
        return
    if mnemonic in ("b", "br", "ret", "brk", "retab", "braa", "brab"):
        regs.clear()
        return
    ops = _operands(ins.op_str)
    if not ops:
        return
    dest = _register(ops[0])

    def resolved(value: int) -> None:
        if doc.has_segment_at(value):
            doc.add_reference(address, value, data=True)

    if mnemonic in ("adrp", "adr") and len(ops) == 2 and (value := _IMM.fullmatch(ops[1])):
        regs[dest] = (int(value.group(1), 0), address if mnemonic == "adrp" else None)
        resolved(regs[dest][0])
        return
    source = regs.get(_register(ops[1])) if len(ops) > 1 else None
    if mnemonic in ("add", "sub") and len(ops) == 3 and source is not None and (value := _IMM.fullmatch(ops[2])):
        delta = int(value.group(1), 0)
        regs[dest] = (source[0] + (delta if mnemonic == "add" else -delta), None)
        if source[1] is not None:  # the adrp only computed part of this address
            doc.remove_reference(source[1], source[0])
        resolved(regs[dest][0])
        return
    if mnemonic == "mov" and len(ops) == 2 and source is not None:
        regs[dest] = (source[0], None)
        return
    if mnemonic in ("ldr", "ldrsw") and len(ops) == 2 and (value := _IMM.fullmatch(ops[1])):
        location = int(value.group(1), 0)  # PC-relative literal: a constant stored in the code
        resolved(location)
        if access := _access(mnemonic, ops[0]):
            _note_access(accesses, location, access + (True,))
        regs.pop(dest, None)
        return
    indexed = _INDEXED.search(ins.op_str)
    if indexed and mnemonic.startswith("ld") and regs.get(_register(indexed.group(1))) is not None:
        switch_tables.add(regs[_register(indexed.group(1))][0])  # table[index]: a switch jump table
    memory = _MEMORY.search(ins.op_str)
    if memory:
        base = _register(memory.group(1))
        if regs.get(base) is not None:
            location = regs[base][0] + (int(memory.group(2), 0) if memory.group(2) else 0)
            resolved(location)
            if mnemonic.startswith(("ld", "st")) and (access := _access(mnemonic, ops[0])):
                _note_access(accesses, location, access + (False,))
            if mnemonic in ("ldr", "ldur") and ins.op_str.startswith("x") and location in doc.data_items:
                for target in doc.references_from(location):  # loading a pointer slot (selrefs, GOT…)
                    resolved(target)
        if memory.group(3) or memory.group(4):  # writeback changes the base register
            regs.pop(base, None)
        if mnemonic.startswith("ld"):
            for operand in ops[:2] if mnemonic.startswith(("ldp", "ldnp", "ldxp", "ldaxp")) else ops[:1]:
                regs.pop(_register(operand), None)
        elif mnemonic.startswith(("stxr", "stlxr", "stxp", "stlxp")):
            regs.pop(dest, None)
        return
    if indexed and mnemonic.startswith("ld"):
        regs.pop(dest, None)
    elif dest and not mnemonic.startswith(_NO_WRITE):
        regs.pop(dest, None)


_X86_SIZE = re.compile(r"\b(byte|word|dword|qword|xmmword) ptr \[")
_X86_WIDTHS = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16}
_X86_NO_WRITE = ("cmp", "test", "push", "j", "call", "ret", "nop", "ucomis", "comis", "bt")


def _track_x86(doc: DisassembledFile, address: int, ins: Instruction, branch: bool,
               regs: dict[str, tuple[int, int | None]], accesses: dict[int, tuple[int, bool, bool]]) -> None:
    """RIP-relative references and the data they load or store."""
    mnemonic = ins.mnemonic
    if mnemonic.startswith(("call", "jmp", "ret")):
        regs.clear()
        return
    ops = _operands(ins.op_str)
    dest = ops[0] if ops and re.fullmatch(r"[re]?[a-z0-9]{2,3}[dwb]?", ops[0]) else None
    rip = _RIP.search(ins.op_str)
    if rip and not branch:
        location = address + ins.size + int(rip.group(2), 0) * (1 if rip.group(1) == "+" else -1)
        doc.add_reference(address, location, data=True)
        if mnemonic == "lea" and dest:
            regs[dest] = (location, None)
            return
        size = _X86_SIZE.search(ins.op_str)
        if size and doc.has_segment_at(location):
            floating = mnemonic.endswith(("sd", "ss")) and not mnemonic.startswith("cvtsi")
            width = 4 if floating and mnemonic.endswith("ss") else _X86_WIDTHS[size.group(1)]
            _note_access(accesses, location, (width, floating, False))
    # x86 switch tables ([table + index*4]) are not labelled: labelling all of them adds
    # far more noise than useful names.
    if dest and not mnemonic.startswith(_X86_NO_WRITE):
        regs.pop(dest, None)


def _find_references(doc: DisassembledFile) -> None:
    cpu = doc.cpu
    regs: dict[str, tuple[int, int | None]] = {}
    accesses: dict[int, tuple[int, bool, bool]] = {}
    switch_tables: set[int] = set()
    expected = None
    for address, ins in doc.instructions.items():
        if address != expected:  # a gap: values from before it are unknown
            regs.clear()
        expected = address + ins.size
        target = branch_target(cpu, ins)
        if target is not None:
            doc.add_reference(address, target)
        if cpu == "arm64":
            _track_arm64(doc, address, ins, regs, accesses, switch_tables)
        elif cpu.startswith("x86"):
            _track_x86(doc, address, ins, target is not None, regs, accesses)
    for table in sorted(switch_tables):
        if doc.has_segment_at(table) and not doc.names.has_name_at_address(table):
            doc.set_name(table, f"switch_table_{table:x}")
    _label_data(doc, accesses)


_WIDTH_TYPES = {1: ByteType.INT8, 2: ByteType.INT16, 4: ByteType.INT32, 8: ByteType.INT64}
_ADDRESS_LABELS = {1: "byte_", 2: "word_", 4: "dword_", 8: "qword_", 16: "oword_"}
_VALUE_LABELS = {(1, False): "byte_value_", (2, False): "word_value_", (4, False): "dword_value_",
                 (8, False): "qword_value_", (4, True): "float_value_", (8, True): "double_value_"}


def _label_data(doc: DisassembledFile, accesses: dict[int, tuple[int, bool, bool]]) -> None:
    """Labels for memory that code loads or stores.

    Writable data is named by address (``qword_1012c9740``); read-only constants in __TEXT by
    value (``double_value_0_1``, ``dword_value_4043308897``).
    """
    for location, (width, floating, literal) in sorted(accesses.items()):
        section = doc.section_at_virtual_address(location)
        if section is None or width not in _WIDTH_TYPES or is_code_section(doc, section) and not literal \
                or location in doc.strings or doc.names.has_name_at_address(location) \
                or doc.object_start_containing(location) not in (None, location) \
                or location in doc.data_items and doc.references_from(location):  # pointer slots stay unnamed
            continue
        if section.segment.name == "__TEXT":
            prefix = _VALUE_LABELS.get((width, floating))
            raw = doc.read_bytes(location, width)
            if prefix is None or len(raw) != width:
                continue
            if floating:  # printf("%g"): 1E06, 0_1, 1_0227E_minus_312
                value = struct.unpack("<d" if width == 8 else "<f", raw)[0]
                text = ("%g" % value).replace("e", "E").replace("+", "").replace("-", "_minus_")
                text = text.replace(".", "_").lstrip("_")
            else:
                text = str(int.from_bytes(raw, "little"))
            label = prefix + text
        else:
            prefix = {4: "float_", 8: "double_"}[width] if floating else _ADDRESS_LABELS[width]
            label = f"{prefix}{location:x}"
        doc.set_name(location, _unique(doc, label, location))
        if width in _WIDTH_TYPES:
            doc.data_items.setdefault(location, DataItem(_WIDTH_TYPES[width], width))


# Optionally fold some compiler-listed functions into the procedure before them (a start reached
# only by `b` from it). Off by default, so that every function the compiler lists
# (LC_FUNCTION_STARTS, unwind info) is a procedure.
MERGE_JUMPED_STARTS = False


def _merge_jumped_into(doc: DisassembledFile, ordered: list[int]) -> list[int]:
    """A start whose only jumps come from the procedure before it, all unconditional
    ``b`` (calls allowed), and with no symbol or data reference, is part of that procedure.

    Such ``LC_FUNCTION_STARTS`` entries are typically Swift outlined tails; starts reached by
    conditional branches stay separate.
    """
    if doc.cpu != "arm64":  # arm64 only; on x86 these follow nop padding
        return ordered
    kept: list[int] = []
    current = None
    for start in ordered:
        if current is not None and start != doc.entry_point and not doc.names.has_name_at_address(start) \
                and doc.section_at_virtual_address(start) is doc.section_at_virtual_address(current):
            sources = doc.references_to(start)
            jumps = [r for r in sources if r in doc.instructions and not is_call(doc.cpu, doc.instructions[r].mnemonic)]
            if jumps and all(r in doc.instructions for r in sources) \
                    and all(current <= r < start and doc.instructions[r].mnemonic == "b" for r in jumps):
                continue
        kept.append(start)
        current = start
    return kept


def _build_procedures(doc: DisassembledFile, code_sections: list[Section]) -> None:
    cpu = doc.cpu
    starts = {a for a in doc.function_starts if a in doc.instructions}
    for ins in doc.instructions.values():
        if is_call(cpu, ins.mnemonic) and not doc.relocatable:
            target = branch_target(cpu, ins)
            if target in doc.instructions:
                starts.add(target)
    if doc.entry_point in doc.instructions:
        starts.add(doc.entry_point)
    stubs = doc.section_named("__objc_stubs") if doc.file_type == "Mach-O" else None
    if stubs is not None:  # each objc_msgSend stub, and each brk padding after it
        previous = "br"
        for address in range(stubs.start, stubs.end, 4):
            ins = doc.instructions.get(address)
            if ins is None:
                continue
            if previous in ("br", "brk") or ins.mnemonic == "brk":
                starts.add(address)
                if ins.mnemonic != "brk" and not doc.names.has_name_at_address(address):
                    _name_objc_stub(doc, address)
            previous = ins.mnemonic
    if not starts and doc.file_type == "Raw" and doc.instructions:
        starts.add(min(doc.instructions))
    ordered = sorted(starts)
    weak = set(ordered) - set(_merge_jumped_into(doc, ordered)) if MERGE_JUMPED_STARTS else set()
    doc.procedures.update(build_procedures(doc, ordered, weak, code_sections))
    for start in sorted(doc.procedures):
        if not doc.names.has_name_at_address(start):
            doc.set_name(start, "EntryPoint" if start == doc.entry_point else f"sub_{start:x}")
    doc.rebuild_object_index()


def _name_objc_stub(doc: DisassembledFile, stub: int) -> None:
    """``_objc_msgSend$selector``: the stub loads its selector (adrp + ldr from ``__objc_selrefs``)."""
    for address in (stub, stub + 4):
        for target in doc.references_from(address):
            section = doc.section_at_virtual_address(target)
            if target in doc.strings and section is not None and section.name == "__objc_methname":
                doc.set_name(stub, _unique(doc, f"_objc_msgSend${doc.strings[target]}", stub))
                return


def display_escaped(text: str) -> str:
    """How a string is displayed: C escapes, and non-ASCII as its UTF-8 bytes (``\\xE2\\x80\\xA6``)."""
    out = []
    for char in text:
        if char in "\n\t\r":
            out.append({"\n": "\\n", "\t": "\\t", "\r": "\\r"}[char])
        elif char in '"\\':
            out.append("\\" + char)
        elif " " <= char <= "~":
            out.append(char)
        else:
            out.extend(f"\\x{byte:02X}" for byte in char.encode("utf-8"))
    return "".join(out)


def string_label(text: str) -> str:
    """The label for a string: ``"When a Window is Open"`` -> ``aWhenAWindowIsO``.

    Built from the escaped text, so a newline contributes an ``n``.
    """
    words = (re.sub(r"[^0-9A-Za-z]", "", word) for word in display_escaped(text).split())
    body = "".join(word[:1].upper() + word[1:].lower() for word in words if word)
    return "a" + body[:14] if body else "asc"


def _unique(doc: DisassembledFile, label: str, address: int) -> str:
    return f"{label}_{address:x}" if doc.names.has_name(label) else label


def _label_strings(doc: DisassembledFile) -> None:
    """Names unnamed strings and CFStrings, so name searches find them.

    When two strings get the same label the first one named keeps it: the Swift
    reflection strings are named first, then the others by address.
    """
    def swift_first(address: int) -> tuple[bool, int]:
        section = doc.section_at_virtual_address(address)
        return (section is None or section.name != "__swift5_reflstr", address)

    texts = {**doc.header_strings, **doc.strings}  # load-command paths are named, not listed as strings
    for address in sorted(texts, key=swift_first):
        if not doc.names.has_name_at_address(address):
            doc.set_name(address, _unique(doc, string_label(texts[address]), address))
    cfstrings = doc.section_named("__cfstring") if doc.file_type == "Mach-O" else None
    if cfstrings is None:
        return
    for address in range(cfstrings.start, cfstrings.end, 32):
        text = next((doc.strings[t] for t in doc.references_from(address) if t in doc.strings), None)
        if text is not None and not doc.names.has_name_at_address(address):
            label = "cfstring_" + re.sub(r"[^0-9A-Za-z]", "_", display_escaped(text))
            doc.set_name(address, _unique(doc, label, address))


def _eh_frame_strings(doc: DisassembledFile) -> None:
    """The augmentation string ("zR") of each CIE in ``__eh_frame``, listed as strings
    (without naming them)."""
    section = doc.section_named("__eh_frame") if doc.file_type == "Mach-O" else None
    if section is None or section.file_offset is None:
        return
    position = section.start
    while position + 8 <= section.end:
        length = int.from_bytes(doc.read_bytes(position, 4), "little")
        if length in (0, 0xFFFFFFFF):  # end marker, or a 64-bit record (not produced for Mach-O)
            return
        if not int.from_bytes(doc.read_bytes(position + 4, 4), "little"):  # CIE id 0
            raw = doc.read_bytes(position + 9, 16).split(b"\0", 1)[0]
            if raw and position + 9 not in doc.data_items:
                _add_string(doc, position + 9, raw)
        position += 4 + length


def _auto_tags(doc: DisassembledFile) -> None:
    if doc.entry_point != BAD_ADDRESS:
        doc.add_tag("entrypoint", doc.entry_point)
    for address, name in list(doc.names.items()):
        match = _OBJC_METHOD.match(name)
        if match:
            doc.add_tag(match.group(1), address)
            if match.group(2):
                doc.add_tag(match.group(2), address)

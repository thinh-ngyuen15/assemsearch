"""Objective-C metadata.

Walks the classes, metaclasses, categories and protocols of a Mach-O image to:

* name method implementations ``-[Class selector]`` / ``+[Class(Category) selector]``,
  and make them procedure starts;
* credit the references held by each metadata structure (``class_ro_t``, ``method_t``,
  ``ivar_t``, ``property_t``…) to the structure's first byte.

Pointers are read through the decoded chained fixups (``pointer_targets``) when present.
"""

from __future__ import annotations

from assemsearch.model import DataItem, DisassembledFile
from assemsearch.types import ByteType

FAST_DATA_MASK = 0x00007FFFFFFFFFF8
RELATIVE_METHODS = 0x80000000
DIRECT_SELECTORS = 0x40000000


class _Reader:
    def __init__(self, doc: DisassembledFile) -> None:
        self.doc = doc

    def u32(self, address: int) -> int:
        raw = self.doc.read_bytes(address, 4)
        return int.from_bytes(raw, "little") if len(raw) == 4 else 0

    def s32(self, address: int) -> int:
        raw = self.doc.read_bytes(address, 4)
        return int.from_bytes(raw, "little", signed=True) if len(raw) == 4 else 0

    def pointer(self, address: int) -> int | None:
        """The address a pointer slot holds (decoded rebase or plain pointer), None if not one."""
        doc = self.doc
        if address in doc.pointer_targets:
            return doc.pointer_targets[address]
        raw = doc.read_bytes(address, 8)
        value = int.from_bytes(raw, "little") if len(raw) == 8 else 0
        return value if value and doc.has_segment_at(value) else None

    def string(self, address: int | None) -> str | None:
        if address is None:
            return None
        if address in self.doc.strings:
            return self.doc.strings[address]
        raw = self.doc.read_bytes(address, 256).split(b"\0", 1)[0]
        return raw.decode("utf-8", "replace") if raw else None


def _label(doc: DisassembledFile, address: int | None, name: str | None) -> None:
    """Names for metadata (``__objc_class_Foo_data``…); a repeated name gets ``_<address>``."""
    if address is None or name is None or doc.names.has_name_at_address(address):
        return
    doc.set_name(address, f"{name}_{address:x}" if doc.names.has_name(name) else name)


def _structure(doc: DisassembledFile, start: int, size: int) -> None:
    """Moves the references made by pointer slots inside a structure to its first byte."""
    for slot in range(start + 8, start + size, 8):
        for target in doc.references_from(slot):
            doc.remove_reference(slot, target)
            doc.add_reference(start, target, data=True)


class ObjCMetadata:
    def __init__(self, doc: DisassembledFile) -> None:
        self.doc = doc
        self.read = _Reader(doc)
        self.methods = 0

    # Lists -----------------------------------------------------------------------------

    def method_list(self, address: int | None, owner: str | None, prefix: str, label: str | None = None) -> None:
        if address is None:
            return
        doc, read = self.doc, self.read
        _label(doc, address, label)
        flags, count = read.u32(address), read.u32(address + 4)
        entry_size = flags & 0xFFFC
        if not entry_size or count > 0x10000:
            return
        _structure(doc, address, 8)
        for entry in range(address + 8, address + 8 + entry_size * count, entry_size):
            if flags & RELATIVE_METHODS:
                name_field = entry + read.s32(entry)
                selector = read.string(name_field if flags & DIRECT_SELECTORS else read.pointer(name_field))
                imp_offset = read.s32(entry + 8)
                imp = entry + 8 + imp_offset if imp_offset else None
                for field in (entry, entry + 4, entry + 8):
                    offset = read.s32(field)
                    doc.data_items.setdefault(field, DataItem(ByteType.INT32, 4))
                    if offset and doc.has_segment_at(field + offset):
                        doc.add_reference(entry, field + offset, data=True)
            else:
                selector = read.string(read.pointer(entry))
                imp = read.pointer(entry + 16)
                _structure(doc, entry, entry_size)
            if imp is not None and selector and owner and imp in doc.instructions:
                self.name_method(imp, f"{prefix}[{owner} {selector}]")

    def name_method(self, imp: int, name: str) -> None:
        doc = self.doc
        doc.function_starts.add(imp)
        self.methods += 1
        if doc.names.has_name_at_address(imp) or doc.names.has_name(name):
            return
        doc.set_name(imp, name)

    def simple_list(self, address: int | None, minimum_entry: int, label: str | None = None,
                    ivars_of: str | None = None) -> None:
        """ivar_list_t / property_list_t: each entry is a structure of its own."""
        if address is None:
            return
        read = self.read
        entry_size, count = read.u32(address) & 0xFFFC, read.u32(address + 4)
        if entry_size < minimum_entry or count > 0x10000:
            return
        _label(self.doc, address, label)
        for entry in range(address + 8, address + 8 + entry_size * count, entry_size):
            if ivars_of is not None:  # ivar_t: the offset variable is "objc_ivar_offset_<class>_<ivar>"
                ivar = read.string(read.pointer(entry + 8))
                _label(self.doc, read.pointer(entry), f"objc_ivar_offset_{ivars_of}_{ivar}" if ivar else None)
            _structure(self.doc, entry, entry_size)

    # Containers ---------------------------------------------------------------------------

    def class_ro(self, address: int | None, prefix: str, seen: set[int]) -> str | None:
        """class_ro_t: returns the class name."""
        if address is None or address in seen:
            return None
        seen.add(address)
        read = self.read
        name = read.string(read.pointer(address + 24))
        label = f"__objc_class_{name}" if name else None
        _label(self.doc, address, label and f"{label}_data")
        self.method_list(read.pointer(address + 32), name, prefix, label and f"{label}_methods")
        self.simple_list(read.pointer(address + 48), 32, label and f"{label}_ivars", ivars_of=name)
        self.simple_list(read.pointer(address + 64), 16, label and f"{label}_properties")
        _structure(self.doc, address, 72)
        return name

    def class_(self, address: int | None, seen: set[int]) -> None:
        if address is None or address in seen:
            return
        seen.add(address)
        read = self.read
        data = read.pointer(address + 32)
        name = self.class_ro(data & FAST_DATA_MASK if data else None, "-", seen)
        _label(self.doc, address, name and f"__objc_class_{name}_class")
        metaclass = read.pointer(address)
        if metaclass is not None and metaclass not in seen:
            seen.add(metaclass)
            label = f"__objc_metaclass_{name}" if name else None
            _label(self.doc, metaclass, label and f"{label}_metaclass")
            meta_data = read.pointer(metaclass + 32)
            if meta_data:
                ro = meta_data & FAST_DATA_MASK
                _label(self.doc, ro, label and f"{label}_data")
                self.method_list(read.pointer(ro + 32), name, "+", label and f"{label}_methods")
                _structure(self.doc, ro, 72)
            _structure(self.doc, metaclass, 40)
        _structure(self.doc, address, 40)

    def class_name(self, slot: int) -> str | None:
        """Name of the class a category extends: one of ours (rebase) or an imported one (bind)."""
        doc, read = self.doc, self.read
        target = read.pointer(slot)
        if target is not None:
            data = read.pointer(target + 32)
            return read.string(read.pointer((data & FAST_DATA_MASK) + 24)) if data else None
        imported = doc.pointer_imports.get(slot)
        return imported.removeprefix("_OBJC_CLASS_$_") if imported else None

    def category(self, address: int | None) -> None:
        if address is None:
            return
        read = self.read
        category = read.string(read.pointer(address))
        owner = f"{self.class_name(address + 8)}({category})"
        label = f"__objc_cat_{category}"
        self.method_list(read.pointer(address + 16), owner, "-", f"{label}_inst_methods")
        self.method_list(read.pointer(address + 24), owner, "+", f"{label}_class_methods")
        self.simple_list(read.pointer(address + 40), 16, f"{label}_inst_properties")
        _structure(self.doc, address, 48)

    def protocol(self, address: int | None) -> None:
        if address is None:
            return
        read = self.read
        name = read.string(read.pointer(address + 8))
        label = f"__objc_proto_{name}"
        for offset, prefix, kind in ((24, "-", "inst_methods"), (32, "+", "class_methods"),
                                     (40, "-", "opt_inst_methods"), (48, "+", "opt_class_methods")):
            # Protocol methods have no IMPs, so only the list is named.
            self.method_list(read.pointer(address + offset), name, prefix, f"{label}_{kind}")
        self.simple_list(read.pointer(address + 56), 16, f"{label}_properties")
        _structure(self.doc, address, min(max(read.u32(address + 64), 72), 128))  # protocol_t.size

    # Entry point ----------------------------------------------------------------------------

    def parse(self) -> int:
        doc, read = self.doc, self.read
        seen: set[int] = set()

        def pointers(section_name: str):
            section = doc.section_named(section_name)
            if section is None or section.file_offset is None:
                return []
            return [read.pointer(slot) for slot in range(section.start, section.end, 8)]

        for address in pointers("__objc_classlist") + pointers("__objc_nlclslist"):
            self.class_(address, seen)
        for address in pointers("__objc_catlist") + pointers("__objc_nlcatlist"):
            self.category(address)
        for address in pointers("__objc_protolist"):
            self.protocol(address)
        return self.methods


def parse_objc_metadata(doc: DisassembledFile) -> int:
    """Returns the number of method implementations found."""
    if doc.file_type != "Mach-O" or doc.section_named("__objc_classlist") is None and \
            doc.section_named("__objc_catlist") is None:
        return 0
    return ObjCMetadata(doc).parse()

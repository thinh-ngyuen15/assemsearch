"""Rendering of the assembly listing (what *String in Assembly* searches)."""

from __future__ import annotations

from assemsearch.analysis import branch_target
from assemsearch.model import DisassembledFile
from assemsearch.types import ByteType, format_address


def _escape(char: str) -> str:
    if char == '"':
        return '\\"'
    if char.isprintable() and char != "\\":
        return char  # keeps non-ASCII text readable and searchable
    return char.encode("unicode_escape").decode("ascii")


def _quote(text: str, limit: int = 60) -> str:
    escaped = "".join(map(_escape, text))
    return '"' + (escaped if len(escaped) <= limit else escaped[:limit] + "…") + '"'


def describe_target(doc: DisassembledFile, address: int) -> str | None:
    if address in doc.strings:
        return _quote(doc.strings[address])
    name = doc.name_for_virtual_address(address)
    if name:
        return name
    procedure = doc.procedure_at(address)
    if procedure is not None and address in procedure.local_labels:
        return procedure.local_labels[address]
    return None


def instruction_text(doc: DisassembledFile, address: int) -> str:
    ins = doc.instructions[address]
    text = ins.text
    target = branch_target(doc.cpu, ins)
    if target is not None:
        label = describe_target(doc, target)
        if label and not label.startswith('"'):
            # Only the last operand is the target.
            head, _, _ = ins.op_str.rpartition(",")
            text = f"{ins.mnemonic} {head + ', ' if head else ''}{label}"
        return text
    notes = [d for t in doc.references_from(address) if (d := describe_target(doc, t))]
    if notes:
        text += "  ; " + ", ".join(notes)
    return text


def data_text(doc: DisassembledFile, address: int) -> str:
    item = doc.data_items[address]
    if item.type == ByteType.ASCII:
        return f"db {_quote(doc.strings.get(address, ''), 200)}, 0"
    raw = doc.read_bytes(address, item.length)
    value = doc.pointer_targets.get(address, int.from_bytes(raw, "little"))
    directive = {1: "db", 2: "dw", 4: "dd", 8: "dq"}.get(item.length, "db")
    target = describe_target(doc, value) if doc.has_segment_at(value) else None
    return f"{directive} {target or format_address(value)}"


def undefined_text(doc: DisassembledFile, address: int) -> str:
    byte = doc.read_bytes(address, 1)
    if not byte:
        return "db ?"
    value = byte[0]
    char = f"  ; {chr(value)!r}" if 0x20 <= value < 0x7F else ""
    return f"db 0x{value:02x}{char}"


def lines_for_virtual_address(doc: DisassembledFile, address: int, include_decorations: bool = True,
                              inline_comments: bool = True, address_field: bool = True,
                              hex_column: bool = False, compact: bool = False) -> list[str]:
    """``stringsForVirtualAddress:includingDecorations:inlineComments:addressField:hexColumn:compactMode:``."""
    lines: list[str] = []
    if include_decorations:
        procedure = doc.procedures.get(address)
        if procedure is not None and not compact:
            lines += ["", "        ; ================ B E G I N   N E X T   P R O C E D U R E ================", ""]
        comment = doc.comment_at_virtual_address(address)
        if comment:
            lines += [f"        ; {line}" for line in comment.splitlines()]
        label = doc.name_for_virtual_address(address)
        if label is None:
            owner = doc.procedure_at(address)
            label = owner.local_labels.get(address) if owner else None
        if label:
            xrefs = doc.references_to(address)
            xref_text = ""
            if xrefs:
                shown = ", ".join(doc.friendly_name_for_virtual_address(x) for x in xrefs[:6])
                xref_text = f"  ; XREF={shown}{', …' if len(xrefs) > 6 else ''}"
            lines.append(f"{label}:{xref_text}")
    if address in doc.instructions:
        body, length = instruction_text(doc, address), doc.instructions[address].size
    elif address in doc.data_items:
        body, length = data_text(doc, address), doc.data_items[address].length
    else:
        body, length = undefined_text(doc, address), 1
    parts = []
    if address_field:
        parts.append(f"{address:016x}" if not compact else f"{address:x}")
    if hex_column:
        parts.append(doc.read_bytes(address, min(length, 8)).hex(" ").ljust(24))
    parts.append(body)
    line = "  ".join(parts)
    if inline_comments:
        inline = doc.inline_comment_at_virtual_address(address)
        if inline:
            line += f"  ; {inline}"
    lines.append(line)
    return lines


def listing(doc: DisassembledFile, start: int, end: int, **options) -> list[tuple[int, list[str]]]:
    """Rendered objects in [start, end)."""
    out = []
    address = start
    while address < end and doc.has_segment_at(address):
        out.append((address, lines_for_virtual_address(doc, address, **options)))
        address = doc.next_address_of_virtual_address(address)
    return out

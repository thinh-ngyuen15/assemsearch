"""Address-string parsing for Go To (address, symbol, file offset)."""

from __future__ import annotations

import enum
import re

from assemsearch.model import DisassembledFile
from assemsearch.types import BAD_ADDRESS

_HEX = re.compile(r"(0[xX])?[0-9a-fA-F]+")
_DEC = re.compile(r"[0-9]+")
_HEX_LETTERS = re.compile(r"[a-fA-F]")

NO_FILE_OFFSET_MATCH = "No addresses match this file offset."
INVALID_NUMBER = "Invalid number."


class GotoType(enum.IntEnum):
    ADDRESS = 0
    FILE_OFFSET = 1
    GLOBAL_FILE_OFFSET = 2


class GotoError(ValueError):
    pass


def reformat_spaces(text: str) -> str:
    return " ".join(text.split())


def is_valid_hex_string(text: str) -> bool:
    return bool(_HEX.fullmatch(text))


def is_valid_dec_string(text: str) -> bool:
    return bool(_DEC.fullmatch(text))


def parse_hex_address(text: str) -> int:
    return int(text, 16) if is_valid_hex_string(text) else BAD_ADDRESS


def parse_address_string(doc: DisassembledFile, text: str) -> int:
    """Resolution order: exact name, ``$``-stripped name, hex, decimal."""
    text = text.strip()
    if not text:
        return BAD_ADDRESS
    address = doc.find_virtual_address_named(text)
    if address != BAD_ADDRESS:
        return address
    if text.startswith("$") and len(text) > 1:
        address = doc.find_virtual_address_named(text[1:])
        if address != BAD_ADDRESS:
            return address
    if is_valid_hex_string(text):
        address = int(text, 16)
        if doc.has_segment_at(address):
            return address
    if is_valid_dec_string(text):
        address = int(text, 10)
        if doc.has_segment_at(address):
            return address
    return BAD_ADDRESS


def parse_offset_number(text: str) -> int:
    """NSScanner logic of the file-offset modes."""
    text = reformat_spaces(text).replace(" ", "")
    if text.lower().startswith("0x") or _HEX_LETTERS.search(text):
        if not is_valid_hex_string(text):
            raise GotoError(INVALID_NUMBER)
        return int(text, 16)
    if is_valid_dec_string(text):
        return int(text, 10)
    raise GotoError(INVALID_NUMBER)


def resolve_goto(doc: DisassembledFile, text: str, goto_type: int) -> int:
    """Address for the Go To sheet input; raises GotoError with the sheet's alerts."""
    text = reformat_spaces(text)
    if GotoType(goto_type) == GotoType.ADDRESS:
        return parse_address_string(doc, text)
    offset = parse_offset_number(text)
    if goto_type == GotoType.GLOBAL_FILE_OFFSET:
        offset -= doc.container_file_offset
    address = doc.virtual_address_from_file_offset(offset)
    if address == BAD_ADDRESS:
        raise GotoError(NO_FILE_OFFSET_MATCH)
    return address

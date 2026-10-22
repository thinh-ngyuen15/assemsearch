"""Shared constants and small value types."""

from __future__ import annotations

import enum
from dataclasses import dataclass

BAD_ADDRESS = 0xFFFFFFFFFFFFFFFF
NOT_FOUND = 0x7FFFFFFFFFFFFFFF  # NSNotFound


class ByteType(enum.IntEnum):
    """Byte types and search meta-types."""

    UNDEFINED = 0
    OUTSIDE = 1
    NEXT = 2
    INT8 = 3
    INT16 = 4
    INT32 = 5
    INT64 = 6
    ASCII = 7
    UNICODE = 8
    EXTERN_ADDRESS = 0x3D
    EXTERN_FUNCTION = 0x3E
    ALIGN = 0x3F
    DATA = 0x40  # meta-type: only used for searching
    CODE = 0x41
    PROCEDURE = 0x42  # meta-type: first byte of a procedure
    STRUCTURE = 0x43


DATA_TYPES = frozenset({
    ByteType.INT8, ByteType.INT16, ByteType.INT32, ByteType.INT64,
    ByteType.ASCII, ByteType.UNICODE, ByteType.EXTERN_ADDRESS,
    ByteType.EXTERN_FUNCTION, ByteType.ALIGN, ByteType.STRUCTURE,
})


@dataclass(frozen=True)
class AddressRange:
    """A half-open range [location, location + length)."""

    location: int
    length: int

    @property
    def end(self) -> int:
        return self.location + self.length

    def __contains__(self, address: int) -> bool:
        return self.location <= address < self.end


def format_address(address: int) -> str:
    return f"0x{address:x}"

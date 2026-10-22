"""Byte matcher: ``-[NSData(Searching) locationOfData:inRange:withOptions:]``.

Option bits: 0x1 ASCII case-insensitive (letters also match ``c ^ 0x20``),
0x2 ``?`` in the pattern matches any byte, 0x4 backwards (last match first).
Returns NOT_FOUND when there is no match.  The semantics are the naive
O(n*m) scan's; plain searches use ``bytes.find`` and option searches compile
an equivalent byte regex.
"""

from __future__ import annotations

import re

from assemsearch.types import NOT_FOUND

CASE_INSENSITIVE = 0x1
WILDCARD = 0x2
BACKWARDS = 0x4


def _is_alpha(byte: int) -> bool:
    return 0x41 <= byte <= 0x5A or 0x61 <= byte <= 0x7A


def _compile(needle: bytes, options: int) -> re.Pattern[bytes]:
    parts = []
    for byte in needle:
        if options & WILDCARD and byte == 0x3F:
            parts.append(b".")
        elif options & CASE_INSENSITIVE and _is_alpha(byte):
            parts.append(b"[" + re.escape(bytes([byte])) + re.escape(bytes([byte ^ 0x20])) + b"]")
        else:
            parts.append(re.escape(bytes([byte])))
    return re.compile(b"".join(parts), re.DOTALL)


def locate_data(haystack: bytes, needle: bytes, start: int = 0, end: int | None = None, options: int = 0) -> int:
    end = len(haystack) if end is None else min(end, len(haystack))
    if not needle or start < 0 or end - start < len(needle):
        return NOT_FOUND
    if not options & (CASE_INSENSITIVE | WILDCARD):
        found = haystack.rfind(needle, start, end) if options & BACKWARDS else haystack.find(needle, start, end)
        return NOT_FOUND if found < 0 else found
    pattern = _compile(needle, options)
    if not options & BACKWARDS:
        match = pattern.search(haystack, start, end)
        return match.start() if match else NOT_FOUND
    # Backwards: test candidate positions from the end (overlapping matches allowed).
    for position in range(end - len(needle), start - 1, -1):
        if pattern.match(haystack, position, end):
            return position
    return NOT_FOUND

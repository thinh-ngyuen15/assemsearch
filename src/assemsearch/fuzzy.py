"""Fuzzy matching and ranking (NSString(FuzzyPatternScore) + FuzzyPredicate).

Scores: 0 = no match, 1 = case-insensitive substring (or empty pattern),
k = the pattern was found as an in-order subsequence split into k contiguous runs
(k - 1 insertions).  Lower is better.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable, Sequence, TypeVar

T = TypeVar("T")

HIGHLIGHT = "\x1b[1;33m"
RESET = "\x1b[0m"


_NONE = 1 << 30  # no way to match


def _fold(text: str) -> str:
    """Upper case, one character per character (``ß`` stays ``ß``), so indices still match ``text``."""
    upper = text.upper()
    if len(upper) == len(text):  # no character expanded (each maps to at least one)
        return upper
    return "".join(u if len(u := c.upper()) == 1 else c for c in text)


def _is_subsequence(n: str, p: str) -> bool:
    it = iter(n)
    return all(ch in it for ch in p)


def _runs(n: str, p: str) -> tuple[int, list[list[int]]]:
    """Fewest contiguous runs of ``n`` that spell ``p`` in order, and the DP rows for backtracking.

    ``rows[i][j]``: fewest runs matching ``p[:j]`` with ``p[j - 1]`` matched at ``n[i]``.
    """
    m = len(p)
    where: dict[str, list[int]] = {}  # character -> the pattern positions holding it
    for j, ch in enumerate(p):
        where.setdefault(ch, []).append(j)
    best = [0] + [_NONE] * m  # fewest runs matching p[:j] within the characters seen so far
    empty = [_NONE] * (m + 1)  # shared by characters that are not in the pattern
    previous = empty
    rows = []
    for ch in n:
        positions = where.get(ch)
        if positions is None:
            previous = empty
            rows.append(empty)
            continue
        row = empty.copy()
        for j in positions:
            row[j + 1] = min(previous[j], best[j] + 1)  # continue the run, or start one
        for j in positions:  # after the whole row: it is computed from the previous characters only
            if row[j + 1] < best[j + 1]:
                best[j + 1] = row[j + 1]
        previous = row
        rows.append(row)
    return best[m], rows


def _fuzzy(n: str, p: str) -> int:
    """``fuzzy_score`` of already folded strings."""
    if p in n:
        return 1
    if not _is_subsequence(n, p):
        return 0
    return _runs(n, p)[0]


def strict_score(name: str, pattern: str) -> int:
    return 1 if _fold(pattern) in _fold(name) else 0


def fuzzy_score(name: str, pattern: str) -> int:
    return _fuzzy(_fold(name), _fold(pattern))


def score(name: str, pattern: str, fuzzy: bool = True) -> int:
    """``-[NSString scoreForMatchingPattern:fuzzy:]``."""
    if not pattern:
        return 1
    n, p = _fold(name), _fold(pattern)
    if p in n:
        return 1
    return _fuzzy(n, p) if fuzzy else 0


def matched_positions(name: str, pattern: str) -> list[int]:
    """Indices of ``name`` characters that the pattern matched (for highlighting), in the fewest runs."""
    if not pattern:
        return []
    n, p = _fold(name), _fold(pattern)
    at = n.find(p)
    if at >= 0:
        return list(range(at, at + len(p)))
    if not _is_subsequence(n, p):
        return []
    cost, rows = _runs(n, p)
    positions = []
    j = len(p)
    i = max(k for k in range(len(n)) if rows[k][j] == cost)
    while j:
        positions.append(i)
        if j > 1 and i > 0 and rows[i - 1][j - 1] == cost:  # the run continues to the left
            i -= 1
        else:  # this run started here: the rest is matched, in one run fewer, further left
            cost -= 1
            if j > 1:
                i = max(k for k in range(i) if rows[k][j - 1] == cost)
        j -= 1
    return positions[::-1]


def colorized(name: str, pattern: str, on: str = HIGHLIGHT, off: str = RESET) -> str:
    """``-colorizedMatchingPattern:``, rendered with ANSI escapes."""
    marks = set(matched_positions(name, pattern))
    if not marks:
        return name
    out = []
    for i, ch in enumerate(name):
        out.append(f"{on}{ch}{off}" if i in marks else ch)
    return "".join(out)


def rank(items: Iterable[T], pattern: str, key: Callable[[T], str], fuzzy: bool = True) -> list[tuple[int, T]]:
    """Keep matching items and sort them ascending by score (stable)."""
    scored = [(s, item) for item in items if (s := score(key(item), pattern, fuzzy))]
    scored.sort(key=lambda pair: pair[0])
    return scored


@dataclass
class FuzzyPredicate:
    """An NSPredicate-like filter over objects: ``key`` extracts the string."""

    key: Callable[[Any], str]
    pattern: str
    fuzzy: bool = True
    hide_empty: bool = False

    def evaluate(self, obj: Any) -> bool:
        if self.hide_empty and not self.pattern:
            return False
        return score(self.key(obj), self.pattern, self.fuzzy) > 0

    __call__ = evaluate

    def filter(self, objects: Sequence[Any]) -> list[Any]:
        """Filter and rank like the bound NSArrayController's arrangedObjects."""
        return [obj for _, obj in rank(
            (o for o in objects if not (self.hide_empty and not self.pattern)),
            self.pattern, self.key, self.fuzzy)]

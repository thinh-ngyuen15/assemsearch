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


def strict_score(name: str, pattern: str) -> int:
    return 1 if pattern.casefold() in name.casefold() else 0


def fuzzy_score(name: str, pattern: str) -> int:
    if pattern.upper() in name.upper():
        return 1
    n, p = name.upper(), pattern.upper()
    runs = j = 0
    prev_matched = False
    for ch in n:
        if j >= len(p):
            break
        matched = ch == p[j]
        if matched and not prev_matched:
            runs += 1
        if matched:
            j += 1
        prev_matched = matched
    return runs if j == len(p) else 0


def score(name: str, pattern: str, fuzzy: bool = True) -> int:
    """``-[NSString scoreForMatchingPattern:fuzzy:]``."""
    if not pattern:
        return 1
    if pattern.upper() in name.upper():
        return 1
    return fuzzy_score(name, pattern) if fuzzy else strict_score(name, pattern)


def matched_positions(name: str, pattern: str) -> list[int]:
    """Indices of ``name`` characters that the pattern matched (for highlighting)."""
    if not pattern:
        return []
    n, p = name.upper(), pattern.upper()
    at = n.find(p)
    if at >= 0:
        return list(range(at, at + len(p)))
    positions, j = [], 0
    for i, ch in enumerate(n):
        if j < len(p) and ch == p[j]:
            positions.append(i)
            j += 1
    return positions if j == len(p) else []


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

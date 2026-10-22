"""Hexadecimal regular expressions over nibbles: HNFA -> HFastDFA.

Grammar (alphabet ``0-9a-f``, one symbol = one 4-bit nibble)::

    expr     := concat ('|' concat)*
    concat   := repeated*
    repeated := word ('*' | '+' | '?')*
    word     := hexdigit | '.' | '[' set ']' | '(' expr ')'

Whitespace is ignored and hex digits are case-insensitive.  The parser builds a
Thompson NFA, subset construction turns it into a DFA, and ``FastDFA`` compiles
that into a dense transition table.
"""

from __future__ import annotations

from dataclasses import dataclass, field

HEX = "0123456789abcdef"
NIBBLE_MODE = 0x1
EARLY_ACCEPT = 0x2


class HexRegexError(ValueError):
    pass


# --- NFA ---------------------------------------------------------------------

@dataclass(eq=False)
class NFAState:
    is_initial: bool = False
    is_final: bool = False
    transitions: dict[int, set["NFAState"]] = field(default_factory=dict)
    epsilon: list["NFAState"] = field(default_factory=list)

    def add(self, label: int, state: "NFAState") -> None:
        self.transitions.setdefault(label, set()).add(state)


@dataclass
class NFA:
    start: NFAState
    accept: NFAState

    @staticmethod
    def for_values(values: set[int]) -> "NFA":
        start, accept = NFAState(), NFAState()
        for value in values:
            start.add(value, accept)
        return NFA(start, accept)

    @staticmethod
    def empty() -> "NFA":
        state = NFAState()
        return NFA(state, state)

    def concat(self, other: "NFA") -> "NFA":
        self.accept.epsilon.append(other.start)
        return NFA(self.start, other.accept)

    def union(self, other: "NFA") -> "NFA":
        start, accept = NFAState(), NFAState()
        start.epsilon += [self.start, other.start]
        self.accept.epsilon.append(accept)
        other.accept.epsilon.append(accept)
        return NFA(start, accept)

    def star(self) -> "NFA":
        start, accept = NFAState(), NFAState()
        start.epsilon += [self.start, accept]
        self.accept.epsilon += [self.start, accept]
        return NFA(start, accept)

    def plus(self) -> "NFA":
        start, accept = NFAState(), NFAState()
        start.epsilon.append(self.start)
        self.accept.epsilon += [self.start, accept]
        return NFA(start, accept)

    def optional(self) -> "NFA":
        start, accept = NFAState(), NFAState()
        start.epsilon += [self.start, accept]
        self.accept.epsilon.append(accept)
        return NFA(start, accept)

    def all_states(self) -> list[NFAState]:
        seen: dict[int, NFAState] = {}
        stack = [self.start]
        while stack:
            state = stack.pop()
            if id(state) in seen:
                continue
            seen[id(state)] = state
            stack.extend(state.epsilon)
            for targets in state.transitions.values():
                stack.extend(targets)
        return list(seen.values())

    def build_fast_recognizer(self) -> "FastDFA":
        return FastDFA.from_nfa(self)

    def export_dot(self) -> str:
        states = self.all_states()
        index = {id(s): i for i, s in enumerate(states)}
        lines = ["digraph NFA {"]
        for s in states:
            shape = "doublecircle" if s is self.accept else "circle"
            lines.append(f'  s{index[id(s)]} [shape={shape}{", style=bold" if s is self.start else ""}];')
            for label, targets in sorted(s.transitions.items()):
                for t in targets:
                    lines.append(f'  s{index[id(s)]} -> s{index[id(t)]} [label="{HEX[label]}"];')
            for t in s.epsilon:
                lines.append(f'  s{index[id(s)]} -> s{index[id(t)]} [label="ε"];')
        lines.append("}")
        return "\n".join(lines)


# --- Parser --------------------------------------------------------------------

class _Parser:
    def __init__(self, text: str) -> None:
        self.text = "".join(text.split()).lower()
        self.index = 0

    def peek(self) -> str:
        return self.text[self.index] if self.index < len(self.text) else ""

    def parse(self) -> NFA:
        if not self.text:
            raise HexRegexError("empty expression")
        nfa = self.expr()
        if self.index != len(self.text):
            raise HexRegexError(f"unexpected {self.peek()!r} at {self.index}")
        return nfa

    def expr(self) -> NFA:
        nfa = self.concat()
        while self.peek() == "|":
            self.index += 1
            nfa = nfa.union(self.concat())
        return nfa

    def concat(self) -> NFA:
        parts = []
        while self.peek() and self.peek() not in "|)":
            parts.append(self.repeated())
        if not parts:
            raise HexRegexError(f"empty branch at {self.index}")
        nfa = parts[0]
        for part in parts[1:]:
            nfa = nfa.concat(part)
        return nfa

    def repeated(self) -> NFA:
        nfa = self.word()
        while self.peek() in ("*", "+", "?") and self.peek():
            op = self.peek()
            self.index += 1
            nfa = nfa.star() if op == "*" else nfa.plus() if op == "+" else nfa.optional()
        return nfa

    def word(self) -> NFA:
        ch = self.peek()
        if not ch:
            raise HexRegexError("unexpected end of expression")
        self.index += 1
        if ch in HEX:
            return NFA.for_values({HEX.index(ch)})
        if ch == ".":
            return NFA.for_values(set(range(16)))
        if ch == "[":
            return NFA.for_values(self.char_set())
        if ch == "(":
            nfa = self.expr()
            if self.peek() != ")":
                raise HexRegexError("missing ')'")
            self.index += 1
            return nfa
        raise HexRegexError(f"unexpected {ch!r} at {self.index - 1}")

    def char_set(self) -> set[int]:
        values: set[int] = set()
        while self.peek() and self.peek() != "]":
            low = self.peek()
            if low not in HEX:
                raise HexRegexError(f"invalid set member {low!r}")
            self.index += 1
            if self.peek() == "-":
                self.index += 1
                high = self.peek()
                if high not in HEX or not high:
                    raise HexRegexError("invalid range")
                self.index += 1
                values.update(range(HEX.index(low), HEX.index(high) + 1))
            else:
                values.add(HEX.index(low))
        if self.peek() != "]" or not values:
            raise HexRegexError("invalid set")
        self.index += 1
        return values


def parse_hex_regular_expression(text: str) -> NFA:
    """Raises HexRegexError for an invalid pattern."""
    return _Parser(text).parse()


# --- DFA -----------------------------------------------------------------------

def _closure(states: frozenset[int], all_states: list[NFAState], ids: dict[int, int]) -> frozenset[int]:
    stack, seen = list(states), set(states)
    while stack:
        for nxt in all_states[stack.pop()].epsilon:
            i = ids[id(nxt)]
            if i not in seen:
                seen.add(i)
                stack.append(i)
    return frozenset(seen)


class FastDFA:
    """Dense table: ``table[label - label_offset][state]``, -1 = dead state."""

    def __init__(self, table: list[list[int]], is_final: list[bool], init_state: int,
                 label_offset: int = 0) -> None:
        self.table = table
        self.is_final = is_final
        self.init_state = init_state
        self.label_offset = label_offset
        self.label_count = len(table)
        self._first_bytes: bytes | None = None

    @classmethod
    def from_nfa(cls, nfa: NFA) -> "FastDFA":
        all_states = nfa.all_states()
        ids = {id(s): i for i, s in enumerate(all_states)}
        accept = ids[id(nfa.accept)]
        start = _closure(frozenset({ids[id(nfa.start)]}), all_states, ids)
        dfa_states = {start: 0}
        order = [start]
        rows: list[dict[int, int]] = []
        i = 0
        while i < len(order):
            current = order[i]
            row = {}
            for label in range(16):
                targets = set()
                for s in current:
                    for t in all_states[s].transitions.get(label, ()):
                        targets.add(ids[id(t)])
                if not targets:
                    continue
                closed = _closure(frozenset(targets), all_states, ids)
                if closed not in dfa_states:
                    dfa_states[closed] = len(order)
                    order.append(closed)
                row[label] = dfa_states[closed]
            rows.append(row)
            i += 1
        table = [[rows[s].get(label, -1) for s in range(len(order))] for label in range(16)]
        return cls(table, [accept in s for s in order], 0)

    @property
    def state_count(self) -> int:
        return len(self.is_final)

    def is_deterministic(self) -> bool:
        return True

    def recognize(self, data: bytes | memoryview, start: int = 0, end: int | None = None,
                  options: int = NIBBLE_MODE) -> int | None:
        """Anchored match at ``start``; returns the recognized length in bytes or None.

        Without EARLY_ACCEPT the longest match is returned; with it, the shortest.
        In nibble mode a match must end on a byte boundary.
        """
        end = len(data) if end is None else end
        state = self.init_state
        table, final, offset = self.table, self.is_final, self.label_offset
        best = 0 if final[state] else None
        if best is not None and options & EARLY_ACCEPT:
            return 0
        position = start
        while position < end:
            byte = data[position]
            labels = (byte >> 4, byte & 0xF) if options & NIBBLE_MODE else (byte,)
            for label in labels:
                index = label - offset
                if not 0 <= index < self.label_count:
                    return best
                state = table[index][state]
                if state < 0:
                    return best
            position += 1
            if final[state]:
                best = position - start
                if options & EARLY_ACCEPT:
                    return best
        return best

    def first_bytes(self) -> bytes:
        """Bytes that can start a match (used to skip impossible offsets quickly)."""
        if self._first_bytes is None:
            out = bytearray()
            for byte in range(256):
                state = self.table[byte >> 4][self.init_state]
                if state >= 0 and self.table[byte & 0xF][state] >= 0:
                    out.append(byte)
            self._first_bytes = bytes(out)
        return self._first_bytes

    def matches_empty(self) -> bool:
        return self.is_final[self.init_state]


def compile_hex_regex(text: str) -> FastDFA:
    return parse_hex_regular_expression(text).build_fast_recognizer()

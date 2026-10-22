"""Debugger lookups: command completion and history, memory-view jumps,
ASLR address translation, module and breakpoint lookup.

The process side is abstract: a ``DebuggerChannel`` supplies completions and
memory.  ``LocalChannel`` completes against a fixed LLDB command vocabulary and
serves memory from the loaded documents, so the lookups work without a live process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from assemsearch.goto import is_valid_hex_string
from assemsearch.model import DisassembledFile
from assemsearch.types import BAD_ADDRESS

LLDB_COMMANDS = sorted([
    "apropos", "breakpoint", "breakpoint clear", "breakpoint delete", "breakpoint disable", "breakpoint enable",
    "breakpoint list", "breakpoint set", "continue", "disassemble", "expression", "finish", "frame",
    "frame info", "frame select", "frame variable", "help", "image", "image list", "image lookup", "kill",
    "memory", "memory find", "memory read", "memory write", "next", "nexti", "process", "process attach",
    "process continue", "process interrupt", "process kill", "process launch", "register", "register read",
    "register write", "run", "settings", "step", "stepi", "target", "thread", "thread backtrace",
    "thread list", "thread select", "thread step-in", "thread step-out", "watchpoint", "watchpoint set",
])


class DebuggerChannel(Protocol):
    can_complete_cli: bool

    def complete_command(self, text: str, cursor_position: int) -> list[str]: ...

    def read_memory(self, address: int, length: int) -> bytes: ...


@dataclass
class LoadedModule:
    name: str
    load_address: int  # runtime address of the module's lowest segment
    size: int
    document: DisassembledFile | None = None

    @property
    def slide(self) -> int:
        return self.load_address - self.document.min_address if self.document else 0

    def contains(self, absolute: int) -> bool:
        return self.load_address <= absolute < self.load_address + self.size


@dataclass
class Breakpoint:
    identifier: int
    absolute_address: int
    enabled: bool = True


class LocalChannel:
    can_complete_cli = True

    def __init__(self, session: "DebuggerSession") -> None:
        self.session = session

    def complete_command(self, text: str, cursor_position: int) -> list[str]:
        prefix = text[:cursor_position].lstrip()
        return [c for c in LLDB_COMMANDS if c.startswith(prefix)]

    def read_memory(self, address: int, length: int) -> bytes:
        module = self.session.loaded_module_containing_absolute_address(address)
        if module is None or module.document is None:
            return b""
        return module.document.read_bytes(address - module.slide, length)


@dataclass
class DebuggerSession:
    modules: list[LoadedModule] = field(default_factory=list)
    breakpoints: list[Breakpoint] = field(default_factory=list)
    history: list[str] = field(default_factory=list)
    channel: DebuggerChannel | None = None
    memory_address: int = 0
    _history_index: int = 0

    def __post_init__(self) -> None:
        if self.channel is None:
            self.channel = LocalChannel(self)

    # Console --------------------------------------------------------------------

    def completions(self, text: str, cursor_position: int | None = None) -> list[str]:
        """``control:textView:completions:forPartialWordRange:indexOfSelectedItem:``."""
        if not self.channel.can_complete_cli:
            return []
        return self.channel.complete_command(text, len(text) if cursor_position is None else cursor_position)

    def send_command(self, command: str) -> None:
        if command and (not self.history or self.history[-1] != command):
            self.history.append(command)
        self._history_index = len(self.history)

    def command_at_index(self, index: int) -> str | None:
        return self.history[index] if 0 <= index < len(self.history) else None

    def last_command(self) -> str | None:
        return self.history[-1] if self.history else None

    def history_up(self) -> str | None:
        if self._history_index > 0:
            self._history_index -= 1
        return self.command_at_index(self._history_index)

    def history_down(self) -> str | None:
        if self._history_index < len(self.history):
            self._history_index += 1
        return self.command_at_index(self._history_index) or ""

    # Modules and translation --------------------------------------------------

    def load_module(self, document: DisassembledFile, load_address: int, name: str | None = None) -> LoadedModule:
        size = max(s.end for s in document.segments) - document.min_address if document.segments else 0
        module = LoadedModule(name or document.path, load_address, size, document)
        self.modules.append(module)
        return module

    def loaded_module_containing_absolute_address(self, absolute: int) -> LoadedModule | None:
        return next((m for m in self.modules if m.contains(absolute)), None)

    def translate_address_from_loaded_process(self, absolute: int) -> tuple[int, DisassembledFile | None]:
        module = self.loaded_module_containing_absolute_address(absolute)
        if module is None or module.document is None:
            return BAD_ADDRESS, None
        return absolute - module.slide, module.document

    def translate_address_to_loaded_process(self, address: int, document: DisassembledFile) -> int:
        module = next((m for m in self.modules if m.document is document), None)
        return BAD_ADDRESS if module is None else address + module.slide

    # Breakpoints ------------------------------------------------------------------

    def set_breakpoint(self, absolute: int) -> Breakpoint:
        existing = self.breakpoint_at(absolute)
        if existing is not None:
            return existing
        bp = Breakpoint(len(self.breakpoints) + 1, absolute)
        self.breakpoints.append(bp)
        return bp

    def breakpoint_at(self, absolute: int) -> Breakpoint | None:
        return next((b for b in self.breakpoints if b.absolute_address == absolute), None)

    def breakpoint_id_at_absolute_address(self, absolute: int) -> int:
        bp = self.breakpoint_at(absolute)
        return bp.identifier if bp else -1

    def address_of_breakpoint_at_index(self, index: int) -> int:
        return self.breakpoints[index].absolute_address if 0 <= index < len(self.breakpoints) else BAD_ADDRESS

    # Memory view --------------------------------------------------------------------

    def set_memory_address(self, text: str) -> bool:
        """The memory dump view's address field: a numeric (hex) address, not a pattern."""
        text = text.strip()
        if not is_valid_hex_string(text):
            return False
        self.memory_address = int(text, 16)
        return True

    def refresh_memory(self, length: int = 64) -> bytes:
        return self.channel.read_memory(self.memory_address, length)

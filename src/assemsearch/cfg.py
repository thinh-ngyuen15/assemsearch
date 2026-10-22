"""Procedures from control flow.

Starting from every known function start, in address order, the code is followed:
conditional branches continue both ways, unconditional jumps continue at their target
unless it is another function's start (a tail call), calls continue unless the callee
never returns, returns and traps stop, and indirect jumps continue at the cases of their
jump table. A procedure is the set of basic blocks reached this way, so it need not be
contiguous. Optionally, code that no procedure reaches (other than padding) then becomes a
procedure of its own.
"""

from __future__ import annotations

import re
from array import array
from collections import defaultdict

from assemsearch.model import BasicBlock, DisassembledFile, Procedure

_IMM = re.compile(r"#?(-?0x[0-9a-f]+|-?\d+)")
_ARM64_INDEXED = re.compile(r"(\w+), \[(\w+), (\w+)(?:, (?:lsl|uxtw|sxtw) #(\d+))?\]$")
_ARM64_ADD_SHIFTED = re.compile(r"(\w+), (\w+), (\w+)(?:, (?:lsl|sxtw|uxtw|sxtb|uxtb|sxth|uxth) #(\d+))?$")
_X86_MOVSXD = re.compile(r"(\w+), dword ptr \[(\w+) \+ (\w+)\*4\]$")
_X86_LEA_RIP = re.compile(r"(\w+), \[rip ([+-]) (0x[0-9a-f]+|\d+)\]$")

NORETURN = {
    "___stack_chk_fail", "_abort", "_exit", "__exit", "___assert_rtn", "_objc_terminate",
    "___cxa_throw", "___cxa_rethrow", "_swift_deletedMethodError", "_pthread_exit", "_longjmp",
    "_siglongjmp", "__Unwind_Resume", "_objc_exception_throw", "_objc_exception_rethrow",
    "_swift_unexpectedError", "_swift_errorInMain", "_dispatch_main", "_xpc_main", "_err", "_errx",
    "___cxa_bad_cast", "___cxa_bad_typeid", "__ZSt9terminatev", "_swift_dynamicCastFailure",
}
MAX_UNBOUNDED_CASES = 256
ARM64_PADDING = {"nop", "brk", "udf"}
X86_PADDING = {"nop", "int3", "ud2", "hlt"}


def _register(name: str) -> str:
    """Canonical register name: w8 -> x8, eax -> rax, r8d -> r8."""
    if re.fullmatch(r"w\d+", name):
        return "x" + name[1:]
    if re.fullmatch(r"r\d+[dwb]", name):
        return name[:-1]
    if re.fullmatch(r"e[a-z]{2}", name):
        return "r" + name[1:]
    return name


def _immediate(text: str) -> int | None:
    match = _IMM.fullmatch(text.strip())
    return int(match.group(1), 0) if match else None


def _operands(op_str: str) -> list[str]:
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


class ControlFlow:
    def __init__(self, doc: DisassembledFile) -> None:
        self.doc = doc
        self.table = doc.instructions
        self.arm64 = doc.cpu == "arm64"
        self.arm32 = doc.cpu == "arm"
        self.padding = ARM64_PADDING if self.arm64 else X86_PADDING
        self._noreturn: dict[int, bool] = {}
        # Tables without a bounds check: off (measured on a large app: resolving them by
        # scanning entries made procedure contents less accurate, not more).
        self.unbounded_tables = False
        # What the cases of a table without a bounds check become: "ignore" them, follow them
        # as part of the procedure ("edges"), or make each one a procedure ("procedures").
        self.unbounded_cases = "ignore"

    # Instruction kinds -----------------------------------------------------------------

    def kind(self, mnemonic: str, op_str: str) -> tuple[str | None, int | None]:
        """(kind, direct target): call, jump, cond, ijump, icall, stop, or None (falls through)."""
        if self.arm64:
            if mnemonic == "bl":
                return "call", _immediate(op_str)
            if mnemonic.startswith("blr"):
                return "icall", None
            if mnemonic == "b":
                return "jump", _immediate(op_str)
            if mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
                return "cond", _immediate(op_str.rsplit(",", 1)[-1])
            if mnemonic.startswith("br"):
                return ("stop", None) if mnemonic == "brk" else ("ijump", None)
            if mnemonic.startswith("ret") or mnemonic in ("eret", "udf", "hlt"):
                return "stop", None
            return None, None
        if self.arm32:
            return self._arm32_kind(mnemonic, op_str)
        if mnemonic == "call":
            target = _immediate(op_str)
            return ("call", target) if target is not None else ("icall", None)
        if mnemonic == "jmp":
            target = _immediate(op_str)
            return ("jump", target) if target is not None else ("ijump", None)
        if mnemonic.startswith("j"):
            return "cond", _immediate(op_str)
        if mnemonic.startswith(("ret", "iret")) or mnemonic in ("ud2", "hlt"):
            return "stop", None
        return None, None

    @staticmethod
    def _arm32_kind(mnemonic: str, op_str: str) -> tuple[str | None, int | None]:
        """32-bit ARM: b/bl/blx, conditional b<cc>, bx lr and pops into pc."""
        target = _immediate(op_str)
        if mnemonic in ("bl", "blx"):
            return ("call", target) if target is not None else ("icall", None)
        if mnemonic == "b":
            return "jump", target
        if mnemonic.startswith("b") and len(mnemonic) == 3 and mnemonic not in ("bic", "bfc", "bfi", "bkpt"):
            return "cond", target
        if mnemonic == "bx":
            return ("stop", None) if op_str == "lr" else ("ijump", None)
        if mnemonic.startswith(("pop", "ldm")) and "pc" in op_str:
            return "stop", None
        if mnemonic in ("udf", "bkpt"):
            return "stop", None
        return None, None

    def noreturn(self, target: int) -> bool:
        known = self._noreturn.get(target)
        if known is None:
            name = (self.doc.names.name_for_address(target) or "").removeprefix("imp___stubs_")
            known = name in NORETURN or ("s5NeverO" in name and name.endswith(("F", "FZ")))
            self._noreturn[target] = known
        return known

    # Jump tables -------------------------------------------------------------------------

    def jump_table(self, i: int) -> list[int]:
        """Case addresses of the indirect jump at index ``i``, from the instructions before it."""
        window = [self.table.row(k) for k in range(max(0, i - 24), i + 1)]
        return self._arm64_table(window) if self.arm64 else self._x86_table(window)

    def _read(self, address: int, width: int, signed: bool) -> int | None:
        raw = self.doc.read_bytes(address, width)
        return int.from_bytes(raw, "little", signed=signed) if len(raw) == width else None

    def _cases(self, base: int, table: int, width: int, signed: bool, shift: int, count: int | None,
               jump: int) -> list[int]:
        """Entries ``base + (entry << shift)``. Without a bounds check (``cmp``/``b.hi``) the size is
        unknown: entries are read while they point at instructions of the same section, near the
        jump (the usual disassembler heuristic), up to MAX_UNBOUNDED_CASES."""
        if count is None and not self.unbounded_tables or count is not None and count > 4096:
            return []
        section = self.doc.section_at_virtual_address(jump)
        targets = []
        for k in range(count if count is not None else MAX_UNBOUNDED_CASES):
            entry = self._read(table + k * width, width, signed)
            if entry is None:
                break
            target = base + (entry << shift)
            if count is None and (section is None or not section.contains(target) or abs(target - jump) > 0x10000
                                  or target not in self.table):
                break
            targets.append(target)
        return targets

    def _arm64_table(self, window) -> list[int]:
        consts: dict[str, int] = {}
        loads: dict[str, tuple[int, int, bool, str]] = {}  # reg -> (table, width, signed, index)
        jumps: dict[str, tuple[int, tuple[int, int, bool, str], int]] = {}
        bounds: dict[str, int] = {}
        compared: tuple[str, int] | None = None
        for _address, _size, mnemonic, op_str in window:
            ops = _operands(op_str)
            dest = _register(ops[0]) if ops else ""
            if mnemonic in ("adrp", "adr") and len(ops) == 2 and (value := _immediate(ops[1])) is not None:
                consts[dest] = value
            elif mnemonic in ("add", "sub") and len(ops) == 3 and _register(ops[1]) in consts \
                    and (value := _immediate(ops[2])) is not None:
                consts[dest] = consts[_register(ops[1])] + (value if mnemonic == "add" else -value)
            elif mnemonic.startswith("ldr") and (m := _ARM64_INDEXED.fullmatch(op_str)) \
                    and _register(m.group(2)) in consts:
                width = {"ldrb": 1, "ldrsb": 1, "ldrh": 2, "ldrsh": 2, "ldrsw": 4}.get(mnemonic, 4)
                loads[dest] = (consts[_register(m.group(2))], width, mnemonic.startswith("ldrs"),
                               _register(m.group(3)))
            elif mnemonic == "add" and (m := _ARM64_ADD_SHIFTED.fullmatch(op_str)):
                a, b, shift = _register(m.group(2)), _register(m.group(3)), int(m.group(4) or 0)
                if a in consts and b in loads:
                    jumps[dest] = (consts[a], loads[b], shift)
                elif b in consts and a in loads:
                    jumps[dest] = (consts[b], loads[a], shift)
            elif mnemonic == "cmp" and len(ops) == 2 and (value := _immediate(ops[1])) is not None:
                compared = (_register(ops[0]), value)
            elif mnemonic in ("b.hi", "b.hs", "b.cs") and compared is not None:
                bounds[compared[0]] = compared[1] + (1 if mnemonic == "b.hi" else 0)
            elif mnemonic in ("mov", "uxtw", "sxtw", "and") and len(ops) >= 2 and _register(ops[1]) in bounds:
                bounds[dest] = bounds[_register(ops[1])]  # the bound follows register copies
            elif mnemonic.startswith("br") and dest in jumps:
                base, (table, width, signed, index), shift = jumps[dest]
                return self._cases(base, table, width, signed, shift, bounds.get(index), _address)
            elif mnemonic.startswith("br"):
                return []
        return []

    def _x86_table(self, window) -> list[int]:
        consts: dict[str, int] = {}
        loads: dict[str, tuple[int, str]] = {}
        jumps: dict[str, tuple[int, str]] = {}
        bounds: dict[str, int] = {}
        compared: tuple[str, int] | None = None
        for address, size, mnemonic, op_str in window:
            ops = _operands(op_str)
            dest = _register(ops[0]) if ops else ""
            if mnemonic == "lea" and (m := _X86_LEA_RIP.fullmatch(op_str)):
                consts[_register(m.group(1))] = address + size + int(m.group(3), 0) * (1 if m.group(2) == "+" else -1)
            elif mnemonic == "movsxd" and (m := _X86_MOVSXD.fullmatch(op_str)) and _register(m.group(2)) in consts:
                loads[dest] = (consts[_register(m.group(2))], _register(m.group(3)))
            elif mnemonic == "add" and len(ops) == 2 and dest in loads and _register(ops[1]) in consts:
                jumps[dest] = (consts[_register(ops[1])], loads[dest][1])
            elif mnemonic == "cmp" and len(ops) == 2 and (value := _immediate(ops[1])) is not None:
                compared = (_register(ops[0]), value)
            elif mnemonic in ("ja", "jae", "jnb") and compared is not None:
                bounds[compared[0]] = compared[1] + (1 if mnemonic == "ja" else 0)
            elif mnemonic in ("mov", "movzx", "movsxd") and len(ops) == 2 and _register(ops[1]) in bounds:
                bounds[dest] = bounds[_register(ops[1])]  # the bound follows register copies
            elif mnemonic == "jmp" and dest in jumps:
                table, index = jumps[dest]
                return self._cases(table, table, 4, True, 0, bounds.get(index), address)
            elif mnemonic == "jmp":
                return []
        return []

    # Procedures ---------------------------------------------------------------------------

    def build(self, seeds: list[int], weak: set[int], code_sections, orphans: bool = False) -> dict[int, Procedure]:
        """``weak`` starts become part of whichever procedure reaches them first.

        With ``orphans``, code that no procedure reaches becomes procedures too. Off by default:
        most such code is unreachable fragments, not functions.
        """
        table, n = self.table, len(self.table)
        owner = array("q", [-1]) * n
        strong = set(seeds) - weak
        entries: list[int] = []
        leaders: list[set[int]] = []
        branch_targets: list[set[int]] = []
        calls: list[tuple[int, int]] = []

        def follow(entry: int) -> None:
            pid = len(entries)
            entries.append(entry)
            heads, targets = {entry}, set()
            leaders.append(heads)
            branch_targets.append(targets)
            work = [entry]

            def edge(target: int | None) -> None:
                if target is None:
                    return
                if target in strong and target != entry:
                    return  # a tail call into another function
                if table.index(target) >= 0:
                    work.append(target)
                    heads.add(target)
                    targets.add(target)

            while work:
                i = table.index(work.pop())
                while 0 <= i < n:
                    address, size, mnemonic, op_str = table.row(i)
                    if owner[i] != -1:
                        if owner[i] == pid:
                            heads.add(address)
                        break
                    if address != entry and address in strong:
                        break  # falls into the next function
                    owner[i] = pid
                    kind, target = self.kind(mnemonic, op_str)
                    if kind == "cond":
                        edge(target)
                        heads.add(address + size)
                    elif kind == "jump":
                        edge(target)
                        break
                    elif kind == "ijump":
                        cases = self.jump_table(i)
                        for case in cases:
                            edge(case)
                        if not cases and self.unbounded_cases != "ignore":
                            self.unbounded_tables = True
                            guessed = self.jump_table(i)
                            self.unbounded_tables = False
                            for case in guessed:
                                if self.unbounded_cases == "edges":
                                    edge(case)
                                else:
                                    later.append(case)
                        break
                    elif kind == "call":
                        if target is not None:
                            calls.append((pid, target))
                            if self.noreturn(target):
                                break
                    elif kind == "stop":
                        break
                    if i + 1 >= n or table.row(i + 1)[0] != address + size:
                        break
                    i += 1

        later: list[int] = []  # cases of unsized jump tables, made procedures once all starts are done
        for seed in sorted(set(seeds)):
            i = table.index(seed)
            if i >= 0 and owner[i] == -1:
                follow(seed)
        while later:
            for case in sorted(set(later)):
                later.remove(case)
                i = table.index(case)
                if i >= 0 and owner[i] == -1:
                    follow(case)
        ranges = [(s.start, s.end) for s in code_sections]
        addresses = table.addresses()
        for i in range(n if orphans else 0):
            if owner[i] != -1:
                continue
            address, _size, mnemonic, op_str = table.row(i)
            if mnemonic in self.padding or not any(lo <= address < hi for lo, hi in ranges) \
                    or not self.arm64 and mnemonic == "add" and op_str == "byte ptr [rax], al":
                continue
            follow(address)
        return self._procedures(entries, owner, leaders, branch_targets, calls, addresses)

    def _procedures(self, entries, owner, leaders, branch_targets, calls, addresses) -> dict[int, Procedure]:
        sizes = self.table.sizes()
        blocks: dict[int, list[BasicBlock]] = defaultdict(list)
        run_owner, run_start, previous_end = -1, 0, None
        for i in range(len(addresses)):
            o, address = owner[i], addresses[i]
            if o != run_owner or address != previous_end or (o != -1 and address in leaders[o] and address != run_start):
                if run_owner != -1:
                    blocks[run_owner].append(BasicBlock(run_start, previous_end))
                run_owner, run_start = o, address
            previous_end = address + sizes[i]
        if run_owner != -1:
            blocks[run_owner].append(BasicBlock(run_start, previous_end))
        procedures: dict[int, Procedure] = {}
        for pid, entry in enumerate(entries):
            own = sorted(blocks.get(pid, []), key=lambda b: b.start)
            if not own:
                continue
            procedure = Procedure(entry, max(b.end for b in own), own)
            procedure.local_labels = {t: f"loc_{t:x}" for t in branch_targets[pid] if t != entry}
            procedures[entry] = procedure
        for pid, target in calls:
            caller, callee = procedures.get(entries[pid]), procedures.get(target)
            if caller is not None and callee is not None:
                caller.callees.add(target)
                callee.callers.add(caller.entry)
        return procedures


def build_procedures(doc: DisassembledFile, seeds: list[int], weak: set[int], code_sections) -> dict[int, Procedure]:
    return ControlFlow(doc).build(seeds, weak, code_sections)

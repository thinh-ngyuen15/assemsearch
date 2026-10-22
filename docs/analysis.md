# How the analysis works

Every search depends on what the analysis found. If a procedure, string or reference is
missing, no search will turn it up. This page explains what assemsearch analyses, and how.

Everything runs when a binary is opened. It takes under a second for small tools and
about 20–27 seconds for a 42 MB app slice.

## Supported input

| Format | Details |
|---|---|
| Mach-O | Thin or universal (fat), 64- and 32-bit; executables, dylibs, bundles. One slice is analysed at a time (`--arch`) |
| ELF | Executables, shared objects and relocatable objects (`.o`) |
| Raw | Any file, with `--raw` and a `--base` address |

CPUs: **arm64** and **x86-64** get full analysis. 32-bit **x86** and **ARM** are
disassembled with calls and branches, but get less of the pointer and metadata analysis.

## The pipeline

```
load ─► disassemble ─► strings & pointers ─► ObjC / Swift metadata ─► references ─► procedures ─► names & tags
```

### 1. Load (`loaders/`)

The loader reads segments, sections, symbols, imports and exports. For Mach-O it also reads:

* **Function starts** (`LC_FUNCTION_STARTS`) and the **unwind table** (`__unwind_info`).
  Both list every function the compiler emitted, even in a stripped binary.
* **Chained fixups** (`LC_DYLD_CHAINED_FIXUPS`): the pointers the loader fills in at launch.
  Rebases become pointers to code or data in the binary. Binds become pointers to imported
  symbols, which appear in an "External Symbols" segment.
* **Stubs and GOT slots**, named after the imported symbol (`imp___stubs__strcmp`).
* **Load-command paths** (linked libraries, rpaths), as strings.

### 2. Disassemble (`analysis.py`)

[Capstone](https://www.capstone-engine.org/) disassembles every code section from start to
end (a *linear sweep*). The sweep restarts at every known function start, so data embedded
in code cannot knock it out of step for long. Instructions are stored in compact arrays: a
large app has millions of them.

### 3. Strings and pointers

* **C strings** in string sections, and printable text elsewhere when code refers to it.
* **CFStrings** (`@"…"` constants), **pointers** found in data and in chained fixups.
* Labels: `aInvalidLicense` (from the text), `cfstring_…`, `qword_…`,
  `double_value_0_1`, `switch_table_…`.

### 4. Objective-C and Swift metadata (`objc.py`)

* Objective-C classes, metaclasses, categories, protocols, method lists (relative and
  absolute), instance variables and properties. Methods get names like
  `-[NSView setFrame:]`, and selector references like `_objc_msgSend$setFrame:` let
  `objcrefs` find every place a message is sent.
* Swift field descriptors, type descriptors and reflection strings.

### 5. References

* **Direct**: calls and branches.
* **Register tracking**, which follows how addresses are built over several instructions.
  On arm64 that covers `adrp` + `add`/`sub`, loads and stores, and literal pools. On x86-64
  it covers RIP-relative operands. This is how `refsto` on a string finds the code that
  loads it.
* **Data**: pointers in data sections, fixups, metadata.

### 6. Procedures (`cfg.py`)

It starts from every known function start: symbols, function
starts, unwind entries, Objective-C methods, call targets and the entry point. From each
one it follows the code:

* through conditional and unconditional branches;
* through **switch jump tables**, when a bounds check before the jump says how big the
  table is;
* through **tail calls** (a jump to another function's start ends this procedure, it does
  not absorb the other one);
* stopping after calls that **never return** (`exit`, `abort`, `__stack_chk_fail`,
  `objc_exception_throw`, and Swift functions returning `Never` such as `fatalError`).

A procedure is the set of **basic blocks** it reaches, so it need not be contiguous. Code
that nothing reaches stays code but does not become a procedure. Procedures without a symbol
are named `sub_ADDRESS`. Their local labels are `loc_ADDRESS`.

### 7. Names and tags

Generated names are given to everything still unnamed. Two kinds of tag are added
automatically: `entrypoint` on the entry point, and the class name (plus the category name,
if any) on every Objective-C method. So `scope NSView` limits a symbol search to `NSView`'s
methods.

## Accuracy

Every function the binary records (`LC_FUNCTION_STARTS`, unwind entries) becomes a
procedure. On a 42 MB Swift and Objective-C app, more than 96% of procedures have exactly
the basic blocks an established commercial disassembler finds, and over 99% of its strings
and string references are found too. The differences are mostly unreachable fragments that
other tools turn into functions, and functions they fold into the one before.

## Tuning switches

For experiments. The defaults gave the most accurate results in testing.

| Switch | Default | Effect when changed |
|---|---|---|
| `analysis.MERGE_JUMPED_STARTS` | `False` | Fold a function into the previous one when only a branch from it reaches it (arm64) |
| `ControlFlow.build(..., orphans=True)` (`cfg.py`) | off | Turn unreachable code into procedures too |
| `ControlFlow.unbounded_tables` (`cfg.py`) | `False` | Follow jump tables that have no bounds check, up to `MAX_UNBOUNDED_CASES` entries |

## Limits

* **No decompiler.** No pseudo-code, no types, no local variable analysis.
* **No live debugging.** `dbg` only does address lookups.
* **Listing format.** assemsearch has its own listing format. This matters when you search the
  listing text (`--mode asm`): write operands the way `where` shows them.
* **Memory.** A 42 MB slice needs about 1.5 GB of RAM while open.
* **Only reads.** assemsearch never modifies the binary.

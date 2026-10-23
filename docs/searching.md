# Searching

assemsearch has these kinds of search:

| You want to find | Use |
|---|---|
| Bytes, text or numbers stored in the binary | **Find**, one of six modes ([below](#find)) |
| A function, label or string by (part of) its name | **Symbol search** (`symbols`) |
| Anything: a command, symbol, string or open document | **Command palette** (`palette`) |
| A known address, name or file offset | **Go To** (`goto`, `offset`) |
| Who uses something | **Cross-references** (`refsto`, `callers`; see [shell](shell.md#cross-references)) |
| Text inside one procedure's listing | **Find bar** (`textfind`) |

## Find

Find searches the binary's sections, starting after the cursor. In the shell, `find` moves to
the first match and `n` / `p` go to the next or previous one. `find --all` and the one-shot
`assemsearch find` list every match.

**Wrapping** (on by default) continues from the start once the end is reached. `--nowrap`
stops at the end instead. The one-shot command always searches the whole binary once.

### `--mode ascii`: text stored in the binary

Finds the bytes of your text (as UTF-8), anywhere: string tables, data, even inside
instructions. Case-insensitive unless `--case`.

```sh
assemsearch find BINARY --mode ascii "Invalid license"
```

A match can start in the middle of a string, so `license` also finds `Invalid license`
eight bytes in.

### `--mode hex`: exact bytes

Hex digits, two per byte. Spaces, tabs, quotes and a leading `0x` are ignored, so all of
these are the same search:

```
c0035fd6     c0 03 5f d6     0xc0035fd6     "c0 03 5f d6"
```

An odd number of digits or a non-hex character is an error
("You entered an invalid hexadecimal string.").

### `--mode number`: an integer in memory

Finds a number in its stored form. Write it in decimal (`42`), hex (`0x2a`), octal (`0o52`)
or binary (`0b101010`); negative numbers are stored as two's complement. A leading zero
is decimal (`010` is 10). A number that does not fit in `--bits` is rejected ("You entered
an invalid number.") rather than cut to its low bytes.

| Option | Default | Meaning |
|---|---|---|
| `--bits 8\|16\|32\|64` | 32 | How many bytes the number takes |
| `--big` | off | Big-endian. Off means little-endian, which is what arm64 and x86 use |

`--bits 32 42` searches for `2a 00 00 00`.

This finds numbers stored as data. A number that is part of an instruction (`mov w0, #42`)
is encoded differently; search the listing text for it with `--mode asm "#0x2a"`.

### `--mode asm` (default): text in the disassembly

Searches the listing text line by line, the way it appears in `where` or an export:
instructions, operands, labels, names and the automatic comments (for example the string a
`add x0, x0, #0x6e7` loads). Case-insensitive unless `--case`.

```sh
assemsearch find BINARY "bl imp___stubs__strcmp"      # every call to strcmp
assemsearch find BINARY "Invalid license"             # instructions that load that string
```

The text follows assemsearch's listing format.
Write the operands the way `where` shows them. With `prefs hexcolumn on` each line also
includes the instruction bytes, which then become searchable.

### `--mode regex`: hexadecimal regular expression

A regular expression over **hex digits** (nibbles), not text. Use it for byte patterns with
wildcards, such as instruction encodings.

| Syntax | Matches |
|---|---|
| `0`-`9`, `a`-`f` | That hex digit (case does not matter) |
| `.` | Any one hex digit |
| `[0-3]`, `[08c]` | One hex digit from the set or range |
| `x*` `x+` `x?` | Zero or more, one or more, optional |
| `(…)` | Grouping |
| `a\|b` | Either |
| spaces | Ignored |

Examples:

```sh
# arm64 "stp x29, x30, [sp, #...]!": the usual function prologue
assemsearch find BINARY --mode regex "fd7b..a9"
# x86-64 "call rel32"
assemsearch find BINARY --mode regex "e8 ........"
# either of two 4-byte constants
assemsearch find BINARY --mode regex "(efbeadde|0df0adba)"
```

A match always covers whole bytes. When several matches start at the same address, the
longest one is reported. `assemsearch hexre PATTERN` prints the pattern's automaton if you
want to check it.

### `--mode comment`: your comments

Searches the comments and inline comments you added with `comment` and `inline` (or that
were restored from a saved `.asdb`). Case-insensitive unless `--case`.

### Options are remembered

In the shell, every option you leave out keeps its last value: `find --case foo` then
`find bar` is still case-sensitive. Turn options back with `--nocase`, `--wrap` and
`--little`. `prefs` shows the current values. They are saved in
`~/.config/assemsearch/preferences.json`, so they last across sessions.

### Use Selection for Find

`usesel` takes the search text from the current selection, or from the instruction at the
cursor (`usesel TEXT` sets it directly). Then `n` / `p` search for it. It is also stored on
the *Find pasteboard* that later sessions start with.

## Symbol search

```
symbols [labels|proc|strings] [PATTERN]          # shell
assemsearch symbols BINARY [PATTERN] [--mode ...]  # one-shot
```

Searches names (`labels`, the default), procedure names only (`proc`) or string contents
(`strings`). It is **fuzzy**: the letters of the pattern must appear in order, but not
necessarily next to each other. Each result gets a score, and lower is better:

| Score | Meaning | `vlic` against `_validate_license` |
|---|---|---|
| 1 | The pattern appears as is (ignoring case) | |
| k | The pattern's letters appear in k separate runs | `v`·`li`…`c`: 3 |
| no result | Letters missing or out of order | |

Results are sorted by score. `--strict` (one-shot) or `prefs fuzzy off` (shell) switches to
plain substring matching. In a terminal, the matched letters are highlighted.

**Tags.** Restrict the search to addresses carrying certain tags: `scope TAG ...` in the
shell, `--tag TAG` on the command line. assemsearch adds some tags automatically during
analysis; you add your own with `tag NAME`.

`recents` shows your recent symbol searches.

## Command palette

```
palette QUERY [!N]
```

A *Search Anything* box. The first character picks what to search:

| Prefix | Searches |
|---|---|
| (none) | Commands, by title (`palette next proc`) |
| `@` | Symbols (`palette @valid`) |
| `"` | Strings (`palette "license`) |
| `#` | Open documents |

Matching is fuzzy, like symbol search. Add `!N` to run result N: `palette @valid !0` goes
to the first symbol.

## Go To

```
goto TEXT            # shell (also: g)
assemsearch goto BINARY TEXT
```

`TEXT` is tried in this order, and the first one that works wins:

1. An exact name: `_main`.
2. A name written with `$`: `$_main`.
3. A hexadecimal address, with or without `0x`: `1000005f0`, `0x1000005f0`.
4. A decimal address.

An address only counts if it is inside the binary. Related commands:

| Command | Goes to |
|---|---|
| `offset NUMBER` | A file offset in the loaded slice. Hex if it has `0x` or any letter a–f, otherwise decimal |
| `offset --global NUMBER` | An offset in the whole file, including a universal binary's header and other slices |
| `procoff OFFSET` | An offset inside the current procedure |
| `top` | The start of the current procedure |
| `follow` | The address the instruction at the cursor refers to |
| `g [N]` | Row N of the last list printed |

`back`, `forward` and `history` walk the navigation history, like a browser's arrows.

## Find bar

```
textfind [--case] [--word] [--regex] TEXT
```

Searches the listing text of the current procedure only and prints every matching line.
`--word` matches whole words; `--regex` takes a Python regular expression:

```
textfind --regex bl\s+\w+
```

## Searching from scripts and AI assistants

* The [MCP server](mcp.md) has `search_strings`, `search_procedures` and `search_name`, which
  take a regular expression.
* The [Python API](python-api.md) returns lists (`getStringsList()`, `getLabelsList()`)
  that you filter yourself.
* `assemsearch export BINARY out.txt` writes the whole listing for `grep`.

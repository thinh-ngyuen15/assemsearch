# Interactive shell

```sh
assemsearch open BINARY [--arch ARCH]
```

The shell works like a disassembler window. There is a **cursor**, one address in
the binary. The prompt shows the document, the cursor's address and its name:

```
(sample_macho 0x1000005f0 _main)
```

Navigation commands move the cursor, `where` shows the listing there, and searches start
from it. Commands that print a list number their rows; `g [N]` jumps to row N of the last
list.

`help` lists every command and `help COMMAND` describes one. Ctrl-C cancels a running
command; `quit`, `exit` or Ctrl-D leaves. Arrow keys recall earlier commands.

## A short session

Find a string, see who uses it, and walk back:

```
(sample_macho 0x1000005f0 _main) symbols strings license
Strings: 2 results
[  0]        0x1000006d7  License OK: %u\n  (score 1)
[  1]        0x1000006e7  Invalid license  (score 1)
(sample_macho 0x1000005f0 _main) g [1]
aInvalidLicense:  ; XREF=_main+148
00000001000006e7  db "Invalid license", 0
(sample_macho 0x1000006e7 aInvalidLicense) refsto
References to 0x1000006e7 (1/1)
[  0]        0x100000684  0x100000684  _main+148 (in _main)
(sample_macho 0x1000006e7 aInvalidLicense) g [0]
0000000100000684  add x0, x0, #0x6e7  ; "Invalid license"
(sample_macho 0x100000684 _main+148) where 3
0000000100000684  add x0, x0, #0x6e7  ; "Invalid license"
0000000100000688  bl imp___stubs__puts
000000010000068c  mov w0, #1
(sample_macho 0x100000684 _main+148) top
_main:
00000001000005f0  sub sp, sp, #0x30
(sample_macho 0x1000005f0 _main) callees
[  0]        0x1000006a0  imp___stubs__printf
[  1]        0x1000006ac  imp___stubs__puts
[  2]        0x1000006b8  imp___stubs__strcmp
(sample_macho 0x1000005f0 _main) back
0000000100000684  add x0, x0, #0x6e7  ; "Invalid license"
```

## Commands

### Look around

| Command | What it does |
|---|---|
| `where [N]` (also `l`) | Show N listing items from the cursor (default 8) |
| `segments [FILTER]` | Segments, with addresses and sizes |
| `sections [FILTER]` | Sections. The filter matches the address text or the name |
| `imports [FILTER]` | Imported functions and symbols |
| `exports [FILTER]` | Exported symbols |
| `docs` | Open documents |
| `open PATH [--arch ARCH] [--raw] [--base HEX]` | Load another binary next to the current one |
| `use NAME\|INDEX` | Switch to another open document |

### Search

| Command | What it does |
|---|---|
| `find [OPTIONS] TEXT` | Find the next match after the cursor and move there. Options: `--mode ascii\|hex\|asm\|regex\|number\|comment`, `--case`/`--nocase`, `--wrap`/`--nowrap`, `--bits 8\|16\|32\|64`, `--big`/`--little`. Options you leave out keep their last value, even across sessions; `prefs` shows them |
| `find --all [--limit N] TEXT` | List the matches instead of moving: the first 200, or N (`--limit 0` for all). `g [N]` jumps to one |
| `n` / `p` | Find Next / Find Previous with the last search |
| `usesel [TEXT]` | *Use Selection for Find*: take the search text from the current selection, the instruction at the cursor, or `TEXT` |
| `symbols [labels\|proc\|strings] [PATTERN]` (also `s`) | Fuzzy, ranked search of names, procedures or strings |
| `scope [TAG ...]` / `scope close` | Show the tag scope and limit `symbols` to addresses with these tags / reset it |
| `recents [clear]` | Recent symbol searches |
| `palette QUERY [!N]` | *Search Anything*. `@` for symbols, `"` for strings, `#` for documents, otherwise commands. `!N` runs result N |
| `textfind [--case] [--word] [--regex] TEXT` | Find bar over the current procedure's listing text |
| `prefs [fuzzy on\|off] [hexcolumn on\|off]` | Fuzzy matching on or off; show instruction bytes in the listing (affects `asm` searches) |

See [Searching](searching.md) for what each search mode matches.

### Go to

| Command | What it does |
|---|---|
| `goto ADDRESS\|NAME` (also `g`) | Go to a name, `$name`, hex address or decimal address, in that order |
| `g [N]` | Go to row N of the last list |
| `offset NUMBER` | Go to a file offset in this slice (`0x` prefix or any hex letter means hex, else decimal) |
| `offset --global NUMBER` | Go to an offset in the whole file, universal-binary header included |
| `procoff OFFSET` | Go to an offset inside the current procedure |
| `top` | Go to the start of the current procedure |
| `follow` | Go to the address the instruction at the cursor refers to |
| `back` / `forward` | Walk the navigation history |
| `history` | Show the navigation history |
| `nextcode` / `nextdata` / `nextproc` / `nextunexplored` | Next code, data, procedure, or bytes nothing has identified |
| `nextsection` / `prevsection` | Next / previous section |

### Cross-references

| Command | What it does |
|---|---|
| `refsto [ADDRESS] [/ FILTER]` | Everything that refers to the cursor's address (or `ADDRESS`) |
| `refsfrom [/ FILTER]` | What the instruction at the cursor refers to |
| `callers [/ FILTER]` | Procedures that call the current procedure |
| `callees` | Procedures the current procedure calls |
| `objcrefs [/ FILTER]` | Places that send the Objective-C message of the method at the cursor |
| `nextxref` / `prevxref` | Step through the references to the cursor's address |

`/ FILTER` keeps only rows whose text contains `FILTER`, for example `refsto / _main`.

### Annotate

| Command | What it does |
|---|---|
| `rename NAME` | Name the cursor's address |
| `comment TEXT` | Comment line above the cursor (empty text removes it) |
| `inline TEXT` | Comment at the end of the cursor's line |
| `tag NAME` / `tag -NAME` | Add / remove a tag at the cursor |
| `bookmark [NAME]` | Toggle a bookmark at the cursor |
| `bookmarks` | List bookmarks |
| `bookmarks N` | Go to bookmark N |
| `bookmarks find NAME` | Find bookmarks by exact name |
| `bookmarks rename NAME` | Rename the bookmark at the cursor |
| `save [PATH]` | Save names, comments, tags and bookmarks |

`save` writes `BINARY.asdb` next to the binary. If that folder is not writable (for example
`/bin`), it writes to `~/.local/share/assemsearch/` instead. The next `open` of the same
binary restores everything, so names and comments you add are searchable later.

### Export

| Command | What it does |
|---|---|
| `export PATH` | Write the whole listing to a text file |
| `export --procedure PATH` | Only the current procedure |
| `export --selection PATH` | Only the selection |

### Debugger lookups

There is no live debugger. `dbg` covers a debugger window's lookups:

| Command | What it does |
|---|---|
| `dbg complete TEXT` | Complete an LLDB command name |
| `dbg load HEXBASE` | Pretend the binary is loaded at this address (ASLR slide) |
| `dbg translate HEXADDR` | Turn a runtime address back into the binary's address |
| `dbg mem HEXADDR` | Show memory at an address |

## Scripting the shell

Run commands without staying interactive:

```sh
assemsearch open BINARY -c "symbols proc parse" -c "g [0]" -c "export --procedure parse.txt"
```

Or pipe them in:

```sh
printf 'nextproc\nwhere 10\n' | assemsearch open BINARY
```

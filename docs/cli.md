# Command line

```
assemsearch [--version] COMMAND ...
```

Every command except `hexre` loads and analyses a binary first. Small binaries take well
under a second; a large app such as BetterDisplay (42 MB per slice) takes about 25 seconds
and 1.5 GB of memory.

## Options for loading a binary

These apply to `open`, `find`, `symbols`, `goto`, `xrefs` and `export`.

| Option | Meaning |
|---|---|
| `BINARY` | Path to a Mach-O (thin or universal), an ELF file (executable, shared object or `.o`), or any file with `--raw` |
| `--arch ARCH` | Which slice of a universal Mach-O to load: `arm64`, `x86_64`, ... Without it, the arm64 slice is used if there is one, otherwise the first. Naming a slice the file does not have is an error that lists the slices it does have |
| `--raw` | Load the file as raw bytes rather than parsing it |
| `--base HEX` | With `--raw`: the address of the first byte |

To look inside a macOS app, point at the executable inside the bundle:

```sh
assemsearch open /Applications/Calculator.app/Contents/MacOS/Calculator
```

If a saved database (`BINARY.asdb`) exists, your names, comments, tags and bookmarks are
restored. See [Interactive shell: save](shell.md#annotate).

## `open`: interactive shell

```sh
assemsearch open BINARY [-j ADDRESS] [-c COMMAND]...
```

| Option | Meaning |
|---|---|
| `-j`, `--jump-to ADDRESS` | Start with the cursor at this hexadecimal address (hex only) |
| `-c`, `--run COMMAND` | Run a shell command and exit instead of staying interactive. Repeat it to run several in order |

```sh
assemsearch open /bin/ls -c "symbols proc main" -c "goto [0]" -c "where 5"
```

See [Interactive shell](shell.md) for the commands.

## `find`: every occurrence of a pattern

```sh
assemsearch find BINARY TEXT [--mode MODE] [--case] [--bits N] [--big] [--limit N]
```

Prints every match as `ADDRESS  NAME+OFFSET`. Exits with status 1 when nothing matches,
which makes it handy in scripts.

| Option | Meaning |
|---|---|
| `--mode asm` | (default) Text in the disassembly listing, e.g. `"bl _strcmp"` |
| `--mode ascii` | Bytes of a text string, e.g. a message the program prints |
| `--mode hex` | Exact bytes, e.g. `"c0 03 5f d6"` |
| `--mode regex` | Hexadecimal regular expression, e.g. `"fd7b..a9"` |
| `--mode number` | An integer stored in memory, e.g. `42` or `0xdeadbeef` |
| `--mode comment` | Text in your comments |
| `--case` | Case-sensitive (`asm`, `ascii`, `comment`) |
| `--bits 8\|16\|32\|64` | With `number`: the integer's size (default 32) |
| `--big` | With `number`: big-endian (default little-endian) |
| `--limit N` | Stop after N matches (default: list them all) |

```sh
$ assemsearch find tests/fixtures/sample_macho --arch arm64 --mode hex c0035fd6
0x100000570  _compute_checksum+40
0x100000578  _compute_checksum+48
```

[Searching](searching.md) explains each mode in detail.

## `symbols`: search names, procedures or strings

```sh
assemsearch symbols BINARY [PATTERN] [--mode labels|proc|strings] [--tag TAG]... [--strict]
```

The sidebar search: fuzzy matching, best matches first. Output is
`ADDRESS  SCORE  NAME`; lower scores are closer matches, and 1 means the pattern appears as
is. In a terminal the matched letters are highlighted.

| Option | Meaning |
|---|---|
| `--mode labels` | (default) All names |
| `--mode proc` | Procedures only |
| `--mode strings` | Strings only |
| `--tag TAG` | Only addresses with this tag (repeatable) |
| `--strict` | Plain substring matching, no fuzzy matches |

```sh
$ assemsearch symbols /bin/ls usage --mode strings
0x100004e06  1  usage: ls [-@ABCFGHILOPRSTUWXabcdefghiklmnopqrstuvwxy1%%,] [--color=when] [-D format] [file ...]\n
0x100004bd4  4  LSCOLORS should use characters a-h instead of 0-9 (see the manual page)
```

## `goto`: resolve an address, name or file offset

```sh
assemsearch goto BINARY TEXT [--type address|offset|global]
```

| `--type` | `TEXT` is |
|---|---|
| `address` | (default) A name (`_main`), then `$name`, then a hex address, then a decimal one |
| `offset` | An offset in the file slice being analysed |
| `global` | An offset in the whole file, counting the universal-binary header and the other slices |

Prints the address and its name, or exits with status 1 if it does not exist.

```sh
$ assemsearch goto tests/fixtures/sample_macho --arch arm64 _main
0x1000005f0  _main
```

## `xrefs`: who refers to an address

```sh
assemsearch xrefs BINARY ADDRESS_OR_NAME
```

Lists every instruction or data item that refers to the address: calls, jumps, loads of a
string, pointers.

```sh
$ assemsearch xrefs tests/fixtures/sample_macho --arch arm64 imp___stubs__strcmp
0x100000594  _validate_license+24 (in _validate_license)
0x10000062c  _main+60 (in _main)
```

## `export`: write the listing to a text file

```sh
assemsearch export BINARY OUTPUT [--procedure NAME_OR_ADDRESS]
```

Writes the full disassembly
listing, or only one procedure, so you can search it with `grep` or diff two versions of
a program. A whole large app writes millions of lines and takes about 40 seconds.

```sh
assemsearch export /bin/ls ls.txt
grep -n "bl.*_strcmp" ls.txt
```

## `hexre`: inspect a hex regular expression

```sh
assemsearch hexre PATTERN
```

Prints the pattern's automaton in Graphviz DOT format, and the number of states to stderr.
Useful for checking that a pattern means what you think.

```sh
assemsearch hexre "fd7b..a9" | dot -Tpng > pattern.png
```

## `mcp`: MCP server

```sh
assemsearch mcp [BINARY...] [--arch ARCH]
```

Serves the loaded binaries to an AI assistant over stdin/stdout. See [MCP server](mcp.md).

## Exit status

| Status | Meaning |
|---|---|
| 0 | Success |
| 1 | Nothing found (`find`, `goto`), an invalid input, or a file that could not be read |
| 2 | Wrong command-line usage |

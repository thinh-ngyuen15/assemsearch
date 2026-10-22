# assemsearch documentation

assemsearch loads a compiled program (Mach-O, ELF or raw bytes), analyses it, and lets you
search and navigate it the way a desktop disassembler does. It is a command-line tool: one-shot
commands, an interactive shell, an MCP server for AI assistants, and a Python API.

```sh
./install.sh
assemsearch open /bin/ls        # then type `help`
```

## Contents

| Page | What it covers |
|---|---|
| [Installation](installation.md) | Install script, wheel, standalone executable, uninstalling, rebuilding |
| [Command line](cli.md) | The one-shot commands: `open`, `find`, `symbols`, `goto`, `xrefs`, `export`, `hexre`, `mcp` |
| [Interactive shell](shell.md) | Every shell command, grouped by task, with a worked session |
| [Searching](searching.md) | The six Find modes, hex regular expressions, fuzzy symbol search, the command palette, Go To |
| [MCP server](mcp.md) | Using assemsearch from Claude Code or another MCP client; the 33 tools |
| [Python API](python-api.md) | Scripting with a camelCase document API |
| [How the analysis works](analysis.md) | Loaders, disassembly, procedures, references, naming; accuracy; limits |
| [Feature map](feature-map.md) | Each feature → module → command; limitations |
| [Development](development.md) | Code layout, tests, fixtures, releasing |

## Why "assemsearch"?

The name is **assem**bly + **search**: the tool searches the assembly of compiled programs.

Nearly everything it does comes back to that. It disassembles a binary into assembly, works
out its procedures, strings and references, and then lets you search all of it: the listing
text, raw bytes, hex patterns, numbers, names, strings and cross-references.

The project folder, the package (`import assemsearch`) and the command (`assemsearch`) all
use the same lowercase word, as is usual for Python command-line tools.

## Quick reference

```sh
assemsearch open BINARY [--arch arm64|x86_64]         # interactive shell
assemsearch find BINARY TEXT [--mode asm|ascii|hex|regex|number|comment]
assemsearch symbols BINARY [PATTERN] [--mode labels|proc|strings]
assemsearch goto BINARY ADDRESS_OR_NAME [--type address|offset|global]
assemsearch xrefs BINARY ADDRESS_OR_NAME
assemsearch export BINARY OUT.txt [--procedure NAME]
assemsearch mcp BINARY...                             # MCP server on stdio
```

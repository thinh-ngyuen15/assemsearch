# Development

## Setup

```sh
cd assemsearch
uv sync                      # creates .venv with capstone and pytest
uv run pytest                # the test suite, about 2 seconds
uv run assemsearch open /bin/ls
```

Lint with [ruff](https://docs.astral.sh/ruff/) (real-error rules):

```sh
uvx ruff check --select F,E9 src tests tools
```

## Code layout

```
assemsearch/
├── src/assemsearch/
│   ├── loaders/          macho.py, elf.py, raw loading; load_file() picks one and runs the analysis
│   ├── analysis.py       the analysis pipeline: disassembly, strings, pointers, references, names
│   ├── cfg.py            procedures from control flow: branches, jump tables, tail calls, noreturn
│   ├── objc.py           Objective-C metadata
│   ├── model.py          DisassembledFile: segments, instructions, procedures, names, comments, tags
│   ├── document.py       Document: cursor, selection, navigation history, the menu-level actions
│   ├── workspace.py      the open documents
│   ├── listing.py        the text of the assembly listing (what `--mode asm` searches)
│   ├── find.py           the Find dialog and the address-space search engine
│   ├── bytesearch.py     byte matching for the ascii / hex / number modes
│   ├── hexregex.py       hex regular expressions: parser → NFA → DFA → table recognizer
│   ├── fuzzy.py          fuzzy scoring and highlighting
│   ├── sidebar.py        symbol search with tag scope
│   ├── palette.py        the command palette
│   ├── goto.py           parsing addresses, names and file offsets
│   ├── lists.py          filterable lists: references, segments, sections, imports, exports
│   ├── textfinder.py     the find bar over a text buffer
│   ├── nametree.py       name ⇄ address index
│   ├── export.py         text export
│   ├── database.py       saving and restoring annotations (.asdb)
│   ├── preferences.py    persisted search options
│   ├── debugger.py       debugger lookups
│   ├── api.py            the camelCase scripting API
│   ├── mcp.py            the MCP server
│   ├── cli.py            command line and interactive shell
│   └── types.py          shared constants
├── tests/                pytest suite and fixture binaries
├── tools/
│   └── build_binary.sh   standalone executable (PyInstaller)
├── docs/                 this documentation
├── install.sh
└── pyproject.toml
```

Data flows one way: **loaders → analysis → model**, then **document / workspace** hold the
state, and **find, sidebar, palette, goto, lists** search it. **cli, mcp, api** are three
front ends over the same document objects; none of them holds search logic of its own.

[Feature map](feature-map.md) lists which module implements each feature.

## Tests

| File | Covers |
|---|---|
| `test_find.py` | Find sheet input, the search engine and its six modes, Use Selection for Find |
| `test_matching.py` | Fuzzy scoring, generated labels, the instruction table, the name index, byte matching, hex regular expressions |
| `test_lists.py` | Symbol search, the palette, list dialogs, the find bar, debugger lookups |
| `test_navigation.py` | Go To, references, next/previous navigation, control flow (procedures), text export, bookmarks, database |
| `test_interfaces.py` | Loaders, MCP server, Python API, command line and shell |

### Fixture binaries

`tests/fixtures/` holds small binaries built from the C and Objective-C sources next to them:

| Fixture | Built from | Used for |
|---|---|---|
| `sample_macho` | `sample.c` | Universal arm64 + x86-64 Mach-O: most tests |
| `sample_elf.o` | `sample.c` | ELF relocatable object |
| `sample_objc`, `sample_objc_stripped` | `sample_objc.m` | Objective-C metadata, with and without local symbols |
| `sample_cfg` | `sample_cfg.c` | Control flow: switch tables, tail calls, noreturn calls |

They are committed so the tests do not need a compiler. To rebuild them (Apple clang
needed): `tests/fixtures/build.sh`. Rebuilding changes addresses, so tests that check exact
addresses may need updating.

Tests never write to your real settings: `conftest.py` points `ASSEMSEARCH_PREFS` and
`XDG_DATA_HOME` at a temporary folder.

## Releasing

1. Bump `__version__` in `src/assemsearch/__init__.py` and commit.
2. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.

The `release` workflow (`.github/workflows/release.yml`) then runs the tests, builds the
wheel and source archive, builds standalone executables on macOS (arm64) and Linux
(x86-64), and publishes a GitHub Release with all of them.

To publish to PyPI as well (once):

1. On PyPI, add a *trusted publisher* for project `assemsearch`: owner `thinh-ngyuen15`,
   repository `assemsearch`, workflow `release.yml`, environment `pypi`.
2. On GitHub, create the environment `pypi` (Settings → Environments) and set the repository
   variable `PUBLISH_TO_PYPI` to `true` (Settings → Secrets and variables → Actions → Variables).

Every later tag is then published to PyPI automatically.

Every push to `main` and every pull request runs the `tests` workflow: Python 3.10 and 3.13
on Linux and macOS.

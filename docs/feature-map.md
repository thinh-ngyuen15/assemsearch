# Feature map

This page maps each feature to the module that implements it and the commands that expose
it.

| Feature | Module | Shell / CLI |
|---|---|---|
| Find dialog: 6 modes, case, wrapping, number size and endianness, Find Next/Previous, Use Selection for Find, Find pasteboard, background search with cancellation | `find.py`, `document.py` | `find`, `n`, `p`, `usesel`; `assemsearch find` |
| Address-space engine: section ranges rotated around the cursor, raw bytes (`locateData` options `0x1/0x2/0x4`), assembly text, comments | `find.py`, `bytesearch.py`, `listing.py` | |
| Hex regular expressions over nibbles: parser → Thompson NFA → subset-construction DFA → dense table recognizer | `hexregex.py` | `find --mode regex`; `assemsearch hexre` (DOT export) |
| Sidebar Labels / Proc. / Str search, ranking, Tag Scope, sort descriptors, recent searches | `sidebar.py` | `symbols`, `scope`, `recents`; `assemsearch symbols` |
| Fuzzy scorer (1 = substring, k = fewest runs, k−1 insertions), strict mode, highlighting, `FuzzyPredicate` | `fuzzy.py` | `prefs fuzzy on/off` |
| Command palette: commands, `@` symbols, `"` strings, `#` documents | `palette.py` | `palette QUERY [!N]` |
| Go To address/symbol (name → `$name` → hex → decimal), file offset, global file offset, procedure offset, top of procedure, address at cursor, Back/Forward, `--jump-to` (hex only) | `goto.py`, `document.py` | `goto`, `offset`, `procoff`, `top`, `follow`, `back`, `forward`, `history`; `open -j` |
| Filterable lists: references, segments, sections (match on address text or comment), imports/exports | `lists.py` | `segments`, `sections`, `imports`, `exports`, `refsto … / FILTER` |
| References to/from, callers/callees, places referencing an Objective-C method, Next/Previous XREF | `analysis.py`, `document.py` | `refsto`, `refsfrom`, `callers`, `callees`, `objcrefs`, `nextxref`, `prevxref`; `assemsearch xrefs` |
| Next Code / Data / Procedure / Unexplored / Section, Previous Section; `findNextAddress:ofTypeOrMetaType:wrapping:` | `document.py` | `nextcode`, `nextdata`, `nextproc`, `nextunexplored`, `nextsection`, `prevsection` |
| Find bar over a text view (incremental matches, next/previous with wrap, whole word, regex, replace in editable views) | `textfinder.py` | `textfind` (over the current procedure's listing) |
| MCP server (JSON-RPC 2.0 over stdio, protocol `2025-03-26`): `search_strings`, `search_procedures`, `search_name` (unanchored regex, `case_sensitive`) and the related lookup and annotation tools | `mcp.py` | `assemsearch mcp` |
| Scripting API with camelCase method names (`getAddressForName`, `getStringsList`, `getNextAddressWithType`, `findBookmarkWithName`, …) | `api.py` | |
| Name ⇄ address index with nearest-name queries | `nametree.py` | |
| Bookmarks: toggle, rename, menu, jump by index, exact case-sensitive name lookup | `model.py`, `document.py` | `bookmark`, `bookmarks [N\|find NAME\|rename NAME]` |
| Text export: the whole listing, the current procedure or the selection, for offline `grep` | `export.py`, `document.py` | `export [--procedure\|--selection] PATH`; `assemsearch export BINARY OUT [--procedure NAME]` |
| Debugger lookups: command completion and history, ASLR translation, module and breakpoint lookup, memory-view jump | `debugger.py` | `dbg complete\|load\|translate\|mem` |

Persistence: search options, the Find pasteboard and recent searches are kept in
`~/.config/assemsearch/preferences.json` (override with `ASSEMSEARCH_PREFS`). Names, comments,
tags and bookmarks are saved with `save` to `BINARY.asdb` and restored on open, so the
searches over them work across sessions. When
the binary's folder is not writable (`/bin/ls`), the database goes to
`~/.local/share/assemsearch/` (or `$XDG_DATA_HOME/assemsearch/`) instead.

## Limitations

* **No decompiler.** The find bar works over the assembly listing; the MCP
  `procedure_pseudo_code` tool returns an error, and `export` writes assembly only
  (there is no *Produce Pseudo-Code File*).
* **Analysis.** Disassembly is a linear sweep over code sections, restarted at every known
  function start; procedures are then built from control flow (`cfg.py`): from each start
  (symbols, `LC_FUNCTION_STARTS`, Objective-C metadata, call targets, the entry point) the
  code is followed through branches, bounded `switch` jump tables and tail calls, stopping
  at calls that never return. A procedure is the set of basic blocks reached, so it need not
  be contiguous. Every function the binary records is a procedure. References come from
  direct branches, register tracking (arm64 `adrp`/`add`/`sub`/loads and stores, literal
  pools, switch tables; x86 RIP-relative operands), Mach-O chained-fixup pointers (decoded),
  Objective-C metadata and Swift field/type descriptors. Generated names follow common
  disassembler conventions (`aSomeString`, `cfstring_…`, `qword_…`, `double_value_0_1`,
  `switch_table_…`, `_objc_msgSend$sel`, `__objc_class_X_data`, an "External Symbols"
  segment…). See [How the analysis works](analysis.md#accuracy).
* **Regex dialects.** The MCP search tools use Python `re` rather than ICU
  (`NSRegularExpression`); typical patterns behave the same.
* **Hex-regexp matches** must end on a byte boundary, and the driver returns the longest
  match at the first matching offset.
* **The debugger** has no live process. `LocalChannel` completes against a fixed
  LLDB command list and serves memory from the loaded documents. Plug a real channel into
  `DebuggerSession(channel=…)` to drive a real process.

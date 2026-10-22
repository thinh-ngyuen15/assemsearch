# MCP server

`assemsearch mcp` lets an AI assistant (Claude Code, Claude Desktop, or any other
[Model Context Protocol](https://modelcontextprotocol.io) client) explore a binary: list
procedures, search strings, read assembly, follow cross-references, and add names and
comments.

It offers 33 tools for listing, searching, reading and annotating a binary. The answers
come from assemsearch's own analysis (see [How the analysis works](analysis.md)).

```sh
assemsearch mcp [BINARY...] [--arch ARCH]
```

The server speaks JSON-RPC 2.0 over stdin/stdout (protocol version `2025-03-26`, one message
per line, batches allowed). It loads and analyses every binary you list before answering, so
the first reply for a large app can take half a minute.

## Connecting a client

**Claude Code:**

```sh
claude mcp add assemsearch -- assemsearch mcp /path/to/binary
# several binaries, a chosen slice:
claude mcp add assemsearch -- assemsearch mcp /path/to/App --arch x86_64
```

**Claude Desktop** and other clients that take a JSON configuration:

```json
{
  "mcpServers": {
    "assemsearch": {
      "command": "assemsearch",
      "args": ["mcp", "/Applications/Calculator.app/Contents/MacOS/Calculator"]
    }
  }
}
```

If the client cannot find `assemsearch` on its `PATH`, give the full path from
`which assemsearch` as `command`.

## Documents

Each binary is a *document*, named after its file (`ls`, `Calculator`). The **last one
listed is the current document**. Every tool takes an optional `document` argument; without
it, the tool works on the current one. `list_documents` and `set_current_document` switch
between them.

## Arguments

* **Addresses** are strings: a name (`_main`), a hex address (`0x1000005f0` or `1000005f0`)
  or a decimal one. Where `address` is optional, it defaults to the document's cursor.
* **Procedures** are given by exact name or by any address inside them.
* **Patterns** in the `search_*` tools are regular expressions matched anywhere in the name
  (Python `re` syntax).
  Case-insensitive unless `case_sensitive` is `true`.

Errors come back as a normal tool result with `isError: true` and a message such as
`Invalid address: foo`, so the assistant can correct itself.

## Tools

### Documents and cursor

| Tool | Arguments | Returns |
|---|---|---|
| `list_documents` | | Names of the open documents |
| `current_document` | | Name of the current document |
| `set_current_document` | `document` | Makes it current |
| `current_address` | | The cursor's address |
| `current_procedure` | | Name of the procedure at the cursor |
| `goto_address` | `address` | Moves the cursor |
| `next_address` / `prev_address` | `address?` | The next / previous item's address |

### Lists and search

| Tool | Arguments | Returns |
|---|---|---|
| `list_segments` | | Segments and their sections |
| `list_procedures` | | Every procedure: address → name |
| `list_procedure_size` | | Every procedure with its size |
| `list_procedure_info` | | Every procedure with size, basic-block count and more |
| `list_strings` | | Every string: address → text |
| `list_names` | | Every name: address → name |
| `list_bookmarks` | | Bookmarks |
| `search_strings` | `pattern`, `case_sensitive?` | Matching strings: address → text |
| `search_procedures` | `pattern`, `case_sensitive?` | Matching procedures: address → name |
| `search_name` | `pattern`, `case_sensitive?` | Matching names: address → name |

On a large app the `list_*` tools return tens of thousands of entries. Prefer the `search_*`
tools.

### Procedures and references

| Tool | Arguments | Returns |
|---|---|---|
| `procedure_info` | `procedure?` | Name, entry point, length, basic blocks, signature, locals |
| `procedure_address` | `procedure?` | Entry point of a procedure |
| `procedure_assembly` | `procedure?` | Its assembly listing |
| `procedure_pseudo_code` | `procedure?` | Always an error: assemsearch has no decompiler |
| `procedure_callers` | `procedure?` | Names of the procedures that call it |
| `procedure_callees` | `procedure?` | Names of the procedures it calls |
| `xrefs` | `address?` | Addresses that refer to this address |

### Names, comments, bookmarks

| Tool | Arguments | Does |
|---|---|---|
| `address_name` | `address?` | Returns the name at an address |
| `set_address_name` | `address?`, `name` | Names an address |
| `comment` / `inline_comment` | `address?` | Returns the comment |
| `set_comment` / `set_inline_comment` | `address?`, `comment` | Sets it |
| `set_bookmark` | `address?`, `name?` | Adds a bookmark |
| `unset_bookmark` | `address?` | Removes it |

Changes the assistant makes stay in memory for the session. They are not saved to the
`.asdb` database; open the binary with `assemsearch open` and use `save` to keep annotations.

## Example exchange

```sh
$ assemsearch mcp tests/fixtures/sample_macho --arch arm64
```

```json
→ {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_strings","arguments":{"pattern":"licen"}}}
← {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"0x1000006d7\": \"License OK: %u\\n\", \"0x1000006e7\": \"Invalid license\"}"}]}}

→ {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"xrefs","arguments":{"address":"0x1000006e7"}}}
← {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"[\"0x100000684\"]"}]}}

→ {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"procedure_info","arguments":{"procedure":"_main"}}}
← {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"name\": \"_main\", \"entrypoint\": \"0x1000005f0\", \"length\": 176, \"basicblock_count\": 9, ...}"}]}}
```

A typical assistant workflow: `search_strings` for an error message → `xrefs` on its address
→ `procedure_info` / `procedure_assembly` on the procedure that uses it →
`procedure_callers` to walk up the call tree → `set_address_name` and `set_comment` to record
what it learned.

## Using it from code

`MCPServer` can be driven without stdio:

```python
from assemsearch.mcp import MCPServer
from assemsearch.workspace import Workspace

workspace = Workspace()
workspace.open("/bin/ls")
server = MCPServer(workspace)
reply = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "search_procedures", "arguments": {"pattern": "^_main$"}}})
```

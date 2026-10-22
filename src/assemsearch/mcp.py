"""MCP server over stdio (JSON-RPC 2.0, protocol 2025-03-26).

The search tools filter names, strings and procedures with an unanchored,
optionally case-insensitive regular expression.  The server owns the Workspace
directly.  JSON-RPC batches are accepted, as protocol 2025-03-26 requires.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any, Callable, TextIO

from assemsearch.document import Document
from assemsearch.listing import lines_for_virtual_address
from assemsearch.types import BAD_ADDRESS, format_address
from assemsearch.workspace import Workspace

PROTOCOL_VERSION = "2025-03-26"
SERVER_NAME = "assemsearch"

DOCUMENT_NOT_FOUND = "Document not found."
NO_CONTENT = "The document has no content."
INVALID_REGEX = "Invalid regular expression provided"


class ToolError(Exception):
    pass


_DOC = {"document": {"type": "string", "description": "Document name. Leave unset for the current document."}}
_ADDR = {"address": {"type": "string", "description": "Hexadecimal address or name. Leave unset for the current address."}}
_PROC = {"procedure": {"type": "string", "description": "Procedure name, or any hexadecimal address within the procedure. Leave unset for the current procedure."}}
_SEARCH = {"pattern": {"type": "string", "description": "Regular expression."},
           "case_sensitive": {"type": "boolean", "description": "Case-sensitive matching (default false)."}}


def _schema(props: dict, required: tuple[str, ...] = ()) -> dict:
    return {"type": "object", "properties": {**_DOC, **props}, "required": list(required)}


class MCPServer:
    def __init__(self, workspace: Workspace) -> None:
        self.workspace = workspace
        self.tools: dict[str, tuple[str, dict, Callable[..., Any]]] = {}
        self._register_tools()

    # Plumbing ---------------------------------------------------------------------

    def tool(self, name: str, description: str, schema: dict):
        def wrap(fn):
            self.tools[name] = (description, schema, fn)
            return fn
        return wrap

    def handle(self, message: Any) -> dict | None:
        if not isinstance(message, dict):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        method, ident = message.get("method"), message.get("id")
        if ident is None:  # notification (e.g. notifications/initialized)
            return None
        try:
            if method == "initialize":
                result = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                          "serverInfo": {"name": SERVER_NAME, "version": "0.1.0"}}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [{"name": n, "description": d, "inputSchema": s}
                                    for n, (d, s, _) in self.tools.items()]}
            elif method == "tools/call":
                result = self.call_tool(message["params"]["name"], message["params"].get("arguments") or {})
            else:
                return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": f"Unknown method {method}"}}
        except Exception as error:  # report, never crash the server
            return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32603, "message": str(error)}}
        return {"jsonrpc": "2.0", "id": ident, "result": result}

    def handle_batch(self, messages: list) -> list | dict | None:
        """One response per request in the batch; nothing when it holds only notifications."""
        if not messages:
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        return [r for r in map(self.handle, messages) if r is not None] or None

    def call_tool(self, name: str, arguments: dict) -> dict:
        if name not in self.tools:
            return {"content": [{"type": "text", "text": f"Unknown tool {name}"}], "isError": True}
        try:
            value = self.tools[name][2](**arguments)
        except ToolError as error:
            return {"content": [{"type": "text", "text": str(error)}], "isError": True}
        except TypeError as error:
            return {"content": [{"type": "text", "text": f"Invalid arguments: {error}"}], "isError": True}
        text = value if isinstance(value, str) else json.dumps(value)
        return {"content": [{"type": "text", "text": text}]}

    def serve(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            else:
                response = self.handle_batch(message) if isinstance(message, list) else self.handle(message)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()

    # Resolution helpers -----------------------------------------------------------

    def _document(self, document: str | None) -> Document:
        doc = self.workspace.find(document)
        if doc is None:
            raise ToolError(DOCUMENT_NOT_FOUND)
        if not doc.file.segments:
            raise ToolError(NO_CONTENT)
        return doc

    @staticmethod
    def _address(doc: Document, address: str | None) -> int:
        if address is None or address == "":
            return doc.cursor
        from assemsearch.goto import parse_address_string
        value = parse_address_string(doc.file, address)
        if value == BAD_ADDRESS:
            raise ToolError(f"Invalid address: {address}")
        return value

    def _procedure(self, doc: Document, procedure: str | None):
        if procedure is None or procedure == "":
            found = doc.current_procedure
        else:
            address = doc.file.find_virtual_address_named(procedure)
            if address == BAD_ADDRESS:
                address = self._address(doc, procedure)
            found = doc.file.procedure_at(address)
        if found is None:
            raise ToolError("No procedure found.")
        return found

    @staticmethod
    def _regex(pattern: str, case_sensitive: bool) -> re.Pattern[str]:
        try:
            return re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as error:
            raise ToolError(INVALID_REGEX) from error

    @staticmethod
    def _proc_name(doc: Document, entry: int) -> str:
        return doc.file.name_for_virtual_address(entry) or f"sub_{entry:x}"

    def _procedure_info(self, doc: Document, procedure) -> dict:
        return {"name": self._proc_name(doc, procedure.entry), "entrypoint": format_address(procedure.entry),
                "length": procedure.length, "basicblock_count": len(procedure.basic_blocks),
                "basicblocks": [{"from": format_address(b.start), "to": format_address(b.end)}
                                for b in procedure.basic_blocks],
                "signature": self._proc_name(doc, procedure.entry),
                "locals": sorted(procedure.local_labels.values())}

    # Tools -----------------------------------------------------------------------------

    def _register_tools(self) -> None:
        ws = self.workspace

        @self.tool("list_documents", "List the names of all documents currently open.", {"type": "object", "properties": {}})
        def list_documents():
            return [d.display_name for d in ws.documents]

        @self.tool("current_document", "Return the name of the current document.", {"type": "object", "properties": {}})
        def current_document():
            return ws.current.display_name if ws.current else DOCUMENT_NOT_FOUND

        @self.tool("set_current_document", "Set the current document.", _schema({}, ("document",)))
        def set_current_document(document):
            if ws.set_current(document) is None:
                raise ToolError(DOCUMENT_NOT_FOUND)
            return "OK"

        @self.tool("current_address", "Return the address of the cursor.", _schema({}))
        def current_address(document=None):
            return format_address(self._document(document).cursor)

        @self.tool("current_procedure", "Return the name of the procedure containing the cursor.", _schema({}))
        def current_procedure(document=None):
            doc = self._document(document)
            procedure = doc.current_procedure
            return self._proc_name(doc, procedure.entry) if procedure else "No procedure at the current address."

        @self.tool("goto_address", "Move the cursor to an address or name.", _schema(_ADDR, ("address",)))
        def goto_address(address, document=None):
            doc = self._document(document)
            if not doc.goto_virtual_address(self._address(doc, address)):
                raise ToolError(f"Invalid address: {address}")
            return format_address(doc.cursor)

        @self.tool("next_address", "Return the address of the object following the given address.", _schema(_ADDR))
        def next_address(address=None, document=None):
            doc = self._document(document)
            return format_address(doc.file.next_address_of_virtual_address(self._address(doc, address)))

        @self.tool("prev_address", "Return the address of the object preceding the given address.", _schema(_ADDR))
        def prev_address(address=None, document=None):
            doc = self._document(document)
            return format_address(doc.file.previous_address_of_virtual_address(self._address(doc, address)))

        @self.tool("comment", "Return the comment at an address.", _schema(_ADDR))
        def comment(address=None, document=None):
            doc = self._document(document)
            return doc.file.comment_at_virtual_address(self._address(doc, address)) or ""

        @self.tool("inline_comment", "Return the inline comment at an address.", _schema(_ADDR))
        def inline_comment(address=None, document=None):
            doc = self._document(document)
            return doc.file.inline_comment_at_virtual_address(self._address(doc, address)) or ""

        @self.tool("set_comment", "Set the comment at an address.", _schema({**_ADDR, "comment": {"type": "string"}}, ("comment",)))
        def set_comment(comment, address=None, document=None):
            doc = self._document(document)
            doc.file.set_comment(self._address(doc, address), comment)
            return "OK"

        @self.tool("set_inline_comment", "Set the inline comment at an address.", _schema({**_ADDR, "comment": {"type": "string"}}, ("comment",)))
        def set_inline_comment(comment, address=None, document=None):
            doc = self._document(document)
            doc.file.set_inline_comment(self._address(doc, address), comment)
            return "OK"

        @self.tool("set_address_name", "Name an address.", _schema({**_ADDR, "name": {"type": "string"}}, ("name",)))
        def set_address_name(name, address=None, document=None):
            doc = self._document(document)
            doc.file.set_name(self._address(doc, address), name)
            return "OK"

        @self.tool("address_name", "Return the name of an address.", _schema(_ADDR))
        def address_name(address=None, document=None):
            doc = self._document(document)
            return doc.file.name_for_virtual_address(self._address(doc, address)) or ""

        @self.tool("list_segments", "List the segments of the document with their sections.", _schema({}))
        def list_segments(document=None):
            doc = self._document(document)
            return [{"name": s.name, "start": format_address(s.start), "end": format_address(s.end),
                     "writable": not s.executable, "executable": s.executable,
                     "sections": [{"name": x.name, "start": format_address(x.start), "end": format_address(x.end)}
                                  for x in s.sections]} for s in doc.file.segments]

        @self.tool("list_procedures", "List all procedures with their entry point addresses. Use search_procedures to find specific procedures.", _schema({}))
        def list_procedures(document=None):
            doc = self._document(document)
            return {format_address(p.entry): self._proc_name(doc, p.entry) for p in doc.file.procedure_list()}

        @self.tool("list_procedure_size", "List all procedures with their size.", _schema({}))
        def list_procedure_size(document=None):
            doc = self._document(document)
            return {format_address(p.entry): {"name": self._proc_name(doc, p.entry), "size": p.length,
                                              "basicblock_count": len(p.basic_blocks)}
                    for p in doc.file.procedure_list()}

        @self.tool("list_procedure_info", "List all procedures with detailed information.", _schema({}))
        def list_procedure_info(document=None):
            doc = self._document(document)
            return {format_address(p.entry): self._procedure_info(doc, p) for p in doc.file.procedure_list()}

        @self.tool("list_strings", "List all strings with their addresses. Use search_strings to find specific strings.", _schema({}))
        def list_strings(document=None):
            doc = self._document(document)
            return {format_address(a): s for a, s in sorted(doc.file.strings.items())}

        @self.tool("list_names", "List all names (labels) with their addresses.", _schema({}))
        def list_names(document=None):
            doc = self._document(document)
            return {format_address(a): n for a, n in doc.file.names.items()}

        @self.tool("list_bookmarks", "List all bookmarks.", _schema({}))
        def list_bookmarks(document=None):
            doc = self._document(document)
            return {format_address(b.address): b.name for b in doc.file.bookmarks}

        @self.tool("set_bookmark", "Set a bookmark at an address.", _schema({**_ADDR, "name": {"type": "string"}}))
        def set_bookmark(address=None, name="", document=None):
            doc = self._document(document)
            target = self._address(doc, address)
            if not doc.file.has_bookmark_at_virtual_address(target):
                doc.file.toggle_bookmark_at_virtual_address(target, name)
            elif name:
                doc.file.rename_bookmark(target, name)
            return "OK"

        @self.tool("unset_bookmark", "Remove the bookmark at an address.", _schema(_ADDR))
        def unset_bookmark(address=None, document=None):
            doc = self._document(document)
            target = self._address(doc, address)
            if doc.file.has_bookmark_at_virtual_address(target):
                doc.file.toggle_bookmark_at_virtual_address(target)
            return "OK"

        @self.tool("search_strings", "Search for strings in the specified document by filtering all strings using a regular expression. Returns an object mapping addresses to strings.", _schema(_SEARCH, ("pattern",)))
        def search_strings(pattern, case_sensitive=False, document=None):
            doc = self._document(document)
            regex = self._regex(pattern, case_sensitive)
            return {format_address(a): s for a, s in sorted(doc.file.strings.items()) if regex.search(s)}

        @self.tool("search_procedures", "Search for procedures in the specified document by filtering procedure names using a regular expression. Returns an object mapping entry point addresses to procedure names.", _schema(_SEARCH, ("pattern",)))
        def search_procedures(pattern, case_sensitive=False, document=None):
            doc = self._document(document)
            regex = self._regex(pattern, case_sensitive)
            names = {format_address(p.entry): self._proc_name(doc, p.entry) for p in doc.file.procedure_list()}
            return {a: n for a, n in names.items() if regex.search(n)}

        @self.tool("search_name", "Search for a label with a name matching a given pattern in the specified document. Returns an object mapping addresses to names.", _schema(_SEARCH, ("pattern",)))
        def search_name(pattern, case_sensitive=False, document=None):
            doc = self._document(document)
            regex = self._regex(pattern, case_sensitive)
            return {format_address(a): n for a, n in doc.file.names.items() if regex.search(n)}

        @self.tool("procedure_info", "Return information about a procedure. Can also be used to find a procedure by its exact name or address.", _schema(_PROC))
        def procedure_info(procedure=None, document=None):
            doc = self._document(document)
            return self._procedure_info(doc, self._procedure(doc, procedure))

        @self.tool("procedure_address", "Find the entry point of a given procedure, by its name, or by any hexadecimal address within the procedure.", _schema(_PROC))
        def procedure_address(procedure=None, document=None):
            doc = self._document(document)
            return format_address(self._procedure(doc, procedure).entry)

        @self.tool("procedure_assembly", "Return the assembly listing of a procedure.", _schema(_PROC))
        def procedure_assembly(procedure=None, document=None):
            doc = self._document(document)
            found = self._procedure(doc, procedure)
            lines = []
            for address in doc.file.procedure_object_addresses(found):
                lines += lines_for_virtual_address(doc.file, address)
            return "\n".join(lines)

        @self.tool("procedure_pseudo_code", "Return the pseudo-code of a procedure.", _schema(_PROC))
        def procedure_pseudo_code(procedure=None, document=None):
            raise ToolError("Pseudo-code is not available: assemsearch has no decompiler.")

        @self.tool("xrefs", "List all addresses referencing a given address in the specified document. Returns a list of addresses in hexadecimal.", _schema(_ADDR))
        def xrefs(address=None, document=None):
            doc = self._document(document)
            return [format_address(a) for a in doc.file.references_to(self._address(doc, address))]

        @self.tool("procedure_callers", "List all procedures that call a given procedure in the specified document. Returns a list of names.", _schema(_PROC))
        def procedure_callers(procedure=None, document=None):
            doc = self._document(document)
            return [self._proc_name(doc, a) for a in sorted(self._procedure(doc, procedure).callers)]

        @self.tool("procedure_callees", "List all procedures called by a given procedure in the specified document. Returns a list of names.", _schema(_PROC))
        def procedure_callees(procedure=None, document=None):
            doc = self._document(document)
            return [self._proc_name(doc, a) for a in sorted(self._procedure(doc, procedure).callees)]


def serve(paths: list[str], arch: str | None = None) -> None:
    workspace = Workspace()
    for path in paths:
        workspace.open(path, arch=arch)
    MCPServer(workspace).serve()

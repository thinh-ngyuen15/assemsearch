"""Command line: one-shot searches, an interactive shell, and the MCP server.

    assemsearch open BINARY [-j ADDRESS]      interactive shell (type `help`)
    assemsearch find BINARY TEXT [--mode M]   list every occurrence
    assemsearch symbols BINARY [PATTERN]      sidebar search
    assemsearch goto BINARY TEXT              resolve an address/name/file offset
    assemsearch xrefs BINARY ADDRESS          references to an address
    assemsearch export BINARY OUT             Produce Text File
    assemsearch mcp BINARY...                 MCP server on stdio
"""

from __future__ import annotations

import argparse
import cmd
import re
import shlex
import sys

from assemsearch import __version__, database, fuzzy
from assemsearch.debugger import DebuggerSession
from assemsearch.document import Document
from assemsearch.find import MODE_TITLES, FindContext, FindInputError, FindMode, SearchEngine
from assemsearch.goto import GotoError, GotoType, parse_address_string, parse_hex_address
from assemsearch.lists import ListOfAddresses, exports_window, imports_window, sections_list, segments_list
from assemsearch.listing import lines_for_virtual_address
from assemsearch.palette import Command, CommandPalette
from assemsearch.preferences import Preferences
from assemsearch.sidebar import DisplayMode, Sidebar
from assemsearch.textfinder import TextFinder
from assemsearch.types import BAD_ADDRESS, format_address
from assemsearch.workspace import Workspace

MODE_NAMES = {"ascii": FindMode.ASCII_STRING, "hex": FindMode.HEX_VALUE, "asm": FindMode.STRING_IN_ASSEMBLY,
              "regex": FindMode.HEX_REGEXP, "number": FindMode.NUMBER, "comment": FindMode.STRING_IN_COMMENTS}
SIDEBAR_MODES = {"labels": DisplayMode.LABELS, "procedures": DisplayMode.PROCEDURES, "proc": DisplayMode.PROCEDURES,
                 "strings": DisplayMode.STRINGS, "str": DisplayMode.STRINGS}


def _split(arg: str) -> list[str]:
    """Shell words; quotes group words but backslashes stay, so regular expressions survive."""
    lexer = shlex.shlex(arg, posix=True)
    lexer.whitespace_split = True
    lexer.escape = ""
    lexer.commenters = ""
    return list(lexer)


class _ArgumentParser(argparse.ArgumentParser):
    """Shell commands report usage errors instead of exiting the process."""

    def error(self, message):
        raise ValueError(f"{message}\n{self.format_usage().rstrip()}")


def _color(text: str, pattern: str) -> str:
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return fuzzy.colorized(text, pattern) if sys.stdout.isatty() else text


def find_all(document: Document, context: FindContext, limit: int | None = None) -> list:
    """Every occurrence (or the first ``limit``), in address order (Find Next repeated without wrapping)."""
    engine = SearchEngine(document.file, document.prefs.show_hex_column)
    context = FindContext(context.mode, context.case_sensitive, False, context.data, context.text)
    hits = []
    first = engine._find(document.file.min_address, context, False, lambda: False, None)
    while first is not None and (limit is None or len(hits) < limit):
        hits.append(first)
        address = first.location
        first = engine.find_next(address, context)
        if first is not None and first.location <= address:
            break
    return hits


class Shell(cmd.Cmd):
    intro = "assemsearch shell. Type `help` for commands, `quit` to exit."

    def __init__(self, workspace: Workspace) -> None:
        super().__init__()
        self.ws = workspace
        self.sidebar: Sidebar | None = None
        self.last_list: list[int] = []
        self.debugger = DebuggerSession()
        self.palette = CommandPalette(self._palette_commands(), workspace.documents, workspace.current, workspace.prefs)

    # Helpers ---------------------------------------------------------------------

    @property
    def doc(self) -> Document:
        if self.ws.current is None:
            raise RuntimeError("no document open (use `open PATH`)")
        return self.ws.current

    @property
    def prompt(self) -> str:  # type: ignore[override]
        if self.ws.current is None:
            return "(assemsearch) "
        name = self.doc.file.friendly_name_for_virtual_address(self.doc.cursor)
        return f"({self.doc.display_name} {format_address(self.doc.cursor)} {name}) "

    def onecmd(self, line: str) -> bool:
        """A failing or interrupted command never ends the session (it may hold unsaved annotations)."""
        try:
            return super().onecmd(line)
        except (OSError, RuntimeError, ValueError, GotoError, FindInputError, re.error) as error:
            print(f"error: {error}")
        except KeyboardInterrupt:
            print("\ninterrupted")
        except Exception as error:  # report, never lose the session
            print(f"error: {type(error).__name__}: {error}")
        return False

    def cmdloop(self, intro=None):
        """Ctrl-C at the prompt discards the line; `quit` or Ctrl-D leaves."""
        while True:
            try:
                return super().cmdloop(intro)
            except KeyboardInterrupt:
                print("^C")
                intro = ""

    def _report(self, ok, what: str = "") -> None:
        if ok:
            self.show_cursor()
        else:
            print(f"\a{self.doc.last_beep or 'not found'}{': ' + what if what else ''}")

    def show_cursor(self, count: int = 1) -> None:
        address = self.doc.cursor
        for _ in range(count):
            if not self.doc.file.has_segment_at(address):
                break
            for line in lines_for_virtual_address(self.doc.file, address, hex_column=self.doc.prefs.show_hex_column):
                print(line)
            address = self.doc.file.next_address_of_virtual_address(address)

    def _print_list(self, rows: list[tuple[int, str]], pattern: str = "", limit: int = 50) -> None:
        self.last_list = [a for a, _ in rows]
        for i, (address, text) in enumerate(rows[:limit]):
            print(f"[{i:>3}] {format_address(address):>18}  {_color(text, pattern)}")
        if len(rows) > limit:
            print(f"… {len(rows) - limit} more")
        if not rows:
            print("(no results)")

    def _show_address_list(self, lst: ListOfAddresses, pattern: str) -> None:
        rows = lst.update_search(pattern)
        print(f"{lst.label} ({len(rows)}/{len(lst.rows)})")
        self._print_list([(r["address"], f"{r['addressRepresentation']}  {r['comment']}") for r in rows], pattern)

    # Documents ---------------------------------------------------------------------

    def do_open(self, arg):
        """open PATH [--arch ARCH] [--raw] [--base HEX] — load a binary (restores its .asdb database)."""
        parser = _ArgumentParser(prog="open", add_help=False)
        parser.add_argument("path")
        parser.add_argument("--arch")
        parser.add_argument("--raw", action="store_true")
        parser.add_argument("--base", type=lambda s: int(s, 16))
        args = parser.parse_args(_split(arg))
        document = self.ws.open(args.path, arch=args.arch, raw=args.raw, base=args.base)
        self.palette.current_document = document
        if document.database_warning:
            print(f"warning: {document.database_warning}")
        print(f"loaded {document.display_name}: {document.file.cpu} {document.file.file_type}, "
              f"{len(document.file.procedures)} procedures, {len(document.file.strings)} strings, "
              f"{len(document.file.names)} names")

    def do_docs(self, arg):
        """docs — list open documents."""
        for i, d in enumerate(self.ws.documents):
            print(f"{'*' if d is self.ws.current else ' '} [{i}] {d.display_name}")

    def do_use(self, arg):
        """use NAME|INDEX — switch the current document."""
        if self.ws.set_current(arg.strip()) is None:
            print("Document not found.")
        self.palette.current_document = self.ws.current

    def do_save(self, arg):
        """save [PATH] — save names, comments, tags and bookmarks to a .asdb database."""
        print(f"saved {database.save(self.doc.file, arg.strip() or None)}")

    def do_export(self, arg):
        """export [--procedure | --selection] PATH — Produce Text File: the listing, for offline grep."""
        parser = _ArgumentParser(prog="export", add_help=False)
        scope = parser.add_mutually_exclusive_group()
        scope.add_argument("--procedure", action="store_true")
        scope.add_argument("--selection", action="store_true")
        parser.add_argument("path")
        args = parser.parse_args(_split(arg))
        if args.procedure:
            count = self.doc.produce_text_file_for_current_procedure(args.path)
        elif args.selection:
            count = self.doc.produce_text_file_for_current_selection(args.path)
        else:
            count = self.doc.produce_text_file(args.path)
        print(f"\a{self.doc.last_beep}" if count is None else f"wrote {count} lines to {args.path}")

    def do_where(self, arg):
        """where [N] — show N listing objects at the cursor."""
        self.show_cursor(int(arg) if arg.strip() else 8)

    do_l = do_where

    # Find ------------------------------------------------------------------------

    def do_find(self, arg):
        """find [--mode ascii|hex|asm|regex|number|comment] [--case|--nocase] [--wrap|--nowrap]
        [--bits 8|16|32|64] [--big|--little] [--all [--limit N]] TEXT
        Find the next occurrence (or --all occurrences, the first 200 unless --limit; 0 = no limit).
        Options default to the last used ones."""
        parser = _ArgumentParser(prog="find", add_help=False)
        parser.add_argument("--mode", choices=MODE_NAMES)
        parser.add_argument("--case", action="store_true", default=None)
        parser.add_argument("--nocase", dest="case", action="store_false")
        parser.add_argument("--wrap", action="store_true", default=None)
        parser.add_argument("--nowrap", dest="wrap", action="store_false")
        parser.add_argument("--bits", type=int, choices=(8, 16, 32, 64))
        parser.add_argument("--little", action="store_true", default=None)
        parser.add_argument("--big", dest="little", action="store_false")
        parser.add_argument("--all", action="store_true")
        parser.add_argument("--limit", type=int, default=200)
        parser.add_argument("text", nargs="+")
        args = parser.parse_args(_split(arg))
        context = self.doc.set_find(" ".join(args.text), MODE_NAMES[args.mode] if args.mode else None,
                                    args.case, args.wrap, args.bits, args.little)
        print(f"[{MODE_TITLES[context.mode]}, case {'on' if context.case_sensitive else 'off'}, "
              f"wrap {'on' if context.wrapping else 'off'}]")
        if args.all:
            limit = args.limit or None
            hits = find_all(self.doc, context, None if limit is None else limit + 1)
            self._print_list([(h.location, self.doc.file.friendly_name_for_virtual_address(h.location)
                               + f"  ({h.length} bytes)") for h in hits[:limit]], limit=len(hits))
            if limit is not None and len(hits) > limit:
                print(f"(stopped after {limit} matches; `find --all --limit 0 ...` lists them all)")
            return
        self._report(self.doc.move_cursor_at_next_occurrence())

    def do_n(self, arg):
        """n — Find Next."""
        self._report(self.doc.move_cursor_at_next_occurrence())

    def do_p(self, arg):
        """p — Find Previous."""
        self._report(self.doc.move_cursor_at_previous_occurrence())

    def do_usesel(self, arg):
        """usesel [TEXT] — Use Selection for Find (seeds the find string from the selection, the cursor's item or TEXT)."""
        context = self.doc.use_selection_for_find(arg or None)
        print(f"find string: {context.text!r}" if context else "nothing to find")

    # Sidebar -----------------------------------------------------------------------

    def do_symbols(self, arg):
        """symbols [labels|proc|strings] [PATTERN] — Search for Symbol (fuzzy, ranked)."""
        words = arg.split(maxsplit=1)
        if self.sidebar is None or self.sidebar.file is not self.doc.file:
            self.sidebar = Sidebar(self.doc.file, self.doc.prefs)
        if words and words[0] in SIDEBAR_MODES:
            self.sidebar.mode = SIDEBAR_MODES[words.pop(0)]
        pattern = words[0] if words else ""
        rows = self.sidebar.update_search(pattern)
        self.sidebar.add_current_search_value_to_search_history()
        scope = f" tags={sorted(self.sidebar.selected_tags)}" if self.sidebar.selected_tags else ""
        print(f"{self.sidebar.mode.name.title()}{scope}: {len(rows)} results")
        self._print_list([(r.address, f"{r.name}" + (f"  (score {r.score})" if pattern else "")) for r in rows],
                         pattern)

    do_s = do_symbols

    def do_scope(self, arg):
        """scope [TAG ...] | scope close — show the Tag Scope and select tags (close resets it)."""
        if self.sidebar is None:
            self.sidebar = Sidebar(self.doc.file, self.doc.prefs)
        if arg.strip() == "close":
            self.sidebar.hide_search_scope_option()
            print("tag scope closed")
        elif arg.strip():
            self.sidebar.select_tags(*arg.split())
            print(f"tag scope: {sorted(self.sidebar.selected_tags)}")
        else:
            print("tags:", ", ".join(self.doc.file.all_tags()) or "(none)")

    def do_recents(self, arg):
        """recents [clear] — the symbol search field's recent searches."""
        sidebar = self.sidebar or Sidebar(self.doc.file, self.doc.prefs)
        if arg.strip() == "clear":
            sidebar.clear_recent_searches()
        print("\n".join(sidebar.recent_searches()) or "(none)")

    # Command palette -----------------------------------------------------------------

    def _palette_commands(self) -> list[Command]:
        def run(line):
            return lambda: self.onecmd(line)
        return [Command("Go Back", run("back"), "⌘["), Command("Go Forward", run("forward"), "⌘]"),
                Command("Find Next", run("n"), "⌘G"), Command("Find Previous", run("p"), "⇧⌘G"),
                Command("Next Code", run("nextcode")), Command("Next Data", run("nextdata")),
                Command("Next Procedure", run("nextproc")), Command("Next Unexplored", run("nextunexplored")),
                Command("Next Section", run("nextsection")), Command("Previous Section", run("prevsection")),
                Command("Next XREF", run("nextxref")), Command("Previous XREF", run("prevxref")),
                Command("Go To Top of Procedure", run("top")), Command("Go To Address at Cursor", run("follow")),
                Command("References To Highlighted Word", run("refsto")),
                Command("References From Highlighted Word", run("refsfrom")),
                Command("Show Places Calling This Procedure", run("callers")),
                Command("Show Places Referencing This Objective-C Method", run("objcrefs")),
                Command("Show Segment List", run("segments")), Command("Show Section List", run("sections")),
                Command("Show Imports", run("imports")), Command("Show Exports", run("exports")),
                Command("Toggle Bookmark", run("bookmark")), Command("Save Database", run("save")),
                Command("Produce Text File", lambda: self.onecmd(f"export {self._export_name()}")),
                Command("Produce Text File for Current Procedure",
                        lambda: self.onecmd(f"export --procedure {self._export_name()}"))]

    def _export_name(self) -> str:
        """Default export path for the palette: BINARY.asm.txt in the working directory."""
        name = self.ws.current.display_name if self.ws.current else "listing"
        return shlex.quote(f"{name}.asm.txt")

    def do_palette(self, arg):
        """palette QUERY [!N] — Search Anything: @symbols, "strings, #documents, otherwise commands.
        Append `!N` to execute result N."""
        query, bang, pick = arg.rpartition("!")
        if bang and pick.strip().isdigit():  # only a trailing `!N` picks; any other `!` is part of the query
            query = query.rstrip()
        else:
            query, pick = arg, ""
        self.palette.documents, self.palette.current_document = self.ws.documents, self.ws.current
        results = self.palette.search(query)
        if pick:
            index = int(pick)
            if index < len(results):
                outcome = self.palette.execute(results[index])
                if results[index].type.value in ("symbol", "string"):
                    self._report(outcome)
                elif results[index].type.value == "document":
                    self.ws.current = outcome
                    print(f"current document: {outcome.display_name}")
            return
        print(f"{self.palette.window_title}: {len(results)} results")
        for i, entry in enumerate(results[:30]):
            extra = f"  [{entry.shortcut}]" if entry.shortcut else ""
            at = f"  {format_address(entry.payload)}" if isinstance(entry.payload, int) else ""
            print(f"[{i:>3}] {_color(entry.display_title, CommandPalette.parse(query)[1])}{extra}{at}")

    # Go To ------------------------------------------------------------------------------

    def do_goto(self, arg):
        """goto ADDRESS|NAME — Go To Address or Symbol (also: g). `goto [N]` jumps to row N of the last list."""
        text = arg.strip()
        if text.startswith("[") and text.endswith("]"):
            index = int(text[1:-1])
            if not 0 <= index < len(self.last_list):
                raise ValueError(f"the last list has no row {index}")
            text = format_address(self.last_list[index])
        self._report(self.doc.goto(text, GotoType.ADDRESS), text)

    do_g = do_goto

    def do_offset(self, arg):
        """offset [--global] NUMBER — Go To File Offset (0x prefix or hex letters → hex, else decimal)."""
        words = arg.split()
        global_mode = "--global" in words
        words = [w for w in words if w != "--global"]
        self._report(self.doc.goto(" ".join(words), GotoType.GLOBAL_FILE_OFFSET if global_mode else GotoType.FILE_OFFSET))

    def do_procoff(self, arg):
        """procoff OFFSET — Go To Offset in Procedure."""
        self._report(self.doc.goto_offset_in_procedure(int(arg, 0)))

    def do_top(self, arg):
        """top — Go To Top of Procedure."""
        self._report(self.doc.goto_top_of_procedure())

    def do_follow(self, arg):
        """follow — Go To Address at Cursor."""
        self._report(self.doc.follow_address())

    def do_back(self, arg):
        """back — Go Back."""
        self._report(self.doc.go_back())

    def do_forward(self, arg):
        """forward — Go Forward."""
        self._report(self.doc.go_forward())

    def do_history(self, arg):
        """history — the navigation stack."""
        for address in reversed(self.doc.navigation.back):
            print(f"  {format_address(address)}  {self.doc.file.friendly_name_for_virtual_address(address)}")

    # lists and XREFs -----------------------------------------------------------------

    def do_segments(self, arg):
        """segments [FILTER] — Show Segment List."""
        self._show_address_list(segments_list(self.doc.file, self.doc.prefs), arg.strip())

    def do_sections(self, arg):
        """sections [FILTER] — Show Section List."""
        self._show_address_list(sections_list(self.doc.file, self.doc.prefs), arg.strip())

    def do_imports(self, arg):
        """imports [FILTER] — Imports window."""
        symbols = imports_window(self.doc.file, self.doc.prefs).search_field_changed(arg.strip())
        self._print_list([(s.address if s.address is not None else BAD_ADDRESS, f"{s.name}  {s.library}")
                          for s in symbols], arg.strip())

    def do_exports(self, arg):
        """exports [FILTER] — Exports window."""
        symbols = exports_window(self.doc.file, self.doc.prefs).search_field_changed(arg.strip())
        self._print_list([(s.address, s.name) for s in symbols], arg.strip())

    def do_refsto(self, arg):
        """refsto [ADDRESS] [/ FILTER] — References To Highlighted Word (or ADDRESS)."""
        target, _, pattern = arg.partition("/")
        if target.strip():
            address = parse_address_string(self.doc.file, target.strip())
            if address == BAD_ADDRESS:
                raise ValueError(f"invalid address {target.strip()}")
            lst = ListOfAddresses(self.doc.references_to_rows(address), f"References to {format_address(address)}",
                                  self.doc.prefs)
        else:
            lst = self.doc.show_references_to_here()
        self._show_address_list(lst, pattern.strip())

    def do_refsfrom(self, arg):
        """refsfrom [/ FILTER] — References From Highlighted Word."""
        self._show_address_list(self.doc.show_references_from_here(), arg.partition("/")[2].strip())

    def do_callers(self, arg):
        """callers [/ FILTER] — Show Places Calling This Procedure."""
        lst = self.doc.show_places_calling_this_procedure()
        if lst is None:
            print("\ano procedure here")
        else:
            self._show_address_list(lst, arg.partition("/")[2].strip())

    def do_objcrefs(self, arg):
        """objcrefs [/ FILTER] — Show Places Referencing This Objective-C Method."""
        lst = self.doc.show_references_to_objective_c_method()
        if lst is None:
            print(f"\a{self.doc.last_beep}")
        else:
            self._show_address_list(lst, arg.partition("/")[2].strip())

    def do_callees(self, arg):
        """callees — procedures called by the current procedure."""
        procedure = self.doc.current_procedure
        if procedure is None:
            print("\ano procedure here")
            return
        self._print_list([(a, self.doc.file.name_for_virtual_address(a) or "") for a in sorted(procedure.callees)])

    def do_nextxref(self, arg):
        """nextxref — Next XREF."""
        self._report(self.doc.move_to_next_xref())

    def do_prevxref(self, arg):
        """prevxref — Previous XREF."""
        self._report(self.doc.move_to_next_xref(backwards=True))

    # structural navigation ------------------------------------------------------------------

    def do_nextcode(self, arg):
        """nextcode — Next Code."""
        self._report(self.doc.next_code())

    def do_nextdata(self, arg):
        """nextdata — Next Data."""
        self._report(self.doc.next_data())

    def do_nextproc(self, arg):
        """nextproc — Next Procedure."""
        self._report(self.doc.next_procedure())

    def do_nextunexplored(self, arg):
        """nextunexplored — Next Unexplored."""
        self._report(self.doc.next_unexplored())

    def do_nextsection(self, arg):
        """nextsection — Next Section."""
        self._report(self.doc.next_section())

    def do_prevsection(self, arg):
        """prevsection — Previous Section."""
        self._report(self.doc.previous_section())

    # text find in a procedure listing ---------------------------------------------------------

    def do_textfind(self, arg):
        """textfind [--case] [--word] [--regex] TEXT — find bar over the current procedure's listing."""
        parser = _ArgumentParser(prog="textfind", add_help=False)
        parser.add_argument("--case", action="store_true")
        parser.add_argument("--word", action="store_true")
        parser.add_argument("--regex", action="store_true")
        parser.add_argument("text", nargs="+")
        args = parser.parse_args(_split(arg))
        procedure = self.doc.current_procedure
        if procedure is None:
            print("\ano procedure here")
            return
        lines = []
        for address in self.doc.file.procedure_object_addresses(procedure):
            lines += lines_for_virtual_address(self.doc.file, address)
        finder = TextFinder("\n".join(lines), case_sensitive=args.case, whole_word=args.word, regex=args.regex)
        matches = finder.find_all(" ".join(args.text))
        print(f"{len(matches)} matches")
        shown = sorted({finder.line_of(start) for start, _ in matches})
        for number in shown[:50]:
            print(f"{number:>5}: {lines[number - 1]}")

    # bookmarks, and annotations -----------------------------------------------------------------

    def do_bookmark(self, arg):
        """bookmark [NAME] — Toggle Bookmark at the cursor."""
        added = self.doc.toggle_bookmark(arg.strip())
        print("bookmark added" if added else "bookmark removed")

    def do_bookmarks(self, arg):
        """bookmarks [N | find NAME | rename NAME] — the Bookmarks menu; N jumps to bookmark N."""
        words = arg.split(maxsplit=1)
        if words and words[0].isdigit():
            self._report(self.doc.bookmark_clicked(int(words[0])))
        elif words and words[0] == "find":
            found = self.doc.file.find_bookmarks_named(words[1] if len(words) > 1 else "")
            self._print_list([(b.address, b.name) for b in found])
        elif words and words[0] == "rename":
            if len(words) < 2:
                raise ValueError("usage: bookmarks rename NAME")
            print("renamed" if self.doc.file.rename_bookmark(self.doc.cursor, words[1]) else "no bookmark here")
        else:
            for i, title in enumerate(self.doc.bookmarks_menu()):
                print(f"[{i}] {title}")

    def do_comment(self, arg):
        """comment TEXT — set the comment at the cursor (empty removes it)."""
        self.doc.file.set_comment(self.doc.cursor, arg)

    def do_inline(self, arg):
        """inline TEXT — set the inline comment at the cursor."""
        self.doc.file.set_inline_comment(self.doc.cursor, arg)

    def do_rename(self, arg):
        """rename NAME — name the cursor address."""
        self.doc.file.set_name(self.doc.cursor, arg.strip())

    def do_tag(self, arg):
        """tag NAME — tag the cursor address (or `tag -NAME` to remove)."""
        name = arg.strip()
        if not name.lstrip("-"):
            raise ValueError("usage: tag NAME | tag -NAME")
        if name.startswith("-"):
            self.doc.file.remove_tag(name[1:], self.doc.cursor)
        else:
            self.doc.file.add_tag(name, self.doc.cursor)
        print("tags here:", ", ".join(self.doc.file.tags_at(self.doc.cursor)) or "(none)")

    # Preferences / debugger -------------------------------------------------------------------------------

    def do_prefs(self, arg):
        """prefs [fuzzy on|off] [hexcolumn on|off] — show or change search preferences."""
        words = arg.split()
        for key, value in zip(words[::2], words[1::2]):
            field = {"fuzzy": "enable_fuzzy_search", "hexcolumn": "show_hex_column"}.get(key)
            if field:
                self.ws.prefs.update(**{field: value == "on"})
        p = self.ws.prefs
        print(f"fuzzy={p.enable_fuzzy_search} hexcolumn={p.show_hex_column} last_find_mode="
              f"{MODE_TITLES[FindMode(p.last_find_mode)]} case={p.last_find_case_sensitive} "
              f"wrap={p.last_find_wrapping} number={p.last_find_number_length}bit "
              f"{'LE' if p.last_find_number_little_endian else 'BE'} find_pasteboard={p.find_pasteboard!r}")

    def do_dbg(self, arg):
        """dbg complete TEXT | dbg load HEXBASE | dbg translate HEXADDR | dbg mem HEXADDR — debugger lookups."""
        words = arg.split(maxsplit=1)
        if not words:
            print(self.do_dbg.__doc__)
            return
        verb, rest = words[0], words[1] if len(words) > 1 else ""
        if verb == "complete":
            print("\n".join(self.debugger.completions(rest)) or "(none)")
        elif verb == "load":
            module = self.debugger.load_module(self.doc.file, int(rest, 16), self.doc.display_name)
            print(f"{module.name} loaded at {format_address(module.load_address)} (slide {module.slide:#x})")
        elif verb == "translate":
            address, document = self.debugger.translate_address_from_loaded_process(int(rest, 16))
            print("not in a loaded module" if document is None else
                  f"{format_address(address)} {document.friendly_name_for_virtual_address(address)}")
        elif verb == "mem":
            if self.debugger.set_memory_address(rest):
                print(self.debugger.refresh_memory().hex(" ") or "(unreadable)")
            else:
                print("invalid address")

    def do_quit(self, arg):
        """quit — exit."""
        return True

    do_exit = do_quit
    do_EOF = do_quit

    def emptyline(self) -> bool:
        return False


def _open(args) -> Workspace:
    workspace = Workspace(Preferences.load())
    document = workspace.open(args.binary, arch=args.arch, raw=args.raw, base=args.base)
    if document.database_warning:
        print(f"assemsearch: warning: {document.database_warning}", file=sys.stderr)
    return workspace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="assemsearch", description="Search the assembly of Mach-O and ELF binaries.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def binary_args(p):
        p.add_argument("binary")
        p.add_argument("--arch", help="slice of a fat Mach-O (arm64, x86_64)")
        p.add_argument("--raw", action="store_true", help="load as raw bytes")
        p.add_argument("--base", type=lambda s: int(s, 16), help="raw base address (hex)")

    p = sub.add_parser("open", help="interactive shell")
    binary_args(p)
    p.add_argument("-j", "--jump-to", help="hexadecimal address to move the cursor to")
    p.add_argument("-c", "--run", action="append", default=[], help="run a shell command and exit (repeatable)")

    p = sub.add_parser("find", help="list every occurrence of a pattern")
    binary_args(p)
    p.add_argument("text")
    p.add_argument("--mode", choices=MODE_NAMES, default="asm")
    p.add_argument("--case", action="store_true")
    p.add_argument("--bits", type=int, choices=(8, 16, 32, 64), default=32)
    p.add_argument("--big", action="store_true")
    p.add_argument("--limit", type=int, default=0, help="stop after N matches (default: all)")

    p = sub.add_parser("symbols", help="sidebar symbol search")
    binary_args(p)
    p.add_argument("pattern", nargs="?", default="")
    p.add_argument("--mode", choices=SIDEBAR_MODES, default="labels")
    p.add_argument("--tag", action="append", default=[])
    p.add_argument("--strict", action="store_true", help="disable fuzzy matching")

    p = sub.add_parser("goto", help="resolve an address, name or file offset")
    binary_args(p)
    p.add_argument("text")
    p.add_argument("--type", choices=("address", "offset", "global"), default="address")

    p = sub.add_parser("xrefs", help="references to an address or name")
    binary_args(p)
    p.add_argument("address")

    p = sub.add_parser("export", help="Produce Text File: write the listing to a file for offline grep")
    binary_args(p)
    p.add_argument("output")
    p.add_argument("--procedure", help="only the procedure containing this address or name")

    p = sub.add_parser("hexre", help="compile a hexadecimal regular expression and print its NFA as DOT")
    p.add_argument("pattern")

    p = sub.add_parser("mcp", help="run the MCP server on stdio")
    p.add_argument("binaries", nargs="*")
    p.add_argument("--arch")

    args, extra = parser.parse_known_args(argv)
    # Before Python 3.12, an optional positional after an option (`symbols BIN --mode proc chk`)
    # is left over instead of filling the pattern.
    if args.command == "symbols" and not args.pattern and len(extra) == 1 and not extra[0].startswith("-"):
        args.pattern = extra.pop()
    if extra:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")

    if args.command == "mcp":
        from assemsearch.mcp import serve
        try:
            serve(args.binaries, args.arch)
        except (OSError, ValueError) as error:
            print(f"assemsearch: {error}", file=sys.stderr)
            return 1
        return 0
    if args.command == "hexre":
        from assemsearch.hexregex import HexRegexError, parse_hex_regular_expression
        try:
            nfa = parse_hex_regular_expression(args.pattern)
        except HexRegexError as error:
            print(f"invalid hexadecimal regular expression: {error}", file=sys.stderr)
            return 1
        print(nfa.export_dot())
        print(f"// DFA states: {nfa.build_fast_recognizer().state_count}", file=sys.stderr)
        return 0

    try:
        workspace = _open(args)
    except (OSError, ValueError) as error:
        print(f"assemsearch: {error}", file=sys.stderr)
        return 1
    document = workspace.current
    if args.command == "open":
        shell = Shell(workspace)
        if args.jump_to:
            address = parse_hex_address(args.jump_to)  # hex only
            if not document.move_cursor_to_virtual_address(address):
                print(f"invalid --jump-to address {args.jump_to}", file=sys.stderr)
        if args.run:
            for line in args.run:
                print(f"{shell.prompt}{line}")
                if shell.onecmd(line):
                    break
            return 0
        shell.cmdloop()
        return 0
    if args.command == "find":
        try:
            context = FindContext.from_string(args.text, MODE_NAMES[args.mode], args.case, False, args.bits,
                                              not args.big)
        except FindInputError as error:
            print(error, file=sys.stderr)
            return 1
        hits = find_all(document, context, args.limit or None)
        for hit in hits:
            print(f"{format_address(hit.location)}  {document.file.friendly_name_for_virtual_address(hit.location)}")
        return 0 if hits else 1
    if args.command == "symbols":
        sidebar = Sidebar(document.file, Preferences(enable_fuzzy_search=not args.strict),
                          SIDEBAR_MODES[args.mode])
        if args.tag:
            sidebar.select_tags(*args.tag)
        for row in sidebar.update_search(args.pattern):
            print(f"{format_address(row.address)}  {row.score}  {_color(row.name, args.pattern)}")
        return 0
    if args.command == "goto":
        goto_type = {"address": GotoType.ADDRESS, "offset": GotoType.FILE_OFFSET,
                     "global": GotoType.GLOBAL_FILE_OFFSET}[args.type]
        try:
            ok = document.goto(args.text, goto_type)
        except GotoError as error:
            print(error, file=sys.stderr)
            return 1
        if not ok:
            print("invalid address", file=sys.stderr)
            return 1
        print(f"{format_address(document.cursor)}  {document.file.friendly_name_for_virtual_address(document.cursor)}")
        return 0
    if args.command == "xrefs":
        address = parse_address_string(document.file, args.address)
        if address == BAD_ADDRESS:
            print(f"invalid address {args.address}", file=sys.stderr)
            return 1
        for row in document.references_to_rows(address):
            print(f"{row['addressRepresentation']}  {row['comment']}")
        return 0
    if args.command == "export":
        try:
            if args.procedure and not document.goto(args.procedure):
                print(f"invalid address {args.procedure}", file=sys.stderr)
                return 1
            count = (document.produce_text_file_for_current_procedure(args.output) if args.procedure
                     else document.produce_text_file(args.output))
        except OSError as error:
            print(f"assemsearch: {error}", file=sys.stderr)
            return 1
        if count is None:
            print(f"no procedure at {args.procedure}", file=sys.stderr)
            return 1
        print(f"wrote {count} lines to {args.output}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

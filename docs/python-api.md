# Python API

`assemsearch.api` is a scripting API in the style of desktop disassemblers: `Document`,
`Segment`, `Section`, `Procedure` and `Tag` classes with camelCase methods
(`getAddressForName`, `getStringsList`, `setNameAtAddress`, …). Get a `Document` with
`Document.open` and read, name and comment the binary from Python.

```python
from assemsearch.api import Document

doc = Document.open("/bin/ls")                 # Mach-O, ELF or raw; analysed on load
doc = Document.open("App", arch="x86_64")      # one slice of a universal binary
doc = Document.open("fw.bin", raw=True, base=0x8000000)
```

`Document.open` also restores names and comments saved earlier (`restore=False` skips that).

Addresses are plain integers. Lookups that fail return `BAD_ADDRESS`
(`0xFFFFFFFFFFFFFFFF`, importable from `assemsearch.api`) or `None`.

## Example

```python
import re
from assemsearch.api import BAD_ADDRESS, TYPE_PROCEDURE, Document

doc = Document.open("tests/fixtures/sample_macho", arch="arm64")

# Strings that mention "license", and the procedures that use them
for segment in doc.getSegmentsList():
    for text, address in segment.getStringsList():
        if re.search("license", text, re.I):
            users = {doc.getProcedureAtAddress(ref).getEntryPoint()
                     for ref in doc.getReferencesOfAddress(address)}
            print(hex(address), repr(text), "used by", [doc.getNameAtAddress(e) for e in users])

# Every procedure in __TEXT, with what it calls
text = doc.getSegmentByName("__TEXT")
end = text.getStartingAddress() + text.getLength()
address = text.getNextAddressWithType(text.getStartingAddress(), TYPE_PROCEDURE)
while address != BAD_ADDRESS and address < end:
    proc = doc.getProcedureAtAddress(address)
    callees = [doc.getNameAtAddress(c.getEntryPoint()) for c in proc.getAllCalleeProcedures()]
    print(doc.getNameAtAddress(address), proc.getBasicBlockCount(), "blocks, calls", callees)
    address = text.getNextAddressWithType(address + 1, TYPE_PROCEDURE)

# Annotate, then keep the annotations
main = doc.getAddressForName("_main")
doc.setCommentAtAddress(main, "checks argv[1] as a licence key")
doc.setNameAtAddress(doc.getAddressForName("aInvalidLicense"), "kInvalidLicenseMessage")
doc.setBookmarkAtAddress(main, "start here")
doc.saveDatabase()                    # sample_macho.asdb, reopened by the shell too
```

Output:

```
0x1000006d7 'License OK: %u\n' used by ['_main']
0x1000006e7 'Invalid license' used by ['_main']
_compute_checksum 5 blocks, calls []
_validate_license 8 blocks, calls ['imp___stubs__strcmp']
_print_banner 1 blocks, calls []
_main 9 blocks, calls ['imp___stubs__printf', 'imp___stubs__puts', 'imp___stubs__strcmp']
...
```

## Reference

### `Document`

| Group | Methods |
|---|---|
| Open / save | `Document.open(path, restore=True, arch=None, raw=False, base=None)`, `saveDatabase(path=None)` (assemsearch addition) |
| Names | `getAddressForName(name)`, `getNameAtAddress(addr)`, `getDemangledNameAtAddress(addr)`, `setNameAtAddress(addr, name)`, `parseAddressString(text)` |
| Segments and sections | `getSegmentCount()`, `getSegment(index)`, `getSegmentsList()`, `getSegmentByName(name)`, `getSectionByName(name)`, `getSegmentAtAddress(addr)`, `getSegmentIndexAtAddress(addr)`, `getSectionAtAddress(addr)`, `getSectionIndexAtAddress(addr)` |
| Procedures | `getProcedureAtAddress(addr)`, `getProcedureIndexAtAddress(addr)` |
| File offsets | `getAddressFromFileOffset(offset)`, `getFileOffsetFromAddress(addr)` |
| Cursor and selection | `getCurrentAddress()`, `getCurrentProcedure()`, `getHighlightedWord()`, `getSelectionAddressRange()`, `moveCursorAtAddress(addr)`, `moveCursorAtEntryPoint()`, `selectAddressRange(range)`, `gotoVirtualAddressString(text)` |
| Comments | `getCommentAtAddress(addr)`, `getInlineCommentAtAddress(addr)`, `setCommentAtAddress(addr, text)`, `setInlineCommentAtAddress(addr, text)` |
| Tags | `getTagWithName(name)`, `buildTag(name)`, `addTagAtAddress(tag, addr)`, `hasTagAtAddress(tag, addr)`, `getTagListAtAddress(addr)` |
| Bookmarks | `getBookmarks()`, `hasBookmarkAtAddress(addr)`, `getBookmarkName(addr)`, `setBookmarkAtAddress(addr, name="")`, `removeBookmarkAtAddress(addr)`, `findBookmarkWithName(name)` |
| References | `getReferencesOfAddress(addr)` (who refers to `addr`), `getReferencesFromAddress(addr)` (what `addr` refers to) |

### `Segment`

`getName()`, `getStartingAddress()`, `getLength()`, `getSectionsList()`,
`getLabelCount()`, `labelIterator()`, `getLabelsList()`, `getNamedAddresses()`,
`getNameAtAddress(addr)`, `getDemangledNameAtAddress(addr)`,
`getStringCount()`, `getStringAtIndex(i)`, `getStringAddressAtIndex(i)`,
`getStringsList()` (a list of `(text, address)`),
`getNextAddressWithType(addr, type)`, `getTypeAtAddress(addr)`,
`getReferencesOfAddress(addr)`, `getReferencesFromAddress(addr)`,
`getProcedureAtAddress(addr)`, `getProcedureIndexAtAddress(addr)`,
`getCommentAtAddress(addr)`, `getInlineCommentAtAddress(addr)`.

Type constants for `getNextAddressWithType` / `getTypeAtAddress`: `TYPE_UNDEFINED`,
`TYPE_CODE`, `TYPE_PROCEDURE`, `TYPE_ASCII`, `TYPE_DATA`.

### `Section`

`getName()`, `getStartingAddress()`, `getLength()`.

### `Procedure`

`getEntryPoint()`, `getBasicBlockCount()`, `getBasicBlockAtAddress(addr)` (a
`(start, end)` pair), `getAllCallerProcedures()`, `getAllCalleeProcedures()`,
`localLabelAtAddress(addr)`, `addressOfLocalLabel(label)`, `hasTag(tag)`.

A procedure has no name of its own: use
`doc.getNameAtAddress(proc.getEntryPoint())`.

### `Tag`

`getName()`.

## Searching from a script

`assemsearch.api` has no search call of its own; scripts filter
`getStringsList()` and `getLabelsList()` themselves, as in the example. For the Find dialog's
modes (bytes, hex regular expressions, numbers, listing text), use the lower-level classes
the shell is built on:

```python
from assemsearch.cli import find_all
from assemsearch.find import FindContext, FindMode
from assemsearch.preferences import Preferences
from assemsearch.workspace import Workspace

document = Workspace(Preferences.in_memory()).open("/bin/ls")
context = FindContext.from_string("fd7b..a9", FindMode.HEX_REGEXP)
for hit in find_all(document, context):
    print(hex(hit.location), document.file.friendly_name_for_virtual_address(hit.location))
```

## What is not in the API

* `Document.getCurrentDocument()`, UI calls (`message`, `ask…`), and anything
  about the decompiler or the debugger.
* Writing bytes or changing types (`setTypeAtAddress`, `writeByte`, …). assemsearch reads
  binaries; it does not patch them.

# Installation

Every method below gives you a `assemsearch` command. Check it with `assemsearch --version`.

## Requirements

* macOS or Linux.
* For the install script or the wheel: Python 3.10 or newer. The only dependency,
  [Capstone](https://www.capstone-engine.org/) (the disassembler engine), is installed
  automatically.
* For the standalone executable: nothing. Python and Capstone are bundled into it.

## Option 1: install script (recommended)

```sh
git clone https://github.com/thinh-ngyuen15/assemsearch.git && cd assemsearch
./install.sh
```

The script picks the first installer it finds:

1. **uv** (`uv tool install`). Installs into its own isolated environment.
2. **pipx** (`pipx install`). Same idea.
3. **pip** (`python3 -m pip install --user`). Last resort; shares your user site-packages.

Running it again upgrades in place. When it finishes it prints where the command went and
warns you if that folder is not on your `PATH`. With uv, `uv tool update-shell` adds it.

Or install straight from GitHub without cloning:

```sh
uv tool install git+https://github.com/thinh-ngyuen15/assemsearch.git
# or
pipx install git+https://github.com/thinh-ngyuen15/assemsearch.git
```

## Option 2: install the wheel

Each [release](https://github.com/thinh-ngyuen15/assemsearch/releases) has a wheel
(`assemsearch-X.Y.Z-py3-none-any.whl`). It contains no compiled code, so it works on any
platform with Python 3.10+:

```sh
uv tool install assemsearch-0.1.0-py3-none-any.whl
# or
pipx install assemsearch-0.1.0-py3-none-any.whl
# or, into the current virtual environment
pip install assemsearch-0.1.0-py3-none-any.whl
```

`uv build` makes the same wheel in `dist/` from a clone.

## Option 3: standalone executable

Each [release](https://github.com/thinh-ngyuen15/assemsearch/releases) has standalone
executables: single ~11 MB files that need no Python.

| File | Runs on |
|---|---|
| `assemsearch-macos-arm64` | Apple Silicon Macs |
| `assemsearch-linux-x86_64` | 64-bit Intel/AMD Linux |

Download the one for your machine, then:

```sh
chmod +x assemsearch-macos-arm64
mv assemsearch-macos-arm64 /usr/local/bin/assemsearch      # or anywhere on your PATH
```

Its limits:

* **Platform.** It only runs on the OS and CPU it was built on. For other machines
  (Intel Macs, ARM Linux), build one there (see below).
* **Quarantine.** macOS blocks an executable that was downloaded or received from someone
  else. Clear the flag once:

  ```sh
  xattr -d com.apple.quarantine /usr/local/bin/assemsearch
  ```

* **Startup.** The first run unpacks itself to a temporary folder, so it starts a little
  slower than an installed wheel (about 0.2 s).

## Running without installing

From the `assemsearch` folder, with [uv](https://docs.astral.sh/uv/):

```sh
uv run assemsearch open /bin/ls
```

Or with any Python that has the package installed: `python -m assemsearch ...`.

## Uninstalling

```sh
./install.sh --uninstall          # whichever installer was used
uv tool uninstall assemsearch       # or directly
pipx uninstall assemsearch
rm /usr/local/bin/assemsearch       # standalone executable
```

assemsearch also leaves these files behind; delete them if you want a clean slate:

| File | What it is |
|---|---|
| `~/.config/assemsearch/preferences.json` | Search options, the Find pasteboard, recent searches (`ASSEMSEARCH_PREFS` overrides the path) |
| `BINARY.asdb` next to a binary | Names, comments, tags and bookmarks you saved with `save` |
| `~/.local/share/assemsearch/*.asdb` | The same, for binaries in folders you cannot write to (`$XDG_DATA_HOME/assemsearch/` if set) |

## Rebuilding the packages

```sh
uv build                    # dist/assemsearch-X.Y.Z-py3-none-any.whl and .tar.gz
tools/build_binary.sh       # dist/assemsearch standalone executable for this machine
```

`build_binary.sh` uses PyInstaller (fetched on the fly by `uv run --with pyinstaller`) and
bundles Capstone's native library. The version number lives in
`src/assemsearch/__init__.py`; change it there before building a release.

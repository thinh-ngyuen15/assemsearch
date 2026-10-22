#!/bin/sh
# Build a standalone `assemsearch` executable (no Python needed to run it) into dist/.
# It runs on the OS and CPU it was built on: build on an arm64 Mac for arm64 Macs, etc.
set -eu
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
uv run --with pyinstaller pyinstaller --onefile --noconfirm --name assemsearch \
    --collect-all capstone --distpath dist --workpath "$work/build" --specpath "$work" \
    src/assemsearch/__main__.py
echo "Built dist/assemsearch ($(uname -s) $(uname -m)): $(dist/assemsearch --version)"

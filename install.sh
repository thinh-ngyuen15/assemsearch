#!/bin/sh
# Install the `assemsearch` command into its own isolated environment.
#
#   ./install.sh              install (or upgrade) from this folder
#   ./install.sh --uninstall  remove it
#
# Uses uv if present, then pipx, then `pip install --user` as a last resort.
set -eu

here=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = "--uninstall" ]; then
    if command -v uv >/dev/null 2>&1 && uv tool list 2>/dev/null | grep -q '^assemsearch '; then
        uv tool uninstall assemsearch
    elif command -v pipx >/dev/null 2>&1 && pipx list --short 2>/dev/null | grep -q '^assemsearch '; then
        pipx uninstall assemsearch
    else
        python3 -m pip uninstall -y assemsearch
    fi
    exit 0
fi

if command -v uv >/dev/null 2>&1; then
    uv tool install --force --reinstall "$here"
    bin_dir=$(uv tool dir --bin)
elif command -v pipx >/dev/null 2>&1; then
    pipx install --force "$here"
    bin_dir=$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")
else
    python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
        echo "assemsearch needs Python 3.10 or newer (or install uv: https://docs.astral.sh/uv/)" >&2
        exit 1
    }
    python3 -m pip install --user --upgrade "$here"
    bin_dir=$(python3 -c 'import sysconfig; print(sysconfig.get_path("scripts", f"{__import__("os").name}_user"))')
fi

echo
echo "Installed: $("$bin_dir/assemsearch" --version) -> $bin_dir/assemsearch"
case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) echo "Add $bin_dir to your PATH to run \`assemsearch\` from anywhere." ;;
esac

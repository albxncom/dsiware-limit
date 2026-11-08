#!/bin/sh
# Emulator tests of the System Settings target. Called by the top-level test.sh.
# Usage: sh test.sh STOCK.dec.code PATCHED.code IPS N
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
echo "== test_settings.py"
uv run --quiet --no-project --with unicorn --with capstone -- python -I "$HERE/tests/test_settings.py" "$1" "$2" "$4"

#!/bin/sh
# Emulator tests of the NS target. Called by the top-level test.sh.
# Usage: sh test.sh STOCK.dec.code PATCHED.code IPS N
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
echo "== test_list256.py"
uv run --quiet --no-project --with unicorn --with capstone -- python -I "$HERE/tests/test_list256.py" --code "$1" --ips "$3"

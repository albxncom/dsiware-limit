#!/bin/sh
# Emulator tests of the HOME Menu target. Called by the top-level test.sh.
# Usage: sh test.sh STOCK.dec.code PATCHED.code IPS N
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
STOCK=$1 PATCHED=$2
failed=""
t() {
  name=$1
  shift
  echo "== $name"
  uv run --quiet --no-project --with unicorn --with capstone -- python -I "$HERE/tests/$name" "$@" || failed="$failed $name"
}
t test_popcnt.py "$STOCK" "$PATCHED"
t test_bitfield.py "$STOCK" "$PATCHED"
t test_mapping.py "$STOCK"
t test_amguard.py "$STOCK"
t test_chain_a.py "$STOCK" "$PATCHED"
t test_guards_a.py "$STOCK" "$PATCHED"
t test_walker.py "$STOCK"

[ -z "$failed" ] || { echo "FAILED:$failed"; exit 1; }

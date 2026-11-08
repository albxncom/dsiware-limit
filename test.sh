#!/bin/sh
# Build N = 256 from the dumps, then run the emulator tests of every target that matched a dump
# (targets/<role>/<build>/test.sh STOCK PATCHED IPS N). Needs uv (fetches unicorn and capstone).
# Usage: sh test.sh DUMPS_DIR
set -u
REPO=$(cd "$(dirname "$0")" && pwd)
DUMPS=$(cd "${1:?usage: sh test.sh DUMPS_DIR}" && pwd)
N=256
OUT=$REPO/out/max-$N
rm -f "$OUT/manifest.tsv"
failed=""
python3 -I "$REPO/dsiware-limit.py" --max $N --dumps "$DUMPS" --out "$OUT" || failed=" build"
[ -f "$OUT/manifest.tsv" ] || exit 1

TAB=$(printf '\t')
while IFS=$TAB read -r tid role target dump patched ips; do
  echo "=== $tid ($role): ${target#"$REPO"/}"
  if [ -f "$target/test.sh" ]; then
    sh "$target/test.sh" "$dump" "$patched" "$ips" $N || failed="$failed $tid"
  else
    echo "no test.sh"
  fi
done < "$OUT/manifest.tsv"

if [ -n "$failed" ]; then
  echo "FAILED:$failed"
  exit 1
fi
echo "all tests OK"

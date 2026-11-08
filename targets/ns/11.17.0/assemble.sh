#!/bin/sh
# Reassemble caves/cave256.S with devkitARM and compare it with the committed caves/cave256.bin.
# Exits non-zero on a difference. Needs docker; writes only to out/asm/<role>-<build>/ at the repo root.
# Usage: sh assemble.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
ASM=$REPO/out/asm/$(basename "$(dirname "$HERE")")-$(basename "$HERE")
rm -rf "$ASM"
mkdir -p "$ASM"

docker run --rm --network none --platform linux/amd64 -v "$HERE/caves":/c:ro -v "$ASM":/a -w /c devkitpro/devkitarm:latest sh -euc '
P=/opt/devkitpro/devkitARM/bin/arm-none-eabi-
${P}as -march=armv6k -o /a/cave256.o cave256.S
${P}ld -Ttext=0x11fa40 -e cave -o /a/cave256.elf /a/cave256.o
${P}objcopy -O binary -j .text /a/cave256.elf /a/cave256.bin
'

if cmp -s "$ASM/cave256.bin" "$HERE/caves/cave256.bin"; then
  echo "same  caves/cave256.bin"
  echo "RESULT: OK"
else
  echo "DIFFERS  caves/cave256.bin"
  echo "RESULT: 1 DIFFERENCES"
  exit 1
fi

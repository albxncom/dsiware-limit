#!/bin/sh
# Assemble caves/shift.S with devkitARM for several N and compare it with the loops target.py generates
# (shift_loop). Exits non-zero on any difference. Needs docker; writes only to out/asm/<role>-<build>/ at the
# repo root.
# Usage: sh assemble.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
ASM=$REPO/out/asm/$(basename "$(dirname "$HERE")")-$(basename "$HERE")
rm -rf "$ASM"
mkdir -p "$ASM"

docker run --rm --network none --platform linux/amd64 -v "$HERE/caves":/c:ro -v "$ASM":/a -w /c devkitpro/devkitarm:latest sh -euc '
P=/opt/devkitpro/devkitARM/bin/arm-none-eabi-
for n in 2 47 130 256; do
  ${P}as -march=armv6k --defsym LAST8=$(( (n - 2) * 8 )) -o /a/shift-$n.o shift.S
  ${P}objcopy -O binary -j .text.a /a/shift-$n.o /a/shift-$n.a.bin
  ${P}objcopy -O binary -j .text.c /a/shift-$n.o /a/shift-$n.c.bin
done
'

python3 -I -B - "$REPO" "$HERE" "$ASM" <<'EOF'
import importlib.util, sys
from pathlib import Path
repo, here, asm = (Path(a) for a in sys.argv[1:])
sys.path.insert(0, str(repo))
spec = importlib.util.spec_from_file_location("target", here / "target.py")
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
fails = 0
for n in (2, 47, 130, 256):
    for sect, reg, body in (("a", 1, target.SHIFT_A), ("c", 0, target.SHIFT_C)):
        got = (asm / f"shift-{n}.{sect}.bin").read_bytes()
        ok = target.shift_loop(reg, n, body)[:len(got)] == got
        fails += not ok
        print(f"{'same' if ok else 'DIFFERS'}  caves/shift.S shift_{sect} N={n} == shift_loop()")
print("RESULT:", "OK" if not fails else f"{fails} DIFFERENCES")
sys.exit(1 if fails else 0)
EOF

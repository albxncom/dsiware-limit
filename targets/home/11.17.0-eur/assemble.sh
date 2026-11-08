#!/bin/sh
# Reassemble the caves of this target from caves/*.S with devkitARM and compare them with the committed
# caves/*.bin (byte for byte) and caves/*.syms (symbol offsets the records in target.py branch to).
# Exits non-zero on any difference. Needs docker; writes only to out/asm/<role>-<build>/ at the repo root.
# When porting, copy the fresh .bin and .syms files from there into caves/ once the sources are right, and
# rerun until everything says "same".
# Usage: sh assemble.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
ASM=$REPO/out/asm/$(basename "$(dirname "$HERE")")-$(basename "$HERE")
rm -rf "$ASM"
mkdir -p "$ASM"

docker run --rm --network none --platform linux/amd64 -v "$HERE/caves":/c:ro -v "$ASM":/a -w /c devkitpro/devkitarm:latest sh -euc '
P=/opt/devkitpro/devkitARM/bin/arm-none-eabi-
# cave name (= source name), assembler flags, link address, ld/objcopy extras
build() {
  name=$1 asflags=$2 ttext=$3 ldflags=$4 ocflags=$5
  ${P}as -march=armv6k $asflags -o /a/$name.o $name.S
  ${P}ld -Ttext=$ttext $ldflags -o /a/$name.elf /a/$name.o
  ${P}objcopy -O binary $ocflags /a/$name.elf /a/$name.bin
  ${P}nm /a/$name.elf > /a/$name.nm
}
build popcnt   ""                  0x1ad84c "--defsym ENSURE_LISTS=0x21e9d8 --defsym BITFIELD=0x34d2c0 --defsym STATE=0x32eda4" ""
build leak     ""                  0x305740 ""             "-j .text"
build guards   ""                  0x305760 ""             "-j .text"
build bitfield ""                  0x305b00 "-e clr_tail"  "-j .text"
build mapping  "-mfpu=vfp"         0x305610 "-e cave"      ""
build amguard  "-mfloat-abi=soft"  0x3058c0 ""             ""
'

python3 -I -B - "$HERE/caves" "$ASM" <<'EOF'
import json, sys
from pathlib import Path
caves, asm = Path(sys.argv[1]), Path(sys.argv[2])
fails = 0


def check(label, ok):
    global fails
    fails += not ok
    print(f"{'same' if ok else 'DIFFERS'}  {label}")


def nm(name):
    return {f[2]: int(f[0], 16) for f in (l.split() for l in open(asm / f"{name}.nm")) if len(f) == 3}


for name in ("popcnt", "leak", "guards", "bitfield", "mapping", "amguard"):
    check(f"caves/{name}.bin", (asm / f"{name}.bin").read_bytes() == (caves / f"{name}.bin").read_bytes())

for name, base in (("guards", 0x305760), ("bitfield", 0x305B00), ("amguard", 0x3058C0)):
    committed = json.loads((caves / f"{name}.syms").read_text())
    sym = nm(name)
    fresh = {k: sym[k] - base for k in committed}
    (asm / f"{name}.syms").write_text(json.dumps(fresh))
    check(f"caves/{name}.syms", committed == fresh)

print("RESULT:", "OK" if not fails else f"{fails} DIFFERENCES")
sys.exit(1 if fails else 0)
EOF

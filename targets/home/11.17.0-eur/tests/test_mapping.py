"""Emulator check of the packed-mapping cave (mapping_records() of target.py) against the HOME code dump, no Python hook.
Runs the real upload 0x24dc74 (kind 2) and the real lookup 0x207c20 in unicorn on the dump with those records
applied, and next to it the unpatched dump as the stock reference. Checks:
- every record's "old" matches the dump, and the patched image differs from stock only inside the records;
- the cave stays below 0x305700 and branches only inside itself or back to 0x207dbc;
- slots 0..383: the icon lands in exactly the 4x4 tiles of cell (texture s>>6, row (s>>3)&7, column s&7),
  no two slots overlap, nothing outside the stack and those tiles is written, the flush is (v, 0x20000), and a
  sampler reading frame 0 (32x32 texels at v 32*cell..) relative to the returned phys address returns the icon;
- lookup kinds 1/2 for slots 0..383 equal the reference mapping (all 10 output words, r0 = out+32);
- slots -1..-9 (kinds 1/2) and kinds 0/3/4/5 equal stock; a NULL texture entry gets no column offset.
Usage: uv run --no-project --with unicorn --with capstone -- python -I targets/home/11.17.0-eur/tests/test_mapping.py dumps/0004003000009802.dec.code
"""
import importlib.util
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP, \
    UC_ARM_REG_LR, UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC


def load_target():
    """This target's target.py (which imports patchkit from the repo root)."""
    here = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(here.parents[2]))
    spec = importlib.util.spec_from_file_location("target", here / "target.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


stock_code = open(sys.argv[1], "rb").read()
records = [{"addr": hex(a), "old": old.hex(), "new": new.hex()}
           for a, old, new in load_target().mapping_records(stock_code)]
BASE = 0x100000
TABLE = 0x3664AC
TEX0 = 0x20000000
STACK = 0x0E000000
OUT = STACK - 0x2000
SRC = 0x30000000
RET = 0x00FF0000
CAVE, CAVE_LIMIT, BACK = 0x305610, 0x305700, 0x207DBC

fails = 0


def fail(msg):
    global fails
    fails += 1
    print(msg)


patched = bytearray(stock_code)
changed = set()
for r in records:
    a, old, new = int(r["addr"], 16), bytes.fromhex(r["old"]), bytes.fromhex(r["new"])
    if len(old) != len(new) or stock_code[a - BASE:a - BASE + len(old)] != old:
        fail(f"record {r['addr']}: old does not match the dump")
    patched[a - BASE:a - BASE + len(new)] = new
    changed.update(range(a, a + len(new)))
diff = {BASE + i for i in range(len(stock_code)) if stock_code[i] != patched[i]}
if not diff <= changed:
    fail(f"patched image differs outside the records at {min(diff - changed):#x}")

cave_rec = next(r for r in records if int(r["addr"], 16) == CAVE)
cave = bytes.fromhex(cave_rec["new"])
if CAVE + len(cave) > CAVE_LIMIT:
    fail(f"cave ends at {CAVE + len(cave):#x}, past {CAVE_LIMIT:#x}")
for ins in Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(cave, CAVE):
    if ins.mnemonic.startswith("b") and ins.op_str.startswith("#"):
        t = int(ins.op_str[1:], 16)
        if not (CAVE <= t < CAVE + len(cave) or t == BACK):
            fail(f"cave branch at {ins.address:#x} to {t:#x}")


class Emu:
    def __init__(self, code):
        mu = self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mu.reg_write(UC_ARM_REG_C1_C0_2, mu.reg_read(UC_ARM_REG_C1_C0_2) | (0xF << 20))
        mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        mu.mem_map(BASE, 0x390000 - BASE)  # code+data from the dump, bss zero
        mu.mem_write(BASE, bytes(code))
        mu.mem_map(TEX0, 8 * 0x20000)
        mu.mem_map(STACK - 0x10000, 0x10000)
        mu.mem_map(SRC, 0x2000)
        mu.mem_map(RET, 0x1000)
        mu.mem_write(RET, struct.pack("<I", 0xE1A00000))
        mu.mem_write(0x14B9B8, struct.pack("<I", 0xE12FFF1E))  # flush stub: bx lr (args recorded in hook)
        for i in range(6):  # TWL table: v, p (fake phys = v), w/h, fmt
            mu.mem_write(TABLE + 16 * i, struct.pack("<IIHHHH", TEX0 + i * 0x20000, TEX0 + i * 0x20000, 256, 256, 0x8363, 0))
        self.flushes, self.writes = [], []
        mu.hook_add(UC_HOOK_CODE, lambda uc, *_: self.flushes.append((uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1))),
                    begin=0x14B9B8, end=0x14B9B8)
        mu.hook_add(UC_HOOK_MEM_WRITE, lambda uc, acc, addr, size, *_: self.writes.append((addr, size)))

    def call(self, fn, *args):
        for r, a in zip([UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3], args):
            self.mu.reg_write(r, a & 0xFFFFFFFF)
        self.mu.reg_write(UC_ARM_REG_SP, STACK - 0x100)
        self.mu.reg_write(UC_ARM_REG_LR, RET)
        self.mu.emu_start(fn, RET)

    def lookup(self, kind, slot):
        self.mu.mem_write(OUT, b"\xAA" * 48)
        self.call(0x207C20, OUT, kind, slot)
        return struct.unpack("<8I2i", self.mu.mem_read(OUT, 40)), self.mu.reg_read(UC_ARM_REG_R0)


stock, emu = Emu(stock_code), Emu(patched)


def reference(slot):  # the mapping test_pack.py applied as a Python hook, for 0 <= slot < 384
    v, p, wh, fmt = struct.unpack("<IIII", emu.mu.mem_read(TABLE + 16 * (slot >> 6), 16))
    col, row = slot & 7, (slot >> 3) & 7
    if v:
        v, p = v + col * 0x200, p + col * 0x200
    return (v, p, wh, fmt, v, p, wh, fmt, row, row), OUT + 32


def morton(x, y):  # PICA200 8x8 tile, Z-order inside
    m = 0
    for i in range(3):
        m |= ((x >> i) & 1) << (2 * i) | ((y >> i) & 1) << (2 * i + 1)
    return m


def sample(base, x, y):  # RGB565 texel of a 256-wide tiled texture at base
    off = ((y >> 3) * 32 + (x >> 3)) * 128 + morton(x & 7, y & 7) * 2
    return struct.unpack("<H", emu.mu.mem_read(base + off, 2))[0]


owner = {}
max_flush_end = 0
for s in range(384):
    # source: B buffer layout, static icon at +0x480 is 32x32 tiled (4 tile rows of 0x200)
    icon = bytes(((s * 7 + i) & 0xFF) for i in range(0x800))
    emu.mu.mem_write(SRC + 0x480, icon)
    emu.writes.clear()
    emu.flushes.clear()
    emu.call(0x24DC74, 2, s, SRC)
    tex, row, col = s >> 6, (s >> 3) & 7, s & 7
    tbase = TEX0 + tex * 0x20000
    exp = set()
    for tr in range(4):
        for tc in range(4):
            t = tbase + ((row * 4 + tr) * 32 + col * 4 + tc) * 128
            exp.update(range(t, t + 128))
    got = set()
    for a, n in emu.writes:
        if STACK - 0x10000 <= a < STACK:
            continue
        got.update(range(a, a + n))
    if got != exp:
        fail(f"slot {s}: wrote {len(got)} bytes, expected {len(exp)}; outside {len(got - exp)}")
    for b in got:
        if b in owner:
            fail(f"slot {s} overlaps slot {owner[b]} at {b:#x}")
            break
        owner[b] = s
    t, r0 = emu.lookup(2, s)
    p, cell = t[1], t[8]
    src_img = [[0] * 32 for _ in range(32)]
    for tr in range(4):  # decode source the same way (it is already tiled, 4 tiles per tile row)
        for x in range(32):
            for y in range(8):
                off = tr * 0x200 + (x >> 3) * 128 + morton(x & 7, y) * 2
                src_img[tr * 8 + y][x] = struct.unpack_from("<H", icon, off)[0]
    bad = sum(1 for y in range(32) for x in range(32) if sample(p, x, 32 * cell + y) != src_img[y][x])
    if bad:
        fail(f"slot {s}: sampler mismatch in {bad} texels")
    if len(emu.flushes) != 1 or emu.flushes[0] != (t[0], 0x20000):
        fail(f"slot {s}: flushes {[(hex(a), hex(n)) for a, n in emu.flushes]}")
    max_flush_end = max(max_flush_end, *(a + n for a, n in emu.flushes))
    for kind in (1, 2):
        if emu.lookup(kind, s) != reference(s):
            fail(f"kind {kind} slot {s}: {emu.lookup(kind, s)} != reference {reference(s)}")
print(f"max flush overrun past the last texture: {max_flush_end - (TEX0 + 6 * 0x20000):#x} bytes (mapped heap in practice)")

for kind in (1, 2):
    for s in range(-9, 0):
        if emu.lookup(kind, s) != stock.lookup(kind, s):
            fail(f"kind {kind} slot {s}: {emu.lookup(kind, s)} != stock {stock.lookup(kind, s)}")
for kind in (0, 3, 4, 5):
    for s in range(-1, 400):
        if emu.lookup(kind, s) != stock.lookup(kind, s):
            fail(f"kind {kind} slot {s} differs from stock")

saved = emu.mu.mem_read(TABLE, 16)
emu.mu.mem_write(TABLE, bytes(16))
t, _ = emu.lookup(2, 5)
if t[0] or t[1]:
    fail("NULL texture got an offset")
emu.mu.mem_write(TABLE, bytes(saved))

t, _ = emu.lookup(2, -1)
print(f"slot -1 -> v {t[0]:#x} cell {t[8]} (stock: v {stock.lookup(2, -1)[0][0]:#x} cell {stock.lookup(2, -1)[0][8]})")
print(f"cave {len(cave):#x} bytes at {CAVE:#x}")
print("FAIL" if fails else "OK", f"({fails} failures, 384 slots)")
sys.exit(1 if fails else 0)

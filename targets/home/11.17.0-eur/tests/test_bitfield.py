"""Emulator test of option A's slot bitfield (0x33c624 -> 0x34d2e0, 12 words) on the real HOME Menu code.

Usage: uv run --no-project --with unicorn --with capstone -- python -I targets/home/11.17.0-eur/tests/test_bitfield.py STOCK.dec.code PATCHED.code
Runs stock and patched side by side:
  1. allocator 0x2030ac, kinds 1 and 2, from empty: patched hands out 1..383 in order, then -1; every bit lands in
     the new bitfield; the old words 0x33c624/0x33c628 and the kind-3 bitfield are never written. Stock hands out
     1..40 then -1 (its cap), so the first 40 results match.
  2. slot 0 path (r1 != 0) returns 0 and writes nothing, as stock.
  3. free 0x20069c (kinds 1 and 2) clears exactly the slot's bit in the new bitfield, for slots 1, 31, 32, 200, 383.
  4. reset 0x24df38, clear-all 0x2f39e4 and the texture-creation tail (from 0x24dad0) clear all 12 new words and
     write everything else exactly as stock does (stock's writes to 0x33c624/0x33c628 map to the new words).
"""
import struct
import sys

from unicorn import UC_ARCH_ARM, UC_HOOK_MEM_WRITE, UC_MODE_ARM, Uc
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_SL, UC_ARM_REG_SP

BASE, MEM_END = 0x100000, 0x390000
OLD_BF, NEW_BF, KIND3 = 0x33C624, 0x34D2E0, 0x33C62C
ALLOCATOR, FREE_SLOT, RESET_FN, CLEAR_ALL, CREATE_TAIL = 0x2030AC, 0x20069C, 0x24DF38, 0x2F39E4, 0x24DAD0
STACK, RET = 0x0FFF0000, 0xDEAD0000
FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("FAIL", msg)


class Env:
    def __init__(self, image):
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mu.mem_map(BASE, MEM_END - BASE)
        mu.mem_write(BASE, image)
        mu.mem_map(STACK, 0x10000)
        mu.mem_map(RET & ~0xFFF, 0x1000)
        self.mu, self.writes = mu, []
        mu.hook_add(UC_HOOK_MEM_WRITE, lambda uc, acc, addr, size, val, d: self.writes.append((addr, size)),
                    begin=0x300000, end=MEM_END)

    def w32(self, addr, *vals):
        self.mu.mem_write(addr, b"".join(struct.pack("<I", v) for v in vals))

    def r32(self, addr, count=1):
        return list(struct.unpack(f"<{count}I", self.mu.mem_read(addr, 4 * count)))

    def call(self, pc, *args):
        mu = self.mu
        mu.reg_write(UC_ARM_REG_SP, STACK + 0x8000)
        mu.reg_write(UC_ARM_REG_LR, RET)
        for i, a in enumerate(args):
            mu.reg_write(UC_ARM_REG_R0 + i, a & 0xFFFFFFFF)
        mu.emu_start(pc, RET, count=200000)
        check(mu.reg_read(UC_ARM_REG_PC) == RET, f"did not return from {pc:#x}")
        check(mu.reg_read(UC_ARM_REG_SP) == STACK + 0x8000, f"stack unbalanced after {pc:#x}")
        return mu.reg_read(UC_ARM_REG_R0)

    def written(self):
        out = set()
        for a, size in self.writes:
            out |= {a + k for k in range(size)}
        self.writes = []
        return out


def main():
    stock, patched = (open(p, "rb").read() for p in sys.argv[1:3])
    new_words = {NEW_BF + k for k in range(48)}
    old_words = {OLD_BF + k for k in range(8)}

    # 1. allocator from empty, kinds 1 and 2
    for kind in (1, 2):
        s, p = Env(stock), Env(patched)
        got_s, got_p = [], []
        for _ in range(400):
            got_p.append(p.call(ALLOCATOR, kind, 0, 0))
            if got_p[-1] == 0xFFFFFFFF:
                break
        for _ in range(60):
            got_s.append(s.call(ALLOCATOR, kind, 0, 0))
            if got_s[-1] == 0xFFFFFFFF:
                break
        check(got_p == list(range(1, 384)) + [0xFFFFFFFF], f"kind {kind}: patched handed out {got_p[:3]}..{got_p[-3:]} ({len(got_p)})")
        check(got_s == list(range(1, 41)) + [0xFFFFFFFF], f"kind {kind}: stock handed out {got_s[:3]}..{got_s[-3:]}")
        bf = p.r32(NEW_BF, 12)
        check(bf == [0xFFFFFFFE] + [0xFFFFFFFF] * 11, f"kind {kind}: new bitfield {[hex(x) for x in bf]}")
        w = p.written()
        check(w <= new_words, f"kind {kind}: writes outside the new bitfield: {sorted(hex(a) for a in w - new_words)[:8]}")
        check(not (w & old_words) and p.r32(OLD_BF, 3) == [0, 0, 0], f"kind {kind}: old or kind-3 bitfield touched")

    # 2. slot 0 path
    p = Env(patched)
    check(p.call(ALLOCATOR, 1, 1, 0) == 0 and not p.written(), "slot 0 path changed")

    # 3. free
    for kind in (1, 2):
        for slot in (1, 31, 32, 200, 383):
            p = Env(patched)
            p.w32(NEW_BF, *([0xFFFFFFFF] * 12))
            p.written()
            p.call(FREE_SLOT, kind, slot)
            bf = p.r32(NEW_BF, 12)
            want = [0xFFFFFFFF] * 12
            want[slot >> 5] &= ~(1 << (slot & 31)) & 0xFFFFFFFF
            check(bf == want, f"free kind {kind} slot {slot}: {[hex(x) for x in bf]}")
            check(p.written() <= new_words, f"free kind {kind} slot {slot}: writes outside the new bitfield")

    # 4. clear sites: patched writes = stock writes with the 8 old bitfield bytes replaced by the 48 new ones
    def run_clear(env, how):
        env.w32(OLD_BF, 0xEEEEEEEE, 0xEEEEEEEE, 0xEEEEEEEE, 0xEEEEEEEE)
        env.w32(NEW_BF, *([0xEEEEEEEE] * 12))
        env.written()
        if how == "tail":
            mu = env.mu
            sp = STACK + 0x8000 - 32
            mu.mem_write(sp, struct.pack("<8I", 4, 5, 6, 7, 8, 9, 0x33C604, RET))  # r4..r9, sl, pc
            mu.reg_write(UC_ARM_REG_SP, sp)
            mu.reg_write(UC_ARM_REG_SL, 0x33C604)
            mu.emu_start(CREATE_TAIL, RET, count=2000)
            check(mu.reg_read(UC_ARM_REG_PC) == RET and mu.reg_read(UC_ARM_REG_SP) == STACK + 0x8000, "create tail: frame")
        else:
            env.call(how)
        return env.written()

    for how, name in ((RESET_FN, "reset 0x24df38"), (CLEAR_ALL, "clear-all 0x2f39e4"), ("tail", "create tail 0x24dad0")):
        s, p = Env(stock), Env(patched)
        ws, wp = run_clear(s, how), run_clear(p, how)
        check(p.r32(NEW_BF, 12) == [0] * 12, f"{name}: new bitfield not cleared {[hex(x) for x in p.r32(NEW_BF, 12)]}")
        check(p.r32(OLD_BF, 2) == [0xEEEEEEEE] * 2, f"{name}: old bitfield words written")
        check(s.r32(KIND3, 2) == p.r32(KIND3, 2), f"{name}: kind-3 words differ: stock {s.r32(KIND3, 2)} patched {p.r32(KIND3, 2)}")
        expect = (ws - old_words) | new_words
        check(wp == expect, f"{name}: write sets differ: {sorted(hex(a) for a in wp ^ expect)[:10]}")

    print("RESULT:", "OK" if not FAILS else f"{len(FAILS)} FAILURES")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()

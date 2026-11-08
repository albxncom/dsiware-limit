"""Offline check of the heap walker used by gdb/heapstat.gdb (HOME Menu EUR 11.17.0-50E).
  uv run --no-project --with unicorn --with capstone -- python -I targets/home/11.17.0-eur/tests/test_walker.py STOCK.code
Runs the real ExpHeap code in unicorn: create 0x12c6b8, alloc 0x12c74c, free 0x137b48, allocatable size
0x12c93c (same entry points the wrappers 0x232a48 / 0x224c60 / 0x224cc4 / 0x22a540 use), on a 256 KiB
region, through a random alloc/free sequence. After every step the Python walker (identical logic to the
GDB `heapstat` command: free list at head+0x24, used list at head+0x2c, next at block+0xc, size at
block+4) must agree with the allocator: used count == live allocations, free+used+headers == heap size,
largest free == the allocator's own 0x12c93c result, every live pointer is a used block payload.
"""
import random
import struct
import sys
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import *

CODE = open(sys.argv[1], "rb").read()
BASE = 0x100000
CREATE, ALLOC, FREE, ALLOCATABLE = 0x12C6B8, 0x12C74C, 0x137B48, 0x12C93C  # 0x12c93c takes the heap object (head - 0x18)
FREE_SIG, USED_SIG = (struct.unpack_from('<I', CODE, a - 0x100000)[0] for a in (0x137FD4, 0x137FD8))  # literals of the split routine
HEAD, REGION, REGION_SIZE, STACK, RET = 0x08000000, 0x30000000, 0x40000, 0x0FFF0000, 0xDEAD0000
FAILS = []


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("FAIL:", msg)


mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
mu.mem_map(BASE, 0x284000)
mu.mem_map(HEAD, 0x1000)
mu.mem_map(REGION, REGION_SIZE)
mu.mem_map(STACK, 0x10000)
mu.mem_map(RET & ~0xFFF, 0x1000)
mu.mem_write(BASE, CODE)


def call(fn, *regs, stack_words=()):
    sp = STACK + 0x8000
    for i, w in enumerate(stack_words):
        mu.mem_write(sp + 4 * i, struct.pack("<I", w))
    mu.reg_write(UC_ARM_REG_SP, sp)
    mu.reg_write(UC_ARM_REG_LR, RET)
    for r, v in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), regs):
        mu.reg_write(r, v)
    mu.emu_start(fn, RET, count=1000000)
    assert mu.reg_read(UC_ARM_REG_PC) == RET and mu.reg_read(UC_ARM_REG_SP) == sp
    return mu.reg_read(UC_ARM_REG_R0)


def r32(a):
    return struct.unpack("<I", mu.mem_read(a, 4))[0]


def r16(a):
    return struct.unpack("<H", mu.mem_read(a, 2))[0]


def walk(head):
    """Same arithmetic as heapstat.gdb: returns (start, end, free_sum, free_max, free_cnt, used_sum, used_cnt, used_blocks)."""
    start, end = r32(head + 0x18), r32(head + 0x1C)
    fsum = fmax = fcnt = 0
    b = r32(head + 0x24)
    free_blocks = []
    while b and fcnt < 100000:
        sz = r32(b + 4)
        free_blocks.append((b, sz))
        fsum += sz
        fmax = max(fmax, sz)
        fcnt += 1
        b = r32(b + 0xC)
    usum = ucnt = 0
    b = r32(head + 0x2C)
    used_blocks = []
    while b and ucnt < 100000:
        used_blocks.append((b, r32(b + 4)))
        usum += r32(b + 4)
        ucnt += 1
        b = r32(b + 0xC)
    return start, end, fsum, fmax, fcnt, usum, ucnt, used_blocks, free_blocks


# create: 0x12c6b8(head, start, size, opt=0); the wrapper 0x232a48 passes opt 0x100 (= 0 after uxth)
check(call(CREATE, HEAD, REGION, REGION_SIZE, 0) != 0, "create failed")
start, end, fsum, fmax, fcnt, usum, ucnt, used, free = walk(HEAD)
check((start, end) == (REGION, REGION + REGION_SIZE), f"range {start:#x}..{end:#x}")
check(fcnt == 1 and fsum == fmax == REGION_SIZE - 16 and ucnt == 0, f"fresh heap: free {fsum} in {fcnt}, used {ucnt}")
check(r16(free[0][0]) == FREE_SIG == 0x4652, f"free block signature {r16(free[0][0]):#x}")
check(r32(HEAD) == 0x45585048, f"head signature {r32(HEAD):#x}")

rng = random.Random(7)
live = {}  # payload pointer -> requested size
steps = 0
for step in range(600):
    if live and (rng.random() < 0.45 or len(live) > 60):
        p = rng.choice(sorted(live))
        call(FREE, HEAD, p)
        del live[p]
    else:
        size = rng.choice([8, 16, 0x1c8, 0x378, 0x1180, 0x1680, 0x23c0, 0x36c0, 0x4000, rng.randrange(1, 0x3000)])
        align = rng.choice([4, 4, 4, 0x80, -4, -8])
        p = call(ALLOC, HEAD, size, align & 0xFFFFFFFF)
        if p == 0:
            largest = call(ALLOCATABLE, HEAD - 0x18, abs(align))
            check(largest < size + abs(align), f"step {step}: alloc({size}, {align}) failed with {largest} allocatable")
            continue
        check(p % abs(align) == 0 and REGION + 16 <= p and p + size <= REGION + REGION_SIZE, f"step {step}: bad pointer {p:#x}")
        live[p] = size
    steps += 1
    start, end, fsum, fmax, fcnt, usum, ucnt, used, free = walk(HEAD)
    check(ucnt == len(live), f"step {step}: walker used count {ucnt} != live {len(live)}")
    check(all(any(b + 16 <= p < b + 16 + sz for b, sz in used) for p in live), f"step {step}: a live pointer is not inside a used block")
    check(fsum + usum + 16 * (fcnt + ucnt) + sum(((r16(b + 2) >> 8) & 0x7F) for b, _ in used) == REGION_SIZE,
          f"step {step}: free {fsum} + used {usum} + headers {16 * (fcnt + ucnt)} + padding != {REGION_SIZE}")
    check(all(r16(b) == FREE_SIG for b, _ in free) and all(r16(b) == USED_SIG for b, _ in used), f"step {step}: block signatures")
    check(fmax == call(ALLOCATABLE, HEAD - 0x18, 1) if fcnt else True, f"step {step}: largest free {fmax} != allocatable {call(ALLOCATABLE, HEAD - 0x18, 1)}")
    check(all(free[i][0] < free[i + 1][0] for i in range(len(free) - 1)), f"step {step}: free list not address sorted")

print(f"{'all tests passed' if not FAILS else f'{len(FAILS)} FAILURES'} ({steps} alloc/free steps, {len(live)} live at the end, "
      f"free {fsum} in {fcnt} blocks, largest {fmax}, used {ucnt})")
sys.exit(1 if FAILS else 0)

"""Emulate the Mset.dat loops of mset (original, N=40) and the patched build (N, default 256) and compare with Python models.

Usage: uv run --no-project --with unicorn --with capstone -- python -I targets/settings/11.17.0-eur/tests/test_settings.py dumps/0004001000022000.dec.code out/max-N/patched/0004001000022000.code [N]
"""
import random, struct, sys
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import *
ORIG = open(sys.argv[1], 'rb').read(); PATCHED = open(sys.argv[2], 'rb').read()
BASE, END = 0x100000, 0x796000
ARR, STOP, SP = 0x08000000, 0x0ff00000, 0x0ff20000
rnd = random.Random(11); fails = 0; cases = 0
def tid(valid=True):
    hi = 0x00048004 if valid else rnd.choice([0x00040010, 0x00048005, 0x0004800e])
    return rnd.getrandbits(32) | hi << 32
NEG1 = (1 << 64) - 1

def machine(code):
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(BASE, END - BASE); mu.mem_write(BASE, code)
    mu.mem_map(ARR, 0x10000); mu.mem_map(STOP, 0x1000); mu.mem_map(0x0ff10000, 0x10000)
    mu.reg_write(UC_ARM_REG_C1_C0_2, mu.reg_read(UC_ARM_REG_C1_C0_2) | (0xf << 20))  # CPACR: cp10/cp11
    mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
    return mu
def run(mu, start, stop, regs):
    mu.reg_write(UC_ARM_REG_SP, SP); mu.reg_write(UC_ARM_REG_LR, STOP)
    for r, v in regs.items(): mu.reg_write(r, v)
    mu.emu_start(start, stop, count=2_000_000)
def put(mu, arr): mu.mem_write(ARR, b''.join(struct.pack('<Q', x) for x in arr))
def get(mu, n): return list(struct.unpack(f'<{n}Q', mu.mem_read(ARR, 8*n)))
def check(name, got, want):
    global fails, cases
    cases += 1
    if got != want:
        fails += 1; print('FAIL', name, [hex(x) for x in got[:6]], [hex(x) for x in want[:6]])

for code, N, label in ((ORIG, 40, 'orig'), (PATCHED, int(sys.argv[3]) if len(sys.argv) > 3 else 256, "patched")):
    mu = machine(code)
    for _ in range(60):
        arr = [tid() if rnd.random() < .7 else NEG1 for _ in range(N)]
        # builder shift: 0x201588 .. 0x2015ec, r0 = array; r2/r3 must survive
        put(mu, arr); run(mu, 0x201588, 0x2015ec, {UC_ARM_REG_R0: ARR, UC_ARM_REG_R2: 0x1234, UC_ARM_REG_R3: 0x5678})
        check(f'{label} builder-shift', get(mu, N), [arr[0]] + arr[:-1])
        assert mu.reg_read(UC_ARM_REG_R2) == 0x1234 and mu.reg_read(UC_ARM_REG_R3) == 0x5678
        # import shift: 0x1ff568 .. 0x1ff5cc, r5 = array; r4/r6/r7 must survive
        put(mu, arr); run(mu, 0x1ff568, 0x1ff5cc, {UC_ARM_REG_R5: ARR, UC_ARM_REG_R4: 1, UC_ARM_REG_R6: 2, UC_ARM_REG_R7: 3})
        check(f'{label} import-shift', get(mu, N), [arr[0]] + arr[:-1])
        assert (mu.reg_read(UC_ARM_REG_R4), mu.reg_read(UC_ARM_REG_R6), mu.reg_read(UC_ARM_REG_R7)) == (1, 2, 3)
        # delete remove: 0x1ffc00 .. 0x1ffcbc, r7 = array, r4/r5 = tid lo/hi
        victim = rnd.choice([x for x in arr if x != NEG1] + [tid()])
        put(mu, arr); run(mu, 0x1ffc00, 0x1ffcbc, {UC_ARM_REG_R7: ARR, UC_ARM_REG_R4: victim & 0xffffffff, UC_ARM_REG_R5: victim >> 32})
        want = list(arr)
        i = 0
        while i < N:
            if want[i] == victim:
                want = want[:i] + want[i+1:] + [NEG1]
            i += 1
        check(f'{label} delete-remove', get(mu, N), want)
        # validator 0x2000a0(array, nandCount): NAND list at 0x3ba858, state at 0x299c68 (+5,+6 = 0)
        nand = [tid(valid=rnd.random() < .6) for _ in range(rnd.randint(0, 120))]
        arr2 = [rnd.choice(nand) if nand and rnd.random() < .6 else (NEG1 if rnd.random() < .5 else tid()) for _ in range(N)]
        mu.mem_write(0x3ba858, b''.join(struct.pack('<Q', x) for x in nand)); mu.mem_write(0x299c68, bytes(16))
        put(mu, arr2); run(mu, 0x2000a0, STOP, {UC_ARM_REG_R0: ARR, UC_ARM_REG_R1: len(nand)})
        want = list(arr2)
        dsi = {x for x in nand if (x >> 46) == 0x12 and not (x >> 32) & 1}
        for i in range(N):
            if want[i] in dsi:
                if i > 0:
                    for j in range(i):
                        if want[j] == NEG1:
                            want[j] = want[i]; want[i] = NEG1; break
            else:
                want[i] = NEG1
        check(f'{label} validator', get(mu, N), want)
        assert mu.reg_read(UC_ARM_REG_R0) == 1
print(f'{cases} cases, {fails} failures')
print('RESULT:', 'OK' if not fails else f'{fails} FAILURES')
sys.exit(1 if fails else 0)

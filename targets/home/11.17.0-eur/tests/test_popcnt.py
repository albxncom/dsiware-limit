"""Run Nintendo's and our ticket popcount as real ARM code (unicorn) and compare.

Usage: uv run --no-project --with unicorn --with capstone -- python -I targets/home/11.17.0-eur/tests/test_popcnt.py dumps/0004003000009802.dec.code out/max-N/patched/0004003000009802.code
"""
import random, sys
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0

code = open(sys.argv[1], 'rb').read()          # original decrypted .code
patched_code = open(sys.argv[2], 'rb').read()  # dsiware-limit.py output
BASE, END = 0x100000, 0x383000
ENTRY, ENSURE, STATE, OLD_BF, NEW_BF, STOP = 0x1ad84c, 0x21e9d8, 0x32eda4, 0x32edc4, 0x34d2c0, 0x0ff00000
new = patched_code[ENTRY - BASE:ENTRY - BASE + 0xb4]

def machine(patched):
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    mu.mem_map(BASE, END - BASE)
    mu.mem_write(BASE, code)
    if patched:
        mu.mem_write(ENTRY, new)
    mu.mem_write(ENSURE, bytes.fromhex('1eff2fe1'))   # bx lr: list init is not under test
    mu.mem_map(STOP, 0x1000); mu.mem_map(0x0ff10000, 0x10000)
    return mu

def run(mu):
    mu.reg_write(UC_ARM_REG_SP, 0x0ff20000); mu.reg_write(UC_ARM_REG_LR, STOP)
    mu.emu_start(ENTRY, STOP, count=100000)
    return mu.reg_read(UC_ARM_REG_R0)

orig, patched = machine(False), machine(True)
rnd = random.Random(7); fails = 0; n = 0
def check(count, bits, stale):
    global fails, n
    n += 1
    mask = (1 << count) - 1
    words = (bits | stale) & ((1 << 256) - 1)
    patched.mem_write(STATE + 0x10, count.to_bytes(4, 'little'))
    patched.mem_write(NEW_BF, words.to_bytes(32, 'little'))
    got = run(patched)
    want = bin(words & mask).count('1')
    if got != want: fails += 1; print('MASK FAIL', count, hex(words), got, want)
    if count <= 64 and not stale:           # equivalence with Nintendo's routine
        orig.mem_write(OLD_BF, (bits & ((1 << 64) - 1)).to_bytes(8, 'little'))
        o = run(orig)
        if o != got: fails += 1; print('EQUIV FAIL', count, hex(bits), o, got)

for count in list(range(0, 257)):
    for _ in range(8):
        bits = rnd.getrandbits(256) & ((1 << count) - 1)
        stale = rnd.getrandbits(256) & ~((1 << count) - 1) if rnd.random() < .5 else 0
        check(count, bits, stale)
for count in (0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256):
    check(count, (1 << count) - 1, 0); check(count, 0, ((1 << 256) - 1) & ~((1 << count) - 1))
print(f'{n} cases, {fails} failures')
print('RESULT:', 'OK' if not fails else f'{fails} FAILURES')
sys.exit(1 if fails else 0)

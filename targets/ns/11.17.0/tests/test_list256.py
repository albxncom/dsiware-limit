#!/usr/bin/env python3
"""Unicorn test of the 256-title variant (caves/cave256.S at 0x11fa40, hook 0x112244), stock vs patched.

Run: uv run --no-project --with unicorn --with capstone -- python -I targets/ns/11.17.0/tests/test_list256.py --code dumps/0004013000008002.dec.code --ips out/max-N/luma/sysmodules/0004013000008002.ips

Same harness as the test of the earlier 205 variant (not kept) (real NS code 0x112244 -> 0x1122b4, only svc 0x32 modelled). Additionally checks
that the content-id scratch of the second AM query is inside the cave's own stack frame, measures the stack
depth below the hook (low-water mark of a 0xAA-filled stack) and verifies Luma's own NS patterns survive the IPS.
"""
import argparse
import random
import struct
import sys
from pathlib import Path

from unicorn import UC_ARCH_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_MODE_ARM, Uc
from unicorn.arm_const import (UC_ARM_REG_C13_C0_3, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R4,
                               UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_SP)

TEXT = 0x100000
IMG_SIZE = 0x118000
STACK, STACK_SIZE = 0x0FF00000, 0x10000
SP_HOOK = STACK + STACK_SIZE - 0x100
TITLE = 0x0FF20000
TLS = 0x1FF82000
RET = 0x0FFF0000
DA = 0x215000
SCR_TIDS, SCR_MAX = 0x217658, 256
SCR_TIDS_END = SCR_TIDS + 8 * SCR_MAX          # 0x217e58 <= 0x218000
FRAME = 0x410
CIDS_ON_STACK = SP_HOOK - 24 - FRAME + 8        # push {r4-r8,lr} then sub sp,#FRAME; cids at sp+8
STACK_NEED = 24 + FRAME + 16 + 16               # cave frame + stock frames below it: 0x103300 (16) and 0x109db0 (16)
START, JOIN, ERR_EXIT = 0x112244, 0x1122B4, 0x1122A0
HDR_TWL_LIST = 0x04110044
LUMA_PATTERNS = [('region-free 0C18E1D8 (text)', bytes([0x0C, 0x18, 0xE1, 0xD8]), 0, 0x1FA3C, 2),
                 ('N3DS CPU 0C009415 (text)', bytes([0x0C, 0x00, 0x94, 0x15]), 0, 0x1FA3C, 1),
                 ('rodata 00B11500', bytes([0x00, 0xB1, 0x15, 0x00]), 0x20000, 0x20000 + 0x15A8, 1)]


def apply_ips(code: bytes, ips: bytes) -> bytes:
    assert ips[:5] == b'PATCH' and ips[-3:] == b'EOF'
    out = bytearray(code)
    pos = 5
    while pos < len(ips) - 3:
        off = int.from_bytes(ips[pos:pos + 3], 'big')
        size = int.from_bytes(ips[pos + 3:pos + 5], 'big')
        pos += 5
        assert size, 'RLE not expected'
        out[off:off + size] = ips[pos:pos + size]
        pos += size
    return bytes(out)


def am_form(tid_hi: int) -> int:
    return (tid_hi & 0x7FFF) | 0x30000


def am_tid(tid: int) -> int:
    return (am_form(tid >> 32) << 32) | (tid & 0xFFFFFFFF)


class Run:
    def __init__(self, image: bytes, model):
        self.model = model
        self.calls = []
        self.exit = None
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(TEXT, IMG_SIZE)
        uc.mem_write(TEXT, image)
        uc.mem_map(STACK, STACK_SIZE)
        uc.mem_map(TITLE, 0x1000)
        uc.mem_map(TLS, 0x1000)
        uc.mem_map(RET, 0x1000)
        uc.reg_write(UC_ARM_REG_C13_C0_3, TLS)
        uc.hook_add(UC_HOOK_INTR, self.h_intr)
        for addr in (JOIN, ERR_EXIT, RET):
            uc.hook_add(UC_HOOK_CODE, self.h_exit, begin=addr, end=addr)
        self.uc = uc

    def h_intr(self, uc, intno, data):
        pc = uc.reg_read(UC_ARM_REG_PC)
        insn = struct.unpack('<I', uc.mem_read(pc - 4, 4))[0]
        assert intno == 2 and (insn & 0x0F000000) == 0x0F000000 and (insn & 0xFFFFFF) == 0x32, f'unexpected trap at {pc:#x}'
        cmd = TLS + 0x80
        hdr, count, d1, tids, d2, cids = struct.unpack('<6I', uc.mem_read(cmd, 24))
        assert hdr == HDR_TWL_LIST and d1 == (0xC | (count << 7)) and d2 == (0xC | (count << 6))
        res, entries = self.model(count, len(self.calls))
        self.calls.append((count, tids, cids))
        if res < 0:
            uc.mem_write(cmd, struct.pack('<III', 0x04110080, res & 0xFFFFFFFF, 0))
        else:
            entries = entries[:count]
            uc.mem_write(tids, b''.join(struct.pack('<Q', t) for t, _ in entries))
            uc.mem_write(cids, b''.join(struct.pack('<I', c) for _, c in entries))
            uc.mem_write(cmd, struct.pack('<III', 0x04110080, 0, len(entries)))
        uc.reg_write(UC_ARM_REG_R0, 0)

    def h_exit(self, uc, addr, size, data):
        self.exit = (addr, uc.reg_read(UC_ARM_REG_R0))
        uc.emu_stop()

    def run(self, tid: int, mediatype: int = 0, caller: int = 0):
        uc = self.uc
        self.calls, self.exit = [], None
        uc.mem_write(DA, b'\0' * 0x1000)
        uc.mem_write(0x217654, b'\0' * (0x218000 - 0x217654))
        uc.mem_write(DA, struct.pack('<Q', caller))
        uc.mem_write(TITLE, struct.pack('<QB', tid, mediatype) + b'\0' * 7)
        uc.mem_write(STACK, b'\xAA' * STACK_SIZE)
        uc.reg_write(UC_ARM_REG_SP, SP_HOOK)
        uc.reg_write(UC_ARM_REG_R4, TITLE)
        uc.reg_write(UC_ARM_REG_R5, 0x102)
        uc.reg_write(UC_ARM_REG_R6, 0xDEAD0006)
        uc.reg_write(UC_ARM_REG_LR, RET)
        uc.emu_start(START, 0, count=400000)
        assert self.exit is not None, 'did not reach the join'
        return self.exit, bytes(uc.mem_read(DA, 0x1000))

    def stack_depth(self) -> int:
        """bytes below SP_HOOK that were touched (0xAA fill broken), i.e. the stack need of the run."""
        mem = bytes(self.uc.mem_read(STACK, SP_HOOK - STACK))
        i = 0
        while i < len(mem) and mem[i] == 0xAA:
            i += 1
        return len(mem) - i


def list_of(da: bytes):
    n = da[0x950]
    tids = [struct.unpack_from('<Q', da, 0x9A0 + 8 * i)[0] for i in range(78)]
    cids = [struct.unpack_from('<I', da, 0xC10 + 4 * i)[0] for i in range(77)]
    return n, tids, cids


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--code', required=True)
    ap.add_argument('--ips', required=True)
    a = ap.parse_args()
    stock = Path(a.code).read_bytes()
    patched = apply_ips(stock, Path(a.ips).read_bytes())
    rng = random.Random(20261108)
    fails = 0

    def expect(label, cond, detail=''):
        nonlocal fails
        if not cond:
            fails += 1
            print(f'FAIL {label} {detail}')

    # 0. IPS footprint and Luma pattern survival
    diff = [i for i in range(len(stock)) if stock[i] != patched[i]]
    expect('IPS footprint: hook word + cave only', min(diff) == 0x12244 and max(diff) < 0x20000
           and all(i in range(0x12244, 0x12248) or i in range(0x1FA40, 0x1FB48) for i in diff), f'{hex(min(diff))}..{hex(max(diff))}')
    expect('scratch tids inside the bss page', SCR_TIDS_END <= 0x218000 and SCR_TIDS >= 0x217654)
    for name, pat, lo, hi, want in LUMA_PATTERNS:
        n, i = 0, patched.find(pat, lo, hi)
        while i >= 0:
            n, i = n + 1, patched.find(pat, i + 1, hi)
        expect(f'Luma pattern {name} still x{want}', n == want, f'got {n}')

    def make_titles(n, hi=0x00048004):
        return [((hi << 32) | (0x4A000000 + 0x1000 * i + rng.randrange(0x1000)), rng.randrange(0, 0x40)) for i in range(n)]

    def installed_model(titles):
        am = [(am_tid(t), c) for t, c in titles]
        return lambda count, call: (0, am)

    # 1. 256 installed: every position 1..256
    titles = make_titles(256)
    model = installed_model(titles)
    s, p = Run(stock, model), Run(patched, model)
    depth_present, depth_absent = 0, 0
    for i, (tid, cid) in enumerate(titles):
        (se, sr0), sda = s.run(tid)
        (pe, pr0), pda = p.run(tid)
        expect(f'#{i + 1} exit', (se, sr0) == (JOIN, 0) and (pe, pr0) == (JOIN, 0))
        n, tids, cids = list_of(sda)
        pn, ptids, pcids = list_of(pda)
        t = am_tid(tid)
        if i < 77:
            expect(f'#{i + 1} present: identical', pda == sda and len(p.calls) == 1)
            depth_present = max(depth_present, p.stack_depth())
        else:
            expect(f'#{i + 1} absent in stock', t not in tids[:n] and n == 77)
            expect(f'#{i + 1} slot 76 = target + AM cid', pn == 77 and ptids[76] == t and pcids[76] == cid, f'n={pn} tid={ptids[76]:#x} cid={pcids[76]:#x} want {cid:#x}')
            expect(f'#{i + 1} rest identical', ptids[:76] == tids[:76] and pcids[:76] == cids[:76] and pda[:0x950] == sda[:0x950]
                   and pda[0x951:0x9A0] == sda[0x951:0x9A0] and pda[0xD44:] == sda[0xD44:])
            expect(f'#{i + 1} second query: 256 into bss-tail tids + stack cids', len(p.calls) == 2
                   and p.calls[1] == (SCR_MAX, SCR_TIDS, CIDS_ON_STACK), f'{[(c, hex(t), hex(d)) for c, t, d in p.calls]}')
            depth_absent = max(depth_absent, p.stack_depth())
    expect('stack depth below hook <= 0x448', depth_absent <= STACK_NEED, f'{depth_absent:#x}')
    print(f'256 installed: 1..77 identical to stock (stack depth {depth_present:#x}), 78..256 fixed; '
          f'worst stack depth below the hook sp {depth_absent:#x} ({depth_absent}) bytes, budget {STACK_NEED:#x}')
    s_depth = s.stack_depth()
    print(f'stock stack depth below the hook for comparison: {s_depth:#x}')

    # 2. 300 installed: 257..300 beyond the scratch -> unchanged
    titles300 = make_titles(300)
    model = installed_model(titles300)
    s, p = Run(stock, model), Run(patched, model)
    for i, (tid, cid) in enumerate(titles300):
        if i < 256 and i % 7:
            continue
        (_, _), sda = s.run(tid)
        (pe, pr0), pda = p.run(tid)
        n, tids, cids = list_of(pda)
        if i < 77:
            expect(f'300/#{i + 1} identical', pda == sda)
        elif i < SCR_MAX:
            expect(f'300/#{i + 1} fixed', tids[76] == am_tid(tid) and cids[76] == cid and n == 77)
        else:
            expect(f'300/#{i + 1} unchanged (beyond scratch)', pda == sda and (pe, pr0) == (JOIN, 0))
    print('300 installed: 78..256 fixed, 257..300 unchanged (scratch limit)')

    # 3. CTR caller appended by stock at slot 77 (count 78): patch replaces slot 76 only
    model = installed_model(titles)
    s, p = Run(stock, model), Run(patched, model)
    caller = 0x0004003000009802
    tid, cid = titles[200]
    (_, _), sda = s.run(tid, caller=caller)
    (_, _), pda = p.run(tid, caller=caller)
    n, tids, cids = list_of(sda)
    pn, ptids, pcids = list_of(pda)
    expect('caller: stock count 78, caller at slot 77', n == 78 and tids[77] == caller)
    expect('caller: patched slot 76 = target, slot 77 untouched, count 78', pn == 78 and ptids[76] == am_tid(tid) and pcids[76] == cid and ptids[77] == caller)
    expect('caller + present: identical', p.run(titles[5][0], caller=caller)[1] == s.run(titles[5][0], caller=caller)[1])

    # 4. Synthetic count < 77 (first query short, second complete) -> append at count
    am256 = installed_model(titles)(0, 0)[1]
    model = lambda count, call: (0, am256[:50] if count == 77 else am256)  # noqa: E731
    p = Run(patched, model)
    tid, cid = titles[200]
    (pe, pr0), pda = p.run(tid)
    pn, ptids, pcids = list_of(pda)
    expect('append: count 51, slot 50 = target', pn == 51 and ptids[50] == am_tid(tid) and pcids[50] == cid and ptids[51] == 0 and (pe, pr0) == (JOIN, 0))

    # 5. Process9 caps the big query (answers only 77 of 256) -> target absent -> list exactly as stock
    model = lambda count, call: (0, am256[:77])  # noqa: E731
    s, p = Run(stock, installed_model(titles)), Run(patched, model)
    (_, _), sda = s.run(titles[200][0])
    (pe, pr0), pda = p.run(titles[200][0])
    expect('AM caps count: patched == stock', sda == pda and (pe, pr0) == (JOIN, 0) and len(p.calls) == 2)

    # 6. AM errors
    err = 0xD8A08400 - (1 << 32)
    model = lambda count, call: (err, [])  # noqa: E731
    s, p = Run(stock, model), Run(patched, model)
    (se, sr0), sda = s.run(titles[200][0])
    (pe, pr0), pda = p.run(titles[200][0])
    expect('AM error 1st: identical', (se, sr0) == (pe, pr0) and se == ERR_EXIT and sda == pda and list_of(sda)[0] == 0)
    model = lambda count, call: (0, am256) if call == 0 else (err, [])  # noqa: E731
    s, p = Run(stock, installed_model(titles)), Run(patched, model)
    (se, sr0), sda = s.run(titles[200][0])
    (pe, pr0), pda = p.run(titles[200][0])
    expect('AM error 2nd (e.g. count 256 refused): patched == stock', (se, sr0) == (pe, pr0) == (JOIN, 0) and sda == pda)
    unknown = 0x0004800400000000 | 0x12345678
    (_, _), sda = s.run(unknown)
    (pe, pr0), pda = Run(patched, installed_model(titles)).run(unknown)
    expect('not installed: patched == stock', sda == pda and (pe, pr0) == (JOIN, 0))

    # 7. 0x00048005 form
    sys_titles = make_titles(3, hi=0x00048005)
    mixed = titles[:77] + sys_titles
    model = installed_model(mixed)
    s, p = Run(stock, model), Run(patched, model)
    tid, cid = sys_titles[2]
    (_, _), sda = s.run(tid)
    (_, _), pda = p.run(tid)
    pn, ptids, pcids = list_of(pda)
    expect('00048005 absent -> slot 76 in 0x00030005 form', ptids[76] == ((0x00030005 << 32) | (tid & 0xFFFFFFFF)) and pcids[76] == cid and pn == 77)
    expect('00048005 present -> identical', p.run(mixed[3][0])[1] == s.run(mixed[3][0])[1])
    expect('CRC block untouched', pda[0x400:0x540] == sda[0x400:0x540] == b'\0' * 0x140)

    print('RESULT:', 'OK' if fails == 0 else f'{fails} FAILURES')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())

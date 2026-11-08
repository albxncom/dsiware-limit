"""Option A version of the original chain test (not kept): every DSi banner is loaded non-animated (0x1326a8 forced to kind 2).
Changes against the original: in the all-ok runs the animated scenarios (twl_anim, twl_anim_nosav, twl_anim_noseq)
are not compared with stock; instead the patched run must end attached (or poolfull for slot -1) with a kind-2
upload from a source buffer, no 0x1180 animation-pair allocation and no fs sub-banner read. C4 expects the kind-2
upload. Everything else (non-animated and 3DS scenarios, the failure matrix, C1-C3) is unchanged.

Unicorn chain test for the DSiWare/3DS tile load (HOME Menu EUR 11.17.0-50E), stock vs patched.
  uv run --no-project --with unicorn --with capstone -- python -I targets/home/11.17.0-eur/tests/test_chain_a.py STOCK.code PATCHED.code

Runs the real code of the whole chain: driver 0x1c7748 (icon-cache hit) or 0x1c7d74 (cache miss) -> banner
object ctor 0x245da4 (TWL) / 0x245cfc (3DS) -> loader 0x132458 / 3DS fill 0x220abc -> attach check 0x2035c4
-> attach 0x1c7308 (-> animation helpers 0x1b3c7c / 0x1b3be8, dtor 0x245f58) with the leaves mocked at their
entry: allocator, memset/memcpy, fs wrappers, icon cache, slot allocator, texture upload, tile bookkeeping.
The allocator mock fails exactly the k-th allocation ("single") or every allocation from the k-th on
("from"), for every k up to the number of allocations the chain makes with everything succeeding.
Asserts for the patched code: no access below 0x10000 (page 0 is unmapped), no NULL buffer passed to fs,
memcpy, memset or the uploads, lock/unlock balanced, every block freed or owned by the tile's animation pair,
and the tile ends in a documented state. With no failures stock and patched must behave identically.
"""
import struct
import sys
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm_const import *

STOCK = open(sys.argv[1], "rb").read()
PATCHED = open(sys.argv[2], "rb").read()
BASE = 0x100000
DRV_HIT, DRV_MISS, ATTACH, ATTACH_TILE, LOADER, FILL3DS = 0x1C7748, 0x1C7D74, 0x2035C4, 0x1C7308, 0x132458, 0x220ABC
RET = 0xDEAD0000
MAINP, MAIN, TILES, CTX, CTX2, CTX3, LOCKBASE, REC, KEY, CACHE, HEAP0, STACK = (
    0x08000000, 0x08010000, 0x08050000, 0x08060000, 0x08061000, 0x08062000, 0x08070000, 0x08080000, 0x08080100,
    0x08090000, 0x09000000, 0x0FFF0000)
HEAP_ID = 0x32EAC8
IDX, SELECTED, SLOT = 5, 99, 7
TILE = TILES + IDX * 0x230
TID_TWL, TID_3DS = (0x4A505041, 0x00048004), (0x00055D00, 0x00040000)
MEDIA, CRC, REGION = 1, 0x1234, 0x00000004
FAILS = []

# leaves
ALLOC, ALLOC2, FREE, FREE2 = 0x235800, 0x236454, 0x2353C4, 0x236424
CLEAR, MEMSET, MEMCPY_A, MEMCPY_B = 0x233F10, 0x232774, 0x2362C8, 0x237B64
CRC16, VALIDATE, FS_HEADER, FS_BANNER, FS_SUB, FS_SMDH = 0x21E108, 0x21E02C, 0x21DFF0, 0x21DFB8, 0x1372B4, 0x231E60
LANGTAB, GETLANG, GETREGION, PICKTITLE, STRCPY16, LOOKUP, LOOKUP3DS, CODE_A, CONVERT, TITLES3DS = (
    0x21DE08, 0x21E1E8, 0x232574, 0x226480, 0x2228C0, 0x13D820, 0x13D740, 0x220A14, 0x143B34, 0x226510)
MAIN_PTR, LOCK, UNLOCK, HEAPID, HEAPID2, SELCTX, CTXA, CTXB, SEL_RESET, RELEASE = (
    0x226780, 0x234BB0, 0x234B68, 0x226828, 0x236488, 0x21BD60, 0x21BC44, 0x21BD50, 0x1C6F60, 0x204D18)
CACHE_LOOKUP, CACHE_WRITE, SLOTALLOC, TEXINFO, UPLOAD, UPLOAD_FRAME, DTOR = (
    0x1C3984, 0x1C39B0, 0x2030AC, 0x207C20, 0x24DC74, 0x24DE60, 0x245F58)
STUBS = {0x203544: 0, 0x202134: 0, 0x1C1830: 0, 0x10EBB0: 0, 0x1AD600: 0, 0x1AD7AC: 0, 0x10097E: 0, 0x20475C: 0,
         0x201F2C: 0, 0x1C810C: 0, 0x1C7614: 0, 0x1FEBB4: 0}  # tile bookkeeping in the tail of 0x2035c4
AFTER_ATTACH = {0x1C785C, 0x1C7F9C}  # instruction after `bl 0x2035c4` in the drivers: r0 = attach result


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("FAIL:", msg)


def header_template():
    h = bytearray(0x378)
    struct.pack_into("<H", h, 0x15E, CRC)
    struct.pack_into("<I", h, 0x1B0, REGION)
    return bytes(h)


def banner_template(animated):
    b = bytearray(0x23C0)
    b[0], b[1] = 3, 1 if animated else 0
    for i in range(0x20, 0x240):
        b[i] = (i * 3) & 0xFF
    for i in range(0x240, 0x340):
        b[i] = 0x41
    for i in range(0x1240, 0x1240 + 0x1180):
        b[i] = (i * 5) & 0xFF
    b[0x1240 + 0x1100] = 1
    return bytes(b)


def subbanner_template(seq_present):
    s = bytearray(0x4000)
    struct.pack_into("<H", s, 8, CRC)
    for i in range(0x20, 0x20 + 0x1180):
        s[i] = (i * 7) & 0xFF
    s[0x20 + 0x1100] = 1 if seq_present else 0
    return bytes(s)


def smdh_template():
    s = bytearray(0x36C0)
    s[0:4] = b"SMDH"
    for i in range(0x208, 0x408):
        s[i] = 0x42  # language 1 title and publisher
    struct.pack_into("<I", s, 0x2018, 0x7FFFFFFF)  # region lockout: all
    struct.pack_into("<I", s, 0x2028, 0x1)  # flags: visible
    for i in range(0x2040, 0x36C0):
        s[i] = (i * 11) & 0xFF  # small + large icon
    return bytes(s)


class Scenario:
    def __init__(self, driver, title, tile, slot=SLOT):
        self.driver, self.title, self.tile, self.slot = driver, title, tile, slot
        self.is_3ds = title == "3ds"
        self.tid = TID_3DS if self.is_3ds else TID_TWL

    def __str__(self):
        return f"{self.driver}/{self.title}/{self.tile}/slot{self.slot}"


class Env:
    def __init__(self, code, sc, mode=None, k=0):
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mu.mem_map(BASE, 0x284000)
        mu.mem_map(0x08000000, 0x100000)
        mu.mem_map(HEAP0, 0x400000)
        mu.mem_map(STACK, 0x10000)
        mu.mem_map(RET & ~0xFFF, 0x1000)
        mu.mem_write(BASE, code)
        mu.reg_write(UC_ARM_REG_C1_C0_2, mu.reg_read(UC_ARM_REG_C1_C0_2) | 0xF00000)
        mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        self.mu, self.sc, self.mode, self.k = mu, sc, mode, k
        self.log, self.nulls, self.faults, self.attach_results, self.obj_snaps = [], [], [], [], []
        self.n_alloc, self.live, self.allocs, self.frees, self.bump, self.locks = 0, {}, [], [], HEAP0, 0
        self.header, self.banner = header_template(), banner_template(sc.title != "twl_static")
        self.sub = subbanner_template(sc.title != "twl_anim_noseq")
        self.smdh = smdh_template()
        self.cache_data = self.smdh if sc.is_3ds else self.header + self.banner
        # globals
        self.w32(0x32F5D4, LOCKBASE)
        self.w32(0x32F5CC, MAINP)
        self.w32(0x32F5BC, 0x08100000)
        self.w32(0x32F5DC, CTX2)
        self.w32(0x32F5C0, CTX)
        self.w32(MAINP, MAIN)
        self.w32(MAIN + 0x398F8, TILES)
        mu.mem_write(CTX + 0x3E, struct.pack("<h", SELECTED))
        self.w32(REC, *sc.tid, 0, 0)
        mu.mem_write(REC + 8, bytes([MEDIA]))
        self.w32(KEY, *sc.tid, 0, 0)
        mu.mem_write(CACHE, self.cache_data)
        # tile: same title and version as the record, so 0x1c7308 does not release it
        self.w32(TILE, *sc.tid)
        mu.mem_write(TILE + 8, bytes([MEDIA]))
        self.pre = []
        if sc.tile == "refresh":  # tile already has a slot, a texture and an animation pair; version differs
            holder, data, anim = self.pre_alloc(8), self.pre_alloc(0x1180), self.pre_alloc(16)
            self.w32(holder, data, anim)
            self.w32(TILE + 0x48, self.sc.slot if self.sc.slot >= 0 else SLOT)
            self.w32(TILE + 0x58, holder)
            self.w32(TILE + 0x5C, 0x38000000)
            mu.mem_write(TILE + 0x2E, struct.pack("<H", 0x1234))
        mu.hook_add(UC_HOOK_CODE, self.on_code)
        mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.on_unmapped)

    # helpers
    def w32(self, addr, *vals):
        self.mu.mem_write(addr, b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in vals))

    def r32(self, addr):
        return struct.unpack("<I", self.mu.mem_read(addr, 4))[0]

    def ret(self, value=None):
        if value is not None:
            self.mu.reg_write(UC_ARM_REG_R0, value & 0xFFFFFFFF)
        self.mu.reg_write(UC_ARM_REG_PC, self.mu.reg_read(UC_ARM_REG_LR))

    def args(self, n):
        return [self.mu.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)[:n]]

    def null(self, what, *ptrs):
        if any(p == 0 for p in ptrs):
            self.nulls.append(what)

    def fill(self, p, data):
        if p:
            self.mu.mem_write(p, data)

    def pre_alloc(self, size):
        p, self.bump = self.bump, self.bump + ((size + 15) & ~15) + 16
        self.pre.append(p)
        return p

    def do_alloc(self, tag, size, align):
        self.n_alloc += 1
        n = self.n_alloc
        if (self.mode == "single" and n == self.k) or (self.mode == "from" and n >= self.k):
            self.log.append((tag, size, "NULL"))
            return 0
        a = max(16, abs(align if align < 0x80000000 else align - 0x100000000))
        self.bump = (self.bump + a - 1) & ~(a - 1)
        p, self.bump = self.bump, self.bump + ((size + 15) & ~15) + 16
        self.live[p] = size
        self.allocs.append((size, p))
        self.log.append((tag, size, "ok"))
        return p

    def on_unmapped(self, mu, access, addr, size, value, ud):
        self.faults.append((access, addr, hex(mu.reg_read(UC_ARM_REG_PC))))
        return False

    def on_code(self, mu, addr, size, ud):
        if addr in (ALLOC, ALLOC2):
            sz, heap, align = self.args(3)
            self.ret(self.do_alloc("alloc", sz, align))
        elif addr in (FREE, FREE2):
            (p,) = self.args(1)
            if p:
                check(p in self.live, f"free of unknown or already freed pointer {p:#x}")
                self.live.pop(p, None)
            self.frees.append(p)
            self.log.append(("free", "NULL" if p == 0 else [s for s, a in self.allocs if a == p][0]))
            self.ret()
        elif addr in (CLEAR, MEMSET):
            p, n = self.args(2)
            self.null("memset", p)
            self.fill(p, bytes(n))
            self.log.append(("memset", n))
            self.ret()
        elif addr in (MEMCPY_A, MEMCPY_B):
            d, s, n = self.args(3)
            self.null("memcpy", d, s)
            if d and s:
                mu.mem_write(d, bytes(mu.mem_read(s, n)))
            self.log.append(("memcpy", n))
            self.ret()
        elif addr == CRC16:
            p, n, init = self.args(3)
            self.null("crc16", p)
            self.log.append(("crc16", n))
            self.ret(CRC)
        elif addr == VALIDATE:
            (p,) = self.args(1)
            self.null("validate", p)
            self.log.append(("validate",))
            self.ret(1)
        elif addr in (FS_HEADER, FS_BANNER, FS_SUB, FS_SMDH):
            p = self.args(1)[0]
            name = {FS_HEADER: "fs_header", FS_BANNER: "fs_banner", FS_SUB: "fs_sub", FS_SMDH: "fs_smdh"}[addr]
            self.null("fs:" + name, p)
            data = {FS_HEADER: self.header, FS_BANNER: self.banner, FS_SUB: self.sub, FS_SMDH: self.smdh}[addr]
            result = 0xC8804464 if (addr == FS_SUB and self.sc.title == "twl_anim_nosav") else 0
            self.fill(p, data)
            self.log.append((name, result))
            self.ret(result)
        elif addr == LANGTAB:
            self.null("langtab", self.args(3)[2])
            self.log.append(("langtab",))
            self.ret()
        elif addr == TITLES3DS:
            self.null("titles3ds", self.args(3)[2])
            self.log.append(("titles3ds",))
            self.ret()
        elif addr == GETLANG:
            self.ret(1)
        elif addr == GETREGION:
            self.ret(2)
        elif addr == PICKTITLE:
            self.log.append(("picktitle",))
            self.ret(1)
        elif addr == STRCPY16:
            d, s, n = self.args(3)
            self.null("strcpy16", s)
            if s:
                mu.mem_write(d, bytes(mu.mem_read(s, n)))
            self.log.append(("strcpy16", n))
            self.ret()
        elif addr in (LOOKUP, LOOKUP3DS):
            self.ret(0xFFFFFFFF)
        elif addr == CODE_A:
            self.log.append(("code_a",))
            self.ret(0x77)
        elif addr == CONVERT:
            d, s, t = self.args(3)
            self.null("convert(0x143b34)", d - 0x480 if d >= 0x480 else d, s, t)
            if d >= 0x480 + HEAP0 and t:
                mu.mem_write(d, bytes([0xCC] * 0x1200))
            self.log.append(("convert",))
            self.ret()
        elif addr == MAIN_PTR:
            self.ret(LOCKBASE)
        elif addr == LOCK:
            self.locks += 1
            self.log.append(("lock",))
            self.ret()
        elif addr == UNLOCK:
            self.locks -= 1
            self.log.append(("unlock",))
            self.ret()
        elif addr == HEAPID:
            self.ret(HEAP_ID)
        elif addr == HEAPID2:
            self.ret(0x32EAD0)
        elif addr == SELCTX:
            self.ret(CTX)
        elif addr == CTXA:
            self.ret(CTX2)
        elif addr == CTXB:
            self.ret(CTX3)
        elif addr == SEL_RESET:
            self.log.append(("sel_reset",))
            self.ret()
        elif addr == RELEASE:
            self.log.append(("release", self.args(2)[1]))
            self.ret()
        elif addr == CACHE_LOOKUP:
            cache, buf = self.args(2)
            self.null("cache_lookup(0x1c3984)", buf)
            self.fill(buf, self.cache_data)
            self.log.append(("cache_lookup",))
            self.ret(1)
        elif addr == CACHE_WRITE:
            self.null("cache_write(0x1c39b0)", self.args(2)[1])
            self.log.append(("cache_write",))
            self.ret()
        elif addr == SLOTALLOC:
            kind, current, _ = self.args(3)
            self.log.append(("slotalloc", kind, current))
            self.ret(self.sc.slot)
        elif addr == TEXINFO:
            out, kind = self.args(2)
            self.w32(out, 0x38000000 + kind * 0x100000, 0x28000000, 0x01000100, 0x8363, 0x38800000, 0x28800000,
                     0x00800080, 0x8363, 5, 5, 0)
            self.log.append(("texinfo", kind))
            self.ret()
        elif addr == UPLOAD:
            kind, slot, src = self.args(3)
            self.null("upload(0x24dc74) src", src)
            self.log.append(("upload", kind, slot, "NULL" if src == 0 else "src"))
            self.ret()
        elif addr == UPLOAD_FRAME:
            slot, src, heap = self.args(3)
            self.null("upload_frame(0x24de60) src", src)
            self.log.append(("upload_frame", slot, "NULL" if src == 0 else "src"))
            self.ret()
        elif addr == DTOR:
            obj = self.args(1)[0]
            self.obj_snaps.append(bytes(mu.mem_read(obj, 0x1C8)))
            self.log.append(("dtor",))
        elif addr in STUBS:
            self.log.append((f"stub_{addr:x}",))
            self.ret(STUBS[addr])
        elif addr in AFTER_ATTACH:
            self.attach_results.append(mu.reg_read(UC_ARM_REG_R0))

    def run(self, fn, *regs, stack_words=()):
        mu = self.mu
        sp = STACK + 0x8000
        for i, w in enumerate(stack_words):
            self.w32(sp + 4 * i, w)
        mu.reg_write(UC_ARM_REG_SP, sp)
        mu.reg_write(UC_ARM_REG_LR, RET)
        for r, v in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), regs):
            mu.reg_write(r, v)
        try:
            mu.emu_start(fn, RET, count=2000000)
        except UcError as e:
            self.log.append(("FAULT", str(e), hex(mu.reg_read(UC_ARM_REG_PC))))
            return False
        ok = mu.reg_read(UC_ARM_REG_PC) == RET and mu.reg_read(UC_ARM_REG_SP) == sp
        if not ok:
            self.log.append(("BAD_RETURN", hex(mu.reg_read(UC_ARM_REG_PC))))
        return ok

    def drive(self):
        fn = DRV_HIT if self.sc.driver == "hit" else DRV_MISS
        return self.run(fn, MAINP, IDX, REC, KEY, stack_words=(0, 1))

    def tile(self):
        return bytes(self.mu.mem_read(TILE, 0x230))

    def tile_word(self, off):
        return self.r32(TILE + off)

    def outstanding(self):
        return {p: s for p, s in self.live.items() if p not in self.pre}

    def owned_by_tile(self):
        holder = self.tile_word(0x58)
        if holder == 0:
            return set()
        return {holder, self.r32(holder), self.r32(holder + 4)}

    def state(self):
        """Documented end states: attached (texture upload with a source), poolfull (slot -1, no texture),
        rejected/untouched (attach returned 0 or the tile was left alone)."""
        if any(c[0] in ("upload", "upload_frame") for c in self.log):
            return "attached"
        if self.tile_word(0x48) == 0xFFFFFFFF and self.tile_word(0x5C) == 0:
            return "poolfull"
        if self.attach_results and self.attach_results[-1] == 0:
            return "rejected"
        return "untouched"


def strip(log):
    """Known stock/patched differences with everything succeeding: the duplicate 0x36c0 clear in 0x1c7d74."""
    out, seen = [], 0
    for c in log:
        if c == ("memset", 0x36C0):
            seen += 1
            if seen == 2:
                continue
        out.append(c)
    return out


def assert_patched(name, ep, ok):
    check(ok, f"{name} patched: did not return cleanly {ep.log[-2:]}")
    check(not ep.faults, f"{name} patched: unmapped access {ep.faults}")
    check(not ep.nulls, f"{name} patched: NULL use {ep.nulls}")
    check(ep.locks == 0, f"{name} patched: lock/unlock unbalanced {ep.locks}")
    owned = ep.owned_by_tile()
    out = ep.outstanding()
    check(set(out) <= owned, f"{name} patched: leaked {[(hex(p), s) for p, s in out.items() if p not in owned]}")
    holder = ep.tile_word(0x58)
    if holder:
        check(0 not in owned and all(p in ep.live or p in ep.pre for p in owned), f"{name} patched: incomplete animation pair at {holder:#x}")
    st = ep.state()
    check(st in ("attached", "poolfull", "rejected", "untouched"), f"{name} patched: state {st}")
    return st


def stock_outcome(es, ok):
    if not ok or es.faults:
        return "fault"
    if es.nulls:
        return "NULL:" + ",".join(sorted(set(es.nulls)))
    return "ok"


scenarios = [Scenario(d, t, tl) for d in ("hit", "miss") for t in ("twl_anim", "twl_anim_nosav", "twl_anim_noseq", "twl_static", "3ds")
             for tl in ("fresh", "refresh")]
scenarios += [Scenario(d, t, "fresh", slot=-1) for d in ("hit", "miss") for t in ("twl_anim", "twl_static", "3ds")]

matrix = []
total_runs = 0
for sc in scenarios:
    name = str(sc)
    # --- everything succeeds: stock == patched ---
    es, ep = Env(STOCK, sc), Env(PATCHED, sc)
    oks, okp = es.drive(), ep.drive()
    check(oks and okp, f"{name} all-ok: stock {oks} {es.log[-2:]} patched {okp} {ep.log[-2:]}")
    animated = sc.title.startswith("twl_anim")
    if not animated:
        check(strip(es.log) == strip(ep.log), f"{name} all-ok: logs differ\n  stock   {es.log}\n  patched {ep.log}")
        check(es.tile() == ep.tile(), f"{name} all-ok: tile bytes differ")
        check(es.obj_snaps == ep.obj_snaps, f"{name} all-ok: banner object bytes at the dtor differ")
    else:
        check(not any(c[0] == "alloc" and c[1] == 0x1180 for c in ep.log), f"{name} all-ok: animation pair allocated {ep.log}")
        check(not any(c[0] == "fs_sub" for c in ep.log), f"{name} all-ok: sub-banner read {ep.log}")
    check(es.nulls == ep.nulls == [] and not es.faults and not ep.faults, f"{name} all-ok: NULL use {es.nulls} {ep.nulls}")
    st = assert_patched(name + " all-ok", ep, okp)
    expect = "poolfull" if sc.slot == -1 else "attached"
    check(st == expect, f"{name} all-ok: state {st}, expected {expect}: {ep.log}")
    if sc.slot >= 0:
        up = [c for c in ep.log if c[0] in ("upload", "upload_frame")]
        kind1 = False  # option A: no tile uploads animation frames
        check((up[-1][0] == "upload_frame") == kind1 and up[-1][-1] == "src", f"{name} all-ok: upload {up}")
        if not kind1:
            check(up[-1][1] == (0 if sc.is_3ds else 2), f"{name} all-ok: upload kind {up}")
    K = ep.n_alloc
    check(K >= 3, f"{name} all-ok: only {K} allocations")
    # --- allocation failures ---
    for mode in ("single", "from"):
        for k in range(1, K + 1):
            run = f"{name} {mode}@{k}"
            es, ep = Env(STOCK, sc, mode, k), Env(PATCHED, sc, mode, k)
            oks, okp = es.drive(), ep.drive()
            st = assert_patched(run, ep, okp)
            matrix.append((name, mode, k, st, stock_outcome(es, oks)))
            total_runs += 1

# --- attach check with an object that has no icon source (the crash_dump_00000005 signature) -------------
def attach_direct(code, kind, region, b, a):
    sc = Scenario("miss", "twl_static", "fresh")
    e = Env(code, sc)
    obj = e.pre_alloc(0x1C8)
    e.mu.mem_write(obj, bytes([0x55]) * 0x1C8)
    e.w32(obj, 0x320EE8, 0, *TID_TWL)
    e.w32(obj + 0x198, 0)
    e.mu.mem_write(obj + 0x1A8, bytes(13))
    e.w32(obj + 0x1B8, region, kind, b, a)
    ok = e.run(ATTACH, MAINP, IDX, obj, 1)
    return e, ok, e.mu.reg_read(UC_ARM_REG_R0)


for kind, region, b, a, what in ((0, 0x7FFFFFFF, 0, 0, "kind 0 (3DS), B NULL"), (2, 0x7FFFFFFF, 0, 0, "kind 2, B NULL"),
                                 (1, REGION, 0, 0, "kind 1, A NULL")):
    es, oks, rs = attach_direct(STOCK, kind, region, b, a)
    ep, okp, rp = attach_direct(PATCHED, kind, region, b, a)
    check(es.nulls and any(n.startswith("upload") or n == "memcpy" for n in es.nulls) or not oks,
          f"C1 stock {what}: expected the NULL source to reach the upload, got {es.nulls} {es.log[-3:]}")
    check(okp and rp == 0 and not ep.nulls and not ep.faults and ep.locks == 0 and not ep.outstanding(),
          f"C1 patched {what}: {okp} r0={rp} nulls {ep.nulls} faults {ep.faults} log {ep.log}")
    check(ep.r32(ep.pre[-1] + 0x1BC) == 0 and ep.r32(ep.pre[-1] + 0x1B8) == 0, f"C1 patched {what}: not the rejected state")
    check(("lock",) in ep.log and ep.log[-1] == ("unlock",), f"C1 patched {what}: {ep.log}")

# valid objects pass the new check unchanged
for kind, region, what in ((0, 0x7FFFFFFF, "kind 0 with B"), (2, 0x7FFFFFFF, "kind 2 with B"), (1, REGION, "kind 1 with A")):
    logs, tiles = [], []
    for code in (STOCK, PATCHED):
        sc = Scenario("miss", "twl_static", "fresh")
        e = Env(code, sc)
        buf = e.pre_alloc(0x1680)
        obj = e.pre_alloc(0x1C8)
        e.mu.mem_write(obj, bytes(0x1C8))
        e.w32(obj, 0x320EE8, 0, *TID_TWL)
        e.w32(obj + 0x1B8, region, kind, 0 if kind == 1 else buf, buf if kind == 1 else 0)
        ok = e.run(ATTACH, MAINP, IDX, obj, 1)
        check(ok and not e.nulls and not e.faults, f"C2 {what}: {ok} {e.nulls} {e.faults}")
        logs.append(e.log)
        tiles.append(e.tile())
    check(logs[0] == logs[1] and tiles[0] == tiles[1] and any(c[0].startswith("upload") for c in logs[1]), f"C2 {what}: {logs}")

# placeholder kind 0x7fffffff (ctor 0x245e20) never had an icon buffer: must still take the stock path
logs = []
for code in (STOCK, PATCHED):
    sc = Scenario("miss", "twl_static", "fresh")
    e = Env(code, sc)
    obj = e.pre_alloc(0x1C8)
    e.mu.mem_write(obj, bytes(0x1C8))
    e.w32(obj, 0x320EE8, 0, *TID_TWL)
    e.w32(obj + 0x1B8, 0x7FFFFFFF, 0x7FFFFFFF, 0, 0)
    ok = e.run(ATTACH, MAINP, IDX, obj, 1)
    check(ok and not e.faults, f"C3 placeholder: {ok} {e.faults} {e.log[-2:]}")
    logs.append(e.log)
check(logs[0] == logs[1] and not any(c[0].startswith("upload") for c in logs[1]) and ("regionchk",) not in logs[1], f"C3 placeholder: {logs}")

# --- refresh of a tile that has a texture but no animation pair (stock: NULL dereference at 0x1c7468) ----
for code, nm in ((STOCK, "stock"), (PATCHED, "patched")):
    sc = Scenario("miss", "twl_anim", "refresh")
    e = Env(code, sc)
    e.w32(TILE + 0x58, 0)
    ok = e.drive()
    if nm == "patched":
        check(ok and not e.faults and not e.nulls and e.locks == 0 and not e.outstanding(), f"C4 patched: {ok} {e.faults} {e.nulls} {e.log[-3:]}")
        check(any(c[0] == "upload" and c[1] == 2 and c[-1] == "src" for c in e.log), f"C4 patched: icon not uploaded {e.log}")
    else:
        check(not ok or e.faults, f"C4 stock: expected a fault, {e.log[-3:]}")

# --- summary ----------------------------------------------------------------------------------------------
by_state = {}
stock_bad = 0
for name, mode, k, st, so in matrix:
    by_state[st] = by_state.get(st, 0) + 1
    stock_bad += so != "ok"
print(f"chain matrix: {len(scenarios)} scenarios, {total_runs} failure runs; patched end states {by_state}; "
      f"stock faulted or used NULL in {stock_bad} of them")
if "--matrix" in sys.argv:
    for row in matrix:
        print("  %-36s %-6s k=%-2d patched=%-9s stock=%s" % row)
diff = sorted(i + BASE for i in range(len(STOCK)) if STOCK[i] != PATCHED[i])
hooks = {0x1C73F8, 0x1C7424, 0x1C744C, 0x1C745C, 0x1C7488, 0x220AE4, 0x220BE8, 0x2035F0}
check(hooks <= set(diff), "chain guard hooks missing from the diff")
print(f"{'all tests passed' if not FAILS else f'{len(FAILS)} FAILURES'} ({len(diff)} patched bytes)")
sys.exit(1 if FAILS else 0)

"""Option A version of the original guards test (not kept): animated DSi banners are loaded non-animated (0x1326a8), so the
animated-path scenarios expect the non-animated end state instead of stock equality; the rest is unchanged.

Unicorn tests for the allocation-failure guards (HOME Menu EUR 11.17.0-50E), stock vs patched.
  uv run --no-project --with unicorn --with capstone -- python -I targets/home/11.17.0-eur/tests/test_guards_a.py STOCK.code PATCHED.code
Runs the TWL tile loader 0x132458 (and, more lightly, the attach function 0x2035c4 and the drivers
0x1c7748 / 0x1c7d74) with every callee mocked at its entry. The allocator mock fails on request; every
mock that receives a buffer records a NULL use. Patched must never use a NULL buffer and must end in the
documented fallback state; with every allocation succeeding, stock and patched must produce the same call
log and the same banner object bytes.
"""
import struct
import sys
from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm_const import *

STOCK = open(sys.argv[1], "rb").read()
PATCHED = open(sys.argv[2], "rb").read()
BASE = 0x100000
LOADER, ATTACH, DRV1, DRV2 = 0x132458, 0x2035C4, 0x1C7748, 0x1C7D74
RET = 0xDEAD0000
STACK, HEAP0, OBJ, CACHE, MAIN, TILES, CTX, TIDBUF = (0x0FFF0000, 0x09000000, 0x08000000, 0x08010000, 0x08100000,
                                                      0x08200000, 0x08300000, 0x08310000)
HEAP_ID = 0x32EAC8
TID = (0x4A505041, 0x00048004)
MEDIA = 1
CRC = 0x1234
REGION = 0x00000004  # DSi header +0x1b0 region flags: Europe
FAILS = []

# callee addresses
ALLOC, ALLOC2, FREE, FREE2 = 0x235800, 0x236454, 0x2353C4, 0x236424
CLEAR, MEMSET, MEMCPY_A, MEMCPY_B = 0x233F10, 0x232774, 0x2362C8, 0x237B64
CRC16, VALIDATE, FS_HEADER, FS_BANNER, FS_SUB = 0x21E108, 0x21E02C, 0x21DFF0, 0x21DFB8, 0x1372B4
LANGTAB, GETLANG, GETREGION, PICKTITLE, STRCPY16, LOOKUP, CODE_A, CONVERT = (0x21DE08, 0x21E1E8, 0x232574, 0x226480,
                                                                              0x2228C0, 0x13D820, 0x220A14, 0x143B34)
MAIN_PTR, LOCK, UNLOCK, HEAPID, SELCTX, REGIONCHK, SEL_RESET = 0x226780, 0x234BB0, 0x234B68, 0x226828, 0x21BD60, 0x223CE4, 0x1C6F60
CACHE_LOOKUP, CACHE_WRITE, CTOR_TWL, CTOR_OTHER, RELEASE = 0x1C3984, 0x1C39B0, 0x245DA4, 0x245CFC, 0x204D18
BANNER_VTABLE = 0x320EE8


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
        print("FAIL:", msg)


def header_template():
    h = bytearray(0x378)
    h[0x12] = 0  # no extra flags -> 0x13d820 not consulted
    struct.pack_into("<H", h, 0x15E, CRC)
    struct.pack_into("<I", h, 0x1B0, REGION)
    return bytes(h)


def banner_template(animated=True):
    b = bytearray(0x23C0)
    b[0] = 3
    b[1] = 1 if animated else 0
    for i in range(0x20, 0x240):
        b[i] = (i * 3) & 0xFF  # static icon bitmap + palette
    for i in range(0x240, 0x340):
        b[i] = 0x41  # title strings (UTF-16 garbage is fine for the mock copy)
    for i in range(0x1240, 0x1240 + 0x1180):
        b[i] = (i * 5) & 0xFF  # ROM banner animation
    b[0x1240 + 0x1100] = 1  # animation sequence present
    return bytes(b)


def subbanner_template(seq_present=True, crc=CRC):
    s = bytearray(0x4000)
    struct.pack_into("<H", s, 8, crc)
    for i in range(0x20, 0x20 + 0x1180):
        s[i] = (i * 7) & 0xFF
    s[0x20 + 0x1100] = 1 if seq_present else 0
    return bytes(s)


class Env:
    """One emulator with mocked callees. fail: set of (size, nth occurrence) allocations that return NULL."""

    def __init__(self, code, fail=(), fs_sub_result=0, fs_banner_result=0, sub_crc_ok=True, animated=True,
                 seq_present=True, validate=1, attach_result=1, region_ok=0):
        mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        mu.mem_map(BASE, 0x284000)
        mu.mem_map(0x08000000, 0x400000)
        mu.mem_map(HEAP0, 0x400000)
        mu.mem_map(STACK, 0x10000)
        mu.mem_map(RET & ~0xFFF, 0x1000)
        mu.mem_write(BASE, code)
        mu.reg_write(UC_ARM_REG_C1_C0_2, mu.reg_read(UC_ARM_REG_C1_C0_2) | 0xF00000)
        mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        self.mu, self.fail, self.log, self.nulls = mu, set(fail), [], []
        self.allocs, self.frees, self.seen = [], [], {}
        self.bump = HEAP0
        self.fs_sub_result, self.fs_banner_result, self.sub_crc_ok = fs_sub_result, fs_banner_result, sub_crc_ok
        self.animated, self.seq_present, self.validate_result = animated, seq_present, validate
        self.attach_result, self.region_ok = attach_result, region_ok
        self.header, self.banner = header_template(), banner_template(animated)
        self.sub = subbanner_template(seq_present, CRC if sub_crc_ok else CRC ^ 0xFFFF)
        self.w32(0x32F5D4, MAIN)
        self.w32(0x32F5CC, MAIN)
        self.w32(0x32F5BC, 0x08320000)
        self.w32(MAIN + 0x398F8, TILES)
        mu.mem_write(CTX + 0x3E, struct.pack("<h", 99))  # selected tile index, never ours
        self.w32(TIDBUF, *TID)
        mu.mem_write(TIDBUF + 8, bytes([MEDIA]))
        mu.hook_add(UC_HOOK_CODE, self.on_code)

    # helpers
    def w32(self, addr, *vals):
        self.mu.mem_write(addr, b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in vals))

    def r32(self, addr, n=1):
        return list(struct.unpack(f"<{n}I", self.mu.mem_read(addr, 4 * n)))

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

    def do_alloc(self, tag, size):
        n = self.seen.get(size, 0) + 1
        self.seen[size] = n
        if (size, n) in self.fail:
            self.log.append((tag, size, "NULL"))
            return 0
        p, self.bump = self.bump, self.bump + ((size + 15) & ~15) + 16
        self.allocs.append((size, p))
        self.log.append((tag, size, "ok"))
        return p

    def on_code(self, mu, addr, size, ud):
        if addr == ALLOC:
            sz, heap, align = self.args(3)
            check(heap == HEAP_ID, f"alloc with heap {heap:#x}")
            self.ret(self.do_alloc("alloc", sz))
        elif addr == ALLOC2:
            sz, heap, align = self.args(3)
            self.ret(self.do_alloc("alloc2", sz))
        elif addr in (FREE, FREE2):
            (p,) = self.args(1)
            check(p == 0 or p in [a for _, a in self.allocs], f"free of unknown pointer {p:#x}")
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
            self.ret(self.validate_result)
        elif addr == FS_HEADER:
            p, media = self.args(2)
            self.null("fs:GetLegacyRomHeader2", p)
            self.fill(p, self.header)
            self.log.append(("fs_header",))
            self.ret(0)
        elif addr == FS_BANNER:
            p, media = self.args(2)
            self.null("fs:GetLegacyBannerData", p)
            self.fill(p, self.banner)
            self.log.append(("fs_banner", self.fs_banner_result))
            self.ret(self.fs_banner_result)
        elif addr == FS_SUB:
            p, media = self.args(2)
            self.null("fs:GetLegacySubBannerData", p)
            self.fill(p, self.sub)
            self.log.append(("fs_sub", self.fs_sub_result))
            self.ret(self.fs_sub_result)
        elif addr == LANGTAB:
            d, _, b = self.args(3)
            self.null("langtab", b)
            self.log.append(("langtab",))
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
        elif addr == LOOKUP:
            self.ret(0xFFFFFFFF)
        elif addr == CODE_A:
            self.log.append(("code_a",))
            self.ret(0x77)
        elif addr == CONVERT:
            d, s, t = self.args(3)
            self.null("convert(0x143b34)", d - 0x480 if d >= 0x480 else d, s, t)
            if d >= 0x480 + HEAP0 and t:
                mu.mem_write(d, bytes([0xCC] * 0x1000))
            self.log.append(("convert",))
            self.ret()
        # attach / driver callees
        elif addr == MAIN_PTR:
            self.ret(MAIN)
        elif addr in (LOCK, UNLOCK):
            self.log.append(("lock" if addr == LOCK else "unlock",))
            self.ret()
        elif addr == HEAPID:
            self.ret(HEAP_ID)
        elif addr == SELCTX:
            self.ret(CTX)
        elif addr == REGIONCHK:
            self.log.append(("regionchk", *self.args(2)))
            self.ret(self.region_ok)
        elif addr == SEL_RESET:
            self.log.append(("sel_reset",))
            self.ret()
        elif addr == CACHE_LOOKUP:
            cache, buf = self.args(2)
            self.null("cache_lookup(0x1c3984)", buf)
            self.log.append(("cache_lookup",))
            self.ret(1)
        elif addr == CACHE_WRITE:
            self.log.append(("cache_write",))
            self.ret()
        elif addr in (CTOR_TWL, CTOR_OTHER):
            obj = self.args(1)[0]
            self.w32(obj, BANNER_VTABLE)
            self.log.append(("ctor", "twl" if addr == CTOR_TWL else "other"))
            self.ret(obj)
        elif addr == ATTACH and self.mock_attach:
            main, idx, banner = self.args(3)
            self.null("attach(0x2035c4) banner", banner)
            self.log.append(("attach",))
            self.ret(self.attach_result)
        elif addr == DRV2 and self.mock_drv2:
            self.log.append(("drv2",))
            self.ret(0)
        elif addr == RELEASE:
            self.log.append(("release", self.args(2)[1]))
            self.ret()

    mock_attach = False
    mock_drv2 = False

    def run(self, fn, *regs, stack_words=()):
        mu = self.mu
        self.log = []
        sp = STACK + 0x8000
        for i, w in enumerate(stack_words):
            self.w32(sp + 4 * i, w)
        mu.reg_write(UC_ARM_REG_SP, sp)
        mu.reg_write(UC_ARM_REG_LR, RET)
        for r, v in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), regs):
            mu.reg_write(r, v)
        try:
            mu.emu_start(fn, RET, count=500000)
        except UcError as e:
            self.log.append(("FAULT", str(e), hex(mu.reg_read(UC_ARM_REG_PC))))
            return False
        ok = mu.reg_read(UC_ARM_REG_PC) == RET and mu.reg_read(UC_ARM_REG_SP) == sp
        if not ok:
            self.log.append(("BAD_RETURN", hex(mu.reg_read(UC_ARM_REG_PC))))
        return ok

    # loader
    def new_obj(self):
        self.mu.mem_write(OBJ, bytes([0x55]) * 0x1C8)  # heap garbage, as 0x235800 leaves it
        self.w32(OBJ, BANNER_VTABLE, 0, *TID)
        self.mu.mem_write(OBJ + 0x10, bytes([MEDIA]))
        for off in (0x198, 0x1B8, 0x1C0, 0x1C4):
            self.w32(OBJ + off, 0)
        for off in range(0x1A8, 0x1B5):
            self.mu.mem_write(OBJ + off, b"\0")

    def load(self, cache=0):
        self.new_obj()
        return self.run(LOADER, OBJ, HEAP_ID, cache)

    def obj(self):
        return bytes(self.mu.mem_read(OBJ, 0x1C8))

    def kind(self):
        return self.r32(OBJ + 0x1BC)[0]

    def region(self):
        return self.r32(OBJ + 0x1B8)[0]

    def buf(self, off):
        return self.r32(OBJ + off)[0]

    def payload(self, p, n):
        return bytes(self.mu.mem_read(p, n))


def run_both(name, cache=False, **kw):
    out = []
    for code in (STOCK, PATCHED):
        e = Env(code, **kw)
        c = 0
        if cache:
            e.mu.mem_write(CACHE, e.header + e.banner)
            c = CACHE
        ok = e.load(c)
        out.append((e, ok))
    return out[0][0], out[1][0], out[0][1], out[1][1]


def same(name, es, ep):
    check(es.log == ep.log, f"{name}: logs differ\n  stock   {es.log}\n  patched {ep.log}")
    check(es.obj() == ep.obj(), f"{name}: object bytes differ")
    check(es.nulls == [] and ep.nulls == [], f"{name}: NULL use {es.nulls} {ep.nulls}")
    for off in (0x1C0, 0x1C4):
        ps, pp = es.buf(off), ep.buf(off)
        if ps and pp:
            check(es.payload(ps, 0x1680) == ep.payload(pp, 0x1680), f"{name}: buffer +{off:#x} content differs")


def patched_ok(name, ep, ok):
    check(ok, f"{name} patched: did not return cleanly: {ep.log[-1:]}")
    check(ep.nulls == [], f"{name} patched: NULL use {ep.nulls}")
    outstanding = [s for s, a in ep.allocs if a not in ep.frees]
    return outstanding


def stock_bad(name, es, ok):
    check(not ok or es.nulls, f"{name} stock: expected a NULL use or fault, log {es.log}")


# ---- option A: every DSi banner takes the non-animated path (0x1326a8 forced to kind 2) ---------------
def static_a(name, ep, okp, convert=True):
    """Patched ends as a non-animated tile: kind 2, DS region rule, static buffer B kept, no sub-banner path."""
    outstanding = patched_ok(name, ep, okp)
    check(ep.kind() == 2 and ep.region() == 0x7FFFFFFF, f"{name} patched: kind {ep.kind()} region {ep.region():#x}")
    check(ep.buf(0x1C4) == 0 and ep.buf(0x1C0) != 0, f"{name} patched: buffers {ep.buf(0x1C0):#x} {ep.buf(0x1C4):#x}")
    check(("fs_sub", 0) not in ep.log and not any(c[0] == "alloc" and c[1] == 0x4000 for c in ep.log), f"{name} patched: sub-banner path {ep.log}")
    if convert:
        check(("convert",) in ep.log, f"{name} patched: icon not converted {ep.log}")
    check(outstanding == [0x1680], f"{name} patched: kept {outstanding}")


# all allocations succeed: animated banners become non-animated, the rest is identical to stock
for name, kw in (("A1 animated, banner.sav ok", {}), ("A2 banner.sav crc mismatch", {"sub_crc_ok": False}),
                 ("A3 banner.sav fs error", {"fs_sub_result": 0xC8804464}), ("A4 animated flag but no sequence", {"seq_present": False}),
                 ("A6 cache hit", {"cache": True})):
    es, ep, oks, okp = run_both(name, **kw)
    check(oks, f"{name} stock: did not return cleanly")
    static_a(name, ep, okp)

es, ep, oks, okp = run_both("A5 static icon title", animated=False)
same("A5", es, ep)
check(ep.kind() == 2 and ep.region() == 0x7FFFFFFF and ("convert",) in ep.log and ("fs_sub", 0) not in ep.log, f"A5: {ep.log}")

es, ep, oks, okp = run_both("A7 banner fs error", fs_banner_result=0xC8804464)
same("A7", es, ep)
check(ep.kind() == 2 and ep.region() == 0, f"A7: kind {ep.kind()} region {ep.region():#x}")

es, ep, oks, okp = run_both("A8 banner invalid", validate=0)
same("A8", es, ep)

# ---- one allocation fails at a time -------------------------------------------------------------------
def bail_case(name, no_fs=False, **kw):
    """Patched must end in the rejected-banner state: kind 0, region 0, no buffers, nothing leaked."""
    es, ep, oks, okp = run_both(name, **kw)
    stock_bad(name, es, oks)
    outstanding = patched_ok(name, ep, okp)
    check(ep.kind() == 0 and ep.region() == 0, f"{name} patched: kind {ep.kind()} region {ep.region():#x}")
    check(ep.buf(0x1C0) == 0 and ep.buf(0x1C4) == 0, f"{name} patched: buffers {ep.buf(0x1C0):#x} {ep.buf(0x1C4):#x}")
    check(outstanding == [], f"{name} patched: leaked {outstanding}")
    if no_fs:  # header or banner buffer missing: fs must not be asked at all
        check(not [c for c in ep.log if c[0].startswith("fs_")], f"{name} patched: fs called {ep.log}")
    return es, ep

bail_case("N1 header buffer 0x378 NULL", no_fs=True, fail={(0x378, 1)})
bail_case("N2 banner buffer 0x23c0 NULL", no_fs=True, fail={(0x23C0, 1)})
bail_case("N3 both NULL", no_fs=True, fail={(0x378, 1), (0x23C0, 1)})
es, ep = bail_case("N4 banner buffer NULL, cache hit", no_fs=True, fail={(0x23C0, 1)}, cache=True)
check(("memcpy", 0x378) not in ep.log and ("memcpy", 0x23C0) not in ep.log, f"N4 patched: copied into NULL {ep.log}")

# first 0x1680 NULL: under option A that is the static buffer B -> rejected state (stock: NULL use in the animated path)
bail_case("N5 first 0x1680 NULL (option A: buffer B)", fail={(0x1680, 1)})

# 0x4000 sub-banner buffer and the second 0x1680 are never requested under option A -> normal non-animated tile
es, ep, oks, okp = run_both("N6 sub-banner buffer NULL", fail={(0x4000, 1)})
stock_bad("N6", es, oks)
static_a("N6", ep, okp)
es, ep, oks, okp = run_both("N8 second 0x1680 NULL", fail={(0x1680, 2)}, seq_present=False)
stock_bad("N8", es, oks)
static_a("N8", ep, okp)

# B NULL, static title
es, ep = bail_case("N7 static buffer B NULL (kind 2 path)", fail={(0x1680, 1)}, animated=False)
check(("convert",) not in ep.log and ("alloc2", 0x1800, "ok") not in ep.log, f"N7 patched: {ep.log}")

# T NULL -> keep the zeroed static buffer, skip the conversion (static and animated titles alike)
for name, kw in (("N9 work buffer T NULL", {"animated": False}), ("N9a work buffer T NULL, animated title", {})):
    es, ep, oks, okp = run_both(name, fail={(0x1800, 1)}, **kw)
    if kw.get("animated") is False:  # stock reaches T only on the non-animated path
        stock_bad(name, es, oks)
    outstanding = patched_ok(name, ep, okp)
    check(ep.kind() == 2 and ep.region() == 0x7FFFFFFF and ep.buf(0x1C0) != 0 and ("convert",) not in ep.log, f"{name} patched: {ep.log}")
    check(ep.payload(ep.buf(0x1C0), 0x1680) == bytes(0x1680) and outstanding == [0x1680] and ("free", "NULL") in ep.log, f"{name} patched: B not blank or leak {outstanding}")

# everything fails
bail_case("N10 all NULL", no_fs=True, fail={(0x378, 1), (0x23C0, 1), (0x1680, 1), (0x1680, 2), (0x4000, 1), (0x1800, 1)})
bail_case("N11 A and B NULL", fail={(0x1680, 1), (0x1680, 2)})

# ---- attach 0x2035c4 with a NULL banner object -------------------------------------------------------
for code, name in ((STOCK, "stock"), (PATCHED, "patched")):
    e = Env(code)
    ok = e.run(ATTACH, MAIN, 5, 0, 0)
    if name == "patched":
        check(ok and e.mu.reg_read(UC_ARM_REG_R0) == 0 and e.log == [("lock",), ("unlock",)], f"AT1 patched: {ok} {e.log}")
    else:
        check(not ok, f"AT1 stock: expected a fault on the NULL banner, log {e.log}")
# valid banner, region rejected: identical
logs = []
for code in (STOCK, PATCHED):
    e = Env(code)
    e.new_obj()
    e.w32(OBJ + 0x1BC, 2)
    ok = e.run(ATTACH, MAIN, 5, OBJ, 0)
    check(ok and e.mu.reg_read(UC_ARM_REG_R0) == 0, "AT2: unexpected return")
    logs.append(e.log)
check(logs[0] == logs[1] and ("regionchk", 0, 0) in logs[0], f"AT2: {logs}")

# ---- drivers with a NULL 0x36c0 buffer ---------------------------------------------------------------
def drv1(code, fail):
    e = Env(code, fail=fail, attach_result=1)
    e.mock_attach = e.mock_drv2 = True
    ok = e.run(DRV1, MAIN, 7, TIDBUF, 0x08320000, stack_words=(0x11, 0x22))
    return e, ok

es, _ = drv1(STOCK, set())
ep, _ = drv1(PATCHED, set())
check(es.log == ep.log and ("cache_lookup",) in ep.log and ("attach",) in ep.log and es.nulls == ep.nulls == [], f"D1 all ok: {es.log} / {ep.log}")
es, oks = drv1(STOCK, {(0x36C0, 1)})
ep, okp = drv1(PATCHED, {(0x36C0, 1)})
check("cache_lookup(0x1c3984)" in es.nulls, f"D1 stock: expected NULL buffer to the cache copy, {es.nulls}")
check(okp and ep.nulls == [] and ("cache_lookup",) not in ep.log and ("drv2",) in ep.log and ("free", "NULL") in ep.log, f"D1 patched: {ep.log} {ep.nulls}")

def drv2(code, fail):
    e = Env(code, fail=fail, attach_result=1)
    e.mock_attach = True
    ok = e.run(DRV2, MAIN, 7, TIDBUF, 0x08320000, stack_words=(0x11, 0x22))
    return e, ok

es, oks = drv2(STOCK, set())
ep, okp = drv2(PATCHED, set())
strip = lambda log: [c for c in log if c != ("memset", 0x36C0)]
check(oks and okp and strip(es.log) == strip(ep.log) and es.log.count(("memset", 0x36C0)) == 2 and ep.log.count(("memset", 0x36C0)) == 1,
      f"D2 all ok: {es.log} / {ep.log}")
check(("fs_header",) in ep.log and ("attach",) in ep.log and ("cache_write",) in ep.log and ep.nulls == [], f"D2 patched: {ep.log}")
es, oks = drv2(STOCK, {(0x36C0, 1)})
ep, okp = drv2(PATCHED, {(0x36C0, 1)})
check(es.nulls, f"D2 stock: expected NULL use, {es.log}")
check(okp and ep.nulls == [] and not [c for c in ep.log if c[0].startswith("fs_")] and ep.log[-1] == ("free", "NULL"), f"D2 patched: {ep.log}")

# driver with a NULL banner object: the attach guard makes the stock driver code safe
es, oks = drv2(STOCK, {(0x1C8, 1)})
es.mock_attach = False
ep, okp = drv2(PATCHED, {(0x1C8, 1)})
ep.mock_attach = False
check(okp, f"D3 patched: {ep.log}")

# ---- patched bytes: only the generator records differ ---------------------------------------------
diff = sorted(i + BASE for i in range(len(STOCK)) if STOCK[i] != PATCHED[i])
guard_sites = {0x1324B0, 0x1326DC, 0x13279C, 0x132800, 0x2035F0, 0x1C7794}
check(guard_sites <= set(diff), "guard hooks missing from the diff")
print(f"{'all tests passed' if not FAILS else f'{len(FAILS)} FAILURES'} ({len(diff)} patched bytes)")
sys.exit(1 if FAILS else 0)

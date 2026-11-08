"""Shared helpers for the targets: ARM encoders, cave and record helpers, and the checked IPS build.

A record is (address, old bytes, new bytes) with a virtual address of the title's .code (file offset = address -
BASE). build() checks every old byte against the dump, refuses overlapping records, and checks that the patched
image differs from the dump only inside the records.
"""
import json

BASE = 0x100000
NOP = 0xE1A00000


def arm_imm(value):
    for rot in range(16):
        imm8 = ((value << (2 * rot)) | (value >> (32 - 2 * rot))) & 0xFFFFFFFF if rot else value
        if imm8 < 0x100:
            return rot << 8 | imm8
    raise ValueError(f"{value} is not an ARM immediate")


def dp(base, rn, rd, value):
    return base | rn << 16 | rd << 12 | arm_imm(value)


def cmp_(rn, v, cond=0xE):
    return dp(cond << 28 | 0x03500000, rn, 0, v)


def mov(rd, v, cond=0xE):
    return dp(cond << 28 | 0x03A00000, 0, rd, v)


def rsb(rd, rn, v):
    return dp(0xE2600000, rn, rd, v)


def str_imm(rt, rn, off):
    assert off < 0x1000
    return 0xE5800000 | rn << 16 | rt << 12 | off


def branch(src, dst, cond=0xE, link=False):
    off = (dst - (src + 8)) >> 2
    assert -0x800000 <= off < 0x800000
    return cond << 28 | (0x0B000000 if link else 0x0A000000) | (off & 0xFFFFFF)


def adr(rd, src, dst):  # add rd, pc, #(dst - src - 8)
    d = dst - (src + 8)
    assert 0 <= d < 0x100 and d % 4 == 0
    return 0xE28F0000 | rd << 12 | d


def words(*ws):
    return b"".join(w.to_bytes(4, "little") for w in ws)


def syms(path, base):
    """Symbol offsets of an assembled cave (JSON {name: offset}), made absolute."""
    return {k: base + v for k, v in json.loads(path.read_text()).items()}


def cave(code, addr, data, end):
    """Record that puts `data` into the zero-filled code cave at `addr` (must end by `end`)."""
    assert len(data) % 4 == 0 and addr + len(data) <= end, f"cave at {addr:#x} does not fit"
    old = code[addr - BASE:addr - BASE + len(data)]
    assert old == bytes(len(data)), f"cave at {addr:#x} is not empty"
    return (addr, old, data)


def build_ips(recs):
    out = bytearray(b"PATCH")
    for addr, _, new in sorted(recs):
        off = addr - BASE
        assert off < 0x1000000 and off != 0x454F46 and 0 < len(new) <= 0xFFFF
        out += off.to_bytes(3, "big") + len(new).to_bytes(2, "big") + new
    return bytes(out + b"EOF")


def apply_ips(ips, data):
    data, i = bytearray(data), 5
    while ips[i:i + 3] != b"EOF":
        off, size = int.from_bytes(ips[i:i + 3], "big"), int.from_bytes(ips[i + 3:i + 5], "big")
        data[off:off + size] = ips[i + 5:i + 5 + size]
        i += 5 + size
    return bytes(data)


def build(name, code, recs):
    """Check the records against the dump and return (ips, patched image)."""
    for addr, old, new in recs:
        assert len(old) == len(new), f"{name}: {addr:#x}: old/new length differ"
        assert code[addr - BASE:addr - BASE + len(old)] == old, f"{name}: {addr:#x}: old bytes differ from the dump"
    spans = sorted((a, a + len(new)) for a, _, new in recs)
    for (a0, e0), (a1, _) in zip(spans, spans[1:]):
        assert e0 <= a1, f"{name}: overlap {a0:#x}..{e0:#x} / {a1:#x}"
    ips = build_ips(recs)
    patched = apply_ips(ips, code)
    allowed = {addr - BASE + k for addr, _, new in recs for k in range(len(new))}
    assert len(patched) == len(code) and all(code[i] == patched[i] for i in range(len(code)) if i not in allowed)
    return ips, patched

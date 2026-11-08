"""Unit test for the amguard null-buffer guards on the three AM request wrappers.

Runs each wrapper in Unicorn on the stock dump and on the dump with amguard_records() of
target.py applied, with a valid output pointer and with a null one, and compares behaviour.

Run: uv run --no-project --with unicorn --with capstone -- python -I targets/home/11.17.0-eur/tests/test_amguard.py dumps/0004003000009802.dec.code
"""

import importlib.util
import struct
import sys
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from unicorn import UC_ARCH_ARM, UC_HOOK_INTR, UC_HOOK_MEM_WRITE, UC_MODE_ARM, Uc, UcError
from unicorn.arm_const import (
    UC_ARM_REG_C13_C0_3,
    UC_ARM_REG_LR,
    UC_ARM_REG_PC,
    UC_ARM_REG_R0,
    UC_ARM_REG_R1,
    UC_ARM_REG_R2,
    UC_ARM_REG_R3,
    UC_ARM_REG_R4,
    UC_ARM_REG_R5,
    UC_ARM_REG_R6,
    UC_ARM_REG_R7,
    UC_ARM_REG_R8,
    UC_ARM_REG_R9,
    UC_ARM_REG_R10,
    UC_ARM_REG_R11,
    UC_ARM_REG_R12,
    UC_ARM_REG_SP,
    UC_CPU_ARM_11MPCORE,
)

DUMP = Path(sys.argv[1])

CODE_BASE, CODE_END = 0x100000, 0x390000
STACK_BASE, STACK_SIZE = 0x08000000, 0x10000
SP0 = STACK_BASE + 0x8000
TLS_BASE, TLS_SIZE = 0x1FF82000, 0x1000
HEAP_BASE, HEAP_SIZE = 0x30000000, 0x10000
RET_ADDR = 0x00F00000  # sentinel return address, its own mapped page

CMD_OFF = 0x80
CMD_WORDS = 8  # TLS+0x80..+0xa0
SVC_SEND_SYNC_REQUEST = 0xEF000032
RESULT_AM_OUT_OF_MEMORY = 0xC86083F3

CALLEE_SAVED = [UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
                UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11]

COUNT_PTR = HEAP_BASE + 0x000
OUT_PTR = HEAP_BASE + 0x100
IDS_IN_PTR = HEAP_BASE + 0x800
TITLE_IDS = [0x0004000000030800, 0x0004000000055E00, 0x000400000017C100]


def load_target():
    """This target's target.py (which imports patchkit from the repo root)."""
    here = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(here.parents[2]))
    spec = importlib.util.spec_from_file_location("target", here / "target.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_images():
    stock = bytearray(DUMP.read_bytes())
    stock.extend(b"\0" * (CODE_END - CODE_BASE - len(stock)))
    patched = bytearray(stock)
    for addr, old, new in load_target().amguard_records(DUMP.read_bytes()):
        off = addr - CODE_BASE
        if patched[off:off + len(old)] != old:
            raise SystemExit(f"amguard_records: old bytes do not match dump at {addr:#x}")
        patched[off:off + len(new)] = new
    return bytes(stock), bytes(patched)


def reply_for(uc, req):
    """Fake AM reply: header, result 0, plausible outputs; mimic the kernel copy-out."""
    cmd = req[0] >> 16
    if cmd in (0x0002, 0x0009):  # list into ids buffer: count out
        out = req[0x10 // 4]
        n = min(len(TITLE_IDS), req[1])
        if out:
            uc.mem_write(out, b"".join(struct.pack("<Q", t) for t in TITLE_IDS[:n]))
        return [(cmd << 16) | 0x80, 0, n]
    if cmd == 0x0003:  # title infos: no normal outputs beyond result
        out, count = req[0x18 // 4], req[2]
        if out:
            info = b"".join(struct.pack("<QQII", TITLE_IDS[i % 3], 0x123000 + i, 0x100 * i, 0) for i in range(count))
            uc.mem_write(out, info)
        return [(cmd << 16) | 0x40, 0]
    raise AssertionError(f"unexpected AM command header {req[0]:#010x}")


def run(image, entry, args):
    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.ctl_set_cpu_model(UC_CPU_ARM_11MPCORE)
    uc.mem_map(CODE_BASE, CODE_END - CODE_BASE)
    uc.mem_write(CODE_BASE, image)
    uc.mem_map(STACK_BASE, STACK_SIZE)
    uc.mem_write(STACK_BASE, b"\xa5" * STACK_SIZE)
    uc.mem_map(TLS_BASE, TLS_SIZE)
    uc.mem_map(HEAP_BASE, HEAP_SIZE)
    uc.mem_write(HEAP_BASE, b"\xcc" * HEAP_SIZE)
    uc.mem_write(IDS_IN_PTR, b"".join(struct.pack("<Q", t) for t in TITLE_IDS))
    uc.mem_map(RET_ADDR, 0x1000)
    uc.reg_write(UC_ARM_REG_C13_C0_3, TLS_BASE)

    for reg, val in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
        uc.reg_write(reg, val)
    for i, reg in enumerate(CALLEE_SAVED + [UC_ARM_REG_R12]):
        uc.reg_write(reg, 0x44440000 + 4 + i)
    uc.reg_write(UC_ARM_REG_SP, SP0)
    uc.reg_write(UC_ARM_REG_LR, RET_ADDR)
    saved_in = [uc.reg_read(r) for r in CALLEE_SAVED]
    tls_before = bytes(uc.mem_read(TLS_BASE, TLS_SIZE))
    heap_before = bytes(uc.mem_read(HEAP_BASE, HEAP_SIZE))

    writes, svcs, errors = [], [], []

    def on_write(uc, _access, addr, size, value, _ud):
        if not STACK_BASE <= addr < STACK_BASE + STACK_SIZE:
            writes.append((addr, size, value & ((1 << (8 * size)) - 1)))

    def on_intr(uc, intno, _ud):
        pc = uc.reg_read(UC_ARM_REG_PC)
        insn = struct.unpack("<I", uc.mem_read(pc - 4, 4))[0]
        if intno != 2 or insn != SVC_SEND_SYNC_REQUEST:
            errors.append(f"unexpected interrupt {intno} insn {insn:#010x} at {pc - 4:#x}")
            uc.emu_stop()
            return
        req = list(struct.unpack(f"<{CMD_WORDS}I", uc.mem_read(TLS_BASE + CMD_OFF, 4 * CMD_WORDS)))
        svcs.append(req)
        reply = reply_for(uc, req)
        uc.mem_write(TLS_BASE + CMD_OFF, struct.pack(f"<{len(reply)}I", *reply))
        uc.reg_write(UC_ARM_REG_R0, 0)

    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_INTR, on_intr)
    try:
        uc.emu_start(entry, RET_ADDR, count=10_000)
    except UcError as e:
        errors.append(f"emu error {e} at {uc.reg_read(UC_ARM_REG_PC):#x}")
    pc = uc.reg_read(UC_ARM_REG_PC)
    if pc != RET_ADDR and not errors:
        errors.append(f"did not return, pc={pc:#x}")

    return {
        "r0": uc.reg_read(UC_ARM_REG_R0),
        "sp": uc.reg_read(UC_ARM_REG_SP),
        "callee_ok": [uc.reg_read(r) for r in CALLEE_SAVED] == saved_in,
        "writes": writes,
        "svcs": svcs,
        "errors": errors,
        "tls_changed": bytes(uc.mem_read(TLS_BASE, TLS_SIZE)) != tls_before,
        "heap": bytes(uc.mem_read(HEAP_BASE, HEAP_SIZE)),
        "heap_changed": bytes(uc.mem_read(HEAP_BASE, HEAP_SIZE)) != heap_before,
    }


def fmt_words(words):
    return " ".join(f"{w:08x}" for w in words)


def frame_problems(res, who):
    probs = [f"{who}: {e}" for e in res["errors"]]
    if res["sp"] != SP0:
        probs.append(f"{who}: sp {res['sp']:#x} != {SP0:#x}")
    if not res["callee_ok"]:
        probs.append(f"{who}: r4-r11 not preserved")
    return probs


# (entry, name, args with valid buffer, index of the out-pointer arg, request desc/ptr offsets)
WRAPPERS = [
    (0x10e738, "AM 0x0002 list", [COUNT_PTR, OUT_PTR, 8, 1], 1, (0x0c, 0x10)),
    (0x14a700, "AM 0x0009 list", [COUNT_PTR, OUT_PTR, 8, 0], 1, (0x0c, 0x10)),
    (0x14a754, "AM 0x0003 infos", [OUT_PTR, 1, IDS_IN_PTR, 2], 0, (0x14, 0x18)),
]


def main():
    stock_img, patched_img = load_images()
    cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    failures = 0

    def report(ok, label, detail):
        nonlocal failures
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'} {label}: {detail}")

    for entry, name, args, out_idx, (desc_off, ptr_off) in WRAPPERS:
        off = entry - CODE_BASE
        insn = next(cs.disasm(patched_img[off:off + 4], entry))
        print(f"---- {entry:#x} {name}: patched entry '{insn.mnemonic} {insn.op_str}'")

        # (a) valid output pointer
        s = run(stock_img, entry, args)
        p = run(patched_img, entry, args)
        probs = frame_problems(s, "stock") + frame_problems(p, "patched")
        if len(s["svcs"]) != 1:
            probs.append(f"stock made {len(s['svcs'])} svc calls")
        if s["svcs"] != p["svcs"]:
            probs.append("request words differ")
        elif s["svcs"] and s["svcs"][0][ptr_off // 4] != args[out_idx]:
            probs.append(f"request +{ptr_off:#x} is not the out pointer")
        if s["r0"] != p["r0"]:
            probs.append(f"r0 differs: stock {s['r0']:#x} patched {p['r0']:#x}")
        if s["writes"] != p["writes"] or s["heap"] != p["heap"]:
            probs.append("non-stack writes differ")
        req = p["svcs"][0] if p["svcs"] else []
        report(not probs, f"{entry:#x} (a) valid ptr",
               "; ".join(probs) or f"r0={p['r0']:#x} writes={len(p['writes'])} req=[{fmt_words(req)}]")

        # (b) output pointer 0
        null_args = list(args)
        null_args[out_idx] = 0
        p = run(patched_img, entry, null_args)
        probs = frame_problems(p, "patched")
        if p["svcs"]:
            probs.append(f"patched made {len(p['svcs'])} svc calls")
        if p["r0"] != RESULT_AM_OUT_OF_MEMORY:
            probs.append(f"r0 {p['r0']:#x} != {RESULT_AM_OUT_OF_MEMORY:#x}")
        if p["writes"] or p["heap_changed"] or p["tls_changed"]:
            probs.append(f"wrote outside stack: {[(hex(a), n, hex(v)) for a, n, v in p['writes']]}")
        report(not probs, f"{entry:#x} (b) null ptr", "; ".join(probs) or f"svc=0 r0={p['r0']:#x} writes=0")

        s = run(stock_img, entry, null_args)
        req = s["svcs"][0] if s["svcs"] else []
        sent = f"desc +{desc_off:#x}={req[desc_off // 4]:#x} ptr +{ptr_off:#x}={req[ptr_off // 4]:#x}" if req else "-"
        print(f"INFO {entry:#x} (b) stock null ptr: svc={len(s['svcs'])} {sent} "
              f"r0={s['r0']:#x} writes={len(s['writes'])} errors={s['errors'] or '-'} req=[{fmt_words(req)}]")

    print("RESULT: OK" if failures == 0 else f"RESULT: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

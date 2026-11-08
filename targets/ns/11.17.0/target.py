"""NS sysmodule, decrypted .code of 0004013000008002 v23553 (11.17.0, dumped from an EUR New 3DS XL).

NS is one title for every region (3dbrew), so this dump probably matches other regions too; --identify tells.
Keeps a launched DSiWare title that sits past AM position 77 in the TWL title list handed to TWL_FIRM
(caves/cave256.S); without it DS titles from position 78 on do not start. Independent of N. Why and how:
docs/findings.md.
"""
import struct
from pathlib import Path

from patchkit import BASE, branch, cave, words

SHA256 = "0e9c322edb02e4a7373282a7cd3e66d2e66d9e8832a0775f84fbbe34c81688a0"
CAVES = Path(__file__).resolve().parent / "caves"

HOOK, HOOK_OLD = 0x112244, 0xEBFFC42D  # bl 0x103300 (stock GetTwlTitleListForReboot into DeliverArg)
CAVE, CAVE_END = 0x11FA40, 0x120000    # zero padding of .text (0x11fa3c..0x120000, mapped RX)
ANCHORS = [  # (address, word, what the cave relies on)
    (0x112240, 0xE320F000, "nop before the hook"),
    (0x112248, 0xE1A06000, "mov r6, r0 after the hook (stock result consumed)"),
    (0x103300, 0xE92D4038, "push {r3,r4,r5,lr}: stock GetTwlTitleListForReboot-into-DeliverArg"),
    (0x103304, 0xE3A0304D, "mov r3, #77 (DeliverArg list size)"),
    (0x109DB4, 0xE92D4070, "push {r4,r5,r6,lr}: am:u GetTwlTitleListForReboot wrapper (nop at 0x109db0)"),
    (0x109E0C, 0x04110044, "IPC header GetTwlTitleListForReboot"),
    (0x100044, 0x00217654, "bss end used by the startup clear (scratch lives above it)"),
    (0x11B600, 0xE59F0014, "ldr r0,=0x20ba98: object below the launching thread stack (12 + 0x1000 bytes)"),
    (0x11B61C, 0x0020BA98, "its address"),
    (0x101E40, 0x002102A8, "stack top of the thread created at 0x101dc4 (runs the TWL launch)"),
]


def records(n, code):
    for addr, want, note in ANCHORS:
        got = struct.unpack_from("<I", code, addr - BASE)[0]
        assert got == want, f"NS: {addr:#x} is {got:08x}, expected {want:08x} ({note})"
    assert not any(code[CAVE - BASE:CAVE_END - BASE]), "NS: cave area is not zero"
    return [
        (HOOK, words(HOOK_OLD), words(branch(HOOK, CAVE, link=True))),
        cave(code, CAVE, (CAVES / "cave256.bin").read_bytes(), CAVE_END),
    ]

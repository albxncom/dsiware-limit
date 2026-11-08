"""HOME Menu, decrypted .code of 0004003000009802 (EUR 11.17.0-50E). Tested on a New 3DS XL with 130 DSiWare.

Moves the DSiWare title list into the free tail of the last bss page and both ticket bitfields into the freed
list space, replaces the 64-bit ticket popcount (caves/popcnt.S) and raises three caps. All DSi icons are loaded
non-animated and packed 8 per texture row (caves/mapping.S), so the 6 stock TWL textures hold 383 icons; the icon
slot bitfield moves to 0x34d2e0 (caves/bitfield.S). Allocation-failure guards (caves/guards.S, caves/leak.S) and
AM null-buffer guards (caves/amguard.S). Stock memory, no exheader. Why and how: docs/findings.md.
"""
from pathlib import Path

from patchkit import BASE, NOP, adr, branch, cave, cmp_, syms, words

SHA256 = "5f4d8d0e80d8e7d6fafcefa0630c5106473ade4658585cfb499a6ec3324d89a7"
CAVES = Path(__file__).resolve().parent / "caves"

TEXT_PAD_END = 0x306000  # caves live in the zero-filled, mapped tail of .text (0x30560c..0x306000)
LITERALS = {  # old address: (new address, literal sites)
    0x34D2B0: (0x3827F0, [0x13BECC, 0x13C158, 0x1AD5FC, 0x204B38, 0x226754]),  # DSiWare title list
    0x32EDCC: (0x34D2B0, [0x13BED4, 0x204B4C]),  # 3DS-NAND ticket bits
    0x32EDC4: (0x34D2C0, [0x13BEC0, 0x204B3C]),  # DSiWare ticket bits
}
CAPS = {0x13BFA0: 2, 0x22158C: 0, 0x203E08: 0}  # `cmp rN, #40`: list builder, install pre-check, icon placement
# popcount of the DSiWare ticket bitfield, replaced by caves/popcnt.bin
POPCOUNT_AT, POPCOUNT_LEN = 0x1AD84C, 0xB4
# anim-buffer guard for tiles without an icon slot (caves/leak.S)
LEAK_CAVE, LEAK_HOOK, LEAK_HOOK_OLD = 0x305740, 0x1C73D4, 0xE3560000  # cmp r6, #0
# allocation-failure guards (caves/guards.S)
GUARDS_CAVE = 0x305760
# icon slots: 1..383 instead of 1..40; slot bitfield 0x33c624 -> 0x34d2e0 (12 words, caves/bitfield.S)
OLD_BF, NEW_BF, NEW_BF_WORDS = 0x33C624, 0x34D2E0, 12
BITFIELD_LITERALS = [0x200730, 0x203390, 0x24DB70, 0x24DFB4, 0x2F3A4C]  # free, alloc, create tail, reset, clear-all
ICON_CAP = 0x20327C       # `cmp r0,#41; blt` loop in the slot allocator: hand out slots 1..383
LOADER_KIND = 0x1326A8    # `beq 0x132768` (kind 2, non-animated) -> `b`
BF_CAVE = 0x305B00
# packed static icon mapping (caves/mapping.S), hooked in the lookup 0x207c20; returns to 0x207dbc
MAPPING_CAVE, MAPPING_HOOK, MAPPING_HOOK_OLD = 0x305610, 0x207D34, 0xE0823EA4  # add r3, r2, r4, lsr #29
# AM null-buffer guards (caves/amguard.S)
AMGUARD_CAVE = 0x3058C0


def blob(name):
    return (CAVES / name).read_bytes()


def list_records(n, code):
    recs = []
    for old, (new, sites) in LITERALS.items():
        recs += [(a, words(old), words(new)) for a in sites]
    recs += [(a, words(cmp_(r, 40)), words(cmp_(r, n))) for a, r in CAPS.items()]
    popcount = blob("popcnt.bin")
    old = code[POPCOUNT_AT - BASE:POPCOUNT_AT - BASE + POPCOUNT_LEN]
    recs.append((POPCOUNT_AT, old, popcount + words(NOP) * ((POPCOUNT_LEN - len(popcount)) // 4)))
    return recs


def leak_records(code):
    return [
        (LEAK_HOOK, words(LEAK_HOOK_OLD), words(branch(LEAK_HOOK, LEAK_CAVE))),
        cave(code, LEAK_CAVE, blob("leak.bin"), TEXT_PAD_END),
    ]


def guard_records(code):
    sym = syms(CAVES / "guards.syms", GUARDS_CAVE)
    EQ = 0x0
    return [
        # --- TWL tile loader 0x132458 ---
        # r6 (0x378) / r7 (0x23c0): check both once r7 is in place, before any use
        (0x1324B0, words(0x0A000019), words(branch(0x1324B0, sym["guard67"]))),  # beq 0x13251c -> b guard67
        # A (0x1680, [obj+0x1c4]): NULL -> kind 2 path
        (0x1326DC, words(0x1B040024), words(branch(0x1326DC, sym["guardA"]))),  # blne 0x232774 -> b guardA
        # S (0x4000 sub-banner): NULL -> stock static path 0x1327b4
        # movs r0,r5; beq 0x1327b4; bl 0x1372b4; adds r0,sl,r0,asr #31 (moved)
        (0x13270C, words(0xE1A00005, 0xEB0012E7, 0xE09A0FC0, 0xE320F000),
         words(0xE1B00005, branch(0x132710, 0x1327B4, EQ), branch(0x132714, 0x1372B4, link=True), 0xE09A0FC0)),
        # B (0x1680, [obj+0x1c0]): NULL -> bail; the kind-1 fallback reuses the kind-2 check sequence
        (0x13279C, words(0x0A000019), words(branch(0x13279C, sym["bail"], EQ))),  # beq 0x132808 -> beq bail
        (0x132800, words(0xE1B05000), words(branch(0x132800, 0x132794))),  # movs r5,r0 -> b 0x132794
        # T (0x1800 work buffer): NULL -> skip the static icon conversion, keep the zeroed B
        # movs r5,r0; beq 0x13283c; ldr r0,[r4,#0x1c0]; add r1,r7,#32; add r0,r0,#0x480; mov r2,r5; bl 0x143b34; mov r0,r5
        (0x132820, words(0xE1A05000, 0xE59401C0, 0xE1A02005, 0xE2871020, 0xE2800D12, 0xEB0044BE, 0xE1A00005, 0xE320F000),
         words(0xE1B05000, branch(0x132824, 0x13283C, EQ), 0xE59401C0, 0xE2871020, 0xE2800D12, 0xE1A02005,
               branch(0x132838, 0x143B34, link=True), 0xE1A00005)),
        # --- attach 0x2035c4: NULL banner object, or an object without the icon buffer its kind reads ---
        (0x2035F0, words(0xE59701BC), words(branch(0x2035F0, sym["attach_guard"]))),  # ldr r0,[r7,#0x1bc] -> b attach_guard
        # --- driver 0x1c7748: NULL 0x36c0 cache buffer ---
        (0x1C7794, words(0xEBFFF07A), words(branch(0x1C7794, sym["cache_guard"], link=True))),  # bl 0x1c3984 -> bl cache_guard
        # --- driver 0x1c7d74: NULL 0x36c0 buffer; replaces a duplicate of the clear at 0x1c7db4 ---
        (0x1C7DB8, words(0xE3A01DDB, 0xE1A00007, 0xEB01B052), words(0xE3570000, branch(0x1C7DBC, 0x1C7FF8, EQ), NOP)),
        # --- attach 0x1c7308: animation block pair (holder 8 / data 0x1180 / anim object 16) ---
        (0x1C73F8, words(0x0A000002), words(branch(0x1C73F8, sym["pair_fail"], EQ))),  # beq 0x1c7408 -> beq pair_fail
        (0x1C7424, words(0x13A01D46), words(branch(0x1C7424, sym["pair_d"]))),  # movne r1,#0x1180 -> b pair_d
        (0x1C744C, words(0x13A01000), words(branch(0x1C744C, sym["pair_a"]))),  # movne r1,#0 -> b pair_a
        (0x1C745C, words(0xE5947058), words(branch(0x1C745C, sym["anim_copy_guard"]))),  # ldr r7,[r4,#0x58] -> b anim_copy_guard
        # --- attach 0x1c7308: icon source check before the slot request and the upload ---
        (0x1C7488, words(0xE3560000), words(branch(0x1C7488, sym["src_guard"]))),  # cmp r6,#0 -> b src_guard
        # --- 3DS banner fill 0x220abc: NULL 0x36c0 SMDH buffer / NULL 0x1680 icon buffer ---
        (0x220AE4, words(0xE1A06000), words(branch(0x220AE4, sym["fill3ds_buf"]))),  # mov r6,r0 -> b fill3ds_buf
        (0x220BE8, words(0xE1B05000), words(branch(0x220BE8, sym["fill3ds_icon"]))),  # movs r5,r0 -> b fill3ds_icon
        cave(code, GUARDS_CAVE, blob("guards.bin"), TEXT_PAD_END),
    ]


def slot_records(code):
    sym = syms(CAVES / "bitfield.syms", BF_CAVE)
    assert NEW_BF + 4 * NEW_BF_WORDS <= 0x34D3F0  # inside the old DSiWare list area, behind the ticket bits
    return [
        (ICON_CAP, words(cmp_(0, 41), 0xBAFFFFF3), words(cmp_(0, 0x180), 0xBAFFFFF3)),
        (LOADER_KIND, words(0x0A00002E), words(0xEA00002E)),
        *[(a, words(OLD_BF), words(NEW_BF)) for a in BITFIELD_LITERALS],
        cave(code, BF_CAVE, blob("bitfield.bin"), TEXT_PAD_END),
        # texture creation tail: ldr r1,=bitfield; clear 2 words + kind-3 word 0 -> bl clr_tail
        (0x24DB08, words(0xE5810000, 0xE5810004, 0xE2811008, 0xE5810000),
         words(branch(0x24DB08, sym["clr_tail"], link=True), NOP, NOP, NOP)),
        # reset 0x24df38 (leaf, lr live): adr ip, back; b clr_leaf
        (0x24DF70, words(0xE5801000, 0xE5801004, 0xE2800008, 0xE5801000),
         words(adr(12, 0x24DF70, 0x24DF80), branch(0x24DF74, sym["clr_leaf"]), NOP, NOP)),
        # clear-all 0x2f39e4 (leaf, lr live): adr ip, back; b clr_leaf
        (0x2F3A18, words(0xE5801000, 0xE5801004, 0xE2800008, 0xE5801000, 0xE5801004),
         words(adr(12, 0x2F3A18, 0x2F3A2C), branch(0x2F3A1C, sym["clr_leaf"]), NOP, NOP, NOP)),
    ]


def mapping_records(code):
    """Slot s -> texture s>>6, row (s>>3)&7, column s&7."""
    return [
        (MAPPING_HOOK, words(MAPPING_HOOK_OLD), words(branch(MAPPING_HOOK, MAPPING_CAVE))),
        cave(code, MAPPING_CAVE, blob("mapping.bin"), TEXT_PAD_END),
    ]


def amguard_records(code):
    """AM list requests never get a null buffer; the title scans keep their lists when their buffer is missing."""
    sym = syms(CAVES / "amguard.syms", AMGUARD_CAVE)
    return [
        # the three AM request wrappers start with a nop: nop -> b guard_*
        (0x10E738, words(NOP), words(branch(0x10E738, sym["guard_10e738"]))),  # AM 0x00020082
        (0x14A700, words(NOP), words(branch(0x14A700, sym["guard_14a700"]))),  # AM 0x00090082
        (0x14A754, words(NOP), words(branch(0x14A754, sym["guard_14a754"]))),  # AM 0x00030084
        # title scan 0x13bef8: clear the counts only once the 0xe000 buffer exists
        (0x13BF08, words(0xE5889010), words(NOP)),  # str r9,[r8,#16] -> nop
        (0x13BF0C, words(0xE5889014), words(NOP)),  # str r9,[r8,#20] -> nop
        (0x13BF24, words(0xE1A06000), words(branch(0x13BF24, sym["scan1_after_alloc"], link=True))),  # mov r6,r0
        # title scan 0x13c160
        (0x13C170, words(0xE585000C), words(NOP)),  # str r0,[r5,#12] -> nop
        (0x13C188, words(0xE1A04000), words(branch(0x13C188, sym["scan2_after_alloc"], link=True))),  # mov r4,r0
        cave(code, AMGUARD_CAVE, blob("amguard.bin"), TEXT_PAD_END),
    ]


def records(n, code):
    return (list_records(n, code) + leak_records(code) + guard_records(code) + slot_records(code)
            + mapping_records(code) + amguard_records(code))

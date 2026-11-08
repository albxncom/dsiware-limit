@ HOME Menu EUR 11.17.0-50E (0004003000009802), option A: clear routines for the relocated DSi icon slot
@ bitfield. The kind-1/2 slot bitfield (stock 0x33c624, 2 words, 48 slots) moves to NEWBF = 0x34d2e0 with
@ 12 words (384 slots), inside the old DSiWare list area that target.py frees (0x34d2b0..0x34d3f0;
@ ticket bits use 0x34d2b0..0x34d2e0). The 5 literals that held 0x33c624 are repointed by target.py (BITFIELD_LITERALS).
@
@ The three stock clear sites clear the 2 kind-1/2 words and then the kind-3 bitfield 0x33c62c through
@ `add #8`, so they cannot simply follow the moved literal. They branch here instead (same hooks as
@ the rejected twlpool variant in docs/findings.md):
@   clr_tail  `bl` from 0x24db08 (texture creation 0x24d88c, lr saved there): r0 = 0, r1 = NEWBF.
@             Clears NEWBF and kind-3 word 0.
@   clr_leaf  `b` from 0x24df74 (reset 0x24df38) and 0x2f3a1c (clear-all 0x2f39e4), ip = return address
@             because lr is live in those leaf functions: r1 = 0, r0 = NEWBF. Clears NEWBF and kind-3 words 0
@             and 1 (0x24df38 overwrites word 1 right after, as in stock).
@ Only r0, r1 (and ip as the return address) are touched, as at the stock sites.

    .arm
    .text
    .global clr_tail, clr_leaf

    .set KIND3BF,   0x33c62c
    .set NEW_WORDS, 12

clr_tail:
    .rept NEW_WORDS
    str     r0, [r1], #4
    .endr
    ldr     r1, =KIND3BF
    str     r0, [r1]
    bx      lr

clr_leaf:
    .rept NEW_WORDS
    str     r1, [r0], #4
    .endr
    ldr     r0, =KIND3BF
    str     r1, [r0]
    str     r1, [r0, #4]
    bx      ip

    .ltorg

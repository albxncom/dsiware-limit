@ 256-title variant of cave.S (NS 11.17.0 EUR, 0004013000008002 v23553). Same hook (0x112244) and the same
@ logic as cave.S; differences:
@   - the second GetTwlTitleListForReboot query asks for 256 titles,
@   - the 2048-byte tid scratch lives in the bss tail 0x217658..0x217e58 (bss ends 0x217654, page 0x218000),
@   - the 1024-byte content-id scratch lives on the stack of the launching thread, inside this frame
@     (sub sp, #0x410: 8 bytes outNum + 0x400 content ids + 8 slack). Stack need below the hook: 24 + 0x410 + 16 (0x103300) + 16 (0x109db0) = 0x448, stock alone needs 0x20.
@ Everything else (membership test, append/replace rule, stock result passthrough, leave-as-stock on any
@ AM failure) is identical to cave.S. See the 205 build for the full commentary.

    .arm
    .syntax unified
    .section .text
    .global cave

    .equ STOCK_LIST_FN, 0x103300
    .equ AM_TWL_LIST_FN, 0x109db0
    .equ DA_COUNT,      0x215950
    .equ DA_TIDS,       0x2159a0
    .equ DA_CIDS,       0x215c10
    .equ SCR_TIDS,      0x217658      @ 256 * 8 = 0x800 -> ends 0x217e58
    .equ SCR_MAX,       256
    .equ FRAME,         0x410         @ [sp] outNum, [sp+8 .. sp+0x408) content ids, 8 bytes slack (0x408 is no ARM immediate)

cave:
    push    {r4-r8, lr}
    sub     sp, sp, #FRAME
    bl      STOCK_LIST_FN
    cmp     r0, #0
    blt     done
    mov     r8, r0
    ldr     r5, [r4]
    ldr     r6, [r4, #4]
    lsl     r6, r6, #17
    lsr     r6, r6, #17
    orr     r6, r6, #0x30000
    ldr     r7, =DA_COUNT
    ldrb    r1, [r7]
    ldr     r0, =DA_TIDS
    bl      find
    cmp     r0, #0
    bge     done_ok
    mov     r0, sp                   @ &outNum
    ldr     r1, =SCR_TIDS
    add     r2, sp, #8               @ content ids on the stack
    mov     r3, #SCR_MAX
    bl      AM_TWL_LIST_FN
    cmp     r0, #0
    blt     done_ok
    ldr     r1, [sp]
    cmp     r1, #SCR_MAX
    movhi   r1, #SCR_MAX
    ldr     r0, =SCR_TIDS
    bl      find
    cmp     r0, #0
    blt     done_ok
    add     r2, sp, #8
    ldr     r2, [r2, r0, lsl #2]     @ content id AM reports for the target
    ldrb    r1, [r7]
    cmp     r1, #77
    movlo   r0, r1
    addlo   r1, r1, #1
    strblo  r1, [r7]
    movhs   r0, #76
    ldr     r3, =DA_TIDS
    add     r3, r3, r0, lsl #3
    stm     r3, {r5, r6}
    ldr     r3, =DA_CIDS
    str     r2, [r3, r0, lsl #2]
done_ok:
    mov     r0, r8
done:
    add     sp, sp, #FRAME
    pop     {r4-r8, pc}

find:
    mov     r2, #0
1:  cmp     r2, r1
    bge     2f
    ldr     r3, [r0]
    ldr     ip, [r0, #4]
    cmp     r3, r5
    cmpeq   ip, r6
    moveq   r0, r2
    bxeq    lr
    add     r0, r0, #8
    add     r2, r2, #1
    b       1b
2:  mvn     r0, #0
    bx      lr

    .ltorg

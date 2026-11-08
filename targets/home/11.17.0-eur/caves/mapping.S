@ Packed static DSi icon mapping for the HOME Menu lookup 0x207c20 (EUR 11.17.0-50E), kinds 1 and 2.
@ Entered from `b cave` at 0x207d34 with r0 = out, r2 = slot s, r4 = s asr 31 (stock prologue).
@ Leaves to 0x207dbc with s0-s3 = s4-s7 = TWL table entry {v, p, wh, fmt} and r3 = ip = cell, as stock does.
@   s >= 0: texture s>>6, cell (s>>3)&7, column s&7; v and p += column*0x200 unless v is 0 (no texture).
@   s <  0: the stock arithmetic unchanged (entry (s+7) asr 3, cell s - ((s+7) & ~7), no column), so -1 stays stock.
@ r1, r2, r4-r7 are free here: r1/r2 are caller-saved, r4-fp are restored by the pop at 0x207dc8.

    .syntax unified
    .arm
    .fpu vfp
    .global cave
cave:
    ldr     r1, =0x003664ac         @ TWL texture table, same literal as stock 0x207dd8
    cmp     r2, #0
    blt     negative
    lsr     r3, r2, #6
    add     r1, r1, r3, lsl #4
    and     ip, r2, #7
    lsr     r3, r2, #3
    and     r3, r3, #7
    b       load
negative:
    add     r3, r2, r4, lsr #29
    asr     ip, r3, #3
    add     r1, r1, ip, lsl #4
    bic     r3, r3, #7
    sub     r3, r2, r3
    mov     ip, #0
load:
    vldmia  r1, {s0-s3}
    ldm     r1, {r1, r2}
    cmp     r1, #0
    addne   r1, r1, ip, lsl #9
    addne   r2, r2, ip, lsl #9
    vmov    s0, s1, r1, r2
    vmov.f64 d2, d0
    vmov.f64 d3, d1
    mov     ip, r3
    b       0x207dbc
    .ltorg

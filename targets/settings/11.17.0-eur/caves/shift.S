@ shift_a: builder 0x201588..0x2015e8 (25 words). in: r0 = array. free: r1,r4,r5,ip. keep r2,r3.
    .arm
    .section .text.a, "ax"
shift_a:
    mov   r1, #LAST8          @ (N-2)*8
1:  ldrd  r4, r5, [r0, r1]
    add   ip, r1, #8
    strd  r4, r5, [r0, ip]
    subs  r1, r1, #8
    bge   1b
@ shift_c: import 0x1ff568..0x1ff5c8 (25 words). in: r5 = array. free: r0,r1,r2,r3,r8,r9,ip. keep r4,r6,r7.
    .section .text.c, "ax"
shift_c:
    mov   r0, #LAST8
1:  ldrd  r2, r3, [r5, r0]
    add   ip, r0, #8
    strd  r2, r3, [r5, ip]
    subs  r0, r0, #8
    bge   1b

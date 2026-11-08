@ HOME Menu EUR 11.17.0-50E: guard AM list requests against failed heap allocations.
@ Linked at 0x3058c0 (zero RX padding). Patch sites (amguard_records in target.py):
@   0x10e738, 0x14a700, 0x14a754  nop -> b guard_*
@   0x13bf08, 0x13bf0c            count stores -> nop (redone in scan1_after_alloc)
@   0x13bf24                      mov r6, r0 -> bl scan1_after_alloc
@   0x13c170                      count store -> nop (redone in scan2_after_alloc)
@   0x13c188                      mov r4, r0 -> bl scan2_after_alloc

    .arm
    .syntax unified
    .text

    .set wrap_10e738_body, 0x10e73c
    .set wrap_14a700_body, 0x14a704
    .set wrap_14a754_body, 0x14a758
    .set scan1_epilogue,   0x13c150
    .set scan2_epilogue,   0x13c224

@ Status level (25) so 0x2361e0 does not turn it into a fatal error;
@ summary OutOfResource (3), module AM (32), description OutOfMemory (1011).
    .set RESULT_AM_OUT_OF_MEMORY, 0xC86083F3

@ AM 0x00020082 (count *, ids out, max, media): output buffer in r1.
    .global guard_10e738
guard_10e738:
    cmp     r1, #0
    bne     wrap_10e738_body
    b       fail_no_buffer

@ AM 0x00090082 (count *, ids out, max, offset): output buffer in r1.
    .global guard_14a700
guard_14a700:
    cmp     r1, #0
    bne     wrap_14a700_body
    b       fail_no_buffer

@ AM 0x00030084 (infos out, media, ids in, count): output buffer in r0.
    .global guard_14a754
guard_14a754:
    cmp     r0, #0
    bne     wrap_14a754_body
fail_no_buffer:
    ldr     r0, =RESULT_AM_OUT_OF_MEMORY
    bx      lr

@ 0x13bef8: r0 = buffer, r8 = 0x32eda4, r9 = 0. Clear the counts only once the
@ buffer exists; otherwise keep the old lists and ask ENSURE_LISTS to rescan.
    .global scan1_after_alloc
scan1_after_alloc:
    movs    r6, r0
    strne   r9, [r8, #16]
    strne   r9, [r8, #20]
    bxne    lr
    strb    r9, [r8, #1]
    b       scan1_epilogue

@ 0x13c160: r0 = buffer, r5 = 0x32eda4; r1 is free (overwritten at 0x13c18c).
    .global scan2_after_alloc
scan2_after_alloc:
    movs    r4, r0
    mov     r1, #0
    strne   r1, [r5, #12]
    bxne    lr
    strb    r1, [r5, #1]
    b       scan2_epilogue

    .ltorg

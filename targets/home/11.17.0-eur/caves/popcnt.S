@ Replacement for HOME Menu EUR 11.17 at 0x1ad84c (popcount of the DSiWare ticket bitfield).
@ Original: popcount of 2 fixed words at 0x32edc4. New: counts only bits below the DSiWare count,
@ so the bitfield can live elsewhere, hold up to 256 bits, and stale bits above the count never matter.
@ ABI unchanged: int f(void), returns the count in r0, clobbers r0-r3, saves r4.
@ BITFIELD, STATE and ENSURE_LISTS come from the linker (--defsym); STATE+0x10 is the DSiWare count.
    .syntax unified
    .arm
    .globl _start
_start:
    push    {r4, lr}
    mov     r0, #1
    bl      ENSURE_LISTS            @ same call the original makes first
    ldr     r4, lit_bitfield
    ldr     r1, lit_state
    ldr     r1, [r1, #0x10]         @ r1 = bits still to count
    mov     r0, #0
next_word:
    cmp     r1, #0
    ble     done
    ldr     r2, [r4], #4
    cmp     r1, #32
    movlt   r3, #1
    lsllt   r3, r3, r1
    sublt   r3, r3, #1
    andlt   r2, r2, r3              @ last word: keep only bits below the count
    sub     r1, r1, #32
clear_lowest:
    cmp     r2, #0
    beq     next_word
    sub     r3, r2, #1
    and     r2, r2, r3
    add     r0, r0, #1
    b       clear_lowest
done:
    pop     {r4, pc}
lit_bitfield:
    .word   BITFIELD
lit_state:
    .word   STATE

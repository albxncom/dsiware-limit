"""System Settings (Data Management), decrypted .code of 0004001000022000 (EUR 11.17.0-50E). Tested on a New 3DS XL.

Grows the Mset.dat display order (system save 00020220) from 40 to N entries: buffer sizes, loop bounds, two
rewritten shift loops (caves/shift.S), the delete path, three UI caps, and the read helper clamps a smaller file.
The 300-slot title record block and bss stay as they are. N, N x 8, N - 2 and (N - 2) x 8 must be ARM
immediates, so N is 2..128 or even 130..256. Why and how: docs/findings.md.
"""
from patchkit import BASE, NOP, cmp_, mov, rsb, str_imm, words

SHA256 = "3dbb076b95304d3612b7b746a2927576b84bd83bd2b2db9f71c41cf732737cec"
SHIFT_A = (0xE18040D1, 0xE281C008, 0xE18040FC, 0xE2511008, 0xAAFFFFFA)  # r0 = array
SHIFT_C = (0xE18520D0, 0xE280C008, 0xE18520FC, 0xE2500008, 0xAAFFFFFA)  # r5 = array


def shift_loop(reg_i, n, body):  # caves/shift.S: mov rI, #(N-2)*8, then 5 loop words, padded to 25 words
    code = words(mov(reg_i, (n - 2) * 8), *body)
    return code + words(NOP) * (25 - len(code) // 4)


def records(n, code):
    def at(a, length):
        return code[a - BASE:a - BASE + length]

    shift_a = shift_loop(1, n, SHIFT_A)
    shift_c = shift_loop(0, n, SHIFT_C)
    return [
        # list builder 0x2013f0
        (0x201424, words(mov(0, 320)), words(mov(0, n * 8))),  # Mset.dat buffer size
        (0x201580, words(cmp_(1, 40)), words(cmp_(1, n))),  # search bound
        (0x201588, at(0x201588, 100), shift_a),  # shift display order by one
        (0x2015F8, words(mov(4, 38)), words(mov(4, n - 2))),  # shift title records
        (0x2016B4, words(cmp_(0, 40)), words(cmp_(0, n))),  # stop after N titles
        # validator 0x2000a0
        (0x200188, words(cmp_(2, 40)), words(cmp_(2, n))),
        # copy/import: insert at the front of Mset.dat 0x1ff494
        (0x1FF520, words(mov(0, 320)), words(mov(0, n * 8))),
        (0x1FF534, words(mov(1, 320)), words(mov(1, n * 8))),
        (0x1FF560, words(cmp_(0, 40)), words(cmp_(0, n))),
        (0x1FF568, at(0x1FF568, 100), shift_c),
        (0x1FF5D8, words(mov(1, 320)), words(mov(1, n * 8))),
        # delete: remove from Mset.dat 0x1ffa88
        (0x1FFBDC, words(mov(0, 320)), words(mov(0, n * 8))),
        (0x1FFBF4, words(mov(1, 320)), words(mov(1, n * 8))),
        (0x1FFC24, words(rsb(3, 2, 40)), words(rsb(3, 2, n))),
        (0x1FFC30, words(cmp_(2, 40)), words(cmp_(2, n))),
        (0x1FFCA8, words(str_imm(3, 0, 0x138)), words(str_imm(3, 0, (n - 1) * 8))),
        (0x1FFCAC, words(str_imm(3, 0, 0x13C)), words(str_imm(3, 0, (n - 1) * 8 + 4))),
        (0x1FFCB4, words(cmp_(11, 40)), words(cmp_(11, n))),
        (0x1FFCC0, words(mov(1, 320)), words(mov(1, n * 8))),
        # UI caps: page table after copy, record insert after copy, list-full check
        (0x224B68, words(mov(1, 40, cond=0)), words(mov(1, n, cond=0))),
        (0x1FE800, words(mov(0, 40, cond=0)), words(mov(0, n, cond=0))),
        (0x225564, words(cmp_(0, 40)), words(cmp_(0, n))),
        # Mset.dat read helper: take the clamping path, the file is still 320 bytes on the first run
        (0x1D0344, words(0x0A00001D), words(0x0A00000F)),
    ]

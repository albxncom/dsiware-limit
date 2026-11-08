@ HOME Menu EUR 11.17.0-50E (0004003000009802): DSiWare tile without an icon slot, code cave.
@
@ Problem: 0x1c7308 (attach a TWL banner to a tile) takes its "fresh tile" path whenever the tile has no
@ texture ([tile+0x5c] == 0). On that path it allocates the animated-icon block pair [tile+0x58] =
@ {data 0x1180, anim object 16} (plus the 8-byte holder) from the device heap without looking at the
@ previous pointer. Stock never re-enters this path (every tile gets a slot), but a tile whose slot
@ request returned -1 keeps [tile+0x5c] == 0, so every later pass over the tile (cursor visit, reload)
@ leaks 0x1180 + 16 + 8 bytes and asks the allocator again.
@
@ Fix: at 0x1c73d4 the stock code is `cmp r6, #0; bne 0x1c745c` (r6 = 1 means "same title, texture
@ exists, refresh the animation buffers only"). The cave adds: if the tile already owns its animation
@ buffers, take the same refresh path (copy the new frame data into the existing block, re-init the
@ animation object) instead of allocating. The slot request that follows (0x1c7494..0x1c74d0) still runs,
@ so a tile that was left with the placeholder gets a real icon on its next pass as soon as a slot is
@ free; -1 again just returns as before, now without holding anything new.
@
@ Placed at CAVE = 0x305740, behind twlpool2's cave (0x305610 + 292 = 0x305734), inside the zero-filled
@ mapped tail of the .text pages (0x30560c..0x306000). Reached by `b anim_guard` written over the `cmp`
@ at 0x1c73d4; the `bne` at 0x1c73d8 is left in place and never executed.
@   as -march=armv6k leak.S; ld -Ttext=0x305740; objcopy -O binary

    .arm
    .text
    .global anim_guard

anim_guard:                     @ r4 = tile, r6 = refresh flag, r8 = banner object (all live, untouched)
    cmp     r6, #0
    bne     0x1c745c            @ stock: refresh the existing animation buffers
    ldr     r0, [r4, #0x58]
    cmp     r0, #0
    bne     0x1c745c            @ left over from an earlier pass without a slot: reuse, do not allocate
    b       0x1c73dc            @ stock: first pass, allocate

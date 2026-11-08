@ HOME Menu EUR 11.17.0-50E (0004003000009802): allocation-failure guards, code cave.
@
@ Placed at CAVE = 0x305760 in the zero-filled, mapped tail of the .text pages, behind twlpool2
@ (0x305610..0x305734) and leak (0x305740..0x305758); 0x305758..0x306000 is zero in the dump.
@ Assembled with devkitARM:
@   as -march=armv6k guards.S; ld -Ttext=0x305760; objcopy -O binary
@
@ Every DSiWare tile allocation comes from heap group 44 via handle 0x32eac8 (0x235800 ->
@ 0x2327b4 kind 2 -> 0x223a78 -> 0x22a540), which returns NULL when the group is full. The TWL tile
@ loader 0x132458, the 3DS banner fill 0x220abc, the drivers 0x1c7748/0x1c7d74 and the attach
@ 0x1c7308 use several of those buffers unchecked; a NULL buffer handed to fs stops the kernel, a NULL
@ icon source reaches memcpy via 0x24dc74 (crash_dump_00000005).
@
@ Fallback states, all stock: "rejected banner" = [obj+0x1bc] (kind) 0 and [obj+0x1b8] (region flags) 0,
@ then 0x2035c4 returns 0 (0x223ce4 with region 0), nothing reads +0x1c0/+0x1c4 and the driver takes its
@ stock retry/release path; this is what a DSi header with region flags 0 produces (0x1326c4 / 0x132774).
@ "pool full" = the exit 0x1c7308 takes when the slot allocator returns -1: [tile+0x48] = -1, unlock,
@ return; the tile keeps the placeholder icon and is visited again later.

    .arm
    .text
    .global guard67, guardA, bail, attach_guard, cache_guard
    .global pair_d, pair_a, pair_fail, anim_copy_guard, src_guard, fill3ds_buf, fill3ds_icon

@ ---------------------------------------------------------------------------------------------------
@ TWL tile loader 0x132458

@ From 0x1324b0 (was `beq 0x13251c`, flags from `cmp r8,#0` at 0x1324a8). r6 = 0x378 header
@ buffer, r7 = 0x23c0 banner buffer, r8 = cached data or 0.
guard67:
    cmp     r6, #0
    cmpne   r7, #0
    beq     bail
    cmp     r8, #0
    beq     0x13251c            @ stock: no cache, load from fs
    b       0x1324b4            @ stock: copy from the cache

@ From 0x1326dc (was `blne 0x232774`, flags from `movs r5,r0` at 0x1326d4). r5 = A, the 0x1680
@ animation buffer that becomes [obj+0x1c4]. r4 = obj, r8 = 2.
guardA:
    beq     a_null
    bl      0x232774            @ stock: memset(A, 0, 0x1680)
    b       0x1326e0
a_null:
    str     r8, [r4, #0x1bc]    @ kind 2 (static icon); +0x1b8 keeps the header's region flags
    b       0x13277c            @ stock kind-2 path: +0x1c4 = 0, allocate B

@ From guard67 (r6 or r7 NULL) and from 0x13279c (B NULL, was `beq 0x132808`). r4 = obj; r6/r7
@ are NULL or valid, 0x2353c4 frees both NULL-safely at 0x132844.
bail:
    mov     r0, #0
    str     r0, [r4, #0x1bc]
    str     r0, [r4, #0x1b8]
    b       0x132844

@ ---------------------------------------------------------------------------------------------------
@ Attach check 0x2035c4

@ From 0x2035f0 (was `ldr r0,[r7,#0x1bc]`). r7 = banner object from the driver, NULL when the
@ 0x1c8 allocation failed (0x1c77c8, 0x1c7814, 0x1c7e50, 0x1c7f4c). A usable object owns the icon
@ buffer its kind reads: kind 1 -> +0x1c4 (A, 0x24de60), every other kind -> +0x1c0 (B, 0x24dc74 reads
@ src+0x480). The placeholder kind 0x7fffffff (ctor 0x245e20) has no buffer and never reaches
@ 0x1c7308 (0x203620 -> 0x203a08).
attach_guard:
    cmp     r7, #0
    beq     0x20364c            @ stock: banner rejected, return 0
    ldr     r0, [r7, #0x1bc]
    cmn     r0, #0x80000001
    beq     0x2035f4            @ placeholder: stock
    cmp     r0, #1
    ldreq   r1, [r7, #0x1c4]
    ldrne   r1, [r7, #0x1c0]
    cmp     r1, #0
    bne     0x2035f4            @ stock: r0 = kind, region check follows
    mov     r0, #0
    str     r0, [r7, #0x1bc]
    str     r0, [r7, #0x1b8]    @ no icon source: rejected banner, 0x223ce4(0, 0) returns 0
    b       0x2035f4

@ ---------------------------------------------------------------------------------------------------
@ Drivers

@ From 0x1c7794 (was `bl 0x1c3984`): copy the icon-cache entry into the 0x36c0 buffer r1, which
@ is NULL when 0x1c7778 failed. Returns 0 -> 0x1c78e8 (free NULL, fall back to 0x1c7d74).
cache_guard:
    cmp     r1, #0
    moveq   r0, #0
    bxeq    lr
    b       0x1c3984

@ ---------------------------------------------------------------------------------------------------
@ Attach 0x1c7308: animation block pair {holder 8: data 0x1180, animation object 16} at [tile+0x58],
@ allocated on the fresh-tile path (r6 = 0, [tile+0x58] == 0 after the leak guard at 0x1c73d4).
@ r4 = tile, r8 = banner object, r6 = refresh flag. The holder NULL case (0x1c73f8 `beq 0x1c7408`)
@ branches to pair_fail directly: nothing is allocated yet.

@ From 0x1c7424 (was `movne r1,#0x1180`, flags from `movs r7,r0` at 0x1c7420). r7 = data block or
@ NULL, the holder is in [tile+0x58].
pair_d:
    beq     pair_fail_d
    mov     r1, #0x1180
    bl      0x232774            @ stock: memset(data, 0, 0x1180)
    b       0x1c742c            @ stock: store into the holder, allocate the animation object
pair_fail_d:
    ldr     r0, [r4, #0x58]
    bl      0x2353c4            @ free the holder
    b       pair_fail

@ From 0x1c744c (was `movne r1,#0`, flags from `cmp r0,#0` at 0x1c7448). r0 = animation object or
@ NULL; holder and data block are valid.
pair_a:
    beq     pair_fail_a
    mov     r1, #0
    bl      0x1b3c7c            @ stock: construct the animation object, returns r0 = object
    b       0x1c7454            @ stock: store into the holder
pair_fail_a:
    ldr     r7, [r4, #0x58]
    ldr     r0, [r7]
    bl      0x2353c4            @ free the data block
    mov     r0, r7
    bl      0x2353c4            @ free the holder

@ No animation buffers: leave the tile as the stock "pool full" exit does (slot -1 at [tile+0x48],
@ 0x1c7540 unlocks and returns). [tile+0x58] = 0 lets the next pass over the tile allocate again.
pair_fail:
    mov     r0, #0
    str     r0, [r4, #0x58]
    mvn     r0, #0
    str     r0, [r4, #0x48]
    b       0x1c7540

@ From 0x1c745c (was `ldr r7,[r4,#0x58]`), reached from the allocation path, from the leak guard
@ (reuse of an earlier pair) and from the stock refresh path (r6 = 1, which assumes a pair exists).
@ Copies A = [obj+0x1c4] into the data block and re-inits the animation object; skipped when there is
@ no holder, no data block or no A (stock: NULL dereference at 0x1c7468 / memcpy to or from NULL).
anim_copy_guard:
    ldr     r7, [r4, #0x58]
    cmp     r7, #0
    ldrne   r3, [r7]
    cmpne   r3, #0
    ldrne   r0, [r8, #0x1c4]
    cmpne   r0, #0
    beq     0x1c7488            @ nothing to copy into or from
    b       0x1c7460            @ stock: memcpy(data, A, 0x1180); 0x1b3be8(anim, data)

@ From 0x1c7488 (was `cmp r6,#0`): last check before the slot request and the texture upload, which
@ read the icon source (kind 1: A = [obj+0x1c4] via 0x24de60, else B = [obj+0x1c0] via 0x24dc74).
src_guard:
    ldr     r0, [r8, #0x1bc]
    cmp     r0, #1
    ldreq   r0, [r8, #0x1c4]
    ldrne   r0, [r8, #0x1c0]
    cmp     r0, #0
    beq     no_src
    cmp     r6, #0              @ stock
    b       0x1c748c
no_src:
    cmp     r6, #0
    bne     0x1c7530            @ refresh of an existing slot: keep the tile as it is, unlock, return
    mvn     r0, #0
    str     r0, [r4, #0x48]     @ fresh tile: the stock "pool full" exit
    b       0x1c7540

@ ---------------------------------------------------------------------------------------------------
@ 3DS banner fill 0x220abc (ctors 0x245cfc, 0x225434 non-TWL branch, 0x245ecc). r4 = banner object.
@ Both failures leave the rejected-banner state; the function's tail 0x220d08 frees r6 (NULL-safe) and
@ returns.

@ From 0x220ae4 (was `mov r6,r0`). r0 = the 0x36c0 SMDH buffer or NULL, r5 = cached SMDH or NULL;
@ 0x220ae8 `beq 0x220b10` needs the flags of `cmp r5,#0`.
fill3ds_buf:
    movs    r6, r0
    beq     fill3ds_reject
    cmp     r5, #0
    b       0x220ae8
fill3ds_reject:
    mov     r0, #0
    str     r0, [r4, #0x1bc]    @ kind 0 (the ctors leave +0x1bc unwritten)
    str     r0, [r4, #0x1b8]    @ region 0: rejected banner
    b       0x220d08

@ From 0x220be8 (was `movs r5,r0`). r0 = the 0x1680 icon buffer B or NULL; kind 0 was stored at
@ 0x220bd0, 0x220bec `movne r1,#0x1680` / 0x220bf0 `blne 0x232774` need the flags of movs.
fill3ds_icon:
    movs    r5, r0
    bne     0x220bec            @ stock: memset B, store it, copy both icons, fill the fields
    str     r5, [r4, #0x1b8]    @ region 0: rejected banner, +0x1c0 stays NULL
    b       0x220d08

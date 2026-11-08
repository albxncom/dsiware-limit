# Findings

What was learned while building the patch, for whoever maintains it or ports it to another region, system version or console. What the patch does and how to build, install and test it is in the [README](../README.md); the patch records are in `targets/<role>/<build>/target.py`, the cave sources in `caves/` and the test descriptions in the docstrings of `tests/*.py` of each target. This file holds the why, the measurements and the dead ends. Why DS games should start as DSiWare at all is in [ds-launch-paths.md](ds-launch-paths.md).

- All addresses are virtual addresses of the reference dumps (`targets/home/11.17.0-eur`, `targets/settings/11.17.0-eur`, `targets/ns/11.17.0`; hashes in their `target.py`). In a `.code` file, file offset = address - 0x100000.
- Tags where it matters: "code" = read from the dump, "emu" = run in unicorn, "live" = read on the console over the Luma GDB stub, "inferred" = concluded, not shown.
- Console: New 3DS XL, EUR 11.17.0-50E, Luma3DS, SysNAND. 130 DSiWare installed for the final tests (2026-11-08).

## HOME Menu internals (0004003000009802)

### Segment layout and free space

- From the exheader: text 0x100000 (size 0x20560c, ends 0x30560c), rodata 0x306000, data 0x32a000 (size 0x170d4), bss 0x4171c. So bss ends at 0x3827f0; the page is mapped up to 0x383000, which leaves 0x810 free, zeroed, writable bytes (live: 0x382ff8 is readable; Luma's loader rounds segments up to pages, `sysmodules/loader/source/loader.c:432`).
- The text pages end at 0x306000, so 0x30560c..0x306000 is zero-filled, mapped and executable. Every HOME cave lives there:

| Cave | Range | Source |
|---|---|---|
| packed icon mapping | 0x305610..0x305678 (0x68 bytes) | `targets/home/11.17.0-eur/caves/mapping.S` |
| anim-buffer leak guard | 0x305740..0x305758 (24 bytes) | `targets/home/11.17.0-eur/caves/leak.S` |
| allocation-failure guards | 0x305760..0x3058bc (348 bytes) | `targets/home/11.17.0-eur/caves/guards.S` |
| AM null-buffer guards | 0x3058c0..0x30591c (92 bytes) | `targets/home/11.17.0-eur/caves/amguard.S` |
| icon slot bitfield clears | 0x305b00..0x305b80 (128 bytes) | `targets/home/11.17.0-eur/caves/bitfield.S` |

- The gaps (0x305678..0x305740, 0x30591c..0x305b00) are historical: the leak and guard caves were placed behind the rejected twlpool cave (0x305610, 292 bytes), whose start the mapping cave now reuses.
- Free data space: the DSiWare title list moves from 0x34d2b0 to the bss tail at 0x3827f0 (5 literals, see below; 0x3827f0..0x382ff0, 256 x 8 = 0x800 of the 0x810 bytes). The old list area 0x34d2b0..0x34d3f0 (40 x 8) is then reused for the ticket bitfields and the icon slot bitfield, see below. 0x34d3f0 is the next object (the NAND 3DS list).

### Title lists, caps and ticket bitfields

- 0x13bef8 fetches the NAND titles from AM (GetTitleList, media NAND, up to 0x1C00 titles) and sorts them into three fixed lists. State block 0x32eda4 holds the counts: +0x0c SD, +0x10 DSiWare, +0x14 NAND 3DS.
  - DSiWare: TID high 0x00048004; TWL titles with bit 0 set are skipped. Stock list 0x34d2b0, 40 entries, cap `cmp r2,#40` at 0x13bfa0.
  - NAND 3DS titles of certain categories: list 0x34d3f0, cap 50 at 0x13c118.
  - SD: list 0x34c950, 300 entries.
  - The second title scan is 0x13c160. Both scans allocate a 0xe000 work buffer (at 0x13bf20 and 0x13c184).
- Every user TWL title in NAND counts, also TWiLight Menu++ and forwarder stubs (live list in stage 1: a YANBF stub, the SoulSilver forwarder, TWiLight Menu++).
- Readers of the DSiWare list (literals 0x34d2b0): 0x13becc, 0x13c158, 0x1ad5fc, 0x204b38, 0x226754. They loop over the count, not over 40.
- Of the 29 compares with 40 in the code, three belong to the DSiWare limit: 0x13bfa0 (list builder), 0x22158c (pre-check before an install, error 0xd860d042) and 0x203e08 (icon placement count, main object +0x1c). All three become `cmp rN,#N`; 256 encodes as `e35x0c01`.
- Shared layout model: 360 entries for SD + DSiWare + NAND + modules together (layout counters in the main object `[0x32f5d4]`: +0x18 total, +0x1c DSiWare, +0x20 SD). The SD slots do not shrink when the DSiWare cap grows; the sum must stay at or below 360. Live on 2026-11-08: 222 of 360 (129 DSiWare, 81 SD titles, 12 others). With 256 DSiWare that leaves 104 entries for everything else (inferred); what happens past 360 is untested.
- Ticket bitfields, one bit per list index: 0x32edc4 (DSiWare, 2 words) and 0x32edcc (NAND 3DS, 2 words); 0x32edd4 is occupied, so they cannot grow in place beyond 128 bits. The popcount at 0x1ad84c counts exactly 2 words of 0x32edc4.
- What the patch does with them:
  - NAND 3DS bits move to 0x34d2b0 (literals 0x13bed4, 0x204b4c).
  - DSiWare bits move to 0x34d2c0, 32 bytes (literals 0x13bec0 for clear and set, 0x204b3c for lookup). The static initializer at 0x2ef804 still clears the old, now unused place.
  - The popcount is replaced by `targets/home/11.17.0-eur/caves/popcnt.S`, which counts only the bits below the DSiWare count. Stale bits above the count never matter, which is also why the stock clear routine clearing only 16 bytes at the new place is harmless.
- Icon cache `Cache.dat`/`CacheD.dat` has 360 entries and no 40 cap; it already held the titles past 40.
- Layout persistence: the HOME Menu stores new tiles only when the "new software was added" dialog is closed with OK. With the patch off, stock HOME saves a layout with 40 DS titles; on re-enabling, the rest come back as gifts, positions and folders lost.

### Launcher.dat+0xBB0

- A field of 40 title IDs in HOME's `Launcher.dat`. At boot HOME inserts every DS tile without flag 0x40 (0x21db54 -> 0x148a54 -> insert 0x14d208; live: 41 inserts, tiles 33 to 136); System Settings writes it when it copies DSiWare. Both silently skip when the field is full.
- Its effect is unknown. It is not on the icon path and not on the launch path. It cannot grow without changing the save format, so it stays at 40.

### Icon slots and TWL textures

- DSi icons live in their own texture pool: 6 textures of 256x256 RGB565 (128 KiB each), table at 0x3664ac (16 bytes per texture: v, p, w/h, format), texture count `cmp r5,#6` at 0x24d8dc, created by 0x24d88c, freed only at scene end by 0x24db7c (which also zeroes the table).
- Stock: one slot = one row of a texture = 8 cells of 32x32, one cell per animation frame. 8 rows per texture, so 6 x 8 = 48 slots. Slot 0 belongs to the selected tile.
- Slot allocator 0x2030ac; its search loop has the cap `cmp r0,#41; blt` at 0x20327c, so stock hands out slots 1..40. Bitfield 0x33c624 (2 words), kind-3 bitfield right behind it at 0x33c62c. Free 0x20069c.
- A tile without a slot (allocator returns -1) gets the black placeholder with the dot pattern. Name and publisher are copied anyway by 0x2035c4, so the top screen text is right. Nothing persistent is involved; a reboot after a fix is enough.
- Option A (shipped):
  - A static icon uses only frame 0, so one row holds 8 static icons: 64 per texture, 384 in the 6 stock textures, slot 0 still reserved.
  - Mapping (`targets/home/11.17.0-eur/caves/mapping.S`, hooked at 0x207d34 in the lookup 0x207c20, returns to 0x207dbc): slot s -> texture s>>6, row (s>>3)&7, column s&7; v and p of the table entry move by column x 0x200 unless the entry is NULL. Negative slots take the stock arithmetic, so -1 stays stock.
  - The slot bitfield moves from 0x33c624 to 0x34d2e0, 12 words (384 bits), via 5 literals: 0x200730 (free), 0x203390 (alloc), 0x24db70 (texture creation tail), 0x24dfb4 (reset), 0x2f3a4c (clear-all). 0x34d2e0..0x34d310 is free: the ticket bits end at 0x34d2e0.
  - The three stock clear sites clear the 2 words and then the kind-3 bitfield through `add #8`, so they cannot just follow the literal. They branch to `clr_tail` (from 0x24db08, texture creation 0x24d88c) and `clr_leaf` (from 0x24df74 in reset 0x24df38 and 0x2f3a1c in clear-all 0x2f39e4).
  - Cap 0x20327c becomes `cmp r0,#0x180; blt`: slots 1..383.
  - Every drawing site that can receive a static TWL tile reads frame 0 (code). The upload flush (0x14b9b8 -> 0x1518c8, GSP FlushDataCache 0x00080082) may run up to 0xe00 bytes past the texture end, which is harmless for a write-back-and-invalidate (code).
- 3DS icons have a separate pool, fixed for 320 slots (16 textures 256x256 plus 16 textures 128x128 RGB565, 2.5 MiB); bookkeeping words at 0x36665c (`cells3ds` in `targets/home/11.17.0-eur/gdb/check-a.gdb`).

### Loader kinds

- Banner object fields: +0x1b8 region flags, +0x1bc kind, +0x1c0 static icon buffer B (0x1680), +0x1c4 animation buffer A (0x1680). Tile fields: +0x44 kind, +0x48 slot, +0x58 animation pair, +0x5c texture.
- The TWL tile loader 0x132458 decides the kind at 0x1326a8 (`beq 0x132768`): 0x132768 writes kind 2 (static icon), the fall-through writes kind 1 (animated). Kind 0 with region 0 is Nintendo's "rejected banner"; kind 0x7fffffff is the placeholder (ctor 0x245e20).
- Only kind 1 costs extra memory per tile: the loader reads the 0x4000 sub-banner (`banner.sav`) through fs, and the attach function 0x1c7308 allocates the animation pair, an 8-byte holder, a 0x1180 data block and a 16-byte animation object (0x11c8 = 4552 bytes with three block headers).
- Option A turns 0x1326a8 into `b`, so every DSi banner takes Nintendo's kind-2 path. Consequences: no DSi icon animates, also not the first 40; custom icons from `banner.sav` are ignored; no animation pair and no 0x4000 sub-banner fs call per tile.

### Heaps and the ExpHeap layout

- Startup config at 0x102580: {0x66000, 0xd00000, 0x500000 (0x300000 on Old 3DS, 0x600000 on New 3DS via 0x23633c), 0x1000000}.
- Device heap: 13 MiB (`mov r1,#0xd00000` at 0x102584). 0x105294 allocates the linear block with `0x23702c(size)` (svcControlMemory MEMOP 0x10003 via 0x235d38, up to 100 retries); 0x105390 creates the device heap (object 0x345fcc, ExpHeap head "EXPH" at 0x345fe8) over exactly that block. Live range 0x37f32000..0x38c32000.
- `0x23702c(new_size)` grows a block in place and refuses with 0xe0e01bf2 unless old and new size are multiples of 1 MiB (check at 0x237064). Any growth of the HOME heap therefore comes in 1 MiB steps. A scene grows the 0x3478c8 heap by another 10 MiB at 0x26e8e4 and shrinks it at 0x26e878 / 0x230bd4; that scene was not identified.
- The device heap is split completely into heap groups. Group table in rodata at 0x306744: 45 rows of 56 bytes (id, owner, size, nested count, then sub id/size pairs). Groups are created on demand (0x115e50) and destroyed with their scene (0x22a5dc). Group 44 is created at startup (0x1053c8) and permanent; its size 0x41e400 (4.1 MiB) is the word at 0x3070ec. Nothing in the table counts titles.
- Live at HOME idle: groups 44 (4217 KiB), 0 (33 KiB), 1 (8094 KiB, nested 0x14a000 + 0xfd000), 14 (256 KiB), created in that order. After each group creation the rest of the device heap becomes the remainder heap (wrapper 0x3476f4, handle 0x32ead0): 729008 bytes (711 KiB), almost entirely free at idle. Who uses the remainder is unknown.
- Tile allocations: handle 0x32eac8 -> 0x235800 -> 0x2327b4 -> 0x223a78 -> 0x22a540, always group 44 (sub-heap B[k] = 0x346034 + k x 0x2d8). 0x22a540 returns NULL when the largest free block is too small; it never throws. Free 0x2353c4 is NULL-safe. 0x236454 is the same allocator with alignment forced to 0x80.
- Icon textures do not come from group 44: they are allocated with handle 0x236488() through 0x236454, in the group active at creation, live group 1 (a fixed 3856 KiB for all icon textures, independent of the title count). Group 44 holds the per-tile data.
- 0x2327b4 has a thread override (current thread vs the handle at [0x32f064], bytes [0x34782c+0x98/0x99], [0x3478c8+0x72/0x73]); only readable live, printed by `heaps`.
- System heap: wrapper 0x345f58, start 0x8000000 + cfg, size 0x66000 (408 KiB).
- ExpHeap head (wrapper + 0xc + 0x18): +0 signature 0x45585048, +0x18 start, +0x1c end, +0x20 attribute, +0x24/+0x28 free list head/tail, +0x2c/+0x30 used list head/tail, +0x34 group id u16, +0x36 feature u16 (bit 0 clear = first fit). Code: create 0x12c6b8, alloc 0x12c74c, free 0x137b48, largest allocatable 0x12c93c.
- Block header, 16 bytes: +0 u16 signature (0x4652 free, 0x5544 used), +2 u16 attributes (bit 15 direction, bits 8..14 alignment padding, bits 0..7 group), +4 payload size, +8 prev, +0xc next. Payload at +16. The free list is address-sorted and coalesced.

### Per-tile memory

- Kept per kind-1 tile: the animation pair, 0x11c8 bytes, plus 1/8 of a texture. Kind-2 tiles keep only their texture share (1/64 of a texture under A).
- Freed right after attach: the banner object (0x1c8) and both 0x1680 icon buffers (driver 0x1c7898 / 0x1c7ff4 -> dtor 0x245f58). An earlier estimate that 2 x 0x1680 stay per tile was wrong.
- Peak while loading one kind-1 tile: 0x36c0 + 0x1c8 + 0x378 + 0x23c0 + 0x1680 (A) + 0x4000 (sub-banner) = 0xc1e0 bytes plus 6 headers. Kind 2 swaps A and the sub-banner for 0x1680 (B) + 0x1800 (work buffer T).
- Live under A with 130 DSiWare: about 0.8 KiB per tile that the code reading does not explain; at 256 that is at most about 205 KiB more, which fits the measured free space (inferred).

## The memory limit

- The SYSTEM region of the New 3DS is about 100 MiB (config memory 0x1FF80044 = 0x063f5000, live, same with every build). HOME's 13 MiB block and the browser (r7 = 0x04e00000, 78 MiB, at its crash, probably its own request) share it with the system modules.
- Growing HOME by G moves its linear block from 13 to 13 + G MiB (0x102584 = `mov r1,#0xd00000+G`, 0x3070ec = 0x41e400 + G). With the real allocator in unicorn, group 44 keeps its start and grows by G, groups 0, 1, 14 move by G, the remainder keeps 0xb1fb0 bytes (emu). HOME itself boots with +1, +2 and +5 MiB (live).
- The system apps do not cope:

| HOME build | G | Browser | Miiverse |
|---|---|---|---|
| no patch | 0 | not noted | starts |
| twlpool, N = 256, exheader | +5 MiB (18 MiB block) | crashes (svcBreak) | hangs in the splash screen, then the console freezes, no dump |
| guards, no pool, N = 256 | +1 MiB (14 MiB block) | runs | hangs, with and without the NS patch |
| guards, no pool, N = 256 | 0 | not noted | starts; leaving it ends in a kernel halt in `am` (see below) |
| option A, N = 256 | 0 | runs | starts, return without a hang |

- Browser crash (dumps 06 and 07, identical): process `SKATER` (`0004003000009d02`), "prefetch abort" with IFSR 2, a debug event; pc 0x3249bc is `svc 0x3c` (svcBreak), lr 0x25c64b (Thumb); around pc the strings of an assertion in `util/ScopedPtr.hpp`.
- Conclusion: Miiverse has less than 1 MiB headroom in the SYSTEM region and growth only comes in 1 MiB steps, so any permanent extra memory for HOME breaks Miiverse, and 5 MiB break the browser too. The patch has to live in stock memory. The NS patch only runs when a TWL title starts and was ruled out by the runs without it.
- Measured free space in group 44 (`heaps`):
  - Interim `--max 47` build (47 animated tiles): 4217 KiB, 324 KiB free in one block (324440 bytes), 405 used blocks. Remainder 711 KiB free. Not enough for 83 more animated tiles (about 375 KiB kept plus 48 KiB transient).
  - +1 MiB, no pool: 5241 KiB, 1380 KiB free after a fresh boot, 944 KiB after unwrapping the gifts, about 4.5 KiB per tile.
  - +2 MiB with pool, N = 130: 6265 KiB, 1874 KiB free, 17 textures.
  - +5 MiB with pool, N = 256: 9337 KiB, 5515 KiB free.
  - Option A, 130 DSiWare: stock size 0x41e400, 499 KiB free (largest block 497 KiB); 130 of 383 icon slots set; the old bitfield 0x33c624 stays 0; device heap 13 MiB.
  - Option A, same day, after 40 more 3DS games were installed (129 DSiWare, 81 SD titles): 507,668 bytes free (was 510,680), largest block 494,392 (was 509,084); device heap, remainder, system heap and config memory unchanged. 3DS icon pool 93 of 320 slots in use (was 53), DSi icon slots 129. So 40 more 3DS titles cost about 3 KB of group 44; their icons come from the fixed 3DS pool.

## Allocation failure and the AM guards

### fs kernel halt (the first crash past 47 tiles)

- Signature: Luma "prefetch abort (kernel panic)", "Debug event", process `fs`, pc FFF1C848, lr FFF23CE0, IFSR 2. Dumps 01 to 04, also with the leak guard in place.
- Cause: when 83 new tiles are added at once, group 44 runs empty. The TWL tile loader gets NULL for its 16 KiB sub-banner buffer (0x1326f4), checks it only before the memset and passes it unchecked at 0x13270c to GetLegacySubBannerData (0x1372b4 -> 0x1441f0, fs command 0x084d0102, buffer descriptor in word 5). The kernel stops on purpose while translating an IPC request with a null buffer (0xFFF23CDC `bllt kernelpanic`). Registers match: r4 = 5 (word), r5 = 0x4000 (size), r6 = 0 (address).
- `fs` shows up only because it was waiting in svcReplyAndReceive. An early reading of an svcOutputDebugString from `fs` was wrong: 0x123de8 is `svc 0x4f` and the 27 is the handle count. The debugger plays no part.
- So pc FFF1C848 / lr FFF23CE0 in any process means "a client sent this process an IPC request with a null buffer". Dump 08 shows the same signature in `am` (r4 3, r5 0x10000, r6 0): HOME's 64 KiB buffer at 0x2ae248 reaches the AM wrapper 0x10e738 unchecked.
- Throttling the fs requests does not help; only enough memory plus NULL checks do.

### HOME data abort (crash 05)

- With the guards but no growth: process `menu`, data abort at 0x2362d4 (memcpy) reading 0x480. Chain: driver 0x1c7d74 -> 0x2035c4 -> 0x1c7308 -> icon upload 0x24dc74 with [obj+0x1c0] NULL for a banner of kind 0 with nonzero region.
- That state is exactly what the 3DS banner fill 0x220abc leaves when its 0x1680 allocation fails (the chain test reproduces it). Why it hit a TWL tile is not explained.

### The anim-buffer leak

- 0x1c7308 takes its "fresh tile" path whenever [tile+0x5c] (texture) is 0. On that path it allocates the animation pair [tile+0x58] again on every pass without freeing the old one. Stock never re-enters the path, but a tile without a slot does on every cursor visit or reload.
- Guard: `b` at 0x1c73d4 (over `cmp r6,#0`) into the 24-byte cave at 0x305740: if the tile already owns a pair, take Nintendo's refresh path 0x1c745c instead of allocating. The slot request behind it still runs, so the tile gets an icon as soon as a slot is free.
- The only release of the pair (0x201ce4 via 0x204d18, only when [tile+0x44] == 1) zeroes [tile+0x58] at 0x201d78, so the guard cannot reuse a freed block.
- Fixing the leak did not stop the fs halts (crash 02 came with the guard in place). Under A no pair is ever allocated; the guard stays as harmless insurance.

### Allocation-failure guards (`targets/home/11.17.0-eur/caves/guards.S`)

- Fallback states, all Nintendo's own: "rejected banner" (kind 0, region 0; 0x2035c4 returns 0, the driver retries later), "pool full" (0x1c7308's exit for slot -1: [tile+0x48] = -1, placeholder, visited again), static icon instead of the ROM animation, blank static icon.
- Guarded: in the loader 0x132458 the 0x378 and 0x23c0 buffers, A, the 0x4000 sub-banner buffer, B and T; the 0x36c0 cache buffer in the drivers 0x1c7748 and 0x1c7d74 (the second replaces a duplicate memset); the banner object and the icon source in the attach check 0x2035c4 (`attach_guard`) and again before the slot request (`src_guard`, 0x1c7488); the animation pair and its copy in 0x1c7308; both buffers of the 3DS fill 0x220abc.
- Not traced: consumers of 0x225434-built objects outside the tile chain (0x1150a8, 0x29840c, 0x2be688, 0x2be724, 0x2e9304..0x2e95b8) now see a rejected object instead of a NULL memcpy; whether they read +0x1c0 without a region check is unknown.

### AM guards (`targets/home/11.17.0-eur/caves/amguard.S`)

- The three AM request wrappers 0x10e738 (AM 0x00020082), 0x14a700 (AM 0x00090082) and 0x14a754 (AM 0x00030084) get a NULL check on their output buffer: with NULL they return 0xC86083F3 (level Status, summary OutOfResource, module AM, description OutOfMemory) instead of sending the request. The level is Status so that 0x2361e0 does not turn it into a fatal error. Every caller already has an error path for a negative result.
- The two title scans 0x13bef8 and 0x13c160 clear their counts only after their 0xe000 buffer was allocated. On failure they keep the old lists, write 0 to the byte [0x32eda4+1] so that ENSURE_LISTS (0x21e9d8) scans again later, and jump to their own epilogue (0x13c150, 0x13c224).
- Under A the 0x4000 sub-banner fs call behind crashes 01 to 04 no longer happens; the fs guards stay.

### What is tested and what is not

- Emulator tests in `targets/*/*/tests/` (see their docstrings), all passing on the N = 256 build: popcount, bitfield, mapping, the whole tile chain with a failure matrix (`test_chain_a.py`: 288 runs without a fault or a NULL use; the new checks fail against stock), the guards, the heap walker, the AM wrappers (`test_amguard.py`: a valid buffer sends the same request as stock, NULL sends nothing and returns 0xC86083F3; against stock the NULL cases fail), System Settings and the NS list.
- Not emulated: the failure path of the two title scans 0x13bef8 / 0x13c160. Their code was only read. Their normal path runs on every boot (titles and icons appear); the failure path (the 0xe000 allocation fails) is untested.
- Read only: the System Settings read helper at 0x1d0344.
- `leak/test_leak.py` of the earlier builds was not ported: its scenarios cover only the animation pair, which A never allocates.
- Live under A, 2026-11-08: all 130 DS icons, also in folders and on the top screen; animated icons stand still; browser, Miiverse and the return from it; SoulSilver and Mario Party DS (AM position 104); a 3DS game; sleep mode; theme shuffle with reboot; fast scrolling; folders. Camera, game notes, screenshots, Mii Maker and eShop (loads; the service is shut down) were tested with the +5 MiB build, which had less free SYSTEM memory, not with A.

## NS: the TWL launch list (0004013000008002)

- NS v23553, extracted from the NAND backup; this NAND has no separate New 3DS variant (0004013020008002).
- Symptom: with all 130 icons shown, some DS titles (SoulSilver, Mario Party DS) end in Nintendo's error screen ("An error has occurred ... POWER button"), others (Layton, Time Hollow) start. HOME is not the thrower: its only ERR:f path (0x222ad4 -> 0x12c680) and its callers (0x1193d8, 0x215b10, 0x220388, 0x236218), svcBreak at 0x136f28, the error path 0x235e24 and the 10 MiB growth 0x26e8bc all stayed silent (live breakpoints).
- Launch path: APT handler 0x104ac8 -> 0x1074e0 -> 0x1051b8 -> 0x1097d0 -> 0x11214c. For NAND DSiWare (00048004) the gate at 0x1121d0..0x11225c calls am:u CheckContentRights(tid, 0) (0x002500c0, at 0x112224); without rights it returns 0xD8808039 (0x112258). Live the check passes (r0 0, hasRights 1) for Mario Party.
- Then NS fills the DeliverArg list for TWL_FIRM through 0x103300 (`mov r3,#77` at 0x103304) -> GetTwlTitleListForReboot (am:u 0x04110044, wrapper 0x109db0): count at +0x950, title IDs u64[77] at +0x9a0, content IDs u32[77] at +0xc10 (0x215950, 0x2159a0, 0x215c10). The list follows AM's order, the same order in which HOME adds tiles. TWL_FIRM starts only titles in this list, so AM positions 78 and later fail. The real limit on the launch path is 77, not 40. NS itself has no 40.
- CRC: 0x110a28 covers only +0x400..+0x540, so the list needs no recomputation. Luma copies back only +0..+0x400 from TWL mode. TLNC +0x310 is cleared by 0x110a28 before the final stop.
- Fix (`targets/ns/11.17.0/caves/cave256.S`): the hook at 0x112244 turns `bl 0x103300` into `bl 0x11fa40`; the cave (260 bytes) sits in the zero padding 0x11fa3c..0x120000 after `.text`.
  1. Call the stock list (77 entries).
  2. Look for the target; its TID high is converted as AM does (00048004 -> 00030004; live, AM returns the 0003 form).
  3. If absent, ask AM again with the same command for 256 entries.
  4. Write the target with AM's content ID into slot 76, or append it when the list has fewer than 77 entries. Slot 77 stays free for the caller's own append.
  5. On any AM error or an unknown title the list stays stock.
- Memory of the 256 variant: 3 KiB of scratch. The title IDs (2048 bytes) go into the unused bss tail 0x217658..0x217e58 (bss and the startup clear end at 0x217654, the page at 0x218000). The content IDs (1024 bytes) go into the cave's own stack frame (`sub sp,#0x410`) on the launching thread's stack. Stack need below the hook: 0x448 bytes (emu; stock 0x20).
- Stack bound: the launching thread is created at 0x101dc4 with stack top 0x2102a8 (literal at 0x101e40); the wrapper 0x111ab8 gets only the top. The next referenced object is at 0x20ba98 (12 + 0x1000 bytes, ends 0x20caa4), so the stack is probably 0x20caa8..0x2102a8 (0x3800 bytes; inferred, an unreferenced object could sit in between). Live at the hook sp = 0x20f118, in the cave 0x20ecf0; the cave reaches down to 0x20ecd0. A live stack dump showed 0x20caa8..0x20f060 (9656 bytes) never written since boot, so the frame fits. "Zero bytes right below sp" does not work as a check: dead frames below sp are not zero.
- `targets/ns/11.17.0/target.py` checks 10 anchor words for these assumptions (`ANCHORS`). Luma's own NS patterns still match after the IPS; only 0x112244 and the cave change.
- Live, 2026-11-08: AM reports 134 TWL titles (outNum 134; the notes do not say why that is 4 more than the 130 DSiWare tiles). Mario Party DS (`0004800441385450`) sits at index 103 of AM's full list (AM position 104), goes to slot 76 with content ID 0x0047e0d4, and starts. Layton (`0004800441354650`) is at index 17 (content ID 0x0011a5f9), the list stays stock, it starts. Patch active: 0x11fa90 = `e3a03c01` (256).
- Install note: Luma loads sysmodule patches only from `/luma/sysmodules/<tid>.ips` and only with "Enable loading external FIRMs and modules" (game patching is not enough, Luma `patcher.c`). That option also loads any `firmware*.bin` under `/luma/` and any `.cxi` under `/luma/sysmodules/`, so check for those first. NS loads once, so the patch takes effect after a reboot.

## System Settings: Mset.dat and Launcher.dat (0004001000022000)

- Unpatched, Data Management shows only 40 DSiWare (8 pages of 5) and does not crash; the titles past 40 cannot be managed there (FBI under "Titles" can delete them). It rebuilds its list on every open. Deleting a DSiWare title there works with the HOME patch in place.
- Where the 40 comes from: the display order is `MSETSYS:/Mset.dat`, 40 x u64 = 320 bytes, in system save 00020220 (64 KiB). The title records (name, icon, size; 0x18a0 bytes each) are already in bss with 300 slots and need no move. The page count is computed as (count-1)/5; there are 20 recycled row widgets.
- Patch, 23 records: buffer sizes 320 -> N x 8; loop bounds 40 -> N in the list builder 0x2013f0, the validator 0x2000a0, the import 0x1ff494 and the delete path 0x1ffa88 (length, bound and offsets of the last entry); two rewritten shift loops (`targets/settings/11.17.0-eur/caves/shift.S`, 25 words each at 0x201588 and 0x1ff568); three UI caps (0x224b68, 0x1fe800, 0x225564); the read helper 0x1d0344 takes its path that accepts a smaller file and pads it with zeros (the validator turns the zeros into -1). On the first run `Mset.dat` is still 320 bytes.
- Persistent effect: `Mset.dat` grows to N x 8 bytes at the first write (SetSize). Unpatched, it shrinks back to 320 at the next write. If needed, delete it with GodMode9; it is recreated.
- `Launcher.dat`+0xBB0 is not changed (see above).
- N values that do not encode: the tool needs N, N x 8, (N-2) x 8 and N-2 as ARM immediates. Above 128 that holds only for even N (for example N = 255: 2040 is not an immediate). So N is 2..128 or even 130..256.
- Live: with N = 256, Data Management showed 10 pages with all 46 titles (2026-11-07). Emulated: the three loops and the validator, 480 cases each for N = 40, 128 and 256.

## Rejected variants

### Icon pool with heap growth and exheader ("twlpool")

- What: keep the animated icons and give every tile its own slot by creating more TWL textures on demand. Slot table and bitfield in a new bss page (0x383000, 0x383220) via a Luma `exheader.bin` (bss 0x4171c -> 0x4271c); textures created lazily from group 44 (cave 0x305610, 292 bytes: `lazy`, `clr_tail`, `clr_leaf`); teardown loop over T textures (T = N/8 + 1); HOME heap grown by G in 1 MiB steps, G = need minus the 324 KiB measured free, need = (N-47) x 0x11c8 + one load peak + 256 KiB margin + (T-6) x 128 KiB. N = 130: G = 2 MiB, N = 256: G = 5 MiB.
- Measured:
  - N = 130, +2 MiB: every DSiWare got a slot, 17 textures, but icons from slot 48 on were partly garbage, and the screen froze once while unwrapping. Cause of the garbage: `lazy` allocated with alignment 4 and did not clear, while Nintendo allocates through 0x236454 (alignment 0x80). Fixed by aligning to 0x80, clearing 128 KiB and publishing the pointer last (beyond Nintendo, which neither clears nor flushes at creation; every upload flushes the whole 128 KiB through GSP). The freeze has no explanation in the code.
  - N = 256, +5 MiB after the fix: icons correct, no freeze, 5515 KiB free in group 44; camera, game notes, screenshots, Mii Maker, a 3DS game and DS games past position 78 fine; browser crashes, Miiverse hangs.
- Dropped: 5 MiB of SYSTEM memory are not available (browser, Miiverse). Textures make up about 4 of the 5 MiB.

### +1 MiB without pool

- What: guards plus G = 1 MiB (the smallest step), animated icons, slots capped at 47, so tiles 48 and later show the placeholder.
- Measured: HOME boots with 14 MiB, the "new software" burst passes, the layout is saved; a DS game started and returned; 1380 KiB free fresh, 944 KiB after unwrapping. Browser runs, Miiverse hangs, with and without the NS patch.
- Dropped: Miiverse has less than 1 MiB headroom.

### G = 0 without A

- What: the same guards in stock memory, still animated icons, slots capped at 47.
- Measured: the first build of this kind turned the fs kernel halt into crash 05 (HOME data abort, see above), which led to more guards. The final one: Miiverse starts, but leaving it ends in the `am` kernel halt (dump 08), because the reload after the return sends AM a request with a NULL buffer.
- Dropped: 130 animated tiles at 0x11c8 each do not fit into the 324 KiB free. It led to A (no animation pairs at all) plus the AM guards.

### Other designs for stock memory (not built)

- B: the first 47 animated, the rest static in free 3DS cells. About twice the code; which 47 animate depends on load order; risk for the 3DS icons.
- C: a temporary heap extension only while HOME is in the foreground, like Nintendo's +10 MiB at 0x26e8e4. Needs hooks at 5 APT launch functions plus return and sleep; Nintendo's own extension goes fatal on failure; icons reload after every return. High risk.
- D: move the remainder into group 44 (only 0x3070ec). At most about 0.7 MiB, not enough for icons, and the remainder's users are unknown.

### A+

- What: like A, but truly animated icons (banner version 0x103) get a whole row again, at most about 47 of them; entry through the kind-1 jump table entries at 0x2030d4 and 0x2006cc.
- Measured: nothing; not built.
- Dropped by decision on 2026-11-08 ("we stay with A"). Idea for later.

### NS: rights gate skip and the 205 variant

- Gate skip: `0x112220` `e1a0000d` -> `ea000006` (`b 0x112240`), skipping CheckContentRights. Dropped before install: live the rights check passes, the list is the cause.
- 205 variant (`cave.S`, 264 bytes, 286-byte IPS): the second AM query asks for 205 entries into the bss tail (title IDs 0x217658, content IDs 0x217cc0). Live: AM accepts the count, Mario Party at index 103 starts. Dropped: titles past AM position 205 stay blocked, and 256 entries need 3 KiB, more than the bss tail; hence the stack frame in the 256 variant.

### Earlier steps, superseded

- Stage 1 moved only the list (caps 40), stage 2 raised the caps to 120 with the icon cap still at 40 (black icons past 40), then N = 256 with icons up to 47 (`cmp r0,#47; ble` at 0x20327c), which crashed with 130 titles. An `--max 47` build was the stable interim state. A first idea to hook 0x14d208 was wrong because that function is live.
- A background that scrolled along was seen in stage 1. The counts were identical to stock, so it is not the patch (probably the theme; not checked).
- SHA-256 prefixes of IPS files that were on the card at some point, to recognise a leftover (the sources are gone):

| File | Build |
|---|---|
| `fee01fc8` | HOME stage 1 (move only) |
| `c859ecf0` | HOME stage 2, N = 120 |
| `e7f6cbcf` | HOME N = 256, icons up to 47 |
| `004ab5d1` | HOME `--max 47` |
| `e3d96301` | HOME N = 256, guards, no pool, G = 0 (crash 05) |
| `2c502aca` | HOME N = 256, guards, no pool, +1 MiB |
| `d9698bd9` | HOME N = 130, twlpool before the alignment fix, +2 MiB |
| `5fe33697` | HOME N = 256, twlpool, +5 MiB |
| `9a1e26ce` | HOME N = 256, guards, no pool, G = 0 (final G = 0 build) |
| `04906e5a` | `exheader.bin` for the twlpool builds (one extra bss page) |
| `eb02e0c8` | NS 205 variant |

## NDSForwarder

- NDSForwarder (MechanicalDragon0687/ndsForwarder at `ad56edf`) refuses to install more forwarders once 40 user TWL titles exist: `#define MAX_DSIWARE 40` in `source/menu.cpp`. `tools/ndsforwarder-256.diff` raises it to 256 and sets `APP_TITLE` to "NDS Forwarder 256", so it runs next to the original.
- Built 2026-11-07 in `devkitpro/devkitarm:latest` (libctru 2.7.0-1, citro2d 1.7.0-1, citro3d 1.7.1-2) with `make TARGET=ndsForwarder`; the `.3dsx` had sha256 `96be19ec…`. An earlier 120 build worked the same way.
- "Install All" on `/roms/nds/` installs past 40; the new titles appear as gifts already before a reboot.

## Live measurement

- Luma's GDB stub (Rosalina debugger on), `arm-none-eabi-gdb` from the devkitARM docker image: `target extended-remote <console-ip>:4000`, `info os processes`, `attach <pid>`, `detach`. In this project HOME (`menu`) was pid 16 and NS pid 7; check them every time.
- `targets/home/11.17.0-eur/gdb/heapstat.gdb`, command `heaps`: device heap object 0x345fcc (alive 0x347828, size 0x347824, default group 0x347820, sub-heap count 0x34781c), walks of the device heap (head 0x345fe8), the remainder (0x347718, alive 0x347764), group 44 (slot table 0x347768, sub-heap 0x346034 + k x 0x2d8) and the system heap (0x345f7c); the override bytes; config memory 0x1FF80040/44/48 (live: 0x07c00000, 0x063f5000, 0x02000000). `groups` prints one line per sub-heap without walking. The walker logic is tested offline by `targets/home/11.17.0-eur/tests/test_walker.py`.
- `targets/home/11.17.0-eur/gdb/check-a.gdb`: `dsislots` counts the set bits of the 12 words at 0x34d2e0 (must equal the DSiWare tiles with an icon) and prints the old bitfield 0x33c624 (must stay 0); `cells3ds` dumps 0x36665c.
- `targets/ns/11.17.0/gdb/ns-list256.gdb` (NS): stops at the gate 0x1121d0, the hook 0x112244 (sp, plus a dump of 0x20b000..0x2103c4 into a directory mounted on the host), the cave 0x11fa98 / 0x11fab4 (second AM query, target index), the list 0x112248, `final` at 0x111e54 right before pm LaunchFIRM (count, target, list, content IDs, CRC block) and NS ERR:f at 0x110ebc / 0x1127f4 / 0x10e77c. It takes the target from the gate because 0x110a28 clears TLNC +0x310 before `final`, and tells the variant by the word at 0x11fa90 because r3 does not survive the svc.
- Other useful reads: DSiWare list 0x3827f0, DSiWare ticket bits 0x34d2c0, state block 0x32eda4, layout counters `[0x32f5d4]`+0x18/+0x1c/+0x20.
- None of the scripts writes console memory. Back up HOME's extdata before a test run: a crash in the middle of a layout save could damage the layout.

## Open points

- Emulator test for the failure path of the title scans 0x13bef8 / 0x13c160.
- DS titles past AM position 205 have not been started live (needs more than 205 DSiWare); the emulator covers 256 installed and 300 installed (257 to 300 stay stock).
- Effect of `Launcher.dat`+0xBB0 staying at 40.
- Why crash 05 hit a TWL tile with kind 0 and region set; consumers of 0x225434 objects outside the tile chain.
- The unexplained 0.8 KiB per tile under A, and who uses the 711 KiB remainder.
- The NS stack bound is inferred from the code plus one live stack dump.
- Animated icons (A+), if ever wanted.
- What the HOME Menu does once the 360 shared layout entries are used up.
- Porting: every address and old byte here belongs to the reference dumps. Another build needs its own target ([CONTRIBUTING.md](../CONTRIBUTING.md)); the SHA-256 and old-byte checks refuse anything else. 3dbrew states that the HOME Menu ExeFS is the same for USA, EUR and JPN, so those dumps may simply match the existing target (not checked). A New 2DS XL on the same region and version should have identical dumps (inferred, not checked), but none of the memory measurements above was made on one, nor on an Old 3DS, whose startup config differs (see "Heaps").

# Read-only trace of the NS TWL launch for the 256-title variant (cave256.S at 0x11fa40, hook 0x112244).
# Same as the earlier ns-list.gdb (not kept) plus a live stack check at the hook. Works with stock NS and with
# either cave build.
# Usage (Luma3DS GDB stub, port 4000 on the console):
#   arm-none-eabi-gdb -ex 'set architecture armv6k' -ex 'target extended-remote <console-ip>:4000' \
#     -ex 'set $pid = <ns pid>' -x ns-list256.gdb
# Without $pid the script lists the processes (look for "ns") and quits.
# Stops print and continue. For one launch expect:
#   gate    (0x1121d0): target tid lo/hi, mediatype
#   stack   (0x112244, the hook, before the cave runs): sp, the lowest address cave256 will touch (sp-0x448),
#           and a dump of 0x20b000..0x2103c4 to /d/stack-at-hook.bin (mount a writable dir as /d).
#   cave    (0x11fa98, 0x11fab4; patched NS only, before "list"): second AM query result and outNum, the
#           target's index in AM's full list (only when the target is beyond the first 77).
#           cave256 keeps its content-id scratch at sp+8..sp+0x408 of the cave frame; the tid scratch is
#           0x217658..0x217e58.
#   list    (0x112248): result of the (hooked) list call, count byte
#   final   (0x111e54): right before pm LaunchFIRM, after the CRC block was computed:
#           count, target from TLNC (+0x310), index of the target in the list or "ABSENT", the whole list,
#           the content ids, the CRC block +0x400..+0x43c. Then the console reboots into TWL_FIRM.
#   errf    (0x110ebc / 0x1127f4 / 0x10e77c): NS throwing ERR:f (after a reboot back, if it happens)
set pagination off
set confirm off
set architecture armv6k
if $_isvoid($pid)
  printf "=== set $pid to the pid of 'ns' from this list and rerun\n"
  info os processes
  quit
end
eval "attach %d", $pid

break *0x1121d0
commands
  silent
  printf "=== gate: target tid lo/hi, mediatype, firm=%03x\n", $r5
  x/2wx $r4
  x/bx $r4+8
  set $tlo = *(unsigned int *)$r4
  set $thi = (*(unsigned int *)($r4 + 4) & 0x7fff) | 0x30000
  continue
end

# The hook itself (stock: bl 0x103300; patched: bl cave). Nothing of the cave has run yet.
break *0x112244
commands
  silent
  printf "=== stack: sp at hook=%08x, cave256 reaches down to %08x (0x448 below), stock alone to %08x\n", $sp, $sp - 0x448, $sp - 0x20
  dump binary memory /d/stack-at-hook.bin 0x20b000 0x2103c4
  printf "=== stack: dumped 0x20b000..0x2103c4 to stack-at-hook.bin (analyse offline)\n"
  continue
end

break *0x112248
commands
  silent
  printf "=== list: list call returned r0=%08x, count byte:\n", $r0
  x/bx 0x215950
  continue
end

# Cave only (never reached with stock NS): the second AM query and where AM puts the target.
# Same addresses in cave.S (205) and cave256.S (256); the count printed tells which build runs.
break *0x11fa98
commands
  silent
  printf "=== cave: second AM query (insn at 0x11fa90 %08x: e3a030cd = 205, e3a03c01 = 256) returned r0=%08x, outNum=%u, sp=%08x\n", *(unsigned int *)0x11fa90, $r0, *(unsigned int *)$sp, $sp
  continue
end

break *0x11fab4
commands
  silent
  printf "=== cave: target index in AM's full TWL list = %d (-1 = AM does not list it)\n", $r0
  continue
end

break *0x111e54
commands
  silent
  set $n = *(unsigned char *)0x215950
  set $lo = $tlo
  set $hi = $thi
  printf "=== final: count=%d target (AM form, from the gate)=%08x %08x\n", $n, $hi, $lo
  set $i = 0
  set $found = -1
  while $i < $n
    if *(unsigned int *)(0x2159a0 + 8 * $i) == $lo && *(unsigned int *)(0x2159a4 + 8 * $i) == $hi
      set $found = $i
    end
    set $i = $i + 1
  end
  if $found < 0
    printf "=== final: target ABSENT from the list\n"
  else
    printf "=== final: target at index %d, content id %08x\n", $found, *(unsigned int *)(0x215c10 + 4 * $found)
  end
  printf "=== final: tids (lo hi) x78 slots:\n"
  x/156wx 0x2159a0
  printf "=== final: content ids x77:\n"
  x/77wx 0x215c10
  printf "=== final: CRC block +0x400..+0x440 (crc at +0x43c), +0x440 tid/mediatype, +0x460 flags:\n"
  x/16wx 0x215400
  x/9wx 0x215440
  printf "=== final: TLNC block +0x300:\n"
  x/8wx 0x215300
  printf "=== final: LaunchFIRM(TWL_FIRM) follows, console reboots now\n"
  continue
end

break *0x110ebc
commands
  silent
  printf "=== errf: ERR:f throw from lr=%08x; info: type/result/pc:\n", $lr
  x/bx $r0
  x/2wx $r0+4
  continue
end

break *0x1127f4
commands
  silent
  printf "=== fatal: result=%08x at pc=%08x (lr=%08x)\n", $r0, $r1, $lr
  continue
end

break *0x10e77c
commands
  silent
  printf "=== fatal2: result=%08x type=%d pc=%08x (lr=%08x)\n", $r0, $r1, $r2, $lr
  continue
end

printf "=== armed, start the DSiWare title now (Ctrl-C to stop, then: delete / detach)\n"
continue

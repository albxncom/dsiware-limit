# Read-only live check of option A on the HOME Menu (EUR 11.17.0-50E) over the Luma GDB stub.
# arm-none-eabi-gdb (devkitARM image), with this directory mounted as /g:
#   target extended-remote <console-ip>:4000
#   attach <pid>                   (HOME Menu "menu"; check with info os processes)
#   source /g/heapstat.gdb
#   source /g/check-a.gdb
#   heaps                         -> device heap, group 44 etc. (group 44 must stay at stock size 0x41e400)
#   dsislots                      -> DSi icon slots in use (bitfield 0x34d2e0, 12 words, slots 1..383)
#   cells3ds                      -> the ten words at 0x36665c (3DS icon cell bookkeeping)
#   detach
# Nothing here writes memory or sets breakpoints.

define dsislots
  set $i = 0
  set $n = 0
  while $i < 12
    set $w = *(unsigned int *)(0x34d2e0 + 4 * $i)
    while $w != 0
      set $n = $n + ($w & 1)
      set $w = $w >> 1
    end
    set $i = $i + 1
  end
  printf "DSi icon slots in use: %d of 383 (bitfield 0x34d2e0); old bitfield 0x33c624: %08x %08x (must stay 0)\n", $n, *(unsigned int *)0x33c624, *(unsigned int *)0x33c628
  x/12wx 0x34d2e0
end
document dsislots
Count the set bits of option A's DSi icon slot bitfield (should equal the number of DSiWare tiles with an icon).
end

define cells3ds
  x/10wx 0x36665c
end
document cells3ds
The 3DS icon cell bookkeeping words at 0x36665c.
end

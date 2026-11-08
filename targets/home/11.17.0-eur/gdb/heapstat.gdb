# Read-only heap statistics for the HOME Menu (EUR 11.17.0-50E) over the Luma GDB stub.
# arm-none-eabi-gdb (devkitARM image), then:
#   target extended-remote <console-ip>:4000
#   attach <pid>                    (HOME Menu is process "menu"; check the pid with info os processes)
#   source heapstat.gdb
#   heaps                          -> device heap, remainder heap, group 44, system heap, config memory
#   groups                         -> one line per created sub-heap (range only, no walk)
#   detach
# Nothing here writes memory or sets breakpoints. Each heap walk reads 4 words per block over the free
# and used lists (ExpHeap); the heaps themselves are never dumped.
# The layout was derived from 0x12c6b8 (create), 0x12c74c (alloc), 0x137b48 (free), 0x12c93c
# (allocatable size) and checked offline with ../tests/test_walker.py.

define heapstat
  # $arg0 = address of the ExpHeap head (wrapper + 0xc + 0x18), $arg1 = name
  set $h = (unsigned int)$arg0
  set $start = *(unsigned int*)($h + 0x18)
  set $end = *(unsigned int*)($h + 0x1c)
  set $fsum = 0
  set $fmax = 0
  set $fcnt = 0
  set $b = *(unsigned int*)($h + 0x24)
  while $b != 0 && $fcnt < 100000
    set $sz = *(unsigned int*)($b + 4)
    set $fsum = $fsum + $sz
    if $sz > $fmax
      set $fmax = $sz
    end
    set $fcnt = $fcnt + 1
    set $b = *(unsigned int*)($b + 0xc)
  end
  set $ucnt = 0
  set $usum = 0
  set $b = *(unsigned int*)($h + 0x2c)
  while $b != 0 && $ucnt < 100000
    set $usum = $usum + *(unsigned int*)($b + 4)
    set $ucnt = $ucnt + 1
    set $b = *(unsigned int*)($b + 0xc)
  end
  printf "%-10s head %08x range %08x..%08x total %8u (%6u KiB)  free %8u in %4u blocks, largest %8u  used %8u in %4u blocks\n", $arg1, $h, $start, $end, $end - $start, ($end - $start) / 1024, $fsum, $fcnt, $fmax, $usum, $ucnt
end
document heapstat
heapstat HEAD "name": range, total, free sum, largest free block, used block count of one ExpHeap.
end

define groupheap
  # $arg0 = heap group id (0..44), $arg1 = name. Sub-heap B[k] = 0x346034 + k*0x2d8, k from the slot table.
  set $gid = (int)$arg0
  set $k = *(int*)(0x347768 + 4 * $gid)
  set $n = *(int*)0x34781c
  if $k < 0 || $k >= $n
    printf "%-10s group %d: no sub-heap (slot %d, %d sub-heaps exist)\n", $arg1, $gid, $k, $n
  else
    set $B = 0x346034 + $k * 0x2d8
    if *(unsigned char*)($B + 0x70) == 0
      printf "%-10s group %d: sub-heap %d not alive\n", $arg1, $gid, $k
    else
      printf "group %d -> sub-heap %d at %08x, declared start %08x size %08x\n", $gid, $k, $B, *(unsigned int*)($B + 4), *(unsigned int*)($B + 8)
      set $hh = $B + 0x24
      heapstat $hh $arg1
    end
  end
end
document groupheap
groupheap ID "name": statistics of the sub-heap that heap group ID lives in.
end

define heaps
  printf "device heap object 0x345fcc: alive %d, size %08x, default group %d, %d sub-heaps created\n", *(unsigned char*)0x347828, *(unsigned int*)0x347824, *(int*)0x347820, *(int*)0x34781c
  heapstat 0x345fe8 "device"
  if *(unsigned char*)0x347764 != 0
    heapstat 0x347718 "remainder"
  else
    printf "%-10s not alive\n", "remainder"
  end
  groupheap 44 "group44"
  heapstat 0x345f7c "system"
  printf "override: thread handle [0x32f064]=%08x  [0x34782c+0x98]=%d [0x34782c+0x99]=%d  [0x3478c8+0x72]=%d [0x3478c8+0x73]=%d\n", *(unsigned int*)0x32f064, *(unsigned char*)0x3478c4, *(unsigned char*)0x3478c5, *(unsigned char*)0x34793a, *(unsigned char*)0x34793b
  printf "config memory 0x1FF80040: %08x  0x1FF80044: %08x  0x1FF80048: %08x\n", *(unsigned int*)0x1FF80040, *(unsigned int*)0x1FF80044, *(unsigned int*)0x1FF80048
end
document heaps
Device heap, remainder heap, heap group 44, system heap statistics plus the allocator override flags and
configuration memory 0x1FF80040/44/48.
end

define groups
  set $n = *(int*)0x34781c
  set $j = 0
  while $j < $n && $j < 8
    set $B = 0x346034 + $j * 0x2d8
    set $g = 0
    set $found = -1
    while $g < 45
      if *(int*)(0x347768 + 4 * $g) == $j
        set $found = $g
      end
      set $g = $g + 1
    end
    printf "sub-heap %d (group %d): alive %d, start %08x size %08x (%u KiB), nested %d\n", $j, $found, *(unsigned char*)($B + 0x70), *(unsigned int*)($B + 4), *(unsigned int*)($B + 8), *(unsigned int*)($B + 8) / 1024, *(int*)($B + 0x2d4)
    set $j = $j + 1
  end
end
document groups
One line per created sub-heap (up to 8): owning group, range, size. No list walk.
end

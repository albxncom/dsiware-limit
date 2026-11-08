# Contributing

Contributions are welcome. This file explains how targets work and how to add one for another build.

Never commit dumps, decrypted titles, disassembly listings or decompiled code. A target holds only addresses, the stock words of the instructions it patches, and its own assembly.

## How targets work

- A target is one build of one title: `targets/<role>/<build>/`, where `<role>` is `home`, `settings` or `ns`, and `<build>` is `<system version>-<region>` (for example `11.17.0-usa`), or just the system version for a region-free title like NS.
- `target.py` defines `SHA256` (of the decrypted, decompressed `.code`) and `records(n, code)`, which returns a list of `(address, old bytes, new bytes)`. Addresses are virtual (file offset = address - 0x100000). It raises `ValueError` when N does not encode.
- `dsiware-limit.py` finds every `targets/*/*/target.py` by itself and picks one by the dump's hash. It then checks every old byte against the dump, refuses overlapping records, and checks that nothing outside the records changed.
- The output path comes from the dump's file name, so one target serves every title ID whose code is identical. If a dump already matches an existing target, there is nothing to port: add the region to the README table.

## Adding a target

1. Dump the three titles as in the README, then run `python3 -I dsiware-limit.py --identify`. Every role without a target needs a port.
2. Copy the reference target of that role, then set `SHA256` to the new hash:

   ```sh
   cp -r targets/settings/11.17.0-eur targets/settings/11.17.0-usa
   ```

3. Find every patch site in the new dump. Everything in the copy is an address of the reference build:
   - the records and constants in `target.py`;
   - the `.set`/`.equ` constants, branch targets and literals in `caves/*.S`;
   - the link addresses and `--defsym` values in `assemble.sh`;
   - the constants at the top of each test in `tests/`.

   Each record carries a comment with its function and the stock instruction, and `docs/findings.md` explains what each function does. The reference work was done in Ghidra; its Version Tracking between the reference dump and the new one maps most functions, and the rest can usually be found by the instruction patterns in the comments. Check that every cave area is still zero-filled padding in the new build (`cave()` refuses otherwise).
4. Reassemble the caves: `sh targets/<role>/<build>/assemble.sh` (docker). It writes fresh `.bin` and `.syms` files to `out/asm/<role>-<build>/` and compares them with `caves/`. Copy the fresh files over and rerun until everything says "same".
5. Build: `python3 -I dsiware-limit.py --max 256`. A wrong address shows up as "old bytes differ from the dump".
6. Run the tests: `sh test.sh dumps`. They run the real code of the dump in unicorn, stock and patched side by side.
7. Test on the console:
   - [ ] Boot, every DSiWare icon present, also in folders and on the top screen
   - [ ] Internet Browser starts
   - [ ] Miiverse starts, and returning from it does not hang
   - [ ] Sleep mode, theme shuffle with a reboot, fast scrolling
   - [ ] A 3DS game
   - [ ] DS titles before and past AM position 77 (DSiWare installed as the 78th title or later)
   - [ ] System Settings > Data Management lists, copies and deletes them

   With the Luma debugger on, the GDB scripts in `targets/<role>/<build>/gdb/` read the free memory of the HOME Menu (`heaps`, group 44) and the icon slots in use (`dsislots`). They never write console memory. The numbers of the reference console are in `docs/findings.md` ("Heaps and the ExpHeap layout").

## Pull request checklist

- [ ] `targets/<role>/<build>/` with `target.py`, `caves/` (sources and assembled files), `assemble.sh`, `test.sh`, `tests/`
- [ ] `sh test.sh dumps` passes; paste the output
- [ ] `assemble.sh` of the new target says "same" for every file
- [ ] A row in the README table, with what was tested on which console
- [ ] No dumps or other Nintendo code in the diff

## Conventions

- The build tool uses only the Python standard library. Tests may use unicorn and capstone through `uv run --with`.
- Comments say why, and what a magic address is (function, stock instruction).
- New findings, including dead ends, go into `docs/findings.md`, tagged with how they were obtained: "code" (read from the dump), "emu", "live" (read on the console) or "inferred".

# dsiware-limit

Raises the DSiWare title limit of the 3DS HOME Menu from 40 to N (up to 256) with three Luma3DS IPS patches, built from your own decrypted code dumps.

This is a proof of concept, not a release. There are no prebuilt patches: you build them from your own dumps, and the build refuses any dump it has no target for. It has been tested on one console (New 3DS XL, EUR 11.17.0-50E, 130 DSiWare). Contributions are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## What it changes

- HOME Menu: shows and launches up to N DSiWare tiles. All DSi icons are static, packed 8 per texture row, so the stock icon textures hold them all and the HOME Menu keeps its stock memory.
- System Settings > Data Management: lists, copies and deletes up to N DSiWare titles.
- NS sysmodule: DS titles past AM position 77 start. Same patch for every N.

How and why: [docs/findings.md](docs/findings.md). Why DS games should be DSiWare forwarders at all (17 s against 42 to 61 s per launch): [docs/ds-launch-paths.md](docs/ds-launch-paths.md).

## Supported dumps

| Role | Target | Dump SHA-256 (decrypted `.code`) | Console test |
|---|---|---|---|
| HOME Menu | `targets/home/11.17.0-eur` | `5f4d8d0e80d8e7d6fafcefa0630c5106473ade4658585cfb499a6ec3324d89a7` | New 3DS XL EUR, 2026-11-08 |
| System Settings | `targets/settings/11.17.0-eur` | `3dbb076b95304d3612b7b746a2927576b84bd83bd2b2db9f71c41cf732737cec` | New 3DS XL EUR, 2026-11-08 |
| NS | `targets/ns/11.17.0` | `0e9c322edb02e4a7373282a7cd3e66d2e66d9e8832a0775f84fbbe34c81688a0` | New 3DS XL EUR, 2026-11-08 |

A target is chosen by the hash of the dump, not by region. 3dbrew states that the HOME Menu ExeFS is the same for USA, EUR and JPN, and NS is one title for every region, so on a USA or JPN console only System Settings might need a port. Nobody has checked yet; `--identify` tells you.

Title IDs (from the [3dbrew title list](https://www.3dbrew.org/wiki/Title_list)):

| Region | HOME Menu | System Settings |
|---|---|---|
| JPN | `0004003000008202` | `0004001000020000` |
| USA | `0004003000008F02` | `0004001000021000` |
| EUR | `0004003000009802` | `0004001000022000` |
| CHN | `000400300000A102` | `0004001000026000` |
| KOR | `000400300000A902` | `0004001000027000` |
| TWN | `000400300000B102` | `0004001000028000` |

NS is `0004013000008002` everywhere.

## Build

Needs Python 3.9 or newer, standard library only.

1. Put your dumps in `dumps/` as `<titleID>.dec.code`. They are Nintendo code, so they stay out of git.
   - HOME Menu and System Settings: in GodMode9, open the title's `.app` under `1:/title/00040030/<low>/content/` (HOME Menu) and `1:/title/00040010/<low>/content/` (System Settings), where `<low>` is the last 8 digits of the title ID, then "NCCH image options" > "Extract .code". The files land in `0:/gm9/out/`.
   - NS: from a GodMode9 SysNAND backup and your own `boot9.bin`:

     ```sh
     uv run --no-project --with pyctr -- python -I tools/extract_sysmodule.py --nand sysnand.bin --boot9 boot9.bin --out out/extract --title 00040130/00008002
     cp out/extract/0004013000008002/code.dec.bin dumps/0004013000008002.dec.code
     ```

2. Check which targets your dumps match:

   ```sh
   python3 -I dsiware-limit.py --identify
   ```

3. Build:

   ```sh
   python3 -I dsiware-limit.py --max 256
   ```

   This writes `out/max-256/luma/`. N can be anything from 2 to 128, and any even number from 130 to 256; the tool refuses values that do not fit the ARM encodings. Options: `--dumps DIR`, `--out DIR`. Every patched byte is checked against your dump.

## Install

1. Back up your NAND and the HOME Menu extdata.
2. Copy `out/max-256/luma/` to the SD card root. With EUR title IDs these files then exist:
   - `/luma/titles/0004003000009802/code.ips`
   - `/luma/titles/0004001000022000/code.ips`
   - `/luma/sysmodules/0004013000008002.ips`
3. In the Luma configuration (hold SELECT at boot), turn on:
   - "Enable game patching" (`enable_game_patching = 1` in `/luma/config.ini`), which loads the HOME Menu and System Settings patches.
   - "Enable loading external FIRMs and modules" (`enable_external_firm_and_modules = 1`), which loads the NS patch. It also loads any `firmware*.bin` under `/luma/` and any `.cxi` under `/luma/sysmodules/`, so check for those first.
4. Reboot.

## Uninstall and recovery

- Delete the three files and reboot. The HOME Menu then loses the layout of the DS titles past 40: when the patch comes back, they reappear as new software, without their positions and folders.
- If the console does not reach the HOME Menu, hold SELECT at boot, turn both options off, boot, and delete the files.

## Known limits

- DSi icons are static, including animated ones and custom icons from `banner.sav`.
- The HOME Menu has 360 layout entries for all titles together. With 256 DSiWare, 104 remain for everything else.
- `Launcher.dat`+0xBB0 (40 title IDs, a HOME Menu file that System Settings writes when it copies DSiWare) stays at 40. System Settings silently skips the entry when that field is full. Its effect is unknown.
- `Mset.dat` (system save 00020220) grows to N x 8 bytes the first time it is written. Without the patch it shrinks back to 320 bytes on the next write.
- Tested only on a New 3DS XL. The Old 3DS starts the HOME Menu with a different memory configuration, and nothing has been measured there.

## Tested

New 3DS XL, EUR 11.17.0-50E, Luma3DS, N = 256, 130 DSiWare, 2026-11-08: all icons (also in folders and on the top screen), Internet Browser, Miiverse and returning from it, sleep mode, theme shuffle with reboot, fast scrolling, a 3DS game, DS titles before and past AM position 77. The emulator tests in `targets/*/*/tests/` pass. Not covered: DS titles past AM position 205 on the console (needs more than 205 DSiWare; covered in the emulator) and the error path of the two HOME Menu title scans.

## Repository layout

```
dsiware-limit.py          identify dumps, build the IPS files
patchkit.py               ARM encoders, cave and record helpers, the checked IPS build
test.sh                   build N = 256, then run the tests of every target that matched a dump
targets/<role>/<build>/   one build of one title (role: home, settings, ns)
  target.py               SHA256 of the dump and records(n, code): every patched span with its stock bytes
  caves/                  assembly sources plus the assembled blobs the build reads (no toolchain needed)
  assemble.sh             reassembles caves/ with devkitARM (docker) and compares with the committed blobs
  test.sh, tests/         emulator tests (unicorn, capstone via uv) on your dump
  gdb/                    read-only scripts for the Luma GDB stub
docs/findings.md          internals, measurements, rejected variants, open points
docs/ds-launch-paths.md   DS launch times and their causes
tools/                    NS extractor, NDSForwarder patch
```

Development checks, all from the repo root:

```sh
python3 -I dsiware-limit.py --max 256     # build
sh test.sh dumps                          # emulator tests, needs uv
sh targets/home/11.17.0-eur/assemble.sh   # cave blobs match their sources, needs docker
```

## NDSForwarder

NDSForwarder refuses to install forwarders once 40 user TWL titles exist. `tools/ndsforwarder-256.diff` raises `MAX_DSIWARE` in [MechanicalDragon0687/ndsForwarder](https://github.com/MechanicalDragon0687/ndsForwarder) (at `ad56edf`) to 256 and renames the app "NDS Forwarder 256", so it runs next to the original. Build it with `make TARGET=ndsForwarder` in devkitARM.

## Legal

Not affiliated with or endorsed by Nintendo. This repository contains no Nintendo code: dumps stay in `dumps/` and are ignored by git; the targets hold only the stock words of the patched instructions, a few per record, which the build checks against your dump. Use at your own risk.

MIT license ([LICENSE](LICENSE)), except `tools/ndsforwarder-256.diff`, which modifies GPL-3.0 code and is under the GPL-3.0.

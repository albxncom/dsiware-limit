# DS launch paths

Why this project lifts the DSiWare limit instead of using 3DS-app forwarders: research from 2026-11-07 and 2026-11-08 on a New 3DS XL, EUR 11.17.0-50E, Luma3DS, with nds-bootstrap starting DS ROMs from the SD card. The patch itself is in [findings.md](findings.md).

## The 40 limit

- Nintendo's manual states 40 DSiWare titles. NDSForwarder counts every user TWL title in NAND against it, including TWiLight Menu++ and forwarder stubs.
- The limit sits in the HOME Menu, not in NAND (GBAtemp thread "[NDS] Forwarder CIAs for your HOME Menu" by RocketRobz, FAQ in the first post and post #6821 on page 342). Installs past 40 go through and appear under System Settings > Data Management > DSiWare; the HOME Menu just does not show the surplus ones. Empty banners are a different problem (file names with Forwarder3-DS).
- As of 2026-11-07 no finished HOME Menu patch was known.

## Measured launch times

Pokémon SoulSilver, stopwatch from pressing the icon to the game, repeated runs per path:

| Path | Total | Screen turns white at |
|---|---|---|
| DSiWare forwarder icon (NDSForwarder / NTR_Forwarder) | 17 s | 6 s |
| Any launch from a 3DS app (APT jump, FIRM launch or reboot) | 42 to 46 s | 10 to 13 s |
| 3DS-app forwarder icon (YANBF v1.6.3) | 61 s | 28 s, with a visible reboot |

- nds-bootstrap plus the game take 12 to 13 s on every path. Everything else is the launch path.
- A first rough measurement gave 15 s (DSiWare) against 60 s (YANBF), and about every second YANBF launch stayed on a white screen.

## Why the paths differ

- YANBF v1.6.3 starts the TWL title with `NS_RebootToTitle`, a real hardware reboot (Luma boot, HOME Menu, only then TWL_FIRM). Upstream went back to the APT jump in 2023, without a release. libctru 2.7.0 requires a third parameter `appmemtype` for `NS_RebootToTitle`.
- A DSiWare forwarder is itself a TWL title, so the HOME Menu only does the FIRM switch. The rest of the chain (`bootstrap.cia`, `sdcard.nds`, nds-bootstrap) is identical on all paths and takes 1 to 2 s.
- Test builds of a 3DS-app stub, all with SoulSilver:
  - DSiWare icon (17 s): the HOME Menu launches the TWL title itself.
  - From a 3DS app (42 to 46 s): `APT_DoApplicationJump`, `NS_LaunchApplicationFIRM` or `NS_RebootToTitle`. With the APT jump the HOME Menu also launches the title, but through its jump handler, and that does not behave like the icon path.
  - YANBF icon (61 s): the reboot costs the remaining 15 to 19 s.
- The 20 s depend only on whether the HOME Menu launches the TWL title from its icon or a 3DS app asks for it, whatever the method (reboot, APT jump, FIRM launch), with or without the banner HMAC, whatever the stub and the title category. The only documented difference is the TWL banner HMAC, which the HOME Menu passes to TWL_FIRM via `NSS:SetTWLBannerHMAC` (FIRM parameter +0x4B0). The buffers of the APT jump land elsewhere (+0x000, presumably as DSi AutoParam, and +0x480), so they cannot carry it. A test build that sets the HMAC itself and then calls `NS_LaunchApplicationFIRM` was as slow as the other 3DS-app paths. The cause is unknown; the `flags` of the APT jump only select the target.

## White screen hangs

- They hit all paths, DSiWare forwarders too (1 of 3 runs in one series).
- Cause not found. Suspicion without proof: the SD initialization in the bootloader of the stubs (YANBF and NTR_Forwarder share that code) has no timeout.
- Every forwarder rewrites `path.txt` right before the handover. That does not explain the slowness: on the reboot path there are 25 s in between, and it is slow anyway.

## Ruled out

- Fragmentation: every ROM was contiguous on the FAT32 card (counted from the raw device).
- The SD card itself, the versions (nds-bootstrap v2.17.0, NTR_Forwarder SD-30), the nds-bootstrap settings (identical to TWiLight Menu++), `sdcard.nds` and `bootstrap.cia`.

## Decision

- Lift the 40 limit in the HOME Menu, so every DS game can be a DSiWare forwarder (17 s). That is this repository.
- Not pursued: removing the 20 s on the TWL side, and patching FIRM/APT so 3DS-app forwarders get from 61 s to 46 s. Both stay open questions.

# Source attribution and execution scope

- `resize_apfs.c`: adapted from HoolockLinux/docs `tools/resize.c` at
  `23ebe1fbc375599221553a7e1815e5de182a6b42`, copyright 2025 Hoolock Linux
  contributors, MIT. Added a probe-only mode and a tightly specified execute
  argument. Retain `LICENSE-Hoolock-MIT.txt` and the entitlement sources.
- `gptcas.c`: brkosebay/omarchy-ipad5 `scripts/nvme-install/ios/gptcas.c` at
  `41f1e15e83720445f46204ff4ffac7edc1d34b3d`, SPDX GPL-2.0.
  Retain `LICENSE-GPL-2.0.txt`. J81 hardening is documented in its source.
- `resize.xml` and `gptcas.xml`: HoolockLinux/docs `tools/resize.xml` and
  `tools/gdisk.xml`, same source pin and MIT notice.

These experimental sources were used on the owner's exact J81 after explicit
native-install authorization. The Apple framework resize to 16 GiB passed;
both GPT copies were updated/verified and normal iPadOS reboot passed. Linux
p2 was then formatted and installed separately through the range-gated Linux
module. Built signed iOS artifacts and private identity/raw metadata are not
distributed. Compiling these sources does not authorize operations on any device.
The hard-coded geometry describes the measured 64 GB owner unit only.

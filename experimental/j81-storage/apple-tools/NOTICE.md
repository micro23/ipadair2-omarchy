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

These are staged experimental tools. Building/signing them is not permission
to execute an APFS resize or a GPT update. The current approved hardware write
scope is one 4096-byte test block, already restored and verified. No resize,
partition modification or filesystem installation has been authorized or run.

The intended native Linux root would use a second partition while retaining
the Apple installation as support for the established cold-boot workflow.
The 16 GiB APFS target is a proposal; measured allocation does not prove the
Apple resizer will accept it. Its runtime must be checked and the concrete
destructive operation approved before execution.

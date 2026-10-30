# omarchy-ipad5 reference assessment — 2026-10-29

Reviewed https://github.com/brkosebay/omarchy-ipad5 at
`41f1e15e83720445f46204ff4ffac7edc1d34b3d`.
Local reference checkout: `work/references/omarchy-ipad5`.
This was a source review; no reference scripts or hardware probes were run.

## Applicability

The reference's tested board is iPad6,11 / j71t / S8003 (A9).
Our board is iPad5,3 / J81 / T7001 (A8X). Its NVMe path does not replace
our ANS1/ASP driver. Its DTBs, firmware, calibration, MMIO addresses, clocks,
charging settings and CPU lifecycle changes are not qualified for J81.

Useful architectural references:

- `scripts/omarchy/initramfs/init`: mount an internal ext4 root, verify its
  identity and exact write-window extent, validate required mountpoints and
  init before moving mounts, then exec switch_root into real PID 1 systemd.
  Adapt the design to J81 ASP identity/range checks and an exact root UUID.
- `docs/nvme-install/`: metadata backups, layout derivation, driver fences,
  transfer verification, install stop conditions and persistence tests.
  Do not run its A9 NVMe or iOS resize/GPT procedures on J81 unchanged.
- `docs/boot/warm-reboot.md`: a future path to warm reboot, requiring an
  EL3 PSCI shim, CPU lifecycle support, runtime FDT preservation and device
  health gates. None of these are established on our J81 by this review.
- `docs/omarchy/` and `patches/omarchy/`: software-rendered desktop/tablet
  integration candidates; board-specific input/display support still required.
- `scripts/boot.sh`: documents transient Pongo USB ownership failures after
  launch. This is a separate failure class from our locally built Pongo
  variants returning to iPadOS; it does not establish a quiet-mode fix.

## Installation planning correction

The reference explicitly retained iPadOS because its existing cold-boot
workflow depends on a bootable Apple installation. See
`docs/nvme-install/DESIGN.md` and `test-plan.md`.
That is a reported A9 workflow dependency, not proof that all checkm8/DFU
paths universally require iPadOS. We must verify our J81 cold-boot and recovery
dependencies before approving any plan that destroys its only APFS partition.
A dedicated Omarchy user experience does not itself establish that deleting
every Apple boot component is technically viable.

Its current status also explicitly says internal root does not remove the
cold-boot tether. Warm kexec does not solve boot after power loss.

## Our verified checkpoint

Our local `private-live/approved-block-test/result.json` reports a successful
4096-byte pattern write, read-back, restoration and verification at the
approved single USERAREA logical LBA 15624738. This does not establish a
full filesystem installation or a qualified broad write window.
No partition replacement is authorized by that bounded test.

Before a destructive proposal: establish a viable retained or replacement
cold-boot path; prepare native root tools and guarded bootstrap; define the
exact layout/write range; obtain explicit approval for that concrete plan.
Current diagnostic one-block window must not be expanded implicitly.

If source is adapted, preserve upstream authorship/SPDX and applicable GPL
terms; do not relicense copied code under our unrelated MIT notices.
No credentials, raw blocks or device identifiers belong in public evidence.

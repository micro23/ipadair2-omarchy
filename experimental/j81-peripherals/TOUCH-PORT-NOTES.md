# J81 touch: usable upstream work and remaining board work

Inspected 2026-10-29, Orchard hardware
`ae1457edee7d2e52213e4d979aee02dbbeb90ce0`, brkosebay/omarchy-ipad5
`41f1e15e83720445f46204ff4ffac7edc1d34b3d`, mattonik/ipad-nixos
`b94d42f78e04c5465e290340a5b6879bbc5956b6`.

## Closest new implementation

The current Orchard A8/iPhone6 (N61/T7000) work is a closer transport reference
than copying the A9/S8003 configuration. Its
`kernel/patches/drivers/spi/0003-spi-apple-add-t7000.patch` applies cleanly to
our prepared working kernel and compiles as an external compatibility artifact.
All undefined symbols exist in the qualified kernel exports. The source/output
were mounted read-only during compilation. This artifact was NOT loaded; the
live SPI driver is built-in, and a duplicate module is not a live replacement.

The patch introduces compatible-selected legacy FIFO configuration0x4018 and
PIO behavior for T7000. It may address part of the old J81 transport gap, but
compilation does not prove wire-level correctness or explain the older59 KB
firmware-ACK failure. The patch is Shayne Legault's; existing Asahi/kernel
copyright and SPDX attribution remain intact.

Related current Orchard components:

- `drivers/input/0006-Input-apple_z2-add-n61-gen1.patch`: Gen1 framing,
  firmware/calibration upload and input integration, with Corellium attribution.
- `drivers/clk/0002-clk-apple-add-t7000-touch.patch`: T7000 clock compatible.
- `drivers/regulator/0002-regulator-apple-add-n61-touch.patch`: N61 supply data.
- `drivers/input/0004-Input-apple_z2-Describe-generation-1-timing-in-match.patch`
  and J71t-specific timing/recovery patches: use match data, preserving each
  board's transport and startup policy.

## Resource mapping that must be ported

| Resource | J81 evidence | N61/A9 transfer limit |
| --- | --- | --- |
| SPI controller | SPI3,0x20a08c000,IRQ155,PS_SPI3; older J81 research | N61 SPI2 base/IRQ must not replace these |
| SPI transport | Running kernel has T8010/default match data, no T7000 match | New T7000 PIO code compiles; J81 wire behavior untested |
| CS/reset/IRQ GPIOs | J81 CS51,reset82,interrupt84 | N61's GPIO185/2/3 are different |
| Supplies | D2207 analog LDO14 and GPIO95 enable | N61 D2186/Chestnut and A9 PMIC registers are not J81 settings |
| Dedicated reference clock | J81 KLCT request32768 Hz; dedicated resource mapping unresolved in old research | N61 PMGR offset0x1e000 is not J81 proof |
| Firmware | J81 N1 personality C1F15,2; old research saw preconstructed Z2 packet | A9 C1F15,1/runtime setup is not a drop-in firmware asset |
| Calibration | Must use this owner's J81 calibration, privately extracted and passed by loader | Never copy another device's MtCl/calibration |
| Runtime reports | Gen1 input parsing/framing is a useful reference | Must bound lengths/checksums and validate actual J81 contacts |

The current native DT exposes no enabled SPI/touch device, and only gpio-keys
was observed in kernel input. Merely adding a compatible or enabling the old
diagnostic spidev node cannot supply these missing startup resources.

## Next concrete device milestone

Prepare a separate candidate kernel with the T7000 SPI transport and J81 SPI3
resources, leaving the touch child disabled initially. Verify bus registration
and preserve the known-working storage/USB/Wi-Fi path. Then bind J81-specific
regulator/clock providers only after their register mapping/sequence is backed
by matching J81 evidence. Supply owner firmware/calibration through the existing
private extraction/loader path. Firmware bootloader ACKs, valid input frames
and physical touches must each be observed before claiming touch works.

No live GPIO, SPI, clock or touch-rail probe was made in this research pass.
The working native desktop remains running, with owner-confirmed noVNC input.

## Primary references

- https://github.com/OrchardLinux/hardware/tree/ae1457edee7d2e52213e4d979aee02dbbeb90ce0/kernel/patches/drivers
- https://github.com/brkosebay/omarchy-ipad5/blob/41f1e15e83720445f46204ff4ffac7edc1d34b3d/docs/release/STATUS.md
- https://github.com/mattonik/ipad-nixos/blob/b94d42f78e04c5465e290340a5b6879bbc5956b6/research/j81-klct-resource-audit.md
- https://github.com/mattonik/ipad-nixos/blob/b94d42f78e04c5465e290340a5b6879bbc5956b6/research/2026-10-12-touch-4cb1-analysis.md
- https://x.com/henrikklee/status/2115941203258822711
- https://x.com/berkaykosebay/status/2115183501175877974

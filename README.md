# ipadair2-omarchy

## Current status — 2026-10-29

The J81 baseline integration, measured hardware results and kernel-wheel fix
have been incorporated into upstream Orchard hardware `main`. See the
[maintainer handoff](integration/2026-10-29/REPORT.md).

The fresh [Pongo quiet/normal comparison](docs/pongo/COMPARISON.md) is complete:
both local source builds returned to iPadOS without a Pongo USB endpoint.
The known-working pinned Hoolock prebuilt remains the qualified loader.

The full **Omarchy A v0.1.1 desktop has booted from the iPad's internal ext4
partition**, with systemd as global PID 1. The owner confirmed the desktop;
Wi-Fi autoconnect, DNS and HTTPS passed, and there were zero failed system units.
The original rootfs archive and installed copy remain distinct. See the
[native installation report](docs/status/2026-10-29-native-install.md).

**A fresh boot also passed:** the persistent counter advanced to 2, the exact
saved owner marker survived, and the native desktop and Wi-Fi returned. The
bootstrap now defers Wi-Fi probing to installed systemd, after an earlier
attempt stalled before recovery USB.
Cold boot still needs a host through Pongo/m1n1; native touch remains unfinished.
The [experimental sources](experimental/j81-storage/README.md) are specific to
this measured J81 and are not a portable installer release.

Owner-confirmed browser mouse/keyboard control and a conservative USB-host
charging path are now available. A 500 mA request enabled small positive battery
current with the display dimmed, but active workloads can still discharge.
Physical touch remains a board-specific port; the newer A8 SPI transport
backport has passed a compile-only check. See the
[peripheral report and source](experimental/j81-peripherals/README.md).

## Original hardware handoff

Public hardware handoff for the **Wi-Fi iPad Air 2 — iPad5,3 / J81AP / A8X
T7001**. This repository contains the device description, exact kernel build
inputs, public device-tree reference, RAM initramfs sources, private-firmware
preparation recipe and Wi-Fi controller source used for a successful RAM test.

The qualified Wi-Fi session loaded BCM4350 firmware, associated using WPA2
Personal, obtained DHCP configuration and passed routing, ICMP, DNS and HTTP
checks. A fresh live check also confirmed a reduced Omarchy-A/Labwc desktop
on that same Wi-Fi kernel, with an active compositor and successful DNS/HTTP
requests as the desktop user. The owner confirmed working Mac keyboard/mouse
forwarding in this combined session. See [qualification](QUALIFICATION.md)
for the observed scope and remaining hardware work.

This is a source contribution for hardware integration. It is **not yet a published, portable Orchard installer or launcher release**. There is no launch-manifest URL to imply that those pieces exist.

## Contents

| Path | Purpose |
| --- | --- |
| `devices/j81/` | Orchard-format device descriptor, firmware recipe and qualification scope |
| `kernel/j81/` | Pinned Linux/J81 patch recipes, effective configs, public DTS references and Linux build adapter |
| `boot/j81/` | Reconstruct the exact firmware-free RAM payload from explicit public inputs |
| `firmware/j81/` | Mac extraction source; firmware and owner-device records remain on the owner's host |
| `runtime/j81/` | Qualified Wi-Fi control logic and the required radio/scan/DNS corrections |
| `provenance/` | Upstream identities, hashes and source-file receipts |
| `LICENSES/` | Retained component notices |
| `docs/pongo/` | Controlled quiet/normal source, build and hardware comparison |
| `integration/2026-10-29/` | Developer-port validation, fixes and upstream incorporation |
| `experimental/j81-storage/` | ANS1 patches, guarded host tools, tests and candidate root policy |

Start with [the device notes](devices/j81/README.md),
[kernel build instructions](kernel/j81/README.md) and
[boot composition](boot/j81/README.md). [Qualification](QUALIFICATION.md)
separates observed hardware behavior from build-time checks and remaining work.

## Hardware contribution context

The Orchard maintainer's request was to contribute hardware support. The
[P105 contribution](https://github.com/OrchardLinux/hardware/pull/2) concerns
the first-generation **iPad mini**, not the original full-size iPad. This J81
tree follows its source-only device/kernel/runtime handoff pattern. It does
not copy P105-specific drivers, boot assumptions or qualification claims.

The descriptor targets the v1 format from
[OrchardLinux/hardware](https://github.com/OrchardLinux/hardware/tree/9bcaef15ba0250503497d3754fa1254e48f96013).
These original producer inputs retain their historical identities. Upstream
Orchard now registers experimental J81/J82 support through its newer hardware
stack; this repository does not replace an installed Orchard package. The
2026-10-29 integration report records the exact baseline actually tested.

## Credits and licenses

The hardware work comes from **HoolockLinux** and the **iPad NixOS
contributors**. Exact source revisions and their Linux patch series are
retained. The desktop userspace came from **OrchardLinux/omarchy-a**. This
handoff adds the RAM-only build configuration, host orchestration, bounded
identity/firmware selection and parser corrections documented here.

See [NOTICE](NOTICE) for component-specific licenses. No Apple firmware,
captured Apple device tree, OTP dump, calibration, Wi-Fi credentials or
session identifiers are included. Binary/rootfs distributions are separate
from this source tree and need their own corresponding-source and license
review.

## Verify this source checkout

Run `shasum -a 256 -c SHA256SUMS` from the repository root. The manifest covers
regular source files; [symlink targets](provenance/symlink-targets.json) record
the three systemd masks separately. They must remain symlinks to `/dev/null`,
not copies of the host device file. Git also records their symlink mode.


## Control an already-running Omarchy desktop from a Mac

[iPad Controls](https://github.com/micro23/ipad-controls) is a small native macOS app that supplies mouse and keyboard input after the iPad has reached its Omarchy Linux desktop. Look at the iPad for its display; click the Mac app's pad to capture input and press Escape to release it. This is useful during bring-up when native touch or attached input is unavailable.

It uses your own authenticated SSH connection and temporary Linux uinput devices. Requirements include Python 3, permission to access `/dev/uinput`, an already-running compositor, and a verified SSH host key. The tested hardware is iPad Air 2/J81 with Labwc; other devices remain unqualified. The optional System info action requires the matching Omarchy About adapter. It does not boot or install Linux.

See the [setup instructions](https://github.com/micro23/ipad-controls#configure-your-connection) and [releases](https://github.com/micro23/ipad-controls/releases). Public builds contain no owner credentials or private device data; each user configures their connection locally.


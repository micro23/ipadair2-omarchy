# ipadair2-omarchy

## Current status — 2026-10-29

The J81 baseline integration, measured hardware results and kernel-wheel fix
have been incorporated into upstream Orchard hardware `main`. See the
[maintainer handoff](integration/2026-10-29/REPORT.md).

The fresh [Pongo quiet/normal comparison](docs/pongo/COMPARISON.md) is complete:
both local source builds returned to iPadOS without a Pongo USB endpoint.
The known-working pinned Hoolock prebuilt remains the qualified loader.

A separate [ANS1 experiment](experimental/j81-storage/README.md) booted Linux
and read this J81's internal 64 GB USERAREA with every namespace read-only.
Full Omarchy A v0.1.1 userspace and native applications have run from NFS/RAM;
**a persistent internal installation and untethered power-on boot are unfinished**.
The experimental write candidate compiles but has no successful live write test.
See the [full checkpoint](docs/status/2026-10-29.md).

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

This is a source contribution for hardware integration. It is **not yet an
Orchard CLI device adapter, published launcher release or internal-storage
installer**. There is no launch-manifest URL to imply that those pieces exist.

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

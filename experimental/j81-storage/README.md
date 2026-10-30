# J81 ANS1 and native-root experiment

The full original **Omarchy A v0.1.1 desktop booted from internal ext4 p2** on
this J81, with global PID 1 systemd, the root identity/write-fence guard passed,
and zero failed system units. The owner confirmed the desktop. Wi-Fi, DNS and
HTTPS passed. [Measured result](reports/native-install-result.json) and
[installation/fix report](../../docs/status/2026-10-29-native-install.md).

A subsequent fresh automatic boot stopped in the early Wi-Fi probe, before USB
setup and before mounting the installed root. The revised bootstrap defers Wi-Fi
to installed systemd/udev and passed a fresh boot: different kernel boot ID,
persistent count 2, exact surviving owner marker, returned desktop and working
Wi-Fi/DNS/HTTPS. [Persistence result](reports/native-reboot-result.json).
Cold boot remains host-tethered through Pongo/m1n1. These are experimental source
references for one measured unit, **not a portable installer release**.

## Base, attribution and qualified driver

- Tested Orchard hardware baseline: `e2b1b591b495ae479951b06c18b99d3c86a0a7a9`.
- Linux upstream pin: `cee9395acd8043be0644b25c34bfa86623f2b935`.
- Orchard-prepared source object before this overlay:
  `8a86872c4bc36d2998f6b1f6b88ec2e0aa97b01e`.
- Nick Chan's ANS1/ASP driver and RTKit/AKF work, via Hoolock `ans1`
  `ed8528f482a526371e59711645794c91fafb2b42`, reconciled/read-only hardened
  in `mattonik/ipad-nixos` `b94d42f78e04c5465e290340a5b6879bbc5956b6`.
- Orchard's existing m1n1 loader fills the ANS firmware region using `asp`.
  The J81 device tree enables ANS/mailbox while retaining Wi-Fi/framebuffer.

The [read-only overlay](patches/Orchard-J81-ANS1-ReadOnly-v1.patch) applies to
that prepared Orchard source, not pristine Linux or arbitrary current main.
The [range-gated delta](patches/J81-ANS1-USERAREA-Range-Gated-Experimental.patch)
applies on top. Original attribution/licenses remain intact; see `NOTICE`.

The hardware-tested kernel is `7.3.0-rc1-orchard-j81-storage-ro-v2mod`.
The matching write-gated `asp.ko` is SHA256
`3e36f4b045a38ba4eeb46cce3a24a9d19955568b5831cd37e4124b5d6d6961f9`.
It retains the exact working kernel ABI; do not substitute modules from the
separate whole-kernel `rwgated-v1` candidate, whose USB boot did not qualify.
The driver defaults to read-only; opt-in requires an explicit first LBA/count.

The controller WRITE_UNLOCK is global. The namespace and extent checks above it
are software guards. Out-of-range writes, auxiliary writes, format/discard and
driver/admin-output remain rejected. Do not describe these as per-namespace
hardware locks or extend the write window without a new reviewed operation.

## Measured storage and installed layout

The owner unit's USERAREA is 64,000,000,000 bytes with 4096-byte logical blocks.
The initial read-only session exposed ten namespaces, all `ro=1`, and validated
GPT headers/tables. A later approved one-block test at logical LBA 15,624,738
passed pattern write/read-back/original restore/verification. All nine auxiliary
namespaces remained read-only. [One-block result](reports/approved-block-test-result.json).
That controller must not be rerun on the now-installed p2.

Apple's framework subsequently resized APFS to 16 GiB. Both GPT copies were
written and verified, followed by a successful normal iPadOS reboot. Linux p2
is logical LBA 4,194,816..15,624,703: 46,816,821,248 bytes. Apple identity/start/
name/flags and the nine auxiliary namespaces were retained. The Linux driver's
current immutable write window is exactly this p2 extent.

Native e2fsprogs formatted p2 and e2fsck passed. The complete pinned original
v0.1.1 rootfs was hash-verified on the iPad before extraction. The J81 overlay
installed matching modules, private owner firmware/Wi-Fi/SSH state, the root
guard and USB services. The original Mac rootfs was unchanged. Arch unit parsing
and actual global PID 1 handoff passed. Root proof and an owner-confirmed desktop
establish an internal installation; a fresh boot is a separate qualification.

## Source map

| Source | Purpose |
| --- | --- |
| `apple-tools/` | Attributed Apple framework resize and exact-layout GPT tooling; GPL/MIT notices retained |
| `host/apple_storage_session.py` | Pinned authenticated Apple-side probe, resize and guarded GPT phases |
| `host/approved_install_p2.py` | Plan-only default; exact private authorization/identity/geometry/hash guards before p2 format/extract |
| `host/test_approved_install_p2.py` | Changed GPT, wrong identity/kernel/module/geometry, stale approval and writable-auxiliary refusal |
| `host/prepare_native_root_overlay.py` | Private owner overlay preparation; generated firmware/credentials/keys are excluded |
| `root-overlay/` | Installed J81 root guard and J71b unit masks/dependencies |
| `native-root-extra/` | Native boot proof/counter, USB-only owner SSH/proof endpoint, network and input permissions |
| `host/compose_installer_bootstrap.py` | Immutable source/payload composition; only existing init changes |
| `host/compose_native_bootstrap.py` | Automatic installed-root bootstrap composition |
| `native_root_mount.sh` | Exact board/module/GPT/geometry/UUID/fence checks, then internal ext4 mount; no format/resize |
| `draft-native-root-handoff.sh` | Versioned handoff source; preserves real mounts and switch_root as PID 1 |
| `installer-handoff-loop.sh` | Installer shell and one explicit guarded handoff; recorded interactive child termination fix |
| `host/guided_internal_boot.py` | Single guided DFU/Pongo/upload attempt, private logs, no blind automatic retry |
| `host/fix_live_native_tool_selection.py` | Historical controlled RAM correction after BusyBox chose the wrong native-tool name |
| `reports/` | Sanitized scoped build/preflight/hardware receipts |

These scripts retain their original local workspace relationships and depend on
private owner metadata, the pinned Orchard CLI, and separately prepared payloads.
They are reviewable reconstruction sources, not copy-paste installation commands.
A recorded approval JSON is an input guard, not authority to operate a device.
Root partition UUIDs, raw metadata, credentials, keys and firmware remain private.

## Handoff and boot fixes

BusyBox standalone mode selected its own applets despite PATH. Explicit
`/usr/bin/mke2fs`, `/usr/bin/e2fsck` and `/usr/bin/blkid` select native tools.
Creating `/dev/null` under nodev `/run` does not provide usable device access;
preflight binds the existing device tree and removes temporary binds afterward.

The first handoff loop waited forever after SIGTERM because interactive ash
ignored it. Verifying and killing that exact child released the pending handoff
without reboot. The source now uses SIGKILL only for the recorded disposable
shell child. It never uses broad `killall` against the installed system.

The first automatic native boot photographed a stop at BCM4350 firmware probe,
before USB setup. The new bootstrap skips only its exact PCI modalias during
initramfs coldplug; installed systemd/udev can initialize Wi-Fi after native root
and recovery USB are available. This ordering passed the fresh native boot, including Wi-Fi after handoff. The pinned
known-working Pongo prebuilt is retained; source-built quiet/normal failures are
separately documented in [the paired comparison](../../docs/pongo/COMPARISON.md).

## Validation and limits

Forty-eight host tests passed in the pinned Orchard CLI environment, including
8 sparse-file GPT cases and installation refusal guards. Sixteen C range-helper
boundary assertions passed with address/undefined-behavior sanitizers. Native
ext4 tool preflight and the explicit hardware results supplement these tests;
simulations do not qualify arbitrary storage or crash safety after torn writes.

```sh
python3 -B -m unittest discover -s experimental/j81-storage/host -p 'test_*.py' -v
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -I experimental/j81-storage experimental/j81-storage/test_write_range.c \
  -o /tmp/j81-range-test
/tmp/j81-range-test
```

The root source guard is present, actual internal-root systemd/desktop startup
passed, followed by a distinct kernel boot with incremented
persistent counter and the exact surviving owner marker. Native touch, hardware
sound, Bluetooth, accelerated graphics, suspend, charging policy and sustained
storage reliability remain unqualified. [A9 reference assessment](REFERENCE-OMARCHY-IPAD5.md)
explains the architecture borrowed from that different-silicon port. It does not
justify copying its hardware drivers or deleting Apple cold-boot prerequisites.

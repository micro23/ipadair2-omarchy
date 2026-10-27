# J81 qualified Wi-Fi control contract

`reference/` contains exact source from the qualified Mac-driven RAM session.
It is a hardware integration reference, not a self-contained Orchard RPC
implementation. The historical host packages verified complete manifests and
private run records before loading this code; those packages and their binary
assets are not reproduced in Git.

| Source | Role |
| --- | --- |
| `wifi_boot.py` | Private firmware composition, owner-device MAC/ADT lineage and verified fresh boot |
| `wifi_session.py` | PCI/driver/MAC checks, USB isolation, scan, WPA2, DHCP, connectivity and owned-process cleanup |
| `tools_stage.py` | Strict manifest/archive verification and bounded staging to RAM |
| `usb_shell.py` | Bounded Telnet transport over the established USB ECM link |
| `scan_parser_fixed.py` | Required iw 6.17 same-line RSN header correction |
| `dns_parser_fixed.py` | Required BusyBox repeated-owner multi-A DNS response correction |
| `live_connection.py` | Read-only evidence of the current protected WPA2/DHCP session |
| `original-host/run-radio-test.py`, `boot_flow_base.py`, `apple_identity.py` | Normal USB identity, private ADT/radio capture and guarded DFU/Pongo transitions |
| `original-host/run-wifi-test.py` | Historical orchestration of firmware composition, boot, staging and connection |
| `original-host/radio_identity.py` | Original parser retained for audit; use the corrected parser instead |

The original `wifi_session.py` is preserved for auditable source identity.
An integrating caller must install **both** parser corrections on that module
before using its scan or connectivity methods, as the qualified sidecar
helpers did. Shipping the original parser alone would restore the known
scan/DNS bugs.

The original radio parser also contains the vendor-record trailing-byte bug
that was fixed during qualification. **Use
`firmware/j81/radio_identity_fixed.py` for radio parsing.** The original copy
under `reference/original-host/` is present only to show the audited change
and the historical import contract. Its obsolete parser is not an alternate
recommended implementation.

These original host files complete the inspectable USB/ADT identity and
orchestration source dependencies. They still require their historical full
bundle manifests, loader/runtime files and private run records to execute as
written. No such runnable bundle is claimed by this directory. An Orchard
adapter should reuse the validated logic under its own package/resource and
current-device identity contracts.

## Runtime invariants

The exact Wi-Fi kernel, J81/T7001 identity, unique current session nonce,
RAM-backed `/run`, inherited disabled shell history and disabled forwarding
are checked before actions. The live PCI endpoint must bind to brcmfmac and
both its DT MAC and interface MAC must match the privately captured hardware
record. The data is checked locally and omitted from public reports.

The nftables input rule drops diagnostic Telnet packets arriving outside the
actual USB ECM interface. It is installed and its exact form read back before
association; the filter stays in place on Wi-Fi disconnect. The successful
run verified it on the real kernel.

The session uses a private directory under `/run`, a bounded local transfer
server and strict source hashes. WPA credentials are read locally without
echo, converted to a PSK and passed as data rather than process arguments.
Temporary configuration is removed after association. Process cleanup checks
PID, start time and exact command identity; it does not use `killall`.

WPA2 Personal with CCMP is qualified. WPA3-only and enterprise authentication
are unsupported by this controller. DHCP sets only the owned Wi-Fi address,
keeps the USB subnet intact and tracks its own resolver changes. ICMP, DNS
and HTTP tests verify routes through Wi-Fi.

## Runtime tools and desktop separation

The Wi-Fi runtime used iw 6.17 plus AArch64 wpa_supplicant 2.12 and nftables
1.1.7 libraries selected from the pinned Omarchy-A release. They run through
an explicit glibc loader with an isolated library path; the base BusyBox
initramfs remains musl. `tools-source/` retains the exact tool build/packaging
logic, selected-package/source-map receipts and pinned iw input receipt. The
historical tool builders use documented scratch paths; an Orchard producer
must adapt those paths or stage those dependencies explicitly. They are
reference sources, not a new general tool installer.

The effective kernel enforces signed regulatory databases. The qualified
private boot image included the unmodified `regulatory.db` and
`regulatory.db.p7s` from wireless-regdb 2025.10.07. Their source archive and
file hashes are in `provenance/public-inputs.json`; the detached CMS signature
was verified against the kernel's built-in `wens` certificate. Keep signature
enforcement enabled and include both files. No country code was forced.

Tool source/build receipts and licenses belong with any separately
distributed runtime archive. This source contribution includes no tool
binaries or rootfs archives.

The separately qualified desktop used a reduced Omarchy-A v0.1.0 AArch64
userspace: Labwc, Quickshell, Foot and software rendering. Input came from a
Mac web controller and an explicit uinput bridge, not the native touch panel.
The combined desktop-on-Wi-Fi wrapper is a separate integration artifact and
has not yet established hardware qualification. A full systemd/persistent
Omarchy installation needs a new installed-root/storage design beyond this
RAM-only kernel contract.

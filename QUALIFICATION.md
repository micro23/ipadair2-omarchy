# Qualification record

## Latest additions — 2026-10-29

Direct Work-mode tests qualified the refactored Orchard J81 baseline, ANS1
read/write operation, and a full native Omarchy A v0.1.1 internal ext4 root with
global systemd PID 1. A clean reboot/fresh kernel boot returned the desktop,
incremented the persistent counter to 2 and preserved the exact owner marker.
Wi-Fi/DNS/HTTPS passed with zero failed system units. See the
[native installation and fixes](docs/status/2026-10-29-native-install.md).
Cold boot remains host-tethered; native touch and the remaining hardware listed
in the current report are unqualified. The historical RAM results below retain
their original narrower scope.

The paired source-built Pongo comparison failed with both quiet and normal
framebuffer output; its cause is unresolved. See
[paired results](docs/pongo/COMPARISON.md) and the
[ANS1 source/evidence](experimental/j81-storage/README.md).

## Historical 2026-10-27 RAM/desktop session

Scope: one owner-operated **iPad5,3 / J81AP**, initially on iPadOS 15.8.3,
booted from an Apple Silicon Mac. The following is a summary of the owner's
reported physical results; the build environment did not directly access the
iPad. The report timestamps are UTC, on 2026-10-27.

| Capability | Evidence and current limit |
| --- | --- |
| RAM Linux boot | Owner shell reported `7.3.0-rc1-j81-ramonly`, then `7.3.0-rc1-j81-wifi-ram`; J81/T7001 DT identity verified |
| USB ECM | Host shell and staged file transfer worked; generic USB product is not unique board proof |
| Display | simpleDRM framebuffer, 1536 × 2048, 32 bits/pixel; software-rendered desktop confirmed |
| Remote input | Owner confirmed working Mac mouse and keyboard forwarding in the combined desktop/Wi-Fi session |
| Omarchy desktop | Reduced Omarchy-A/Labwc session first confirmed on the earlier RAM kernel; current compositor, desktop root, user and tty2 also verified on the Wi-Fi kernel |
| BCM4350 firmware | Driver bound and firmware version observed on the current Wi-Fi kernel |
| Radio identity | C2 / rieslinga / CIDR / u / 2.1 observed; no private OTP or ADT published |
| Wi-Fi scan | Corrected helper observed 9 named networks, 8 eligible for its WPA2-Personal mode |
| WPA2 / DHCP | Current live association and owned DHCP processes verified |
| Wi-Fi internet | Wi-Fi route, ICMP, DNS and HTTP checks passed at 03:39:44 UTC and again during the combined desktop check at 04:07:26 UTC |
| USB root-shell isolation | Exact nftables rule verified in the same successful live connection check |
| Battery telemetry | Earlier RAM session exposed battery capacity/status/temperature; charging policy not qualified |
| Touchscreen | No native touch input qualified; compiled driver presence is not proof |
| Bluetooth / audio | Not qualified |
| GPU acceleration | Not qualified; current graphics use simpleDRM/software rendering |
| Sleep / resume | Not qualified |
| Internal storage | Disabled in these RAM kernels; no partition or installed-root test |
| Combined Wi-Fi + desktop | Confirmed in one live check on `7.3.0-rc1-j81-wifi-ram`: Wi-Fi reachability passed while the desktop compositor was active, and fresh desktop-user DNS/HTTP requests also passed |

The owner supplied the successful **J81 Desktop Wi-Fi Check v1** report
collected at **2026-10-27 04:07:26 UTC**. The same invocation verified the
current kernel and private boot identity, installed Wi-Fi tools, existing
WPA2/DHCP ownership and USB-shell filter. It then checked the desktop
compositor's process identity, root, UID and active tty2 before and after
DNS/HTTP probes run as desktop UID 1000. These were fresh observations, not
results copied from an earlier report. They establish short reachability
tests in this combined RAM session; no throughput or long-duration test was
performed by this helper.

The existing Mac control server also answered an authenticated status request.
macOS accepted the request to open its page in Brave; the helper did not verify
that a tab became visible. Brave is the Mac controls browser. The reduced
iPad userspace contains no installed web browser, and this result does not
qualify a full persistent Omarchy installation.

All regular files and connection state in the qualified Linux session are
temporary. Reboot ends the RAM session. The internet recheck did not rescan or
reassociate; its zero scan counts therefore do not negate the preceding
successful scan.

No network names, BSSIDs, device MACs, private IP leases, credentials, ECIDs,
session identifiers, raw hardware captures or personal logs are included in
this record. Generic fixed USB subnet details in source are protocol
configuration, not the owner's Wi-Fi network.

Build-time verification of this handoff is recorded separately in
`provenance/handoff-validation.json`. Existing historical producer receipts
retain their original build-time `hardware_tested: false` fields. This
qualification record adds later observations without rewriting old evidence.

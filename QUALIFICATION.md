# Qualification record

Scope: one owner-operated **iPad5,3 / J81AP**, initially on iPadOS 15.8.3,
booted from an Apple Silicon Mac. The following is a summary of the owner's
reported physical results; the build environment did not directly access the
iPad. The report timestamps are UTC, on 2026-10-27.

| Capability | Evidence and current limit |
| --- | --- |
| RAM Linux boot | Owner shell reported `7.3.0-rc1-j81-ramonly`, then `7.3.0-rc1-j81-wifi-ram`; J81/T7001 DT identity verified |
| USB ECM | Host shell and staged file transfer worked; generic USB product is not unique board proof |
| Display | simpleDRM framebuffer, 1536 × 2048, 32 bits/pixel; software-rendered desktop confirmed |
| Remote input | Mac mouse and keyboard forwarded through uinput worked |
| Omarchy desktop | Reduced Omarchy-A/Labwc session confirmed on earlier RAM kernel, after udev startup fix |
| BCM4350 firmware | Driver bound and firmware version observed on the current Wi-Fi kernel |
| Radio identity | C2 / rieslinga / CIDR / u / 2.1 observed; no private OTP or ADT published |
| Wi-Fi scan | Corrected helper observed 9 named networks, 8 eligible for its WPA2-Personal mode |
| WPA2 / DHCP | Current live association and owned DHCP processes verified |
| Wi-Fi internet | Wi-Fi route, ICMP, DNS and HTTP checks passed at 03:39:44 UTC |
| USB root-shell isolation | Exact nftables rule verified in the same successful live connection check |
| Battery telemetry | Earlier RAM session exposed battery capacity/status/temperature; charging policy not qualified |
| Touchscreen | No native touch input qualified; compiled driver presence is not proof |
| Bluetooth / audio | Not qualified |
| GPU acceleration | Not qualified; current graphics use simpleDRM/software rendering |
| Sleep / resume | Not qualified |
| Internal storage | Disabled in these RAM kernels; no partition or installed-root test |
| Combined Wi-Fi + desktop | Separate work in progress; the two successful milestones do not prove their combined runtime |

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

# Wi-Fi iPad Air 2 (J81)

| Identity | Qualified value |
| --- | --- |
| Apple product / board | `iPad5,3` / `J81AP` |
| SoC / DFU chip | A8X T7001 / `0x7001` |
| DFU board | `0x06` |
| Linux compatibility | `apple,j81`, `apple,t7001`, `apple,arm-platform` |
| ABI / kernel page size | AArch64 / 4 KiB |
| RAM / panel | 2 GiB physical / 1536 × 2048 |
| Qualified original OS | iPadOS 15.8.3 |
| Qualified RAM kernel | `7.3.0-rc1-j81-wifi-ram` |
| Wi-Fi endpoint | BCM4350, PCI `14e4:43a3` |

The cellular Air 2 (J82 / iPad5,4) has not been qualified. The USB ECM gadget
uses a generic Linux product string, so `match.linux.product` is deliberately
absent. Match DFU chip/board and verify the full running kernel/device-tree
identity and fresh session marker after boot.

## Qualified manual path

1. The owner starts from the unlocked, USB-connected Wi-Fi Air 2. The host
   identifies the normal-mode product/board and retains its chip identity
   privately across the DFU/Pongo transition.
2. The pinned palera1n v2.4/Pongo helper enters a RAM loader. A8X on the
   qualified Apple Silicon Mac sometimes needed one cable reconnect while
   transitioning to download mode. Do not treat a disconnect alone as proof
   that Linux booted or automatically repeat a partially completed upload.
3. A firmware-free radio-ID RAM image captures bounded radio identity data.
   The owner-device ADT and OTP data remain private. The corrected radio
   parser validates the stepping and board selector.
4. The Mac extracts generic firmware from the pinned iOS 8.1 IPSW, selects
   only the observed board variant and privately composes the Wi-Fi payload.
   m1n1 supplies the real owner-device MAC to the `wifi0` DT node.
5. The host verifies the new kernel, J81/T7001 identity, session nonce, PCI
   endpoint, driver binding and MAC. It installs and reads back the rule
   restricting the diagnostic root shell to the USB interface before Wi-Fi
   association. WPA2, DHCP and connectivity are controlled in RAM.

These steps describe the observed integration. The exact host package used
for that run had pinned bundle manifests and private session records; it is
not recreated merely by running the reference Python files in this source
tree. The portable producers here build public kernel/boot inputs; an Orchard
host adapter must implement the same identity and handoff contract.

## Firmware

The firmware source OS version and currently installed iPadOS serve different
purposes. The public recipe pins Apple's iPad5,3 iOS 8.1 / 12B410 archive.
The extractor uses macOS CommonCrypto, verifies the full archive and decrypted
filesystem hashes, then attaches the filesystem read-only.

The qualified radio identified **C2 / rieslinga / CIDR / u / 2.1**. This is
observed metadata, not a default for every Air 2. Keep the bounded owner OTP
capture, ADT, real MAC and all resulting private receipts outside Git. Never
substitute a reference device's MAC or calibration.

`firmware.json` uses `manual-source-only` with `orchard_adapter = false` in
its preparation metadata. It does not claim that Orchard's generic extraction
patterns can decrypt this legacy RootFS or make the private selection.

## Current limitations

The support flags record qualified **Wi-Fi** and **USB ECM networking**.
`usb_serial` is false: the diagnostic shell is Telnet over USB networking,
not a CDC ACM console. The screen uses simpleDRM and software rendering.
Native touchscreen, Bluetooth, audio, accelerated graphics, suspend and an
installed-root handoff are unqualified. The kernel disables block/MTD/MMC and
internal NVMe/ASP storage paths. See [qualification](../../QUALIFICATION.md).

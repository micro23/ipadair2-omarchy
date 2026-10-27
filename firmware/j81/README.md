# Private firmware preparation

`prepare_firmware.py` is the unchanged extraction library used for the
qualified Wi-Fi run. Its original command-line entry point expects the
complete old preparation bundle. The new `prepare-assets` adapter provides
an explicit-path entry point for its generic extraction stage without
pretending that the old bundle is present.

On a Mac with Python 3.12 or newer:

```sh
python3 -B firmware/j81/prepare-assets \
  --state "$HOME/Library/Application Support/J81 private firmware"
```

Use `--ipsw /absolute/path/iPad5,3_8.1_12B410_Restore.ipsw` to supply an
already downloaded exact archive. Otherwise it downloads Apple's pinned
2.18 GB archive; allow about 7 GB of working space. CommonCrypto and hdiutil
are macOS facilities used for authenticated-by-hash extraction and read-only
mounting. This adapter has been syntax/preflight reviewed in Linux; its
underlying extraction routine was executed on the qualified Mac, while this
new wrapper still needs a native Mac trial.

This prepares generic C2/C4 assets but **does not select a board, contact an
iPad or boot it**. `radio_identity_fixed.py` is the corrected bounded parser
for owner-device radio evidence. It tolerates the opaque bytes after the two
bounded vendor strings as the upstream C parser does; it retains the chip,
record bounds and selector checks.

Private selection requires validated radio identity and matching fresh ADT
evidence. The qualified quartet came from C2/rieslinga/CIDR/u/2.1; another
unit must prove its own selector. No synthetic or reference MAC is inserted
into the NVRAM. m1n1 copies the real device MAC to the wifi0 DT property and
brcmfmac uses it at firmware setup.

Keep extracted firmware, raw OTP, Apple device-tree captures, unique device
identifiers, calibration, passwords and all local selection receipts outside
this source tree. The public recipe records original Apple archive hashes,
generic firmware hashes and selectors only. It contains no Apple firmware
bytes or decryption key.

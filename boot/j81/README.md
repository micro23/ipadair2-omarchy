# J81 RAM payload composition

The boot chain is palera1n/checkm8 → pinned PongoOS → Hoolock m1n1 → Linux.
The m1n1 payload concatenates its loader, one newline-terminated bootargs
record, a padded J81 DTB, gzip-compressed ARM64 Image and gzip newc initramfs.
Pongo is supplied separately to the exploit/loader flow.

This directory reconstructs the **firmware-free public template**. The
qualified connected Wi-Fi payload additionally had owner-selected firmware,
the public regulatory database, shell-history suppression and a fresh
session marker added privately by the host. Do not associate using the bare
template as if those private composition and runtime steps had occurred.

## Explicit public inputs

The URLs, revisions and SHA-256 values are in
[`provenance/public-inputs.json`](../../provenance/public-inputs.json).
Supply the pinned Pongo and m1n1 files, the pinned SoMainline debug initrd,
the kernel products and the unpacked dtc/fdtget tools. Upstream CI artifact
retention may limit access to the old m1n1 artifact. If its exact bytes are
unavailable, a separately rebuilt loader needs its own qualification; the
adapter will reject a silent substitution.

Run from the repository root:

```sh
python3 -B boot/j81/assemble wifi-base \
  --products /work/j81-kernel-build/wifi/products \
  --debug-initrd /work/inputs/debug_initrd.img \
  --pongo /work/inputs/Pongo.bin \
  --m1n1 /work/inputs/m1n1.bin \
  --tools /work/toolchain/usr/bin \
  --output /work/j81-wifi-template
```

For radio identification, use profile `radio-id`, the radio-ID product
directory and a separate output directory. Each output must be new or empty
and outside the repository.

The source debug initrd is never executed. Only its exact BusyBox 1.31.1,
BusyBox-extras and matching musl files are retained. Replacement init code
mounts RAM/pseudo filesystems, creates USB ECM and starts a diagnostic console.
The reference image's old startup, partition and root-discovery scripts are
discarded. The deterministic reconstructed base initramfs must match its
recorded hash before the payload assembler proceeds.

## Qualified host handoff requirements

- Verify normal-mode product/board and keep the same private ECID across DFU
  and Pongo. Validate the expected Pongo version before upload.
- Capture this owner's ADT. Validate its J81/T7001/platform identity and
  actual Wi-Fi MAC; do not ship the capture or hashes of private identity data.
- Require a fresh boot session nonce in `/proc/cmdline`, exact kernel release
  and J81/T7001 compatibility before treating a USB Telnet response as ready.
- Before wireless association, require shell startup to set
  `HISTFILE=/dev/null` **before** the interactive shell begins. A later
  `export` inside a command subshell does not protect parent-shell history.
- Install and verify the nftables restriction for TCP port 23 on the actual
  USB gadget interface before raising Wi-Fi. Binding Telnet to the USB IP
  alone is insufficient under Linux weak-host routing.
- A handoff-time USB error can accompany successful boot but proves nothing
  by itself. Validate the new live kernel/session before another operation.

There is no storage installer, partition operation or Orchard launcher
manifest in this handoff. See `runtime/j81/README.md` for the control contract.

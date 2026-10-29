# J81 ANS1 and internal-root experiments

**Research source and evidence, not an internal-storage installer.** The
read-only module has a successful J81 session. The range-gated write candidate
has no successful live write test, and the native-root handoff is unfinished.
No internal storage write occurred during these experiments.

## Exact base and attribution

- Tested Orchard hardware baseline: `e2b1b591b495ae479951b06c18b99d3c86a0a7a9`.
- Linux upstream pin: `cee9395acd8043be0644b25c34bfa86623f2b935`.
- Orchard-prepared source-tree object before this overlay:
  `8a86872c4bc36d2998f6b1f6b88ec2e0aa97b01e`.
- Nick Chan's ANS1/ASP driver and shared RTKit/AKF changes, via Hoolock
  `ans1` `ed8528f482a526371e59711645794c91fafb2b42`, reconciled/read-only
  hardened in `mattonik/ipad-nixos` `b94d42f78e04c5465e290340a5b6879bbc5956b6`.
- The existing Orchard m1n1 loader fills the ANS firmware region using the
  `asp` alias. The J81 device tree adds/enables ANS and its mailbox while
  preserving the previously tested Wi-Fi/framebuffer configuration.

The read-only [overlay patch](patches/Orchard-J81-ANS1-ReadOnly-v1.patch) is
against that already-prepared Orchard source, **not pristine Linux or current
Orchard main**. Apply it only in a separate experimental copy and validate the
context. The [range-gated delta](patches/J81-ANS1-USERAREA-Range-Gated-Experimental.patch)
applies on top of the read-only overlay. Existing driver attribution and licenses
remain intact; see the repository `NOTICE` and `LICENSES`.

The common [config](configs/j81-storage.config) makes `CONFIG_APPLE_ASP=m`.
The initial built-in v1 candidate reset to iPadOS after upload; its exact cause
was not established. Delaying ASP until after USB was attached produced the
working read-only session. That is a demonstrated working sequence, not proof
of a complete explanation of the earlier reset.

Build the prepared source using the same native ARM64/clang-19 toolchain as
Orchard's kernel recipe, with the supplied config and a unique LOCALVERSION.
For example, inside its existing disposable build environment:

```sh
make -C /src O=/out LLVM=-19 ARCH=arm64 olddefconfig
make -C /src O=/out -j4 LLVM=-19 ARCH=arm64 \
  LOCALVERSION=-orchard-j81-storage-ro-v2mod DTC_FLAGS=-@ Image.gz modules dtbs
```

The write-delta build used `LOCALVERSION=-orchard-j81-storage-rwgated-v1`.
Stage matching modules with Orchard's `kernel/stage-modules.py`; do not reuse
another release's modules. The build receipts record the actual kernel/DTB/
payload hashes. No binary, firmware, source-build cache or rootfs is included.
The deferred [init source](init-deferred-asp.sh) is the source used by both
modular diagnostic images; it skips ASP during coldplug and contains no Wi-Fi
configuration. It is a diagnostic RAM bootstrap, not the final installed root.

## Read-only hardware evidence

The successful kernel was `7.3.0-rc1-orchard-j81-storage-ro-v2mod`. USB serial
came up before `modprobe asp`; the module then exposed ten namespaces and all
reported `ro=1`. The driver never submitted `ASP_CMD_WRITE_UNLOCK`, centrally
rejected writes/flush/admin-output, and marked every disk read-only before
registration. One 4096-byte USERAREA read succeeded. Bounded GPT metadata reads
validated the primary header/table and backup header CRCs.

This device's USERAREA is 64,000,000,000 bytes, logical block size 4096. The
single APFS partition occupies LBA 6..15,624,994 (63,999,954,944 bytes), with no
unallocated usable blocks. This capacity must not be inferred for another unit.
The nine auxiliary namespaces were not used as scratch space. Unique GUIDs,
partition names, raw blocks and full device/kernel logs remain private.

See [namespace/read result](reports/storage-report.json),
[GPT result](reports/gpt-report.json), and the
[scoped build receipt](reports/BUILD-RO-V2MOD-VERIFIED.json).

## Write candidate: compiled, not qualified

The separate range-gated candidate defaults to controller-locked read-only.
Opt-in requires all of these at module load:

- `allow_userarea_writes=1`;
- explicit `write_first_lba` and nonzero `write_lba_count`, measured in **4096-byte
  logical blocks**, not the 512-byte units used by sysfs `size`/request sectors;
- a non-overflowing range within the identified USERAREA capacity.

Only ordinary USERAREA writes/flush are admitted. Writes outside the configured
range, every auxiliary write, driver-output and format/discard operations remain
rejected. All auxiliary disks remain read-only. The controller's WRITE_UNLOCK
itself is global; the namespace and range limits above it are **software guards**,
not separate controller-enforced write locks. The unused automatic-reformat
parameter was removed from this candidate.

Sixteen C boundary assertions against the actual range helper passed with
address/undefined-behavior sanitizers, and the full kernel/49 matching modules
built. Those checks do not exercise the real controller write protocol.
The new image reached owner-visible Linux text, but USB did not enumerate;
the module write probe was never sent. The proposed one-block write/read-back/
restore has not run. No writable filesystem or persistent reboot result exists.

The [host test controller](host/approved_block_test.py) is **plan-only by default**.
It is specific to this measured 64 GB unit and the one recorded test block;
it is not a general installer. It requires private device/backup/approval state,
the exact new kernel, ASP still deferred, exact range/geometry checks, all nine
auxiliary RO flags, no ASP mounts, a current block matching the local backup,
and verified RAM staging before its first write. It attempts restoration even
if the pattern write fails, then verifies the original bytes. A disconnect or
firmware failure can still prevent restoration. Do not interpret an approval
JSON file as permission to mutate someone else's device or erase APFS.

Private execution state belongs in an ignored `private-live/` beside the host
scripts. No real approval record or backed-up block is published. Pinned Orchard
CLI serial/USB APIs from the baseline above are required for the host controller;
stdlib-only guard/parser tests can be run independently.

```sh
python3 -B -m unittest discover -s experimental/j81-storage/host -p 'test_*.py' -v
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
  -I experimental/j81-storage experimental/j81-storage/test_write_range.c \
  -o /tmp/j81-range-test
/tmp/j81-range-test
```

The complete host test suite imports `orchard_cli`; use the tested CLI environment.
It includes wrong-identity rejection, GPT CRC/bounds/overlap checks, debug-vs-BUG
regression, original-block mismatch refusal, auxiliary-writable refusal and
restoration after a simulated partial write failure. The simulated tests do not
write hardware.

## Future persistent root

The [root overlay](root-overlay/) and [policy plan](root-policy.json) stage a
J81-native root guard and getty/seatd dependencies, mask J71b-specific boot/charge
units, and disable the old boot-scoped diagnostic service. The original Omarchy
rootfs was not modified. Existing desktop autologin and Labwc startup are retained
in the intended copied root; applying this overlay alone does not create a bootable
system.

Before handoff the installer must generate the actual new ext4 UUID, matching
fstab and exact qualified kernel identity, preserve numeric ownership/modes/
xattrs and install matching modules. The root guard requires internal ext4 on
USERAREA partition 1, the exact UUID/kernel and a write window matching that
partition, with all auxiliary namespaces read-only. Its shell syntax was checked;
Arch unit parsing and systemd PID 1/desktop startup have not been verified.

The final bootstrap must mount the internal ext4 root and `switch_root` to its
systemd. It must not substitute an NFS root or disposable RAM overlay for a
persistent install. Cold boot remains host-tethered through Pongo/m1n1 unless a
separate untethered boot mechanism is established.

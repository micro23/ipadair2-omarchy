# Historical full Omarchy A v0.1.1 userspace experiments

These source files explain the full-root NFS/RAM session and systemd parser
work completed before the separate Orchard/ANS1 experiments. They are **not an
installed-root boot path** and are not substitutes for the current hardware
stack. The scripts retain their original strict kernel/source identities and
project-layout dependencies; do not relax those checks to run them against a
different image.

- `fullroot/`: validate the pinned upstream rootfs, extract it onto an
  owner-aware case-sensitive APFS image and perform a bounded read-only NFS
  mount test. Its offline tests cover archive and host lifecycle safeguards.
- `arch-exec/`: run selected native Arch ARM64 utilities through a private
  chroot/namespace, without starting the original J71b services.
- `systemd-stage/`: disposable RAM policy overlay and Arch systemd unit-parser
  validation, including the private `/dev/null` correction. No PID 1 transition.
- `desktop/`: bounded Labwc/Quickshell session with a 384 MiB RAM upper,
  per-user D-Bus, software rendering and guest cleanup. The actual shell IPC
  and a compositor frame establish readiness. Runtime paths in the private
  namespace are inspected through `/proc/PID/root`, not the outer mount view.

The full Quickshell UI, Foot, calculator and Firefox rendered on the physical
J81; injected keyboard input executed as UID 1000. PipeWire/WirePlumber clients
were present but no physical audio device was exposed. Firefox's chroot/session
logs showed namespace/sandbox limits, so this was not a qualified general
browsing environment. The source does not add sandbox-disabling flags.

The integrated `--existing-nfs` guest session and cleanup were tested. The
launcher `.command` path with a fresh export was not separately exercised end
to end; it used the already-tested host export lifecycle. Do not infer that
an IPC/frame check proves automatic host NFS permission/setup worked.

A Mac host administrator is needed only when running the temporary NFS setup;
existing exports/services cause a guarded stop rather than being overwritten.
The owner project layout and pinned older `7ea2b2b` source checkout are still
required by these historical scripts. `J81_PROJECT_DIR` can select the desktop
wrapper's project root; `source-receipts.json` records that path-only adaptation.
The helper hashes and source revisions are intentionally retained. The remaining
sources are exact copies of the tested scripts. The rootfs archive itself is
not included; its verified release/hash is in `provenance/full-userspace-v0.1.1.json`.

See the [full UI report](FULL-UI-RESULT.txt) and
[systemd stage report](SYSTEMD-STAGE-RESULT.txt). Their remaining-work lists
are historical snapshots; [the current checkpoint](../../docs/status/2026-10-29.md)
adds the later read-only ANS1 results. The persistent root policy lives in the
separate `experimental/j81-storage/root-overlay` and has not been boot-tested.
Raw runtime logs, live state, secrets, screenshots, firmware and rootfs archives
are excluded from this source handoff.

Validation of the published copies: run each historical `test_offline.py`
directly (they use script assertions, not unittest discovery). The full-root
archive script passed 14 cases; the systemd-stage script passed 39 static,
syntax and fake-device checks. Its printed PASS/NOT VERIFIED stage examples
come from fakes and are not new live hardware runs. The NFS helper's old header
mentions mapall; its actual numeric-ownership fix and test assert maproot=root
for the single USB client, preserving desktop UID 1000.

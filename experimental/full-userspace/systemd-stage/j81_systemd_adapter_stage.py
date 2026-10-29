#!/usr/bin/env python3
"""Stage a J81 systemd checkpoint in a disposable RAM OverlayFS over NFS.

No PID1 transition, systemd start, systemctl daemon-reload, network state
changes, iPad internal storage, boot payload, or persistent rootfs writes.

Uses the previously hardware-proven guarded host NFS lifecycle and USB shell.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

PROJECT = Path.home() / "ChatGPT-Projects/iPad-Air2-Omarchy"
WORK = PROJECT / "Current/J81-Omarchy-A-Netroot-Work-v1"
ARCH_HELPER = PROJECT / "Current/J81-Arch-Userspace-Exec-v1/j81_arch_exec_test.py"
ARCH_SHA = "3db4cede36213b02fbc5df8d62d7e028e9138c98ed3519202142477a534715e8"
REPORT = PROJECT / "Reports/J81-SYSTEMD-ADAPTER-STAGE-V1_1-RESULT.txt"
KERNEL = "7.3.0-rc1-j81-omarchy-netroot"
ROOT = Path("/Volumes/J81_OMARCHY_A_V011/rootfs")

MASKS = (
    "j71b-platform-ready.service",
    "j71b-charge.service",
    "omarchy-diagnostics.service",
    "getty@tty1.service",
)

UNIT_GUARD = """[Unit]
Description=J81 USB-root identity guard (candidate, not enabled on disk)
Documentation=man:systemd.unit(5)

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/j81-usb-root-guard
RemainAfterExit=yes
"""

UNIT_TARGET = """[Unit]
Description=J81 USB-root minimum systemd checkpoint (no desktop)
DefaultDependencies=no
Requires=j81-usb-root-guard.service
After=j81-usb-root-guard.service
Conflicts=shutdown.target
Before=shutdown.target
AllowIsolate=yes
"""

GUARD_SCRIPT = """#!/bin/sh
# Future boot guard. This file is only syntax-checked, NEVER run by this test.
set -eu
[ \"$(uname -r)\" = '7.3.0-rc1-j81-omarchy-netroot' ] || exit 41
[ -r /proc/device-tree/compatible ] || exit 42
tr '\\000' '\\n' < /proc/device-tree/compatible | grep -Fxq 'apple,j81' || exit 43
tr '\\000' '\\n' < /proc/device-tree/compatible | grep -Fxq 'apple,t7001' || exit 44
[ -r /usr/lib/os-release ] || exit 45
# USB gadget + NFS continuity must be implemented before this target is booted.
exit 0
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def load_arch():
    require(ARCH_HELPER.is_file() and not ARCH_HELPER.is_symlink(),
            "Previously verified Arch execution toolkit missing")
    code = ARCH_HELPER.read_bytes()
    require(hashlib.sha256(code).hexdigest() == ARCH_SHA,
            "Previously verified Arch helper differs from the pinned version")
    spec = importlib.util.spec_from_file_location("j81_arch_pinned_stage", ARCH_HELPER)
    require(spec is not None and spec.loader is not None, "Cannot load pinned Arch helper")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    require(mod.KERNEL == KERNEL and mod.GUEST_ROOT == str(ROOT), "Wrong Arch host profile")
    return mod


def preflight(arch, host):
    arch.preflight_owners(host)
    for rel in (
        "usr/bin/systemd-analyze",
        "usr/lib/systemd/systemd",
        "usr/lib/systemd/system/j71b-platform-ready.service",
        "usr/lib/systemd/system/j71b-charge.service",
        "usr/lib/systemd/system/omarchy-diagnostics.service",
        "etc/systemd/system/getty@tty1.service.d/20-j71b-platform.conf",
        "etc/systemd/system/multi-user.target.wants/j71b-charge.service",
    ):
        p = ROOT / rel
        require(p.exists() or p.is_symlink(), "Expected J71b release component absent: " + rel)
    gate = (ROOT / "etc/systemd/system/getty@tty1.service.d/20-j71b-platform.conf").read_text()
    require("Requires=j71b-platform-ready.service" in gate,
            "Original J71b login gate has changed; no test performed")
    require(not (ROOT / "etc/systemd/system/j81-usb-root-preflight.target").exists(),
            "J81 target already exists in original root; stop and inspect")
    proc = subprocess.run(["/bin/sh", "-n"], input=GUARD_SCRIPT, text=True, capture_output=True)
    require(proc.returncode == 0, "Candidate J81 identity guard failed shell syntax check")
    require("/dev/disk" not in GUARD_SCRIPT and "reboot" not in UNIT_TARGET,
            "Unexpected operation in candidate policy")
    print("PASS: J71b boot/login services identified; original filesystem unchanged")
    print("PASS: J81 systemd checkpoint and identity guard generated in memory")


def guest_script(token: str) -> str:
    assert re.fullmatch(r"[0-9a-f]{8}", token)
    script = r'''
set -u
D=/mnt/j81-systemd-stage-@@TOKEN@@
nfs=0
ram=0
cow=0
dev=0
if command -v chroot >/dev/null 2>&1; then
  CHROOT='chroot'
elif busybox --list | grep -qx chroot; then
  CHROOT='busybox chroot'
else
  echo J81_ERROR_CHROOT_MISSING
  exit 10
fi
if ! mkdir "$D"; then echo J81_ERROR_TEST_DIR; exit 11; fi
cleanup() {
  rc=$?
  trap - EXIT
  cleanup_ok=1
  if [ "$dev" -eq 1 ]; then
    umount "$D/merged/dev" || { echo J81_ERROR_DEV_UMOUNT; rc=1; cleanup_ok=0; }
  fi
  if [ "$cow" -eq 1 ]; then
    umount "$D/merged" || { echo J81_ERROR_OVERLAY_UMOUNT; rc=1; cleanup_ok=0; }
  fi
  if [ "$ram" -eq 1 ]; then
    umount "$D/ram" || { echo J81_ERROR_TMPFS_UMOUNT; rc=1; cleanup_ok=0; }
  fi
  if [ "$nfs" -eq 1 ]; then
    umount "$D/lower" || { echo J81_ERROR_NFS_UMOUNT; rc=1; cleanup_ok=0; }
  fi
  if ! rmdir "$D/merged" "$D/ram" "$D/lower" "$D" 2>/dev/null; then
    echo J81_ERROR_DIR_CLEANUP
    rc=1
    cleanup_ok=0
  fi
  if [ "$cleanup_ok" -eq 1 ]; then echo J81_STAGE_GUEST_CLEANUP_OK; fi
  exit "$rc"
}
trap cleanup EXIT
if ! mkdir "$D/lower" "$D/ram" "$D/merged"; then
  echo J81_ERROR_TEST_DIR
  exit 12
fi
if detail=$(mount -t nfs -o ro,vers=3,proto=tcp,nolock,soft,timeo=10,retrans=1 172.16.42.2:/Volumes/J81_OMARCHY_A_V011/rootfs "$D/lower" 2>&1); then
  nfs=1
  echo J81_STAGE_FULLROOT_NFS_MOUNTED
else
  echo J81_ERROR_NFS_MOUNT
  printf 'J81_DETAIL=%s\n' "$detail"
  exit 13
fi
if [ ! -x "$D/lower/usr/bin/systemd-analyze" ] ||
   [ ! -e "$D/lower/usr/lib/systemd/systemd" ] ||
   [ ! -f "$D/lower/etc/systemd/system/getty@tty1.service.d/20-j71b-platform.conf" ]; then
  echo J81_ERROR_UPSTREAM_LAYOUT
  exit 14
fi
if ! mount -t tmpfs -o size=96m,mode=0755 tmpfs "$D/ram"; then
  echo J81_ERROR_TMPFS_MOUNT
  exit 15
fi
ram=1
if ! mkdir "$D/ram/upper" "$D/ram/work"; then
  echo J81_ERROR_TMPFS_DIR
  exit 16
fi
if detail=$(mount -t overlay overlay -o lowerdir="$D/lower",upperdir="$D/ram/upper",workdir="$D/ram/work" "$D/merged" 2>&1); then
  cow=1
  echo J81_STAGE_RAM_OVERLAY_MOUNTED
else
  echo J81_ERROR_OVERLAY_MOUNT
  printf 'J81_DETAIL=%s\n' "$detail"
  exit 17
fi
# A private, bounded RAM /dev supplies only the null device needed by the parser.
# Never bind the host /dev tree or expose iPad storage devices to this chroot.
if [ -L "$D/merged/dev" ] || ! mkdir -p "$D/merged/dev"; then
  echo J81_ERROR_DEV_DIRECTORY
  exit 30
fi
if ! mount -t tmpfs -o size=1m,mode=0755,nosuid,noexec tmpfs "$D/merged/dev"; then
  echo J81_ERROR_DEV_TMPFS
  exit 31
fi
dev=1
if ! mknod "$D/merged/dev/null" c 1 3 || ! chmod 666 "$D/merged/dev/null"; then
  echo J81_ERROR_DEV_NULL
  exit 32
fi
[ -c "$D/merged/dev/null" ] || { echo J81_ERROR_DEV_NULL; exit 33; }
echo J81_STAGE_PRIVATE_DEV_NULL_READY
M="$D/merged/etc/systemd/system"
for unit in j71b-platform-ready.service j71b-charge.service omarchy-diagnostics.service 'getty@tty1.service'; do
  if [ -e "$M/$unit" ] || [ -L "$M/$unit" ]; then
    echo J81_ERROR_EXISTING_MASK_DESTINATION
    exit 18
  fi
  if ! ln -s /dev/null "$M/$unit"; then
    echo J81_ERROR_CREATE_MASK
    exit 19
  fi
  if [ "$(readlink "$M/$unit")" != /dev/null ]; then
    echo J81_ERROR_MASK_INCORRECT
    exit 20
  fi
done
echo J81_STAGE_J71B_SERVICES_MASKED_IN_RAM
if ! mkdir -p "$D/merged/usr/local/libexec"; then
  echo J81_ERROR_GUARD_PARENT
  exit 21
fi
cat > "$D/merged/usr/local/libexec/j81-usb-root-guard" <<'J81_GUARD_FILE'
@@GUARD_SCRIPT@@
J81_GUARD_FILE
cat > "$M/j81-usb-root-guard.service" <<'J81_GUARD_UNIT'
@@UNIT_GUARD@@
J81_GUARD_UNIT
cat > "$M/j81-usb-root-preflight.target" <<'J81_PREFLIGHT_TARGET'
@@UNIT_TARGET@@
J81_PREFLIGHT_TARGET
if ! chmod 755 "$D/merged/usr/local/libexec/j81-usb-root-guard"; then
  echo J81_ERROR_GUARD_PERMISSIONS
  exit 22
fi
# Only the temporary OverlayFS view gets the default target override.
# Nothing is started by the current diagnostic PID1.
if ! ln -sfn /etc/systemd/system/j81-usb-root-preflight.target "$M/default.target"; then
  echo J81_ERROR_DEFAULT_TARGET
  exit 23
fi
if [ "$(readlink "$M/default.target")" != /etc/systemd/system/j81-usb-root-preflight.target ]; then
  echo J81_ERROR_DEFAULT_TARGET
  exit 24
fi
# Validate the lower NFS root still contains the unchanged J71b units.
if [ ! -f "$D/lower/usr/lib/systemd/system/j71b-charge.service" ] ||
   [ ! -f "$D/lower/etc/systemd/system/getty@tty1.service.d/20-j71b-platform.conf" ] ||
   [ -e "$D/lower/etc/systemd/system/j81-usb-root-preflight.target" ]; then
  echo J81_ERROR_ORIGINAL_CHANGED
  exit 25
fi
echo J81_STAGE_ORIGINAL_J71B_ROOT_UNMODIFIED
if detail=$($CHROOT "$D/merged" /usr/bin/sh -n /usr/local/libexec/j81-usb-root-guard 2>&1); then
  echo J81_STAGE_J81_GUARD_SYNTAX_PASS
else
  echo J81_ERROR_GUARD_SYNTAX
  printf 'J81_DETAIL=%s\n' "$detail"
  exit 26
fi
# systemd-analyze verify parses units; it DOES NOT launch PID1 or services.
if detail=$($CHROOT "$D/merged" /usr/bin/systemd-analyze verify --man=no --recursive-errors=no /etc/systemd/system/j81-usb-root-guard.service /etc/systemd/system/j81-usb-root-preflight.target 2>&1); then
  echo J81_STAGE_SYSTEMD_ANALYZE_VERIFY_PASS
else
  echo J81_ERROR_SYSTEMD_ANALYZE_VERIFY
  printf 'J81_DETAIL=%s\n' "$detail"
  exit 27
fi
# Ensure a mask lookup and default target are visible to user space.
for unit in j71b-platform-ready.service j71b-charge.service omarchy-diagnostics.service 'getty@tty1.service'; do
  [ "$(readlink "$M/$unit")" = /dev/null ] || {
    echo J81_ERROR_MASK_MISSING
    exit 28
  }
done
echo J81_STAGE_J81_CANDIDATE_VERIFIED_IN_RAM
# No systemd launch, switch_root, boot arguments, kernel or storage commands.
echo J81_STAGE_SYSTEMD_CANDIDATE_PASS
'''
    return (script.replace("@@TOKEN@@", token)
                  .replace("@@GUARD_SCRIPT@@", GUARD_SCRIPT.rstrip("\n"))
                  .replace("@@UNIT_GUARD@@", UNIT_GUARD.rstrip("\n"))
                  .replace("@@UNIT_TARGET@@", UNIT_TARGET.rstrip("\n")))


def confirm():
    print("\nJ81 systemd adaptation dry run: read-only full NFS root, 96 MiB RAM overlay plus a private 1 MiB /dev.")
    print("Temporarily mask J71b charge, identity, diagnostics, and tty1 login IN RAM ONLY.")
    print("Stage J81 identity guard + minimal systemd target, run Arch systemd-analyze verify.")
    print("No systemd start, PID1 replacement, reboot, USB interface changes or iPad storage writes.")
    print("Original Mac Omarchy rootfs remains read-only and unchanged.")
    print("Temporary Mac NFS export limited to the connected iPad USB address.")
    with open("/dev/tty", "r", encoding="utf-8") as tty:
        print("Type STAGE J81 to authorize this test: ", end="", flush=True)
        answer = tty.readline().strip()
    return answer == "STAGE J81"


def run_guest(usb, host, token):
    time.sleep(4)
    client = usb.IPadShell()
    try:
        output, rc = client.run(guest_script(token), seconds=150, check=False)
        markers = host.static_markers(output)
        live, live_rc = client.run("uname -r", seconds=15, check=False)
        if live_rc == 0 and live.strip() == KERNEL:
            markers.append("J81_STAGE_DIAGNOSTIC_SHELL_ALIVE")
        else:
            rc = rc or 99
    finally:
        client.close()
    print("\n--- J81 systemd candidate staging (RAM only) ---")
    for label, code in (
        ("Full Omarchy NFS root", "J81_STAGE_FULLROOT_NFS_MOUNTED"),
        ("RAM writable OverlayFS", "J81_STAGE_RAM_OVERLAY_MOUNTED"),
        ("Private RAM /dev/null", "J81_STAGE_PRIVATE_DEV_NULL_READY"),
        ("J71b units masked only in RAM", "J81_STAGE_J71B_SERVICES_MASKED_IN_RAM"),
        ("Original Mac root unchanged", "J81_STAGE_ORIGINAL_J71B_ROOT_UNMODIFIED"),
        ("J81 guard shell syntax", "J81_STAGE_J81_GUARD_SYNTAX_PASS"),
        ("Arch systemd unit parser", "J81_STAGE_SYSTEMD_ANALYZE_VERIFY_PASS"),
        ("Guest mounts cleaned", "J81_STAGE_GUEST_CLEANUP_OK"),
        ("Diagnostic USB shell still alive", "J81_STAGE_DIAGNOSTIC_SHELL_ALIVE"),
    ):
        print(f"{label}: {'PASS' if code in markers else 'NOT VERIFIED'}")
    print("Diagnostic codes:", ", ".join(markers) if markers else "(none)")
    for line in output.splitlines():
        if line.startswith("J81_DETAIL="):
            detail = re.sub(r"(?i)\b(?:ECID|UDID|UniqueChipID)[:=]\S+", "[private]", line.split("=", 1)[1])
            print("Failure detail:", detail[:450])
    needed = {
        "J81_STAGE_FULLROOT_NFS_MOUNTED", "J81_STAGE_RAM_OVERLAY_MOUNTED",
        "J81_STAGE_PRIVATE_DEV_NULL_READY",
        "J81_STAGE_J71B_SERVICES_MASKED_IN_RAM",
        "J81_STAGE_ORIGINAL_J71B_ROOT_UNMODIFIED",
        "J81_STAGE_J81_GUARD_SYNTAX_PASS", "J81_STAGE_SYSTEMD_ANALYZE_VERIFY_PASS",
        "J81_STAGE_J81_CANDIDATE_VERIFIED_IN_RAM", "J81_STAGE_GUEST_CLEANUP_OK",
        "J81_STAGE_DIAGNOSTIC_SHELL_ALIVE", "J81_STAGE_SYSTEMD_CANDIDATE_PASS",
    }
    errors = [marker for marker in markers if marker.startswith("J81_ERROR_")]
    host.need(rc == 0 and needed <= set(markers),
              "J81 systemd candidate dry run not passed: " + (", ".join(errors) or "missing proof marker"))


def report(success, stage, error=None, cleanup_ok=False):
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "J81 SYSTEMD ADAPTER STAGING TEST",
        "Result: " + ("PASS" if success and cleanup_ok else "NOT PASSED"),
        "Stage: " + stage,
        "Device: iPad Air 2 Wi-Fi / iPad5,3 / J81AP / T7001",
        "Live kernel expected: " + KERNEL,
        "Source: complete Orchard Omarchy A v0.1.1 (J71b profile)",
        "Boot/login J71b masks: transient RAM overlay ONLY",
        "Candidate J81 systemd unit parsing: no PID1, no service launch",
        "Mac NFS rootfs and boot files: UNMODIFIED",
        "Mac NFS export cleanup: " + ("VERIFIED" if cleanup_ok else "UNCONFIRMED"),
        "iPad internal storage: NEVER ACCESSED",
        "Systemd PID1/switch_root/desktop: NOT ATTEMPTED",
    ]
    if error:
        lines.append("Issue: " + str(error).replace("\n", " ")[:240])
    REPORT.write_text("\n".join(lines) + "\n")
    print("Shareable report:", REPORT)


def main():
    try:
        arch = load_arch()
        host = arch.load_verified_host()
        preflight(arch, host)
        usb = host.git_source(WORK.resolve(strict=True))
        host.check_mac_net()
        host.get_live_kernel(usb)
        arch.check_guest_chroot(usb)
        result = {"passed": False}
        host.confirm = confirm
        def guarded_guest(usb_module):
            run_guest(usb_module, host, secrets.token_hex(4))
            result["passed"] = True
        host.run_on_ipad = guarded_guest
        host.report = lambda unused_work, success, stage, error=None, cleanup_ok=False: report(
            success, stage, error=error, cleanup_ok=cleanup_ok)
        host.test(WORK)
        if not result["passed"]:
            print("CANCELLED: No NFS export or systemd adapter test completed.")
            return 0
        print("PASS: J81 systemd unit candidates parsed inside full Arch ARM64 userspace.")
        print("Systemd PID1 and Omarchy desktop were NOT started.")
        return 0
    except Exception as exc:
        print("STOP:", str(exc)[:320], file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

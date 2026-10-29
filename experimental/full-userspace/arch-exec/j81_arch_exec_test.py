#!/usr/bin/env python3
"""Hardware-gated J81 Arch Linux ARM chroot execution test.

Uses pinned v1.3 host NFS export code, the previously verified iPad USB shell,
read-only Mac NFS lower, and a small tmpfs-only OverlayFS upper.

NEVER uses switch_root, pivot_root, new kernel payload, systemd, graphics,
firmware access, disk partitioning, or Apple internal storage.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time

PROJECT = Path.home() / "ChatGPT-Projects/iPad-Air2-Omarchy"
WORK = PROJECT / "Current/J81-Omarchy-A-Netroot-Work-v1"
HOST_HELPER = PROJECT / "Current/J81-Omarchy-A-FullRoot-v1.3/test_full_root_usb.py"
HOST_HELPER_SHA256 = "63980ab8156c17c32733ad90bc2f10122ef2c6d7be695540a15dbf953eea9fd9"
REPORT = PROJECT / "Reports/J81-ARCH-USERSPACE-EXEC-RESULT.txt"
GUEST_ROOT = "/Volumes/J81_OMARCHY_A_V011/rootfs"
KERNEL = "7.3.0-rc1-j81-omarchy-netroot"


class ReadinessError(RuntimeError):
    pass


def verify(condition: bool, message: str) -> None:
    if not condition:
        raise ReadinessError(message)


def load_verified_host():
    verify(HOST_HELPER.is_file() and not HOST_HELPER.is_symlink(),
           "Original FullRoot v1.3 helper missing; no changes made")
    blob = HOST_HELPER.read_bytes()
    verify(hashlib.sha256(blob).hexdigest() == HOST_HELPER_SHA256,
           "Original FullRoot v1.3 helper does not match pinned checksum")
    spec = importlib.util.spec_from_file_location("j81_arch_exec_verified_host", HOST_HELPER)
    verify(spec is not None and spec.loader is not None, "Cannot read verified host helper")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    verify(str(mod.VOLUME_ROOT) == GUEST_ROOT and mod.EXPECTED_KERNEL == KERNEL,
           "Unexpected NFS root or J81 kernel in verified helper")
    return mod


def preflight_owners(host):
    root = host.check_stage(WORK.resolve(strict=True))
    # If macOS maps every owner to the logged-in user, the guest will not see
    # correct ownership and a systemd transition is unsafe. No chmod/chown.
    for rel, uid, gid in (
        ("etc/passwd", 0, 0),
        ("etc/shadow", 0, 0),
        ("usr/lib/systemd/systemd", 0, 0),
        ("home/tablet", 1000, 1000),
    ):
        st = (root / rel).stat()
        verify((st.st_uid, st.st_gid) == (uid, gid),
               "Linux ownership is not enabled or does not match for " + rel)
    loader = root / "usr/lib/ld-linux-aarch64.so.1"
    verify(loader.is_file(), "Arch Linux ARM ELF loader missing")
    for rel in ("usr/bin/uname", "usr/bin/cat", "usr/bin/id", "usr/bin/touch"):
        p = root / rel
        verify(p.is_file() and os.access(p, os.X_OK),
               "Required Arch Linux ARM executable unavailable: " + rel)
    lib = root / "lib"
    verify(lib.is_symlink() and os.readlink(lib) == "usr/lib",
           "Expected relative /lib -> usr/lib link is missing")
    info = subprocess.run(["/usr/sbin/diskutil", "info", str(root.parent)],
                          capture_output=True, text=True, check=True).stdout
    verify(re.search(r"(?m)^\s*Owners:\s*Enabled\s*$", info) is not None,
           "Enable ownership on dedicated Omarchy APFS image before executing binaries")
    print("PASS: Original rootfs is on the dedicated, owner-aware APFS image")
    print("PASS: Arch ARM64 loader and execution targets are present")


def check_guest_chroot(usb):
    """Read-only probe: do not export NFS unless guest has a chroot command."""
    command = r'''
if [ "$(id -u)" != 0 ]; then
  echo J81_ERROR_NOT_ROOT
  exit 11
fi
if command -v chroot >/dev/null 2>&1; then
  echo J81_STAGE_CHROOT_TOOL_AVAILABLE
elif command -v busybox >/dev/null 2>&1 && busybox --list | grep -qx chroot; then
  echo J81_STAGE_CHROOT_TOOL_AVAILABLE
elif command -v busybox-extras >/dev/null 2>&1 && busybox-extras --list | grep -qx chroot; then
  echo J81_STAGE_CHROOT_TOOL_AVAILABLE
else
  echo J81_ERROR_CHROOT_TOOL_UNAVAILABLE
  exit 12
fi
'''
    client = usb.IPadShell()
    try:
        out, rc = client.run(command, seconds=15, check=False)
    finally:
        client.close()
    verify(rc == 0 and "J81_STAGE_CHROOT_TOOL_AVAILABLE" in out.splitlines(),
           "The running RAM image has no chroot applet (or is not root). "
           "No NFS export started; a J81 initramfs applet update may be required")
    print("PASS: iPad RAM shell supports chroot without changing PID 1")


def guest_script(token: str) -> str:
    assert re.fullmatch(r"[0-9a-f]{8}", token)
    script = r'''
set -u
D=/mnt/j81-arch-user-@@TOKEN@@
nfs=0
ram=0
cow=0
if command -v chroot >/dev/null 2>&1; then
  CHROOT="chroot"
elif command -v busybox >/dev/null 2>&1 && busybox --list | grep -qx chroot; then
  CHROOT="busybox chroot"
elif command -v busybox-extras >/dev/null 2>&1 && busybox-extras --list | grep -qx chroot; then
  CHROOT="busybox-extras chroot"
else
  echo J81_ERROR_CHROOT_TOOL_UNAVAILABLE
  exit 13
fi
if ! mkdir "$D"; then echo J81_ERROR_TEST_DIR; exit 14; fi
cleanup() {
  code=$?
  trap - EXIT
  if [ "$cow" -eq 1 ]; then
    umount "$D/merged" || { echo J81_ERROR_COW_UMOUNT; code=1; }
  fi
  if [ "$ram" -eq 1 ]; then
    umount "$D/ram" || { echo J81_ERROR_RAM_UMOUNT; code=1; }
  fi
  if [ "$nfs" -eq 1 ]; then
    umount "$D/lower" || { echo J81_ERROR_NFS_UMOUNT; code=1; }
  fi
  if ! rmdir "$D/merged" "$D/ram" "$D/lower" "$D" 2>/dev/null; then
    echo J81_ERROR_TEST_DIR_CLEANUP
    code=1
  fi
  if [ "$code" -eq 0 ]; then echo J81_STAGE_GUEST_CLEANUP_OK; fi
  exit "$code"
}
trap cleanup EXIT
if ! mkdir "$D/lower" "$D/ram" "$D/merged"; then
  echo J81_ERROR_TEST_DIR
  exit 15
fi
if msg=$(mount -t nfs -o ro,vers=3,proto=tcp,nolock,soft,timeo=10,retrans=1 172.16.42.2:/Volumes/J81_OMARCHY_A_V011/rootfs "$D/lower" 2>&1); then
  nfs=1
  echo J81_STAGE_NFS_MOUNTED
else
  echo J81_ERROR_NFS_MOUNT
  printf 'J81_EXEC_DETAIL=%s\n' "$msg"
  exit 16
fi
if [ ! -x "$D/lower/usr/bin/uname" ] || [ ! -x "$D/lower/usr/bin/cat" ] ||
   [ ! -x "$D/lower/usr/bin/touch" ] || [ ! -e "$D/lower/usr/lib/ld-linux-aarch64.so.1" ]; then
  echo J81_ERROR_ARCH_BINARIES_UNAVAILABLE
  exit 17
fi
if ! mount -t tmpfs -o size=64m,mode=0755 tmpfs "$D/ram"; then
  echo J81_ERROR_TMPFS_MOUNT
  exit 18
fi
ram=1
if ! mkdir "$D/ram/upper" "$D/ram/work"; then
  echo J81_ERROR_TMPFS_DIRS
  exit 19
fi
if msg=$(mount -t overlay overlay -o lowerdir="$D/lower",upperdir="$D/ram/upper",workdir="$D/ram/work" "$D/merged" 2>&1); then
  cow=1
  echo J81_STAGE_OVERLAY_MOUNTED
else
  echo J81_ERROR_OVERLAY_MOUNT
  printf 'J81_EXEC_DETAIL=%s\n' "$msg"
  exit 20
fi
if [ ! -x "$D/merged/usr/bin/uname" ] || [ ! -r "$D/merged/usr/lib/os-release" ]; then
  echo J81_ERROR_OVERLAY_ARCH_FILES
  exit 21
fi
# Only execute four known Arch Linux ARM binaries in a short-lived child
# chroot. This is NOT a PID1 change, and does not mount proc/sys/dev inside.
if arch=$($CHROOT "$D/merged" /usr/bin/uname -m 2>&1); then
  if [ "$arch" = "aarch64" ]; then
    echo J81_STAGE_ARCH_UNAME_EXECUTED
  else
    echo J81_ERROR_UNEXPECTED_ARCH
    exit 22
  fi
else
  echo J81_ERROR_UNAME_EXEC
  printf 'J81_EXEC_DETAIL=%s\n' "$arch"
  exit 23
fi
if uid=$($CHROOT "$D/merged" /usr/bin/id -u 2>&1); then
  if [ "$uid" = "0" ]; then
    echo J81_STAGE_ARCH_ID_EXECUTED
  else
    echo J81_ERROR_UNEXPECTED_UID
    exit 24
  fi
else
  echo J81_ERROR_ID_EXEC
  printf 'J81_EXEC_DETAIL=%s\n' "$uid"
  exit 25
fi
if osrel=$($CHROOT "$D/merged" /usr/bin/cat /usr/lib/os-release 2>&1); then
  case "$osrel" in
    *ID=*) echo J81_STAGE_ARCH_OS_RELEASE_EXECUTED ;;
    *) echo J81_ERROR_OS_RELEASE_CONTENT; exit 26 ;;
  esac
else
  echo J81_ERROR_CAT_EXEC
  printf 'J81_EXEC_DETAIL=%s\n' "$osrel"
  exit 27
fi
# New file is created *by Arch's real touch executable* within the merged
# filesystem. It exists in RAM upper but not in the read-only Mac NFS lower.
if msg=$($CHROOT "$D/merged" /usr/bin/touch /var/tmp/j81-arch-@@TOKEN@@ 2>&1); then
  echo J81_STAGE_ARCH_TOUCH_EXECUTED
else
  echo J81_ERROR_TOUCH_EXEC
  printf 'J81_EXEC_DETAIL=%s\n' "$msg"
  exit 28
fi
if [ ! -f "$D/merged/var/tmp/j81-arch-@@TOKEN@@" ] ||
   [ ! -f "$D/ram/upper/var/tmp/j81-arch-@@TOKEN@@" ] ||
   [ -e "$D/lower/var/tmp/j81-arch-@@TOKEN@@" ]; then
  echo J81_ERROR_ARCH_TOUCH_NOT_IN_RAM
  exit 29
fi
echo J81_STAGE_RAM_ONLY_WRITE_VERIFIED
# No systemd, init, login, or hardware-specific scripts are executed.
echo J81_FULL_ARCH_EXEC_PASS
'''
    return script.replace("@@TOKEN@@", token)


def confirmation():
    print("\nNext J81 milestone: execute four Arch ARM64 userspace utilities")
    print("inside a temporary chroot backed by read-only Mac NFS + 64 MiB RAM overlay.")
    print("No systemd, PID 1 replacement, firmware, internal storage, DFU or reboot.")
    print("Temporary NFS export limited to the iPad USB address 172.16.42.1.")
    print("The original Omarchy root files are not modified.")
    with open("/dev/tty", "r", encoding="utf-8") as tty:
        print("Type EXEC ARCH to authorize this live test: ", end="", flush=True)
        answer = tty.readline().strip()
    return answer == "EXEC ARCH"


def run_guest(usb, host, token):
    # Earlier hardware-confirmed NFS test needed a short startup delay.
    time.sleep(4)
    client = usb.IPadShell()
    out = ""
    try:
        out, rc = client.run(guest_script(token), seconds=145, check=False)
        marks = host.static_markers(out)
        # The parent shell is still the diagnostic shell; no PID1 transition.
        alive, alive_rc = client.run("uname -r", seconds=15, check=False)
        if alive_rc == 0 and alive.strip() == KERNEL:
            marks.append("J81_STAGE_DIAGNOSTIC_SHELL_ALIVE")
        else:
            rc = rc or 99
    finally:
        client.close()
    print("\n--- Real Arch Linux ARM userspace execution on J81 ---")
    for title, marker in (
        ("Full NFS root", "J81_STAGE_NFS_MOUNTED"),
        ("RAM OverlayFS", "J81_STAGE_OVERLAY_MOUNTED"),
        ("Arch uname (ARM64)", "J81_STAGE_ARCH_UNAME_EXECUTED"),
        ("Arch id (root)", "J81_STAGE_ARCH_ID_EXECUTED"),
        ("Arch cat (OS identity)", "J81_STAGE_ARCH_OS_RELEASE_EXECUTED"),
        ("Arch touch (RAM write)", "J81_STAGE_ARCH_TOUCH_EXECUTED"),
        ("Original NFS root unchanged", "J81_STAGE_RAM_ONLY_WRITE_VERIFIED"),
        ("Guest mounts cleaned", "J81_STAGE_GUEST_CLEANUP_OK"),
        ("Diagnostic shell still running", "J81_STAGE_DIAGNOSTIC_SHELL_ALIVE"),
    ):
        print(f"{title}: {'PASS' if marker in marks else 'NOT VERIFIED'}")
    print("Diagnostic codes:", ", ".join(marks) if marks else "(none)")
    for line in out.splitlines():
        if line.startswith("J81_EXEC_DETAIL="):
            # Only expected command/mount error text, not device identifiers.
            detail = re.sub(r"(?i)\b(?:ECID|UDID)[:=]\S+", "[private]", line.split("=", 1)[1])
            print("Failure detail:", detail[:400])
    needed = {
        "J81_STAGE_NFS_MOUNTED", "J81_STAGE_OVERLAY_MOUNTED",
        "J81_STAGE_ARCH_UNAME_EXECUTED", "J81_STAGE_ARCH_ID_EXECUTED",
        "J81_STAGE_ARCH_OS_RELEASE_EXECUTED", "J81_STAGE_ARCH_TOUCH_EXECUTED",
        "J81_STAGE_RAM_ONLY_WRITE_VERIFIED", "J81_STAGE_GUEST_CLEANUP_OK",
        "J81_STAGE_DIAGNOSTIC_SHELL_ALIVE", "J81_FULL_ARCH_EXEC_PASS",
    }
    failures = [m for m in marks if m.startswith("J81_ERROR_")]
    host.need(rc == 0 and needed <= set(marks),
              "Arch userspace test did not pass: " + (", ".join(failures) or
              "missing a required proof or cleanup marker"))


def make_report(success, stage, error=None, cleanup_ok=False):
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "J81 ARCH LINUX ARM USERSPACE EXECUTION TEST",
        "Result: " + ("PASS" if success and cleanup_ok else "NOT PASSED"),
        "Stage: " + stage,
        "iPad: iPad Air 2 Wi-Fi / J81AP / iPad5,3 / T7001",
        "Live kernel expected: " + KERNEL,
        "Mac root: Orchard Omarchy A v0.1.1 (original J71b profile)",
        "Execution: short-lived chroot of four Arch ARM64 utilities only",
        "Root filesystem: read-only USB NFS lower + 64 MiB iPad RAM upper",
        "iPad storage writes: NONE",
        "systemd/PID1: NOT STARTED OR REPLACED",
        "J71b services and desktop: NOT STARTED",
        "Mac NFS export cleanup: " + ("VERIFIED" if cleanup_ok else "NOT VERIFIED"),
    ]
    if error:
        lines.append("Issue: " + str(error).replace("\n", " ")[:240])
    REPORT.write_text("\n".join(lines) + "\n")
    print("Shareable report:", REPORT)


def main():
    try:
        host = load_verified_host()
        preflight_owners(host)
        usb = host.git_source(WORK.resolve(strict=True))
        host.check_mac_net()
        host.get_live_kernel(usb)
        check_guest_chroot(usb)
        result = {"guest_passed": False}
        host.confirm = confirmation
        def guarded_guest(usb_mod):
            run_guest(usb_mod, host, secrets.token_hex(4))
            result["guest_passed"] = True
        host.run_on_ipad = guarded_guest
        host.report = lambda unused_work, success, stage, error=None, cleanup_ok=False: make_report(
            success, stage, error=error, cleanup_ok=cleanup_ok)
        host.test(WORK)
        if not result["guest_passed"]:
            print("CANCELLED: No Arch userspace programs were run.")
            return 0
        print("PASS: Native Arch Linux ARM utilities executed on the Air 2.")
        print("J71b services, systemd and the graphical desktop were NOT started.")
        return 0
    except Exception as exc:
        # Includes the verified NFS helper's own TestError. We report only
        # fixed validation/cleanup text, not raw USB diagnostic transcripts.
        print("STOP:", str(exc)[:280], file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Mount complete Omarchy A release over J81 USB/NFS READ ONLY; never start it.

Host /etc/exports is used only if previously absent. The export is restricted
by source IP and remains read-only, with macOS mapall=nobody. The guest does
not chroot, pivot_root, switch_root or run unreviewed J71b services.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys

WORK_DEFAULT = Path.home() / 'Downloads/J81-Omarchy-A-Netroot-Work-v1'
VOLUME_ROOT = Path('/Volumes/J81_OMARCHY_A_V011/rootfs')
EXPECTED_KERNEL = '7.3.0-rc1-j81-omarchy-netroot'
EXPECTED_J81_COMMIT = '7ea2b2b0f5c070690bf0efafd25a69d6ea345454'
EXPORT_PATH = Path('/etc/exports')
IPAD_USB_IP = '172.16.42.1'
HOST_USB_IP = '172.16.42.2'
TEST_ROOT = '/mnt/j81-full-omarchy-test'


class TestError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise TestError(message)


def run(cmd, *, capture=False, input=None, check=True):
    return subprocess.run([str(arg) for arg in cmd], capture_output=capture,
                          text=True, input=input, check=check)


def git_source(work):
    repo = work / 'source/ipadair2-omarchy'
    need(repo.is_dir(), 'Pinned J81 source checkout missing')
    head = run(['git', '-C', repo, 'rev-parse', 'HEAD'], capture=True).stdout.strip()
    dirty = run(['git', '-C', repo, 'status', '--porcelain', '--untracked-files=no'], capture=True).stdout.strip()
    need(head == EXPECTED_J81_COMMIT and not dirty, 'Pinned J81 source is modified or unexpected')
    file = repo / 'runtime/j81/reference/usb_shell.py'
    need(file.is_file() and not file.is_symlink(), 'Original J81 USB shell transport missing')
    spec = importlib.util.spec_from_file_location('j81_fullroot_original_usb_shell', file)
    need(spec is not None and spec.loader is not None, 'Cannot load J81 USB transport')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(module.IPAD == IPAD_USB_IP and module.MAC == HOST_USB_IP,
         'Unexpected J81 USB IP addresses')
    return module


def check_mac_net():
    out = run(['/sbin/ifconfig'], capture=True).stdout
    need(re.search(r'\binet\s+172\.16\.42\.2(?:\s|$)', out),
         'Mac USB IP 172.16.42.2 is not configured (keep iPad connected)')


def check_stage(work):
    statfile = work / 'fullroot-stage-v1/fullroot-stage.json'
    need(statfile.is_file() and not statfile.is_symlink(),
         'Full rootfs is not staged; run Stage-Full-Omarchy-A.command')
    data = json.loads(statfile.read_text())
    need(data.get('stage') == 'FULL_ARCH_OMARCHY_A_USERSPACE_READY_ON_MAC_NOT_BOOTED',
         'Full root stage status is not ready')
    need(data.get('upstream_profile') == 'j71b' and data.get('full_desktop_hardware_tested') is False,
         'Unreviewed rootfs metadata: do not start it')
    root = VOLUME_ROOT
    need(root.is_dir() and not root.is_symlink(), 'Case-sensitive APFS image must remain mounted')
    need(root.parent.stat().st_dev != root.parent.parent.stat().st_dev,
         'Full root path is not on an independently mounted disk image')
    for rel in ('usr/lib/systemd/systemd', 'usr/bin/labwc', 'usr/bin/quickshell',
                'etc/orchard/release.json', 'home/tablet/.local/share/omarchy-ipad/shell/shell.qml'):
        need((root / rel).is_file(), 'Required full-root member missing: ' + rel)
    release = json.loads((root / 'etc/orchard/release.json').read_text())
    need(release.get('profile') == 'j71b',
         'Rootfs profile changed; J81 adaptation assumptions must be reviewed')
    return root


def confirm():
    need(sys.stdin.isatty(), 'Run interactively in Mac Terminal')
    print('\nThe current J81 Linux USB shell will READ this FULL Arch/Omarchy root.')
    print('It will NOT boot systemd, run the J71b services, change the kernel or touch the iPad storage.')
    print('A temporary read-only NFS share will be restricted to 172.16.42.1.')
    print('Client root maps to root only within this PUBLIC rootfs export to access protected tablet files.')
    return input('Type TEST FULL ROOT to allow the temporary export: ').strip() == 'TEST FULL ROOT'


def check_no_existing_nfs():
    need(not os.path.lexists(EXPORT_PATH),
         'Existing /etc/exports detected; this helper will not modify it')
    ps = run(['/usr/bin/pgrep', '-x', 'nfsd'], capture=True, check=False)
    need(ps.returncode != 0, 'An NFS server is already running; no changes made')


def sudo(*args, **kwargs):
    return run(['sudo', *args], **kwargs)


def export_spec(root):
    """Read-only, ONE-IP export. Preserve guest UIDs; only map guest root to root.

    The prior -mapall=nobody works for public hello.txt, but can hide files
    below a private user home (for example /home/tablet) in the full rootfs.
    The host export stays limited to this dedicated public rootfs and one
    physically connected iPad USB address. Never export $HOME or /Volumes.
    """
    need(root == VOLUME_ROOT, 'Unexpected NFS export target')
    return str(root) + ' -ro -maproot=root ' + IPAD_USB_IP + '\n'


def build_test_script():
    """Temporary guest read-only NFS test, with allowlisted status markers."""
    return r"""
set -u
ROOT=/mnt/j81-full-omarchy-test
echo J81_STAGE_GUEST_READY
mkdir -p "$ROOT" || { echo J81_ERROR_MOUNTPOINT; exit 21; }
if grep -q ' /mnt/j81-full-omarchy-test nfs' /proc/mounts; then
  echo J81_ERROR_OLD_MOUNT
  exit 22
fi
if MOUNT_ERROR="$(mount -t nfs -o ro,vers=3,proto=tcp,nolock,soft,timeo=10,retrans=1 172.16.42.2:/Volumes/J81_OMARCHY_A_V011/rootfs "$ROOT" 2>&1)"; then
  echo J81_STAGE_NFS_MOUNTED
else
  echo J81_ERROR_NFS_MOUNT
  case "$MOUNT_ERROR" in
    *"Permission denied"*|*"permission denied"*|*"access denied"*) echo J81_CAUSE_NFS_ACCESS_DENIED ;;
    *"No such file"*|*"not found"*) echo J81_CAUSE_NFS_PATH_NOT_FOUND ;;
    *"Connection refused"*|*"Network is unreachable"*|*"timed out"*|*"Timed out"*) echo J81_CAUSE_NFS_CONNECTION ;;
    *"Protocol not supported"*|*"Invalid argument"*) echo J81_CAUSE_NFS_PROTOCOL ;;
    *) echo J81_CAUSE_NFS_OTHER ;;
  esac
  exit 23
fi
check=0
[ -r "$ROOT/etc/os-release" ] || { echo J81_ERROR_READ_OS_RELEASE; check=1; }
[ -r "$ROOT/etc/orchard/release.json" ] || { echo J81_ERROR_READ_RELEASE_JSON; check=1; }
[ -r "$ROOT/home/tablet/.local/share/omarchy-ipad/shell/shell.qml" ] || { echo J81_ERROR_READ_TABLET_SHELL; check=1; }
[ -x "$ROOT/usr/lib/systemd/systemd" ] || { echo J81_ERROR_ACCESS_SYSTEMD; check=1; }
[ -x "$ROOT/usr/bin/labwc" ] || { echo J81_ERROR_ACCESS_LABWC; check=1; }
[ -x "$ROOT/usr/bin/quickshell" ] || { echo J81_ERROR_ACCESS_QUICKSHELL; check=1; }
if [ "$check" -eq 0 ]; then
  echo J81_FULL_OMARCHY_USERSPACE_FOUND
else
  echo J81_ERROR_USERSPACE_ACCESS
fi
if ! umount "$ROOT"; then
  echo J81_ERROR_UNMOUNT
  exit 24
fi
echo J81_STAGE_NFS_UNMOUNTED
[ "$check" -eq 0 ] || exit 25
echo J81_FULLROOT_READONLY_NFS_PASS
"""


def static_markers(output):
    """Never expose raw device output in a report, only static J81 status codes."""
    names = []
    for line in output.splitlines():
        marker = line.strip()
        if (re.fullmatch(r'J81_(?:STAGE|ERROR|CAUSE|FULL)[A-Z0-9_]{1,70}', marker)
                and marker not in names):
            names.append(marker)
    return names


def get_live_kernel(module):
    client = module.IPadShell()
    try:
        out, rc = client.run('uname -r', seconds=12)
        need(rc == 0 and out.strip() == EXPECTED_KERNEL,
             'Wrong live Linux kernel; no NFS export started')
    finally:
        client.close()


def run_on_ipad(module):
    client = module.IPadShell()
    try:
        out, rc = client.run(build_test_script(), seconds=80, check=False)
        markers = static_markers(out)
        print('\n--- iPad full-root probe ---')
        print('NFS mount:', 'PASS' if 'J81_STAGE_NFS_MOUNTED' in markers else 'NOT VERIFIED')
        print('Omarchy files:', 'READABLE' if 'J81_FULL_OMARCHY_USERSPACE_FOUND' in markers else 'NOT VERIFIED')
        print('NFS unmount:', 'PASS' if 'J81_STAGE_NFS_UNMOUNTED' in markers else 'NOT VERIFIED')
        print('Diagnostic codes:', ', '.join(markers) if markers else '(no status markers returned)')
        passed = (rc == 0 and 'J81_FULL_OMARCHY_USERSPACE_FOUND' in markers
                  and 'J81_STAGE_NFS_UNMOUNTED' in markers
                  and 'J81_FULLROOT_READONLY_NFS_PASS' in markers)
        failures = [m for m in markers if m.startswith(('J81_ERROR_', 'J81_CAUSE_'))]
        need(passed,
             'Full-root NFS probe failed' + (': ' + ', '.join(failures) if failures else
              ': remote stage markers not received; keep the current iPad session and inspect Mac output'))
    finally:
        client.close()


def report(work, success, stage, error=None, cleanup_ok=False):
    dest = work / 'fullroot-stage-v1/J81-FULLROOT-USB-RESULT.txt'
    dest.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        'J81 OMARCHY A COMPLETE ROOTFS NFS TEST',
        'Result: ' + ('PASS (READ-ONLY FULL ROOTFS MOUNT; NOT BOOTED)' if success else 'NOT PASSED'),
        'Stage reached: ' + stage,
        'iPad target: iPad5,3/J81AP/T7001',
        'Kernel expected: ' + EXPECTED_KERNEL,
        'Rootfs: Orchard Omarchy A v0.1.1 (original J71b release)',
        'USB/NFS: 172.16.42.2 host -> 172.16.42.1 iPad',
        'macOS NFS cleanup: ' + ('VERIFIED' if cleanup_ok else 'UNCONFIRMED; REVIEW MAC TERMINAL'),
        'iPad internal storage: NOT ACCESSED',
        'Linux full Omarchy PID1/switch_root: NOT ATTEMPTED',
        'J71b systemd services: NOT STARTED',
        'Linux rootfs files: NOT MODIFIED',
    ]
    if error:
        # Only status text written by our code, not raw potentially private logs.
        lines.append('Note: ' + error[:200].replace('\n', ' '))
    dest.write_text('\n'.join(lines) + '\n')
    print('Shareable result: ' + str(dest))


def test(work):
    need(platform.system() == 'Darwin' and platform.machine() == 'arm64',
         'This tool must run on the Apple Silicon Mac')
    work = work.expanduser().resolve(strict=True)
    root = check_stage(work)
    module = git_source(work)
    check_mac_net()
    get_live_kernel(module)
    check_no_existing_nfs()
    if not confirm():
        report(work, False, 'USER CANCELLED')
        print('Cancelled. No exports or iPad mounts were attempted.')
        return
    print('Requesting macOS administrator approval for a temporary NFS export ...')
    sudo('-v')
    # Refresh the no-clobber preflight after sudo/password interaction.
    check_no_existing_nfs()
    export_line = export_spec(root)
    created = False
    started = False
    pass_probe = False
    cleanup_ok = True
    stage = 'EXPORT NOT CREATED'
    error = None
    try:
        # noclobber guards against accidentally truncating an existing export.
        sudo('/bin/sh', '-c', 'set -C; umask 077; cat > /etc/exports', input=export_line)
        created = True
        stage = 'EXPORT CREATED'
        sudo('/sbin/nfsd', 'checkexports')
        stage = 'EXPORT VALIDATED'
        started = True  # cleanup even if start returns a partial failure
        sudo('/sbin/nfsd', 'start')
        stage = 'MAC NFS STARTED'
        print('Mac NFS export active only for the current read-only test.')
        run_on_ipad(module)
        pass_probe = True
        stage = 'FULL ROOTFS READ AND UNMOUNT VERIFIED'
        print('PASS: FULL Omarchy A userspace mounted and read over USB/NFS.')
        print('The J71b image was NOT booted; its services still need J81 adaptation.')
    except (TestError, subprocess.CalledProcessError, OSError, TimeoutError, ConnectionError) as exc:
        error = str(exc)
        print('\nSTOP: ' + error, file=sys.stderr)
    finally:
        if started:
            try:
                stopped = sudo('/sbin/nfsd', 'stop', capture=True, check=False)
                if stopped.returncode != 0:
                    cleanup_ok = False
                    print('WARNING: Could not confirm nfsd stop; check Mac NFS status')
            except OSError:
                cleanup_ok = False
                print('WARNING: Could not stop temporary Mac NFS service; check Mac NFS status')
        if created:
            try:
                got = sudo('/bin/cat', '/etc/exports', capture=True).stdout
                if got == export_line:
                    sudo('/bin/rm', '-f', '/etc/exports')
                    if os.path.lexists(EXPORT_PATH):
                        cleanup_ok = False
                        print('WARNING: Temporary export file is still present')
                else:
                    print('WARNING: /etc/exports changed while test ran. Leaving file unchanged for review.')
                    cleanup_ok = False
            except (subprocess.CalledProcessError, OSError):
                print('WARNING: Unable to confirm/remove /etc/exports; review manually.')
                cleanup_ok = False
        report(work, pass_probe and cleanup_ok, stage, error=error, cleanup_ok=cleanup_ok)
        print('Temporary NFS service cleanup attempted. Rootfs image stays mounted on your Mac.')
        if not cleanup_ok:
            pass_probe = False
    need(pass_probe, 'Full-root NFS mount did not pass; inspect the report and Mac Terminal output')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work', type=Path, default=WORK_DEFAULT)
    args = ap.parse_args(argv)
    try:
        test(args.work)
    except (TestError, OSError, ValueError, subprocess.CalledProcessError, socket.error) as exc:
        print('STOP: ' + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

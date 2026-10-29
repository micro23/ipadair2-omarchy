#!/usr/bin/env python3
"""Offline-only safety and fake iPad tests. No USB/network/host writes."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import re
import subprocess
import shutil

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'j81_systemd_adapter_stage.py'
SPEC = importlib.util.spec_from_file_location('j81_systemd_stage', SOURCE)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

checks = 0

def check(condition, detail):
    global checks
    assert condition, detail
    checks += 1

check(module.ARCH_SHA == '3db4cede36213b02fbc5df8d62d7e028e9138c98ed3519202142477a534715e8', 'original Arch-tool pin')
check(module.KERNEL == '7.3.0-rc1-j81-omarchy-netroot', 'J81 kernel pin')
check(str(module.ROOT) == '/Volumes/J81_OMARCHY_A_V011/rootfs', 'Mac root pin')
check(set(module.MASKS) == {'j71b-charge.service','j71b-platform-ready.service','omarchy-diagnostics.service','getty@tty1.service'}, 'exactly four masks')
check('j81-usb-root-guard.service' in module.UNIT_TARGET, 'target gated by guard')
check('DefaultDependencies=no' in module.UNIT_TARGET, 'minimal target dependencies')
check('ExecStart=/usr/local/libexec/j81-usb-root-guard' in module.UNIT_GUARD, 'guard path')
check('apple,j81' in module.GUARD_SCRIPT and 'apple,t7001' in module.GUARD_SCRIPT, 'board checks in future guard')
check('7.3.0-rc1-j81-omarchy-netroot' in module.GUARD_SCRIPT, 'guard kernel release')
check('systemctl' not in module.UNIT_TARGET and 'systemctl' not in module.UNIT_GUARD, 'no activation')
cmd = module.guest_script('deadbeef')
check('deadbeef' in cmd and '@@' not in cmd, 'dynamic token expanded')
check('size=96m' in cmd and '-o ro,vers=3,proto=tcp' in cmd, 'bounded RAM overlay and NFS read-only')
check('172.16.42.2:/Volumes/J81_OMARCHY_A_V011/rootfs' in cmd, 'USB-only root')
check('ln -s /dev/null "$M/$unit"' in cmd, 'mask in RAM merged')
check('readlink "$M/$unit"' in cmd, 'mask verified')
check('chroot "$D/merged" /usr/lib/systemd/systemd' not in cmd, 'no PID1 execution')
check('--recursive-errors=no' in cmd and '/usr/bin/systemd-analyze verify' in cmd, 'unit syntax validation only')
check('J81_STAGE_SYSTEMD_ANALYZE_VERIFY_PASS' in cmd, 'verified unit parse marker')
check('J81_STAGE_ORIGINAL_J71B_ROOT_UNMODIFIED' in cmd, 'original lower safety')
check('J81_STAGE_GUEST_CLEANUP_OK' in cmd, 'cleanup proof marker')
check(cmd.index('umount "$D/merged"') < cmd.index('umount "$D/ram"') < cmd.index('umount "$D/lower"'), 'unmount order')
check(not re.search(r'(?m)^\s*(?:reboot|switch_root|pivot_root|poweroff|sfdisk|fdisk|parted|mkfs|dd|rm\s+-rf)\b', cmd), 'forbidden mutation commands')
check('/dev/disk' not in cmd and '/dev/mmcblk' not in cmd, 'no internal storage paths')
check(cmd.index('J81_STAGE_FULLROOT_NFS_MOUNTED') < cmd.index('J81_STAGE_RAM_OVERLAY_MOUNTED') < cmd.index('J81_STAGE_SYSTEMD_ANALYZE_VERIFY_PASS'), 'expected stage order')
check('J81_STAGE_SYSTEMD_CANDIDATE_PASS' in cmd, 'final recognized status marker')
check(subprocess.run(['/bin/sh','-n'],input=cmd,text=True,capture_output=True).returncode == 0, 'guest script shell syntax')
check(subprocess.run(['/bin/sh','-n'],input=module.GUARD_SCRIPT,text=True,capture_output=True).returncode == 0, 'guard shell syntax')
check('EXEC ARCH' not in module.confirm.__code__.co_consts, 'unique confirmation')
check('STAGE J81' in module.confirm.__code__.co_consts, 'explicit confirmation')
check((HERE / 'Run-J81-Systemd-Adapter.command').is_file(), 'launcher present')
launcher=(HERE/'Run-J81-Systemd-Adapter.command').read_text()
check(launcher.startswith('#!/bin/zsh') and 'j81_systemd_adapter_stage.py' in launcher and 'Run-J81-Systemd-Adapter' not in launcher.splitlines()[-1], 'Mac launcher paths and shebang')
if shutil.which('zsh'):
    check(subprocess.run(['zsh','-n',str(HERE/'Run-J81-Systemd-Adapter.command')],capture_output=True).returncode == 0, 'Mac launcher zsh syntax')

check('--man=no' in cmd, 'manual-page lookup disabled, unit parsing retained')
check('mknod "$D/merged/dev/null" c 1 3' in cmd, 'only null character device created')
check('size=1m,mode=0755,nosuid,noexec' in cmd, 'private bounded RAM dev filesystem')
check(cmd.index('umount "$D/merged/dev"') < cmd.index('umount "$D/merged"'), 'private dev cleanup precedes overlay')
check('if [ "$cleanup_ok" -eq 1 ]' in cmd, 'cleanup reports independently of validation result')

class FakeHost:
    @staticmethod
    def static_markers(output):
        return [s for s in output.splitlines() if re.fullmatch(r'J81_(?:STAGE|ERROR|CAUSE|FULL)[A-Z0-9_]{1,70}',s)]
    @staticmethod
    def need(test, reason):
        if not test:
            raise ValueError(reason)

ok_codes = [
    'J81_STAGE_FULLROOT_NFS_MOUNTED',
    'J81_STAGE_RAM_OVERLAY_MOUNTED',
    'J81_STAGE_PRIVATE_DEV_NULL_READY',
    'J81_STAGE_J71B_SERVICES_MASKED_IN_RAM',
    'J81_STAGE_ORIGINAL_J71B_ROOT_UNMODIFIED',
    'J81_STAGE_J81_GUARD_SYNTAX_PASS',
    'J81_STAGE_SYSTEMD_ANALYZE_VERIFY_PASS',
    'J81_STAGE_J81_CANDIDATE_VERIFIED_IN_RAM',
    'J81_STAGE_GUEST_CLEANUP_OK',
    'J81_STAGE_SYSTEMD_CANDIDATE_PASS',
]
class FakeUSB:
    result = '\n'.join(ok_codes)
    rc = 0
    class IPadShell:
        def run(self,command,seconds=20,check=True):
            if command=='uname -r':
                return module.KERNEL,0
            return FakeUSB.result, FakeUSB.rc
        def close(self):
            return None

old_sleep = module.time.sleep
try:
    module.time.sleep = lambda _: None
    module.run_guest(FakeUSB,FakeHost,'deadbeef')
    checks += 1
    FakeUSB.result = '\n'.join(c for c in ok_codes if c != 'J81_STAGE_SYSTEMD_ANALYZE_VERIFY_PASS') + '\nJ81_ERROR_SYSTEMD_ANALYZE_VERIFY'
    FakeUSB.rc = 27
    try:
        module.run_guest(FakeUSB,FakeHost,'1234abcd')
    except ValueError as e:
        check('J81_ERROR_SYSTEMD_ANALYZE_VERIFY' in str(e), 'fake failed unit check is fatal')
    else:
        raise AssertionError('bad unit verification incorrectly passed')
finally:
    module.time.sleep=old_sleep

print(f'PASS: {checks} offline static, shell-syntax, and fake-device checks')

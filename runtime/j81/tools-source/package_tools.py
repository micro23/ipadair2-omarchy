#!/usr/bin/env python3
"""Validate and package the small, RAM-only J81 network tool runtime.

No iPad, Wi-Fi association, DHCP, nft rule modification, or installer runs here.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

import build_tools as build

HERE = Path(__file__).resolve().parent
ROOT = HERE / 'root'
OUT = HERE / 'output'
ORIGIN = HERE / 'verified-origin'
BASE = Path('/tmp/air2-linux-build/ramdisk-validation/rootfs')
QEMU = build.QEMU
QEMU_DEB = Path('/tmp/air2-linux-build/ramdisk-validation/qemu-user-static_1%3a8.2.2+ds-0ubuntu1.18_amd64.deb')
QEMU_DEB_SHA = '5bb397f66063efa349f6fd5cb3b68cd96f29edd0994e4ba5115cf0859a716bf0'
TOOLS = ('iw', 'wpa_supplicant', 'wpa_cli', 'nft')

WRAPPER = '''#!/bin/sh
# Fixed runtime for the J81 RAM experiment. Use the base initramfs's BusyBox.
set -eu
base=/run/j81-wifi-tools
case "${1-}" in
    iw|wpa_supplicant|wpa_cli|nft) tool=$1; shift ;;
    *) printf '%s\\n' 'Usage: run-tool {iw|wpa_supplicant|wpa_cli|nft} [arguments...]' >&2; exit 64 ;;
esac
unset LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT GLIBC_TUNABLES ENV BASH_ENV
exec /bin/busybox env -i \\
    PATH=/bin:/sbin LC_ALL=C HOME=/run/j81-wifi-session TMPDIR=/run/j81-wifi-session \\
    OPENSSL_CONF=/dev/null OPENSSL_MODULES="$base/empty-openssl-modules" \\
    "$base/lib/ld-linux-aarch64.so.1" --inhibit-cache \\
    --library-path "$base/lib" "$base/bin/$tool" "$@"
'''


def run(args, *, input_text=None, expected=(0,)):
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null',
           'OPENSSL_MODULES': str(ROOT / 'empty-openssl-modules')}
    p = subprocess.run([str(v) for v in args], input=input_text, env=env,
                       capture_output=True, text=True, timeout=20)
    if p.returncode not in expected:
        raise RuntimeError(f'Unexpected validation failure: {args}: {p.returncode}: {p.stderr}')
    return {'command': [str(v) for v in args], 'exit_status': p.returncode,
            'stdout': p.stdout, 'stderr': p.stderr}


def under_qemu(program, args):
    return [QEMU, ROOT / 'lib/ld-linux-aarch64.so.1', '--inhibit-cache',
            '--library-path', ROOT / 'lib', program, *args]


def validate_qemu_package():
    if build.sha(QEMU_DEB) != QEMU_DEB_SHA:
        raise RuntimeError('Existing pinned QEMU package changed')
    proc = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(QEMU_DEB)], stdout=subprocess.PIPE)
    extracted_sha = None
    with tarfile.open(fileobj=proc.stdout, mode='r|') as tar:
        for member in tar:
            if member.name.removeprefix('./') == 'usr/bin/qemu-aarch64-static':
                extracted_sha = hashlib.sha256(tar.extractfile(member).read()).hexdigest()
    if proc.wait(timeout=10) or extracted_sha != build.sha(QEMU):
        raise RuntimeError('QEMU binary differs from its archived package')
    return {'package': QEMU_DEB.name, 'package_sha256': QEMU_DEB_SHA,
            'binary_sha256': extracted_sha, 'binary_matches_package': True,
            'version': run([QEMU, '--version'])['stdout'].splitlines()[0],
            'hash_reference': 'Original J81 RAM-test source/ramdisk/VALIDATION.txt; rechecked here.'}


def validate():
    checks = []
    # Every DT_NEEDED dependency resolves within the bundle; RPATH/RUNPATH is absent.
    closure = {}
    for path in sorted([*list((ROOT / 'bin').glob('*')), *list((ROOT / 'lib').glob('*'))]):
        data = path.read_bytes()
        if data[:4] != b'\x7fELF' or int.from_bytes(data[18:20], 'little') != 183:
            raise RuntimeError('Unexpected architecture or non-ELF runtime object: ' + str(path))
        dynamic = subprocess.run(['readelf', '-d', str(path)], check=True, capture_output=True, text=True).stdout
        if re.search(r'\((?:RPATH|RUNPATH)\)', dynamic):
            raise RuntimeError('Embedded library path found: ' + str(path))
        needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
        if any(not (ROOT / 'lib' / name).is_file() for name in needed):
            raise RuntimeError('Unresolved runtime library: ' + str(path))
        closure[path.relative_to(ROOT).as_posix()] = needed
    for tool, args, expected_text in [
        ('iw', ['--version'], 'iw version 6.17'),
        ('wpa_supplicant', ['-v'], 'wpa_supplicant v2.12'),
        ('wpa_supplicant', ['-h'], 'nl80211 = Linux nl80211/cfg80211'),
        ('wpa_cli', ['-v'], 'wpa_cli v2.12'),
    ]:
        result = run(under_qemu(ROOT / 'bin' / tool, args))
        if expected_text not in result['stdout']:
            raise RuntimeError('Expected tool feature/version is missing')
        result.update({'check': tool + ' ' + ' '.join(args), 'result': 'PASS'})
        checks.append(result)
    crypto = run(under_qemu(ORIGIN / 'usr/bin/wpa_passphrase', ['IEEE', 'password']))
    expected_psk = hashlib.pbkdf2_hmac('sha1', b'password', b'IEEE', 4096, 32).hex()
    if expected_psk != 'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e' or '\tpsk=' + expected_psk not in crypto['stdout']:
        raise RuntimeError('WPA PBKDF2 test vector failed')
    crypto.update({'check': 'Public WPA2 PBKDF2 test vector (IEEE/password)', 'result': 'PASS',
                   'notes': 'Synthetic public vector only. wpa_passphrase is a validation tool, not included in the runtime.'})
    checks.append(crypto)
    # --list uses the real dynamic loader but does not enter nft constructors.
    nft_libraries = run([QEMU, ROOT / 'lib/ld-linux-aarch64.so.1', '--inhibit-cache',
                         '--library-path', ROOT / 'lib', '--list', ROOT / 'bin/nft'])
    if 'not found' in nft_libraries['stdout'] + nft_libraries['stderr']:
        raise RuntimeError('nft library resolution failed')
    nft_libraries.update({'check': 'nft dynamic loader closure', 'result': 'PASS'})
    checks.append(nft_libraries)
    nft = run(under_qemu(ROOT / 'bin/nft', ['--version']), expected=(0, 3))
    if nft['exit_status'] == 3 and 'Unable to initialize Netlink socket: Protocol not supported' not in nft['stderr']:
        raise RuntimeError('Unexpected nft runtime error')
    nft.update({'check': 'nft execution in QEMU/container',
                'result': 'PASS' if nft['exit_status'] == 0 else 'BLOCKED_ENVIRONMENT',
                'notes': 'This environment does not expose NETLINK_NETFILTER. Device-side nft installation and exact readback must succeed before enabling Wi-Fi.'})
    checks.append(nft)
    applets = run([QEMU, '-L', BASE, BASE / 'bin/busybox', '--list'])
    requested = 'ip udhcpc timeout nslookup wget ping base64 stat od readlink awk tr cmp head tail kill sleep sha256sum tar gzip env'.split()
    if set(requested) - set(applets['stdout'].splitlines()):
        raise RuntimeError('Required BusyBox applet missing')
    checks.append({'check': 'Original BusyBox applets', 'result': 'PASS', 'applets': requested,
                   'binary_sha256': build.sha(BASE / 'bin/busybox'), 'version': '1.31.1',
                   'full_applet_list': applets['stdout'].splitlines()})
    shell = run([QEMU, '-L', BASE, BASE / 'bin/busybox', 'sh', '-n', ROOT / 'run-tool'])
    shell.update({'check': 'run-tool syntax under exact original AArch64 BusyBox shell', 'result': 'PASS'})
    checks.append(shell)
    reject = run([QEMU, '-L', BASE, BASE / 'bin/busybox', 'sh', ROOT / 'run-tool', '../../bin/sh'], expected=(64,))
    reject.update({'check': 'run-tool rejects an unlisted executable before invocation', 'result': 'PASS'})
    checks.append(reject)
    return {'qemu': validate_qemu_package(), 'checks': checks, 'elf_needed_closure': closure,
            'hardware_tested': False,
            'not_tested': ['brcmfmac firmware loading', 'radio scan', 'association', 'DHCP', 'device nft execution', 'internet connectivity'],
            'linker_note': 'The existing binutils 2.42 linker warned that it could not emit the newer startup object’s optional .sframe unwind section. The link returned success; the resulting iw executes with this bundled loader.'}


def licenses_and_wrapper():
    # wpa_passphrase is retained in verified-origin for one crypto test only.
    (ROOT / 'bin/wpa_passphrase').unlink(missing_ok=True)
    source_map = json.loads((HERE / 'runtime-source-map.json').read_text())
    source_map.pop('bin/wpa_passphrase', None)
    source_map['bin/iw'] = 'Cross-built from official iw-6.17.tar.xz; see iw-build-command.json.'
    build.write_json(HERE / 'runtime-source-map.json', source_map)
    (ROOT / 'run-tool').write_text(WRAPPER)
    (ROOT / 'run-tool').chmod(0o755)
    source = ORIGIN / 'usr/share/licenses'
    for path in source.rglob('*'):
        if path.is_file():
            # Regulatory files are documented with the boot image instead.
            rel = path.relative_to(source)
            if rel.parts[0] == 'orchard-regdb':
                continue
            # Keep license texts relevant to the selected package set.
            if rel.parts[0] == 'spdx' and not (rel.name.startswith(('GPL-', 'LGPL-', 'AGPL-', 'Apache-')) or rel.name in ('Linux-syscall-note.txt', 'CC0-1.0.txt')):
                continue
            dest = ROOT / 'licenses' / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
            dest.chmod(0o644)
    (ROOT / 'licenses/iw').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / 'build/iw-6.17/COPYING', ROOT / 'licenses/iw/COPYING')
    build.write_json(ROOT / 'packages.json', json.loads((HERE / 'selected-packages.json').read_text()))


def archive():
    sums = []
    for p in sorted(ROOT.rglob('*')):
        if p.is_file() and p.name != 'SHA256SUMS':
            sums.append(build.sha(p) + '  ' + p.relative_to(ROOT).as_posix())
    (ROOT / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
    (ROOT / 'SHA256SUMS').chmod(0o644)
    records = []
    for p in sorted(ROOT.rglob('*')):
        if p.is_symlink() or (not p.is_dir() and not p.is_file()):
            raise RuntimeError('Runtime contains a special file/link')
        relative = p.relative_to(ROOT).as_posix()
        if p.is_dir():
            records.append({'path': relative, 'type': 'directory', 'bytes': 0, 'mode': '0755'})
        else:
            mode = '0755' if relative == 'run-tool' or relative.startswith(('bin/', 'lib/')) else '0644'
            records.append({'path': relative, 'type': 'file', 'bytes': p.stat().st_size,
                            'mode': mode, 'sha256': build.sha(p)})
    OUT.mkdir(exist_ok=True)
    path = OUT / 'tools.tar.gz'
    with path.open('wb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
            for record in records:
                info = tarfile.TarInfo(record['path'])
                info.mode = int(record['mode'], 8)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ''
                if record['type'] == 'directory':
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                else:
                    info.size = record['bytes']
                    with (ROOT / record['path']).open('rb') as content:
                        tar.addfile(info, content)
    manifest = {'format': 'j81-wifi-tools-v1', 'target': 'aarch64 Linux J81 RAM image',
                'extract_to': '/run/j81-wifi-tools', 'archive_has_top_directory': False,
                'archive': {'name': path.name, 'bytes': path.stat().st_size, 'sha256': build.sha(path)},
                'total_regular_bytes': sum(r['bytes'] for r in records),
                'regular_file_count': sum(r['type'] == 'file' for r in records),
                'total_entry_count': len(records), 'entries': records}
    build.write_json(OUT / 'tools-manifest.json', manifest)
    (OUT / 'tools.sha256').write_text(manifest['archive']['sha256'] + '  tools.tar.gz\n')
    return manifest


def main():
    licenses_and_wrapper()
    validation = validate()
    manifest = archive()
    build.write_json(OUT / 'VALIDATION.json', validation)
    provenance = {
        'source_rootfs': {'url': 'https://github.com/OrchardLinux/omarchy-a/releases/download/v0.1.0/rootfs.tar.zst',
                          'bytes': build.ARCHIVE.stat().st_size, 'sha256': build.ARCHIVE_SHA,
                          'verification': 'Locally rehashed pinned source archive, selected bytes re-extracted, candidate bytes compared. Original release receipt and GitHub digest were checked previously; no independent Sigstore verification claimed.'},
        'iw': {'url': 'https://www.kernel.org/pub/software/network/iw/iw-6.17.tar.xz', 'sha256': build.IW_SHA,
               'version': '6.17', 'verification': 'Downloaded over HTTPS and matched kernel.org sha256sums.asc. Detached signatures retained; PGP signature was not independently verified.'},
        'runtime_sources': json.loads((HERE / 'runtime-source-map.json').read_text()),
        'package_records': json.loads((HERE / 'selected-packages.json').read_text()),
        'scope': 'Public tool binaries/libraries/licenses only. No Apple firmware, device capture, SSID, password, secret, or mutable Wi-Fi session state.',
        'reproducibility': 'Deterministic packaging and precise source hash chain. No claim that upstream Arch packages were rebuilt reproducibly.'}
    build.write_json(OUT / 'PROVENANCE.json', provenance)
    source_dir = OUT / 'source'
    source_dir.mkdir(exist_ok=True)
    for name in ['build_tools.py', 'package_tools.py', 'origin-manifest.json', 'elf-closure.json',
                 'selected-packages.json', 'runtime-source-map.json', 'iw-build-command.json', 'iw-build.log']:
        shutil.copyfile(HERE / name, source_dir / name)
    for name in ['iw-6.17.tar.xz', 'sha256sums.asc', 'iw-6.17.tar.sign', 'download-receipt.json']:
        shutil.copyfile(HERE / 'downloads' / name, source_dir / name)
    shutil.copyfile('/tmp/air2-linux-build/toolchain-packages.json', source_dir / 'toolchain-packages.json')
    (OUT / 'README.md').write_text('''# J81 RAM Wi-Fi tool runtime

Extract `tools.tar.gz` into a fresh, private `/run/j81-wifi-tools` directory.
Its archive paths are relative to that directory; there is no top directory.
Verify the compressed hash and every manifest entry before execution. The
archive contains regular files/directories only and performs no installation.

Use `/run/j81-wifi-tools/run-tool iw`, `wpa_supplicant`, `wpa_cli`, or `nft`
with the desired arguments. The wrapper uses the bundled AArch64 glibc loader,
its explicit library path, no loader cache, and a clean fixed environment.
The original initramfs remains musl/BusyBox; do not invoke these binaries
directly or copy their libraries over the base system. The wrapper does not
start a daemon on its own. The session controller owns config, logs, PID,
control socket, DHCP, nft rules, and cleanup under `/run/j81-wifi-session`.

The included `nft` library closure resolves. This QEMU/container environment
does not expose NETLINK_NETFILTER, so it cannot test nft rule execution. The
device controller must successfully install and read back the scoped firewall
before raising the Wi-Fi interface. Do not bypass that check.

`VALIDATION.json` records real local emulator results and their limits.
`PROVENANCE.json`, `source/`, and runtime `licenses/` preserve source URLs,
versions, license notices, and hashes. All shared inputs are public software;
no proprietary firmware or credentials are in this runtime. GPL/LGPL package
source locations are the recorded upstream/package URLs; rebuilding those
upstream distribution binaries was outside this packaging task.
''')
    print(json.dumps({k: manifest[k] for k in ['archive', 'total_regular_bytes', 'regular_file_count', 'total_entry_count']}))


if __name__ == '__main__':
    main()

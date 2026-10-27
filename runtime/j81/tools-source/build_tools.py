#!/usr/bin/env python3
"""Select verified AArch64 WPA libraries and cross-build the small iw tool.

Only the already downloaded, pinned public rootfs and official iw source are
read. No installer/package scripts, iPad calls or network commands execute.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
ARCHIVE = Path('/tmp/air2-omarchy-build/rootfs-v0.1.0.tar.zst')
ARCHIVE_SHA = '8ff6897909d2fa3d894f7c87264e223000649f6be513414b9a0fef307adf3e46'
SOURCE = Path('/tmp/air2-omarchy-build/candidate-root')
ORIGIN = HERE / 'verified-origin'
ROOT = HERE / 'root'
TOOLCHAIN = Path('/tmp/air2-linux-build/toolchain')
IW_SHA = '7d182e498289ab39b257da6780d562e415377107f50358ee5b55b8cfe40b1e33'
PROGRAMS = ('wpa_supplicant', 'wpa_cli', 'wpa_passphrase', 'nft')
QEMU = Path('/tmp/air2-linux-build/ramdisk-validation/qemu/usr/bin/qemu-aarch64-static')
selected = set()
edges = {}


def sha(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()


def write_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def canonical(relative):
    path = (SOURCE / relative).resolve(strict=True)
    path.relative_to(SOURCE)
    if not path.is_file():
        raise RuntimeError('Expected source file: ' + relative)
    return path.relative_to(SOURCE).as_posix()


def dependencies(relative):
    relative = canonical(relative)
    if relative in selected:
        return
    selected.add(relative)
    data = (SOURCE / relative).read_bytes()[:20]
    if data[:4] != b'\x7fELF' or int.from_bytes(data[18:20], 'little') != 183:
        raise RuntimeError('Expected AArch64 ELF: ' + relative)
    result = subprocess.run(['readelf', '-d', str(SOURCE / relative)], check=True, capture_output=True, text=True).stdout
    needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', result)
    if re.search(r'\((?:RPATH|RUNPATH)\)', result):
        raise RuntimeError('Unexpected embedded library search path: ' + relative)
    edges[relative] = {}
    for name in needed:
        target = canonical('usr/lib/' + name)
        edges[relative][name] = target
        dependencies(target)


def metadata_fields(text):
    fields = {}
    for block in text.strip().split('\n\n'):
        lines = block.splitlines()
        if lines and lines[0].startswith('%'):
            fields[lines[0].strip('%')] = lines[1:]
    return fields


def extract_verified():
    if sha(ARCHIVE) != ARCHIVE_SHA:
        raise RuntimeError('Original rootfs archive changed')
    for name in PROGRAMS:
        dependencies('usr/bin/' + name)
    dependencies('usr/lib/ld-linux-aarch64.so.1')
    # ELF closure roots for iw; its link-only .so aliases are not packaged.
    dependencies('usr/lib/libnl-3.so.200')
    dependencies('usr/lib/libnl-genl-3.so.200')
    package_records = []
    development_files = set()
    for path in sorted((SOURCE / 'var/lib/pacman/local').glob('*/files')):
        fields = metadata_fields(path.read_text())
        if path.parent.name.startswith(('glibc-', 'linux-api-headers-', 'libnl-')):
            development_files.update(name for name in fields.get('FILES', []) if name.startswith('usr/include/') and not name.endswith('/'))
        owned = set(fields.get('FILES', [])) & selected
        if owned:
            desc = metadata_fields((path.parent / 'desc').read_text())
            package_records.append({'directory': path.parent.name, 'fields': desc, 'selected_files': sorted(owned)})
    wanted = set(selected) | development_files | {
        'usr/lib/libc.so', 'usr/lib/libc_nonshared.a',
        'usr/lib/crt1.o', 'usr/lib/Scrt1.o', 'usr/lib/crti.o', 'usr/lib/crtn.o',
    }
    inventory = json.loads(Path('/tmp/air2-omarchy-build/archive-inventory.json').read_text())
    package_names = {p['fields']['NAME'][0] for p in package_records}
    for entry in inventory:
        name = entry['path']
        if (name.startswith('usr/include/libnl3/')
                or name in ('usr/lib/firmware/regulatory.db', 'usr/lib/firmware/regulatory.db.p7s')
                or name.startswith('usr/share/licenses/common/')
                or name.startswith('usr/share/licenses/spdx/')
                or name.startswith('usr/share/licenses/orchard-regdb/')
                or any(name.startswith('usr/share/licenses/' + package + '/') for package in package_names)):
            if entry['type'] == 'file':
                wanted.add(name)
    ORIGIN.mkdir(parents=True, exist_ok=True)
    extracted = {}
    process = subprocess.Popen(['zstd', '-dq', '-c', str(ARCHIVE)], stdout=subprocess.PIPE)
    try:
        with tarfile.open(fileobj=process.stdout, mode='r|', bufsize=1024 * 1024) as archive:
            for member in archive:
                name = member.name.removeprefix('./').rstrip('/')
                if name not in wanted:
                    continue
                if not member.isfile() or member.size > 64 * 1024 * 1024:
                    raise RuntimeError('Selected archive member is not an expected bounded file: ' + name)
                if Path(name).is_absolute() or '..' in PurePosixPath(name).parts or name in extracted:
                    raise RuntimeError('Invalid selected archive path')
                data = archive.extractfile(member).read()
                if len(data) != member.size:
                    raise RuntimeError('Incomplete source extraction')
                target = ORIGIN / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
                extracted[name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                if name in selected and sha(SOURCE / name) != extracted[name]['sha256']:
                    raise RuntimeError('Previously extracted candidate differs from the pinned archive: ' + name)
        if process.wait(timeout=15):
            raise RuntimeError('Source decompression failed')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    if wanted != set(extracted):
        raise RuntimeError('Missing selected archive members: ' + str(sorted(wanted - set(extracted))))
    write_json(HERE / 'origin-manifest.json', {'rootfs_sha256': ARCHIVE_SHA, 'files': extracted})
    write_json(HERE / 'elf-closure.json', edges)
    write_json(HERE / 'selected-packages.json', package_records)
    return extracted


def prepare_root():
    ROOT.mkdir(exist_ok=True)
    for path in (ROOT / 'bin', ROOT / 'lib', ROOT / 'empty-openssl-modules'):
        path.mkdir(exist_ok=True)
    sources = {}
    for name in PROGRAMS:
        origin = canonical('usr/bin/' + name)
        shutil.copyfile(ORIGIN / origin, ROOT / 'bin' / name)
        (ROOT / 'bin' / name).chmod(0o755)
        sources['bin/' + name] = origin
    aliases = {'ld-linux-aarch64.so.1': canonical('usr/lib/ld-linux-aarch64.so.1')}
    for values in edges.values():
        for name, target in values.items():
            if name in aliases and aliases[name] != target:
                raise RuntimeError('Library name ambiguity')
            aliases[name] = target
    for name, origin in aliases.items():
        shutil.copyfile(ORIGIN / origin, ROOT / 'lib' / name)
        (ROOT / 'lib' / name).chmod(0o755)
        sources['lib/' + name] = origin
    write_json(HERE / 'runtime-source-map.json', sources)


def build_iw():
    archive = HERE / 'downloads/iw-6.17.tar.xz'
    if sha(archive) != IW_SHA:
        raise RuntimeError('Official iw source hash changed')
    source = HERE / 'build/iw-6.17'
    if not source.is_dir():
        with tarfile.open(archive, 'r:xz') as tar:
            tar.extractall(HERE / 'build', filter='data')
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = str(TOOLCHAIN / 'usr/lib/x86_64-linux-gnu')
    env['LC_ALL'] = 'C'
    compiler = TOOLCHAIN / 'usr/bin/aarch64-linux-gnu-gcc'
    flags = ('--sysroot=' + str(ORIGIN) + ' -B' + str(ORIGIN / 'usr/lib') + '/'
             + ' -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare'
             + ' -DCONFIG_LIBNL30 -I' + str(ORIGIN / 'usr/include/libnl3'))
    # Development headers, C runtime objects and runtime libraries all come
    # from the same pinned archive. GCC contributes its target built-ins and
    # crtbegin/crtend; no host C headers or host libraries are selected.
    libs = ('-L' + str(ROOT / 'lib') + ' ' + str(ROOT / 'lib/libnl-genl-3.so.200')
            + ' ' + str(ROOT / 'lib/libnl-3.so.200')
            + ' -Wl,-rpath-link,' + str(ROOT / 'lib'))
    ldflags = '--sysroot=' + str(ORIGIN) + ' -B' + str(ORIGIN / 'usr/lib') + '/'
    command = ['make', '-j4', 'NO_PKG_CONFIG=1', 'CC=' + str(compiler), 'CFLAGS=' + flags,
               'LDFLAGS=' + ldflags, 'LIBS=' + libs, 'V=1']
    with (HERE / 'iw-build.log').open('w') as log:
        result = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT)
    write_json(HERE / 'iw-build-command.json', {'command': command, 'cwd': str(source), 'exit_status': result.returncode,
                                            'source_sha256': IW_SHA, 'compiler': subprocess.run([str(compiler), '--version'], env=env, capture_output=True, text=True, check=True).stdout.splitlines()[0]})
    result.check_returncode()
    shutil.copyfile(source / 'iw', ROOT / 'bin/iw')
    (ROOT / 'bin/iw').chmod(0o755)
    subprocess.run([str(TOOLCHAIN / 'usr/bin/aarch64-linux-gnu-strip'), '--strip-debug', str(ROOT / 'bin/iw')],
                   env=env, check=True)


def main():
    extract_verified()
    prepare_root()
    build_iw()
    print(json.dumps({'selected_elf_objects': len(selected), 'programs': [*PROGRAMS, 'iw'], 'root': str(ROOT)}))


if __name__ == '__main__':
    main()

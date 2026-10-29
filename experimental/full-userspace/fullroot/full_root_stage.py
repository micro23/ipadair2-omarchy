#!/usr/bin/env python3
"""Safe, non-device J81 Omarchy A full-root staging onto a case-sensitive APFS image.

Input: signed upstream J71b v0.1.1 userspace by pinned SHA256. This does not
install, boot or modify the iPad. The J71b startup services remain UNQUALIFIED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import shutil
import stat
import subprocess
import sys
import tarfile

VERSION = 'v1.2'
ROOT_SHA = 'a5850a1575f52edab451783c3e4fdc2ac8cf727d5740c135c3929ff732da255c'
VOLUME = 'J81_OMARCHY_A_V011'
VOLUME_MOUNT = Path('/Volumes') / VOLUME
IMAGE_NAME = 'j81-omarchy-a-v0.1.1-case-sensitive.sparsebundle'
STAGE_NAME = 'fullroot-stage-v1'
SENTINEL = '.j81-omarchy-owner-stage-v1'
SENTINEL_VALUE = 'J81 full Omarchy A userspace staging only; no device install\n'
REQUIRED = {
    'usr/lib/systemd/systemd', 'usr/bin/labwc', 'usr/bin/quickshell',
    'home/tablet/.local/share/omarchy-ipad/shell/shell.qml',
    'etc/orchard/release.json', 'usr/libexec/j71b-check-platform',
    'arch-ipad-ui-manifest.json',
}
MAX_MEMBERS = 800_000
MAX_UNCOMPRESSED = 32 * (1 << 30)


class StageError(Exception):
    pass


def require(check, message):
    if not check:
        raise StageError(message)


def digest_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def do(cmd, **opts):
    return subprocess.run([str(x) for x in cmd], check=True, **opts)


def normalize_name(name):
    # POSIX names may contain literal backslashes. Only '/' separates path
    # components on macOS and Linux; rejecting '\\' falsely rejects legal
    # Arch package files. Keep absolute paths, NUL and '..' blocked below.
    require(isinstance(name, str), 'Invalid archive pathname type')
    require(name != '', 'Invalid archive pathname: empty name')
    require('\x00' not in name, 'Invalid archive pathname: NUL byte')
    require(not name.startswith('/'), 'An archive path is absolute')
    require('..' not in PurePosixPath(name).parts, 'An archive path traverses above its root')
    normalized = posixpath.normpath(name)
    require(not normalized.startswith('../') and normalized != '..', 'An archive path traverses upward')
    return normalized


def rewrite_link(member):
    """Normalize guest absolute/relative symlinks to safe guest-relative links.

    A guest-absolute /usr/lib link must NOT point to the Mac's /usr/lib.
    Rewriting to a relative path keeps its meaning when the root is later
    mounted as the actual guest filesystem, without affecting Mac host paths.
    """
    raw = member.linkname
    # In POSIX symlink targets a backslash is also a literal character.
    # All guest-absolute links are converted to in-root relative links and
    # checked by tarfile.data_filter before extraction.
    require(isinstance(raw, str), 'Archive link target has invalid type')
    require(raw != '' and '\x00' not in raw, 'Archive link target invalid')
    if member.issym():
        guest_parent = '/' + posixpath.dirname(member.name)
        guest_target = posixpath.normpath(
            raw if raw.startswith('/') else posixpath.join(guest_parent, raw))
        require(guest_target.startswith('/'), 'Link resolves outside guest root')
        relative = posixpath.relpath(guest_target, guest_parent)
        require(not relative.startswith('/'), 'Link conversion failed')
        member.linkname = relative
        return raw.startswith('/')
    if member.islnk():
        require(not raw.startswith('/'), 'Absolute hardlink in root filesystem')
        member.linkname = normalize_name(raw)
    return False


def vet_member(member, seen):
    name = normalize_name(member.name)
    if name == '.':
        require(member.isdir(), 'Invalid root archive member')
        return None, False
    require(name not in seen, 'Duplicate archive member: ' + name)
    seen.add(name)
    require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
            'Device/socket/FIFO/special archive member rejected: ' + name)
    member.name = name
    rewrote = rewrite_link(member) if (member.issym() or member.islnk()) else False
    require(0 <= member.size <= MAX_UNCOMPRESSED, 'Oversized tar member')
    return member, rewrote


def iter_archive(archive, zstd):
    """Stream verified zstd tar without unpacking large files in Python RAM."""
    proc = subprocess.Popen([zstd, '-d', '-q', '-c', str(archive)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert proc.stdout is not None
        with tarfile.open(fileobj=proc.stdout, mode='r|') as source:
            yield source
        proc.stdout.close()
        err = proc.stderr.read(4096).decode('utf-8', 'replace') if proc.stderr else ''
        rc = proc.wait()
        require(rc == 0, 'Compressed archive decoder failed: ' + err[:150])
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()


def audit_tar(archive, zstd):
    """Audit all members before extraction, including dangerous link types."""
    count, expanded, replaced, seen = 0, 0, 0, set()
    for source in iter_archive(archive, zstd):
        for member in source:
            try:
                member, changed = vet_member(member, seen)
            except StageError as exc:
                name = repr(getattr(member, 'name', '<unknown>'))[:160]
                raise StageError(f'Archive audit entry {count + 1} ({name}): {exc}') from exc
            if member is None:
                continue
            count += 1
            expanded += member.size
            replaced += int(changed)
            require(count <= MAX_MEMBERS and expanded <= MAX_UNCOMPRESSED,
                    'Root filesystem exceeds offline audit limits')
    missing = REQUIRED - seen
    require(not missing, 'Upstream archive is missing expected desktop/runtime member(s): ' + ', '.join(sorted(missing)))
    require('lib' in seen, 'Root filesystem has no /lib entry')
    return {'members': count, 'expanded_regular_bytes': expanded,
            'guest_absolute_symlinks_rewritten_on_extraction': replaced,
            'required_members': sorted(REQUIRED)}


def filter_for_extraction(tarinfo, destination):
    """Check paths with CPython's defense-in-depth data_filter; keep Linux modes.

    All input metadata is from a SHA256-pinned published rootfs. The named
    image mount is dedicated to this task. Absolute guest symlinks are already
    normalized to relative before we reach data_filter.
    """
    try:
        tarfile.data_filter(tarinfo, destination)
    except (tarfile.FilterError, ValueError, OSError) as exc:
        raise StageError('Unsafe archive extraction path: ' + tarinfo.name) from exc
    return tarinfo


def extract_tar(archive, zstd, dest):
    """Stream each unique entry exactly once; tolerate tarfile directory fixups.

    CPython 3.13 extractall() invokes the user filter a second time for
    directory ownership/mode/mtime fixups, passing back the SAME TarInfo
    object. A second distinct TarInfo with the same path remains rejected.
    Other legitimate reapplications (e.g. hardlink fallback) are also only
    allowed for the identical previously vetted object.
    """
    seen, identities, count = set(), {}, 0
    for source in iter_archive(archive, zstd):
        def approved(member, target):
            nonlocal count
            name = normalize_name(member.name)
            old = identities.get(name)
            if old is not None:
                if old is not member:
                    raise StageError('Actual duplicate archive member: ' + name)
                # The exact SAME tar member is being revalidated by tarfile.
                # Never add to seen twice, increment count, or rewrite links.
                return filter_for_extraction(member, target)
            try:
                vetted, _ = vet_member(member, seen)
            except StageError as exc:
                name = repr(getattr(member, 'name', '<unknown>'))[:160]
                raise StageError(f'Extraction member {count + 1} ({name}): {exc}') from exc
            if vetted is None:
                return None
            name = vetted.name
            # Hold the original TarInfo strongly: streaming tar releases
            # members, so numeric id() values alone can be reused later.
            identities[name] = member
            count += 1
            require(count <= MAX_MEMBERS, 'Archive exceeded member limit')
            return filter_for_extraction(vetted, target)
        source.extractall(path=dest, numeric_owner=True, filter=approved)
    require(REQUIRED <= seen, 'Extracted archive is missing required members')


def expected_paths(work):
    return (work / IMAGE_NAME, VOLUME_MOUNT, work / STAGE_NAME,
            Path.home() / 'Downloads/J81-Omarchy-A-v0.1.1/rootfs.tar.zst')


def platform_check():
    require(platform.system() == 'Darwin' and platform.machine() == 'arm64',
            'This staging command must run on your Apple Silicon Mac')


def tools_check():
    zstd = shutil.which('zstd') or '/opt/homebrew/bin/zstd'
    require(Path(zstd).is_file() and os.access(zstd, os.X_OK),
            'zstd is missing. Run: brew install zstd (then rerun this helper)')
    require(Path('/usr/bin/hdiutil').is_file(), 'macOS hdiutil not available')
    return zstd


def check_volume(mount):
    require(mount.is_dir() and not mount.is_symlink(), 'Case-sensitive disk image is not mounted')
    require(mount == VOLUME_MOUNT and mount.resolve() == VOLUME_MOUNT.resolve(),
            'Unexpected disk image mountpoint')
    require(mount.stat().st_dev != mount.parent.stat().st_dev,
            'The expected location is not a separate mounted disk image')
    # Probe actual case sensitivity instead of relying only on a format label.
    low = mount / '.j81_case_probe_1641'
    high = mount / '.J81_CASE_PROBE_1641'
    require(not low.exists() and not high.exists(), 'A case test file already exists')
    try:
        low.write_text('case-sensitive\n')
        require(not high.exists(), 'Disk image is not case sensitive')
    finally:
        low.unlink(missing_ok=True)


def ready_root(root):
    return all((root / name).exists() for name in REQUIRED)


def output_report(work, status):
    report = work / STAGE_NAME / 'J81-FULLROOT-STATUS.txt'
    report.parent.mkdir(exist_ok=True, parents=True)
    lines = [
        'J81 FULL OMARCHY A USERSPACE STAGE',
        'Result: ' + status,
        'Source release: Orchard Omarchy A v0.1.1',
        'Original root profile: J71b (NOT safe to boot unchanged on J81)',
        'Archive SHA256 verified: ' + ROOT_SHA,
        'Target: case-sensitive APFS disk image on the Mac',
        'J81 boot payload: NOT MODIFIED',
        'iPad internal storage: NOT ACCESSED',
        'Full-system init/switch_root: NOT ATTEMPTED',
        'J71b services and hardware gate: NOT ADAPTED',
        'Next: TEST the full-root read-only NFS mount over USB',
        'Share only this TXT report, not rootfs files or private boot files.',
    ]
    report.write_text('\n'.join(lines) + '\n')
    print('Shareable status: ' + str(report))


def stage(work):
    platform_check()
    zstd = tools_check()
    work = work.expanduser().resolve(strict=True)
    require((work / 'source/ipadair2-omarchy').is_dir(), 'J81 source/workspace missing')
    bundle, mount, stagedir, archive = expected_paths(work)
    require(archive.is_file() and not archive.is_symlink(),
            'Verified Omarchy A archive not found in your earlier Downloads folder')
    require(archive.stat().st_size == 1099445091, 'Upstream root archive length is unexpected')
    print('Verifying complete upstream Omarchy A archive (1.1 GB) ...', flush=True)
    require(digest_file(archive) == ROOT_SHA, 'Omarchy A v0.1.1 archive checksum differs')
    print('Auditing all archive members and symlinks ...', flush=True)
    audit = audit_tar(archive, zstd)
    free = shutil.disk_usage(work).free
    require(free >= 12 * 1024 ** 3, 'At least 12 GiB free disk space is required for safe staging')
    stagedir.mkdir(parents=True, exist_ok=True)
    if not bundle.exists():
        print('Creating a separate 24 GiB-maximum, sparse, CASE-SENSITIVE APFS image ...', flush=True)
        do(['/usr/bin/hdiutil', 'create', '-size', '24g', '-fs', 'Case-sensitive APFS',
            '-volname', VOLUME, '-type', 'SPARSEBUNDLE', str(bundle)])
    require(bundle.is_dir() and not bundle.is_symlink(), 'Disk image path is not a sparse bundle')
    if not mount.exists() or mount.stat().st_dev == mount.parent.stat().st_dev:
        print('Mounting case-sensitive disk image ...', flush=True)
        do(['/usr/bin/hdiutil', 'attach', '-nobrowse', '-owners', 'on',
            '-mountpoint', str(mount), str(bundle)])
    # A newly formatted disk image may be owned by root when -owners on is
    # selected. Give the Mac user control of the IMAGE ROOT only; the Linux
    # rootfs subtree is separately extracted as root with numeric ownership.
    if not os.access(mount, os.W_OK):
        print('Allowing your Mac account to manage the dedicated disk-image root ...', flush=True)
        do(['sudo', '/usr/sbin/chown', str(os.getuid()) + ':' + str(os.getgid()), str(mount)])
    check_volume(mount)
    sentinel = mount / SENTINEL
    if not sentinel.exists():
        sentinel.write_text(SENTINEL_VALUE)
    require(not sentinel.is_symlink() and sentinel.read_text() == SENTINEL_VALUE,
            'Disk image does not have this staging tool identity')
    root = mount / 'rootfs'
    partial = mount / 'rootfs.partial'
    if root.exists():
        require(root.is_dir() and not root.is_symlink() and ready_root(root),
                'An incomplete rootfs directory already exists; no changes made')
        print('Existing complete Omarchy A root filesystem detected; no files overwritten.')
    else:
        if partial.exists() or partial.is_symlink():
            require(partial.is_dir() and not partial.is_symlink(),
                    'Incomplete root is not a normal directory; no changes made')
            require(partial.stat().st_dev == mount.stat().st_dev,
                    'Incomplete root is not contained in our dedicated APFS image')
            require(not os.path.ismount(partial),
                    'Incomplete root is unexpectedly a mountpoint; no changes made')
            require(sys.stdin.isatty(), 'A failed v1.1 rootfs.partial exists. Use interactive Terminal for guarded cleanup')
            print('Found incomplete v1.1 extraction inside the dedicated J81 sparse image.', flush=True)
            print('ONLY that rootfs.partial directory will be deleted and re-extracted.', flush=True)
            print('The Omarchy archive, working iPad boot payload and Mac home files stay untouched.', flush=True)
            consent = input('Type RESET PARTIAL to delete the incomplete rootfs.partial and retry: ')
            require(consent == 'RESET PARTIAL', 'Cleanup cancelled; incomplete extraction preserved')
            do(['sudo', sys.executable, str(Path(__file__).resolve()),
                '--cleanup-partial-as-root', '--mount', str(mount)])
            require(not partial.exists() and not partial.is_symlink(),
                    'The previous partial extraction could not be removed')
        print('Extracting full Arch/Omarchy userspace with Linux numeric ownership ...', flush=True)
        do(['sudo', sys.executable, str(Path(__file__).resolve()), '--extract-as-root',
            '--archive', str(archive), '--mount', str(mount), '--zstd', zstd])
    require(ready_root(root), 'Missing required files after extraction')
    status = {
        'format': 1,
        'stage': 'FULL_ARCH_OMARCHY_A_USERSPACE_READY_ON_MAC_NOT_BOOTED',
        'archive_sha256': ROOT_SHA,
        'upstream_release': 'v0.1.1',
        'upstream_profile': 'j71b',
        'mac_root_path': str(root),
        'image_name': IMAGE_NAME,
        'rootfs_verified_required': sorted(REQUIRED),
        'archive_audit': audit,
        'j81_kernel_untouched': True,
        'internal_storage_unmodified': True,
        'full_desktop_hardware_tested': False,
    }
    (stagedir / 'fullroot-stage.json').write_text(json.dumps(status, indent=2) + '\n')
    output_report(work, 'PASS (FULL USERSPACE STAGED ON MAC; NOT BOOTED)')
    print('PASS: full Omarchy A rootfs staged on the Mac:', root)
    print('Next: run Test-Full-Root-USB.command while the experimental J81 Linux kernel is running.')


def cleanup_partial_as_root(args):
    """Remove only a v1.1 incomplete root on an identified, dedicated image."""
    platform_check()
    require(os.geteuid() == 0, 'Root privileges required for restricted cleanup')
    mount = args.mount
    require(mount == VOLUME_MOUNT and mount.is_dir() and not mount.is_symlink(),
            'Unexpected privileged cleanup mountpoint')
    require(mount.stat().st_dev != mount.parent.stat().st_dev,
            'Cleanup target is not a separate mounted APFS disk image')
    require((mount / SENTINEL).is_file() and not (mount / SENTINEL).is_symlink()
            and (mount / SENTINEL).read_text() == SENTINEL_VALUE,
            'Missing verified J81 fullroot staging identity')
    partial = mount / 'rootfs.partial'
    require(not (mount / 'rootfs').exists(),
            'A completed rootfs exists; refuse partial cleanup')
    require(partial.is_dir() and not partial.is_symlink() and not os.path.ismount(partial),
            'Incomplete extraction is not a plain directory')
    require(partial.stat().st_dev == mount.stat().st_dev,
            'Incomplete extraction is on another filesystem')
    # Refuse to traverse a newly mounted child filesystem, even if it was
    # attached after the original extraction. Symlinks are never followed.
    for base, dirs, _files in os.walk(partial, followlinks=False):
        for entry in [Path(base)] + [Path(base) / name for name in dirs]:
            if entry.is_symlink():
                continue
            require(entry.stat().st_dev == mount.stat().st_dev,
                    'A nested filesystem is mounted inside rootfs.partial; no deletion')
    shutil.rmtree(partial)
    print('Removed only incomplete rootfs.partial from the dedicated J81 image.')


def extract_as_root(args):
    platform_check()
    require(os.geteuid() == 0, 'Root privileges required to preserve Linux UID/GID and file modes')
    mount, archive = args.mount, args.archive
    require(mount == VOLUME_MOUNT and archive.is_file(), 'Unexpected privileged extraction path')
    require(mount.is_dir() and mount.stat().st_dev != mount.parent.stat().st_dev,
            'Dedicated APFS image is not mounted')
    require((mount / SENTINEL).read_text() == SENTINEL_VALUE, 'Missing expected stage identity')
    dest = mount / 'rootfs.partial'
    require(not dest.exists() and not (mount / 'rootfs').exists(), 'Target already exists; no overwrite')
    require(digest_file(archive) == ROOT_SHA, 'Archive changed before privileged extraction')
    dest.mkdir(mode=0o755)
    extract_tar(archive, args.zstd, dest)
    require(ready_root(dest), 'Full desktop userland incomplete after extraction')
    os.replace(dest, mount / 'rootfs')
    print('Privileged rootfs extraction complete. No other filesystem modified.')


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--work', type=Path, default=Path.home() / 'Downloads/J81-Omarchy-A-Netroot-Work-v1')
    ap.add_argument('--extract-as-root', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--cleanup-partial-as-root', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--archive', type=Path, help=argparse.SUPPRESS)
    ap.add_argument('--mount', type=Path, help=argparse.SUPPRESS)
    ap.add_argument('--zstd', help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        if args.extract_as_root and args.cleanup_partial_as_root:
            raise StageError('Select only one privileged operation')
        if args.cleanup_partial_as_root:
            require(args.mount is not None, 'Missing cleanup mountpoint')
            cleanup_partial_as_root(args)
        elif args.extract_as_root:
            require(args.archive is not None and args.mount is not None and args.zstd, 'Missing internal extraction argument')
            extract_as_root(args)
        else:
            stage(args.work)
    except (StageError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print('\nSTOP: ' + str(exc), file=sys.stderr)
        print('No iPad operation was performed by this tool.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

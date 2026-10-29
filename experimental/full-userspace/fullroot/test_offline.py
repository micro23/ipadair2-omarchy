#!/usr/bin/env python3
"""Linux-host executable safety tests of archive conversion/extraction; no Mac/iPad."""
from pathlib import Path
import io
import importlib.util
import os
import subprocess
import sys
import tarfile
import tempfile

spec = importlib.util.spec_from_file_location('fullstage',Path(__file__).with_name('full_root_stage.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def item(name, data=b'', kind=tarfile.REGTYPE, link=None, mode=None):
    m=tarfile.TarInfo(name)
    m.type=kind
    m.uid=0
    m.gid=0
    m.mode=mode if mode is not None else (0o755 if kind==tarfile.DIRTYPE else 0o644)
    if kind==tarfile.REGTYPE:
        m.size=len(data)
    if link is not None:
        m.linkname=link
    return m, io.BytesIO(data) if kind==tarfile.REGTYPE else None


def make_tar(path, extra=(), omissions=()):
    names=sorted(s.REQUIRED-set(omissions))
    with tarfile.open(path,'w') as t:
        for name in names:
            m,b=item(name,(name+'\n').encode(),mode=0o755 if '/bin/' in name or name.endswith('systemd') else 0o644)
            t.addfile(m,b)
        for m,b in extra:
            t.addfile(m,b)


def zstd(src,dst):
    with dst.open('wb') as o:
        subprocess.run(['zstd','-q','-c',str(src)],check=True,stdout=o)


def assert_raises(f,like):
    try:
        f()
    except Exception as e:
        assert like in str(e), (like, str(e))
    else:
        raise AssertionError('expected failure containing '+like)


def main():
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)
        good=root/'good.tar'
        compressed=root/'good.tar.zst'
        extra=[item('lib',kind=tarfile.SYMTYPE,link='/usr/lib'),
               item('etc/os-release',kind=tarfile.SYMTYPE,link='../usr/lib/os-release'),
               item('usr/lib/os-release',b'ID=arch\n'),
               item('etc/relative',kind=tarfile.SYMTYPE,link='../../../../usr/lib/os-release')]
        make_tar(good,extra)
        zstd(good,compressed)
        audit=s.audit_tar(compressed,'zstd')
        assert audit['members']==len(s.REQUIRED)+len(extra)
        assert audit['guest_absolute_symlinks_rewritten_on_extraction']==1
        print('PASS: verified upstream-shape root archive audit')
        dst=root/'extracted';dst.mkdir()
        s.extract_tar(compressed,'zstd',dst)
        assert (dst/'lib').is_symlink()
        assert os.readlink(dst/'lib')=='usr/lib'
        assert (dst/'etc/os-release').resolve()==(dst/'usr/lib/os-release').resolve()
        assert (dst/'etc/relative').resolve()==(dst/'usr/lib/os-release').resolve()
        assert (dst/'etc/os-release').read_text()=='ID=arch\n'
        print('PASS: absolute guest symlink converted to safe in-root relative link')
        print('PASS: relative symlink with excessive upward traversal clamped to guest root')
        # Arch package archives can contain literal backslashes in POSIX
        # filenames. They are not path separators on Linux or macOS.
        raw=root/'literal-backslash.tar'
        archive=root/'literal-backslash.tar.zst'
        escaped_name='usr/share/j81\\literal.txt'
        make_tar(raw,[item('lib',kind=tarfile.SYMTYPE,link='/usr/lib'),
                      item(escaped_name,b'legal POSIX name\n'),
                      item('usr/share/j81-backslash-link',kind=tarfile.SYMTYPE,
                           link='j81\\literal.txt')])
        zstd(raw,archive)
        s.audit_tar(archive,'zstd')
        backslash_dst=root/'literal-extracted';backslash_dst.mkdir()
        s.extract_tar(archive,'zstd',backslash_dst)
        assert (backslash_dst/escaped_name).read_bytes()==b'legal POSIX name\n'
        assert (backslash_dst/'usr/share/j81-backslash-link').read_bytes()==b'legal POSIX name\n'
        print('PASS: POSIX literal-backslash filename and symlink accepted safely')
        # CPython tarfile.extractall reapplies the filter when it restores
        # directory mode, uid/gid and mtime. That is not a duplicate entry.
        raw = root / 'directory-fixup.tar'
        archive = root / 'directory-fixup.tar.zst'
        make_tar(raw, [item('lib', kind=tarfile.SYMTYPE, link='/usr/lib'),
                       item('var', kind=tarfile.DIRTYPE, mode=0o755),
                       item('var/tmp', kind=tarfile.DIRTYPE, mode=0o1777),
                       item('var/tmp/test', b'CPYTHON_DIR_FIXUP_OK\n')])
        zstd(raw, archive)
        s.audit_tar(archive, 'zstd')
        directory_dst = root / 'directory-extracted'
        directory_dst.mkdir()
        s.extract_tar(archive, 'zstd', directory_dst)
        assert (directory_dst / 'var/tmp/test').read_bytes() == b'CPYTHON_DIR_FIXUP_OK\n'
        assert (directory_dst / 'var/tmp').stat().st_mode & 0o7777 == 0o1777
        print('PASS: real directory fixup revalidates same TarInfo without duplicate error')
        # Actual duplicate directories are still a hard failure in both the
        # archive-wide audit and streaming extraction.
        raw = root / 'bad-duplicate-directory.tar'
        archive = root / 'bad-duplicate-directory.tar.zst'
        make_tar(raw, [item('lib', kind=tarfile.SYMTYPE, link='/usr/lib'),
                       item('var/tmp', kind=tarfile.DIRTYPE),
                       item('var/tmp', kind=tarfile.DIRTYPE)])
        zstd(raw, archive)
        assert_raises(lambda: s.audit_tar(archive, 'zstd'), 'Duplicate')
        rejected_dir = root / 'rejected-directory'
        rejected_dir.mkdir()
        assert_raises(lambda: s.extract_tar(archive, 'zstd', rejected_dir), 'duplicate')
        print('PASS: actual duplicate directory entries still rejected')
        assert_raises(lambda:s.normalize_name(''), 'empty name')
        print('PASS: empty member pathname still rejected')
        for name,error in [('/host-escape','absolute'),('../escape','traverses')]:
            raw=root/(name.replace('/','_')+'.tar'); archive=root/(raw.name+'.zst')
            make_tar(raw,[item(name,b'invalid')]);zstd(raw,archive)
            assert_raises(lambda:s.audit_tar(archive,'zstd'),error)
        print('PASS: absolute and parent traversal archive members rejected')
        raw=root/'special.tar'; archive=root/'special.tar.zst'
        make_tar(raw,[item('dev/test-block',kind=tarfile.BLKTYPE)]);zstd(raw,archive)
        assert_raises(lambda:s.audit_tar(archive,'zstd'),'special')
        print('PASS: special device files rejected')
        raw=root/'missing.tar';archive=root/'missing.tar.zst'
        make_tar(raw,omissions={'usr/bin/quickshell'});zstd(raw,archive)
        assert_raises(lambda:s.audit_tar(archive,'zstd'),'missing')
        print('PASS: incomplete GUI userspace rejected')
        raw=root/'duplicate.tar';archive=root/'duplicate.tar.zst'
        make_tar(raw,[item('usr/bin/labwc',b'duplicate')]);zstd(raw,archive)
        assert_raises(lambda:s.audit_tar(archive,'zstd'),'Duplicate')
        print('PASS: duplicate archive path rejected')
        # Test that the USB remote shell text has no pivot root or installation commands.
        spec=importlib.util.spec_from_file_location('fulltest',Path(__file__).with_name('test_full_root_usb.py'))
        t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
        code=t.build_test_script()
        for banned in ('chroot ', 'switch_root', 'pivot_root', 'sfdisk','mkfs','dd if=', 'rm -rf'):
            assert banned not in code,banned
        for word in ('mount -t nfs','-o ro,vers=3','umount "$ROOT"','J81_FULLROOT_READONLY_NFS_PASS'):
            assert word in code,word
        print('PASS: remote command is read-only NFS mount/probe/unmount, not full root launch')
        spec = t.export_spec(t.VOLUME_ROOT)
        assert spec == '/Volumes/J81_OMARCHY_A_V011/rootfs -ro -maproot=root 172.16.42.1\n'
        assert '-mapall=' not in spec and '-alldirs' not in spec
        print('PASS: read-only export restricts one USB client and maps root without collapsing tablet UID')
        assert 'J81_STAGE_NFS_MOUNTED' in code and 'J81_STAGE_NFS_UNMOUNTED' in code
        assert 'J81_ERROR_READ_TABLET_SHELL' in code and 'J81_CAUSE_NFS_ACCESS_DENIED' in code
        assert 'J81_ERROR_NFS_MOUNT' in t.static_markers('noise\nJ81_ERROR_NFS_MOUNT\n')
        assert t.static_markers('J81_SECRET_SERIAL=private\nJ81_STAGE_NFS_MOUNTED\n') == ['J81_STAGE_NFS_MOUNTED']
        print('PASS: diagnostic stages distinguish NFS, permissions, and unmount without private output')
    print('ALL 14 OFFLINE STAGING TESTS PASSED')

if __name__=='__main__': main()

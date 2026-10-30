"""Prepare a deferred-ASP installer payload; no hardware access or writes."""
from pathlib import Path,PurePosixPath
import gzip,hashlib,json,os,shutil,stat,subprocess,tarfile
from newc_archive import unpack,pack,add
from orchard_cli.ram import verify_ram

TASK=Path(__file__).resolve().parent
ROOT=TASK.parents[1]
BASE=TASK/'image-module-compat/out'

def main(native=False):
    os.umask(0o077)
    meta=json.loads((BASE/'linux.bin.json').read_text());image=(BASE/'linux.bin').read_bytes()
    if hashlib.sha256(image).hexdigest()!='0dd9b7cc685689789fecd010d04864984bf3a3d22678082acf89ff0a9757bacd':
        raise RuntimeError('Expected exact hardware-tested matching-module payload')
    raw=gzip.decompress((BASE/'initramfs.cpio.gz').read_bytes());entries,tail=unpack(raw)
    assert pack(entries,tail)==raw
    original={e[0]:(list(e[1]),e[3]) for e in entries}
    init=next(e for e in entries if e[0]=='init')
    old_tail='while :; do\n    setsid -c sh -i </dev/ttyGS0 >/dev/ttyGS0 2>&1 || true\n    sleep 1\ndone\n'
    source=init[3].decode()
    if source.count(old_tail)!=1:raise RuntimeError('Diagnostic PID 1 loop differs')
    source=source.replace(old_tail,(TASK/'installer-handoff-loop.sh').read_text())
    old_dhcp='udhcpd -S /run/udhcpd.conf 2>/dev/null || true'
    old_http='httpd -p 8080 -h /run 2>/dev/null || true'
    if source.count(old_dhcp)!=1 or source.count(old_http)!=1:raise RuntimeError('USB helper launch differs')
    source=source.replace(old_dhcp,'udhcpd -f -S /run/udhcpd.conf 2>/dev/null &\ndhcp_pid=$!')
    source=source.replace(old_http,'httpd -f -p 8080 -h /run 2>/dev/null &\nhttp_pid=$!')
    source=source.replace('echo "Storage inspection only: no internal filesystem is mounted."',
                          'echo "J81: checking the installed local system."' if native else 'echo "J81 installer: storage is deferred until the approved installer starts."')
    if native:
        # This exact J81's BCM4350 probe stalled before USB on the first
        # automatic native boot. It is not needed to mount local storage.
        # Leave its ordinary modalias event to installed systemd/udev, after
        # the recovery USB gadget and native root are available.
        coldplug_case='case "$a" in *apple,t7001-ans*|*apple,s5l8960x-ans*) continue;; esac'
        if source.count(coldplug_case)!=1:raise RuntimeError('Expected deferred ASP coldplug guard')
        source=source.replace(coldplug_case,'case "$a" in pci:v000014E4d000043A3*|*apple,t7001-ans*|*apple,s5l8960x-ans*) continue;; esac')
        source=source.replace('coldplug\necho "ANS1', 'echo "J81 native bootstrap: Wi-Fi deferred until installed systemd; preparing USB."\ncoldplug\necho "ANS1',1)
        marker='mkdir -p /run/j81\nwhile :; do'
        if source.count(marker)!=1:raise RuntimeError('Expected one installer wait loop')
        autostart='''mkdir -p /run/j81
echo 'J81: USB configured; mounting the installed internal ext4 root.'
if /sbin/j81-native-mount >/run/j81/native-mount.log 2>&1 && /sbin/j81-native-handoff --check >/run/j81/handoff-check.log 2>&1; then
    kill "$dhcp_pid" "$http_pid" 2>/dev/null || true
    wait "$dhcp_pid" "$http_pid" 2>/dev/null || true
    exec /sbin/j81-native-handoff --handoff
fi
echo 'J81 native root unavailable or refused; diagnostic shell remains available.'
while :; do'''
        source=source.replace(marker,autostart)
    init[3]=source.encode()
    def put(name,data,mode=0o100755):
        for parent in reversed(PurePosixPath(name).parents):
            if str(parent)=='.':continue
            if not any(e[0]==str(parent) for e in entries):add(entries,str(parent),b'',0o40755)
        add(entries,name,data,mode)
    tool_manifest=json.loads((TASK/'native-install-tools/manifest.json').read_text())
    tool_archive=TASK/'native-install-tools/tools.tar.gz'
    if hashlib.sha256(tool_archive.read_bytes()).hexdigest()!=tool_manifest['tar_sha256']:raise RuntimeError('Native tool archive changed')
    with tarfile.open(tool_archive) as tar:
        for member in tar:
            if not member.isfile() or member.name.startswith('/') or '..' in member.name.split('/'):
                raise RuntimeError('Unexpected native-tool archive member')
            data=tar.extractfile(member).read()
            expected=tool_manifest['files']['/'+member.name]
            if hashlib.sha256(data).hexdigest()!=expected['sha256']:raise RuntimeError('Native tool hash changed')
            put(member.name,data,stat.S_IFREG|member.mode)
    private_plan=json.loads((TASK/'private-live/preserved-boot-plan/private-plan.json').read_text())
    config={'ROOT_DEVICE':private_plan['linux_root_device'],'ROOT_UUID':private_plan['root_uuid'],
            'KERNEL_RELEASE':'7.3.0-rc1-orchard-j81-storage-ro-v2mod',
            'FIRST_LBA':private_plan['linux_first_lba'],'LBA_COUNT':private_plan['linux_lba_count'],
            'GPT_PRIMARY_SHA256':private_plan['file_sha256']['new-primary.bin'],
            'GPT_BACKUP_SHA256':private_plan['file_sha256']['new-backup.bin'],
            'ASP_MODULE_SHA256':'3e36f4b045a38ba4eeb46cce3a24a9d19955568b5831cd37e4124b5d6d6961f9'}
    put('etc/j81-native-root.conf',''.join(f'{k}={v}\n' for k,v in config.items()).encode(),0o100600)
    handoff_bytes=(TASK/'native_root_handoff.sh').read_bytes()
    put('sbin/j81-native-handoff',handoff_bytes)
    if native:put('sbin/j81-native-mount',(TASK/'native_root_mount.sh').read_bytes())
    # The driver and every preexisting member other than init remain exact.
    changed=[e[0] for e in entries if e[0] in original and (e[1],e[3])!=original[e[0]]]
    if changed!=['init']:raise RuntimeError('Unexpected existing archive change: '+repr(changed))
    new_raw=pack(entries,tail)
    prefix='image-native-bootstrap' if native else 'image-installer-bootstrap'
    receipt_name='NATIVE-BOOTSTRAP-BUILD-VERIFIED.json' if native else 'INSTALLER-BOOTSTRAP-BUILD-VERIFIED.json'
    init_name='native-candidate-init.sh' if native else 'installer-candidate-init.sh'
    OUT=TASK/prefix/('out-'+hashlib.sha256(new_raw).hexdigest()[:12])
    if OUT.exists():
        verify_ram(OUT)
        if gzip.decompress((OUT/'initramfs.cpio.gz').read_bytes())!=new_raw:raise RuntimeError('Existing immutable bootstrap archive differs')
        receipt=json.loads((OUT/'build.json').read_text())
        (TASK/receipt_name).write_text(json.dumps(receipt,indent=2)+'\n')
        (TASK/init_name).write_text(source)
        print('PASS: reused verified immutable installer bootstrap.');return
    OUT.mkdir(parents=True,exist_ok=False)
    with (OUT/'initramfs.cpio.gz').open('wb') as f,gzip.GzipFile(fileobj=f,mode='wb',mtime=0,filename='') as z:z.write(new_raw)
    boot=next(c for c in meta['components'] if c['name']=='bootargs')
    profile=TASK/'installer-bootstrap-profile.json'
    profile.write_text(json.dumps({'bootargs':image[boot['offset']:boot['offset']+boot['bytes']].decode()}))
    subprocess.run([str(ROOT/'work/orchard-integration/orchard-air2/.venv/bin/python'),'-B',str(ROOT/'work/orchard-integration/hardware-review/boot/assemble.py'),'--manifest',str(profile),'--loader',str(ROOT/'work/orchard-integration/prebuilt-loader.bin'),'--dtb',str(TASK/'kernel-ro-v2mod/j81.dtb'),'--kernel',str(TASK/'kernel-ro-v2mod/Image.gz'),'--initramfs',str(OUT/'initramfs.cpio.gz'),'--output',str(OUT/'linux.bin')],check=True)
    new=json.loads((OUT/'linux.bin.json').read_text())
    for name in ['loader','bootargs','dtb','kernel']:
        assert next(c for c in meta['components'] if c['name']==name)==next(c for c in new['components'] if c['name']==name),name
    shutil.copyfile(BASE/'pongo.bin',OUT/'pongo.bin')
    receipt={'kind':'orchard.ram-build','device':'j81','kernel_release':config['KERNEL_RELEASE'],
             'artifact_dir':OUT.relative_to(TASK).as_posix(),
             'hardware_tested':False,'kernel_loader_dtb_bootargs_unchanged':True,
             'storage_driver_auto_loaded':native,'storage_writes_enabled_by_boot':native,
             'root_mode':'native-internal-ext4' if native else 'deferred-installer',
             'native_tools_included':True,'only_changed_preexisting_archive_member':'init',
             'native_root_handoff_device_tested':False,
             'init_sha256':hashlib.sha256(source.encode()).hexdigest(),
             'native_root_handoff_sha256':hashlib.sha256(handoff_bytes).hexdigest(),
             'native_root_policy_sha256':hashlib.sha256(''.join(f'{k}={v}\n' for k,v in config.items()).encode()).hexdigest(),
             'files':{n:hashlib.sha256((OUT/n).read_bytes()).hexdigest() for n in ['linux.bin','pongo.bin']}}
    (OUT/'build.json').write_text(json.dumps(receipt,indent=2)+'\n');verify_ram(OUT)
    (TASK/receipt_name).write_text(json.dumps(receipt,indent=2)+'\n')
    (TASK/init_name).write_text(source)
    print('PASS: '+('post-install native-root' if native else 'deferred-ASP installer')+' payload assembled; native root handoff is not hardware tested.')

if __name__=='__main__':main()

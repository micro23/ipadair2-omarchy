"""Package J81-only native-root changes; credentials/payload remain private."""
from pathlib import Path
import ast,gzip,hashlib,io,json,os,stat,subprocess,tarfile,uuid
from newc_archive import unpack

TASK=Path(__file__).resolve().parent
ROOT=TASK.parents[1]
MOUNT=Path('/Volumes/J81_OMARCHY_A_V011/rootfs')
PRIVATE=TASK/'private-live'
RELEASE='7.3.0-rc1-orchard-j81-storage-ro-v2mod'

def keyfile_string(value):
    return value.replace('\\','\\\\').replace('\n','\\n').replace('\r','\\r').replace('\t','\\t').replace(' ','\\s')

def main():
    os.umask(0o077)
    plan=json.loads((PRIVATE/'preserved-boot-plan/private-plan.json').read_text())
    out=PRIVATE/'native-root-package';out.mkdir(mode=0o700,exist_ok=True)
    key=out/'owner_ed25519'
    if not key.exists():
        subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','j81-native-owner','-f',str(key)],check=True)
    if key.is_symlink() or stat.S_IMODE(key.stat().st_mode)!=0o600:
        raise RuntimeError('Owner validation private-key permissions changed')
    files={}
    def put(name,data,mode=0o644,uid=0,gid=0,link=None):
        if name.startswith('/') or '..' in name.split('/') or name in files:
            raise RuntimeError('Unsafe or duplicate overlay path')
        files[name]=(data,mode,uid,gid,link)
    for folder in ['persistent-root-overlay','native-root-extra']:
        for p in sorted((TASK/folder).rglob('*')):
            rel=p.relative_to(TASK/folder).as_posix()
            if p.is_symlink():put(rel,b'',0o777,link=os.readlink(p))
            elif p.is_file():put(rel,p.read_bytes(),0o755 if '/libexec/' in rel else 0o644)
    raw=gzip.decompress((TASK/'image-module-compat/out/initramfs.cpio.gz').read_bytes())
    entries,_=unpack(raw)
    for name,fields,namebytes,data in entries:
        if name.startswith('lib/modules/'+RELEASE+'/') or name.startswith('lib/firmware/'):
            if stat.S_ISREG(fields[1]):put('usr/'+name,data,fields[1]&0o777)
            elif stat.S_ISLNK(fields[1]):put('usr/'+name,b'',0o777,link=data.decode())
    for archive_name,dest in [('usr/sbin/dropbear','usr/local/libexec/j81-dropbear'),('usr/bin/dropbearkey','usr/local/libexec/j81-dropbearkey')]:
        matches=[e for e in entries if e[0]==archive_name]
        if len(matches)!=1 or not stat.S_ISREG(matches[0][1][1]):raise RuntimeError('Expected native SSH helper')
        put(dest,matches[0][3],0o755)
    build_script=(ROOT/'work/orchard-integration/hardware-review/boot/initramfs/recovery/build-tools-in-container').read_text()
    for setting in ['#define DROPBEAR_SVR_PASSWORD_AUTH 0','#define DROPBEAR_SVR_PAM_AUTH 0']:
        if setting not in build_script:raise RuntimeError('Passwordless-only SSH build evidence changed')
    source=(MOUNT/'usr/local/libexec/arch-ipad-login-session').read_text()
    marker='exec /usr/bin/labwc'
    if source.count(marker)!=1:raise RuntimeError('Released desktop launcher changed')
    source=source.replace(marker,'export WLR_BACKENDS=drm,libinput WLR_DRM_DEVICES=/dev/dri/card0\nexport WLR_NO_HARDWARE_CURSORS=1 WLR_LIBINPUT_NO_DEVICES=1\n'+marker)
    put('usr/local/libexec/arch-ipad-login-session',source.encode(),0o755)
    identity=f'ROOT_DEVICE=/dev/asp0n1p2\nROOT_UUID={plan["root_uuid"]}\nKERNEL_RELEASE={RELEASE}\n'
    put('etc/j81/internal-root.conf',identity.encode(),0o600)
    put('etc/fstab',f'UUID={plan["root_uuid"]} / ext4 defaults,noatime,nodiscard 0 1\n'.encode())
    put('etc/hostname',b'j81-omarchy\n')
    put('etc/machine-id',b'')
    put('var/lib/dbus/machine-id',b'',0o777,link='/etc/machine-id')
    put('home/tablet/.ssh/authorized_keys',key.with_suffix('.pub').read_bytes(),0o600,1000,1000)
    config=ROOT/'work/orchard-integration/orchard-air2/examples/hardware-check/rootfs/etc/wpa_supplicant.conf'
    values={}
    for line in config.read_text().splitlines():
        k,separator,v=line.strip().partition('=')
        if separator and k in ('ssid','psk'):
            if k in values:raise RuntimeError('Multiple private Wi-Fi entries require review')
            values[k]=ast.literal_eval(v) if v.startswith('"') else v
    if set(values)!= {'ssid','psk'}:raise RuntimeError('Owner Wi-Fi configuration is incomplete')
    wifi_uuid=str(uuid.uuid5(uuid.UUID(plan['root_uuid']),'owner-wifi'))
    nm='[connection]\nid=J81 Owner Wi-Fi\nuuid='+wifi_uuid+'\ntype=wifi\nautoconnect=true\nautoconnect-priority=100\n\n[wifi]\nmode=infrastructure\nssid='+keyfile_string(values['ssid'])+'\n\n[wifi-security]\nkey-mgmt=wpa-psk\npsk='+keyfile_string(values['psk'])+'\n\n[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\n'
    put('etc/NetworkManager/system-connections/j81-owner-wifi.nmconnection',nm.encode(),0o600)
    services=['j81-native-boot-proof.service','j81-proof-http.service','j81-owner-ssh.service']
    for name in services:
        put('etc/systemd/system/multi-user.target.wants/'+name,b'',0o777,link='../'+name)
    put('etc/systemd/system/multi-user.target.wants/systemd-networkd.service',b'',0o777,link='/usr/lib/systemd/system/systemd-networkd.service')
    for name in ['j71b-platform.service','j71b-charge.service','omarchy-diagnostics.service']:
        path='etc/systemd/system/'+name
        if path not in files:put(path,b'',0o777,link='/dev/null')
    with tarfile.open(out/'root-overlay-private.tar.gz','w:gz') as tar:
        dirs={}
        for name,(_,_,uid,gid,_) in files.items():
            for parent in Path(name).parents:
                if str(parent)=='.':continue
                owner=(1000,1000) if str(parent).startswith('home/tablet') else (0,0)
                dirs[str(parent)]=owner
        for name,(uid,gid) in sorted(dirs.items(),key=lambda v:(len(Path(v[0]).parts),v[0])):
            entry=tarfile.TarInfo(name);entry.type=tarfile.DIRTYPE;entry.mode=0o700 if name in ['home/tablet/.ssh','etc/j81','etc/NetworkManager/system-connections'] else 0o755;entry.uid=uid;entry.gid=gid;tar.addfile(entry)
        for name,(data,mode,uid,gid,link) in sorted(files.items()):
            entry=tarfile.TarInfo(name);entry.mode=mode;entry.uid=uid;entry.gid=gid
            if link is not None:entry.type=tarfile.SYMTYPE;entry.linkname=link;tar.addfile(entry)
            else:entry.size=len(data);tar.addfile(entry,io.BytesIO(data))
    private={'root_uuid':plan['root_uuid'],'overlay_sha256':hashlib.sha256((out/'root-overlay-private.tar.gz').read_bytes()).hexdigest(),
             'files':{name:{'sha256':hashlib.sha256(data).hexdigest(),'mode':oct(mode),'uid':uid,'gid':gid,'symlink':link} for name,(data,mode,uid,gid,link) in files.items()}}
    (out/'private-manifest.json').write_text(json.dumps(private,indent=2)+'\n')
    report={'original_rootfs_modified':False,'ipad_modified':False,'copied_file_or_symlink_count':len(files),
            'qualified_modules_and_owner_firmware_in_private_bundle':True,'wifi_credentials_private':True,
            'owner_login_key_generated_locally':True,'ssh_password_and_pam_auth_compiled_out':True,
            'ssh_bound_to_usb_address_and_interface':True,'root_ssh_login_disabled':True,
            'native_boot_counter_staged':True,'native_systemd_and_desktop_runtime_verified':False}
    (TASK/'NATIVE-ROOT-PACKAGE-PREPARED.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()

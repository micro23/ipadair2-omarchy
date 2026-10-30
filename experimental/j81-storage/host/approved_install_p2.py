"""Install the original full Omarchy release into the approved native J81 p2.

No Apple resize/GPT operation is implemented here. Default invocation prints
the proposal. Execution requires a separate exact human installation approval
and refuses to reuse an existing install attempt. Not hardware qualified yet.
"""
from pathlib import Path
import argparse,hashlib,http.server,json,os,secrets,shlex,socket,threading,time
from orchard_cli.apple.usb import devices
from orchard_cli.serial import SerialPort
from apfs_capacity_readonly import checked,u32,u64
from storage_policy_v2 import CRASH

TASK=Path(__file__).resolve().parent
PRIVATE=TASK/'private-live'
ARCHIVE=Path('/Users/micro/ChatGPT-Projects/iPad-Air2-Omarchy/Current/J81-Omarchy-A-v0.1.1/rootfs.tar.zst')
ARCHIVE_SHA='a5850a1575f52edab451783c3e4fdc2ac8cf727d5740c135c3929ff732da255c'
RELEASE='7.3.0-rc1-orchard-j81-storage-ro-v2mod'
MODULE_SHA='3e36f4b045a38ba4eeb46cce3a24a9d19955568b5831cd37e4124b5d6d6961f9'

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()

def approval_scope(plan,overlay_hash,bootstrap_init_hash):
    return {'scope':'j81-native-p2-install-preserve-apple','approved':True,
            'root_device':'/dev/asp0n1p2','first_lba':4194816,'lba_count':11429888,
            'root_uuid':plan['root_uuid'],'rootfs_sha256':ARCHIVE_SHA,
            'gpt_primary_sha256':plan['file_sha256']['new-primary.bin'],
            'gpt_backup_sha256':plan['file_sha256']['new-backup.bin'],
            'private_overlay_sha256':overlay_hash,'bootstrap_init_sha256':bootstrap_init_hash,
            'apfs_and_gpt_must_already_match_reviewed_plan':True,
            'format_and_extract_native_p2':True,'handoff_to_global_systemd':True}

def validate_approval(plan,permission,overlay_hash,bootstrap_init_hash):
    required=approval_scope(plan,overlay_hash,bootstrap_init_hash)
    if not isinstance(permission,dict) or any((permission.get(k) is not v) if type(v) is bool else permission.get(k)!=v for k,v in required.items()):
        raise RuntimeError('Exact human approval for native p2 installation is absent or stale')
    if (plan.get('linux_root_device'),plan.get('linux_first_lba'),plan.get('linux_lba_count'),plan.get('apfs_target_bytes'))!=('/dev/asp0n1p2',4194816,11429888,17179869184):
        raise RuntimeError('Native partition proposal changed')

class USBArtifacts:
    def __init__(self,artifacts):
        with socket.create_connection(('10.71.0.1',8080),timeout=5) as s:
            if s.getsockname()[0]!='10.71.0.2':raise RuntimeError('Expected dedicated USB host address')
        self.routes={'/'+secrets.token_hex(24):(name,path) for name,path in artifacts.items()}
        self.urls={};self.sent={name:0 for name in artifacts};self.stop=threading.Event()
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                if self.client_address[0]!='10.71.0.1' or self.path not in owner.routes:
                    self.send_error(404);return
                label,path=owner.routes[self.path]
                self.send_response(200);self.send_header('Content-Length',str(path.stat().st_size));self.end_headers()
                try:
                    with path.open('rb') as f:
                        for block in iter(lambda:f.read(65536),b''):
                            self.wfile.write(block);owner.sent[label]+=len(block)
                except (BrokenPipeError,ConnectionResetError):pass
        self.server=http.server.HTTPServer(('10.71.0.2',0),Handler)
        for route,(name,path) in self.routes.items():self.urls[name]=f'http://10.71.0.2:{self.server.server_port}{route}'
    def __enter__(self):
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True);self.worker.start()
        def progress():
            while not self.stop.wait(15):
                sent=sum(self.sent.values())
                if sent:print('USB artifact bytes sent:',sent,flush=True)
        self.monitor=threading.Thread(target=progress,daemon=True);self.monitor.start()
        return self
    def __exit__(self,*args):
        self.stop.set();self.server.shutdown();self.server.server_close()
        self.worker.join(timeout=5);self.monitor.join(timeout=5)

def main(execute=False,resume=False):
    os.umask(0o077)
    plan=json.loads((PRIVATE/'preserved-boot-plan/private-plan.json').read_text())
    package=PRIVATE/'native-root-package'
    overlay=package/'root-overlay-private.tar.gz'
    overlay_meta=json.loads((package/'private-manifest.json').read_text())
    if overlay_meta['root_uuid']!=plan['root_uuid']:raise RuntimeError('Native root package belongs to a different layout proposal')
    bootstrap=json.loads((TASK/'INSTALLER-BOOTSTRAP-BUILD-VERIFIED.json').read_text())
    init_hash=bootstrap['init_sha256']
    if not execute:
        print(json.dumps({'mode':'PLAN ONLY','native_root':'/dev/asp0n1p2','linux_bytes':plan['linux_bytes'],
                          'retained_apple_bytes':plan['apfs_target_bytes'],'requires_separate_install_approval':True,
                          'apple_resize_or_gpt_change_performed':False,'format_performed':False},indent=2));return
    permission_path=PRIVATE/'native-install-approval.json'
    if not permission_path.is_file():raise RuntimeError('Human native-install approval is required; no device command sent')
    validate_approval(plan,json.loads(permission_path.read_text()),overlay_meta['overlay_sha256'],init_hash)
    if digest(overlay)!=overlay_meta['overlay_sha256'] or digest(ARCHIVE)!=ARCHIVE_SHA:
        raise RuntimeError('Pinned release or private root package changed; no device command sent')
    for name in ['new-primary.bin','new-backup.bin']:
        if digest(PRIVATE/'preserved-boot-plan'/name)!=plan['file_sha256'][name]:raise RuntimeError('Reviewed GPT proposal bytes changed; no device command sent')
    selected=json.loads((PRIVATE/'selected-device.json').read_text())
    def target():
        ds=[d for d in devices() if d['location']==selected['location'] and d.get('product')=='Orchard j81_storage_ro' and d.get('serial_port')]
        if len(ds)!=1:raise RuntimeError('Expected one selected J81 installer USB endpoint')
        return ds[0]
    state=PRIVATE/'native-install-run'
    result={'format_attempted':False,'rootfs_extracted':False,'overlay_applied':False,'unit_parser_passed':False,
            'handoff_preflight_passed':False,'handoff_requested':False,'passed':False}
    if resume:
        previous=json.loads((state/'result.json').read_text())
        fix=json.loads((state/'tool-selection-fix.json').read_text())
        if (previous.get('phase')!='stopped-for-inspection' or previous.get('rootfs_extracted')
                or previous.get('tool_selection_resume_started') or fix.get('native_tools_verified') is not True
                or fix.get('no_filesystem_signature_present') is not True
                or fix.get('original_handoff_sha256')!=bootstrap['native_root_handoff_sha256']):
            raise RuntimeError('This is not the diagnosed pre-format BusyBox tool-selection stop')
        result.update(previous);result['previous_stop_reason']='BusyBox formatter option rejection'
    def save():
        with (state/'result.json').open('w') as f:
            json.dump(result,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
    with SerialPort(target()['serial_port'],target) as port:
        def run(command,timeout=30):
            rc,data=port.run('set -eu\n'+command,timeout=timeout)
            if state.exists():
                with (state/'private-command-output.log').open('a') as f:f.write(data+'\n')
            if rc:raise RuntimeError('Guest installation command failed; inspect the private command log')
            return data
        identity=run('uname -r; tr "\\000" "\\n" </proc/device-tree/compatible; sha256sum /init; test '+('' if resume else '! ')+'-d /sys/module/asp')
        lines=identity.splitlines()
        if lines[0]!=RELEASE or 'apple,j81' not in lines or 'apple,t7001' not in lines or lines[-1].split()[0]!=init_hash:
            raise RuntimeError('Expected exact installer bootstrap with ASP still deferred')
        if run('sha256sum /lib/modules/'+RELEASE+'/kernel/drivers/block/asp.ko').split()[0]!=MODULE_SHA:
            raise RuntimeError('Qualified ASP module differs')
        for path,key in [('/sbin/j81-native-handoff','native_root_handoff_sha256'),('/etc/j81-native-root.conf','native_root_policy_sha256')]:
            expected=fix['patched_handoff_sha256'] if resume and path=='/sbin/j81-native-handoff' else bootstrap[key]
            if run('sha256sum '+path).split()[0]!=expected:raise RuntimeError('Native handoff or root policy differs')
        if not resume:state.mkdir(mode=0o700,exist_ok=False)
        else:
            result['tool_selection_resume_started']=True;result.pop('error_type',None)
        save()
        try:
            print('Approved installer identity verified; '+('checking the existing' if resume else 'loading the exact')+' p2-only write window.',flush=True)
            if not resume:run('modprobe asp allow_userarea_writes=1 write_first_lba=4194816 write_lba_count=11429888',timeout=45)
            run('i=0; while [ ! -b /dev/asp0n1p2 ] || [ ! -e /sys/class/block/asp0n10/ro ]; do '
                'i=$((i+1)); [ "$i" -lt 30 ] || exit 72; sleep 1; done',timeout=35)
            status=run('cat /sys/module/asp/parameters/allow_userarea_writes; cat /sys/module/asp/parameters/write_first_lba; cat /sys/module/asp/parameters/write_lba_count; '
                       'cat /sys/class/block/asp0n1/size; cat /sys/class/block/asp0n1/queue/logical_block_size; '
                       'cat /sys/class/block/asp0n1p2/start; cat /sys/class/block/asp0n1p2/size; '
                       'for n in 2 3 4 5 6 7 8 9 10; do cat /sys/class/block/asp0n$n/ro; done; '
                       'if grep -q /dev/asp /proc/mounts; then exit 71; fi')
            if status.split()!=['Y','4194816','11429888','125000000','4096',str(4194816*8),str(11429888*8)]+['1']*9:
                raise RuntimeError('Native write window, geometry or auxiliary read-only guard differs')
            def readblocks(lba,count):
                return port.capture_exact(f'timeout 20 dd if=/dev/asp0n1 bs=4096 skip={lba} count={count} 2>/dev/null',4096*count,timeout=30)
            for name,lba in [('new-primary.bin',1),('new-backup.bin',15624995)]:
                if readblocks(lba,5)!=(PRIVATE/'preserved-boot-plan'/name).read_bytes():raise RuntimeError('Disk GPT differs from exact reviewed proposal; no format sent')
            base=readblocks(6,1)
            if not checked(base) or base[32:36]!=b'NXSB' or u32(base,36)!=4096 or u32(base,24)&0xffff!=1:raise RuntimeError('Invalid Apple container header')
            count,address=u32(base,104),u64(base,112)
            if not 1<=count<=512 or not 1<=address<4194304 or address+count>4194304:
                raise RuntimeError('Unexpected Apple checkpoint descriptor bounds')
            desc=readblocks(6+address,count)
            nx=[desc[i:i+4096] for i in range(0,len(desc),4096) if checked(desc[i:i+4096]) and desc[i+32:i+36]==b'NXSB' and u32(desc,i+24)&0xffff==1 and u32(desc,i+36)==4096 and desc[i+72:i+88]==base[72:88]]
            if not nx or u64(max(nx,key=lambda b:u64(b,16)),40)!=4194304:
                raise RuntimeError('Apple container has not shrunk to the exact approved size; no format sent')
            log=run('dmesg')
            if CRASH.search(log.encode()):raise RuntimeError('Kernel stop condition before native filesystem writes')
            result['phase']='format';result['format_attempted']=True;save()
            print('Both GPT copies and Apple shrink verified. Formatting only the approved Linux p2.',flush=True)
            run('timeout 600 /usr/bin/mke2fs -q -F -t ext4 -b 4096 -m 1 -U '+shlex.quote(plan['root_uuid'])+' -L J81_OMARCHY -E nodiscard,lazy_itable_init=0,lazy_journal_init=0 /dev/asp0n1p2',timeout=620)
            result['native_formatter_completed']=True;save()
            run('timeout 120 /usr/bin/e2fsck -fn /dev/asp0n1p2',timeout=130)
            result['filesystem_check_passed']=True;save()
            if run('/usr/bin/blkid -s UUID -o value /dev/asp0n1p2').strip()!=plan['root_uuid']:
                raise RuntimeError('Formatted Linux UUID differs; no rootfs extraction sent')
            run('mkdir -p /newroot; mount -t ext4 -o rw,noatime,nodiscard /dev/asp0n1p2 /newroot')
            result['native_root_mounted']=True
            stage='/newroot/.j81-install-'+secrets.token_hex(8);result['staging_directory']=stage;save()
            run('umask 077; mkdir '+stage)
            with USBArtifacts({'rootfs':ARCHIVE,'overlay':overlay}) as artifacts:
                for name,expected_hash in [('rootfs',ARCHIVE_SHA),('overlay',overlay_meta['overlay_sha256'])]:
                    destination=stage+'/'+name+'.tar'
                    print('Transferring and hashing',name,'over the dedicated USB network.',flush=True)
                    run('timeout 2400 wget -q -O '+destination+' '+shlex.quote(artifacts.urls[name]),timeout=2420)
                    if run('sha256sum '+destination,timeout=120).split()[0]!=expected_hash:raise RuntimeError('Guest artifact hash differs; extraction stopped')
                    result.setdefault('verified_artifacts',[]).append(name);save()
            result['rootfs_extract_attempted']=True;save()
            run('LC_ALL=C.UTF-8 timeout 1800 /usr/bin/bsdtar --numeric-owner --acls --xattrs -xpf '+stage+'/rootfs.tar -C /newroot >/run/j81/rootfs-extract.log 2>&1',timeout=1820)
            result['rootfs_extracted']=True;save()
            run('rm -f /newroot/etc/systemd/system/getty@tty1.service.d/20-j71b-platform.conf '
                '/newroot/etc/systemd/system/multi-user.target.wants/j71b-charge.service '
                '/newroot/etc/systemd/system/multi-user.target.wants/omarchy-diagnostics.service; '
                'for f in /newroot/etc/NetworkManager/system-connections/*; do [ ! -f "$f" ] || rm -f "$f"; done')
            run('LC_ALL=C.UTF-8 timeout 120 /usr/bin/bsdtar --numeric-owner --acls --xattrs -xpf '+stage+'/overlay.tar -C /newroot >/run/j81/overlay-extract.log 2>&1',timeout=130)
            result['overlay_applied']=True;save()
            run('mkdir -p /newroot/dev /newroot/proc /newroot/sys /newroot/run; '
                'mount -o bind /dev /newroot/dev; mount -o bind /proc /newroot/proc; mount -o bind /sys /newroot/sys')
            try:
                run('chroot /newroot /usr/bin/systemd-analyze verify --man=no j81-internal-root-guard.service j81-native-boot-proof.service j81-proof-http.service j81-owner-ssh.service seatd.service getty@tty1.service',timeout=90)
                result['unit_parser_passed']=True;save()
                run('test "$(stat -c %u /newroot/home/tablet)" = 1000; test "$(stat -c %a /newroot/home/tablet/.ssh/authorized_keys)" = 600; '
                    'test "$(stat -c %a /newroot/etc/NetworkManager/system-connections/j81-owner-wifi.nmconnection)" = 600; '
                    'test "$(readlink /newroot/etc/systemd/system/j71b-charge.service)" = /dev/null')
            finally:
                run('umount /newroot/sys; umount /newroot/proc; umount /newroot/dev')
            run('rm -rf '+stage+'; sync')
            run('/sbin/j81-native-handoff --check',timeout=60)
            result['handoff_preflight_passed']=True;result['phase']='ready-for-global-pid1';save()
            # Leave the actual one-shot request separate from installation so
            # its serial disconnect is observed as a transition, not a retry.
            result['passed']=True;save()
            print('Native p2 installation and handoff preflight passed. Global PID 1 handoff and desktop still require live verification.',flush=True)
        except BaseException as e:
            result['error_type']=type(e).__name__;result['phase']='stopped-for-inspection';save()
            raise

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--resume-tool-selection',action='store_true');args=parser.parse_args()
    if args.resume_tool_selection and not args.execute:parser.error('Resuming requires --execute and the original authorization')
    main(args.execute,resume=args.resume_tool_selection)

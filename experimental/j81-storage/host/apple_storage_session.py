"""Authenticated SSH over the selected iPad's USB mux; no LAN connection.

Default phase only probes the Apple framework and GPT writer's refusal before
resize. Resize/GPT phases require the recorded broad native-install approval
and a fresh one-shot operation journal; they are never retried automatically.
"""
from pathlib import Path
import argparse,base64,hashlib,json,os,secrets,shlex,socket,sys,time
import paramiko

TASK=Path(__file__).resolve().parent
PRIVATE=TASK/'private-live'
PREP=Path('/Users/micro/ChatGPT-Projects/iPad-Air2-Omarchy/Boot-Tools/J81-WiFi-Preparation-v1')
sys.path.insert(0,str(PREP/'host'))
import apple_identity as identity
from boot_flow_base import validate_normal

PREFIX='export PATH=/cores/binpack/usr/bin:/cores/binpack/bin:/usr/bin:/bin:/usr/sbin:/sbin; '

def save(path,value):
    with path.open('w') as f:
        json.dump(value,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())

class AppleSSH:
    def __init__(self,boot_directory):self.boot_directory=boot_directory
    def __enter__(self):
        expected=json.loads((TASK.parents[1]/'work/orchard-integration/private-live/attempt-001/selected-device.json').read_text())['ecid']
        info=identity.identify_normal(timeout=10)
        if info is None or validate_normal(info)!=expected:raise RuntimeError('Original normal-mode J81 identity is unavailable')
        self.os_version=info['product_version']
        deadline=time.monotonic()+15
        sock=identity._connect(identity._SOCKET_PATH,deadline)
        try:
            reply=identity._mux_request(sock,{'MessageType':'Connect','DeviceID':info['device_id'],'PortNumber':socket.htons(44)},1,deadline)
            if reply.get('Number')!=0:raise RuntimeError('Apple USB SSH service is not ready')
            self.transport=paramiko.Transport(sock);self.transport.start_client(timeout=15)
            key=self.transport.get_remote_server_key()
            hostkey={'type':key.get_name(),'base64':base64.b64encode(key.asbytes()).decode()}
            pin=self.boot_directory/'usb-ssh-hostkey.json'
            if pin.exists() and json.loads(pin.read_text())!=hostkey:raise RuntimeError('USB SSH host key changed within this boot attempt')
            if not pin.exists():save(pin,hostkey)
            # One documented factory credential, only for this owner-verified
            # USB device. Never try the Mac or Wi-Fi password, or guess others.
            self.transport.auth_password('root','alpine',fallback=False)
            if not self.transport.is_authenticated():raise RuntimeError('Root authentication is unavailable')
            rc,data=self.run('id -u; uname -m')
            (self.boot_directory/'private-identity-check.log').write_bytes(data)
            if rc or data.decode().split()!=['0','iPad5,3']:raise RuntimeError('Authenticated shell is not root on the expected iPad')
            return self
        except BaseException:
            if hasattr(self,'transport'):self.transport.close()
            sock.close();raise
    def __exit__(self,*args):self.transport.close()
    def run(self,command,stdin=None,timeout=60):
        channel=self.transport.open_session(timeout=15)
        try:
            channel.exec_command(PREFIX+command)
            if stdin is not None:channel.sendall(stdin)
            channel.shutdown_write()
            deadline=time.monotonic()+timeout;out=bytearray();err=bytearray()
            while True:
                if time.monotonic()>deadline:raise TimeoutError('Apple-side command outcome unknown; inspect before any retry')
                if channel.recv_ready():out.extend(channel.recv(65536))
                if channel.recv_stderr_ready():err.extend(channel.recv_stderr(65536))
                if len(out)+len(err)>8*1024*1024:raise RuntimeError('Unexpectedly large Apple command output')
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():break
                time.sleep(0.05)
            return channel.recv_exit_status(),bytes(out)+bytes(err)
        finally:channel.close()
    def upload(self,path,data,executable=False):
        rc,out=self.run('umask 077; cat > '+shlex.quote(path)+'; chmod '+('700' if executable else '600')+' '+shlex.quote(path),stdin=data)
        if rc:raise RuntimeError('Private Apple helper staging failed')
        rc,copy=self.run('cat '+shlex.quote(path))
        if rc or hashlib.sha256(copy).digest()!=hashlib.sha256(data).digest():raise RuntimeError('Apple helper read-back differs')

def authorize(phase):
    permission=json.loads((PRIVATE/'apple-probe-approval.json').read_text())
    if permission.get('approved') is not True or permission.get('scope')!='rootless-ipados-apple-probe-only':raise RuntimeError('Apple preparation approval missing')
    if phase!='probe':
        approval=json.loads((PRIVATE/'native-install-scope-authorization.json').read_text())
        fields={'approved':True,'scope':'native-omarchy-installation-proposed-preserved-apple-layout',
                'apfs_target_bytes':17179869184,'linux_root_device':'/dev/asp0n1p2',
                'linux_first_lba':4194816,'linux_lba_count':11429888,
                'preserve_apple_boot_support':True,'preserve_auxiliary_namespaces':True}
        if any((approval.get(k) is not v) if type(v) is bool else approval.get(k)!=v for k,v in fields.items()):
            raise RuntimeError('Exact native-install scope approval missing')

def main(phase='probe'):
    os.umask(0o077);authorize(phase)
    active=PRIVATE/'apple-active-boot.json'
    name=json.loads(active.read_text())['directory'] if active.exists() else 'apple-probe-boot'
    if not isinstance(name,str) or '/' in name or name in ('.','..'):raise RuntimeError('Invalid active boot reference')
    boot_directory=PRIVATE/name
    boot=json.loads((boot_directory/'result.json').read_text())
    if boot.get('rootless_boot_attempted') is not True or boot.get('tool_exit_code')!=0:
        raise RuntimeError('Rootless boot has not completed successfully; no SSH command sent')
    tools=TASK/'apple-tools';receipt=json.loads((tools/'build-receipt.json').read_text())
    for name in ['gptcas-ios','resize_apfs-ios']:
        if hashlib.sha256((tools/name).read_bytes()).hexdigest()!=receipt['sha256'][name]:raise RuntimeError('Signed Apple tool changed')
    plan=PRIVATE/'preserved-boot-plan';manifest=json.loads((plan/'private-plan.json').read_text())
    for name,sha in manifest['file_sha256'].items():
        if hashlib.sha256((plan/name).read_bytes()).hexdigest()!=sha:raise RuntimeError('Private layout proposal changed')
    state=PRIVATE/('apple-storage-'+phase)
    state.mkdir(mode=0o700,exist_ok=False)
    result={'phase':phase,'operation_sent':False,'resize_sent':False,'gpt_write_sent':False,'passed':False}
    save(state/'result.json',result)
    with AppleSSH(boot_directory) as ssh:
        stage='/private/var/tmp/j81-storage-'+secrets.token_hex(8)
        rc,out=ssh.run('umask 077; mkdir '+stage)
        if rc:raise RuntimeError('Could not create private Apple staging directory')
        for name in ['gptcas-ios','resize_apfs-ios']:
            ssh.upload(stage+'/'+name,(tools/name).read_bytes(),True)
        for name in manifest['file_sha256']:
            ssh.upload(stage+'/'+name,(plan/name).read_bytes())
        result['ios_version']=ssh.os_version
        rc,out=ssh.run(stage+'/resize_apfs-ios --probe')
        (state/'private-framework-probe.log').write_bytes(out)
        if rc:raise RuntimeError('Apple APFS framework probe failed; inspect private log')
        rc,out=ssh.run(stage+'/gptcas-ios --dry-run /dev/rdisk0 '+stage)
        (state/'private-gpt-dry-run.log').write_bytes(out)
        if phase=='probe':
            if not ((rc==3 and b"doesn't fit" in out) or rc==0):raise RuntimeError('GPT identity/geometry checks refused; no resize sent')
            result['framework_probe_passed']=True
            result['gpt_current_identity_checked']=True
            result['pre_resize_fit_refusal']=rc==3
        elif phase=='resize':
            if rc==0:
                result['already_fits']=True
            elif rc==3 and b"doesn't fit" in out:
                result['operation_sent']=True;result['resize_sent']=True;save(state/'result.json',result)
                print('Sending the authorized Apple APFS resize to 16 GiB. Keep USB connected.',flush=True)
                rc,out=ssh.run(stage+'/resize_apfs-ios --execute-approved-j81-shrink disk0s1 17179869184 J81-16GiB-APFS',timeout=1800)
                (state/'private-resize.log').write_bytes(out)
                if rc:raise RuntimeError('Apple resize did not report success; no GPT update sent')
                rc,out=ssh.run(stage+'/gptcas-ios --dry-run /dev/rdisk0 '+stage)
                (state/'private-after-resize-dry-run.log').write_bytes(out)
                if rc:raise RuntimeError('Post-resize container/GPT guard refused; no GPT update sent')
            else:raise RuntimeError('Pre-resize identity/geometry check refused')
        elif phase=='gpt':
            if rc:raise RuntimeError('Container does not fit proposed GPT; no partition write sent')
            result['operation_sent']=True;result['gpt_write_sent']=True;save(state/'result.json',result)
            rc,out=ssh.run(stage+'/gptcas-ios /dev/rdisk0 '+stage,timeout=120)
            (state/'private-gpt-write.log').write_bytes(out)
            if rc:raise RuntimeError('GPT update not verified; inspect both copies before any retry')
        result['passed']=True;save(state/'result.json',result)
        print(json.dumps(result,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--phase',choices=['probe','resize','gpt'],default='probe')
    main(p.parse_args().phase)

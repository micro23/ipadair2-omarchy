"""Patch only the RAM handoff helper after the diagnosed BusyBox argument stop."""
from pathlib import Path
import base64,hashlib,json,os,shlex
from orchard_cli.apple.usb import devices
from orchard_cli.serial import SerialPort

TASK=Path(__file__).resolve().parent;PRIVATE=TASK/'private-live'

def main():
    os.umask(0o077)
    state=PRIVATE/'native-install-run';result=json.loads((state/'result.json').read_text())
    log=(state/'private-command-output.log').read_text()
    if result.get('rootfs_extracted') or result.get('native_formatter_completed') or "mke2fs: invalid option -- 't'" not in log:
        raise RuntimeError('Not the specific rejected BusyBox formatter invocation')
    selected=json.loads((PRIVATE/'selected-device.json').read_text())
    boot=json.loads((TASK/'INSTALLER-BOOTSTRAP-BUILD-VERIFIED.json').read_text())
    manifest=json.loads((TASK/'native-install-tools/manifest.json').read_text())
    def target():
        ds=[d for d in devices() if d['location']==selected['location'] and d.get('product')=='Orchard j81_storage_ro' and d.get('serial_port')]
        if len(ds)!=1:raise RuntimeError('Expected selected installer USB')
        return ds[0]
    with SerialPort(target()['serial_port'],target) as port:
        def run(command):
            rc,data=port.run('set -eu\n'+command,timeout=25)
            if rc:raise RuntimeError('RAM-only tool correction preflight failed')
            return data
        old=run('sha256sum /sbin/j81-native-handoff').split()[0]
        if old!=boot['native_root_handoff_sha256']:raise RuntimeError('Original RAM handoff helper changed')
        for name in ['mke2fs','e2fsck','blkid']:
            if run('sha256sum /usr/bin/'+name).split()[0]!=manifest['files']['/usr/bin/'+name]['sha256']:
                raise RuntimeError('Native tool bytes changed')
        rc,fs=port.run('/usr/bin/blkid -p -s TYPE -o value /dev/asp0n1p2')
        if rc not in (0,2) or fs.strip():raise RuntimeError('A filesystem may already exist; inspect instead of resuming')
        before=port.capture_exact('timeout 10 dd if=/dev/asp0n1p2 bs=4096 count=1 2>/dev/null',4096,timeout=15)
        (state/'p2-before-native-format-private.bin').write_bytes(before)
        data=(TASK/'native_root_handoff.sh').read_bytes();encoded=base64.b64encode(data).decode()
        run('umask 077; : > /run/j81/handoff-fixed.b64')
        for start in range(0,len(encoded),512):run('printf %s '+shlex.quote(encoded[start:start+512])+' >> /run/j81/handoff-fixed.b64')
        run('base64 -d /run/j81/handoff-fixed.b64 > /run/j81/handoff-fixed; /bin/sh -n /run/j81/handoff-fixed')
        new=hashlib.sha256(data).hexdigest()
        if run('sha256sum /run/j81/handoff-fixed').split()[0]!=new:raise RuntimeError('RAM helper hash differs')
        run('cp /sbin/j81-native-handoff /run/j81/handoff-before-tool-fix; cp /run/j81/handoff-fixed /sbin/j81-native-handoff; chmod 755 /sbin/j81-native-handoff')
        if run('sha256sum /sbin/j81-native-handoff').split()[0]!=new:raise RuntimeError('Installed RAM helper hash differs')
        record={'original_handoff_sha256':old,'patched_handoff_sha256':new,'native_tools_verified':True,
                'no_filesystem_signature_present':True,'internal_storage_written_by_correction':False,
                'reason':'BusyBox standalone shell selected its applet for unqualified mke2fs; use absolute native tool paths'}
        (state/'tool-selection-fix.json').write_text(json.dumps(record,indent=2)+'\n')
        print('Native binaries verified; corrected the RAM-only handoff helper. No disk write was sent by this correction.')

if __name__=='__main__':main()

"""Request one native global-PID1 handoff and observe its read-only USB proof."""
from pathlib import Path
import json,os,time,urllib.request,urllib.error
from orchard_cli.apple.usb import devices
from orchard_cli.serial import SerialPort

TASK=Path(__file__).resolve().parent;PRIVATE=TASK/'private-live'

def main():
    os.umask(0o077)
    install=json.loads((PRIVATE/'native-install-run/result.json').read_text())
    if not all(install.get(k) is True for k in ['passed','rootfs_extracted','overlay_applied','unit_parser_passed','handoff_preflight_passed']):
        raise RuntimeError('Native installation and preflight are not complete')
    selected=json.loads((PRIVATE/'selected-device.json').read_text())
    def target():
        ds=[d for d in devices() if d['location']==selected['location'] and d.get('product')=='Orchard j81_storage_ro' and d.get('serial_port')]
        if len(ds)!=1:raise RuntimeError('Expected selected installer endpoint')
        return ds[0]
    state=PRIVATE/'native-first-handoff';state.mkdir(mode=0o700,exist_ok=False)
    result={'request_attempted':False,'request_scheduled':False,'native_proof_received':False,'passed':False}
    def save():(state/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    save()
    with SerialPort(target()['serial_port'],target) as port:
        rc,data=port.run('/sbin/j81-native-handoff --check; code=$?; echo J81_CHECK_CODE=$code; exit $code',timeout=60)
        (state/'private-final-preflight.log').write_text(data)
        if rc or 'J81_CHECK_CODE=0' not in data:raise RuntimeError('Final native handoff preflight refused')
        result['request_attempted']=True;save()
        try:
            rc,data=port.run("(trap '' HUP; sleep 2; touch /run/j81/handoff.ready) </dev/null >/run/j81/handoff-request.log 2>&1 & echo J81_HANDOFF_SCHEDULED",timeout=10)
            if rc==0 and 'J81_HANDOFF_SCHEDULED' in data:result['request_scheduled']=True
        except Exception as e:result['request_reply_error_type']=type(e).__name__
        save()
    install['handoff_requested']=True
    (PRIVATE/'native-install-run/result.json').write_text(json.dumps(install,indent=2)+'\n')
    print('Native handoff requested once. Waiting for actual global systemd/ext4 proof over USB.',flush=True)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        try:
            with opener.open('http://10.71.0.1:8080/proof.json',timeout=3) as response:
                raw=response.read(16385)
            if len(raw)>16384:raise RuntimeError('Oversized native boot proof')
            proof=json.loads(raw)
            if (proof.get('global_pid1')!='systemd' or proof.get('filesystem')!='ext4'
                    or proof.get('root_device')!='/dev/asp0n1p2' or proof.get('root_identity_guard_passed') is not True
                    or proof.get('nfs_or_overlay_root') is not False or type(proof.get('persistent_boot_count')) is not int
                    or proof['persistent_boot_count']<1):raise RuntimeError('Native boot proof does not establish the required root')
            (state/'private-native-boot-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
            result['native_proof_received']=True;result['passed']=True;result['persistent_boot_count']=proof['persistent_boot_count'];save()
            print('PASS: real PID1 is systemd, root is internal ext4 p2, identity guard passed, boot count '+str(proof['persistent_boot_count'])+'.',flush=True)
            return
        except (urllib.error.URLError,TimeoutError,ConnectionError,json.JSONDecodeError):pass
        time.sleep(1)
    save();raise RuntimeError('Native proof has not appeared; inspect the current screen/services without repeating handoff')

if __name__=='__main__':main()

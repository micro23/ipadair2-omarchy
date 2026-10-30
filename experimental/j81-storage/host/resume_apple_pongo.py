"""Resume the authorized rootless boot from a verified existing Pongo endpoint."""
from pathlib import Path
import hashlib,json,os,select,signal,subprocess,sys,tempfile,time
from orchard_cli.apple.usb import devices

TASK=Path(__file__).resolve().parent
PRIVATE=TASK/'private-live'
PREP=Path('/Users/micro/ChatGPT-Projects/iPad-Air2-Omarchy/Boot-Tools/J81-WiFi-Preparation-v1')
sys.path.insert(0,str(PREP/'host'))
import boot_flow_base as legacy

def main():
    os.umask(0o077)
    if json.loads((PRIVATE/'apple-probe-approval.json').read_text()).get('approved') is not True:raise RuntimeError('Preparation is not approved')
    expected=json.loads((TASK.parents[1]/'work/orchard-integration/private-live/attempt-001/selected-device.json').read_text())['ecid']
    found=devices()
    if len(found)!=1 or found[0]['mode']!='pongo' or (found[0]['chip'],found[0]['board'],found[0]['ecid'])!=(0x7001,6,expected):
        raise RuntimeError('Original J81 is not at the existing Pongo endpoint')
    tool=PREP/'runtime/bin/palera1n-macos-arm64'
    if hashlib.sha256(tool.read_bytes()).hexdigest()!=legacy.PALERA1N_SHA256:raise RuntimeError('Verified tool changed')
    state=PRIVATE/'apple-probe-resume-pongo-001';state.mkdir(mode=0o700,exist_ok=False)
    result={'rootless_boot_attempted':True,'started_from_verified_pongo':True,'resize_attempted':False,'gpt_write_attempted':False}
    process=None
    try:
        with tempfile.TemporaryDirectory(prefix='j81-ios-resume-',dir='/private/tmp') as tmp:
            env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':str(Path.home()),'TMPDIR':tmp,'LC_ALL':'C','TERM':'dumb'}
            process=subprocess.Popen([str(tool),'--rootless','--no-colors'],stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE,stderr=subprocess.STDOUT,cwd=tmp,env=env,start_new_session=True)
            result['host_pid']=process.pid
            (state/'result.json').write_text(json.dumps(result,indent=2)+'\n')
            deadline=time.monotonic()+150;pending=''
            with (state/'private-boot.log').open('wb') as log:
                while process.poll() is None:
                    if time.monotonic()>deadline:raise TimeoutError('Pongo resume did not complete; inspect before any new attempt')
                    if select.select([process.stdout],[],[],0.2)[0]:
                        data=os.read(process.stdout.fileno(),65536)
                        if not data:break
                        log.write(data);log.flush();pending+=data.decode(errors='replace').replace('\r','\n')
                        while '\n' in pending:
                            line,pending=pending.split('\n',1)
                            public=legacy.public_log_line(line)
                            if public:print(public,flush=True)
                            if 'Entering recovery mode' in line or 'Press Enter when ready for DFU' in line:
                                raise RuntimeError('Resume unexpectedly requested a new DFU cycle; stopped')
                result['tool_exit_code']=process.wait(timeout=5)
                if result['tool_exit_code']!=0:raise RuntimeError('Pongo resume tool stopped')
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                try:info=legacy.identify_normal(timeout=5)
                except legacy.IdentificationError:info=None
                if info is not None:
                    if legacy.validate_normal(info)!=expected:raise RuntimeError('Returned iPad identity differs')
                    result['ios_normal_identity_verified']=True;break
                time.sleep(2)
            if not result.get('ios_normal_identity_verified'):raise RuntimeError('Normal iPadOS has not reappeared; shell not verified')
            (PRIVATE/'apple-active-boot.json').write_text(json.dumps({'directory':state.name})+'\n')
            print('Original iPadOS identity returned. Next check is authenticated USB SSH.',flush=True)
    except BaseException as e:
        result['error_type']=type(e).__name__;raise
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid,signal.SIGINT)
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=5)
        (state/'result.json').write_text(json.dumps(result,indent=2)+'\n')

if __name__=='__main__':main()

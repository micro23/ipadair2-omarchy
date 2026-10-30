"""One guided J81 boot of the prepared installer or installed-native payload."""
from pathlib import Path
import argparse,contextlib,hashlib,json,os,shutil,signal,sys,tempfile,threading,time,types
from explicit_identity import read_identity
from orchard_cli.apple import usb as apple_usb
from orchard_cli.boot import boot_ram
from orchard_cli.ram import verify_ram

TASK=Path(__file__).resolve().parent
BASE=TASK.parents[1]/'work/orchard-integration'
PRIVATE=TASK/'private-live'
PREP=Path('/Users/micro/ChatGPT-Projects/iPad-Air2-Omarchy/Boot-Tools/J81-WiFi-Preparation-v1')
sys.path.insert(0,str(PREP/'host'))
import boot_flow_base as old

def main(mode='installer',attempt='001'):
    os.umask(0o077)
    if not sys.stdin.isatty():raise RuntimeError('Open this guide in Mac Terminal')
    permission=json.loads((PRIVATE/'native-install-scope-authorization.json').read_text())
    if permission.get('approved') is not True or permission.get('scope')!='native-omarchy-installation-proposed-preserved-apple-layout':raise RuntimeError('Native installation scope not approved')
    if json.loads((PRIVATE/'apple-post-gpt-reboot/result.json').read_text()).get('passed') is not True:
        raise RuntimeError('Apple post-GPT reboot must be verified first')
    if mode=='native' and json.loads((PRIVATE/'native-install-run/result.json').read_text()).get('passed') is not True:
        raise RuntimeError('Native installation and preflight must pass before automatic native boot')
    record_name='INSTALLER-BOOTSTRAP-BUILD-VERIFIED.json' if mode=='installer' else 'NATIVE-BOOTSTRAP-BUILD-VERIFIED.json'
    receipt=json.loads((TASK/record_name).read_text());out=TASK/receipt['artifact_dir'];verify_ram(out)
    if receipt['root_mode']!=('deferred-installer' if mode=='installer' else 'native-internal-ext4'):raise RuntimeError('Wrong bootstrap kind')
    expected=json.loads((BASE/'private-live/attempt-001/selected-device.json').read_text())['ecid']
    if attempt=='next':
        # Allocate a new log directory, never retry a device operation.
        for number in range(1,1000):
            state=PRIVATE/('native-'+mode+'-boot-'+str(number).zfill(3))
            try:state.mkdir(mode=0o700,exist_ok=False);break
            except FileExistsError:continue
        else:raise RuntimeError('No unused boot attempt directory')
    else:
        if len(attempt)!=3 or not attempt.isascii() or not attempt.isdecimal():raise RuntimeError('Expected three-digit attempt number or next')
        state=PRIVATE/('native-'+mode+'-boot-'+attempt);state.mkdir(mode=0o700,exist_ok=False)
    result={'mode':mode,'phase':'waiting-for-owner','linux_upload_sent':False,'driver_auto_loaded_by_image':mode=='native','linux_usb_ready':False}
    def save():(state/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    def log(line):
        print(line,flush=True)
        with (state/'private-progress.log').open('a') as f:f.write(line+'\n')
        if any(x in line for x in ['Device reconnected in DFU mode, starting over','Sanity check transfer failed','Unable to perform checkm8:']):
            raise RuntimeError('Exploit stopped; no automatic retry')
    def event(e):
        result['phase']=e['phase'];save()
        if e['phase']=='dfu_ready':
            input('\nPut one finger on Home and one on top Power. Press RETURN when ready for the countdown: ')
            if not flow.continue_dfu():raise RuntimeError('DFU prompt expired')
        elif e['phase']=='reconnect':print('\a\n>>> RECONNECT LIGHTNING NOW — unplug and reconnect ONCE. <<<\n',flush=True)
        elif e['phase'] in ['dfu_countdown','dfu','pongo_loading','pongo_wait']:print(e['message']+' — '+e.get('detail',''),flush=True)
    save();print('\nJ81 NATIVE '+mode.upper()+' BOOT\n')
    print('The iPad should be in normal iPadOS. No preliminary restart is needed if it is already there.')
    if mode=='native':
        print('If the previous Linux boot stopped without USB: hold Home + top Power until the Apple logo appears, then release both. Wait for normal iPadOS and unlock it.')
    print('This guide boots the prepared Linux payload once. Keep the cable ready for its cue.')
    input('Press RETURN when normal iPadOS is ready and USB is connected: ')
    normal=old.identify_normal(timeout=10)
    if normal is None or old.validate_normal(normal)!=expected:raise RuntimeError('Original J81 normal iPadOS identity required')
    for name,sha in [('runtime/bin/palera1n-macos-arm64',old.PALERA1N_SHA256),('runtime/wheels/pyusb-1.3.1-py3-none-any.whl',old.PYUSB_SHA256)]:
        if hashlib.sha256((PREP/name).read_bytes()).hexdigest()!=sha:raise RuntimeError('Verified boot runtime differs')
    lib=PREP/'runtime/libusb/libusb-1.0.dylib'
    inventory=json.loads((PREP/'bundle-manifest.json').read_text())['files']
    if hashlib.sha256(lib.read_bytes()).hexdigest()!=inventory['runtime/libusb/libusb-1.0.dylib']['sha256']:raise RuntimeError('USB library differs')
    sys.path.insert(0,str(PREP/'runtime/wheels/pyusb-1.3.1-py3-none-any.whl'))
    import usb.core,usb.util,usb.backend.libusb1
    backend=usb.backend.libusb1.get_backend(find_library=lambda _:str(lib))
    if backend is None:raise RuntimeError('Verified USB library could not load')
    flow=old.BootFlow(PREP,state,log,event=event)
    flow._core=usb.core;flow._util=usb.util;flow._backend=backend;flow._expected_ecid=expected
    flow._identity=types.MethodType(lambda self,d,expected=None,pongo=False:read_identity(self,old,d,expected=expected,pongo=pongo),flow)
    def interrupted(*args):flow.cancel.set();raise KeyboardInterrupt('Guide interrupted; inspect current device state')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGHUP,interrupted)
    with tempfile.TemporaryDirectory(prefix='j81-internal-',dir='/private/tmp') as tmp:
        runtime=Path(tmp);shutil.copyfile(out/'pongo.bin',runtime/'Pongo.bin')
        flow.state_dir=runtime;flow.bundle=runtime
        rc=flow._run_palera1n('dfu')
        if rc:raise RuntimeError('DFU helper stopped')
        d,device_identity=flow._one_boot_device({old.DFU},expected=expected,seconds=10);flow._dispose(d)
        result['phase']='starting-pongo';save()
        outcome={}
        def launch():
            try:outcome['rc']=flow._run_palera1n('pongo')
            except BaseException as e:outcome['error']=e
        thread=threading.Thread(target=launch);thread.start();deadline=time.monotonic()+100;endpoint=False
        try:
            while time.monotonic()<deadline:
                endpoints=apple_usb.devices()
                if len(endpoints)==1 and (endpoints[0]['mode'],endpoints[0]['chip'],endpoints[0]['board'],endpoints[0]['ecid'])==('pongo',0x7001,6,expected):
                    endpoint=True;time.sleep(1)
                    if flow._process is not None and flow._process.poll() is None:
                        os.killpg(flow._process.pid,signal.SIGINT)
                        result['released_host_after_pongo_enumeration']=True
                    break
                if not thread.is_alive() and ('error' in outcome or outcome.get('rc')!=0):break
                time.sleep(0.25)
            thread.join(timeout=10)
            if thread.is_alive():raise RuntimeError('Pongo host process did not stop cleanly')
            if 'error' in outcome:raise outcome['error']
            if not endpoint:raise RuntimeError('Original Pongo endpoint did not appear; no payload sent')
        finally:
            if thread.is_alive():flow.cancel.set();flow._stop_process(flow._process);thread.join(timeout=10)
        result['pongo_tool_exit_code']=outcome.get('rc');save()
        d,device_identity=flow._one_boot_device({old.PONGO},expected=expected,pongo=True,seconds=15);flow._dispose(d)
    selected=apple_usb.sole_target()
    if (selected['mode'],selected['chip'],selected['board'],selected['ecid'])!=('pongo',0x7001,6,expected):raise RuntimeError('Pongo identity changed before upload')
    (PRIVATE/'selected-device.json').write_text(json.dumps(selected,indent=2)+'\n')
    os.environ['ORCHARD_HOME']=str(BASE/'private-state')
    print('\nPongo verified. Sending the prepared '+mode+' Linux payload once.\n',flush=True)
    result['phase']='linux-upload';save()
    with (state/'private-upload.log').open('w') as f,contextlib.redirect_stdout(f),contextlib.redirect_stderr(f):boot_ram(out,yes=True)
    result['linux_upload_sent']=True;result['phase']='waiting-linux-usb';save()
    deadline=time.monotonic()+120
    while time.monotonic()<deadline:
        endpoints=apple_usb.devices()
        ready=[d for d in endpoints if d.get('product')=='Orchard j81_storage_ro' and d.get('serial_port') and d['location']==selected['location']]
        if len(ready)==1:
            result['linux_usb_ready']=True;result['phase']='ready-for-verification';save()
            print('\nLinux USB is ready. Leave the iPad connected; Codex will verify this boot and the native root.\n',flush=True);return
        time.sleep(1)
    raise RuntimeError('Linux USB has not appeared; leave the screen as it is for inspection')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=['installer','native'],default='installer');p.add_argument('--attempt',default='001')
    try:
        args=p.parse_args();main(args.mode,args.attempt)
    except BaseException as e:print('\nSTOP:',str(e),'\nNo automatic retry. Leave the screen as it is.',flush=True);raise SystemExit(1)

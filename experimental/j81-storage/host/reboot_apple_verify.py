"""One normal iPadOS reboot after verified GPT update; never retries reboot."""
import json,time
from apple_storage_session import AppleSSH,PRIVATE,identity,validate_normal,authorize,save,TASK

def main():
    authorize('gpt')
    for phase in ['resize','gpt']:
        if json.loads((PRIVATE/('apple-storage-'+phase)/'result.json').read_text()).get('passed') is not True:
            raise RuntimeError('Successful resize and GPT verification required before reboot')
    boot=PRIVATE/json.loads((PRIVATE/'apple-active-boot.json').read_text())['directory']
    state=PRIVATE/'apple-post-gpt-reboot';state.mkdir(mode=0o700,exist_ok=False)
    result={'reboot_command_sent':False,'usb_disconnect_observed':False,'original_ipados_returned':False,'passed':False}
    save(state/'result.json',result)
    with AppleSSH(boot) as ssh:
        rc,data=ssh.run('sync')
        if rc:raise RuntimeError('iPadOS sync failed; reboot not requested')
        result['reboot_command_sent']=True;save(state/'result.json',result)
        try:
            rc,data=ssh.run('/cores/binpack/sbin/reboot',timeout=15)
            (state/'private-reboot-output.log').write_bytes(data)
            result['reboot_reply_code']=rc
        except (EOFError,TimeoutError,OSError):result['ssh_closed_during_reboot']=True
    expected=json.loads((TASK.parents[1]/'work/orchard-integration/private-live/attempt-001/selected-device.json').read_text())['ecid']
    deadline=time.monotonic()+150
    print('Normal reboot requested once. Waiting for USB disconnect and the original iPadOS identity.',flush=True)
    while time.monotonic()<deadline:
        try:info=identity.identify_normal(timeout=3)
        except identity.IdentificationError:info=None
        if info is None:
            result['usb_disconnect_observed']=True;save(state/'result.json',result)
        else:
            if validate_normal(info)!=expected:raise RuntimeError('Returned iPad identity changed')
            if result['usb_disconnect_observed']:
                result['original_ipados_returned']=True;result['ios_version']=info['product_version'];result['passed']=True
                save(state/'result.json',result);print(json.dumps(result,indent=2));return
        time.sleep(1)
    save(state/'result.json',result)
    raise RuntimeError('Post-GPT normal reboot is not yet verified; no second reboot sent')

if __name__=='__main__':main()

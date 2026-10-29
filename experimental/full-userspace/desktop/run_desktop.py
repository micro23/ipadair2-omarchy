#!/usr/bin/env python3
"""Full-root native J81 desktop session. Temporary RAM overlay, existing J81 boot."""
import os
import argparse,hashlib,importlib.util,json,re,secrets,shlex,sys,threading,time
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PROJECT=Path(os.environ.get('J81_PROJECT_DIR',str(Path.home()/'ChatGPT-Projects/iPad-Air2-Omarchy')))
WORK=PROJECT/'Current/J81-Omarchy-A-Netroot-Work-v1'
HELPER=PROJECT/'Current/J81-Omarchy-A-FullRoot-v1.3/test_full_root_usb.py'
HELPER_SHA='63980ab8156c17c32733ad90bc2f10122ef2c6d7be695540a15dbf953eea9fd9'
REPORT=HERE/'LAST-SESSION-RESULT.json'
def need(test,reason):
 if not test:raise RuntimeError(reason)
def load_host():
 need(hashlib.sha256(HELPER.read_bytes()).hexdigest()==HELPER_SHA,'Original NFS helper changed')
 s=importlib.util.spec_from_file_location('j81_host',HELPER);h=importlib.util.module_from_spec(s);s.loader.exec_module(h);return h

def desktop(usb,seconds):
 d='/mnt/j81-full-desktop-'+secrets.token_hex(6)
 inner=(HERE/'guest-session.sh').read_text().replace('@@D@@',d)
 inner=inner.replace('timeout -s TERM 540','timeout -s TERM '+str(seconds))
 need('@@' not in inner,'Unexpanded guest template')
 c=usb.IPadShell()
 try:
  _,rc=c.run('set -eu\n[ -z "$(pidof labwc)" ]\nmkdir '+d+'; mkdir '+d+'/lower '+d+'/ram '+d+'/root',check=False)
  need(rc==0,'Another compositor is active, or staging directory unavailable')
 finally:c.close()
 state={};done=threading.Event();stop=threading.Event()
 def worker():
  c=None
  try:
   c=usb.IPadShell()
   script="cat > "+d+"/run.sh <<'J81_SCRIPT'\n"+inner+"\nJ81_SCRIPT\n"+'timeout -s KILL '+str(seconds+30)+' unshare -m -p -f --mount-proc=/proc --propagation private /bin/sh '+d+'/run.sh'
   out,rc=c.run(script,seconds=seconds+45,check=False)
   state.update(output=out,rc=rc)
  except Exception as exc:state['error']=str(exc)
  finally:
   if c:c.close()
   done.set()
 t=threading.Thread(target=worker,daemon=True);t.start()
 ready=False;logs={};interrupted=False
 try:
  deadline=time.monotonic()+seconds+40
  while not done.wait(2):
   need(time.monotonic()<deadline,'Desktop session exceeded its time bound')
   c=usb.IPadShell()
   try:
    root=d+'/root'
    probe='set -eu\np=$(pidof labwc)\n[ -n "$p" ]\n[ "$(readlink /proc/$p/root)" = '+shlex.quote(root)+' ]\nnsenter -t "$p" -m -p -- chroot '+shlex.quote(root)+' /usr/bin/setpriv --reuid=1000 --regid=1000 --init-groups --reset-env /usr/bin/env XDG_RUNTIME_DIR=/run/j81-demo WAYLAND_DISPLAY=wayland-0 OMARCHY_PATH=/home/tablet/.local/share/omarchy-ipad PATH=/usr/local/bin:/usr/bin /usr/local/bin/omarchy-shell shell ping\n[ -s /proc/$p/root/run/j81-demo/omarchy-desktop-ready.json ]\necho J81_FULL_SHELL_FRAME_READY'
    out,rc=c.run(probe,seconds=8,check=False)
    if rc==0 and 'J81_FULL_SHELL_FRAME_READY' in out and not ready:
     ready=True;print('READY: Native Omarchy shell replied and captured a compositor frame.',flush=True)
    if True:
     for name in ('ui.log','pipewire.log','wireplumber.log'):
      out,rc=c.run('p=$(pidof labwc); [ -n "$p" ] && tail -c 24000 /proc/$p/root/run/j81-demo/'+name,seconds=6,check=False)
      if rc==0:logs[name]=out
   finally:c.close()
 except KeyboardInterrupt:
  interrupted=True
 finally:
  if not done.is_set():
   c=usb.IPadShell()
   try:c.run('for p in $(pidof labwc); do [ "$(readlink /proc/$p/root)" != '+d+'/root ] || kill -TERM "$p"; done',seconds=10,check=False)
   finally:c.close()
   done.wait(20)
  need(done.is_set(),'Guest stop not confirmed; bounded supervisor remains responsible')
  c=usb.IPadShell()
  try:
   out,rc=c.run('set -eu\n! grep -F '+shlex.quote(d)+' /proc/mounts\nfor f in run.sh labwc.log seatd.log; do [ ! -f '+d+'/$f ] || rm '+d+'/$f; done\nrmdir '+d+'/lower '+d+'/ram '+d+'/root '+d+'\n[ "$(cat /sys/class/net/usb0/operstate)" = up ]\necho J81_DESKTOP_CLEANUP_OK',seconds=15,check=False)
   need(rc==0 and 'J81_DESKTOP_CLEANUP_OK' in out,'Guest cleanup not confirmed')
  finally:c.close()
  (HERE/'LAST-SUPERVISOR.log').write_text(str(state)+'\n')
  for name,content in logs.items():(HERE/('LAST-'+name)).write_text(content+'\n')
 need('error' not in state,state.get('error',''))
 need(ready,'Omarchy shell/frame readiness was not confirmed')
 need(state.get('rc')==0,'Guest supervisor failed')
 m=re.search(r'J81_LABWC_STATUS=(\d+)',state.get('output',''))
 need(m and int(m[1]) in (0,124),'Compositor exited unexpectedly')
 return {'shell_and_frame_ready':True,'guest_cleanup_verified':True,'compositor_exit':int(m[1]),'user_stopped':interrupted}

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--seconds',type=int,default=900)
 ap.add_argument('--existing-nfs',action='store_true',help='Diagnostic mode: caller owns an already-active read-only NFS share')
 args=ap.parse_args();need(30<=args.seconds<=3600,'Duration must be 30 to 3600 seconds')
 h=load_host();h.check_stage(WORK);h.check_mac_net();usb=h.git_source(WORK);h.get_live_kernel(usb)
 result={'installation':'NOT INSTALLED','kernel':h.EXPECTED_KERNEL,'internal_storage_writes':False}
 if args.existing_nfs:
  result.update(desktop(usb,args.seconds));result['nfs_cleanup']='EXTERNAL SHARE: caller must stop it';REPORT.write_text(json.dumps(result,indent=2)+'\n')
 else:
  h.confirm=lambda:True
  h.run_on_ipad=lambda module:result.update(desktop(module,args.seconds))
  def report(work,success,stage,error=None,cleanup_ok=False):
   result.update(passed=success,nfs_cleanup_verified=cleanup_ok)
   if error:result['error']=str(error)[:300]
   REPORT.write_text(json.dumps(result,indent=2)+'\n')
  h.report=report
  print('Starting native J81 Omarchy with a temporary one-client, read-only NFS share.',flush=True)
  print('Administrator authentication is required for that share. Ctrl+C stops the session.',flush=True)
  h.test(WORK)
 print('Session ended and guest cleanup verified. Report: '+str(REPORT))
if __name__=='__main__':
 try:main()
 except Exception as exc:print('STOP: '+str(exc),file=sys.stderr);raise SystemExit(1)

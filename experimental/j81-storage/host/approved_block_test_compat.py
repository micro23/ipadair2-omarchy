"""One approved 4 KiB USERAREA write/read-back/restore; no installer or format."""
import argparse,base64,hashlib,json,os,secrets,shlex,time
from pathlib import Path
from orchard_cli.apple.usb import devices
from orchard_cli.serial import SerialPort
from storage_policy_v2 import CRASH

TASK=Path(__file__).resolve().parent;PRIVATE=TASK/'private-live'
RELEASE='7.3.0-rc1-orchard-j81-storage-ro-v2mod'
MODULE_SHA256='3e36f4b045a38ba4eeb46cce3a24a9d19955568b5831cd37e4124b5d6d6961f9'
LBA=15624738;SIZE=4096;CAPACITY=64000000000
os.umask(0o077)

def main(execute=False):
 plan=json.loads((PRIVATE/'proposed-write-test-private.json').read_text())
 original=(PRIVATE/'proposed-test-block-original-4096.bin').read_bytes()
 if len(original)!=SIZE or hashlib.sha256(original).hexdigest()!=plan['original_backup_sha256'] or plan['logical_lba']!=LBA or plan['bytes']!=SIZE:raise RuntimeError('Exact original backup/approved block mismatch')
 if not execute:
  print('PLAN ONLY: one 4096-byte write/read-back/restore at USERAREA logical LBA',LBA);return
 approval=json.loads((PRIVATE/'one-block-approval.json').read_text())
 if approval.get('approved') is not True or approval.get('logical_lba')!=LBA or approval.get('bytes')!=SIZE:raise RuntimeError('Recorded one-block approval required')
 expected=json.loads((PRIVATE/'selected-device.json').read_text())
 def target():
  found=[d for d in devices() if d['location']==expected['location'] and d.get('product') in ('Orchard j81_storage_ro','Orchard j81-storage-ro') and d.get('serial_port')]
  if len(found)!=1:raise RuntimeError('Expected one diagnostic endpoint at selected port')
  return found[0]
 state=PRIVATE/'approved-block-test'
 # Create only after verifying the new running kernel below; never retry writes automatically.
 result={'logical_lba':LBA,'bytes':SIZE,'pattern_write_attempted':False,'pattern_readback_passed':False,'restore_attempted':False,'restore_verified':False}
 def save():
  with (state/'result.json').open('w') as f:json.dump(result,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
 with SerialPort(target()['serial_port'],target) as port:
  def run(command,timeout=20):
   rc,data=port.run(command,timeout=timeout)
   if rc:raise RuntimeError('Guest command failed; see local diagnostics')
   return data
  data=run('uname -r; tr "\\000" " " < /proc/device-tree/compatible; echo; test ! -d /sys/module/asp; echo asp_unloaded_rc=$?')
  if data.splitlines()[0].strip()!=RELEASE or 'apple,j81' not in data or 'asp_unloaded_rc=0' not in data:raise RuntimeError('Expected new J81 write candidate with ASP still deferred')
  module_path='/lib/modules/'+RELEASE+'/kernel/drivers/block/asp.ko'
  if run('sha256sum '+module_path).split()[0]!=MODULE_SHA256:raise RuntimeError('Experimental module hash mismatch; no write-mode module loaded')
  state.mkdir(mode=0o700)
  save()
  try:
   run(f'modprobe asp allow_userarea_writes=1 write_first_lba={LBA} write_lba_count=1',timeout=30)
   result['module_loaded']=True;save()
   data=run('''cat /sys/module/asp/parameters/allow_userarea_writes; cat /sys/module/asp/parameters/write_first_lba; cat /sys/module/asp/parameters/write_lba_count
cat /sys/class/block/asp0n1/ro; cat /sys/class/block/asp0n1/size; cat /sys/class/block/asp0n1/queue/logical_block_size
for n in 2 3 4 5 6 7 8 9 10; do cat /sys/class/block/asp0n$n/ro; done
if grep -q '/dev/asp' /proc/mounts; then exit 71; fi''')
   values=data.split()
   if values!=['Y',str(LBA),'1','0','125000000','4096']+['1']*9:raise RuntimeError('Write range, geometry, or auxiliary read-only guard mismatch')
   # Kernel's one dev_warn is expected opt-in disclosure; actual WARNING:CPU/BUG stops remain fatal.
   log=run('dmesg',timeout=15)
   (state/'before-dmesg.txt').write_text(log)
   if CRASH.search(log.encode()):raise RuntimeError('Kernel stop condition before first write')
   def readblock():return port.capture_exact(f'timeout 10 dd if=/dev/asp0n1 bs=4096 skip={LBA} count=1 2>/dev/null',SIZE,timeout=15)
   if readblock()!=original:raise RuntimeError('Chosen APFS block changed since rollback backup; no write sent')
   pattern=secrets.token_bytes(SIZE)
   if pattern==original:raise RuntimeError('Pattern generation failed')
   with (state/'pattern.bin').open('xb') as f:f.write(pattern);f.flush();os.fsync(f.fileno())
   def stage(name,data):
    path='/run/j81-write-test/'+name;encoded=base64.b64encode(data).decode()
    run('umask 077; mkdir -p /run/j81-write-test; : > '+shlex.quote(path+'.b64'))
    for offset in range(0,len(encoded),512):run('printf %s '+shlex.quote(encoded[offset:offset+512])+' >> '+shlex.quote(path+'.b64'))
    run('base64 -d '+shlex.quote(path+'.b64')+' > '+shlex.quote(path))
    if run('sha256sum '+shlex.quote(path)).split()[0]!=hashlib.sha256(data).hexdigest():raise RuntimeError('RAM staging hash mismatch')
    return path
   origpath=stage('original',original);patternpath=stage('pattern',pattern)
   # Validate the exact dd/fsync option set on RAM before any block-device write.
   run(f'dd if={patternpath} of=/run/j81-write-test/ram-check bs=4096 count=1 conv=notrunc,fsync 2>/dev/null')
   if run('sha256sum /run/j81-write-test/ram-check').split()[0]!=hashlib.sha256(pattern).hexdigest():raise RuntimeError('RAM dd/fsync check failed')
   try:
    result['pattern_write_attempted']=True;save()
    run(f'timeout 15 dd if={patternpath} of=/dev/asp0n1 bs=4096 seek={LBA} count=1 conv=notrunc,fsync 2>/dev/null',timeout=20)
    if readblock()!=pattern:raise RuntimeError('Pattern read-back mismatch')
    result['pattern_readback_passed']=True;save()
   finally:
    if result['pattern_write_attempted']:
     result['restore_attempted']=True;save()
     run(f'timeout 15 dd if={origpath} of=/dev/asp0n1 bs=4096 seek={LBA} count=1 conv=notrunc,fsync 2>/dev/null',timeout=20)
     if readblock()!=original:raise RuntimeError('Original restoration not verified; preserve current state and local backup')
     result['restore_verified']=True;save()
   log=run('dmesg',timeout=15);(state/'after-dmesg.txt').write_text(log)
   if CRASH.search(log.encode()):raise RuntimeError('Kernel stop condition after test; no further writes')
   result['passed']=True;save();print(json.dumps(result,indent=2))
  except BaseException as error:
   result['error']=type(error).__name__+': '+str(error);save()
   if port.pending:(state/'partial-serial.bin').write_bytes(bytes(port.pending))
   raise

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true');main(parser.parse_args().execute)

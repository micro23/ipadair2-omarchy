import contextlib,hashlib,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import approved_block_test_compat as test

class FakePort:
 def __init__(self,private,*,partial_failure=False,changed=False,aux_writable=False,wrong_module=False):
  self.private=private;self.original=b'\x5a'*4096;self.disk=b'\x33'*4096 if changed else self.original;self.partial_failure=partial_failure;self.aux_writable=aux_writable;self.wrong_module=wrong_module;self.commands=[];self.writes=[];self.pending=bytearray()
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def write_data(self,name):return self.original if name=='original' else (self.private/'approved-block-test/pattern.bin').read_bytes()
 def run(self,c,timeout=20):
  self.commands.append(c)
  if c.startswith('uname -r;'):return 0,test.RELEASE+'\napple,j81\nasp_unloaded_rc=0\n'
  if c.startswith('cat /sys/module/asp/parameters/'):
   v=['Y',str(test.LBA),'1','0','125000000','4096']+['1']*9
   if self.aux_writable:v[-1]='0'
   return 0,'\n'.join(v)
  if c=='dmesg':return 0,'normal driver log\n'
  if c.startswith('sha256sum /lib/modules/'):
   return 0,('0'*64 if self.wrong_module else test.MODULE_SHA256)+'  asp.ko\n'
  if c.startswith('sha256sum '):
   name=c.split()[-1].split('/')[-1];name='pattern' if name=='ram-check' else name
   return 0,hashlib.sha256(self.write_data(name)).hexdigest()+'  ramfile\n'
  if ' of=/dev/asp0n1 ' in c:
   name='original' if 'if=/run/j81-write-test/original ' in c else 'pattern'
   self.writes.append(name);self.disk=self.write_data(name)
   if self.partial_failure and name=='pattern':return 1,'simulated failure after media changed'
  return 0,''
 def capture_exact(self,*args,**kw):return self.disk

class BlockTestControl(unittest.TestCase):
 def scenario(self,**kw):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);p=Path(temp.name)
  original=b'\x5a'*4096;(p/'proposed-test-block-original-4096.bin').write_bytes(original)
  (p/'proposed-write-test-private.json').write_text(json.dumps({'original_backup_sha256':hashlib.sha256(original).hexdigest(),'logical_lba':test.LBA,'bytes':4096}))
  (p/'one-block-approval.json').write_text(json.dumps({'approved':True,'logical_lba':test.LBA,'bytes':4096}));(p/'selected-device.json').write_text('{"location":1}')
  fake=FakePort(p,**kw)
  def execute():
   with patch.object(test,'PRIVATE',p),patch.object(test,'devices',return_value=[{'location':1,'product':'Orchard j81_storage_ro','serial_port':'/dev/cu.fake'}]),patch.object(test,'SerialPort',return_value=fake),contextlib.redirect_stdout(__import__('io').StringIO()):test.main(True)
  return p,fake,execute
 def test_wrong_module_hash_prevents_module_load(self):
  p,fake,execute=self.scenario(wrong_module=True)
  with self.assertRaises(RuntimeError):execute()
  self.assertEqual(fake.writes,[])
  self.assertFalse(any(c.startswith('modprobe ') for c in fake.commands))
  self.assertFalse((p/'approved-block-test').exists())
 def test_pattern_verified_and_original_restored(self):
  p,fake,execute=self.scenario();execute();self.assertEqual(fake.writes,['pattern','original']);self.assertEqual(fake.disk,fake.original);self.assertTrue(json.loads((p/'approved-block-test/result.json').read_text())['restore_verified'])
 def test_partial_pattern_failure_still_restores(self):
  p,fake,execute=self.scenario(partial_failure=True)
  with self.assertRaises(RuntimeError):execute()
  self.assertEqual(fake.writes,['pattern','original']);self.assertEqual(fake.disk,fake.original);self.assertTrue(json.loads((p/'approved-block-test/result.json').read_text())['restore_verified'])
 def test_changed_original_blocks_all_writes(self):
  p,fake,execute=self.scenario(changed=True)
  with self.assertRaises(RuntimeError):execute()
  self.assertEqual(fake.writes,[])
 def test_writable_auxiliary_namespace_blocks_all_writes(self):
  p,fake,execute=self.scenario(aux_writable=True)
  with self.assertRaises(RuntimeError):execute()
  self.assertEqual(fake.writes,[])
if __name__=='__main__':unittest.main()

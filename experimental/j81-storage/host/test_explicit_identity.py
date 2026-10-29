from pathlib import Path
from types import SimpleNamespace
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[3]/'runtime/j81/reference/original-host'))
import boot_flow_base as legacy
from explicit_identity import read_identity
class USBError(Exception):pass
class IdentityTests(unittest.TestCase):
 def flow(self,serial):
  def get_string(device,index,*,langid):
   self.assertEqual(langid,0x0409);self.assertEqual(index,3)
   if isinstance(serial,Exception):raise serial
   return serial
  return SimpleNamespace(_util=SimpleNamespace(get_string=get_string),_core=SimpleNamespace(USBError=USBError))
 def read(self,s,**kw):return read_identity(self.flow(s),legacy,SimpleNamespace(iSerialNumber=3),expected=42,**kw)
 def test_valid_dfu(self):self.assertEqual(self.read('CPID:7001 BDID:06 ECID:2a').ecid,42)
 def test_valid_pongo(self):self.assertEqual(self.read('CPID:7001 BDID:06 ECID:2a SRTG:['+legacy.PONGO_VERSION+']',pongo=True).version,legacy.PONGO_VERSION)
 def test_wrong_chip_board_and_ecid(self):
  for s in ['CPID:7000 BDID:06 ECID:2a','CPID:7001 BDID:02 ECID:2a','CPID:7001 BDID:06 ECID:2b']:
   with self.assertRaises(legacy.BootError):self.read(s)
 def test_wrong_loader(self):
  with self.assertRaises(legacy.BootError):self.read('CPID:7001 BDID:06 ECID:2a SRTG:[other]',pongo=True)
 def test_missing_descriptor(self):
  with self.assertRaises(legacy.BootError):self.read(None)
 def test_usb_error(self):
  with self.assertRaises(legacy.BootError):self.read(USBError('unavailable'))
if __name__=='__main__':unittest.main()

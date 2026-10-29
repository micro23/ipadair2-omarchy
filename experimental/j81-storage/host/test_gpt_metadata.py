import struct,unittest,zlib
from gpt_metadata import header,partitions
N=15625000

def fixture():
 table=bytearray(128*128);table[:16]=b'\x01'*16;struct.pack_into('<QQ',table,32,6,N-7)
 h=bytearray(4096);h[:8]=b'EFI PART';struct.pack_into('<III',h,8,0x10000,92,0);struct.pack_into('<QQQQ',h,24,1,N-1,6,N-7);struct.pack_into('<QIII',h,72,2,128,128,zlib.crc32(table));recrc(h)
 return h,table

def recrc(h):struct.pack_into('<I',h,16,0);struct.pack_into('<I',h,16,zlib.crc32(h[:92]))
class GPTTests(unittest.TestCase):
 def test_valid_4096_geometry(self):
  h,t=fixture();result=partitions(t,header(h,N));self.assertEqual(len(result),1);self.assertEqual(result[0]['first_lba'],6)
 def test_header_crc(self):
  h,t=fixture();h[50]^=1
  with self.assertRaises(ValueError):header(h,N)
 def test_wrong_device_size(self):
  h,t=fixture()
  with self.assertRaises(ValueError):header(h,N+1)
 def test_unbounded_table(self):
  h,t=fixture();struct.pack_into('<I',h,80,0xffffffff);recrc(h)
  with self.assertRaises(ValueError):header(h,N)
 def test_bad_entry_crc(self):
  h,t=fixture();t[90]^=1
  with self.assertRaises(ValueError):partitions(t,header(h,N))
 def test_partition_outside_device(self):
  h,t=fixture();struct.pack_into('<QQ',t,32,6,N);struct.pack_into('<I',h,88,zlib.crc32(t));recrc(h)
  with self.assertRaises(ValueError):partitions(t,header(h,N))
 def test_overlapping_partitions(self):
  h,t=fixture();t[128:144]=b'\x02'*16;struct.pack_into('<QQ',t,160,10,20);struct.pack_into('<I',h,88,zlib.crc32(t));recrc(h)
  with self.assertRaises(ValueError):partitions(t,header(h,N))
if __name__=='__main__':unittest.main()

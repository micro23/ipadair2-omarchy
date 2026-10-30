"""Exercise the actual C writer on sparse host fixtures, never an iPad disk."""
import struct, subprocess, tempfile, unittest, uuid, zlib
from pathlib import Path
from apfs_capacity_readonly import checked, u64

TASK=Path(__file__).resolve().parent
BS=4096

def sign_apfs(block):
    a=b=0
    for word, in struct.iter_unpack('<I',block[8:]):
        a=(a+word)%0xffffffff;b=(b+a)%0xffffffff
    low=0xffffffff-(a+b)%0xffffffff;high=0xffffffff-(a+low)%0xffffffff
    struct.pack_into('<Q',block,0,(high<<32)|low)

def synthetic_plan(folder):
    """Build only invented identities and counters; no owner disk metadata."""
    folder.mkdir()
    old=bytearray(4*BS)
    struct.pack_into('<16s16sQQQ72s',old,0,
        uuid.UUID('7c3457ef-0000-11aa-aa11-00306543ecac').bytes_le,
        uuid.UUID(int=2).bytes_le,6,15624994,0,
        'synthetic-apfs'.encode('utf-16-le').ljust(72,b'\0'))
    new=bytearray(old)
    struct.pack_into('<Q',new,40,4194309)
    struct.pack_into('<16s16sQQQ72s',new,128,
        uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4').bytes_le,
        uuid.UUID(int=3).bytes_le,4194816,15624703,0,
        'synthetic-linux'.encode('utf-16-le').ljust(72,b'\0'))
    def header(entries,backup=False):
        b=bytearray(BS)
        struct.pack_into('<8sIIIIQQQQ16sQIII',b,0,b'EFI PART',0x10000,92,0,0,
            15624999 if backup else 1,1 if backup else 15624999,
            6,15624994,uuid.UUID(int=1).bytes_le,
            15624995 if backup else 2,128,128,zlib.crc32(entries))
        struct.pack_into('<I',b,16,zlib.crc32(b[:92]))
        return b
    for name,entries in [('old',old),('new',new)]:
        (folder/(name+'-primary.bin')).write_bytes(header(entries)+entries)
        (folder/(name+'-backup.bin')).write_bytes(entries+header(entries,True))
    cfg={'lba_size':4096,'disk_lbas':15625000,'primary_lba':1,'primary_count':5,
         'backup_lba':15624995,'backup_count':5,'p1_first':6,
         'p1_last_old':15624994,'p1_last_new':4194309}
    (folder/'plan.cfg').write_text(''.join(f'{key} {value}\n' for key,value in cfg.items()))
    blocks=[]
    for xid in (1,2):
        b=bytearray(BS)
        struct.pack_into('<Q',b,16,xid)
        struct.pack_into('<I',b,24,1)
        b[32:36]=b'NXSB'
        struct.pack_into('<I',b,36,BS)
        struct.pack_into('<Q',b,40,15624989)
        struct.pack_into('<I',b,0x68,1)
        struct.pack_into('<Q',b,0x70,1)
        sign_apfs(b);blocks.append(b)
    return blocks

class GPTCompareAndSwap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build=tempfile.TemporaryDirectory(prefix='j81-gptcas-build-')
        cls.binary=Path(cls.build.name)/'gptcas'
        tools=TASK/'apple-tools'
        if not tools.is_dir():tools=TASK.parent/'apple-tools'
        subprocess.run(['cc','-std=c11','-O2','-Wall','-Wextra','-Werror',
                        str(tools/'gptcas.c'),'-o',str(cls.binary)],check=True)
    @classmethod
    def tearDownClass(cls):cls.build.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='j81-gptcas-fixture-')
        self.base=Path(self.temp.name);self.plan=self.base/'plan'
        blocks=synthetic_plan(self.plan)
        self.disk=self.base/'sparse-fixture.img'
        with self.disk.open('wb') as f:f.truncate(64000000000)
        self.write(1,(self.plan/'old-primary.bin').read_bytes())
        self.write(15624995,(self.plan/'old-backup.bin').read_bytes())
        self.write(6,blocks[0])
        self.write(7,blocks[1])
    def tearDown(self):self.temp.cleanup()
    def write(self,lba,data):
        with self.disk.open('r+b') as f:f.seek(lba*BS);f.write(data)
    def read(self,lba,n):
        with self.disk.open('rb') as f:f.seek(lba*BS);return f.read(n)
    def tables(self):return self.read(1,5*BS),self.read(15624995,5*BS)
    def run_tool(self,*flags):
        p=subprocess.run([str(self.binary),*flags,str(self.disk),str(self.plan)],capture_output=True,text=True,timeout=20)
        return p.returncode,p.stdout+p.stderr
    def simulate_smaller_apfs(self):
        # Synthetic NX counters qualify the writer's guard, not Apple's resizer.
        for lba in range(6,287):
            block=bytearray(self.read(lba,BS))
            if checked(block) and block[32:36]==b'NXSB':
                struct.pack_into('<Q',block,40,16*1024**3//BS);sign_apfs(block);self.write(lba,block)
    def rewrite_target_entry(self,offset,data):
        primary=bytearray((self.plan/'new-primary.bin').read_bytes())
        backup=bytearray((self.plan/'new-backup.bin').read_bytes())
        primary[BS+offset:BS+offset+len(data)]=data;backup[offset:offset+len(data)]=data
        crc=zlib.crc32(primary[BS:])
        for region,head in [(primary,0),(backup,4*BS)]:
            struct.pack_into('<I',region,head+88,crc);struct.pack_into('<I',region,head+16,0)
            struct.pack_into('<I',region,head+16,zlib.crc32(region[head:head+92]))
        (self.plan/'new-primary.bin').write_bytes(primary);(self.plan/'new-backup.bin').write_bytes(backup)
    def test_full_container_refuses_without_writes(self):
        before=self.tables();code,text=self.run_tool('--dry-run')
        self.assertEqual(code,3,text);self.assertIn("doesn't fit",text);self.assertEqual(self.tables(),before)
    def test_post_shrink_dry_run_does_not_write(self):
        self.simulate_smaller_apfs();before=self.tables();code,text=self.run_tool('--dry-run')
        self.assertEqual(code,0,text);self.assertEqual(self.tables(),before)
    def test_write_verify_idempotent_and_reverse(self):
        self.simulate_smaller_apfs();before=self.tables();code,text=self.run_tool()
        self.assertEqual(code,0,text)
        self.assertEqual(self.tables(),((self.plan/'new-primary.bin').read_bytes(),(self.plan/'new-backup.bin').read_bytes()))
        self.assertEqual(self.run_tool()[0],0)
        code,text=self.run_tool('--reverse');self.assertEqual(code,0,text);self.assertEqual(self.tables(),before)
    def test_interrupted_between_copies_finishes(self):
        self.simulate_smaller_apfs();self.write(15624995,(self.plan/'new-backup.bin').read_bytes())
        code,text=self.run_tool();self.assertEqual(code,0,text)
        self.assertEqual(self.read(1,5*BS),(self.plan/'new-primary.bin').read_bytes())
    def test_changed_source_refuses(self):
        self.simulate_smaller_apfs();self.write(1,b'BROKEN!!');before=self.tables()
        code,text=self.run_tool();self.assertEqual(code,3,text);self.assertEqual(self.tables(),before)
    def test_changed_apfs_identity_refuses_even_with_valid_crcs(self):
        self.simulate_smaller_apfs();self.rewrite_target_entry(16,b'X'*16);before=self.tables()
        code,text=self.run_tool();self.assertEqual(code,3,text);self.assertIn('identity',text);self.assertEqual(self.tables(),before)
    def test_wrong_linux_extent_refuses_even_with_valid_crcs(self):
        self.simulate_smaller_apfs();self.rewrite_target_entry(168,struct.pack('<Q',15624704));before=self.tables()
        code,text=self.run_tool();self.assertEqual(code,3,text);self.assertIn('write-window',text);self.assertEqual(self.tables(),before)
    def test_bad_apfs_checksum_refuses(self):
        self.simulate_smaller_apfs();block=bytearray(self.read(6,BS));block[88]^=1;self.write(6,block);before=self.tables()
        code,text=self.run_tool();self.assertEqual(code,3,text);self.assertEqual(self.tables(),before)

if __name__=='__main__':unittest.main()

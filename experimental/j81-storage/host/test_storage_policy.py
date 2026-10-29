import unittest
from storage_policy import InspectionStop,RELEASE,validate_read_target

def rows():return [{'name':'asp0n'+str(i),'ro':1,'bytes':4096*100,'logical_block_size':4096} for i in range(1,11)]
class ReadGuards(unittest.TestCase):
    def test_valid_readonly_userarea(self):self.assertEqual(validate_read_target(RELEASE,rows(),b'ASP namespaces: USERAREA PANICLOG'),'asp0n1')
    def test_debug_printk_is_not_a_bug(self):
        self.assertEqual(validate_read_target(RELEASE,rows(),b'[0.000] printk: debug: ignoring loglevel setting.'),'asp0n1')
    def test_wrong_kernel(self):
        with self.assertRaises(InspectionStop):validate_read_target('old-kernel',rows(),b'')
    def test_missing_namespace(self):
        with self.assertRaises(InspectionStop):validate_read_target(RELEASE,rows()[:-1],b'')
    def test_duplicate_namespace(self):
        data=rows();data[-1]=data[0].copy()
        with self.assertRaises(InspectionStop):validate_read_target(RELEASE,data,b'')
    def test_writable_aux_namespace(self):
        data=rows();data[4]['ro']=0
        with self.assertRaises(InspectionStop):validate_read_target(RELEASE,data,b'')
    def test_wrong_block_size(self):
        data=rows();data[0]['logical_block_size']=512
        with self.assertRaises(InspectionStop):validate_read_target(RELEASE,data,b'')
    def test_zero_capacity(self):
        data=rows();data[0]['bytes']=0
        with self.assertRaises(InspectionStop):validate_read_target(RELEASE,data,b'')
    def test_crash_and_unlock_indicators(self):
        for log in [b'Kernel panic - not syncing',b'WARNING: CPU: 0',b'WRITE_UNLOCK',b'Oops: abort',b'BUG: unable to handle kernel']:
            with self.subTest(log=log),self.assertRaises(InspectionStop):validate_read_target(RELEASE,rows(),log)
if __name__=='__main__':unittest.main()

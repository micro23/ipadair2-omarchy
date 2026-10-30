"""Safety ordering tests: fake USB only; never run format or open a real port."""
import hashlib,json,tempfile,unittest
from pathlib import Path
from unittest import mock
import approved_install_p2 as install

class InstallGuards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='j81-install-guard-')
        self.task=Path(self.temp.name);self.private=self.task/'private'
        (self.private/'preserved-boot-plan').mkdir(parents=True)
        (self.private/'native-root-package').mkdir()
        self.bootstrap={'init_sha256':'1'*64,'native_root_handoff_sha256':'2'*64,'native_root_policy_sha256':'3'*64}
        self.plan={'root_uuid':'00000000-1111-4222-8333-444444444444','linux_root_device':'/dev/asp0n1p2',
                   'linux_first_lba':4194816,'linux_lba_count':11429888,'apfs_target_bytes':17179869184,
                   'linux_bytes':46816821248,'file_sha256':{}}
        for name,value in [('new-primary.bin',b'P'*20480),('new-backup.bin',b'B'*20480)]:
            (self.private/'preserved-boot-plan'/name).write_bytes(value)
            self.plan['file_sha256'][name]=hashlib.sha256(value).hexdigest()
        (self.private/'preserved-boot-plan/private-plan.json').write_text(json.dumps(self.plan))
        self.overlay_hash='4'*64
        (self.private/'native-root-package/private-manifest.json').write_text(json.dumps({'root_uuid':self.plan['root_uuid'],'overlay_sha256':self.overlay_hash}))
        (self.task/'INSTALLER-BOOTSTRAP-BUILD-VERIFIED.json').write_text(json.dumps(self.bootstrap))
        (self.private/'selected-device.json').write_text(json.dumps({'location':0}))
        self.permission=install.approval_scope(self.plan,self.overlay_hash,self.bootstrap['init_sha256'])
        self.commands=[];self.status=['Y','4194816','11429888','125000000','4096',str(4194816*8),str(11429888*8)]+['1']*9
        self.kernel=install.RELEASE;self.module_sha=install.MODULE_SHA
        owner=self
        class FakePort:
            def __init__(self,*args):pass
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def run(self,command,timeout=0):
                owner.commands.append(command)
                if 'uname -r;' in command:return 0,owner.kernel+'\napple,j81\napple,t7001\n'+owner.bootstrap['init_sha256']+'  /init\n'
                if command.startswith('set -eu\nsha256sum '):
                    if '/asp.ko' in command:return 0,owner.module_sha+'  /module\n'
                    key='native_root_policy_sha256' if '/etc/j81-native-root.conf' in command else 'native_root_handoff_sha256'
                    return 0,owner.bootstrap[key]+'  /checked\n'
                if '\nmodprobe asp ' in command:return 0,''
                if '\ni=0; while ' in command:return 0,''
                if '\ncat /sys/module/asp/' in command:return 0,'\n'.join(owner.status)+'\n'
                raise AssertionError('Unexpected guest operation: '+command)
            def capture_exact(self,command,size,timeout=0):
                owner.commands.append(command)
                return b'changed-GPT'.ljust(size,b'X')
        self.patches=[mock.patch.object(install,'TASK',self.task),mock.patch.object(install,'PRIVATE',self.private),
                      mock.patch.object(install,'SerialPort',FakePort),
                      mock.patch.object(install,'devices',return_value=[{'location':0,'product':'Orchard j81_storage_ro','serial_port':'FAKE-NEVER-OPEN'}]),
                      mock.patch.object(install,'digest',side_effect=self.digest)]
        for patch in self.patches:patch.start()
    def digest(self,path):
        if path==install.ARCHIVE:return install.ARCHIVE_SHA
        if path.name=='root-overlay-private.tar.gz':return self.overlay_hash
        return hashlib.sha256(path.read_bytes()).hexdigest()
    def tearDown(self):
        for patch in reversed(self.patches):patch.stop()
        self.temp.cleanup()
    def approve(self):
        (self.private/'native-install-approval.json').write_text(json.dumps(self.permission))
    def assert_no_format(self):
        self.assertFalse(any('mke2fs' in cmd or 'mount -t ext4' in cmd or 'bsdtar' in cmd for cmd in self.commands))
    def test_missing_approval_sends_no_device_command(self):
        with self.assertRaisesRegex(RuntimeError,'approval'):install.main(execute=True)
        self.assertEqual(self.commands,[])
    def test_boolean_one_is_not_human_approval(self):
        self.permission['approved']=1;self.approve()
        with self.assertRaisesRegex(RuntimeError,'approval'):install.main(execute=True)
        self.assertEqual(self.commands,[])
    def test_stale_overlay_approval_sends_nothing(self):
        self.permission['private_overlay_sha256']='0'*64;self.approve()
        with self.assertRaisesRegex(RuntimeError,'approval'):install.main(execute=True)
        self.assertEqual(self.commands,[])
    def test_changed_proposed_gpt_sends_nothing(self):
        self.approve();(self.private/'preserved-boot-plan/new-primary.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'proposal bytes'):install.main(execute=True)
        self.assertEqual(self.commands,[])
    def test_wrong_kernel_stops_before_driver_load(self):
        self.approve();self.kernel='unqualified'
        with self.assertRaisesRegex(RuntimeError,'bootstrap'):install.main(execute=True)
        self.assertFalse(any('modprobe' in cmd for cmd in self.commands));self.assert_no_format()
    def test_wrong_module_stops_before_driver_load(self):
        self.approve();self.module_sha='0'*64
        with self.assertRaisesRegex(RuntimeError,'module'):install.main(execute=True)
        self.assertFalse(any('\nmodprobe' in cmd for cmd in self.commands));self.assert_no_format()
    def test_writable_auxiliary_stops_before_format(self):
        self.approve();self.status[-1]='0'
        with self.assertRaisesRegex(RuntimeError,'read-only guard'):install.main(execute=True)
        self.assert_no_format()
    def test_wrong_root_geometry_stops_before_format(self):
        self.approve();self.status[5]='0'
        with self.assertRaisesRegex(RuntimeError,'geometry'):install.main(execute=True)
        self.assert_no_format()
    def test_changed_disk_gpt_stops_before_format(self):
        self.approve()
        with self.assertRaisesRegex(RuntimeError,'Disk GPT'):install.main(execute=True)
        self.assert_no_format()
        state=json.loads((self.private/'native-install-run/result.json').read_text())
        self.assertFalse(state['format_attempted']);self.assertFalse(state['passed'])

if __name__=='__main__':unittest.main()

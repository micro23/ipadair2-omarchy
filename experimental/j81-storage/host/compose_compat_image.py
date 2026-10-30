"""Replace exactly one ASP module in the known-working RAM archive."""
from pathlib import Path
import gzip,hashlib,io,json,os,shutil,subprocess,struct
from orchard_cli.ram import verify_ram
os.umask(0o077)
root=Path.cwd();task=root/'work/j81-internal-install';old=task/'image-ro-v2mod/out';out=task/'image-module-compat/out';out.mkdir(parents=True,exist_ok=False)
meta=json.loads((old/'linux.bin.json').read_text());base_image=(old/'linux.bin').read_bytes()
assert hashlib.sha256(base_image).hexdigest()=='1e98e353b6ed9dcd585eff52fba865a9aed17a9a20b1878bcfaf38ec9ec6eac1'
base_ram=(old/'initramfs.cpio.gz').read_bytes();raw=gzip.decompress(base_ram)
entries=[];pos=0
while raw[pos:pos+6]==b'070701':
 fields=[int(raw[pos+6+i*8:pos+14+i*8],16) for i in range(13)];namebytes=raw[pos+110:pos+110+fields[11]]
 assert namebytes[-1:]==b'\0';name=namebytes[:-1].decode();start=(pos+110+fields[11]+3)&~3;data=raw[start:start+fields[6]];end=(start+fields[6]+3)&~3
 entries.append([name,fields,namebytes,data]);pos=end
 if name=='TRAILER!!!':break
assert entries[-1][0]=='TRAILER!!!' and not any(raw[pos:])
tail=raw[pos:]
def pack(items):
 result=bytearray()
 for name,fields,namebytes,data in items:
  f=list(fields);f[6]=len(data);result.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in f));result.extend(namebytes);result.extend(b'\0'*((-len(result))%4));result.extend(data);result.extend(b'\0'*((-len(result))%4))
 result.extend(tail);return bytes(result)
assert pack(entries)==raw
release='7.3.0-rc1-orchard-j81-storage-ro-v2mod';target='lib/modules/'+release+'/kernel/drivers/block/asp.ko'
module=root/'work/orchard-integration/linux-build/j81-module-compat/output/drivers/block/asp.ko';data=module.read_bytes();proof=json.loads((task/'MODULE-COMPAT-BUILD-VERIFIED.json').read_text());assert hashlib.sha256(data).hexdigest()==proof['module_sha256']
changed=[]
for entry in entries:
 if entry[0]==target:
  assert entry[3]!=data;entry[3]=data;changed.append(target)
assert changed==[target]
assert not any('wpa_supplicant.conf' in e[0] for e in entries)
with (out/'initramfs.cpio.gz').open('xb') as f,gzip.GzipFile(fileobj=f,mode='wb',mtime=0,filename='') as z:z.write(pack(entries))
boot=next(c for c in meta['components'] if c['name']=='bootargs');profile=task/'module-compat-boot.json';profile.write_text(json.dumps({'bootargs':base_image[boot['offset']:boot['offset']+boot['bytes']].decode()}))
subprocess.run([str(root/'work/orchard-integration/orchard-air2/.venv/bin/python'),'-B',str(root/'work/orchard-integration/hardware-review/boot/assemble.py'),'--manifest',str(profile),'--loader',str(root/'work/orchard-integration/prebuilt-loader.bin'),'--dtb',str(task/'kernel-ro-v2mod/j81.dtb'),'--kernel',str(task/'kernel-ro-v2mod/Image.gz'),'--initramfs',str(out/'initramfs.cpio.gz'),'--output',str(out/'linux.bin')],check=True)
newmeta=json.loads((out/'linux.bin.json').read_text())
for name in ['loader','bootargs','dtb','kernel']:
 a=next(c for c in meta['components'] if c['name']==name);b=next(c for c in newmeta['components'] if c['name']==name);assert a==b,name
shutil.copy2(old/'pongo.bin',out/'pongo.bin')
receipt={'kind':'orchard.ram-build','device':'j81','kernel_release':release,'hardware_tested':False,'files':{p:hashlib.sha256((out/p).read_bytes()).hexdigest() for p in ['linux.bin','pongo.bin']},'base_hardware_tested_image_sha256':meta['image_sha256'],'changed_archive_entries':changed,'kernel_loader_dtb_bootargs_unchanged':True,'module_sha256':proof['module_sha256'],'storage_driver_auto_loaded':False,'storage_writes_enabled_by_boot':False}
(out/'build.json').write_text(json.dumps(receipt,indent=2)+'\n');verify_ram(out)
(task/'MODULE-COMPAT-IMAGE-VERIFIED.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('PASS: exactly one module replaced; kernel/DTB/loader/bootargs and all other initramfs entries unchanged.')

"""Collect the released ARM64 tools and their exact shared-library closure."""
from pathlib import Path,PurePosixPath
import hashlib,json,struct,tarfile,io,stat,subprocess
ROOT=Path('/Volumes/J81_OMARCHY_A_V011/rootfs');TASK=Path(__file__).resolve().parent;OUT=TASK/'native-install-tools';OUT.mkdir(exist_ok=True)

def resolve(path):
 queue=list(PurePosixPath(path).parts);parts=[];links=0
 while queue:
  part=queue.pop(0)
  if part in ('','/','.'):continue
  if part=='..':
   if parts:parts.pop()
   continue
  candidate=ROOT.joinpath(*parts,part)
  if candidate.is_symlink():
   links+=1
   if links>40:raise ValueError('Guest symlink loop')
   target=PurePosixPath(candidate.readlink().as_posix())
   if target.is_absolute():parts=[]
   queue=list(target.parts)+queue
  else:parts.append(part)
 result=ROOT.joinpath(*parts)
 if not result.is_file():raise ValueError('Missing guest file: '+path)
 return result

def elf(data):
 if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=183:raise ValueError('Expected little-endian ARM64 ELF')
 off=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
 if size<56 or count>1024 or off+size*count>len(data):raise ValueError('ELF program-header bounds')
 loads=[];dynamic=None;interp=None
 for i in range(count):
  kind,flags,p_off,vaddr,paddr,fsize,msize,align=struct.unpack_from('<IIQQQQQQ',data,off+i*size)
  if p_off+fsize>len(data):raise ValueError('ELF segment bounds')
  if kind==1:loads.append((vaddr,p_off,fsize))
  if kind==2:dynamic=(p_off,fsize)
  if kind==3:interp=data[p_off:p_off+fsize].rstrip(b'\0').decode()
 needed=[];strtab=None;strsz=None
 if dynamic:
  d_off,d_size=dynamic
  if d_size%16:raise ValueError('ELF dynamic size')
  for pos in range(d_off,d_off+d_size,16):
   tag,value=struct.unpack_from('<QQ',data,pos)
   if tag==0:break
   if tag==1:needed.append(value)
   if tag==5:strtab=value
   if tag==10:strsz=value
 if needed:
  if strtab is None or strsz is None:raise ValueError('Missing ELF string table')
  matches=[o+strtab-v for v,o,n in loads if v<=strtab and strtab+strsz<=v+n]
  if len(matches)!=1:raise ValueError('ELF string mapping ambiguous')
  strings=data[matches[0]:matches[0]+strsz];names=[]
  for index in needed:
   if index>=len(strings):raise ValueError('ELF dependency offset')
   end=strings.find(b'\0',index)
   if end<0:raise ValueError('ELF dependency terminator')
   name=strings[index:end].decode()
   if '/' in name or not name:raise ValueError('Unexpected ELF dependency name')
   names.append(name)
 else:names=[]
 return names,interp

files={};sources={};pending=['/usr/bin/mke2fs','/usr/bin/e2fsck','/usr/bin/bsdtar','/usr/bin/zstd','/usr/bin/sfdisk','/usr/bin/blkid']
while pending:
 dest=pending.pop(0)
 if dest in files:continue
 source=resolve(dest);data=source.read_bytes();deps,interp=elf(data)
 files[dest]=data;sources[dest]=source.relative_to(ROOT).as_posix()
 if interp:pending.append(interp)
 for name in deps:
  choices=['/usr/lib/'+name,'/lib/'+name]
  chosen=next((p for p in choices if (ROOT/p.lstrip('/')).exists() or (ROOT/p.lstrip('/')).is_symlink()),None)
  if chosen is None:raise ValueError('Missing shared library: '+name)
  pending.append(chosen)
config=resolve('/etc/mke2fs.conf');files['/etc/mke2fs.conf']=config.read_bytes();sources['/etc/mke2fs.conf']=config.relative_to(ROOT).as_posix()
# Match every selected byte stream to the original pinned release archive.
archive=Path('/Users/micro/ChatGPT-Projects/iPad-Air2-Omarchy/Current/J81-Omarchy-A-v0.1.1/rootfs.tar.zst')
expected={sources[k]:hashlib.sha256(v).hexdigest() for k,v in files.items()};found={}
p=subprocess.Popen(['/opt/homebrew/bin/zstd','-q','-dc',str(archive)],stdout=subprocess.PIPE)
with tarfile.open(fileobj=p.stdout,mode='r|') as tar:
 for member in tar:
  name=member.name.removeprefix('./').rstrip('/')
  if name in expected and member.isfile():
   stream=tar.extractfile(member);h=hashlib.sha256()
   for block in iter(lambda:stream.read(1<<20),b''):h.update(block)
   found[name]=h.hexdigest()
assert p.wait()==0
if found!=expected:raise RuntimeError('Selected native tools differ from pinned release archive')
with tarfile.open(OUT/'tools.tar.gz','w:gz') as tar:
 for dest,data in sorted(files.items()):
  t=tarfile.TarInfo(dest.lstrip('/'));t.size=len(data);t.mode=0o644 if dest.startswith('/etc/') else 0o755;t.uid=t.gid=0;t.mtime=0;tar.addfile(t,io.BytesIO(data))
report={'architecture':'ARM64','source_release':'Omarchy A v0.1.1','selected_files_verified_against_release':True,'file_count':len(files),'expanded_bytes':sum(map(len,files.values())),'tar_sha256':hashlib.sha256((OUT/'tools.tar.gz').read_bytes()).hexdigest(),'files':{k:{'sha256':hashlib.sha256(v).hexdigest(),'bytes':len(v)} for k,v in sorted(files.items())},'device_execution_verified':False,'device_writes':False}
(OUT/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='files'},indent=2))

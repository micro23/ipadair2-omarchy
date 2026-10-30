"""Strict newc parsing/packing for the pinned local boot archive."""
import stat

def unpack(raw):
    entries=[];seen=set();pos=0
    while raw[pos:pos+6]==b'070701':
        if pos+110>len(raw):raise ValueError('Truncated cpio header')
        fields=[int(raw[pos+6+i*8:pos+14+i*8],16) for i in range(13)]
        length=fields[11]
        if not 1<=length<=4096 or pos+110+length>len(raw):raise ValueError('Invalid cpio name bounds')
        namebytes=raw[pos+110:pos+110+length]
        if namebytes[-1:]!=b'\0' or b'\0' in namebytes[:-1]:raise ValueError('Invalid cpio name terminator')
        name=namebytes[:-1].decode()
        if name in seen or name.startswith('/') or '..' in name.split('/'):raise ValueError('Unsafe or duplicate cpio path')
        seen.add(name);start=(pos+110+length+3)&~3
        if start+fields[6]>len(raw):raise ValueError('Truncated cpio data')
        data=raw[start:start+fields[6]];pos=(start+fields[6]+3)&~3
        entries.append([name,fields,namebytes,data])
        if name=='TRAILER!!!':break
    if not entries or entries[-1][0]!='TRAILER!!!' or any(raw[pos:]):raise ValueError('Missing cpio trailer or unexpected tail')
    return entries,raw[pos:]

def pack(entries,tail=b''):
    out=bytearray()
    for name,fields,namebytes,data in entries:
        f=list(fields);f[6]=len(data)
        out.extend(b'070701'+b''.join(f'{v:08x}'.encode() for v in f));out.extend(namebytes)
        out.extend(b'\0'*((-len(out))%4));out.extend(data);out.extend(b'\0'*((-len(out))%4))
    out.extend(tail)
    return bytes(out)

def add(entries,name,data,mode):
    if any(e[0]==name for e in entries):raise ValueError('Refusing to replace archive member: '+name)
    encoded=name.encode()+b'\0';ino=max(e[1][0] for e in entries)+1
    fields=[ino,mode,0,0,2 if stat.S_ISDIR(mode) else 1,0,len(data),0,0,0,0,len(encoded),0]
    entries.insert(len(entries)-1,[name,fields,encoded,data])

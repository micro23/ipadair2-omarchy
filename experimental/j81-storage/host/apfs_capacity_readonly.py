"""Bounded APFS capacity inspection; no mount, crypto keys or disk writes.

Structures: Apple File System Reference, Container and Space Manager sections.
https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
"""
import json, os, struct
from pathlib import Path
from orchard_cli.apple.usb import devices
from orchard_cli.serial import SerialPort

TASK = Path(__file__).resolve().parent
PRIVATE = TASK / 'private-live'
BS = 4096

def checked(data):
    if len(data) < BS or len(data) % BS:
        return False
    a = b = 0
    for word, in struct.iter_unpack('<I', data[8:]):
        a = (a + word) % 0xffffffff
        b = (b + a) % 0xffffffff
    low = 0xffffffff - (a + b) % 0xffffffff
    high = 0xffffffff - (a + low) % 0xffffffff
    return struct.unpack_from('<Q', data)[0] == (high << 32) | low

def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]

def u64(data, offset):
    return struct.unpack_from('<Q', data, offset)[0]

def main():
    os.umask(0o077)
    saved = json.loads((PRIVATE / 'selected-device.json').read_text())
    def target():
        ds = [d for d in devices() if d['location'] == saved['location']
              and d.get('product') == 'Orchard j81_storage_ro' and d.get('serial_port')]
        if len(ds) != 1:
            raise RuntimeError('Expected selected J81 diagnostic endpoint')
        return ds[0]
    out = PRIVATE / 'apfs-capacity'
    out.mkdir(mode=0o700, exist_ok=True)
    total_read = 0
    with SerialPort(target()['serial_port'], target) as port:
        rc, text = port.run('uname -r; tr "\\000" "\\n" < /proc/device-tree/compatible; '
                            'cat /sys/module/asp/parameters/write_first_lba; cat /sys/module/asp/parameters/write_lba_count')
        lines = text.splitlines()
        if rc or lines[0] != '7.3.0-rc1-orchard-j81-storage-ro-v2mod' or 'apple,j81' not in lines or 'apple,t7001' not in lines or lines[-2:] != ['15624738','1']:
            raise RuntimeError('J81 identity or one-block fence changed')
        def read(name, block, count, bounds):
            nonlocal total_read
            lo, hi = bounds
            if not (lo <= block and 1 <= count <= 512 and block + count <= hi):
                raise RuntimeError('APFS metadata request outside bounded region')
            total_read += count * BS
            if total_read > 4 * 1024 * 1024:
                raise RuntimeError('APFS metadata budget exceeded')
            data = port.capture_exact(f'timeout 20 dd if=/dev/asp0n1p1 bs=4096 skip={block} count={count} 2>/dev/null', count * BS, timeout=30)
            (out / name).write_bytes(data)
            return data
        base = read('container-block0.bin', 0, 1, (0, 15624989))
        if not checked(base) or base[32:36] != b'NXSB' or u32(base,36) != BS or u64(base,40) != 15624989:
            raise RuntimeError('APFS container header invalid or geometry changed')
        desc_count, desc_base = u32(base,104), u64(base,112)
        if desc_count & 0x80000000 or not 1 <= desc_count <= 512:
            raise RuntimeError('Unsupported or excessive checkpoint descriptor area')
        desc = read('checkpoint-descriptors.bin', desc_base, desc_count, (1,15624989))
        containers, maps = [], {}
        for offset in range(0,len(desc),BS):
            block = desc[offset:offset+BS]
            if not checked(block):
                continue
            kind, xid = u32(block,24) & 0xffff, u64(block,16)
            if kind == 1 and block[32:36] == b'NXSB':
                containers.append(block)
            elif kind == 12:
                count = u32(block,36)
                if count > (BS-40)//40:
                    raise RuntimeError('Checkpoint map entry count exceeds object')
                maps.setdefault(xid,[]).append(block)
        if not containers:
            raise RuntimeError('No checksum-valid checkpoint container')
        latest = max(containers,key=lambda b:u64(b,16))
        xid, sm_oid = u64(latest,16), u64(latest,152)
        if u32(latest,36) != BS or u64(latest,40) != 15624989:
            raise RuntimeError('Latest checkpoint geometry differs')
        found = []
        for block in maps.get(xid,[]):
            for n in range(u32(block,36)):
                kind, subtype, size, pad, fs_oid, oid, address = struct.unpack_from('<IIIIQQQ',block,40+n*40)
                if kind & 0xffff == 5 and oid == sm_oid:
                    found.append((size,address))
        if len(found) != 1:
            raise RuntimeError('Latest space-manager mapping absent or ambiguous')
        size, address = found[0]
        if size % BS or not BS <= size <= 65536:
            raise RuntimeError('Unsupported space-manager object size')
        data_count, data_base = u32(latest,108), u64(latest,120)
        if data_count & 0x80000000 or not 1 <= data_count <= 131072:
            raise RuntimeError('Unsupported checkpoint data area')
        sm = read('space-manager.bin',address,size//BS,(data_base,data_base+data_count))
        if not checked(sm) or u32(sm,24) & 0xffff != 5 or u64(sm,16) != xid or u32(sm,32) != BS:
            raise RuntimeError('Space-manager checksum, identity or geometry differs')
        blocks, free = u64(sm,48), u64(sm,72)
        if blocks != 15624989 or not 0 <= free <= blocks:
            raise RuntimeError('Space-manager counters outside container')
        report = {'read_only':True,'internal_writes_performed':False,'metadata_bytes_read':total_read,
                  'latest_checkpoint_and_spaceman_checksums_valid':True,
                  'container_bytes':blocks*BS,'allocated_bytes':(blocks-free)*BS,'free_bytes':free*BS,
                  'apple_resize_minimum_verified':False,
                  'note':'Allocation counters do not establish an APFS resize minimum; Apple resizer must validate any proposed shrink.'}
        (TASK / 'apfs-capacity-result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))

if __name__ == '__main__':
    main()

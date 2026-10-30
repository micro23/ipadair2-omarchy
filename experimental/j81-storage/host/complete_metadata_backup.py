"""Finish bounded GPT metadata backup through the current diagnostic shell."""
import hashlib, json, os, struct, zlib
from pathlib import Path
from orchard_cli.apple.usb import devices
from orchard_cli.serial import SerialPort
from gpt_metadata import header, partitions

os.umask(0o077)
TASK = Path(__file__).resolve().parent
PRIVATE = TASK / 'private-live'

def main():
    selected = json.loads((PRIVATE / 'selected-device.json').read_text())
    def target():
        ds = [d for d in devices() if d['location'] == selected['location']
              and d.get('product') in ('Orchard j81_storage_ro', 'Orchard j81-storage-ro')
              and d.get('serial_port')]
        if len(ds) != 1:
            raise RuntimeError('Expected selected J81 diagnostic endpoint')
        return ds[0]
    out = PRIVATE / 'metadata-complete'
    out.mkdir(mode=0o700, exist_ok=True)
    with SerialPort(target()['serial_port'], target) as port:
        def run(command):
            rc, text = port.run(command, timeout=20)
            if rc:
                raise RuntimeError('Metadata identity check failed')
            return text
        text = run('uname -r; tr "\\000" "\\n" < /proc/device-tree/compatible; '
                   'cat /sys/class/block/asp0n1/size; cat /sys/class/block/asp0n1/queue/logical_block_size; '
                   'cat /sys/module/asp/parameters/write_first_lba; cat /sys/module/asp/parameters/write_lba_count; '
                   'for n in 2 3 4 5 6 7 8 9 10; do cat /sys/class/block/asp0n$n/ro; done')
        lines = text.splitlines()
        if (lines[0] != '7.3.0-rc1-orchard-j81-storage-ro-v2mod'
                or 'apple,j81' not in lines or 'apple,t7001' not in lines
                or lines[-13:] != ['125000000', '4096', '15624738', '1'] + ['1'] * 9):
            raise RuntimeError('J81 identity, geometry, one-block range or auxiliary RO state changed')
        blobs = {}
        def read(name, lba, blocks=1):
            if not (0 <= lba < 15625000 and 1 <= blocks <= 16 and lba + blocks <= 15625000):
                raise ValueError('Read exceeds bounded metadata request')
            data = port.capture_exact(f'timeout 10 dd if=/dev/asp0n1 bs=4096 skip={lba} count={blocks} 2>/dev/null', blocks * 4096, timeout=15)
            blobs[name] = data
            (out / name).write_bytes(data)
            return data
        read('protective-mbr.bin', 0)
        primary = read('gpt-primary-header.bin', 1)
        h = header(primary, 15625000)
        entries = read('gpt-primary-entries.bin', h['table_lba'], h['table_blocks'])
        rows = partitions(entries, h)
        if len(rows) != 1 or rows[0]['type_guid'] != '7c3457ef-0000-11aa-aa11-00306543ecac':
            raise RuntimeError('Original single APFS partition changed')
        backup = read('gpt-backup-header.bin', h['backup_lba'])
        revision, size, checksum = struct.unpack_from('<III', backup, 8)
        if backup[:8] != b'EFI PART' or revision != 0x10000 or not 92 <= size <= 4096:
            raise RuntimeError('Backup GPT header invalid')
        checked = bytearray(backup[:size]); checked[16:20] = b'\0' * 4
        if zlib.crc32(checked) != checksum:
            raise RuntimeError('Backup GPT checksum invalid')
        if struct.unpack_from('<QQ', backup, 24) != (h['backup_lba'], 1) or backup[40:72] != primary[40:72]:
            raise RuntimeError('Primary and backup GPT identity/geometry differ')
        table_lba, count, entry_size, table_crc = struct.unpack_from('<QIII', backup, 72)
        if (count, entry_size, table_crc) != (h['entry_count'], h['entry_size'], h['table_crc']):
            raise RuntimeError('Backup GPT entry dimensions differ')
        if not h['last_usable_lba'] < table_lba or table_lba + h['table_blocks'] > h['backup_lba']:
            raise RuntimeError('Backup table outside metadata area')
        tail = read('gpt-backup-entries.bin', table_lba, h['table_blocks'])
        if tail[:count * entry_size] != entries[:count * entry_size]:
            raise RuntimeError('Primary and backup GPT entries differ')
        nx = read('apfs-container-block0.bin', rows[0]['first_lba'])
        nx_info = {'signature_present': nx[32:36] == b'NXSB'}
        if nx_info['signature_present']:
            blocksize, blockcount = struct.unpack_from('<IQ', nx, 36)
            nx_info.update(block_size=blocksize, block_count=blockcount, bytes=blocksize * blockcount)
        report = {'internal_writes_performed': False, 'primary_header_crc_valid': True,
                  'primary_and_backup_entries_crc_valid': True, 'backup_header_crc_valid': True,
                  'primary_and_backup_entries_identical': True, 'logical_block_size': 4096,
                  'userarea_bytes': 64000000000, 'partitions': rows,
                  'apfs_block0': nx_info, 'auxiliary_namespaces_read_only': True,
                  'private_metadata_backup_bytes': sum(map(len, blobs.values()))}
        (out / 'private-checksums.json').write_text(json.dumps({k: hashlib.sha256(v).hexdigest() for k, v in blobs.items()}, indent=2) + '\n')
        (TASK / 'metadata-backup-result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()

"""Construct a proposal from verified private metadata; never opens a disk."""
from pathlib import Path
import hashlib, json, os, struct, uuid, zlib
from gpt_metadata import header, partitions

TASK = Path(__file__).resolve().parent
PRIVATE = TASK / 'private-live'
BS = 4096

def main():
    os.umask(0o077)
    meta = PRIVATE / 'metadata-complete'
    checks = json.loads((meta / 'private-checksums.json').read_text())
    blobs = {name:(meta/name).read_bytes() for name in checks}
    if any(hashlib.sha256(data).hexdigest()!=checks[name] for name,data in blobs.items()):
        raise RuntimeError('Private metadata backup changed')
    h = header(blobs['gpt-primary-header.bin'],15625000)
    entries = blobs['gpt-primary-entries.bin']
    rows = partitions(entries,h)
    if (h['entry_count'],h['entry_size'],h['table_lba'],h['table_blocks']) != (128,128,2,4):
        raise RuntimeError('Unexpected original GPT entry layout')
    if len(rows)!=1 or (rows[0]['first_lba'],rows[0]['last_lba'],rows[0]['type_guid'])!=(6,15624994,'7c3457ef-0000-11aa-aa11-00306543ecac'):
        raise RuntimeError('Not the original single APFS layout')
    if blobs['gpt-backup-entries.bin'] != entries or any(entries[128:]):
        raise RuntimeError('Backup entries differ or another original slot is nonzero')
    capacity = json.loads((TASK/'apfs-capacity-result.json').read_text())
    target = 16 * 1024**3
    if not capacity['latest_checkpoint_and_spaceman_checksums_valid'] or capacity['allocated_bytes']+3*1024**3 > target:
        raise RuntimeError('Insufficient proposed Apple boot-area headroom')
    p1_first,p1_last = 6,6+target//BS-1
    align = 256
    p2_first = ((p1_last+1+align+align-1)//align)*align
    p2_last = ((h['last_usable_lba']+1-align)//align)*align-1
    out = PRIVATE/'preserved-boot-plan'
    out.mkdir(mode=0o700,exist_ok=True)
    record = out/'private-plan.json'
    identities = json.loads(record.read_text()) if record.exists() else {'p2_guid':str(uuid.uuid4()),'root_uuid':str(uuid.uuid4())}
    new_entries = bytearray(entries)
    struct.pack_into('<Q',new_entries,40,p1_last)
    struct.pack_into('<16s16sQQQ72s',new_entries,128,
                     uuid.UUID('0fc63daf-8483-4772-8e79-3d69d8477de4').bytes_le,
                     uuid.UUID(identities['p2_guid']).bytes_le,p2_first,p2_last,0,
                     'j81-omarchy-root'.encode('utf-16-le').ljust(72,b'\0'))
    crc = zlib.crc32(new_entries)
    def new_header(old):
        data=bytearray(old)
        struct.pack_into('<I',data,88,crc);struct.pack_into('<I',data,16,0)
        struct.pack_into('<I',data,16,zlib.crc32(data[:struct.unpack_from('<I',data,12)[0]]))
        return bytes(data)
    planned_header = new_header(blobs['gpt-primary-header.bin'])
    ph = header(planned_header,15625000)
    planned_rows = partitions(new_entries,ph)
    assert len(planned_rows)==2 and planned_rows[1]['first_lba']==4194816 and planned_rows[1]['last_lba']==15624703
    files={'old-primary.bin':blobs['gpt-primary-header.bin']+entries,
           'old-backup.bin':entries+blobs['gpt-backup-header.bin'],
           'new-primary.bin':planned_header+bytes(new_entries),
           'new-backup.bin':bytes(new_entries)+new_header(blobs['gpt-backup-header.bin'])}
    cfg={'lba_size':BS,'disk_lbas':15625000,'primary_lba':1,'primary_count':5,
         'backup_lba':15624995,'backup_count':5,'p1_first':6,'p1_last_old':15624994,'p1_last_new':p1_last}
    files['plan.cfg']=''.join(f'{k} {v}\n' for k,v in cfg.items()).encode()
    for name,data in files.items():
        path=out/name
        if path.exists() and path.read_bytes()!=data:
            raise RuntimeError('Refusing to replace a different existing GPT proposal')
        path.write_bytes(data)
    proposal={'device':'J81 / iPad5,3 / T7001','approved':False,'executed':False,
              'purpose':'Native Omarchy root with retained Apple cold-boot support',
              'apple_resize_runtime_verified':False,'apfs_resize_minimum_verified':False,
              'apfs_first_lba':p1_first,'apfs_last_lba':p1_last,'apfs_target_bytes':target,
              'apfs_current_allocated_bytes':capacity['allocated_bytes'],
              'apfs_headroom_after_current_allocations':target-capacity['allocated_bytes'],
              'linux_root_device':'/dev/asp0n1p2','linux_first_lba':p2_first,'linux_last_lba':p2_last,
              'linux_lba_count':p2_last-p2_first+1,'linux_bytes':(p2_last-p2_first+1)*BS,
              'all_auxiliary_namespaces_must_remain_read_only':True,
              'cold_boot_still_host_tethered':True}
    identities.update(proposal)
    identities['file_sha256']={k:hashlib.sha256(v).hexdigest() for k,v in files.items()}
    record.write_text(json.dumps(identities,indent=2)+'\n')
    (TASK/'preserved-boot-layout-proposal.json').write_text(json.dumps(proposal,indent=2)+'\n')
    print(json.dumps(proposal,indent=2))

if __name__=='__main__':
    main()

"""Validate GPT metadata from bounded read-only buffers; do not expose disk IDs."""
import math,struct,uuid,zlib

def header(data,total_blocks,block_size=4096):
 if len(data)!=block_size or data[:8]!=b'EFI PART':raise ValueError('Missing GPT signature at logical LBA 1')
 revision,size,crc=struct.unpack_from('<III',data,8)
 if revision!=0x10000 or not 92<=size<=block_size:raise ValueError('Unexpected GPT header size/revision')
 h=bytearray(data[:size]);h[16:20]=b'\0'*4
 if zlib.crc32(h)!=crc:raise ValueError('GPT header CRC mismatch')
 current,backup,first,last=struct.unpack_from('<QQQQ',data,24)
 table_lba,count,entry_size,table_crc=struct.unpack_from('<QIII',data,72)
 if current!=1 or backup!=total_blocks-1 or not 2<=first<=last<backup:raise ValueError('GPT geometry mismatch')
 if not 1<=count<=1024 or not 128<=entry_size<=1024 or entry_size%8:raise ValueError('Unsupported GPT table dimensions')
 blocks=math.ceil(count*entry_size/block_size)
 if table_lba<2 or table_lba+blocks>first or count*entry_size>1024*1024:raise ValueError('GPT table outside bounded metadata area')
 return dict(current_lba=current,backup_lba=backup,first_usable_lba=first,last_usable_lba=last,table_lba=table_lba,entry_count=count,entry_size=entry_size,table_crc=table_crc,table_blocks=blocks)

def partitions(data,h):
 data=data[:h['entry_count']*h['entry_size']]
 if len(data)!=h['entry_count']*h['entry_size'] or zlib.crc32(data)!=h['table_crc']:raise ValueError('GPT entry CRC mismatch')
 result=[]
 for i in range(h['entry_count']):
  row=data[i*h['entry_size']:(i+1)*h['entry_size']]
  if row[:16]==bytes(16):continue
  start,end=struct.unpack_from('<QQ',row,32)
  if not h['first_usable_lba']<=start<=end<=h['last_usable_lba']:raise ValueError('Partition outside usable GPT area')
  if any(start<=p['last_lba'] and end>=p['first_lba'] for p in result):raise ValueError('Overlapping GPT partitions')
  result.append(dict(index=i+1,type_guid=str(uuid.UUID(bytes_le=bytes(row[:16]))),first_lba=start,last_lba=end,bytes=(end-start+1)*4096))
 return result

from pathlib import Path
import ctypes,os,json,time
assert os.getuid()==0
assert b'apple,j81\0' in Path('/proc/device-tree/compatible').read_bytes()
node=Path('/sys/bus/i2c/devices/0-003c')
assert b'apple,arabela-pmic\0' in (node/'of_node/compatible').read_bytes()
assert (node/'driver').resolve().name=='simple-mfd-i2c'
class Msg(ctypes.Structure):
 _fields_=[('addr',ctypes.c_uint16),('flags',ctypes.c_uint16),('length',ctypes.c_uint16),('buffer',ctypes.POINTER(ctypes.c_uint8))]
class Transfer(ctypes.Structure):
 _fields_=[('messages',ctypes.POINTER(Msg)),('count',ctypes.c_uint32)]
libc=ctypes.CDLL(None,use_errno=True);libc.ioctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_void_p]
fd=os.open('/dev/i2c-0',os.O_RDWR|os.O_CLOEXEC)
def read(reg):
 assert reg in [0x10,0x4c0,0x4c6,0x4c7,0x4cf]
 tx=(ctypes.c_uint8*2)(reg>>8,reg&255);rx=(ctypes.c_uint8*1)()
 msgs=(Msg*2)(Msg(0x3c,0,2,tx),Msg(0x3c,1,1,rx));transfer=Transfer(msgs,2)
 if libc.ioctl(fd,0x707,ctypes.byref(transfer))!=2:raise OSError(ctypes.get_errno(),'Read-only register transfer failed')
 return int(rx[0])
try:
 values={f'{reg:04x}':read(reg) for reg in [0x10,0x4c0,0x4c6,0x4c7,0x4cf]}
 c=values['04c0'];r={'raw':values,'usb_input_suspended':bool(values['0010']&4),'input_current_limit_ma':3262 if c>=254 else 75+(100*c+7)//8,'active_battery_charge_limit_ma':(values['04c6']&63)*50,'hardware_charge_limit_ma':(values['04c7']&63)*50,'configured_charge_ceiling_ma':(values['04cf']&63)*50,'configuration_writes':0}
 print(json.dumps(r,indent=2))
finally:os.close(fd)

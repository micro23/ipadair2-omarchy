"""J81-only bounded USB 500 mA probe; restores register, descriptor and brightness."""
from pathlib import Path
import ctypes,json,os,signal,time
assert os.getuid()==0
assert b'apple,j81\0' in Path('/proc/device-tree/compatible').read_bytes()
assert b'apple,arabela-pmic\0' in Path('/sys/bus/i2c/devices/0-003c/of_node/compatible').read_bytes()
assert Path('/sys/bus/i2c/devices/0-003c/driver').resolve().name=='simple-mfd-i2c'
class Msg(ctypes.Structure):_fields_=[('addr',ctypes.c_uint16),('flags',ctypes.c_uint16),('length',ctypes.c_uint16),('buffer',ctypes.POINTER(ctypes.c_uint8))]
class Transfer(ctypes.Structure):_fields_=[('messages',ctypes.POINTER(Msg)),('count',ctypes.c_uint32)]
libc=ctypes.CDLL(None,use_errno=True);libc.ioctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_void_p]
fd=os.open('/dev/i2c-0',os.O_RDWR|os.O_CLOEXEC)
def read(reg):
 assert reg in [0x10,0x4c0,0x4c6,0x4c7]
 tx=(ctypes.c_uint8*2)(reg>>8,reg&255);rx=(ctypes.c_uint8*1)();msgs=(Msg*2)(Msg(0x3c,0,2,tx),Msg(0x3c,1,1,rx));d=Transfer(msgs,2)
 if libc.ioctl(fd,0x707,ctypes.byref(d))!=2:raise OSError(ctypes.get_errno(),'charger read failed')
 return int(rx[0])
def write(code):
 assert code in [2,34]
 tx=(ctypes.c_uint8*3)(4,0xc0,code);msgs=(Msg*1)(Msg(0x3c,0,3,tx));d=Transfer(msgs,1)
 if libc.ioctl(fd,0x707,ctypes.byref(d))!=1:raise OSError(ctypes.get_errno(),'input limit write failed')
 assert read(0x4c0)==code
p=Path('/run/j81');p.mkdir(exist_ok=True);log=p/'usb-charge-probe.json'
g=Path('/sys/kernel/config/usb_gadget/j81-storage-ro');u=g/'UDC';power=g/'configs/c.1/MaxPower';udc=u.read_text().strip();state=Path('/sys/class/udc')/udc/'state';assert state.read_text().strip()=='configured'
lights=list(Path('/sys/class/backlight').glob('*'));assert len(lights)==1
brightness=lights[0]/'brightness';old_brightness=int(brightness.read_text());assert 0<old_brightness<=2047
assert int(power.read_text())==100 and read(0x4c0)==2 and read(0x10)&4==0 and read(0x4c6)&63==60
result={'scope':'J81 USB-host 500mA bounded test','old_input_code':2,'old_usb_request_ma':100,'old_brightness':old_brightness,'samples':[],'restored':False}
def save():log.write_text(json.dumps(result,indent=2)+'\n')
def sample(phase):
 b=Path('/sys/class/power_supply/battery');d={k:int((b/k).read_text()) for k in ['current_now','voltage_now','temp','capacity']};d.update(phase=phase,elapsed=round(time.monotonic()-start,2),udc=state.read_text().strip(),input_code=read(0x4c0),brightness=int(brightness.read_text()));result['samples'].append(d);save();assert 100<=d['temp']<380 and 3400000<d['voltage_now']<4250000

def rebind(ma):
 u.write_text('\n');time.sleep(.5);power.write_text(str(ma)+'\n');u.write_text(udc+'\n')
 for _ in range(60):
  if state.read_text().strip()=='configured':return
  time.sleep(.25)
 raise RuntimeError('USB configuration did not return')
def stop(*args):raise RuntimeError('Probe stopped')
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
start=time.monotonic();save()
try:
 sample('baseline-100mA');rebind(500);write(34);sample('500mA-original-brightness')
 for _ in range(4):time.sleep(5);sample('500mA-original-brightness')
 brightness.write_text('800\n')
 for _ in range(6):time.sleep(5);sample('500mA-dimmed')
 result['test_completed']=True
except Exception as e:result['error']=str(e)
finally:
 try:
  write(2);brightness.write_text(str(old_brightness)+'\n');rebind(100);result['restored']=True
 except Exception as e:result['restore_error']=str(e)
 result['active_battery_charge_code_unchanged']=read(0x4c6)==60;save();os.close(fd)

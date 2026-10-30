#!/usr/bin/python3
"""Conservative J81 USB-host input policy; never alters battery charge/voltage limits."""
from pathlib import Path
import argparse,ctypes,json,os,signal,time

def target_code(configured,request_ma,temp,voltage):
    if configured and request_ma==500 and isinstance(temp,int) and 100<=temp<380 and isinstance(voltage,int) and 3400000<voltage<4220000:
        return 34  # D2207 75 + floor((100*34+7)/8) = 500 mA.
    return 2       # Original 100 mA input budget.

class Charger:
    def __init__(self):
        if os.getuid()!=0 or b'apple,j81\0' not in Path('/proc/device-tree/compatible').read_bytes():raise RuntimeError('J81 administrator required')
        if os.uname().release!='7.3.0-rc1-orchard-j81-storage-ro-v2mod':raise RuntimeError('Unqualified kernel; review the PMIC policy first')
        if {p.name for p in Path('/sys/class/power_supply').iterdir()}!={'battery'}:raise RuntimeError('Another power-supply driver may own charging; no raw policy access')
        if b'apple,arabela-pmic\0' not in Path('/sys/bus/i2c/devices/0-003c/of_node/compatible').read_bytes():raise RuntimeError('Wrong PMIC')
        if Path('/sys/bus/i2c/devices/0-003c/driver').resolve().name!='simple-mfd-i2c':raise RuntimeError('Unexpected PMIC owner')
        class Msg(ctypes.Structure):_fields_=[('addr',ctypes.c_uint16),('flags',ctypes.c_uint16),('length',ctypes.c_uint16),('buffer',ctypes.POINTER(ctypes.c_uint8))]
        class Transfer(ctypes.Structure):_fields_=[('messages',ctypes.POINTER(Msg)),('count',ctypes.c_uint32)]
        self.Msg,self.Transfer=Msg,Transfer
        self.libc=ctypes.CDLL(None,use_errno=True);self.libc.ioctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_void_p]
        self.fd=os.open('/dev/i2c-0',os.O_RDWR|os.O_CLOEXEC)
    def transfer(self,msgs,count):
        d=self.Transfer(msgs,count)
        if self.libc.ioctl(self.fd,0x707,ctypes.byref(d))!=count:raise OSError(ctypes.get_errno(),'D2207 transfer failed')
    def read(self,reg):
        if reg not in [0x10,0x4c0,0x4c6,0x4c7,0x4cf]:raise ValueError('Register not allowlisted')
        tx=(ctypes.c_uint8*2)(reg>>8,reg&255);rx=(ctypes.c_uint8*1)()
        self.transfer((self.Msg*2)(self.Msg(0x3c,0,2,tx),self.Msg(0x3c,1,1,rx)),2)
        return int(rx[0])
    def write_input(self,code):
        if code not in [2,34]:raise ValueError('Only 100/500 mA input limits allowed')
        before=self.read(0x4c0)
        if before not in [2,34]:raise RuntimeError('Input register now belongs to another policy')
        if before==code:return
        tx=(ctypes.c_uint8*3)(4,0xc0,code)
        self.transfer((self.Msg*1)(self.Msg(0x3c,0,3,tx)),1)
        if self.read(0x4c0)!=code:raise RuntimeError('Input register read-back failed')
    def close(self):os.close(self.fd)

def serve():
    charger=Charger();g=Path('/sys/kernel/config/usb_gadget/j81-storage-ro');udc_file=g/'UDC';power=g/'configs/c.1/MaxPower'
    udc=udc_file.read_text().strip()
    if udc!='20c100000.usbdev':raise RuntimeError('Unexpected J81 USB controller')
    state=Path('/sys/class/udc')/udc/'state'
    old_request=int(power.read_text())
    if old_request not in [100,500] or charger.read(0x4c0) not in [2,34]:raise RuntimeError('Unexpected USB/input budget')
    if charger.read(0x10)&4 or charger.read(0x4c6)&63!=60:raise RuntimeError('Unexpected suspend/active-charge state; no change')
    changed_descriptor=False
    def stop(*args):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        if old_request==100:
            # Announce the USB 2.0 budget before allowing the PMIC to draw it.
            udc_file.write_text('\n');power.write_text('500\n');udc_file.write_text(udc+'\n');changed_descriptor=True
            for _ in range(60):
                if state.read_text().strip()=='configured':break
                time.sleep(.25)
            else:raise RuntimeError('Host did not configure the 500mA request')
        runtime=Path('/run/j81');runtime.mkdir(exist_ok=True)
        while True:
            b=Path('/sys/class/power_supply/battery')
            try:telemetry={k:int((b/k).read_text()) for k in ['temp','voltage_now','current_now','capacity']}
            except (OSError,ValueError):telemetry={}
            configured=state.read_text().strip()=='configured';request=int(power.read_text())
            code=target_code(configured,request,telemetry.get('temp'),telemetry.get('voltage_now'))
            if charger.read(0x10)&4:code=2
            charger.write_input(code)
            report={'usb_configured':configured,'advertised_budget_ma':request,'input_limit_ma':500 if code==34 else 100,'battery':telemetry,'battery_telemetry_may_be_cached':True,'physical_charge_voltage_and_charge_current_unchanged':True,'other_power_sources_qualified':False}
            tmp=runtime/'usb-charge-policy.tmp';tmp.write_text(json.dumps(report,indent=2)+'\n');tmp.replace(runtime/'usb-charge-policy.json')
            time.sleep(2)
    finally:
        try:charger.write_input(2)
        finally:
            # Roll back a failed descriptor negotiation; successful stop keeps
            # an advertised 500mA ceiling while drawing only the original 100mA.
            if changed_descriptor and state.read_text().strip()!='configured':
                udc_file.write_text('\n');power.write_text(str(old_request)+'\n');udc_file.write_text(udc+'\n')
            charger.close()

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--serve-usb-500ma',action='store_true');a=p.parse_args()
    if a.serve_usb_500ma:
        try:serve()
        except KeyboardInterrupt:pass
    else:
        c=Charger()
        try:print(json.dumps({f'{reg:04x}':c.read(reg) for reg in [0x10,0x4c0,0x4c6,0x4c7,0x4cf]},indent=2))
        finally:c.close()

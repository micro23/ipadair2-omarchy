"""Read the physical identity descriptor without an optional LANGID-table query."""
def read_identity(flow, legacy, device, *, expected=None, pongo=False):
 try:
  serial=flow._util.get_string(device,device.iSerialNumber,langid=0x0409)
 except flow._core.USBError as error:
  raise legacy.BootError('USB identity descriptor was unavailable; no payload sent. Reconnect and inspect the current mode.') from error
 return legacy.check_j81(legacy.parse_usb_identity(serial),expected,pongo=pongo)

"""Read-only USB identity queries using macOS usbmuxd and lockdownd.

Equivalent to the public-key queries made by ideviceinfo --simple. No pairing,
StartSession, service launch, filesystem access, or device mutation is performed.
Protocol references and tests ship with the app source.
"""
from __future__ import annotations

import plistlib
import re
import socket
import struct
import time

_SOCKET_PATH = "/var/run/usbmuxd"
_MAX_PACKET = 1024 * 1024
_LABEL = "J81OmarchyLauncher"


class IdentificationError(RuntimeError):
    """A connected normal-mode device could not be identified safely."""


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise IdentificationError("Timed out while reading the iPad identity. Unlock it and reconnect its USB cable.")
    return remaining


def _recv_exact(sock, count, deadline):
    if not 0 <= count <= _MAX_PACKET:
        raise IdentificationError("The Apple device service returned an invalid packet length.")
    chunks = []
    while count:
        sock.settimeout(_remaining(deadline))
        part = sock.recv(count)
        if not part:
            raise IdentificationError("The iPad identity connection closed. Unlock it and reconnect its USB cable.")
        chunks.append(part)
        count -= len(part)
    return b"".join(chunks)


def _plist(data):
    try:
        value = plistlib.loads(data)
    except (ValueError, TypeError, plistlib.InvalidFileException, OverflowError) as exc:
        raise IdentificationError("The Apple device service returned an unreadable identity response.") from exc
    if not isinstance(value, dict):
        raise IdentificationError("The Apple device service returned an invalid identity response.")
    return value


def _connect(path, deadline):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.settimeout(_remaining(deadline))
        sock.connect(path)
        return sock
    except BaseException:
        sock.close()
        raise


def _mux_request(sock, message, tag, deadline):
    request = {
        "BundleID": "org.j81.omarchy-launcher",
        "ClientVersionString": "J81 Omarchy Launcher 1.0",
        "ProgName": _LABEL,
        "kLibUSBMuxVersion": 3,
        **message,
    }
    payload = plistlib.dumps(request, fmt=plistlib.FMT_XML, sort_keys=False)
    sock.settimeout(_remaining(deadline))
    sock.sendall(struct.pack("<IIII", len(payload) + 16, 1, 8, tag) + payload)
    size, version, kind, response_tag = struct.unpack("<IIII", _recv_exact(sock, 16, deadline))
    if not 16 <= size <= _MAX_PACKET or version != 1 or kind != 8 or response_tag != tag:
        raise IdentificationError("The macOS USB service returned an unexpected reply.")
    response = _plist(_recv_exact(sock, size - 16, deadline))
    if "Number" in response and (type(response["Number"]) is not int or response["Number"] != 0):
        raise IdentificationError("The macOS USB service could not connect to the iPad. Unlock it and reconnect the cable.")
    return response


def _lockdown_request(sock, request, deadline):
    payload = plistlib.dumps({"Label": _LABEL, **request}, fmt=plistlib.FMT_XML, sort_keys=False)
    sock.settimeout(_remaining(deadline))
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    size = struct.unpack(">I", _recv_exact(sock, 4, deadline))[0]
    if not 1 <= size <= _MAX_PACKET:
        raise IdentificationError("The iPad returned an invalid identity packet length.")
    response = _plist(_recv_exact(sock, size, deadline))
    if response.get("Request") != request["Request"] or "Error" in response:
        raise IdentificationError("The iPad did not allow its identity to be read. Unlock it, approve Trust if macOS asks, then retry.")
    return response


def identify_normal(timeout=10.0, *, _socket_path=_SOCKET_PATH):
    """Return one USB-connected device's public identity, or None if none exists.

    Network devices are ignored. More than one USB device, incomplete identity,
    nonpositive ECID, service errors, and malformed replies fail closed. The
    caller MUST compare product_type and hardware_model against its target.
    udid and ecid are private identifiers; callers should not display or log them.
    """
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
        raise ValueError("timeout must be between 0 and 30 seconds")
    deadline = time.monotonic() + timeout
    try:
        with _connect(_socket_path, deadline) as sock:
            reply = _mux_request(sock, {"MessageType": "ListDevices"}, 1, deadline)
        entries = reply.get("DeviceList")
        if not isinstance(entries, list) or len(entries) > 128:
            raise IdentificationError("The macOS USB device list was not valid.")
        usb = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("Properties"), dict):
                raise IdentificationError("The macOS USB device list contained an invalid entry.")
            if entry["Properties"].get("ConnectionType") == "USB":
                usb.append(entry)
        if not usb:
            return None
        if len(usb) != 1:
            raise IdentificationError("Connect only the Wi-Fi iPad Air 2. Unplug other USB-connected iPhones or iPads, then retry.")
        entry = usb[0]
        device_id = entry.get("DeviceID", entry["Properties"].get("DeviceID"))
        udid = entry["Properties"].get("SerialNumber")
        if type(device_id) is not int or not 0 < device_id <= 0xFFFFFFFF:
            raise IdentificationError("The macOS USB service did not return a valid device handle.")
        if not isinstance(udid, str) or not re.fullmatch(r"[A-Za-z0-9-]{8,128}", udid):
            raise IdentificationError("The macOS USB service did not return a valid device identifier.")
        with _connect(_socket_path, deadline) as sock:
            connected = _mux_request(sock, {"MessageType": "Connect", "DeviceID": device_id, "PortNumber": socket.htons(62078)}, 2, deadline)
            if connected.get("MessageType") != "Result" or type(connected.get("Number")) is not int or connected["Number"] != 0:
                raise IdentificationError("The macOS USB service did not confirm the iPad connection.")
            kind = _lockdown_request(sock, {"Request": "QueryType"}, deadline)
            if kind.get("Type") != "com.apple.mobile.lockdown":
                raise IdentificationError("The connected device did not identify its Apple device service.")
            values = {}
            for key in ("ProductType", "HardwareModel", "ProductVersion", "UniqueChipID"):
                values[key] = _lockdown_request(sock, {"Request": "GetValue", "Key": key}, deadline).get("Value")
        for key in ("ProductType", "HardwareModel"):
            if not isinstance(values[key], str) or not re.fullmatch(r"[A-Za-z0-9,._-]{1,64}", values[key]):
                raise IdentificationError("The iPad returned an incomplete model identity.")
        if not isinstance(values["ProductVersion"], str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", values["ProductVersion"]):
            raise IdentificationError("The iPad returned an incomplete operating-system version.")
        ecid = values["UniqueChipID"]
        if type(ecid) is not int or not 0 < ecid <= 0xFFFFFFFFFFFFFFFF:
            raise IdentificationError("The iPad did not return a valid chip identity. Unlock it and retry.")
        return {"product_type": values["ProductType"], "hardware_model": values["HardwareModel"],
                "product_version": values["ProductVersion"], "ecid": ecid,
                "udid": udid, "device_id": device_id}
    except IdentificationError:
        raise
    except (OSError, TimeoutError) as exc:
        raise IdentificationError("Could not read the iPad identity through macOS USB. Connect and unlock the iPad, then retry.") from exc

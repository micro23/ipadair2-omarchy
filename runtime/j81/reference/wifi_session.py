"""Guarded Wi-Fi control for the J81 experimental RAM kernel.

The Mac caller supplies the private boot nonce and the device's own ADT MAC.
Only the already-running Linux USB shell is used; this module cannot boot an
image. Public reports deliberately omit network and unique device identities.
"""
from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

KERNEL = "7.3.0-rc1-j81-wifi-ram"
TOOLS = "/run/j81-wifi-tools/run-tool"
WPA_BINARY = "/run/j81-wifi-tools/bin/wpa_supplicant"
TABLE = "j81_wifi_test"
CHAIN = "usb_shell_only"
FILTER_COMMENT = "J81 WiFi RAM test USB shell"
BB = "/bin/busybox"
MAX_SCAN = 200000


class WifiError(RuntimeError):
    """A safe, static user-facing diagnostic; never contains command output."""


def mac_hex(value):
    if isinstance(value, bytes):
        if len(value) != 6:
            raise WifiError("The private device MAC has an invalid length.")
        value = value.hex()
    if not isinstance(value, str):
        raise WifiError("The private device MAC has an invalid format.")
    compact = value.lower().replace(":", "")
    if not re.fullmatch(r"[0-9a-f]{12}", compact):
        raise WifiError("The private device MAC has an invalid format.")
    raw = bytes.fromhex(compact)
    if not any(raw) or raw[0] & 1:
        raise WifiError("The private device MAC is not a valid unicast address.")
    return compact


def interface_name(value):
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", value)
            or value in ("lo", "sit0")):
        raise WifiError("The Linux network interface name is not supported.")
    return value


def derive_wpa2_psk(ssid, passphrase):
    """Caller must collect passphrase with getpass only on a real local TTY."""
    if not isinstance(ssid, bytes) or not 1 <= len(ssid) <= 32:
        raise WifiError("The network name must contain 1 to 32 bytes.")
    if not isinstance(passphrase, str):
        raise WifiError("Enter a WPA2 Personal passphrase locally on the Mac.")
    raw = passphrase.encode("utf-8")
    if not 8 <= len(raw) <= 63 or any(c < 32 or c == 127 for c in raw):
        raise WifiError("This test requires an 8 to 63 byte WPA2 Personal passphrase without control characters.")
    return hashlib.pbkdf2_hmac("sha1", raw, ssid, 4096, 32).hex()


def decode_iw_ssid(text):
    data = bytearray()
    index = 0
    while index < len(text):
        if text[index:index + 2] == "\\x":
            token = text[index + 2:index + 4]
            if len(token) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", token):
                raise WifiError("The scan returned an unsupported network-name encoding.")
            data.append(int(token, 16))
            index += 4
        else:
            code = ord(text[index])
            if not 32 <= code < 127 or text[index] == "\\":
                raise WifiError("The scan returned an unsupported network-name encoding.")
            data.append(code)
            index += 1
    if len(data) > 32:
        raise WifiError("The scan returned an oversized network name.")
    return bytes(data)


def display_ssid(ssid):
    # Escape controls, terminal sequences and non-ASCII bytes for the local menu.
    return json.dumps(ssid.decode("utf-8", "backslashreplace"), ensure_ascii=True)[1:-1]


def dns_ipv4_answer(text):
    """Accept a public A answer only after the queried hostname's Name line."""
    if not isinstance(text, str) or len(text) > 16000:
        raise WifiError("The bounded DNS result was not readable.")
    sections = re.split(r"(?im)^Name:\s*example\.com\.?\s*$", text)
    if len(sections) != 2:
        return None
    for value in re.findall(r"(?m)^Address(?:\s+[0-9]+)?:\s*([0-9]+(?:\.[0-9]+){3})(?:\s|$)", sections[1]):
        try:
            address = ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            continue
        if address.is_global:
            return str(address)
    return None


def parse_scan(text):
    if not isinstance(text, str) or len(text) >= MAX_SCAN:
        raise WifiError("The scan output was incomplete or exceeded its limit.")
    networks = {}
    for block in re.split(r"(?m)^BSS ", text)[1:]:
        ssid_match = re.findall(r"(?m)^\s*SSID: (.*)$", block)
        if len(ssid_match) != 1:
            continue
        ssid = decode_iw_ssid(ssid_match[0])
        if not ssid:
            continue
        signal = re.search(r"(?m)^\s*signal: (-?[0-9]+(?:\.[0-9]+)?) dBm\s*$", block)
        frequency = re.search(r"(?m)^\s*freq: ([0-9]{4})\s*$", block)
        strength = float(signal.group(1)) if signal else None
        if strength is not None and not -150 <= strength <= 0:
            strength = None
        mhz = int(frequency.group(1)) if frequency else None
        rsn = re.search(r"(?m)^\s*RSN:\s*\n((?:^\s+\*.*(?:\n|$))+)", block)
        supported = False
        if rsn:
            body = rsn.group(1)
            pairwise = re.search(r"Pairwise ciphers:([^\n]*)", body)
            group = re.search(r"Group cipher:([^\n]*)", body)
            auth = re.search(r"Authentication suites:([^\n]*)", body)
            supported = bool(pairwise and group and auth
                             and "CCMP" in pairwise.group(1).split()
                             and group.group(1).strip() == "CCMP"
                             and "PSK" in auth.group(1).split()
                             and "MFP-required" not in body)
        candidate = {"ssid": ssid, "display": display_ssid(ssid), "signal_dbm": strength,
                     "frequency_mhz": mhz, "wpa2_psk_ccmp": supported}
        previous = networks.get(ssid)
        if (previous is None or (supported and not previous["wpa2_psk_ccmp"])
                or supported == previous["wpa2_psk_ccmp"] and (strength or -151) > (previous["signal_dbm"] or -151)):
            networks[ssid] = candidate
    return sorted(networks.values(), key=lambda x: (not x["wpa2_psk_ccmp"], -(x["signal_dbm"] or -151), x["ssid"]))


def filter_expressions(usb_interface):
    interface_name(usb_interface)
    return [
        {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": usb_interface}},
        {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "tcp"}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 23}},
        {"drop": None},
    ]


def filter_transaction(usb_interface):
    return {"nftables": [
        {"add": {"table": {"family": "inet", "name": TABLE}}},
        {"add": {"chain": {"family": "inet", "table": TABLE, "name": CHAIN,
                            "type": "filter", "hook": "input", "prio": -300, "policy": "accept"}}},
        {"add": {"rule": {"family": "inet", "table": TABLE, "chain": CHAIN,
                           "expr": filter_expressions(usb_interface), "comment": FILTER_COMMENT}}},
    ]}


def verify_filter(value, usb_interface):
    if not isinstance(value, dict) or set(value) != {"nftables"} or not isinstance(value["nftables"], list):
        raise WifiError("The USB-shell protection could not be verified.")
    entries = []
    for item in value["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            raise WifiError("The USB-shell protection contains unexpected data.")
        kind, data = next(iter(item.items()))
        if kind == "metainfo":
            continue
        if kind not in ("table", "chain", "rule") or not isinstance(data, dict):
            raise WifiError("The USB-shell protection contains unexpected objects.")
        cleaned = dict(data)
        if "handle" in cleaned:
            if type(cleaned.pop("handle")) is not int:
                raise WifiError("The USB-shell protection has an invalid handle.")
        entries.append((kind, cleaned))
    expected = [
        ("table", {"family": "inet", "name": TABLE}),
        ("chain", {"family": "inet", "table": TABLE, "name": CHAIN,
                   "type": "filter", "hook": "input", "prio": -300, "policy": "accept"}),
        ("rule", {"family": "inet", "table": TABLE, "chain": CHAIN,
                  "expr": filter_expressions(usb_interface), "comment": FILTER_COMMENT}),
    ]
    # nft may serialize the well-known TCP protocol as its numeric value.
    for kind, data in entries:
        if kind == "rule" and isinstance(data.get("expr"), list):
            for expression in data["expr"]:
                match = expression.get("match", {}) if isinstance(expression, dict) else {}
                if match.get("left") == {"meta": {"key": "l4proto"}} and match.get("right") == 6:
                    match["right"] = "tcp"
            # nft's readback removes the explicit TCP dependency when the typed
            # tcp dport predicate already supplies it. Accept only that exact
            # canonical form; raw offsets or other protocols remain rejected.
            canonical = filter_expressions(usb_interface)
            if data["expr"] == [canonical[0], canonical[2], canonical[3]]:
                data["expr"] = canonical
    if entries != expected:
        raise WifiError("An unexpected existing J81 firewall table was found. No Wi-Fi interface was activated.")
    return True


class Session:
    def __init__(self, shell_class, run_id, expected_mac, private_directory=None):
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise WifiError("The private Wi-Fi run identifier is invalid.")
        self.shell_class = shell_class
        self.run_id = run_id
        self.expected_mac = mac_hex(expected_mac)
        self.work = "/run/j81-wifi-session/" + run_id
        self.private_directory = Path(private_directory) if private_directory is not None else None
        self.interface = None
        self.usb_interface = None
        self.results = {"kernel_verified": False, "pci_device_found": False, "driver_bound": False,
                        "dt_mac_matches": False, "netdev_mac_matches": False, "firmware_message_seen": False,
                        "usb_shell_isolation": False, "scan_completed": False, "networks_seen": 0,
                        "supported_networks_seen": 0, "association": "not tested in this report", "dhcp": "not tested in this report",
                        "wifi_route": False, "internet_ping": "not attempted", "dns": "not attempted",
                        "http": "not attempted", "disconnected": False}

    def guard(self):
        return "\n".join([
            "set -eu", "set -f", "export LC_ALL=C", "umask 077",
            '[ "${HISTFILE:-}" = /dev/null ]',
            '[ "$(uname -r)" = ' + "'" + KERNEL + "' ]",
            "tr '\\000' '\\n' </proc/device-tree/compatible | grep -Fqx 'apple,j81'",
            "tr '\\000' '\\n' </proc/device-tree/compatible | grep -Fqx 'apple,t7001'",
            "awk '$2 == \"/run\" && $3 == \"tmpfs\" {found=1} END {exit !found}' /proc/mounts",
            "[ \"$(tr ' ' '\\n' </proc/cmdline | grep -c '^j81.wifi_run=')\" = 1 ]",
            "tr ' ' '\\n' </proc/cmdline | grep -Fqx 'j81.wifi_run=" + self.run_id + "'",
            '[ "$(cat /proc/sys/net/ipv4/ip_forward)" = 0 ]',
        ])

    def _run(self, body, *, seconds=15, limit=70000, error="The guarded Wi-Fi command did not complete."):
        command = self.guard() + "\n" + body
        # The confirmed BusyBox interactive shell accepts at most 1024 bytes
        # per input line. Leave room for its prompt/editing bookkeeping.
        if any(len(line.encode("utf-8")) > 900 for line in command.splitlines()):
            raise WifiError("The Wi-Fi helper exceeded its safe shell line limit. No command was sent.")
        shell = None
        try:
            shell = self.shell_class()
            output, status = shell.run(command, seconds=seconds, check=False)
        except (OSError, RuntimeError, ValueError) as exc:
            raise WifiError("The Wi-Fi test USB shell was interrupted. Keep the iPad running and retry collection.") from exc
        finally:
            if shell is not None:
                with contextlib.suppress(OSError):
                    shell.close()
        if not isinstance(output, str) or len(output) > limit:
            raise WifiError("The private Wi-Fi command exceeded its output limit.")
        if status:
            raise WifiError(error)
        self.results["kernel_verified"] = True
        return output

    def _private_save(self, name, text):
        if self.private_directory is None:
            return
        folder = self.private_directory
        folder.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = folder.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise WifiError("The private Wi-Fi log folder has unexpected permissions.")
        path = folder / (name + "-" + secrets.token_hex(6) + ".txt")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)

    def inspect(self):
        self.interface = None
        for key in ("kernel_verified", "pci_device_found", "driver_bound", "dt_mac_matches", "netdev_mac_matches", "firmware_message_seen"):
            self.results[key] = False
        script = r'''printf 'J81_WIFI_INSPECT_BEGIN\n'
alias=$(tr -d '\000' </proc/device-tree/aliases/wifi0)
case "$alias" in /soc/pcie@610000000/pci@1,0/network@0,0) ;; *) exit 1;; esac
printf 'DT_MAC='
/bin/busybox od -An -tx1 -v "/proc/device-tree$alias/local-mac-address" | tr -d ' \n'
printf '\n'
pci=/sys/bus/pci/devices/0000:01:00.0
if [ -d "$pci" ]; then
  printf 'PCI_VENDOR='; cat "$pci/vendor"
  printf 'PCI_DEVICE='; cat "$pci/device"
  driver=$(readlink -f "$pci/driver" || true)
  printf 'PCI_DRIVER=%s\n' "${driver##*/}"
fi
n=0
set +f
for d in /sys/class/net/*; do
  [ -d "$d/phy80211" ] || continue
  n=$((n+1)); [ "$n" -le 8 ] || exit 1
  printf 'IFACE=%s\n' "${d##*/}"
  printf 'NET_MAC='; cat "$d/address"
  device=$(readlink -f "$d/device")
  printf 'NET_PCI=%s\n' "${device##*/}"
  ofnode=$(readlink -f "$d/device/of_node")
  expected=$(readlink -f "/proc/device-tree$alias")
  [ "$ofnode" = "$expected" ] && printf 'OF_MATCH=yes\n' || printf 'OF_MATCH=no\n'
done
set -f
printf 'COUNT=%s\nJ81_WIFI_INSPECT_END\n' "$n"
printf 'J81_WIFI_LOG_BEGIN\n'
dmesg | tail -c 60000
printf '\nJ81_WIFI_LOG_END\n'
'''
        output = self._run(script, seconds=15)
        self._private_save("kernel", output)
        match = re.search(r"(?m)^J81_WIFI_INSPECT_BEGIN\n([\s\S]*?)^J81_WIFI_INSPECT_END$", output)
        if not match:
            raise WifiError("The Wi-Fi status record was incomplete.")
        values = {}
        for line in match.group(1).splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in ("DT_MAC", "PCI_VENDOR", "PCI_DEVICE", "PCI_DRIVER", "IFACE", "NET_MAC", "NET_PCI", "OF_MATCH", "COUNT"):
                raise WifiError("The Wi-Fi status record contained unexpected fields.")
            values.setdefault(key, []).append(value)
        dt = values.get("DT_MAC", [])
        self.results["dt_mac_matches"] = len(dt) == 1 and dt[0] == self.expected_mac
        self.results["pci_device_found"] = values.get("PCI_VENDOR") == ["0x14e4"] and values.get("PCI_DEVICE") == ["0x43a3"]
        self.results["driver_bound"] = values.get("PCI_DRIVER") == ["brcmfmac"]
        self.results["firmware_message_seen"] = bool(re.search(r"brcmfmac[^\n]*Firmware: BCM4350", output))
        self.interface = None
        self.results["netdev_mac_matches"] = False
        if (values.get("COUNT") == ["1"] and len(values.get("IFACE", [])) == 1
                and values.get("NET_PCI") == ["0000:01:00.0"] and values.get("OF_MATCH") == ["yes"]):
            iface = interface_name(values["IFACE"][0])
            addresses = values.get("NET_MAC", [])
            if len(addresses) == 1:
                try:
                    matching = mac_hex(addresses[0]) == self.expected_mac
                except WifiError:
                    matching = False
                self.results["netdev_mac_matches"] = matching
                if matching:
                    self.interface = iface
        ready = bool(self.interface and self.results["pci_device_found"] and self.results["driver_bound"]
                     and self.results["dt_mac_matches"] and self.results["netdev_mac_matches"])
        return {**self.results, "ready": ready, "interface": self.interface}

    def _proof(self):
        if self.interface is None:
            raise WifiError("The radio interface and device MAC have not been verified.")
        iface = interface_name(self.interface)
        return "\n".join([
            "[ '" + iface + "' != 'usb0' ]",
            "[ \"$(cat /sys/class/net/" + iface + "/address | tr -d ':\\n')\" = '" + self.expected_mac + "' ]",
            "[ \"$(cat /sys/class/net/" + iface + "/device/vendor)\" = '0x14e4' ]",
            "[ \"$(cat /sys/class/net/" + iface + "/device/device)\" = '0x43a3' ]",
            "[ \"$(readlink -f /sys/class/net/" + iface + "/device/driver)\" = '/sys/bus/pci/drivers/brcmfmac' ]",
            "[ \"$(readlink -f /sys/class/net/" + iface + "/device)\" = \"$(readlink -f /sys/bus/pci/devices/0000:01:00.0)\" ]",
            "[ \"$(readlink -f /sys/class/net/" + iface + "/device/of_node)\" = \"$(readlink -f /proc/device-tree/soc/pcie@610000000/pci@1,0/network@0,0)\" ]",
            "[ \"$(/bin/busybox od -An -tx1 -v /sys/class/net/" + iface + "/device/of_node/local-mac-address | tr -d ' \\n')\" = '" + self.expected_mac + "' ]",
        ])

    def _require_radio(self):
        if not self.inspect()["ready"]:
            raise WifiError("The Wi-Fi driver or this device's MAC handoff is not ready. No network scan or connection was attempted.")

    def _workspace(self):
        return "\n".join([
            "[ ! -L /run/j81-wifi-session ]", "mkdir -p /run/j81-wifi-session",
            "chmod 700 /run/j81-wifi-session", "[ ! -L '" + self.work + "' ]",
            "mkdir -p '" + self.work + "'", "chmod 700 '" + self.work + "'",
            "[ \"$(stat -c %u '" + self.work + "')\" = 0 ]",
        ])

    def ensure_isolation(self):
        self.results["usb_shell_isolation"] = False
        self._require_radio()
        output = self._run(self._proof() + r'''
usbif=$(cat /config/usb_gadget/j81ram/functions/ecm.usb0/ifname)
case "$usbif" in ''|*[!A-Za-z0-9_.-]*) exit 1;; esac
[ "${#usbif}" -le 15 ]
ip -o -4 addr show dev "$usbif" | grep -Fq ' inet 172.16.42.1/24 '
printf 'USBIF=%s\n' "$usbif"
''', error="The USB network interface could not be verified. Wi-Fi remains inactive.")
        match = re.fullmatch(r"\s*USBIF=([A-Za-z0-9][A-Za-z0-9_.-]{0,14})\s*", output)
        if not match:
            raise WifiError("The USB network interface record was invalid.")
        usbif = interface_name(match.group(1))
        if usbif == self.interface:
            raise WifiError("The Wi-Fi and USB interfaces cannot be the same.")
        raw = self._run(self._proof() + "\n" + TOOLS + " nft -j list tables", error="The kernel's USB-shell firewall support is unavailable. No Wi-Fi interface was activated.")
        try:
            tables = json.loads(raw)["nftables"]
        except (ValueError, KeyError, TypeError) as exc:
            raise WifiError("The firewall table inventory could not be read.") from exc
        present = False
        for entry in tables:
            if not isinstance(entry, dict):
                raise WifiError("The firewall table inventory was malformed.")
            item = entry.get("table", {})
            if isinstance(item, dict) and item.get("family") == "inet" and item.get("name") == TABLE:
                if present:
                    raise WifiError("The J81 firewall table inventory was ambiguous.")
                present = True
        if not present:
            transaction = json.dumps(filter_transaction(usbif), separators=(",", ":"))
            body = self._proof() + "\n" + TOOLS + " nft -j -f - <<'J81_FIXED_NFT_RULES'\n" + transaction + "\nJ81_FIXED_NFT_RULES\n"
            self._run(body, error="The USB-shell firewall could not be installed. No Wi-Fi interface was activated.")
        current = self._run(self._proof() + "\n" + TOOLS + " nft -j list table inet " + TABLE,
                            error="The USB-shell firewall could not be read back. No Wi-Fi interface was activated.")
        try:
            verify_filter(json.loads(current), usbif)
        except ValueError as exc:
            raise WifiError("The USB-shell firewall returned invalid verification data.") from exc
        self.usb_interface = usbif
        self.results["usb_shell_isolation"] = True
        return usbif

    def _filter_proof(self):
        if not self.results["usb_shell_isolation"] or self.usb_interface is None:
            raise WifiError("USB-shell isolation must be verified before Wi-Fi activation.")
        return self._proof()

    def scan(self):
        self.ensure_isolation()
        body = self._filter_proof() + "\n" + self._workspace() + "\n" + "\n".join([
            "ip link set dev '" + self.interface + "' up",
            "ulimit -f 512", "[ ! -L '" + self.work + "/scan.txt' ]", "[ ! -L '" + self.work + "/scan-error.txt' ]",
            "timeout -s KILL 25 " + TOOLS + " iw dev '" + self.interface + "' scan >'" + self.work + "/scan.txt' 2>'" + self.work + "/scan-error.txt'",
            "[ \"$(wc -c <'" + self.work + "/scan.txt')\" -lt " + str(MAX_SCAN) + " ]",
            "cat '" + self.work + "/scan.txt'",
        ])
        output = self._run(body, seconds=35, limit=MAX_SCAN, error="The guarded Wi-Fi scan did not complete. No password or connection was attempted.")
        networks = parse_scan(output)
        self.results["scan_completed"] = True
        self.results["networks_seen"] = len(networks)
        self.results["supported_networks_seen"] = sum(n["wpa2_psk_ccmp"] for n in networks)
        return networks

    def _process_functions(self):
        # Every signal requires both exact private arguments and process start
        # ticks. Never use killall, pkill, a reused PID, or another interface.
        return r'''
j81_check_process() {
  kind=$1
  pidfile="$J81_WORK/$kind.pid"
  [ -f "$pidfile" ] && [ ! -L "$pidfile" ] || return 1
  pid=$(cat "$pidfile")
  case "$pid" in ''|*[!0-9]*) return 2;; esac
  [ "$pid" -gt 1 ] && [ -d "/proc/$pid" ] || return 1
  [ -f "$J81_WORK/$kind.start" ] && [ ! -L "$J81_WORK/$kind.start" ] || return 2
  [ "$(awk '{print $22}' "/proc/$pid/stat")" = "$(cat "$J81_WORK/$kind.start")" ] || return 2
  [ "$(awk '{print $3}' "/proc/$pid/stat")" != Z ] || return 1
  args=$(tr '\000' '\n' <"/proc/$pid/cmdline")
  if [ "$kind" = wpa ]; then
    [ "$(printf '%s\n' "$args" | head -n 1)" = /run/j81-wifi-tools/lib/ld-linux-aarch64.so.1 ] || return 2
    [ "$(readlink -f "/proc/$pid/exe")" = /run/j81-wifi-tools/lib/ld-linux-aarch64.so.1 ] || return 2
    printf '%s\n' "$args" | grep -Fqx '/run/j81-wifi-tools/bin/wpa_supplicant' || return 2
    printf '%s\n' "$args" | grep -Fqx -- "-i$J81_IFACE" || return 2
    printf '%s\n' "$args" | grep -Fqx -- "-c$J81_WORK/wpa.conf" || return 2
    printf '%s\n' "$args" | grep -Fqx -- "-P$J81_WORK/wpa.pid" || return 2
  else
    [ "$(readlink -f "/proc/$pid/exe")" = /bin/busybox ] || return 2
    printf '%s\n' "$args" | grep -Fqx 'udhcpc' || return 2
    printf '%s\n' "$args" | grep -Fqx "$J81_IFACE" || return 2
    printf '%s\n' "$args" | grep -Fqx "$J81_WORK/udhcpc-script" || return 2
  fi
  return 0
}
j81_stop_process() {
  kind=$1
  if j81_check_process "$kind"; then
    kill -TERM "$pid"
    n=0
    while [ "$n" -lt 20 ] && [ -d "/proc/$pid" ]; do
      sleep 0.1; n=$((n+1))
    done
    if [ -d "/proc/$pid" ]; then
      if j81_check_process "$kind"; then
        kill -KILL "$pid"
      else
        code=$?
        [ "$code" = 1 ] || return 2
      fi
    fi
  else
    code=$?
    [ "$code" = 1 ] || return 2
  fi
  rm -f "$J81_WORK/$kind.pid" "$J81_WORK/$kind.start"
}
'''

    def _process_environment(self):
        return "J81_WORK='" + self.work + "'\nJ81_IFACE='" + interface_name(self.interface) + "'\n"

    def _dhcp_script(self):
        return "#!/bin/sh\n" + self.guard() + "\n" + self._proof() + "\n" + self._process_environment() + DHCP_BODY

    def connect_wpa2(self, ssid, psk_hex):
        if not isinstance(ssid, bytes) or not 1 <= len(ssid) <= 32:
            raise WifiError("The network name must contain 1 to 32 bytes.")
        if not isinstance(psk_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", psk_hex):
            raise WifiError("A locally derived WPA2 key is required.")
        self.ensure_isolation()
        # Remove only a prior connection owned by this exact nonce/work folder.
        self.disconnect(keep_link=True)
        conf = ("ctrl_interface=" + self.work + "/ctrl\nupdate_config=0\np2p_disabled=1\n"
                "mac_addr=0\npreassoc_mac_addr=0\nap_scan=1\nnetwork={\nssid=" + ssid.hex()
                + "\npsk=" + psk_hex + "\nkey_mgmt=WPA-PSK\nproto=RSN\npairwise=CCMP\n"
                  "group=CCMP\nieee80211w=0\nscan_ssid=1\n}\n")
        def wrapped_base64(text):
            encoded = base64.b64encode(text.encode("ascii")).decode("ascii")
            return "\n".join(encoded[start:start + 76] for start in range(0, len(encoded), 76))
        encoded = wrapped_base64(conf)
        dhcp = wrapped_base64(self._dhcp_script())
        body = self._filter_proof() + "\n" + self._workspace() + "\n" + self._process_environment() + "\n".join([
            "[ ! -L \"$J81_WORK/wpa.conf\" ]", "[ ! -L \"$J81_WORK/udhcpc-script\" ]",
            "[ ! -L \"$J81_WORK/wpa.log\" ]", "mkdir -p \"$J81_WORK/ctrl\"", "chmod 700 \"$J81_WORK/ctrl\"",
            "base64 -d >\"$J81_WORK/wpa.conf\" <<'J81_PRIVATE_WPA_DATA'\n" + encoded + "\nJ81_PRIVATE_WPA_DATA",
            "base64 -d >\"$J81_WORK/udhcpc-script\" <<'J81_PRIVATE_DHCP_DATA'\n" + dhcp + "\nJ81_PRIVATE_DHCP_DATA",
            "chmod 600 \"$J81_WORK/wpa.conf\"", "chmod 700 \"$J81_WORK/udhcpc-script\"",
            "ip link set dev \"$J81_IFACE\" up",
            "ulimit -f 512",
            TOOLS + " wpa_supplicant -B -Dnl80211 \"-i$J81_IFACE\" \"-c$J81_WORK/wpa.conf\" \"-P$J81_WORK/wpa.pid\" \"-f$J81_WORK/wpa.log\" >/dev/null 2>&1",
            "n=0; while [ ! -s \"$J81_WORK/wpa.pid\" ] && [ \"$n\" -lt 30 ]; do sleep 0.1; n=$((n+1)); done",
            "pid=$(cat \"$J81_WORK/wpa.pid\")", "case \"$pid\" in ''|*[!0-9]*) exit 1;; esac",
            "[ \"$pid\" -gt 1 ] && [ -r \"/proc/$pid/stat\" ]", "awk '{print $22}' \"/proc/$pid/stat\" >\"$J81_WORK/wpa.start\"",
        ])
        self.results["association"] = "pending"
        try:
            self._run(body, seconds=15, error="The private WPA2 connection process could not start. No credential is included in this error.")
        except WifiError as original:
            self.results["association"] = "not completed"
            cleanup_failed = False
            try:
                self.disconnect()
            except WifiError:
                cleanup_failed = True
            with contextlib.suppress(WifiError):
                self._run(self._proof() + "\nrm -f '" + self.work + "/wpa.conf'")
            if cleanup_failed:
                raise WifiError("WPA2 startup stopped, and owned-process cleanup could not be confirmed. Keep the iPad running and save the report.") from original
            raise
        try:
            status_body = self._proof() + "\n" + self._process_environment() + self._process_functions() + "\n" + \
                'j81_check_process wpa\n' + TOOLS + ' wpa_cli -p "$J81_WORK/ctrl" -i "$J81_IFACE" status\n'
            completed = False
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                output = self._run(status_body, seconds=8, limit=16000, error="The private WPA2 status could not be read.")
                fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
                if fields.get("wpa_state") == "COMPLETED":
                    if fields.get("key_mgmt") != "WPA2-PSK":
                        raise WifiError("The connection did not report the required WPA2 Personal mode.")
                    completed = True
                    break
                time.sleep(1)
            if not completed:
                raise WifiError("WPA2 association did not finish. Check the locally selected network and password; no credential is included in this report.")
            self.results["association"] = "completed (WPA2 Personal)"
            self._run(self._proof() + "\nrm -f '" + self.work + "/wpa.conf'", error="The temporary WPA2 configuration could not be removed.")
            self._request_dhcp()
            self.connectivity()
            self.results["disconnected"] = False
            return dict(self.results)
        except WifiError as original:
            if self.results["association"] == "pending":
                self.results["association"] = "not completed"
            try:
                self.disconnect()
            except WifiError:
                raise WifiError("The Wi-Fi attempt stopped, and owned-process cleanup could not be confirmed. Keep the iPad running and save the report.") from original
            raise

    def _request_dhcp(self):
        body = self._proof() + "\n" + self._process_environment() + self._process_functions() + r'''
j81_check_process wpa
[ ! -L "$J81_WORK/dhcp.log" ]
[ ! -e "$J81_WORK/dhcp.pid" ] && [ ! -e "$J81_WORK/dhcp.start" ]
# -f keeps the PID stable across the first lease and every renewal. Ignore
# terminal hangup, with no terminal input/output inherited by this worker.
(trap '' HUP; ulimit -f 512; exec /bin/busybox udhcpc -f -i "$J81_IFACE" -p "$J81_WORK/dhcp.pid" -s "$J81_WORK/udhcpc-script" -n -t 4 -T 3) </dev/null >"$J81_WORK/dhcp.log" 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$J81_WORK/dhcp.pid"
[ "$pid" -gt 1 ] && [ -r "/proc/$pid/stat" ]
awk '{print $22}' "/proc/$pid/stat" >"$J81_WORK/dhcp.start"
# Allow the just-forked shell to exec BusyBox before checking its exact argv.
n=0
while [ "$n" -lt 30 ]; do
  if j81_check_process dhcp; then break; fi
  sleep 0.1; n=$((n+1))
done
j81_check_process dhcp
n=0
while [ "$n" -lt 250 ]; do
  j81_check_process dhcp
  if [ -f "$J81_WORK/address" ] && [ -f "$J81_WORK/lease-ready" ]; then break; fi
  sleep 0.1; n=$((n+1))
done
if [ ! -f "$J81_WORK/address" ] || [ ! -f "$J81_WORK/lease-ready" ]; then
  j81_stop_process dhcp
  exit 1
fi
j81_check_process dhcp
printf 'J81_DHCP_READY\n'
'''
        self.results["dhcp"] = "pending"
        try:
            output = self._run(body, seconds=35, error="DHCP did not complete or its network conflicted with the USB connection. Private logs remain in RAM.")
            if output.strip() != "J81_DHCP_READY":
                raise WifiError("The DHCP completion record was invalid.")
        except BaseException:
            self.results["dhcp"] = "not completed"
            raise
        self.results["dhcp"] = "configured"

    def connectivity(self):
        if self.results["association"] != "completed (WPA2 Personal)" or self.results["dhcp"] != "configured":
            raise WifiError("A verified WPA2 connection and DHCP lease are required for connectivity tests.")
        body = self._proof() + "\n" + self._process_environment() + r'''
ip -4 route get 1.1.1.1 | awk -v wanted="$J81_IFACE" '{for(i=1;i<NF;i++)if($i=="dev"&&$(i+1)==wanted)ok=1}END{exit !ok}'
printf 'ROUTE=wifi\n'
if timeout -s KILL 8 /bin/busybox ping -I "$J81_IFACE" -c 2 -W 2 1.1.1.1 >/dev/null 2>&1; then printf 'PING=pass\n'; else printf 'PING=not-confirmed\n'; fi
printf 'DNS_SERVER='; head -n 1 "$J81_WORK/dns"
'''
        output = self._run(body, seconds=15, limit=2000, error="The Internet route did not use the Wi-Fi interface. Connectivity was not claimed.")
        fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        if set(fields) != {"ROUTE", "PING", "DNS_SERVER"} or fields["ROUTE"] != "wifi" or fields["PING"] not in ("pass", "not-confirmed"):
            raise WifiError("The connectivity result was not recognized.")
        self.results.update(wifi_route=True, internet_ping=fields["PING"], dns="not-confirmed", http="not-confirmed")
        try:
            server = str(ipaddress.IPv4Address(fields["DNS_SERVER"]))
        except ipaddress.AddressValueError:
            return dict(self.results)
        # The resolver request and actual HTTP destination must each use Wi-Fi,
        # preventing a USB route/proxy from producing a false positive.
        route = "ip -4 route get '" + server + "' | awk -v wanted='" + self.interface + "' '{for(i=1;i<NF;i++)if($i==\"dev\"&&$(i+1)==wanted)ok=1}END{exit !ok}'\n"
        try:
            answer = self._run(self._proof() + "\n" + route + "timeout -s KILL 8 /bin/busybox nslookup -type=a example.com '" + server + "'",
                               seconds=12, limit=16000, error="The Wi-Fi DNS test was not confirmed.")
        except WifiError:
            return dict(self.results)
        destination = dns_ipv4_answer(answer)
        if destination is None:
            return dict(self.results)
        self.results["dns"] = "pass"
        route = "ip -4 route get '" + destination + "' | awk -v wanted='" + self.interface + "' '{for(i=1;i<NF;i++)if($i==\"dev\"&&$(i+1)==wanted)ok=1}END{exit !ok}'\n"
        try:
            self._run(self._proof() + "\n" + route + "timeout -s KILL 12 /bin/busybox wget -q -Y off -T 8 --header 'Host: example.com' -O /dev/null 'http://" + destination + "/' >/dev/null 2>&1",
                      seconds=16, limit=1000, error="The Wi-Fi HTTP check was not confirmed.")
        except WifiError:
            return dict(self.results)
        self.results["http"] = "pass"
        return dict(self.results)

    def disconnect(self, *, keep_link=False):
        if self.interface is None:
            return False
        body = self._proof() + "\n" + self._process_environment() + self._process_functions() + r'''
if [ -d "$J81_WORK" ]; then
  [ ! -L "$J81_WORK" ] && [ "$(stat -c %u "$J81_WORK")" = 0 ]
  j81_stop_process dhcp
  j81_stop_process wpa
  if [ -x "$J81_WORK/udhcpc-script" ] && [ ! -L "$J81_WORK/udhcpc-script" ]; then
    interface="$J81_IFACE" "$J81_WORK/udhcpc-script" deconfig
  fi
  rm -f "$J81_WORK/wpa.conf"
fi
'''
        if not keep_link:
            body += '\nip link set dev "$J81_IFACE" down\n'
        self._run(body, seconds=15, error="The owned Wi-Fi connection could not be fully stopped. Other processes were not signalled.")
        if not keep_link:
            self.results["disconnected"] = True
        return True

    def public_report(self):
        yes = lambda key: "yes" if self.results[key] else "no"
        return "\n".join([
            "J81 Wi-Fi RAM test report", "Target: Wi-Fi iPad Air 2 / iPad5,3 / J81AP",
            "Kernel: " + KERNEL, "Collected: " + datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "Kernel and current session verified: " + yes("kernel_verified"),
            "BCM4350 PCI device present: " + yes("pci_device_found"),
            "brcmfmac driver bound: " + yes("driver_bound"),
            "Firmware version message observed: " + yes("firmware_message_seen"),
            "Device-tree MAC matches private Apple hardware record: " + yes("dt_mac_matches"),
            "Wi-Fi interface MAC matches private Apple hardware record: " + yes("netdev_mac_matches"),
            "USB root-shell isolation verified in this command: " + yes("usb_shell_isolation"),
            "Wi-Fi scan completed in this command: " + yes("scan_completed"),
            "Distinct named networks observed: " + str(self.results["networks_seen"]),
            "Supported WPA2 Personal networks observed: " + str(self.results["supported_networks_seen"]),
            "Association: " + self.results["association"], "DHCP: " + self.results["dhcp"],
            "Internet route uses Wi-Fi: " + yes("wifi_route"),
            "Internet ICMP check: " + self.results["internet_ping"],
            "DNS check: " + self.results["dns"], "HTTP connectivity check: " + self.results["http"],
            "Connection explicitly stopped: " + yes("disconnected"),
            "SSID, BSSID, MAC, IP addresses, credentials and session identifiers are omitted.", "",
        ])


DHCP_BODY = r'''
[ "${interface:-}" = "$J81_IFACE" ]
[ ! -L "$J81_WORK" ] && [ -d "$J81_WORK" ] && [ "$(stat -c %u "$J81_WORK")" = 0 ]
ipv4() {
  printf '%s\n' "$1" | awk -F. 'NF != 4 {exit 1} {for(i=1;i<=4;i++) if($i !~ /^[0-9][0-9]?[0-9]?$/ || $i+0>255 || (length($i)>1 && substr($i,1,1)=="0")) exit 1}'
}
remove_owned() {
  if [ -f "$J81_WORK/address" ] && [ ! -L "$J81_WORK/address" ]; then
    old=$(cat "$J81_WORK/address")
    case "$old" in ''|*[!0-9./]*) exit 1;; esac
    ip -4 addr del "$old" dev "$J81_IFACE" 2>/dev/null || true
    ip -4 route del default dev "$J81_IFACE" metric 600 2>/dev/null || true
    rm -f "$J81_WORK/address" "$J81_WORK/lease-ready"
  fi
  if [ -f "$J81_WORK/resolv.ours" ] && [ ! -L /etc/resolv.conf ] && cmp -s "$J81_WORK/resolv.ours" /etc/resolv.conf; then
    if [ -f "$J81_WORK/resolv.before" ]; then cp "$J81_WORK/resolv.before" /etc/resolv.conf; else rm -f /etc/resolv.conf; fi
  fi
}
case "${1:-}" in
deconfig) remove_owned; exit 0;;
bound|renew) ;;
*) exit 0;;
esac
ipv4 "${ip:-}" && ipv4 "${subnet:-}"
prefix=$(printf '%s\n' "$subnet" | awk -F. 'BEGIN {b[255]=8;b[254]=7;b[252]=6;b[248]=5;b[240]=4;b[224]=3;b[192]=2;b[128]=1;b[0]=0} {n=0;partial=0;for(i=1;i<=4;i++){v=$i+0;if(!(v in b)||(partial&&v!=0))exit 1;n+=b[v];if(v!=255)partial=1} if(n<8||n>30)exit 1;print n}')
# Refuse any subnet overlap with the existing point-to-point USB network.
printf '%s %s\n' "$ip" "$prefix" | awk '{split($1,a,".");n=((a[1]*256+a[2])*256+a[3])*256+a[4];block=2^(32-$2);low=int(n/block)*block;high=low+block-1;usb=((172*256+16)*256+42)*256;if(low<=usb+255&&high>=usb)exit 1;if(a[1]==0||a[1]==127||a[1]>=224||n==low||n==high)exit 1}'
router_one=
for candidate in ${router:-}; do
  ipv4 "$candidate" || exit 1
  if [ -z "$router_one" ]; then router_one=$candidate; fi
done
[ -n "$router_one" ]
printf '%s %s %s\n' "$ip" "$router_one" "$prefix" | awk '{split($1,a,".");split($2,b,".");x=((a[1]*256+a[2])*256+a[3])*256+a[4];y=((b[1]*256+b[2])*256+b[3])*256+b[4];n=2^(32-$3);if(int(x/n)!=int(y/n)||x==y||y%n==0||y%n==n-1)exit 1}'
dns_count=0
for server in ${dns:-}; do
  ipv4 "$server" || exit 1
  dns_count=$((dns_count+1)); [ "$dns_count" -le 3 ] || break
done
# Never replace a default route belonging to USB or another interface.
ip -4 route show default | while IFS= read -r line; do
  printf '%s\n' "$line" | awk -v wanted="$J81_IFACE" '{for(i=1;i<NF;i++)if($i=="dev"&&$(i+1)==wanted)ok=1}END{exit !ok}' || exit 1
done
if [ ! -f "$J81_WORK/resolv.saved" ]; then
  [ ! -L /etc/resolv.conf ]
  if [ -f /etc/resolv.conf ]; then
    [ "$(wc -c </etc/resolv.conf)" -le 8192 ]; cp /etc/resolv.conf "$J81_WORK/resolv.before"
  fi
  : >"$J81_WORK/resolv.saved"
fi
if [ -f "$J81_WORK/address" ]; then remove_owned; fi
[ -z "$(ip -o -4 addr show dev "$J81_IFACE" scope global)" ]
ip -4 addr add "$ip/$prefix" dev "$J81_IFACE"
printf '%s/%s\n' "$ip" "$prefix" >"$J81_WORK/address"
ip -4 route add default via "$router_one" dev "$J81_IFACE" metric 600
: >"$J81_WORK/dns"
: >"$J81_WORK/resolv.ours"
dns_count=0
for server in ${dns:-}; do
  dns_count=$((dns_count+1)); [ "$dns_count" -le 3 ] || break
  printf '%s\n' "$server" >>"$J81_WORK/dns"
  printf 'nameserver %s\n' "$server" >>"$J81_WORK/resolv.ours"
done
if [ -s "$J81_WORK/resolv.ours" ]; then
  [ ! -L /etc/resolv.conf ]; cp "$J81_WORK/resolv.ours" /etc/resolv.conf
fi
printf 'ready\n' >"$J81_WORK/lease-ready"
'''

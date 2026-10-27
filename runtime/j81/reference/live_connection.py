"""Read-only proof of the existing, owned J81 Wi-Fi connection.

The caller has already verified the original packages, current boot nonce,
radio MAC and installed tool bytes. This module never installs a filter,
starts a process daemon, changes a link, obtains a lease or disconnects.
"""
from __future__ import annotations

import json
import re


USB_BODY = r'''
usbif=$(cat /config/usb_gadget/j81ram/functions/ecm.usb0/ifname)
case "$usbif" in ''|*[!A-Za-z0-9_.-]*) exit 1;; esac
[ "${#usbif}" -le 15 ]
ip -o -4 addr show dev "$usbif" | grep -Fq ' inet 172.16.42.1/24 '
printf 'USBIF=%s\n' "$usbif"
'''


LIVE_BODY = r'''
[ -d /run/j81-wifi-session ] && [ ! -L /run/j81-wifi-session ]
[ "$(stat -c '%u:%a' /run/j81-wifi-session)" = '0:700' ]
[ -d "$J81_WORK" ] && [ ! -L "$J81_WORK" ]
[ "$(stat -c '%u:%a' "$J81_WORK")" = '0:700' ]
[ -d "$J81_WORK/ctrl" ] && [ ! -L "$J81_WORK/ctrl" ]
[ "$(stat -c '%u' "$J81_WORK/ctrl")" = 0 ]
j81_check_lease() {
  for name in address lease-ready; do
    file="$J81_WORK/$name"
    [ -f "$file" ] && [ ! -L "$file" ] || return 1
    [ "$(stat -c '%u:%a' "$file")" = '0:600' ] || return 1
    [ "$(wc -c <"$file")" -le 64 ] || return 1
    [ "$(wc -l <"$file")" -eq 1 ] || return 1
  done
  [ "$(cat "$J81_WORK/lease-ready")" = ready ] || return 1
  address=$(cat "$J81_WORK/address")
  case "$address" in ''|*[!0-9./]*) return 1;; esac
  # Matching the actual IPv4 address output also validates CIDR syntax.
  ip -o -4 addr show dev "$J81_IFACE" scope global |
    awk -v wanted="$address" '$3=="inet" && $4==wanted {found++} END {exit found!=1}'
}
j81_check_process wpa
j81_check_process dhcp
j81_check_lease
before_address=$address
status=$(@TOOLS@ wpa_cli -p "$J81_WORK/ctrl" -i "$J81_IFACE" status)
[ "${#status}" -le 16000 ]
printf '%s\n' "$status" | awk '
  /^wpa_state=/ {states++; if($0!="wpa_state=COMPLETED") bad=1}
  /^key_mgmt=/ {keys++; if($0!="key_mgmt=WPA2-PSK") bad=1}
  END {exit bad || states!=1 || keys!=1}'
unset status
# Renewal can update the lease files while status is being read. Require
# the current address to remain the one just checked, without renewing it.
j81_check_lease
[ "$address" = "$before_address" ]
j81_check_process wpa
j81_check_process dhcp
printf 'J81_EXISTING_CONNECTION_VERIFIED\n'
'''


def _check_function(session, error_type):
    """Reuse the delivered ownership check without including stop operations."""
    functions = session._process_functions()
    separator = "\nj81_stop_process() {\n"
    if (not functions.startswith("\nj81_check_process() {\n")
            or functions.count(separator) != 1):
        raise error_type("The delivered connection-ownership helper has an unexpected format.")
    return functions.split(separator, 1)[0]


def verify(session, modules):
    """Set fresh success outcomes only after all current-state proofs pass."""
    control = modules.session
    error = control.WifiError
    # Never let a retained successful snapshot become this invocation's proof.
    session.results.update(association="not tested in this report",
                           dhcp="not tested in this report", usb_shell_isolation=False)
    session.usb_interface = None
    interface = control.interface_name(session.interface)
    proof = session._proof()
    output = session._run(proof + "\n" + USB_BODY, seconds=10, limit=256,
        error="The existing USB interface could not be verified. This check did not change the connection.")
    match = re.fullmatch(r"\s*USBIF=([A-Za-z0-9][A-Za-z0-9_.-]{0,14})\s*", output)
    if match is None:
        raise error("The existing USB interface record was not recognized.")
    usb = control.interface_name(match.group(1))
    if usb == interface:
        raise error("The USB and Wi-Fi interface identities unexpectedly match.")
    firewall = session._run(proof + "\n" + control.TOOLS + " nft -j list table inet " + control.TABLE,
        seconds=10, limit=70000,
        error="The existing USB-shell protection could not be read. No firewall change was made.")
    try:
        control.verify_filter(json.loads(firewall), usb)
    except (ValueError, TypeError, error) as exc:
        raise error("The existing USB-shell protection did not match this test. The connection was left unchanged.") from exc
    body = (proof + "\n" + session._process_environment()
            + _check_function(session, error) + "\n"
            + LIVE_BODY.replace("@TOOLS@", control.TOOLS))
    marker = session._run(body, seconds=15, limit=512,
        error="The existing association, owned DHCP client or current lease could not be verified. No reconnection was attempted.")
    if marker.strip() != "J81_EXISTING_CONNECTION_VERIFIED":
        raise error("The existing connection returned an unexpected verification record.")
    session.usb_interface = usb
    session.results.update(association="completed (WPA2 Personal)", dhcp="configured",
                           usb_shell_isolation=True, disconnected=False)

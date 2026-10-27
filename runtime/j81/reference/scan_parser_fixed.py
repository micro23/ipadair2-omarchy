"""Narrow iw 6.17 RSN header parser correction for the verified J81 v1 helper.

Installed only in memory after the launcher verifies the original package.
No boot, upload, network-setting, authentication-mode or credential change.
"""
import re

FIX_ID = "iw-6.17-rsn-first-line-v1"
EXPECTED_KERNEL = "7.3.0-rc1-j81-wifi-ram"

# iw6.17 scan.c prints the IE label without a newline, then the first
# RSN bullet: "\tRSN:\t * Version: 1\n". Later bullets start on new
# indented lines. Permit both this source-proven layout and the older test
# layout, and stop at the next named IE. All v1 security gates are retained.

def parse_scan(text, original):
    if not isinstance(text, str) or len(text) >= original.MAX_SCAN:
        raise original.WifiError("The scan output was incomplete or exceeded its limit.")
    networks = {}
    for block in re.split(r"(?m)^BSS ", text)[1:]:
        ssid_match = re.findall(r"(?m)^\s*SSID: (.*)$", block)
        if len(ssid_match) != 1:
            continue
        ssid = original.decode_iw_ssid(ssid_match[0])
        if not ssid:
            continue
        signal = re.search(r"(?m)^\s*signal: (-?[0-9]+(?:\.[0-9]+)?) dBm\s*$", block)
        frequency = re.search(r"(?m)^\s*freq: ([0-9]{4})\s*$", block)
        strength = float(signal.group(1)) if signal else None
        if strength is not None and not -150 <= strength <= 0:
            strength = None
        mhz = int(frequency.group(1)) if frequency else None
        rsn = re.search(r"(?m)^[ \t]*RSN:[ \t]*(?:\n[ \t]*)?(\*[^\n]*(?:\n[ \t]+\*[^\n]*)*)", block)
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
        candidate = {"ssid": ssid, "display": original.display_ssid(ssid), "signal_dbm": strength,
                     "frequency_mhz": mhz, "wpa2_psk_ccmp": supported}
        previous = networks.get(ssid)
        if (previous is None or (supported and not previous["wpa2_psk_ccmp"])
                or supported == previous["wpa2_psk_ccmp"] and (strength or -151) > (previous["signal_dbm"] or -151)):
            networks[ssid] = candidate
    return sorted(networks.values(), key=lambda x: (not x["wpa2_psk_ccmp"], -(x["signal_dbm"] or -151), x["ssid"]))


def install(original):
    """Replace only original.parse_scan; preserve the verified v1 helpers."""
    if (getattr(original, "KERNEL", None) != EXPECTED_KERNEL
            or getattr(original, "MAX_SCAN", None) != 200000
            or not callable(getattr(original, "decode_iw_ssid", None))
            or not callable(getattr(original, "display_ssid", None))
            or not callable(getattr(original, "parse_scan", None))
            or not isinstance(getattr(original, "WifiError", None), type)
            or not issubclass(original.WifiError, RuntimeError)):
        raise RuntimeError("The verified J81 controller is not compatible with this scan parser correction.")

    def corrected(text):
        return parse_scan(text, original)

    corrected.__name__ = "parse_scan"
    corrected.__doc__ = "J81 v1 scan parser with the iw6.17 same-line RSN header correction."
    original.parse_scan = corrected
    return FIX_ID

"""Narrow correction for BusyBox 1.31.1 nslookup's per-answer Name sections.

Install in memory after the caller verifies the original J81 controller.
No network, filesystem, process or interface actions occur in this module.
"""
import ipaddress
import re

FIX_ID = 'busybox-1.31.1-multiple-a-sections-v1'
EXPECTED_KERNEL = '7.3.0-rc1-j81-wifi-ram'
_NAME = re.compile(r'^Name:[ \t]*(\S+)[ \t]*$', re.IGNORECASE)
_ADDRESS = re.compile(r'^Address(?:[ \t]+[0-9]+)?:[ \t]*([0-9]+(?:\.[0-9]+){3})(?:[ \t]|$)')


def dns_ipv4_answer(text, original):
    """Return a public A answer owned by example.com, never the DNS server."""
    if not isinstance(text, str) or len(text) > 16000:
        raise original.WifiError('The bounded DNS result was not readable.')
    owner_matches = False
    for line in text.splitlines():
        if line.lower().startswith('name:'):
            name = _NAME.fullmatch(line)
            owner_matches = bool(name and name.group(1).lower() in ('example.com', 'example.com.'))
            continue
        if not owner_matches:
            continue
        match = _ADDRESS.match(line)
        if match is None:
            continue
        try:
            address = ipaddress.IPv4Address(match.group(1))
        except ipaddress.AddressValueError:
            continue
        if address.is_global:
            return str(address)
    return None


def install(original):
    """Replace only original.dns_ipv4_answer; leave connectivity logic intact."""
    if (getattr(original, 'KERNEL', None) != EXPECTED_KERNEL
            or not callable(getattr(original, 'dns_ipv4_answer', None))
            or not isinstance(getattr(original, 'WifiError', None), type)
            or not issubclass(original.WifiError, RuntimeError)):
        raise RuntimeError('The verified J81 controller is not compatible with this DNS parser correction.')

    def corrected(text):
        return dns_ipv4_answer(text, original)

    corrected.__name__ = 'dns_ipv4_answer'
    corrected.__doc__ = 'J81 DNS parser with scoped BusyBox multiple-A answer support.'
    original.dns_ipv4_answer = corrected
    return FIX_ID

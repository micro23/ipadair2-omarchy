"""Bounded, fail-closed parsing of the J81 firmware-free radio diagnostic.

Based on pinned Hoolock brcmfmac SYS_VENDOR records, the upstream 0049 bounds
audit, and the J81 0061/0062 probe contract at ipad-nixos b94d42f. Raw ADT and
OTP bytes must remain on the user's Mac. Only selector metadata is returned.
"""
from __future__ import annotations

import base64
import re
import struct
import zlib

TARGET = "iPad5,3/J81AP/T7001"
KERNEL = "7.3.0-rc1-j81-radio-id"
OFFSET = 0xC0
MAX_SHADOW = 1024
SAFE_SELECTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}\Z")


class RadioIdentityError(RuntimeError):
    pass


def _property_value(raw):
    raw = raw.strip()
    if re.fullmatch(r"[A-Za-z0-9,_.-]{1,64}", raw):
        return raw
    # Pongo prints non-string properties as hex bytes plus a printable view.
    match = re.fullmatch(r"((?:[0-9a-fA-F]{2}[ \t]+)+)\|[^\r\n]*\|", raw)
    if match:
        blob = bytes.fromhex(match.group(1)).rstrip(b"\0")
        if b"\0" not in blob:
            try:
                value = blob.decode("ascii")
            except UnicodeDecodeError:
                return None
            if re.fullmatch(r"[A-Za-z0-9,_.-]{1,64}", value):
                return value
    return None


def parse_adt_platform(data, minimum=200000):
    if not isinstance(data, bytes) or not minimum <= len(data) <= 8 * 1024 * 1024:
        raise RadioIdentityError("The private Apple hardware description was incomplete.")
    text = data.decode("utf-8", "replace")
    found = {}
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(target-type|platform-name|regulatory-model-number|name|module-instance)\s+(.+?)\s*", line)
        if match:
            key, raw = match.groups()
            value = _property_value(raw)
            if value is not None or key != "name":
                found.setdefault(key, []).append(value)
    for key, expected in (("target-type", "J81"), ("platform-name", "t7001"),
                          ("regulatory-model-number", "A1566")):
        if found.get(key) != [expected]:
            raise RadioIdentityError("The private Apple hardware description did not uniquely identify the Wi-Fi Air 2.")
    if "device-tree" not in found.get("name", []):
        raise RadioIdentityError("The Apple hardware description has no expected root.")
    instances = found.get("module-instance", [])
    if not instances or set(instances) != {"rieslinga"}:
        raise RadioIdentityError("The Wi-Fi module platform was absent, ambiguous, or unsupported. No radio firmware was selected.")
    return "rieslinga"


def parse_vendor_record(data):
    if len(data) < 7 or struct.unpack_from("<I", data)[0] != 8:
        raise RadioIdentityError("The radio identity record has an unsupported vendor header.")
    first = data.find(b"\0", 4)
    second = data.find(b"\0", first + 1) if first >= 0 else -1
    if first < 0 or second < 0 or any(data[second + 1:]):
        raise RadioIdentityError("The radio identity record has incomplete strings.")
    try:
        chip = data[4:first].decode("ascii")
        board = data[first + 1:second].decode("ascii")
    except UnicodeDecodeError as exc:
        raise RadioIdentityError("The radio identity record is not supported text.") from exc
    if any(ord(c) < 32 or ord(c) > 126 for c in chip + board):
        raise RadioIdentityError("The radio identity record contains control characters.")
    parameters = {}
    for token in chip.split():
        key, separator, value = token.partition("=")
        if key == "s":
            if not separator or key in parameters or value not in ("C2", "C4"):
                raise RadioIdentityError("The radio stepping is missing, ambiguous, or unsupported.")
            parameters[key] = value
    if "s" not in parameters:
        raise RadioIdentityError("The radio stepping could not be proven from its identity record.")
    board_parameters = {}
    for token in board.split():
        key, separator, value = token.partition("=")
        if key in ("M", "V", "m"):
            if not separator or key in board_parameters or not SAFE_SELECTOR.fullmatch(value):
                raise RadioIdentityError("The radio module selector is incomplete or ambiguous.")
            board_parameters[key] = value
    if set(board_parameters) != {"M", "V", "m"}:
        raise RadioIdentityError("The radio module selector lacks a required field.")
    return {"stepping": parameters["s"], "module": board_parameters["M"],
            "vendor": board_parameters["V"], "version": board_parameters["m"]}


def parse_shadow(data):
    if not isinstance(data, bytes) or not OFFSET + 2 <= len(data) <= MAX_SHADOW or len(data) % 2:
        raise RadioIdentityError("The private radio shadow has an unsupported size.")
    cursor = OFFSET
    records = []
    terminated = False
    while cursor < len(data):
        kind = data[cursor]
        if kind == 0:
            terminated = True
            break
        if len(data) - cursor < 2:
            raise RadioIdentityError("The private radio shadow ends inside a record header.")
        size = data[cursor + 1]
        if size > len(data) - cursor - 2:
            raise RadioIdentityError("The private radio shadow ends inside a record.")
        if kind == 0x15:
            records.append(parse_vendor_record(data[cursor + 2:cursor + 2 + size]))
        cursor += 2 + size
    if not terminated or len(records) != 1:
        raise RadioIdentityError("The radio shadow does not contain exactly one complete supported identity record.")
    return records[0]


def _one(pattern, text, description):
    matches = re.findall(pattern, text, re.M)
    if len(matches) != 1:
        raise RadioIdentityError("The radio probe did not provide one verified " + description + ".")
    return matches[0]


def parse_probe_capture(output, *, platform, base_payload_sha256, payload_sha256):
    if not isinstance(output, str) or len(output) > 32000:
        raise RadioIdentityError("The radio diagnostic exceeded its output limit.")
    log = _one(r"^J81_RADIO_LOG_BEGIN\n([\s\S]*?)\nJ81_RADIO_LOG_END$", output, "metadata log")
    encoded = _one(r"^J81_RADIO_SHADOW_BEGIN\n([A-Za-z0-9+/=\n]+)\nJ81_RADIO_SHADOW_END$", output, "private shadow capture")
    if len(encoded) > 1500:
        raise RadioIdentityError("The private radio capture exceeded its size limit.")
    try:
        shadow = base64.b64decode(encoded.replace("\n", ""), validate=True)
    except (ValueError, TypeError) as exc:
        raise RadioIdentityError("The private radio capture was not valid base64.") from exc
    prefix = r"^.*?t7000-bcm-probe: "
    chip, chiprev = _one(prefix + r"chipid=0x[0-9a-f]{8} chip=(0x[0-9a-f]{4}) chiprev=([0-9]+) pkg=[0-9]+ eromptr=0x[0-9a-f]{8}$", log, "chip identity")
    core, revision = _one(prefix + r"erom first component: id=(0x[0-9a-f]+) rev=([0-9]+) \(cia=0x[0-9a-f]{8} cib=0x[0-9a-f]{8}\)$", log, "ChipCommon identity")
    span, srom, otpsel, otp = _one(prefix + r"capabilities=0x[0-9a-f]{8} otpsize_enc=([0-9]+) otplayout=0x[0-9a-f]{8} wrap=[0-9]+ sromcontrol=0x[0-9a-f]{8} srom_present=([01]) srom_size_enc=[0-9]+ otpsel=([01]) otp_present=([01])$", log, "shadow mapping")
    words, count, crc = _one(prefix + r"shadow: captured ([0-9]+) words \(([0-9]+) bytes\) crc32=(0x[0-9a-f]{8}) allones=[0-9]+ zero=[0-9]+; bytes in debugfs t7000-bcm-otp-shadow \(root only, private, not for Git\)$", log, "capture checksum")
    _one(prefix + r"mapping path: chipcommon$", log, "ChipCommon mapping path")
    saved, restored = _one(prefix + r"BAR0 window restore PASS \(saved (0x[0-9a-f]{8}), now (0x[0-9a-f]{8})\)$", log, "restored BAR window")
    chiprev, revision, span, words, count = map(int, (chiprev, revision, span, words, count))
    if (chip != "0x4350" or not 0 <= chiprev <= 15 or core != "0x800"
            or revision not in (44, 45, 46, 47, 48, 50, 51)
            or not 1 <= span <= 7 or (srom, otpsel, otp) != ("0", "1", "1")
            or words != (span + 1) * 64 or count != words * 2
            or count != len(shadow) or count > MAX_SHADOW or saved != restored):
        raise RadioIdentityError("The observed radio metadata does not satisfy the supported read-only capture contract.")
    if (zlib.crc32(shadow) ^ 0xFFFFFFFF) != int(crc, 16):
        raise RadioIdentityError("The private radio capture checksum did not match the kernel's capture.")
    if platform != "rieslinga" or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (base_payload_sha256, payload_sha256)):
        raise RadioIdentityError("The radio capture is not linked to a verified boot and Apple platform.")
    selector = {
        "format": 1, "target": TARGET, "kernel": KERNEL,
        "chip": chip, "chip_rev": chiprev, "chipcommon_rev": revision,
        "platform": platform, **parse_shadow(shadow),
        "evidence": {"kind": "j81-bcm-otp-shadow", "payload_sha256": payload_sha256,
                     "base_payload_sha256": base_payload_sha256,
                     "crc32_verified": True, "bar_window_restored": True,
                     "record_offset": OFFSET, "platform_source": "pongo-adt-module-instance",
                     "platform_validated": True},
    }
    return selector, shadow

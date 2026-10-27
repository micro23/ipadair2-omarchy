#!/usr/bin/env python3
"""Prepare Air 2 Wi-Fi assets locally on the Mac; never contact or boot an iPad.

prepare: verify/download one pinned Apple IPSW, decrypt its RootFS with a public
key, attach the image read-only, and retain the allowlisted Wi-Fi files locally.
select: require the separately collected J81 radio identity; select one matching
quartet without transmitting, scanning, or loading it into hardware.

Uses Python's standard library and macOS CommonCrypto/hdiutil. Decryption design
is adapted from mattonik/ipad-nixos tools/vfdecrypt_ios8.py (MIT; see LICENSES).
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile

sys.dont_write_bytecode = True
VERSION = "1.0.0"
IPSW_NAME = "iPad5,3_8.1_12B410_Restore.ipsw"
IPSW_URL = "http://appldnld.apple.com/iOS8.1/031-09027.20141020.TLRqV/" + IPSW_NAME
IPSW_BYTES = 2178168430
IPSW_SHA256 = "d9cb4feda3d98fdb3c1d92713bac2bc6f5d1f317a2707770a248cbd1829ebc07"
ROOTFS_NAME = "058-01629-167.dmg"
ENCRYPTED_BYTES = 2123436032
ROOTFS_BYTES = 2123313195
ROOTFS_SHA256 = "b187f71f38d53e227cfbd2bacb3bb76b55c19f5c7285e913b2154e467ad965bb"
ROOTFS_OFFSET = 122368
KEY_URL = "https://theapplewiki.com/api.php?action=parse&page=Keys%3AOkemoTaos_12B410_%28iPad5%2C3%29&prop=wikitext&format=json"
KEY_TITLE = "Keys:OkemoTaos 12B410 (iPad5,3)"
KEY_SHA256 = "2f9fd3991c0e24ad4233630dc11f1a4129af246de0e52a67c8e275776007bbd0"
TARGET = "iPad5,3/J81AP/T7001"
RADIO_KERNEL = "7.3.0-rc1-j81-radio-id"
STATE_NAME = "J81 WiFi Next"
LINUX_BASE = "brcmfmac4350c2-pcie"

# From the pinned upstream private-firmware inventory. These are source facts,
# not proprietary firmware bytes. Board selectors are never defaulted.
BINARY_ASSETS = {
    "C2": {
        "rieslinga.trx": (566531, "e42b32ab33fcadfaa34414a8ea2c6f90f7931c9a194dad207095275fe3493177"),
        "rieslinga.clmb": (9001, "f1a77b5d933be97f472530c10c9c8d3ae204e8977c32275a113798c00cb2fa66"),
        "rieslinga.txcb": (316, "9d270addd113628f9d30fe89a7cbd27ce127503343b5e7bb1ba7b1072cd1722a"),
    },
    "C4": {
        "rieslinga.trx": (566387, "8aa9c0ce91af27684ccc2427fc81eb8bcd008392cb0534771a6464ccd2d38391"),
        "rieslinga.clmb": (9001, "f019088130abc0773fd8fbef143da483f7650448c2346a8e934ad03e0439d883"),
        "rieslinga.txcb": (316, "da69bc267fe59ab4623f6f9b9fc8d712feb766562c9d313cb1c0af988375f4e2"),
    },
}
NVRAM_VERSIONS = {
    "C2": {
        ("CIDR", "m"): "1.2 1.3 1.8 1.9 2.0 2.1 2.11 2.2 2.3 2.9".split(),
        ("CIDR", "u"): "1.2 1.3 2.0 2.1 2.5".split(),
        ("STEL", "m"): "3.8 3.9 4.0 4.1 4.11 4.2 4.3 4.6 4.7 4.9".split(),
        ("STEL", "u"): "2.10 2.11 3.0 3.1 3.4 3.5".split(),
    },
    "C4": {("CIDR", "m"): ["2.13"], ("CIDR", "u"): ["2.9"]},
}


class PreparationError(RuntimeError):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def regular(path, *, private=False, max_bytes=None):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PreparationError("Expected a regular file: " + path.name)
    if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise PreparationError("A private file has unexpected ownership or permissions: " + path.name)
    if max_bytes is not None and info.st_size > max_bytes:
        raise PreparationError("File is larger than expected: " + path.name)
    return info


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return require_private_directory(path)


def require_private_directory(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PreparationError("The private work directory has unexpected ownership or permissions: " + str(path))
    return path


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
    except BaseException:
        Path(path).unlink(missing_ok=True)
        raise


def read_json(path, *, private=False, max_bytes=65536):
    regular(path, private=private, max_bytes=max_bytes)
    with Path(path).open("rb") as stream:
        return json.load(stream)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def check_file(path, size, digest, *, private=False):
    info = regular(path, private=private)
    if info.st_size != size or not hmac.compare_digest(sha256_file(path), digest):
        raise PreparationError("Integrity check failed: " + Path(path).name)


def verify_bundle(bundle):
    """Read-only full package verification; no state or network access."""
    bundle = Path(bundle).resolve(strict=True)
    manifest = read_json(bundle / "bundle-manifest.json", max_bytes=2 * 1024 * 1024)
    if (not isinstance(manifest, dict) or manifest.get("format") != 1
            or manifest.get("target") != TARGET or manifest.get("purpose") != "wifi-preparation-v1"):
        raise PreparationError("This is not the expected J81 Wi-Fi preparation package.")
    files = manifest.get("files")
    required = {"firmware/prepare_firmware.py", "Prepare-WiFi-Firmware.command",
                "payloads/radio-id/manifest.json", "payloads/radio-id/m1n1-linux.bin"}
    if not isinstance(files, dict) or not required.issubset(files) or not 4 <= len(files) <= 10000:
        raise PreparationError("The preparation package is incomplete.")
    for name, entry in files.items():
        if not isinstance(name, str) or len(name) > 512 or "\\" in name or "\x00" in name:
            raise PreparationError("The preparation package has an invalid file path.")
        relative = PurePosixPath(name)
        if (not name or relative.is_absolute() or ".." in relative.parts
                or relative.as_posix() != name or not isinstance(entry, dict)
                or type(entry.get("bytes")) is not int or not 0 <= entry["bytes"] <= 128 * 1024 * 1024
                or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", "")))):
            raise PreparationError("The preparation package has invalid file metadata.")
        path = bundle / name
        if not path.resolve(strict=True).is_relative_to(bundle):
            raise PreparationError("A preparation package file points outside the bundle.")
        check_file(path, entry["bytes"], entry["sha256"])
    return manifest


class Progress:
    def __init__(self, label, total):
        self.label, self.total, self.last = label, total, 0.0
    def __call__(self, done):
        now = time.monotonic()
        if done >= self.total or now - self.last >= 5:
            print(f"{self.label}: {done / 1048576:.1f} / {self.total / 1048576:.1f} MiB", flush=True)
            self.last = now


class PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if newurl != req.full_url:
            raise PreparationError("The download redirected to an unexpected address; no data was accepted.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_url(url, headers=None):
    if url not in (IPSW_URL, KEY_URL):
        raise PreparationError("Unexpected download URL")
    request = urllib.request.Request(url, headers={"User-Agent": "J81-WiFi-Preparation/" + VERSION,
                                                "Accept-Encoding": "identity", **(headers or {})})
    return urllib.request.build_opener(PinnedRedirect()).open(request, timeout=30)


def obtain_ipsw(cache, local=None):
    if local is not None:
        local = Path(local).expanduser()
        print("Verifying the local Apple archive…", flush=True)
        check_file(local, IPSW_BYTES, IPSW_SHA256)
        return local
    final = cache / IPSW_NAME
    if final.exists() or final.is_symlink():
        print("Verifying the cached Apple archive…", flush=True)
        check_file(final, IPSW_BYTES, IPSW_SHA256, private=True)
        return final
    partial = cache / (IPSW_NAME + ".part")
    if partial.exists() or partial.is_symlink():
        offset = regular(partial, private=True, max_bytes=IPSW_BYTES).st_size
    else:
        write_private(partial, b"")
        offset = 0
    if offset < IPSW_BYTES:
        print("Downloading the pinned Apple archive (about 2.2 GB). A failed download can resume.", flush=True)
        headers = {"Range": f"bytes={offset}-"} if offset else {}
        with open_url(IPSW_URL, headers) as response:
            if offset:
                if response.status != 206 or response.headers.get("Content-Range") != f"bytes {offset}-{IPSW_BYTES - 1}/{IPSW_BYTES}":
                    raise PreparationError("The server did not honor the resume request. The partial archive was retained.")
            elif response.status != 200:
                raise PreparationError("Apple returned an unexpected download response.")
            length = response.headers.get("Content-Length")
            if length is None or int(length) != IPSW_BYTES - offset:
                raise PreparationError("Apple returned an unexpected archive length.")
            fd = os.open(partial, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            with os.fdopen(fd, "ab") as stream:
                progress = Progress("Apple archive", IPSW_BYTES)
                while offset < IPSW_BYTES:
                    chunk = response.read(min(1024 * 1024, IPSW_BYTES - offset))
                    if not chunk:
                        raise PreparationError("The download ended early. Rerun preparation to resume it.")
                    stream.write(chunk)
                    offset += len(chunk)
                    progress(offset)
                if response.read(1):
                    raise PreparationError("The download exceeded the expected size.")
    print("Checking the complete archive SHA-256…", flush=True)
    check_file(partial, IPSW_BYTES, IPSW_SHA256, private=True)
    # The private state lock prevents concurrent preparation; don't overwrite.
    if final.exists() or final.is_symlink():
        raise PreparationError("The archive destination appeared during preparation.")
    partial.rename(final)
    return final


def extract_encrypted_rootfs(ipsw, output):
    with zipfile.ZipFile(ipsw) as archive:
        matches = [entry for entry in archive.infolist() if entry.filename == ROOTFS_NAME]
        if len(matches) != 1 or matches[0].file_size != ENCRYPTED_BYTES:
            raise PreparationError("The verified archive has an unexpected RootFS entry.")
        entry = matches[0]
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as target, archive.open(entry) as source:
                count = 0
                progress = Progress("Extracting filesystem", ENCRYPTED_BYTES)
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    count += len(block)
                    if count > ENCRYPTED_BYTES:
                        raise PreparationError("The filesystem entry exceeded its expected size.")
                    target.write(block)
                    progress(count)
            if count != ENCRYPTED_BYTES:
                raise PreparationError("The filesystem entry was truncated.")
        except BaseException:
            Path(output).unlink(missing_ok=True)
            raise


def parse_public_key(document):
    parsed = document.get("parse") if isinstance(document, dict) else None
    if not isinstance(parsed, dict) or parsed.get("title") != KEY_TITLE:
        raise PreparationError("The public key page returned an unexpected identity.")
    wikitext = parsed.get("wikitext")
    content = wikitext.get("*") if isinstance(wikitext, dict) else None
    if not isinstance(content, str):
        raise PreparationError("The public key page did not contain the expected text.")
    rootfs = re.findall(r"(?m)^\s*\|\s*RootFS\s*=\s*([^\s]+)\s*$", content)
    keys = re.findall(r"(?m)^\s*\|\s*RootFSKey\s*=\s*([0-9a-fA-F]{72})\s*$", content)
    if rootfs != [ROOTFS_NAME[:-4]] or len(keys) != 1:
        raise PreparationError("The public key page has an ambiguous filesystem/key entry.")
    key = bytes.fromhex(keys[0])
    if not hmac.compare_digest(hashlib.sha256(key).hexdigest(), KEY_SHA256):
        raise PreparationError("The public filesystem key does not match the verified source.")
    return key


def obtain_public_key():
    print("Retrieving the published filesystem key…", flush=True)
    with open_url(KEY_URL) as response:
        data = response.read(65537)
    if len(data) > 65536:
        raise PreparationError("The public key response exceeded its limit.")
    return parse_public_key(json.loads(data))


class CommonCryptoAES:
    def __init__(self, key):
        if len(key) != 16:
            raise PreparationError("Invalid AES key size")
        self.library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        self.function = self.library.CCCrypt
        self.function.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                                  ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.function.restype = ctypes.c_int
        self.key = ctypes.create_string_buffer(key, len(key))
    def __call__(self, iv, data):
        if len(iv) != 16 or not data or len(data) % 16:
            raise PreparationError("Invalid AES-CBC block")
        source = ctypes.create_string_buffer(data, len(data))
        iv_buffer = ctypes.create_string_buffer(iv, len(iv))
        output = ctypes.create_string_buffer(len(data))
        moved = ctypes.c_size_t()
        result = self.function(1, 0, 0, self.key, 16, iv_buffer, source, len(data),
                               output, len(data), ctypes.byref(moved))
        if result != 0 or moved.value != len(data):
            raise PreparationError("CommonCrypto could not decrypt a filesystem block.")
        return output.raw


def check_native_crypto():
    # NIST SP 800-38A F.2.2, AES-128 CBC first block. This validates the actual
    # Mac API/library before any large download or filesystem extraction.
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ciphertext = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
    expected = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    try:
        result = CommonCryptoAES(key)(iv, ciphertext)
    except (OSError, AttributeError) as error:
        raise PreparationError("macOS CommonCrypto is unavailable to this Python runtime.") from error
    if not hmac.compare_digest(result, expected):
        raise PreparationError("macOS CommonCrypto failed its known-answer check.")


def decrypt_rootfs(source, output, key, decrypt_factory=CommonCryptoAES):
    if len(key) != 36:
        raise PreparationError("The filesystem key has an unexpected size.")
    regular(source, private=True)
    with Path(source).open("rb") as stream:
        header = stream.read(256)
        if len(header) != 256 or header[:8] != b"encrcdsa" or struct.unpack_from(">I", header, 8)[0] != 2:
            raise PreparationError("The encrypted filesystem header is not the pinned v2 format.")
        block_size = struct.unpack_from(">I", header, 52)[0]
        data_size, data_offset = struct.unpack_from(">QQ", header, 56)
        if (block_size != 512 or data_size != ROOTFS_BYTES or data_offset != ROOTFS_OFFSET
                or Path(source).stat().st_size != ENCRYPTED_BYTES
                or data_offset + math.ceil(data_size / block_size) * block_size != ENCRYPTED_BYTES):
            raise PreparationError("The encrypted filesystem geometry differs from the verified archive.")
        decrypt = decrypt_factory(key[:16])
        hmac_key = key[16:]
        stream.seek(data_offset)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        digest = hashlib.sha256()
        try:
            with os.fdopen(fd, "wb") as target:
                done = block = 0
                progress = Progress("Decrypting filesystem", data_size)
                while done < data_size:
                    encrypted = stream.read(block_size)
                    if len(encrypted) != block_size:
                        raise PreparationError("The encrypted filesystem ended unexpectedly.")
                    iv = hmac.new(hmac_key, struct.pack(">I", block), hashlib.sha1).digest()[:16]
                    data = decrypt(iv, encrypted)[:min(block_size, data_size - done)]
                    if not data:
                        raise PreparationError("The decryption returned no data.")
                    target.write(data)
                    digest.update(data)
                    done += len(data)
                    block += 1
                    progress(done)
            if done != ROOTFS_BYTES or not hmac.compare_digest(digest.hexdigest(), ROOTFS_SHA256):
                raise PreparationError("The decrypted filesystem failed its pinned SHA-256 check; it was not mounted.")
        except BaseException:
            Path(output).unlink(missing_ok=True)
            raise


def nvram_filename(module, vendor, version):
    return f"P-rieslinga_M-{module}_V-{vendor}__m-{version}.txt"


def expected_assets():
    result = {}
    for stepping, binaries in BINARY_ASSETS.items():
        prefix = f"C-4350__s-{stepping}/"
        result.update({prefix + name: pin for name, pin in binaries.items()})
        for (module, vendor), versions in NVRAM_VERSIONS[stepping].items():
            for version in versions:
                result[prefix + nvram_filename(module, vendor, version)] = None
    return result


def normalize_nvram(data, *, require_device_mac=False):
    if not 1 <= len(data) <= 65536 or any(byte > 126 or (byte < 32 and byte not in (9, 10, 13)) for byte in data):
        raise PreparationError("A board configuration is not bounded ASCII text.")
    output, assignments = [], []
    for raw in data.decode("ascii").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            output.append(line)
            continue
        key, separator, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not separator or not key:
            raise PreparationError("A board configuration contains an invalid assignment.")
        if require_device_mac and key.lower() == "macaddr":
            raise PreparationError("The board configuration contains a MAC address; the device must supply its own address at boot.")
        # Preserve assignment order, including repeated keys, exactly as the
        # upstream normalizer does. Selection never guesses an alternate file.
        assignments.append(key)
        output.append(key + "=" + value)
    if len(assignments) < 10:
        raise PreparationError("A board configuration has too few assignments.")
    return ("\n".join(output) + "\n").encode("ascii")


def extract_assets_from_mount(mount, stage):
    mount = Path(mount).resolve(strict=True)
    source_root = mount / "usr/share/firmware/wifi"
    records = {}
    for name, pin in sorted(expected_assets().items()):
        source = source_root / name
        if source.is_symlink() or not source.resolve(strict=True).is_relative_to(mount):
            raise PreparationError("An expected firmware asset is an unexpected link.")
        regular(source, max_bytes=1024 * 1024)
        data = source.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if pin is not None:
            if len(data) != pin[0] or not hmac.compare_digest(digest, pin[1]):
                raise PreparationError("A firmware binary differs from the verified archive: " + source.name)
        else:
            normalize_nvram(data)  # Structural check; preserve the original bytes.
        target = Path(stage) / name
        private_directory(target.parent)
        write_private(target, data)
        records[name] = {"bytes": len(data), "sha256": digest}
    manifest = {"format": 1, "target": TARGET, "build": "12B410", "ipsw_sha256": IPSW_SHA256,
                "rootfs_sha256": ROOTFS_SHA256, "files": records, "selected": False}
    write_private(Path(stage) / "assets.json", json_bytes(manifest))
    return manifest


def attach_and_extract(image, work, stage, runner=subprocess.run):
    mount = private_directory(work / "mount")
    disk = None
    # Do not remove a work directory when attachment state is uncertain.
    attached = False
    try:
        attached = True  # An interrupted/failed attach leaves state uncertain.
        result = runner(["/usr/bin/hdiutil", "attach", "-readonly", "-nobrowse", "-plist",
                         "-mountpoint", str(mount), str(image)], stdin=subprocess.DEVNULL,
                        capture_output=True, timeout=180, check=False)
        if result.returncode:
            raise PreparationError("macOS could not attach the verified filesystem read-only. "
                                   "The private work folder was retained: " + str(work))
        description = plistlib.loads(result.stdout)
        entities = description.get("system-entities", [])
        disks = [item.get("dev-entry") for item in entities
                 if isinstance(item, dict) and re.fullmatch(r"/dev/disk[0-9]+", str(item.get("dev-entry", "")))]
        mounts = [item.get("mount-point") for item in entities if isinstance(item, dict) and item.get("mount-point")]
        if len(disks) == 1:
            disk = disks[0]
        if disk is None or mounts != [str(mount)]:
            raise PreparationError("macOS returned an unexpected disk-image attachment. "
                                   "The private work folder was retained: " + str(work))
        return extract_assets_from_mount(mount, stage)
    finally:
        if disk is not None:
            detached = runner(["/usr/bin/hdiutil", "detach", disk], stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=60, check=False)
            if detached.returncode:
                raise PreparationError("macOS could not detach the helper's read-only image. "
                                       "Its private work folder was retained: " + str(work))
            attached = False
        if not attached and not os.path.ismount(mount):
            # Only files created in this helper's unique temporary directory.
            shutil.rmtree(work)


def verify_assets(assets):
    require_private_directory(assets)
    for stepping in BINARY_ASSETS:
        require_private_directory(Path(assets) / ("C-4350__s-" + stepping))
    manifest = read_json(Path(assets) / "assets.json", private=True)
    if (manifest.get("format") != 1 or manifest.get("target") != TARGET
            or manifest.get("build") != "12B410" or manifest.get("ipsw_sha256") != IPSW_SHA256
            or manifest.get("rootfs_sha256") != ROOTFS_SHA256
            or not isinstance(manifest.get("files"), dict)
            or set(manifest["files"]) != set(expected_assets())):
        raise PreparationError("The local firmware inventory does not match this preparation package.")
    for name, pin in expected_assets().items():
        entry = manifest["files"][name]
        if not isinstance(entry, dict) or type(entry.get("bytes")) is not int or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
            raise PreparationError("The local firmware inventory has invalid file metadata.")
        path = Path(assets) / name
        check_file(path, entry["bytes"], entry["sha256"], private=True)
        if pin is not None and (entry["bytes"], entry["sha256"]) != pin:
            raise PreparationError("The local firmware binary pin has changed.")
        if pin is None:
            normalize_nvram(path.read_bytes())
    return manifest


def prepare_assets(state, local_ipsw=None):
    firmware = private_directory(Path(state) / "firmware")
    assets = firmware / "assets"
    if assets.exists() or assets.is_symlink():
        verify_assets(assets)
        print("The locally prepared firmware assets are already verified.", flush=True)
        return assets
    cache = private_directory(firmware / "cache")
    needs_download = local_ipsw is None and not (cache / IPSW_NAME).exists()
    required = 2 * ENCRYPTED_BYTES + (IPSW_BYTES if needs_download else 0) + 512 * 1024 * 1024
    if shutil.disk_usage(firmware).free < required:
        raise PreparationError(f"Preparation needs about {required / 1e9:.1f} GB of free space on the Mac.")
    ipsw = obtain_ipsw(cache, local_ipsw)
    work = Path(tempfile.mkdtemp(prefix="extract-", dir=firmware))
    stage = Path(tempfile.mkdtemp(prefix="assets-stage-", dir=firmware))
    attached_attempted = False
    try:
        encrypted, decrypted = work / "encrypted.dmg", work / "verified-rootfs.dmg"
        extract_encrypted_rootfs(ipsw, encrypted)
        key = obtain_public_key()
        decrypt_rootfs(encrypted, decrypted, key)
        del key
        print("Verified filesystem ready. Reading only the allowlisted Wi-Fi files…", flush=True)
        attached_attempted = True
        attach_and_extract(decrypted, work, stage)
        verify_assets(stage)
        if assets.exists() or assets.is_symlink():
            raise PreparationError("The firmware destination appeared during preparation.")
        stage.rename(assets)
        print("Firmware files prepared locally. Device identification is required before selection.", flush=True)
        return assets
    finally:
        if not attached_attempted and work.exists():
            shutil.rmtree(work)
        if stage.exists():
            shutil.rmtree(stage)


def validate_selector(record, *, expected_base_payload_sha256):
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_base_payload_sha256)):
        raise PreparationError("The expected radio-identification payload hash is invalid.")
    if (not isinstance(record, dict) or record.get("format") != 1 or record.get("target") != TARGET
            or record.get("kernel") != RADIO_KERNEL or record.get("chip") != "0x4350"
            or record.get("platform") != "rieslinga"):
        raise PreparationError("The radio selector does not identify this J81 test.")
    evidence = record.get("evidence")
    if (not isinstance(evidence, dict) or evidence.get("kind") != "j81-bcm-otp-shadow"
            or evidence.get("base_payload_sha256") != expected_base_payload_sha256
            or not re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("payload_sha256", "")))
            or evidence.get("crc32_verified") is not True or evidence.get("bar_window_restored") is not True
            or evidence.get("record_offset") != 192 or evidence.get("platform_validated") is not True
            or evidence.get("platform_source") != "pongo-adt-module-instance"):
        raise PreparationError("The radio selector lacks verified evidence from this identification image.")
    if (type(record.get("chipcommon_rev")) is not int
            or record["chipcommon_rev"] not in (*range(44, 49), 50, 51)):
        raise PreparationError("The radio selector has an unsupported ChipCommon revision.")
    for field in ("module", "vendor", "version"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,14}", str(record.get(field, ""))):
            raise PreparationError("The radio selector contains an invalid module field.")
    if record.get("stepping") != "C2" or type(record.get("chip_rev")) is not int or record["chip_rev"] != 5:
        raise PreparationError("This radio revision is not the verified C2/revision-5 path. "
                               "Keep the identification report; no firmware was selected.")
    name = nvram_filename(record["module"], record["vendor"], record["version"])
    source = "C-4350__s-C2/" + name
    if source not in expected_assets():
        raise PreparationError("The archive has no exact board configuration for this radio tuple. "
                               "No fallback configuration was selected.")
    return source


def select_assets(selector_path, state, expected_base_payload_sha256):
    require_private_directory(Path(state))
    record = read_json(selector_path, private=True, max_bytes=16384)
    board = validate_selector(record, expected_base_payload_sha256=expected_base_payload_sha256)
    validate_radio_run(state, record, expected_base_payload_sha256)
    firmware = private_directory(Path(state) / "firmware")
    assets = firmware / "assets"
    inventory = verify_assets(assets)
    selection_identity = hashlib.sha256(json_bytes(record)).hexdigest()
    selections = private_directory(firmware / "selected")
    destination = selections / selection_identity
    if destination.exists() or destination.is_symlink():
        require_private_directory(destination)
        manifest = read_json(destination / "selection.json", private=True)
        if manifest.get("selector_sha256") != selection_identity:
            raise PreparationError("An existing firmware selection has an unexpected identity.")
        for name, entry in manifest.get("files", {}).items():
            if name not in {LINUX_BASE + suffix for suffix in (".bin", ".clm_blob", ".txcap_blob", ".txt")}:
                raise PreparationError("An existing firmware selection has an unexpected filename.")
            check_file(destination / name, entry["bytes"], entry["sha256"], private=True)
        if len(manifest.get("files", {})) != 4:
            raise PreparationError("An existing firmware selection is incomplete.")
        return destination
    stage = Path(tempfile.mkdtemp(prefix="select-", dir=selections))
    try:
        mapping = {"C-4350__s-C2/rieslinga.trx": LINUX_BASE + ".bin",
                   "C-4350__s-C2/rieslinga.clmb": LINUX_BASE + ".clm_blob",
                   "C-4350__s-C2/rieslinga.txcb": LINUX_BASE + ".txcap_blob", board: LINUX_BASE + ".txt"}
        files = {}
        for source, name in mapping.items():
            data = (assets / source).read_bytes()
            if name.endswith(".txt"):
                data = normalize_nvram(data, require_device_mac=True)
            write_private(stage / name, data)
            files[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                           "source": source, "source_sha256": inventory["files"][source]["sha256"]}
        manifest = {"format": 1, "target": TARGET, "selector_sha256": selection_identity,
                    "selector": record, "files": files, "ipsw_sha256": IPSW_SHA256,
                    "rootfs_sha256": ROOTFS_SHA256,
                    "mac_source": "not inserted; the later bootloader/driver path must supply this iPad's MAC",
                    "requires_mac_handoff_validation": True,
                    "credentials_included": False, "firmware_loaded": False}
        write_private(stage / "selection.json", json_bytes(manifest))
        stage.rename(destination)
        return destination
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def validate_radio_run(state, selector, expected_base_payload_sha256):
    """Require the current completed capture, not an older retained selector."""
    try:
        run = read_json(Path(state) / "radio-run.json", private=True, max_bytes=16384)
    except FileNotFoundError:
        raise PreparationError("No matching completed radio test exists. Run Start-Radio-ID first.") from None
    evidence = selector["evidence"]
    if (not isinstance(run, dict) or run.get("format") != 1
            or run.get("target") != TARGET or run.get("kernel") != RADIO_KERNEL
            or run.get("state") != "radio_verified"
            or not re.fullmatch(r"[0-9a-f]{32}", str(run.get("run_id", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(run.get("device", "")))
            or run.get("base_payload_sha256") != expected_base_payload_sha256
            or run.get("base_payload_sha256") != evidence["base_payload_sha256"]
            or run.get("payload_sha256") != evidence["payload_sha256"]
            or run.get("platform") != selector["platform"] or run.get("platform_validated") is not True):
        raise PreparationError("The selector is not from the current completed radio test. "
                               "Finish radio identification before selecting firmware.")


def expected_radio_hash(bundle):
    directory = Path(bundle) / "payloads/radio-id"
    manifest = read_json(directory / "manifest.json")
    target = manifest.get("target", {})
    if (manifest.get("format_version") != 1 or manifest.get("kernel_release") != RADIO_KERNEL
            or target.get("product_type") != "iPad5,3" or target.get("hardware_model") != "J81AP"
            or target.get("chip_id") != "0x7001" or target.get("board_id") != "0x06"):
        raise PreparationError("The packaged identification image has an unexpected identity.")
    entry = manifest.get("files", {}).get("m1n1-linux.bin", {})
    if type(entry.get("bytes")) is not int or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))):
        raise PreparationError("The packaged identification image has invalid hash metadata.")
    check_file(directory / "m1n1-linux.bin", entry["bytes"], entry["sha256"])
    return entry["sha256"]


@contextlib.contextmanager
def state_lock(state):
    path = state / "firmware-preparation.lock"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PreparationError("The firmware lock has unexpected ownership or permissions.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise PreparationError("Another firmware preparation is already running.") from None
        yield
    finally:
        os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify package hashes only; no network, state writes, or Mac calls")
    sub = parser.add_subparsers(dest="action")
    prepare = sub.add_parser("prepare", help="Prepare private firmware files on the Mac")
    prepare.add_argument("--ipsw", type=Path, help="Use an existing exact Apple IPSW instead of downloading")
    sub.add_parser("select", help="Select only the quartet matching the private radio identification")
    sub.add_parser("verify", help="Verify the already prepared local firmware files")
    args = parser.parse_args(argv)
    if args.check and args.action:
        parser.error("--check is a separate read-only action")
    if not args.check and not args.action:
        parser.error("choose prepare, select, verify, or --check")
    try:
        bundle = Path(__file__).resolve().parent.parent
        verify_bundle(bundle)
        print("Preparation package hashes OK.", flush=True)
        if args.check:
            print("Check complete. No network, iPad, or Mac state was accessed.")
            return 0
        if sys.platform != "darwin":
            raise PreparationError("Run this preparation helper on your Mac.")
        os.umask(0o077)
        state = private_directory(Path.home() / "Library/Application Support" / STATE_NAME)
        with state_lock(state):
            if args.action == "prepare":
                check_native_crypto()
                result = prepare_assets(state, args.ipsw)
                print("\nPrepared local assets: " + str(result))
                selector = state / "radio-selector.json"
                if selector.exists() or selector.is_symlink():
                    selected = select_assets(selector, state, expected_radio_hash(bundle))
                    print("Matching firmware selected locally: " + str(selected))
                    print("The iPad session was not contacted. This package has not uploaded or booted the firmware.")
                else:
                    print("The current iPad session was not contacted. Run Start-Radio-ID when ready.")
            elif args.action == "verify":
                verify_assets(state / "firmware/assets")
                print("Local firmware inventory verified.")
            else:
                selector = state / "radio-selector.json"
                if not selector.exists():
                    raise PreparationError("Run radio identification first. No device-specific firmware can be selected yet.")
                result = select_assets(selector, state, expected_radio_hash(bundle))
                print("\nMatching firmware selected locally: " + str(result))
                print("Selection is complete. This helper has not uploaded or booted it.")
        return 0
    except (PreparationError, OSError, ValueError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print("\nSTOP: " + str(error), file=sys.stderr)
        print("Keep your current iPad session running. Copy this message for diagnosis.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nPreparation cancelled. A partial Apple archive can be resumed. The iPad was not contacted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

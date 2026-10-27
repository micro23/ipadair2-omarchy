"""Verified private firmware assembly and fresh J81 Wi-Fi RAM boot.

This module never downloads firmware and never starts Wi-Fi association.
Its existing-package imports are pinned before execution. The caller must
hold its application lock while preparing/booting or updating wifi-run.json.
"""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import sys
from types import SimpleNamespace

TARGET = "iPad5,3/J81AP/T7001"
KERNEL = "7.3.0-rc1-j81-wifi-ram"
ORIGINAL_MANIFEST_SHA256 = "cb2847788cd859ca266abc37a06642b97a77af1f22da8c854e307e7bb8045219"
ORIGINAL_RUNNER_SHA256 = "350176ef8da461011a9f4a19e80b175a6930d4407fcb5cdf54cb5a77e2e5884f"
RADIO_BASE_SHA256 = "8e3944abab7190575c108030f0f7481807a546875c223b7d74ded6cce5f0202a"
WIFI_BASE_SHA256 = "589f66d414af53688ddb2c7e9e28cf8c82fcf146660128c1c9639e922408c81e"
ARCHIVE_HELPER_SHA256 = "86958125b3a4a111dd0a724d80f1bd2d0631c30b02c5bebbe4a4217a1f1d608a"
PARTS = ("m1n1.bin", "bootargs", "t7001-j81.dtb", "Image.gz", "initramfs.gz")
FW_BASE = "brcmfmac4350c2-pcie"
FW_NAMES = {FW_BASE + suffix for suffix in (".bin", ".clm_blob", ".txcap_blob", ".txt")}
PUBLIC_FW_NAMES = {"regulatory.db", "regulatory.db.p7s"}
EXACT_SELECTOR = {"chip": "0x4350", "chip_rev": 5, "chipcommon_rev": 47,
                  "stepping": "C2", "platform": "rieslinga", "module": "CIDR", "vendor": "u", "version": "2.1"}
MAX_PAYLOAD = 128 * 1024 * 1024
sys.dont_write_bytecode = True


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular_bytes(path, maximum, *, private=False):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= maximum
                or (private and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
            raise RuntimeError("A required J81 file has unexpected type, size or permissions.")
        data = stream.read(maximum + 1)
    if len(data) != info.st_size:
        raise RuntimeError("A J81 file changed while being read.")
    return data


def pinned_bytes(path, expected, maximum=MAX_PAYLOAD):
    data = regular_bytes(path, maximum)
    if digest(data) != expected:
        raise RuntimeError("The original J81 preparation package failed its integrity check: " + Path(path).name)
    return data


def load_bytes(name, path, data):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(data, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_original(bundle):
    """Read-only complete verification, then imports of verified original bytes."""
    bundle = Path(bundle).expanduser().resolve()
    pinned_bytes(bundle / "bundle-manifest.json", ORIGINAL_MANIFEST_SHA256, 2 * 1024 * 1024)
    path = bundle / "host/run-radio-test.py"
    runner = load_bytes("j81_wifi_original_radio_runner", path,
                        pinned_bytes(path, ORIGINAL_RUNNER_SHA256, 1024 * 1024))
    manifest = runner.verify_bundle()

    def component(relative, name):
        entry = manifest["files"][relative]
        path = bundle / relative
        data = pinned_bytes(path, entry["sha256"], entry["bytes"])
        if len(data) != entry["bytes"]:
            raise RuntimeError("An original J81 component changed size.")
        return load_bytes(name, path, data)

    apple = component("host/apple_identity.py", "apple_identity")
    base = component("host/boot_flow_base.py", "j81_wifi_original_boot_flow")
    shell = component("host/usb_shell.py", "j81_wifi_original_usb_shell")
    firmware = component("firmware/prepare_firmware.py", "j81_wifi_original_firmware")
    radio_parser = component("host/radio_identity.py", "j81_wifi_original_radio_identity")
    archive = component("source/assembly/ramdisk/archive_support.py", "j81_wifi_original_archive")
    if manifest["files"]["source/assembly/ramdisk/archive_support.py"]["sha256"] != ARCHIVE_HELPER_SHA256:
        raise RuntimeError("The original archive helper is not the reviewed build.")
    if (manifest["files"]["payloads/radio-id/m1n1-linux.bin"]["sha256"] != RADIO_BASE_SHA256
            or manifest["files"]["payloads/wifi-base/m1n1-linux.bin"]["sha256"] != WIFI_BASE_SHA256):
        raise RuntimeError("The original J81 kernel images do not match this test.")
    return SimpleNamespace(bundle=bundle, manifest=manifest, radio=runner, base=base,
                           shell_class=shell.IPadShell, firmware=firmware,
                           radio_parser=radio_parser, archive=archive, apple=apple)


def validate_evidence(ctx, state):
    fw = ctx.firmware
    fw.require_private_directory(Path(state))
    selector = fw.read_json(Path(state) / "radio-selector.json", private=True, max_bytes=16384)
    board = fw.validate_selector(selector, expected_base_payload_sha256=RADIO_BASE_SHA256)
    fw.validate_radio_run(state, selector, RADIO_BASE_SHA256)
    run = fw.read_json(Path(state) / "radio-run.json", private=True, max_bytes=16384)
    if any(selector.get(key) != value for key, value in EXACT_SELECTOR.items()):
        raise RuntimeError("This Wi-Fi test requires the observed C2 / CIDR / u / 2.1 radio. No alternate board file was chosen.")
    if board != "C-4350__s-C2/P-rieslinga_M-CIDR_V-u__m-2.1.txt":
        raise RuntimeError("The radio evidence selected an unexpected board file.")
    return selector, run, board


def selected_firmware(ctx, state):
    """Select only existing verified Mac-local assets; never download anything."""
    fw = ctx.firmware
    selector, run, board = validate_evidence(ctx, state)
    assets = Path(state) / "firmware/assets"
    if not assets.exists():
        raise RuntimeError("Apple firmware has not been prepared on this Mac. Run the original Prepare-WiFi-Firmware.command first, then retry this preparation.")
    # The original helper validates all source-archive provenance, binary pins,
    # complete asset inventory and the current completed radio run.
    selected = fw.select_assets(Path(state) / "radio-selector.json", state, RADIO_BASE_SHA256)
    inventory = fw.verify_assets(assets)
    selection = fw.read_json(selected / "selection.json", private=True, max_bytes=32768)
    selector_hash = digest(fw.json_bytes(selector))
    if (selection.get("format") != 1 or selection.get("target") != TARGET
            or selection.get("selector_sha256") != selector_hash or selection.get("selector") != selector
            or selection.get("ipsw_sha256") != fw.IPSW_SHA256
            or selection.get("rootfs_sha256") != fw.ROOTFS_SHA256
            or selection.get("credentials_included") is not False
            or selection.get("firmware_loaded") is not False
            or selection.get("requires_mac_handoff_validation") is not True
            or set(selection.get("files", {})) != FW_NAMES):
        raise RuntimeError("The private firmware selection does not match the current radio evidence.")
    mapping = {FW_BASE + ".bin": "C-4350__s-C2/rieslinga.trx",
               FW_BASE + ".clm_blob": "C-4350__s-C2/rieslinga.clmb",
               FW_BASE + ".txcap_blob": "C-4350__s-C2/rieslinga.txcb", FW_BASE + ".txt": board}
    files = {}
    for name, source in mapping.items():
        source_data = regular_bytes(assets / source, 2 * 1024 * 1024, private=True)
        source_entry = inventory["files"][source]
        if len(source_data) != source_entry["bytes"] or digest(source_data) != source_entry["sha256"]:
            raise RuntimeError("A private firmware source changed after verification.")
        expected = fw.normalize_nvram(source_data, require_device_mac=True) if name.endswith(".txt") else source_data
        data = regular_bytes(selected / name, 2 * 1024 * 1024, private=True)
        entry = selection["files"][name]
        if (data != expected or entry.get("source") != source
                or entry.get("source_sha256") != digest(source_data)
                or entry.get("sha256") != digest(data) or entry.get("bytes") != len(data)):
            raise RuntimeError("A selected firmware file no longer matches its verified Apple source.")
        files[name] = data
    return files, selector, run, selector_hash


def validate_public_firmware(files):
    """Input supplied by the verified new package: name -> {data, sha256}."""
    if not isinstance(files, dict) or set(files) != PUBLIC_FW_NAMES:
        raise RuntimeError("Both signed regulatory database files are required.")
    result = {}
    for name, item in files.items():
        if (not isinstance(item, dict) or not isinstance(item.get("data"), bytes)
                or not 0 < len(item["data"]) <= 1024 * 1024
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))
                or digest(item["data"]) != item["sha256"]):
            raise RuntimeError("A public regulatory database file failed its package check.")
        result[name] = item["data"]
    return result


def compressed(data):
    stream = io.BytesIO()
    with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0, compresslevel=9) as output:
        output.write(data)
    return stream.getvalue()


def assemble_payload(ctx, firmware, public_firmware, run_id):
    if not re.fullmatch(r"[0-9a-f]{32}", str(run_id)) or set(firmware) != FW_NAMES:
        raise RuntimeError("The private Wi-Fi payload inputs are incomplete.")
    public = validate_public_firmware(public_firmware)
    folder = ctx.bundle / "payloads/wifi-base"
    parts = {name: pinned_bytes(folder / name,
             ctx.manifest["files"]["payloads/wifi-base/" + name]["sha256"]) for name in PARTS}
    if digest(b"".join(parts[name] for name in PARTS)) != WIFI_BASE_SHA256:
        raise RuntimeError("The verified Wi-Fi template has inconsistent components.")
    raw = gzip.decompress(parts["initramfs.gz"])
    if len(raw) > 4 * 1024 * 1024:
        raise RuntimeError("The base RAM filesystem exceeds its size limit.")
    entries = ctx.archive.parse_newc(raw)
    original = {name: dict(entry) for name, entry in entries.items()}
    for name in ("lib/firmware", "lib/firmware/brcm"):
        if name in entries:
            raise RuntimeError("The Wi-Fi template already contains a firmware directory.")
        entries[name] = {"mode": stat.S_IFDIR | 0o755, "data": b""}
    for name, data in firmware.items():
        if not isinstance(data, bytes) or not 0 < len(data) <= 2 * 1024 * 1024:
            raise RuntimeError("A private firmware file has an invalid size.")
        entries["lib/firmware/brcm/" + name] = {"mode": stat.S_IFREG | 0o600, "data": data}
    for name, data in public.items():
        entries["lib/firmware/" + name] = {"mode": stat.S_IFREG | 0o644, "data": data}
    init = entries["init"]["data"]
    old_comment = b"# Direct USB diagnostic access only: no password, no SSH keys, no Wi-Fi."
    if init.count(old_comment) != 1:
        raise RuntimeError("The original USB-shell binding comment changed.")
    init = init.replace(old_comment, b"# USB diagnostic shell only; never expose it on the Wi-Fi address.")
    entries["init"]["data"] = init
    ram_shell = entries["bin/ram-shell"]["data"]
    shell_line = b"export PS1='j81-ram# '\n"
    if ram_shell.count(shell_line) != 1 or b"HISTFILE=" in ram_shell:
        raise RuntimeError("The original interactive USB shell environment changed.")
    # IPadShell.run uses a subshell, so disabling history inside a command
    # would not change the interactive parent's history settings. Set it
    # before that parent starts, preventing encoded WPA keys entering a file.
    entries["bin/ram-shell"]["data"] = ram_shell.replace(shell_line,
        shell_line + b"export HISTFILE=/dev/null\n")
    entries["etc/issue"]["data"] = (b"\nJ81 Wi-Fi RAM connection test\n"
        b"USB shell: 172.16.42.1:23 (USB interface only)\n"
        b"All files and logs are temporary. Use the Mac helper for Wi-Fi.\n\n")
    entries["etc/j81-test-profile"]["data"] = b"wifi-connection-v1\n"
    ordered = sorted(entries, key=lambda name: (name.count("/"), name))
    archive = b"".join(ctx.archive.newc_entry(name, entries[name], index + 1)
                       for index, name in enumerate(ordered))
    archive += ctx.archive.newc_entry("TRAILER!!!", {"mode": 0, "data": b""}, len(entries) + 1)
    archive += b"\0" * (-len(archive) % 512)
    roundtrip = ctx.archive.parse_newc(archive)
    if set(roundtrip) != set(entries) or any(roundtrip[name]["data"] != entries[name]["data"] for name in entries):
        raise RuntimeError("The private RAM filesystem did not round-trip.")
    for name, entry in original.items():
        if name not in ("init", "bin/ram-shell", "etc/issue", "etc/j81-test-profile") and entries[name] != entry:
            raise RuntimeError("An unrelated base userspace file changed during assembly.")
    parts["initramfs.gz"] = compressed(archive)
    args = parts["bootargs"]
    if (not args.endswith(b"\n") or args.count(b"\n") != 1 or b"\0" in args
            or b"j81.wifi_run=" in args or len(args) > 4096):
        raise RuntimeError("The verified Wi-Fi boot arguments have an unexpected format.")
    parts["bootargs"] = args[:-1] + b" j81.wifi_run=" + run_id.encode("ascii") + b"\n"
    payload = b"".join(parts[name] for name in PARTS)
    if not 0 < len(payload) <= MAX_PAYLOAD:
        raise RuntimeError("The private Wi-Fi image exceeds its RAM upload limit.")
    metadata = {"base_payload_sha256": WIFI_BASE_SHA256, "payload_sha256": digest(payload),
                "payload_bytes": len(payload), "initramfs_sha256": digest(parts["initramfs.gz"]),
                "firmware_files": {name: {"bytes": len(data), "sha256": digest(data)} for name, data in firmware.items()},
                "public_regulatory_files": {name: {"bytes": len(data), "sha256": digest(data)} for name, data in public.items()},
                "macaddr_inserted_by_assembler": False, "credentials_included": False,
                "usb_shell_history_file": "/dev/null"}
    return payload, metadata


def parse_adt_mac(data, radio_parser):
    """Only the direct /chosen node and one six-byte wifi0 property are accepted."""
    radio_parser.parse_adt_platform(data)
    text = data.decode("utf-8", "replace").replace("\r", "")
    # Pongo dt.c dt_cbn prints a 128-hyphen separator before every child node.
    blocks = re.split(r"(?m)^-{128}$", text)
    chosen = [(index, block) for index, block in enumerate(blocks)
              if re.search(r"(?m)^ {4}name[ \t]+chosen[ \t]*$", block)]
    if (len(chosen) != 1 or chosen[0][0] == 0
            or re.findall(r"(?m)^( *)name[ \t]+([^\n]+)$", chosen[0][1]) != [("    ", "chosen")]):
        raise RuntimeError("The private Apple hardware description has no unique direct chosen node.")
    matches = re.findall(r"(?m)^ {4}mac-address-wifi0[ \t]+([^\n]+)$", chosen[0][1])
    if len(matches) != 1:
        raise RuntimeError("The private Apple hardware description has no unique Wi-Fi MAC property.")
    value = matches[0].strip()
    match = re.fullmatch(r"((?:[0-9a-fA-F]{2}[ \t]+){5}[0-9a-fA-F]{2})[ \t]+\|[^\n]*\|", value)
    if match:
        raw = bytes.fromhex(match.group(1))
    elif len(value) == 6 and all(0x21 <= ord(char) < 0x7f for char in value):
        # Pongo renders a six-byte entirely printable property directly.
        raw = value.encode("ascii")
    else:
        raise RuntimeError("The private Wi-Fi MAC property has an unsupported representation. No image was uploaded.")
    if len(raw) != 6 or raw == b"\0" * 6 or raw[0] & 1:
        raise RuntimeError("The private Wi-Fi MAC property is not a valid unicast address.")
    return ":".join(f"{byte:02x}" for byte in raw)


def exact_guard(run_id):
    if not re.fullmatch(r"[0-9a-f]{32}", str(run_id)):
        raise RuntimeError("Invalid private Wi-Fi run identifier.")
    return "\n".join(("set -eu", f"[ \"$(uname -r)\" = '{KERNEL}' ]",
        "tr '\\000' '\\n' </proc/device-tree/compatible | grep -Fqx 'apple,j81'",
        "tr '\\000' '\\n' </proc/device-tree/compatible | grep -Fqx 'apple,t7001'",
        "awk '$2 == \"/run\" && $3 == \"tmpfs\" {found=1} END {exit !found}' /proc/mounts",
        "[ \"$(tr ' ' '\\n' </proc/cmdline | grep -c '^j81.wifi_run=')\" = 1 ]",
        f"tr ' ' '\\n' </proc/cmdline | grep -Fqx 'j81.wifi_run={run_id}'"))


def probe_wifi(shell_class, record):
    shell = None
    try:
        shell = shell_class()
        _, code = shell.run(exact_guard(record["run_id"]), seconds=10, check=False)
        if code:
            raise RuntimeError("The reachable USB shell is a different Linux image or Wi-Fi test session. No Wi-Fi action was performed.")
        return True
    except OSError:
        return False
    finally:
        if shell is not None:
            with contextlib.suppress(OSError):
                shell.close()


def read_wifi_run(ctx, state):
    selector, radio_run, _ = validate_evidence(ctx, state)
    radio_mac, radio_adt_hash = read_radio_adt(ctx, state, radio_run)
    record = ctx.firmware.read_json(Path(state) / "wifi-run.json", private=True, max_bytes=32768)
    if (not isinstance(record, dict) or record.get("format") != 1 or record.get("target") != TARGET
            or record.get("kernel") != KERNEL or record.get("state") not in ("pongo_verified", "linux_verified")
            or not re.fullmatch(r"[0-9a-f]{32}", str(record.get("run_id", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("payload_sha256", "")))
            or record.get("base_payload_sha256") != WIFI_BASE_SHA256
            or record.get("device") != radio_run["device"] or record.get("source_radio_run_id") != radio_run["run_id"]
            or record.get("radio_selector_sha256") != digest(ctx.firmware.json_bytes(selector))
            or record.get("source_radio_payload_sha256") != radio_run["payload_sha256"]
            or record.get("mac_source") != "pongo-adt-chosen-mac-address-wifi0"
            or record.get("usb_shell_history_file") != "/dev/null"
            or record.get("platform") != "rieslinga" or record.get("platform_validated") is not True
            or not valid_mac(record.get("expected_mac"))
            or record.get("radio_expected_mac") != radio_mac
            or record.get("expected_mac") != radio_mac
            or record.get("radio_adt_sha256") != radio_adt_hash):
        raise RuntimeError("The private Wi-Fi run record does not match the completed radio identification and boot.")
    return record


def valid_mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", value):
        return False
    raw = bytes.fromhex(value.replace(":", ""))
    return raw != b"\0" * 6 and not raw[0] & 1


def read_radio_adt(ctx, state, radio_run):
    """Preflight the already captured private MAC before the user restarts Linux."""
    root = Path(state)
    for parent in (root, root / "radio-runs", root / "radio-runs" / radio_run["run_id"]):
        ctx.firmware.require_private_directory(parent)
    data = regular_bytes(root / "radio-runs" / radio_run["run_id"] / "apple-device-tree.txt",
                         8 * 1024 * 1024, private=True)
    return parse_adt_mac(data, ctx.radio_parser), digest(data)


def prepare_session(ctx, state, public_firmware):
    state = ctx.radio.private_dir(state)
    with ctx.firmware.state_lock(state):
        firmware, selector, radio_run, selector_hash = selected_firmware(ctx, state)
        radio_mac, radio_adt_hash = read_radio_adt(ctx, state, radio_run)
    run_id = secrets.token_hex(16)
    payload, metadata = assemble_payload(ctx, firmware, public_firmware, run_id)
    folder = ctx.radio.private_dir(ctx.radio.private_dir(state / "wifi-runs") / run_id)
    record = {"format": 1, "target": TARGET, "kernel": KERNEL, "run_id": run_id,
              "state": "prepared", "device": radio_run["device"],
              "source_radio_run_id": radio_run["run_id"],
              "source_radio_payload_sha256": radio_run["payload_sha256"],
              "radio_selector_sha256": selector_hash, "platform": "rieslinga",
              "platform_validated": True, "radio_expected_mac": radio_mac,
              "radio_adt_sha256": radio_adt_hash, **metadata}
    ctx.radio.private_write(folder / "m1n1-linux-private.bin", payload)
    ctx.radio.private_json(folder / "prepared.json", record)
    # Preparation does not invalidate a still-running previous Wi-Fi test.
    # The global current-run record is replaced only as a new boot begins.
    return SimpleNamespace(folder=folder, record=record, payload=payload)


def wifi_flow_class(ctx):
    base = ctx.base

    class WiFiFlow(base.BootFlow):
        def __init__(self, state, prepared, log, event):
            super().__init__(ctx.bundle, state, log, event=event)
            self.bundle = ctx.bundle / "payloads/wifi-base"
            self.prepared = prepared
            self.run_record = dict(prepared.record)
            self._payload = prepared.payload
            self._journal = Path(state) / "wifi-boot-attempt.json"
            self._runtime_ready = False

        def _check_radio_device(self, ecid):
            if type(ecid) is not int or self._journal_fingerprint(ecid) != self.run_record["device"]:
                raise base.BootError("This is not the Air 2 whose radio was identified. No boot tool or image was sent to this device.")

        def _identity(self, device, *, expected=None, pongo=False):
            identity = super()._identity(device, expected=expected, pongo=pongo)
            self._check_radio_device(identity.ecid)
            return identity

        def _run_palera1n(self, mode):
            self._check_radio_device(self._expected_ecid)
            return super()._run_palera1n(mode)

        def _emit(self, phase, message, detail="", needs_action=None):
            replacements = {
                "checking": ("Checking the identified Air 2", "This test requires the same physical iPad and verified C2 firmware selection."),
                "linux_upload": ("Loading the private Wi-Fi image into RAM", "Keep the cable connected. No Wi-Fi credentials are in this boot image."),
                "linux_ready": ("The Wi-Fi test kernel is running", "The Mac will check firmware attachment and the device's own MAC before scanning or connecting."),
                "linux_wait": ("Waiting for the Wi-Fi test's USB shell", "Keep the cable connected. The exact kernel and private boot-session identifier must match."),
            }
            if phase in replacements:
                message, detail = replacements[phase]
            detail = detail.replace("Click Ready", "Press Return").replace("Leave the app open", "Leave this Terminal open")
            super()._emit(phase, message, detail, needs_action)

        def _prepare(self):
            if self._runtime_ready:
                return
            if platform.system() != "Darwin" or platform.machine() != "arm64":
                raise base.BootError("Run this Wi-Fi test on the Apple Silicon Mac connected to the Air 2.")
            wheel = ctx.bundle / "runtime/wheels/pyusb-1.3.1-py3-none-any.whl"
            for relative in ("payloads/wifi-base/Pongo.bin", "runtime/bin/palera1n-macos-arm64",
                             "runtime/libusb/libusb-1.0.dylib", "runtime/wheels/pyusb-1.3.1-py3-none-any.whl"):
                entry = ctx.manifest["files"][relative]
                if len(pinned_bytes(ctx.bundle / relative, entry["sha256"], entry["bytes"])) != entry["bytes"]:
                    raise base.BootError("A verified boot runtime file changed size.")
            sys.path.insert(0, str(wheel))
            try:
                import usb.core
                import usb.util
                import usb.backend.libusb1
                backend = usb.backend.libusb1.get_backend(find_library=lambda _: str(self.libusb))
            except (ImportError, OSError) as exc:
                raise base.BootError("The verified USB runtime could not load. Keep the original preparation folder intact.") from exc
            if backend is None:
                raise base.BootError("The verified USB library could not load.")
            self._core, self._util, self._backend = usb.core, usb.util, backend
            self._runtime_ready = True

        def _upload(self, device, identity, *, fresh_pongo):
            if not fresh_pongo:
                raise base.BootError("A fresh observed DFU-to-Pongo transition is required. Return to iPadOS before another boot attempt.")
            self._check_cancel()
            self._identity(device, expected=identity.ecid, pongo=True)
            # A new radio identification while this helper waited cannot
            # silently change which device/board selection this image uses.
            selector, radio_run, _ = validate_evidence(ctx, self.state_dir)
            if (radio_run["run_id"] != self.run_record["source_radio_run_id"]
                    or digest(ctx.firmware.json_bytes(selector)) != self.run_record["radio_selector_sha256"]):
                raise base.BootError("The radio evidence changed during preparation. Stop and prepare a new Wi-Fi test.")
            radio_mac, radio_adt_hash = read_radio_adt(ctx, self.state_dir, radio_run)
            if (radio_mac != self.run_record["radio_expected_mac"]
                    or radio_adt_hash != self.run_record["radio_adt_sha256"]
                    or digest(self._payload) != self.run_record["payload_sha256"]):
                raise base.BootError("The private Wi-Fi boot inputs changed after preparation. No image was uploaded.")
            device.set_configuration()
            self._emit("platform", "Checking the iPad's private Wi-Fi hardware identity", "The address stays on this Mac; it is not included in the public report.")
            adt = ctx.radio.capture_adt(device, self._check_cancel)
            expected_mac = parse_adt_mac(adt, ctx.radio_parser)
            if expected_mac != radio_mac:
                raise base.BootError("The current Wi-Fi hardware address differs from the completed radio test. No image was uploaded.")
            ctx.radio.private_write(self.prepared.folder / "apple-device-tree.txt", adt)
            self.run_record.update(expected_mac=expected_mac,
                                   mac_source="pongo-adt-chosen-mac-address-wifi0", state="pongo_verified")
            ctx.radio.private_json(self.state_dir / "wifi-run.json", self.run_record)
            super()._upload(device, identity, fresh_pongo=True)

        def ensure_linux(self, session_probe):
            self._prepare()
            devices = self._devices()
            try:
                if any(d.idVendor == 0x05AC and d.idProduct == base.PONGO for d in devices):
                    raise base.BootError("PongoOS is already running. Hold Home + top Power until the Apple logo, unlock iPadOS, then start a fresh Wi-Fi boot.")
                if any((d.idVendor, d.idProduct) == base.LINUX for d in devices):
                    raise base.BootError("A Linux USB device is still present. Keep it running and retry collection, or return to iPadOS manually before a fresh Wi-Fi boot.")
            finally:
                for device in devices:
                    self._dispose(device)
            ctx.radio.private_json(self.state_dir / "wifi-run.json", self.run_record)
            result = super().ensure_linux(session_probe)
            self.run_record["state"] = "linux_verified"
            ctx.radio.private_json(self.state_dir / "wifi-run.json", self.run_record)
            return result

    return WiFiFlow


class BootRunner:
    """Root's CLI handles physical restart prompts and holds its app lock."""
    def __init__(self, context, state, public_firmware, log, event):
        self.context, self.state = context, Path(state)
        self.public_firmware, self.log, self.event = public_firmware, log, event
        self.prepared = None
        self.flow = None

    def prepare(self):
        if self.prepared is None:
            self.prepared = prepare_session(self.context, self.state, self.public_firmware)
        return dict(self.prepared.record)

    def continue_dfu(self):
        return False if self.flow is None else self.flow.continue_dfu()

    def boot(self):
        kernel = self.context.radio.observed_kernel(self.context.shell_class)
        if kernel == KERNEL:
            record = read_wifi_run(self.context, self.state)
            if not probe_wifi(self.context.shell_class, record):
                raise RuntimeError("The existing Wi-Fi USB shell could not be verified. Keep it running and reconnect the cable once.")
            return record
        if kernel is not None:
            raise RuntimeError("The current Linux RAM session is still running. Save your work and physically return the iPad to normal iPadOS before this new kernel boot.")
        self.prepare()
        Flow = wifi_flow_class(self.context)
        self.flow = Flow(self.state, self.prepared, self.log, self.event)
        self.flow.ensure_linux(lambda: False if "expected_mac" not in self.flow.run_record
                               else probe_wifi(self.context.shell_class, self.flow.run_record))
        return read_wifi_run(self.context, self.state)

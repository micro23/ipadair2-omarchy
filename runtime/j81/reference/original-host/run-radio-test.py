#!/usr/bin/env python3
"""J81 radio identification: verified RAM boot and a private, bounded capture.

--check validates local files only. --boot performs the interactive physical
boot workflow. --report resumes collection from this helper's current radio
test boot. No command reboots a running Linux session or starts a desktop.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
TARGET = "iPad5,3/J81AP/T7001"
KERNEL = "7.3.0-rc1-j81-radio-id"
OLD_KERNEL = "7.3.0-rc1-j81-ramonly"
PONGO_SHA256 = "1e5543fd8e6dbd84c334b87d71aa473f4d347c2ba8a5e863b6e10f18461c7575"
PALERA1N_SHA256 = "950c357b6ae5df36128f6e42a3c6d371e55aeb69a5afcde276f096276210d0c9"
PYUSB_SHA256 = "bf9b754557af4717fe80c2b07cc2b923a9151f5c08d17bdb5345dac09d6a0430"
LIBUSB_SHA256 = "59644bed86d641b47dc24792dc52cf1b93cfd1f93e383137e4ba47a815191868"
PAYLOAD_PARTS = ("m1n1.bin", "bootargs", "t7001-j81.dtb", "Image.gz", "initramfs.gz")
sys.dont_write_bytecode = True


class DiagnosticIncomplete(RuntimeError):
    def __init__(self, message, metadata=None):
        super().__init__(message)
        self.metadata = metadata or {}


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def verify_bundle(root=ROOT):
    root = Path(root).resolve()
    path = root / "bundle-manifest.json"
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise RuntimeError("The bundle manifest is missing or invalid. Extract a fresh copy.")
    value = json.loads(path.read_text("utf-8"))
    if (not isinstance(value, dict) or value.get("format") != 1
            or value.get("target") != TARGET or value.get("purpose") != "wifi-preparation-v1"):
        raise RuntimeError("This is not the expected J81 Wi-Fi preparation bundle.")
    files = value.get("files")
    required = {
        "host/run-radio-test.py", "host/boot_flow_base.py", "host/apple_identity.py",
        "host/radio_identity.py", "host/usb_shell.py",
        "runtime/bin/palera1n-macos-arm64", "runtime/libusb/libusb-1.0.dylib",
        "runtime/wheels/pyusb-1.3.1-py3-none-any.whl",
        "payloads/radio-id/m1n1-linux.bin", "payloads/radio-id/Pongo.bin",
        "payloads/radio-id/kernel.config", "payloads/radio-id/manifest.json",
    } | {"payloads/radio-id/" + name for name in PAYLOAD_PARTS}
    if not isinstance(files, dict) or not required.issubset(files) or len(files) > 4096:
        raise RuntimeError("The preparation bundle is incomplete.")
    for name, item in files.items():
        relative = PurePosixPath(name)
        if (not name or relative.is_absolute() or ".." in relative.parts or "\\" in name
                or "\0" in name or not isinstance(item, dict)
                or type(item.get("bytes")) is not int or not 0 <= item["bytes"] <= 128 * 1024 * 1024
                or not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", "")))):
            raise RuntimeError("The preparation bundle contains an invalid file entry.")
        candidate = root / name
        if (candidate.is_symlink() or not candidate.is_file()
                or not candidate.resolve().is_relative_to(root)
                or candidate.stat().st_size != item["bytes"] or digest(candidate) != item["sha256"]):
            raise RuntimeError("Bundle integrity check failed: " + name)
    for name, wanted in {
        "payloads/radio-id/Pongo.bin": PONGO_SHA256,
        "runtime/bin/palera1n-macos-arm64": PALERA1N_SHA256,
        "runtime/libusb/libusb-1.0.dylib": LIBUSB_SHA256,
        "runtime/wheels/pyusb-1.3.1-py3-none-any.whl": PYUSB_SHA256,
    }.items():
        if files[name]["sha256"] != wanted:
            raise RuntimeError("A required runtime component is not the pinned build: " + name)
    payload = root / "payloads/radio-id"
    combined = b"".join((payload / name).read_bytes() for name in PAYLOAD_PARTS)
    if not 0 < len(combined) <= 128 * 1024 * 1024 or combined != (payload / "m1n1-linux.bin").read_bytes():
        raise RuntimeError("The radio identification image does not match its verified components.")
    return value


def compose_run_payload(payload_dir, run_id):
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise RuntimeError("Invalid private run identifier.")
    parts = {name: (Path(payload_dir) / name).read_bytes() for name in PAYLOAD_PARTS}
    args = parts["bootargs"]
    if (not args.endswith(b"\n") or args.count(b"\n") != 1 or b"\0" in args
            or b"j81.radio_run=" in args or len(args) > 4096):
        raise RuntimeError("The verified boot arguments have an unsupported format.")
    parts["bootargs"] = args[:-1] + b" j81.radio_run=" + run_id.encode("ascii") + b"\n"
    result = b"".join(parts[name] for name in PAYLOAD_PARTS)
    if len(result) > 128 * 1024 * 1024:
        raise RuntimeError("The radio identification image exceeds the bootloader limit.")
    return result


def private_dir(path):
    path = Path(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("The private J81 working folder has unexpected permissions.")
    return path


def private_write(path, data, *, replace=False):
    path = Path(path)
    if replace:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise RuntimeError("An existing private J81 record has unexpected permissions.")
        fd, temporary = tempfile.mkstemp(prefix=".j81-record-", dir=path.parent)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        temporary = str(path)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
    finally:
        if replace:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)


def private_json(path, value):
    private_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(), replace=True)


def read_record(state, base_hash):
    path = Path(state) / "radio-run.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 16384:
                raise RuntimeError("The private radio boot record is invalid.")
            record = json.load(stream)
    except FileNotFoundError as exc:
        raise RuntimeError("There is no matching radio-test boot record. Start the radio test from this package first.") from exc
    if (not isinstance(record, dict) or record.get("format") != 1
            or record.get("target") != TARGET or record.get("kernel") != KERNEL
            or not re.fullmatch(r"[0-9a-f]{32}", str(record.get("run_id", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("device", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("payload_sha256", "")))
            or record.get("base_payload_sha256") != base_hash
            or record.get("platform") != "rieslinga" or record.get("platform_validated") is not True
            or record.get("state") not in ("pongo_verified", "radio_verified", "radio_incomplete")):
        raise RuntimeError("The private radio-test record does not match this package and platform.")
    return record


def exact_guard(run_id):
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise RuntimeError("Invalid radio run identifier.")
    return "\n".join([
        "set -eu", f"[ \"$(uname -r)\" = '{KERNEL}' ]",
        "tr '\\000' '\\n' </proc/device-tree/compatible | grep -Fqx 'apple,j81'",
        "tr '\\000' '\\n' </proc/device-tree/compatible | grep -Fqx 'apple,t7001'",
        "awk '$2 == \"/run\" && $3 == \"tmpfs\" {found=1} END {exit !found}' /proc/mounts",
        "[ \"$(tr ' ' '\\n' </proc/cmdline | grep -c '^j81.radio_run=')\" = 1 ]",
        f"tr ' ' '\\n' </proc/cmdline | grep -Fqx 'j81.radio_run={run_id}'",
    ])


def observed_kernel(shell_class):
    shell = None
    try:
        shell = shell_class()
        output, code = shell.run("uname -r", seconds=5, check=False)
        if code or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", output.strip()):
            raise RuntimeError("The connected USB shell did not return a recognizable kernel identity.")
        return output.strip()
    except OSError:
        return None
    finally:
        if shell is not None:
            with contextlib.suppress(OSError):
                shell.close()


def probe_radio(shell_class, record):
    shell = None
    try:
        shell = shell_class()
        _, code = shell.run(exact_guard(record["run_id"]), seconds=10, check=False)
        if code:
            raise RuntimeError("The USB shell is running a different image or radio-test session. No diagnostic or upload was performed on it.")
        return True
    except OSError:
        return False
    finally:
        if shell is not None:
            with contextlib.suppress(OSError):
                shell.close()


def capture_adt(device, check_cancel):
    def read():
        check_cancel()
        return bytes(device.ctrl_transfer(0xA1, 1, 0, 0, 512, timeout=1000)).rstrip(b"\0")
    start = time.monotonic()
    quiet = None
    while quiet is None or time.monotonic() - quiet < 0.25:
        if time.monotonic() - start >= 5:
            raise RuntimeError("The bootloader console did not become idle before reading the hardware description.")
        if read():
            quiet = None
        elif quiet is None:
            quiet = time.monotonic()
        time.sleep(0.01)
    check_cancel()
    if device.ctrl_transfer(0x21, 3, 0, 0, b"dt\n", timeout=5000) != 3:
        raise RuntimeError("The bootloader did not accept the hardware-description request.")
    started, last_data = time.monotonic(), None
    captured = bytearray()
    while time.monotonic() - started < 90:
        chunk = read()
        now = time.monotonic()
        if chunk:
            captured.extend(chunk)
            last_data = now
            if len(captured) > 8 * 1024 * 1024:
                raise RuntimeError("The private hardware description exceeded its size limit.")
        elif last_data is not None and now - last_data >= 2:
            return bytes(captured)
        else:
            time.sleep(0.01)
    raise RuntimeError("The private hardware-description capture did not finish in time.")


def radio_flow_class(base, parser):
    class RadioFlow(base.BootFlow):
        def __init__(self, root, state, manifest, log, event):
            super().__init__(root, state, log, event=event)
            self.bundle = Path(root) / "payloads/radio-id"
            self.palera1n = Path(root) / "runtime/bin/palera1n-macos-arm64"
            self.libusb = Path(root) / "runtime/libusb/libusb-1.0.dylib"
            self.manifest = manifest
            self.run_record = None
            self.prepared = False

        def _emit(self, phase, message, detail="", needs_action=None):
            replacements = {
                "checking": ("Checking the connected iPad", "The radio test only proceeds on the verified Wi-Fi Air 2."),
                "linux_upload": ("Loading the radio identification image into RAM", "This new experimental build reads the radio identity; it does not load Wi-Fi firmware."),
                "linux_ready": ("The radio identification Linux image is running", "Collecting the bounded radio metadata next."),
            }
            if phase in replacements:
                message, detail = replacements[phase]
            detail = detail.replace("Click Ready", "Press Return")
            super()._emit(phase, message, detail, needs_action)

        def _prepare(self):
            if self.prepared:
                return
            if platform.system() != "Darwin" or platform.machine() != "arm64":
                raise base.BootError("Run this package on the Apple Silicon Mac connected to your Air 2.")
            private_dir(self.state_dir)
            self.run_id = secrets.token_hex(16)
            self.run_dir = private_dir(private_dir(self.state_dir / "radio-runs") / self.run_id)
            self._payload = compose_run_payload(self.bundle, self.run_id)
            # A newly prepared run invalidates any older selector for automatic
            # use, while retaining old private captures for diagnosis.
            private_json(self.state_dir / "radio-run.json", {
                "format": 1, "target": TARGET, "kernel": KERNEL,
                "run_id": self.run_id, "state": "prepared",
                "base_payload_sha256": self.manifest["files"]["payloads/radio-id/m1n1-linux.bin"]["sha256"],
                "payload_sha256": hashlib.sha256(self._payload).hexdigest(),
            })
            wheel = self.resources / "runtime/wheels/pyusb-1.3.1-py3-none-any.whl"
            sys.path.insert(0, str(wheel))
            try:
                import usb.core
                import usb.util
                import usb.backend.libusb1
                backend = usb.backend.libusb1.get_backend(find_library=lambda _: str(self.libusb))
            except (ImportError, OSError) as exc:
                raise base.BootError("The bundled USB runtime could not load. Extract a fresh complete copy.") from exc
            if backend is None:
                raise base.BootError("The bundled USB library could not load.")
            self._core, self._util, self._backend = usb.core, usb.util, backend
            self.prepared = True

        def _upload(self, device, identity, *, fresh_pongo):
            if not fresh_pongo:
                raise base.BootError("This test requires a fresh DFU-to-Pongo boot observed by this helper. Return to iPadOS and run it again.")
            self._check_cancel()
            base.check_j81(identity, self._expected_ecid, pongo=True)
            self._identity(device, expected=identity.ecid, pongo=True)
            device.set_configuration()
            self._emit("platform", "Reading the Air 2 hardware description", "The private data stays on this Mac; only the radio platform selector is retained in the report.")
            data = capture_adt(device, self._check_cancel)
            platform_name = parser.parse_adt_platform(data)
            private_write(self.run_dir / "apple-device-tree.txt", data)
            self.run_record = {
                "format": 1, "target": TARGET, "kernel": KERNEL, "run_id": self.run_id,
                "device": self._journal_fingerprint(identity.ecid),
                "base_payload_sha256": self.manifest["files"]["payloads/radio-id/m1n1-linux.bin"]["sha256"],
                "payload_sha256": hashlib.sha256(self._payload).hexdigest(),
                "platform": platform_name, "platform_validated": True, "state": "pongo_verified",
            }
            private_json(self.state_dir / "radio-run.json", self.run_record)
            super()._upload(device, identity, fresh_pongo=True)

        def ensure_linux(self, session_probe):
            self._prepare()
            devices = self._devices()
            try:
                if any(d.idVendor == 0x05AC and d.idProduct == base.PONGO for d in devices):
                    raise base.BootError("PongoOS is already running. To establish a fresh upload buffer, hold Home + top Power until the Apple logo appears, unlock iPadOS, then run this test again.")
            finally:
                for device in devices:
                    self._dispose(device)
            return super().ensure_linux(session_probe)

    return RadioFlow


def safe_metadata(output):
    """Allow-list numeric, nonunique metadata; never echo arbitrary log text."""
    result = {}
    matches = re.findall(r"t7000-bcm-probe: chipid=0x[0-9a-f]{8} chip=(0x[0-9a-f]{4}) chiprev=([0-9]{1,2}) pkg=[0-9]+ eromptr=0x[0-9a-f]{8}", output)
    if len(matches) == 1:
        result["Chip"] = matches[0][0]
        result["Chip revision"] = matches[0][1]
    matches = re.findall(r"t7000-bcm-probe: erom first component: id=0x[0-9a-f]+ rev=([0-9]{1,3})", output)
    if len(matches) == 1:
        result["ChipCommon revision"] = matches[0]
    matches = re.findall(r"t7000-bcm-probe: mapping path: (chipcommon|gci|stop)(?=\s|$)", output)
    if len(matches) == 1:
        result["Observed mapping path"] = matches[0]
    return result


def collect_radio(shell_class, parser, record, state):
    shell = None
    output = ""
    script = exact_guard(record["run_id"]) + "\n" + r"""/bin/busybox timeout -s KILL 12 sh <<'J81_FIXED_RADIO_READS'
set -eu
printf 'J81_RADIO_LOG_BEGIN\n'
dmesg | grep -F 't7000-bcm-probe:' | head -c 22000
printf '\nJ81_RADIO_LOG_END\n'
[ -r /sys/kernel/debug/t7000-bcm-otp-shadow ]
size=$(wc -c </sys/kernel/debug/t7000-bcm-otp-shadow)
[ "$size" -gt 0 ] && [ "$size" -le 1024 ]
printf 'J81_RADIO_SHADOW_BEGIN\n'
base64 /sys/kernel/debug/t7000-bcm-otp-shadow
printf '\nJ81_RADIO_SHADOW_END\n'
J81_FIXED_RADIO_READS
"""
    run_dir = private_dir(private_dir(Path(state) / "radio-runs") / record["run_id"])
    try:
        shell = shell_class()
        output, code = shell.run(script, seconds=20, check=False)
    finally:
        if shell is not None:
            with contextlib.suppress(OSError):
                shell.close()
    private_write(run_dir / ("capture-" + secrets.token_hex(4) + ".txt"), output.encode("utf-8"))
    if code:
        record["state"] = "radio_incomplete"
        private_json(Path(state) / "radio-run.json", record)
        raise DiagnosticIncomplete("The bounded radio read did not complete; the probe may have refused an unsupported mapping or the shadow may be unavailable. No firmware selector was generated.", safe_metadata(output))
    try:
        selector, shadow = parser.parse_probe_capture(
            output, platform=record["platform"], base_payload_sha256=record["base_payload_sha256"],
            payload_sha256=record["payload_sha256"])
    except parser.RadioIdentityError as exc:
        record["state"] = "radio_incomplete"
        private_json(Path(state) / "radio-run.json", record)
        raise DiagnosticIncomplete(str(exc) + " No firmware selector was generated.", safe_metadata(output)) from exc
    private_write(run_dir / ("otp-shadow-" + secrets.token_hex(4) + ".bin"), shadow)
    record["state"] = "radio_verified"
    private_json(Path(state) / "radio-run.json", record)
    private_json(Path(state) / "radio-selector.json", selector)
    return selector


def save_public_report(selector=None, failure=None):
    lines = [
        "J81 radio identification report", "Target: Wi-Fi iPad Air 2 / iPad5,3 / J81AP",
        "Kernel: " + KERNEL,
        "Collected: " + datetime.datetime.now(datetime.timezone.utc).isoformat(),
    ]
    if selector is not None:
        lines += ["Result: radio identity and private capture verified",
        "Chip: " + selector["chip"], "Chip revision: " + str(selector["chip_rev"]),
        "ChipCommon revision: " + str(selector["chipcommon_rev"]),
        "Apple radio stepping: " + selector["stepping"], "Platform: " + selector["platform"],
        "Module: " + selector["module"], "Vendor: " + selector["vendor"],
        "Module version: " + selector["version"]]
    else:
        lines += ["Result: Linux booted; radio identity selection is incomplete.",
                  "Diagnostic: " + str(failure)]
        lines += [str(key) + ": " + str(value) for key, value in failure.metadata.items()]
    lines += [
        "Firmware loaded: no", "Wi-Fi association attempted: no",
        "Raw Apple hardware data, OTP, MAC addresses, and device identifiers are omitted.", "",
    ]
    report = "\n".join(lines)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    fd, name = tempfile.mkstemp(prefix="J81-radio-report-" + stamp + "-", suffix=".txt", dir=Path.home() / "Downloads")
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(report)
    print("\n" + report + "Saved shareable report:\n" + name + "\n\nAttach that text file in our chat.", flush=True)
    try:
        subprocess.run(["/usr/bin/open", "-R", name], capture_output=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return Path(name)


def main(argv=None):
    arguments = argparse.ArgumentParser(description=__doc__)
    modes = arguments.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--boot", action="store_true")
    modes.add_argument("--report", action="store_true")
    args = arguments.parse_args(argv)
    try:
        manifest = verify_bundle()
        print("J81 radio-test bundle hashes verified.", flush=True)
        if not (args.boot or args.report):
            print("Local checks complete. No iPad connection or device action was performed.")
            return 0
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise RuntimeError("Run this helper on the Apple Silicon Mac connected to the Air 2.")
        sys.path.insert(0, str(ROOT / "host"))
        import boot_flow_base as base
        import radio_identity as radio
        from usb_shell import IPadShell
        state = private_dir(Path.home() / "Library/Application Support/J81 WiFi Next")
        lock_fd = os.open(state / "radio.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lock_fd, "w") as lock:
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise RuntimeError("The radio-test lock has unexpected permissions.")
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("Another radio-test helper is running. Use its Terminal window.") from exc
            base_hash = manifest["files"]["payloads/radio-id/m1n1-linux.bin"]["sha256"]
            kernel = observed_kernel(IPadShell)
            if args.report or kernel == KERNEL:
                record = read_record(state, base_hash)
                if not probe_radio(IPadShell, record):
                    raise RuntimeError("The radio-test USB shell is not reachable. Keep the iPad running, reconnect its cable once, then retry --report.")
            else:
                while kernel is not None:
                    if kernel != OLD_KERNEL:
                        raise RuntimeError("A different Linux image is running. Keep that session intact; return to normal iPadOS manually before this radio test.")
                    print("\nYour working Omarchy RAM session is still running.")
                    print("This next test needs a fresh boot and will replace that temporary session with a text diagnostic.")
                    print("Save any work first. Hold Home + top Power until the Apple logo appears, then unlock iPadOS.")
                    input("Press Return after the iPad is back in normal iPadOS: ")
                    kernel = observed_kernel(IPadShell)
                flow = None
                def event(value):
                    if value["phase"] == "reconnect":
                        print("\a", end="", flush=True)
                    print("\n" + value["message"] + ("\n" + value["detail"] if value.get("detail") else ""), flush=True)
                    if value.get("needs_action") == "dfu_ready":
                        input("Press Return when your fingers are ready on Home and top Power: ")
                        flow.continue_dfu()
                Flow = radio_flow_class(base, radio)
                flow = Flow(ROOT, state, manifest, lambda line: print(line, flush=True), event)
                def probe():
                    return False if flow.run_record is None else probe_radio(IPadShell, flow.run_record)
                flow.ensure_linux(probe)
                record = read_record(state, base_hash)
            try:
                selector = collect_radio(IPadShell, radio, record, state)
            except DiagnosticIncomplete as exc:
                save_public_report(failure=exc)
                print("Linux remains running. Send the report; repeating the boot upload is not a radio fix.")
                return 2
            save_public_report(selector)
            print("The radio test remains running. Keep the iPad connected for the next step.")
        return 0
    except (KeyboardInterrupt, EOFError):
        print("\nRadio test cancelled. No restore or erase command was sent.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, ValueError) as exc:
        # Never include raw ADT, raw diagnostic output, or private identifiers.
        message = str(exc)
        message = re.sub(r"\b[0-9a-fA-F]{24,64}\b", "[private identifier]", message)
        message = re.sub(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", "[MAC omitted]", message)
        print("\nSTOP: " + message, file=sys.stderr)
        print("Keep the iPad screen as it is and copy this message. The helper will not repeat a partial upload.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

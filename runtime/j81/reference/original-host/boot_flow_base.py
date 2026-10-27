"""Guarded, RAM-only boot flow for the one-device J81 Omarchy Mac launcher.

Hardware boot payloads are byte-identical to the user's confirmed working build.
The new orchestration is locally tested with fakes; a Mac/iPad trial is still
required. USB chip identifiers are used only in memory and never sent to logs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import re
import select
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time

from apple_identity import identify_normal, IdentificationError


DFU = 0x1227
RECOVERY = frozenset((0x1280, 0x1281, 0x1282, 0x1283))
PONGO = 0x4141
LINUX = (0x18D1, 0xD001)
PONGO_VERSION = "PongoOS-2.6.3-bb492b00"
PALERA1N_SHA256 = "950c357b6ae5df36128f6e42a3c6d371e55aeb69a5afcde276f096276210d0c9"
PAYLOAD_SHA256 = "886824eab4dcb4efa6babc9d1cdbdb776331d3d95de7390dc481d088c7c1e74e"
PONGO_SHA256 = "1e5543fd8e6dbd84c334b87d71aa473f4d347c2ba8a5e863b6e10f18461c7575"
PYUSB_SHA256 = "bf9b754557af4717fe80c2b07cc2b923a9151f5c08d17bdb5345dac09d6a0430"


class BootError(RuntimeError):
    """An actionable failure, after which this object never retries USB writes."""


class BootCancelled(BootError):
    pass


@dataclass(frozen=True)
class USBIdentity:
    chip: int
    board: int
    ecid: int = field(repr=False)
    version: str = ""


def parse_usb_identity(serial):
    if not isinstance(serial, str) or len(serial) > 1024:
        raise BootError("The iPad's USB identity could not be verified. No boot payload was sent.")
    values = {}
    for name, digits in (("CPID", 4), ("BDID", 2), ("ECID", 16)):
        matches = re.findall(r"(?:^|\s)" + name + r":([0-9A-Fa-f]{1," + str(digits) + r"})(?=\s|$)", serial)
        # Reject duplicate or malformed fields rather than accepting a prefix.
        if len(matches) != 1 or len(re.findall(r"(?:^|\s)" + name + ":", serial)) != 1:
            raise BootError("The iPad's USB identity is incomplete or ambiguous. No boot payload was sent.")
        values[name] = int(matches[0], 16)
    if not values["ECID"]:
        raise BootError("The iPad did not expose a valid chip identity. No boot payload was sent.")
    versions = re.findall(r"(?:^|\s)SRTG:\[([^\]\r\n]{1,128})\](?=\s|$)", serial)
    if len(versions) > 1:
        raise BootError("The iPad returned an ambiguous bootloader identity.")
    return USBIdentity(values["CPID"], values["BDID"], values["ECID"], versions[0] if versions else "")


def check_j81(identity, expected_ecid=None, *, pongo=False):
    if identity.chip != 0x7001 or identity.board != 0x06:
        raise BootError("This app is only for the Wi-Fi iPad Air 2 (iPad5,3 / J81AP). No boot payload was sent.")
    if expected_ecid is not None and identity.ecid != expected_ecid:
        raise BootError("The connected iPad changed during boot. Reconnect the original Air 2 and restart this boot attempt.")
    if pongo and identity.version != PONGO_VERSION:
        raise BootError("This PongoOS build is not the matching Linux loader. Hold Home + top Power until the Apple logo appears, unlock iPadOS, then start again.")
    return identity


def validate_normal(info):
    if not isinstance(info, dict):
        raise BootError("Connect and unlock the Wi-Fi iPad Air 2, then start again.")
    if info.get("product_type") != "iPad5,3" or str(info.get("hardware_model", "")).upper() != "J81AP":
        raise BootError("This app is only for the Wi-Fi iPad Air 2 (iPad5,3 / J81AP). The connected device has not been changed.")
    version = info.get("product_version", "")
    if not isinstance(version, str) or not re.fullmatch(r"15(?:\.[0-9]+){1,2}", version):
        raise BootError("This build was prepared for the Air 2 on iPadOS 15. The connected device has not been changed.")
    ecid = info.get("ecid")
    if type(ecid) is not int or not 0 < ecid <= 0xFFFFFFFFFFFFFFFF:
        raise BootError("The Air 2 chip identity could not be verified. Unlock it and reconnect its cable.")
    return ecid


_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def public_log_line(text):
    """Keep progress messages while removing common device-identifier formats."""
    text = _ANSI.sub("", text)
    text = re.sub(r"\b(?:ECID|UDID|UniqueChipID)\s*[:=]\s*[^\s]+", "device-id: [private]", text, flags=re.I)
    text = re.sub(r"\b[0-9a-fA-F]{24,64}\b", "[private identifier]", text)
    text = re.sub(r"\b[0-9]{12,20}\b", "[private identifier]", text)
    return "".join(c for c in text if c == "\t" or ord(c) >= 32).strip()


def _verify_file(path, digest, size=None):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or (size is not None and info.st_size != size):
            raise ValueError("not the expected regular file")
        data = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise BootError("A required app component is missing or damaged: " + path.name + ". Download a fresh copy of the app.") from exc
    if hashlib.sha256(data).hexdigest() != digest:
        raise BootError("An app component failed its integrity check: " + path.name + ". Download a fresh copy of the app.")
    return data


class BootFlow:
    """Blocking worker. All callbacks run on the worker thread.

    event receives dicts containing phase/message/detail/needs_action. A
    needs_action value of "dfu_ready" enables the UI button that invokes
    continue_dfu(). All other events clear that prompt. cancel is a
    threading.Event; cancelling never sends a boot/reboot/restore command.

    ensure_linux(session_probe) calls a READ-ONLY probe repeatedly. The probe
    must return truthy only after verifying the exact J81 kernel and device
    tree. It returns false for a currently unreachable shell and raises on a
    reachable wrong image. Successful USB handoff alone never means booted.
    """
    def __init__(self, resources, state_dir, log, event=None, cancel=None, *, status=None):
        self.resources = Path(resources).resolve()
        self.state_dir = Path(state_dir).resolve()
        self.bundle = self.resources / "bundles" / "ipad-air2-ram-test-v1"
        self.palera1n = self.resources / "runtime" / "bin" / "palera1n-macos-arm64"
        self.libusb = self.resources / "runtime" / "libusb" / "libusb-1.0.dylib"
        self.log = log
        self.event = event if event is not None else status
        if not callable(self.event) or not callable(log):
            raise TypeError("log and event/status callbacks are required")
        self.cancel = cancel if cancel is not None else threading.Event()
        self._ready = threading.Event()
        self._prompt_lock = threading.Lock()
        self._awaiting_dfu = False
        self._core = self._util = self._backend = None
        self._journal = self.state_dir / "boot-attempt.json"
        self._payload = None
        self._process = None
        self._expected_ecid = None
        self._ran = False
        self._reconnect_notified = False

    def _emit(self, phase, message, detail="", needs_action=None):
        self.event({"phase": phase, "message": message, "detail": detail, "needs_action": needs_action})

    def _check_cancel(self):
        if self.cancel.is_set():
            raise BootCancelled("Boot cancelled. The app did not send a restore or erase command. You can hold Home + top Power until the Apple logo appears to return to iPadOS.")

    def continue_dfu(self):
        with self._prompt_lock:
            if not self._awaiting_dfu or self.cancel.is_set():
                return False
            self._ready.set()
            return True

    def _prepare(self):
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise BootError("This package runs on an Apple Silicon Mac.")
        self._payload = _verify_file(self.bundle / "m1n1-linux.bin", PAYLOAD_SHA256, 9297647)
        _verify_file(self.bundle / "Pongo.bin", PONGO_SHA256, 238096)
        _verify_file(self.palera1n, PALERA1N_SHA256)
        wheel = self.bundle / "wheels" / "pyusb-1.3.1-py3-none-any.whl"
        _verify_file(wheel, PYUSB_SHA256, 58465)
        if not self.libusb.is_file() or self.libusb.is_symlink():
            raise BootError("The app's USB library is missing. Download a fresh copy of the app.")
        if str(wheel) not in sys.path:
            sys.path.insert(0, str(wheel))
        try:
            import usb.core
            import usb.util
            import usb.backend.libusb1
            backend = usb.backend.libusb1.get_backend(find_library=lambda _: str(self.libusb))
        except (ImportError, OSError) as exc:
            raise BootError("The app's USB library could not be loaded. Download a fresh copy of the app.") from exc
        if backend is None:
            raise BootError("The app's USB library could not be loaded.")
        self._core, self._util, self._backend = usb.core, usb.util, backend
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BootError("The app's private state directory has unexpected permissions.")

    def _devices(self):
        self._check_cancel()
        try:
            all_devices = list(self._core.find(find_all=True, backend=self._backend))
            relevant = [dev for dev in all_devices if
                        (dev.idVendor == 0x05AC and dev.idProduct in ({DFU, PONGO} | RECOVERY))
                        or (dev.idVendor, dev.idProduct) == LINUX]
        except self._core.USBError as exc:
            raise BootError("The app could not read the USB device list. Reconnect the iPad and retry.") from exc
        if len(relevant) > 1:
            raise BootError("More than one boot-mode device is connected. Connect only the Wi-Fi Air 2, then retry.")
        return relevant

    def _identity(self, device, *, expected=None, pongo=False):
        try:
            serial = self._util.get_string(device, device.iSerialNumber)
            return check_j81(parse_usb_identity(serial), expected, pongo=pongo)
        except self._core.USBError as exc:
            raise BootError("The iPad's USB identity could not be read. Reconnect its cable and retry.") from exc

    def _dispose(self, device):
        try:
            self._util.dispose_resources(device)
        except self._core.USBError:
            pass

    def _one_boot_device(self, kinds, *, expected=None, pongo=False, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self._check_cancel()
            devices = self._devices()
            if devices:
                device = devices[0]
                if device.idVendor == 0x05AC and device.idProduct in kinds:
                    try:
                        identity = self._identity(device, expected=expected, pongo=pongo)
                    except BaseException:
                        self._dispose(device)
                        raise
                    return device, identity
                self._dispose(device)
            self.cancel.wait(0.2)
        raise BootError("The expected iPad boot stage did not appear. If PongoOS is visible on the iPad, reconnect its USB cable once, then try again. If the screen is black or shows recovery, hold Home + top Power until the Apple logo appears and start again.")

    def _journal_fingerprint(self, ecid):
        return hashlib.sha256(b"j81-local-boot-attempt\0" + ecid.to_bytes(8, "big")).hexdigest()

    def _read_journal(self):
        try:
            info = self._journal.lstat()
        except FileNotFoundError:
            return None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > 4096):
            raise BootError("The app's previous boot record is invalid. Start the iPad from normal iPadOS before retrying.")
        try:
            value = json.loads(self._journal.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise BootError("The app could not read its previous boot record.") from exc
        if (not isinstance(value, dict) or value.get("format") != 1
                or not re.fullmatch(r"[0-9a-f]{64}", value.get("device", ""))
                or value.get("state") not in ("attempted", "handoff", "linux_verified")):
            raise BootError("The app's previous boot record is incomplete. Start the iPad from normal iPadOS before retrying.")
        return value

    def _record(self, ecid, state):
        data = {"format": 1, "device": self._journal_fingerprint(ecid), "state": state}
        fd, name = tempfile.mkstemp(prefix=".boot-attempt-", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(data, out, sort_keys=True)
                out.write("\n")
                out.flush()
                os.fsync(out.fileno())
            os.replace(name, self._journal)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    def _guard_upload(self, identity, *, fresh_pongo):
        # A newly observed DFU->matching-Pongo transition establishes a fresh
        # RAM upload buffer, even when an earlier attempt record was incomplete.
        journal = None if fresh_pongo else self._read_journal()
        if (not fresh_pongo and journal is not None
                and journal["device"] == self._journal_fingerprint(identity.ecid)):
            raise BootError("A Linux upload was already attempted on this iPad. The app will not repeat a possibly partial transfer. Hold Home + top Power until the Apple logo appears, unlock iPadOS, then launch the app again.")
        self._record(identity.ecid, "attempted")

    def _handle_line(self, raw, mode):
        line = public_log_line(raw)
        if not line:
            return
        self.log(line)
        if "Press Enter when ready for DFU mode" in line:
            # Gate the transition into DFU against the same physical chip that
            # was identified before entering recovery. Nothing is auto-entered.
            device, _ = self._one_boot_device(RECOVERY, expected=self._expected_ecid, seconds=4)
            self._dispose(device)
            with self._prompt_lock:
                self._ready.clear()
                self._awaiting_dfu = True
            self._emit("dfu_ready", "Get ready to hold the iPad buttons", "Put one finger on Home and one on the top Power button. Click Ready when you can follow the countdown.", "dfu_ready")
        elif re.search(r"Hold home \+ power button \([0-9]+\)", line):
            count = re.search(r"\(([0-9]+)\)", line).group(1)
            self._emit("dfu_countdown", "Hold Home + top Power", "Keep both buttons held. Countdown: " + count)
        elif re.search(r"Hold home button \([0-9]+\)", line):
            count = re.search(r"\(([0-9]+)\)", line).group(1)
            self._emit("dfu_countdown", "Release Power; keep holding Home", "Keep Home held until DFU is detected. Countdown: " + count)
        elif "Device entered DFU mode successfully" in line:
            self._emit("dfu", "DFU mode detected", "Release the buttons. The app is checking the iPad before loading PongoOS.")
        elif "Checkmate!" in line or "Device should now reconnect in download mode" in line:
            # These two messages normally arrive back-to-back for one handoff.
            # The user should see one cable instruction, not repeat the action.
            if not self._reconnect_notified:
                self._reconnect_notified = True
                self._emit("reconnect", "Reconnect the Lightning cable once now", "Leave the app open. Briefly unplug and reconnect the iPad cable, just as in your successful boot.")
        elif "Entered download mode" in line:
            self._emit("pongo_loading", "Cable reconnected — loading PongoOS", "Keep the cable connected.")
        elif "Booting PongoOS" in line:
            self._emit("pongo_wait", "PongoOS is starting", "If its screen appears but this step waits, reconnect the USB cable once.")
        elif "Whoops, device did not enter DFU mode" in line:
            self._emit("dfu_retry", "The iPad missed the DFU timing", "The tool is waiting for the iPad to reconnect. Follow the next Ready prompt; no Linux payload has been sent.")

    def _stop_process(self, process):
        if process.poll() is not None:
            return
        for sig, timeout in ((signal.SIGINT, 2), (signal.SIGTERM, 2), (signal.SIGKILL, 2)):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                return
            try:
                process.wait(timeout=timeout)
                return
            except subprocess.TimeoutExpired:
                pass

    def _run_palera1n(self, mode):
        self._reconnect_notified = False
        if mode == "dfu":
            args = [str(self.palera1n), "--dfuhelper", "--no-colors", "--cli"]
        elif mode == "pongo":
            args = [str(self.palera1n), "--pongo-shell", "--override-pongo", str(self.bundle / "Pongo.bin"), "--no-colors", "--cli"]
        else:
            raise ValueError("invalid palera1n mode")
        self._check_cancel()
        master, slave = pty.openpty()
        process = None
        pending = ""
        # A private temp directory is only for the verified tool's extracted
        # embedded helper; no user-controlled replacement helper is inherited.
        with tempfile.TemporaryDirectory(prefix="pongo-tool-", dir=self.state_dir) as temp:
            env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.path.expanduser("~"), "TMPDIR": temp, "LC_ALL": "C", "TERM": "dumb"}
            try:
                process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                                           cwd=self.bundle, env=env, close_fds=True, start_new_session=True)
                self._process = process
                os.close(slave)
                slave = -1
                deadline = time.monotonic() + (600 if mode == "dfu" else 90)
                closed = False
                while not closed:
                    self._check_cancel()
                    if time.monotonic() >= deadline:
                        raise BootError("The boot tool timed out. Check the iPad screen and cable, then start a fresh boot from iPadOS.")
                    with self._prompt_lock:
                        send_enter = self._awaiting_dfu and self._ready.is_set()
                        if send_enter:
                            self._awaiting_dfu = False
                            self._ready.clear()
                    if send_enter:
                        os.write(master, b"\n")
                        self._emit("dfu_countdown", "Follow the button countdown", "Keep the iPad and this window in view.")
                    readable, _, _ = select.select([master], [], [], 0.1)
                    if readable:
                        try:
                            data = os.read(master, 65536)
                        except OSError as exc:
                            if exc.errno == 5 and process.poll() is not None:
                                data = b""
                            else:
                                raise
                        if not data:
                            closed = True
                        else:
                            pending += data.decode("utf-8", "replace").replace("\r", "\n")
                            if len(pending) > 1024 * 1024:
                                raise BootError("The boot tool returned more output than expected.")
                            while "\n" in pending:
                                line, pending = pending.split("\n", 1)
                                self._handle_line(line, mode)
                            # Palera1n's countdown has no newline until the next
                            # carriage return; present the current number now.
                            if re.search(r"Hold home(?: \+ power)? button \([0-9]+\)$", _ANSI.sub("", pending)):
                                self._handle_line(pending, mode)
                                pending = ""
                    elif process.poll() is not None:
                        closed = True
                if pending:
                    self._handle_line(pending, mode)
                return process.wait(timeout=3)
            except OSError as exc:
                raise BootError("The verified Mac boot tool could not run. Check macOS Privacy & Security for an app-opening prompt.") from exc
            finally:
                with self._prompt_lock:
                    self._awaiting_dfu = False
                    self._ready.clear()
                if process is not None:
                    self._stop_process(process)
                self._process = None
                os.close(master)
                if slave != -1:
                    os.close(slave)

    def _upload(self, device, identity, *, fresh_pongo):
        self._check_cancel()
        check_j81(identity, self._expected_ecid, pongo=True)
        # Check again on this exact USB handle immediately before the first
        # configuration/upload request; enumeration alone is not identity.
        self._identity(device, expected=identity.ecid, pongo=True)
        self._guard_upload(identity, fresh_pongo=fresh_pongo)
        payload = self._payload
        self._emit("linux_upload", "Loading Linux into the iPad's memory", "Keep the cable connected. This is the same verified image that booted successfully on your Air 2.")
        try:
            device.set_configuration()
            if device.ctrl_transfer(0x21, 2, 0, 0, 0, timeout=5000) != 0:
                raise BootError("PongoOS did not confirm its upload-buffer reset. No Linux boot command was sent. Restart the iPad into normal iPadOS before another attempt.")
            self._check_cancel()
            if device.ctrl_transfer(0x21, 1, 0, 0, struct.pack("<I", len(payload)), timeout=5000) != 4:
                raise BootError("PongoOS did not accept the upload length. No Linux boot command was sent. Restart the iPad into normal iPadOS before another attempt.")
            self._check_cancel()
            written = device.write(2, payload, timeout=120000)
            if written != len(payload):
                raise BootError("The Linux transfer was incomplete. No boot command was sent. Restart the iPad into normal iPadOS before another attempt.")
            self._check_cancel()
            if device.ctrl_transfer(0x21, 4, 0, 0, b"", timeout=5000) != 0:
                raise BootError("PongoOS did not confirm command readiness. No boot command was sent. Restart the iPad into normal iPadOS before another attempt.")
        except self._core.USBError as exc:
            raise BootError("The Linux transfer stopped before boot. The app will not repeat a possibly partial upload. Restart the iPad into normal iPadOS before another attempt.") from exc
        self._check_cancel()
        self._emit("linux_boot", "Starting Linux", "A USB disconnect can occur during this handoff. The app will verify the Linux shell before continuing.")
        try:
            sent = device.ctrl_transfer(0x21, 3, 0, 0, b"bootm\n", timeout=5000)
            if sent != len(b"bootm\n"):
                self.log("The boot command acknowledgement was incomplete; waiting for actual Linux confirmation.")
        except self._core.USBError:
            self.log("USB changed during boot handoff; waiting for actual Linux confirmation.")
        self._record(identity.ecid, "handoff")

    def _wait_linux(self, probe, seconds=90):
        self._emit("linux_wait", "Waiting for the Linux USB connection", "Keep the cable connected. The app is checking the running kernel and iPad model.")
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self._check_cancel()
            if probe():
                self._emit("linux_ready", "Linux is running on the Air 2", "The J81 image is verified. Preparing the desktop next.")
                return
            self.cancel.wait(1)
        raise BootError("The Linux shell did not become reachable. Keep the iPad screen as it is and reconnect the USB cable once, then reopen the app. A USB disconnect alone is not proof Linux booted.")

    def ensure_linux(self, session_probe):
        if self._ran:
            raise BootError("This boot attempt has already run. Start a new attempt after checking the iPad screen.")
        self._ran = True
        self._check_cancel()
        self._emit("checking", "Checking the connected iPad", "An existing verified Linux session will be reused.")
        if session_probe():
            self._emit("linux_ready", "Your Linux session is already running", "Preparing or reconnecting to the desktop.")
            return {"mode": "existing", "booted": False}
        self._prepare()
        devices = self._devices()
        if devices and (devices[0].idVendor, devices[0].idProduct) == LINUX:
            self._dispose(devices[0])
            self._wait_linux(session_probe)
            return {"mode": "existing", "booted": False}
        try:
            normal = identify_normal(timeout=10)
        except IdentificationError as exc:
            for device in devices:
                self._dispose(device)
            raise BootError(str(exc)) from exc
        if devices and normal is not None:
            self._dispose(devices[0])
            raise BootError("More than one iPhone or iPad is connected. Connect only the Wi-Fi Air 2, then retry.")
        if devices:
            device = devices[0]
            mode = device.idProduct
            try:
                identity = self._identity(device, pongo=mode == PONGO)
                self._expected_ecid = identity.ecid
                if mode == PONGO:
                    self.log("Verified the Wi-Fi Air 2 and matching PongoOS build over USB.")
                    self._upload(device, identity, fresh_pongo=False)
            finally:
                self._dispose(device)
            if mode == PONGO:
                self._wait_linux(session_probe)
                self._record(identity.ecid, "linux_verified")
                return {"mode": "pongo", "booted": True}
        else:
            self._expected_ecid = validate_normal(normal)
            mode = None
            self.log("Verified Wi-Fi iPad Air 2 / J81AP / iPadOS " + normal["product_version"] + ".")
        if mode != DFU:
            self._emit("recovery", "Preparing the Air 2 for its button sequence", "The app will pause before the countdown so you can get ready.")
            self._run_palera1n("dfu")
        device, identity = self._one_boot_device({DFU}, expected=self._expected_ecid, seconds=6)
        self._dispose(device)
        # palera1n v2.4 has no per-ECID CLI selector. Recheck its other device
        # discovery channel after the human countdown, so a newly attached
        # normal-mode phone cannot be selected alongside the verified DFU iPad.
        try:
            other_normal = identify_normal(timeout=5)
        except IdentificationError as exc:
            raise BootError(str(exc)) from exc
        if other_normal is not None:
            raise BootError("Another normal-mode iPhone or iPad appeared during the button sequence. Leave only the Air 2 connected and start again. No Pongo or Linux payload was sent by this attempt.")
        self._emit("pongo_loading", "Loading the verified PongoOS image", "Keep the cable ready. When prompted, reconnect it once after Checkmate.")
        self._run_palera1n("pongo")
        self._emit("pongo_wait", "Waiting for PongoOS over USB", "If the Pongo screen is already visible, reconnect its cable once while this window waits.")
        device, identity = self._one_boot_device({PONGO}, expected=self._expected_ecid, pongo=True, seconds=45)
        try:
            self._upload(device, identity, fresh_pongo=True)
        finally:
            self._dispose(device)
        self._wait_linux(session_probe)
        self._record(identity.ecid, "linux_verified")
        return {"mode": "cold", "booted": True}

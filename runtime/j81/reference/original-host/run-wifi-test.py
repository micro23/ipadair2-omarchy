#!/usr/bin/env python3
"""Local Mac launcher for the experimental J81 Wi-Fi RAM test.

--start prepares private firmware and performs a fresh physical boot if needed.
--connect operates only on this package's already verified Wi-Fi RAM session.
--report reads its status without starting Wi-Fi or booting another image.
--disconnect stops only the connection owned by that session.
--check verifies package files locally, without contacting the iPad.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import fcntl
import getpass
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import warnings

ROOT = Path(__file__).resolve().parent.parent
TARGET = "iPad5,3/J81AP/T7001"
KERNEL = "7.3.0-rc1-j81-wifi-ram"
KNOWN_PREVIOUS_KERNELS = {"7.3.0-rc1-j81-radio-id", "7.3.0-rc1-j81-ramonly"}
REGULATORY = {
    "regulatory.db": "5560f4f0fdac7d1bb2adf8d4d083f39e3bee5ba55192feadadc091df55a813eb",
    "regulatory.db.p7s": "5dd27969661bed1e021ce435f535a53f201705bda14c2dba0db6353d1cdc6fff",
}
REQUIRED = {
    "host/run-wifi-test.py", "host/wifi_boot.py", "host/wifi_session.py", "host/tools_stage.py",
    "payload/wifi-tools.tar.gz", "payload/tools-manifest.json",
    "Start-WiFi-Test.command", "Connect-WiFi.command", "Save-WiFi-Report.command",
    "Disconnect-WiFi.command", "README.txt",
} | {"public-firmware/" + name for name in REGULATORY}
sys.dont_write_bytecode = True


class LauncherError(RuntimeError):
    """A short diagnostic suitable for the local Terminal."""


def say(message):
    print(message, flush=True)


def file_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= maximum:
            raise LauncherError("A required package file has an unexpected type or size.")
        data = stream.read(maximum + 1)
    if len(data) != info.st_size:
        raise LauncherError("A package file changed while it was being checked.")
    return data


def verify_package(root):
    root = Path(root).resolve()
    try:
        manifest = json.loads(file_bytes(root / "bundle-manifest.json", 2 * 1024 * 1024))
    except (OSError, ValueError) as exc:
        raise LauncherError("The Wi-Fi test package manifest is missing or unreadable. Extract a fresh copy of the ZIP.") from exc
    if (not isinstance(manifest, dict) or manifest.get("format") != 1
            or manifest.get("target") != TARGET or manifest.get("purpose") != "wifi-ram-test-v1"):
        raise LauncherError("This is not the expected J81 Wi-Fi RAM test package.")
    entries = manifest.get("files")
    if not isinstance(entries, dict) or not REQUIRED.issubset(entries) or len(entries) > 4096:
        raise LauncherError("The Wi-Fi test package is incomplete.")
    total = 0
    for name, entry in entries.items():
        if not isinstance(name, str):
            raise LauncherError("The Wi-Fi test manifest contains an invalid filename.")
        relative = PurePosixPath(name)
        if (not name or str(relative) != name or relative.is_absolute()
                or any(part in ("", ".", "..") for part in relative.parts)
                or "\\" in name or "\0" in name or not isinstance(entry, dict)
                or type(entry.get("bytes")) is not int or not 0 <= entry["bytes"] <= 64 * 1024 * 1024
                or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", "")))):
            raise LauncherError("The Wi-Fi test manifest contains an invalid entry.")
        total += entry["bytes"]
        if total > 256 * 1024 * 1024:
            raise LauncherError("The Wi-Fi test manifest exceeds its size limit.")
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise LauncherError("A package path is a symbolic link. Extract a fresh copy of the ZIP.")
        try:
            data = file_bytes(current, entry["bytes"])
        except OSError as exc:
            raise LauncherError("A required Wi-Fi package file is missing. Extract a fresh copy of the ZIP.") from exc
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise LauncherError("A Wi-Fi package file failed its hash check. Extract a fresh copy of the ZIP.")
    for name, wanted in REGULATORY.items():
        if entries["public-firmware/" + name]["sha256"] != wanted:
            raise LauncherError("The signed regulatory database is not the verified build.")
    return manifest


def verified_module(root, manifest, relative, name):
    entry = manifest["files"][relative]
    path = Path(root) / relative
    data = file_bytes(path, entry["bytes"])
    if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise LauncherError("A launcher component changed after package verification.")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(data, str(path), "exec"), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load_components(root, manifest):
    return SimpleNamespace(**{
        name: verified_module(root, manifest, "host/" + filename, "j81_wifi_test_" + name)
        for name, filename in (("boot", "wifi_boot.py"), ("session", "wifi_session.py"), ("stage", "tools_stage.py"))
    })


def regulatory_files(root):
    result = {}
    for name, wanted in REGULATORY.items():
        data = file_bytes(Path(root) / "public-firmware" / name, 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != wanted:
            raise LauncherError("A regulatory database file changed after verification.")
        result[name] = {"data": data, "sha256": wanted}
    return result


@contextlib.contextmanager
def application_locks(state):
    # Also exclude the original radio launcher, which owns the same USB device.
    with contextlib.ExitStack() as stack:
        for name in ("wifi-test.lock", "radio.lock"):
            fd = os.open(Path(state) / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            stream = stack.enter_context(os.fdopen(fd, "r+"))
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise LauncherError("A J81 launcher lock has unexpected ownership or permissions.")
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LauncherError("Another J81 Wi-Fi or radio helper is running. Use its Terminal window first.") from exc
        yield


def require_terminal():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise LauncherError("Open this command in the Mac Terminal. Button prompts and the Wi-Fi password require a local terminal.")


def ensure_local_firmware(modules, ctx, state):
    # Finish local preparation before asking the user to end the current RAM session.
    with ctx.firmware.state_lock(state):
        _, radio_record, _ = modules.boot.validate_evidence(ctx, state)
        modules.boot.read_radio_adt(ctx, state, radio_record)
        assets = Path(state) / "firmware/assets"
        if not assets.exists() and not assets.is_symlink():
            say("Preparing the matching Apple firmware locally on this Mac.")
            say("The first preparation may download a 2.2 GB Apple restore archive and needs about 7 GB of working space.")
            say("Keep the iPad as it is while these local files are prepared.")
            ctx.firmware.check_native_crypto()
            ctx.firmware.prepare_assets(state)


def start_or_reuse(modules, ctx, state, public_firmware, *, ask=input):
    kernel = ctx.radio.observed_kernel(ctx.shell_class)
    runner = None

    def event(value):
        if value.get("phase") == "reconnect":
            print("\a", end="", flush=True)
        say("\n" + value["message"] + ("\n" + value["detail"] if value.get("detail") else ""))
        if value.get("needs_action") == "dfu_ready":
            ask("Press Return when your fingers are ready on Home and top Power: ")
            if not runner.continue_dfu():
                raise LauncherError("The button-sequence prompt expired. Keep the iPad screen as it is and copy this message.")

    runner = modules.boot.BootRunner(ctx, state, public_firmware, say, event)
    if kernel == KERNEL:
        say("The Wi-Fi test kernel is already running. Verifying this existing session.")
        return runner.boot()
    if kernel is not None and kernel not in KNOWN_PREVIOUS_KERNELS:
        raise LauncherError("A different Linux image is running. Keep it running; this launcher will not replace an unidentified session.")
    require_terminal()
    ensure_local_firmware(modules, ctx, state)
    say("Preparing a private Wi-Fi RAM image from the completed radio identification.")
    runner.prepare()
    if kernel is not None:
        say("\nThe current radio/desktop RAM session must end so the Wi-Fi kernel can boot.")
        say("Save any temporary work. Hold Home + top Power until the Apple logo appears, then unlock iPadOS.")
        for attempt in range(3):
            ask("Press Return after the iPad is back in normal, unlocked iPadOS: ")
            kernel = ctx.radio.observed_kernel(ctx.shell_class)
            if kernel is None:
                break
            if kernel not in KNOWN_PREVIOUS_KERNELS:
                raise LauncherError("The running image changed while waiting. Keep the iPad as it is and copy this message.")
            say("The previous Linux session is still answering over USB. Wait for normal iPadOS before continuing.")
        else:
            raise LauncherError("The previous RAM session is still running. The Wi-Fi image has not been uploaded.")
    say("Leave only the identified Wi-Fi Air 2 connected by USB. Follow the button prompts below.")
    return runner.boot()


def existing_session(modules, ctx, state):
    record = modules.boot.read_wifi_run(ctx, state)
    if not modules.boot.probe_wifi(ctx.shell_class, record):
        raise LauncherError("The Wi-Fi test USB shell is not reachable. Keep the iPad running, reconnect its cable once, and retry Save-WiFi-Report.command.")
    return record


def new_session(modules, ctx, state, record):
    folder = ctx.radio.private_dir(ctx.radio.private_dir(Path(state) / "wifi-runs") / record["run_id"])
    logs = ctx.radio.private_dir(folder / "session")
    return modules.session.Session(ctx.shell_class, record["run_id"], record["expected_mac"], private_directory=logs)


def inspect_with_wait(session, *, wait=False):
    deadline = time.monotonic() + (15 if wait else 0)
    while True:
        status = session.inspect()
        if status["ready"] or time.monotonic() >= deadline:
            return status
        time.sleep(1)


def choose_network(session, modules, *, ask=input):
    require_terminal()
    say("Checking USB-shell isolation, then scanning nearby Wi-Fi networks…")
    networks = session.scan()
    supported = [entry for entry in networks if entry["wpa2_psk_ccmp"]]
    say("\nChoose a WPA2 Personal network. Network names are shown only in this local Terminal.")
    for number, entry in enumerate(supported, 1):
        signal = "" if entry["signal_dbm"] is None else "  (" + str(round(entry["signal_dbm"])) + " dBm)"
        say("  " + str(number) + ". " + entry["display"] + signal)
    if not supported:
        say("No supported named WPA2 Personal networks were found in this scan.")
    unsupported = len(networks) - len(supported)
    if unsupported:
        say(str(unsupported) + " other named network(s) were observed; this first test supports WPA2 Personal with CCMP.")
    say("  M. Enter a hidden WPA2 Personal network name manually")
    say("Press Return without a choice to save the radio/scan report and stop here.")
    for attempt in range(3):
        choice = ask("Network number, M, or Return to skip: ").strip()
        if not choice:
            return None
        if choice.lower() == "m":
            text = ask("Hidden network name (entered locally): ")
            ssid = text.encode("utf-8")
            if not 1 <= len(ssid) <= 32 or any(ord(c) < 32 or ord(c) == 127 for c in text):
                say("The name must contain 1–32 UTF-8 bytes and no control characters.")
                continue
            return ssid
        if re.fullmatch(r"[0-9]{1,3}", choice) and 1 <= int(choice) <= len(supported):
            return supported[int(choice) - 1]["ssid"]
        say("Choose one of the displayed network numbers, M, or press Return.")
    raise LauncherError("No valid network was selected. The scan report can still be saved.")


def connect_interactively(session, modules, *, ask=input, password_prompt=None):
    ssid = choose_network(session, modules, ask=ask)
    if ssid is None:
        say("Connection skipped. No password was requested.")
        return False
    password_prompt = password_prompt or getpass.getpass
    require_terminal()
    password = psk = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = password_prompt("Wi-Fi password (hidden; entered only on this Mac): ")
        psk = modules.session.derive_wpa2_psk(ssid, password)
        password = None
        say("Connecting to the selected network. Association and DHCP may take about a minute.")
        result = session.connect_wpa2(ssid, psk)
    finally:
        password = psk = None
    say("\nAssociation: " + result["association"])
    say("DHCP: " + result["dhcp"])
    say("DNS check: " + result["dns"] + "; HTTP check: " + result["http"])
    say("The Wi-Fi connection remains in this RAM session. Disconnect-WiFi.command stops it.")
    return True


SNAPSHOT_ENUMS = {
    "association": {"not tested in this report", "pending", "completed (WPA2 Personal)", "not completed"},
    "dhcp": {"not tested in this report", "pending", "configured", "not completed"},
    "internet_ping": {"not attempted", "not-confirmed", "pass"},
    "dns": {"not attempted", "not-confirmed", "pass"},
    "http": {"not attempted", "not-confirmed", "pass"},
}
SNAPSHOT_BOOLS = ("usb_shell_isolation", "scan_completed", "wifi_route", "disconnected")
SNAPSHOT_COUNTS = ("networks_seen", "supported_networks_seen")


def validated_outcomes(value):
    if not isinstance(value, dict):
        raise LauncherError("The previous connection result has an invalid format.")
    result = {}
    for key, choices in SNAPSHOT_ENUMS.items():
        if not isinstance(value.get(key), str) or value[key] not in choices:
            raise LauncherError("The previous connection result contains an unexpected status.")
        result[key] = value[key]
    for key in SNAPSHOT_BOOLS:
        if type(value.get(key)) is not bool:
            raise LauncherError("The previous connection result contains an unexpected flag.")
        result[key] = value[key]
    for key in SNAPSHOT_COUNTS:
        if type(value.get(key)) is not int or not 0 <= value[key] <= 10000:
            raise LauncherError("The previous connection result contains an invalid network count.")
        result[key] = value[key]
    return result


def remember_attempt(ctx, session, action):
    record = {"format": 1, "run_id": session.run_id, "action": action,
              "saved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "outcomes": validated_outcomes(session.results)}
    ctx.radio.private_json(session.private_directory / "last-attempt.json", record)


def previous_attempt(modules, session):
    path = session.private_directory / "last-attempt.json"
    if not path.exists() and not path.is_symlink():
        return None
    try:
        value = json.loads(modules.boot.regular_bytes(path, 8192, private=True))
        if (not isinstance(value, dict) or value.get("format") != 1 or value.get("run_id") != session.run_id
                or value.get("action") not in ("start", "connect", "disconnect")
                or not isinstance(value.get("saved_at"), str)):
            return None
        timestamp = datetime.datetime.fromisoformat(value["saved_at"])
        if timestamp.tzinfo is None or timestamp.utcoffset() != datetime.timedelta(0):
            return None
        return {"action": value["action"], "saved_at": timestamp.isoformat(),
                "outcomes": validated_outcomes(value["outcomes"])}
    except (OSError, ValueError, RuntimeError, KeyError, TypeError):
        return None


def previous_report_text(previous):
    if previous is None:
        return ""
    values = previous["outcomes"]
    return "\n".join([
        "", "== Previous attempt saved on this Mac ==",
        "Saved: " + previous["saved_at"], "Action: " + previous["action"],
        "These are earlier outcomes from this same boot session. They were not re-tested by Save Report.",
        "USB isolation verified then: " + ("yes" if values["usb_shell_isolation"] else "no"),
        "Scan completed then: " + ("yes" if values["scan_completed"] else "no"),
        "Named networks then: " + str(values["networks_seen"]),
        "Supported named networks then: " + str(values["supported_networks_seen"]),
        "Association then: " + values["association"], "DHCP then: " + values["dhcp"],
        "Wi-Fi route then: " + ("yes" if values["wifi_route"] else "no"),
        "ICMP then: " + values["internet_ping"], "DNS then: " + values["dns"], "HTTP then: " + values["http"],
        "Connection explicitly stopped then: " + ("yes" if values["disconnected"] else "no"), "",
    ])


def save_report(session, *, folder=None, reveal=True, previous=None, readonly=False, failure=None):
    report = session.public_report()
    if not isinstance(report, str) or not report.startswith("J81 Wi-Fi RAM test report\n") or len(report) > 32768:
        raise LauncherError("The shareable report could not be generated safely.")
    if readonly:
        report += "\nThis command read hardware status only; it did not scan, connect or repeat connectivity tests.\n"
    if failure is not None:
        report += "\nCommand stopped: " + failure + "\n"
    report += previous_report_text(previous)
    folder = Path(folder) if folder is not None else Path.home() / "Downloads"
    if not folder.is_dir():
        raise LauncherError("The Downloads folder is unavailable. The report could not be saved.")
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%SZ")
    path = folder / ("J81-wifi-report-" + date + "-" + secrets.token_hex(3) + ".txt")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(report)
    say("\n" + report)
    say("Saved shareable report:\n" + str(path))
    say("Attach that text file in our chat. It omits network names, passwords and unique device addresses.")
    if reveal:
        try:
            subprocess.run(["/usr/bin/open", "-R", str(path)], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return path


def safe_message(exc, modules=None, ctx=None):
    # Only reviewed static helper exceptions are displayed. Unexpected library
    # errors may include private commands, payload data or network identities.
    safe_types = [LauncherError]
    if modules is not None:
        safe_types.append(modules.session.WifiError)
        if hasattr(modules.stage, "StageError"):
            safe_types.append(modules.stage.StageError)
    if ctx is not None:
        safe_types.extend([ctx.base.BootError, ctx.firmware.PreparationError])
    if isinstance(exc, tuple(safe_types)) or type(exc) is RuntimeError:
        message = str(exc)
        message = re.sub(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", "[private address]", message)
        message = re.sub(r"\b[0-9a-fA-F]{24,}\b", "[private identifier]", message)
        message = "".join(c for c in message if ord(c) >= 32)
        return message[:1800]
    if isinstance(exc, OSError):
        return "A local file or USB connection could not be accessed (" + type(exc).__name__ + "). Keep the iPad as it is and copy this message."
    if isinstance(exc, getpass.GetPassWarning):
        return "The local Terminal could not hide password input. No password was sent. Reopen Connect-WiFi.command in Terminal."
    return "The helper stopped on an unexpected " + type(exc).__name__ + ". Keep the iPad as it is and copy this message."


def perform(action, root, modules, ctx, state):
    session = None
    report_saved = False
    failure = None
    try:
        if action == "start":
            record = start_or_reuse(modules, ctx, state, regulatory_files(root))
        else:
            record = existing_session(modules, ctx, state)
        session = new_session(modules, ctx, state, record)
        status = inspect_with_wait(session, wait=action in ("start", "connect"))
        if action == "report":
            save_report(session, previous=previous_attempt(modules, session), readonly=True)
            report_saved = True
            say("Status collected. The existing iPad session is still running.")
            return 0
        if action == "disconnect":
            if not status["ready"]:
                raise LauncherError("The Wi-Fi interface could not be verified for cleanup. Keep the iPad running and save its report.")
            session.disconnect()
            save_report(session)
            report_saved = True
            say("The owned Wi-Fi connection is stopped. USB-shell isolation remains in place until reboot.")
            return 0
        if not status["ready"]:
            save_report(session)
            report_saved = True
            say("The Wi-Fi driver or device-address handoff is not ready. Send the report; keep this kernel running.")
            return 2
        say("The BCM4350 driver and this iPad's hardware address are verified.")
        modules.stage.stage(ctx.shell_class, record["run_id"], Path(root) / "payload/wifi-tools.tar.gz",
                            Path(root) / "payload/tools-manifest.json", log=say)
        connect_interactively(session, modules)
        save_report(session)
        report_saved = True
        say("Keep the iPad connected. This test runs in RAM; a reboot ends the session.")
        return 0
    except (KeyboardInterrupt, EOFError):
        failure = "Cancelled from the local Terminal."
        if session is not None:
            try:
                session.disconnect()
            except Exception:
                say("Owned Wi-Fi cleanup could not be confirmed. Keep the iPad connected and retry Disconnect-WiFi.command.")
        raise
    except Exception as exc:
        failure = safe_message(exc, modules, ctx)
        raise
    finally:
        if session is not None and action in ("start", "connect", "disconnect"):
            try:
                remember_attempt(ctx, session, action)
            except (OSError, ValueError, RuntimeError):
                say("The previous-attempt record could not be retained on this Mac; the shareable report below is still available.")
        if session is not None and not report_saved:
            try:
                save_report(session, failure=failure)
            except (OSError, RuntimeError, ValueError):
                say("The shareable report could not be saved. Keep the iPad running and retry Save-WiFi-Report.command.")


def main(argv=None, *, root=ROOT):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    for action in ("start", "connect", "report", "disconnect", "check"):
        actions.add_argument("--" + action, action="store_const", const=action, dest="action")
    parser.add_argument("--bundle", type=Path, default=Path.home() / "Downloads/J81-WiFi-Preparation-v1",
                        help="Path to the unchanged original J81-WiFi-Preparation-v1 folder")
    args = parser.parse_args(argv)
    action = args.action or "check"
    modules = ctx = None
    try:
        os.umask(0o077)
        manifest = verify_package(root)
        modules = load_components(root, manifest)
        modules.stage.validate_archive(Path(root) / "payload/wifi-tools.tar.gz", Path(root) / "payload/tools-manifest.json")
        if not args.bundle.is_dir():
            raise LauncherError("Keep the original J81-WiFi-Preparation-v1 folder in Downloads. This new test uses its verified boot files; --bundle can specify its actual location.")
        ctx = modules.boot.load_original(args.bundle)
        regulatory_files(root)
        say("New Wi-Fi test package and original boot-package hashes verified.")
        if action == "check":
            say("Local checks complete. No iPad, private state, network or boot operation was accessed.")
            return 0
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise LauncherError("Run this command on the Apple Silicon Mac connected to the Wi-Fi iPad Air 2.")
        state = ctx.radio.private_dir(Path.home() / "Library/Application Support/J81 WiFi Next")
        with application_locks(state):
            return perform(action, root, modules, ctx, state)
    except (KeyboardInterrupt, EOFError):
        say("\nWi-Fi test cancelled. Keep the iPad screen as it is; the helper will not repeat a partial boot upload.")
        return 130
    except Exception as exc:
        print("\nSTOP: " + safe_message(exc, modules, ctx), file=sys.stderr, flush=True)
        print("Keep the iPad running and copy this message. Connection/report commands do not repeat the boot upload.", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

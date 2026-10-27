"""Validate and stage public Wi-Fi tools into the guarded J81 RAM session.

The USB transport follows the previously hardware-tested graphics helper.
The shared mkdir lock excludes other cooperating stagers. The caller also
holds its Mac run locks. Concurrent unmanaged root modification of /run is
outside this contract; post-publication verification prevents tools from
running if the final directory unexpectedly differs.
"""
from __future__ import annotations

import contextlib
import gzip
import hashlib
import hmac
import http.server
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shlex
import stat
import tarfile
import threading
import zlib

IPAD = "172.16.42.1"
MAC = "172.16.42.2"
KERNEL = "7.3.0-rc1-j81-wifi-ram"
FINAL = "/run/j81-wifi-tools"
LOCK = "/run/j81-wifi-tools.lock"
MAX_COMPRESSED = 64 * 1024 * 1024
MAX_EXPANDED = 96 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_ENTRIES = 512
MAX_MANIFEST = 1024 * 1024
MAX_SUMS = 128 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")


class StageError(RuntimeError):
    """Safe, fixed diagnostic. Never includes USB output or capability URLs."""


def _fail(message="The Wi-Fi tools archive or manifest failed validation."):
    raise StageError(message)


def _positive(value, maximum, *, zero=False):
    return type(value) is int and (0 if zero else 1) <= value <= maximum


def _path(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 220:
        _fail()
    if not re.fullmatch(r"[A-Za-z0-9_+.,@=-]+(?:/[A-Za-z0-9_+.,@=-]+)*", value):
        _fail()
    if any(part in (".", "..") for part in value.split("/")):
        _fail()
    return value


def _read_file(path, limit):
    fd = None
    try:
        fd = os.open(os.fspath(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            _fail()
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(limit + 1)
        if len(data) != info.st_size:
            _fail()
        return data
    except (OSError, ValueError):
        _fail("A required Wi-Fi tools file could not be read safely.")
    finally:
        if fd is not None:
            os.close(fd)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def validate_archive(archive_path, manifest_path):
    """Return a fully validated manifest; make no network/device connection.

    Accept only bounded USTAR regular files/directories, including zero-only
    padding. Verify every member and the internal SHA256SUMS independently.
    The archive filename itself need not match manifest['archive']['name'].
    """
    try:
        manifest = json.loads(_read_file(manifest_path, MAX_MANIFEST), object_pairs_hook=_unique_object)
        if not isinstance(manifest, dict) or manifest.get("format") != "j81-wifi-tools-v1":
            _fail()
        if (manifest.get("target") != "aarch64 Linux J81 RAM image"
                or manifest.get("extract_to") != FINAL
                or manifest.get("archive_has_top_directory") is not False):
            _fail()
        archive = manifest.get("archive")
        if (not isinstance(archive, dict) or not _positive(archive.get("bytes"), MAX_COMPRESSED)
                or not isinstance(archive.get("sha256"), str) or not HEX.fullmatch(archive["sha256"])):
            _fail()
        rows = manifest.get("entries")
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ENTRIES:
            _fail()
        entries = {}
        regular_bytes = 0
        for row in rows:
            if not isinstance(row, dict):
                _fail()
            name = _path(row.get("path"))
            if name in entries:
                _fail()
            if row.get("type") == "file":
                if (set(row) != {"path", "type", "bytes", "mode", "sha256"}
                        or not _positive(row.get("bytes"), MAX_FILE, zero=True)
                        or row.get("mode") not in ("0644", "0755")
                        or not isinstance(row.get("sha256"), str) or not HEX.fullmatch(row["sha256"])):
                    _fail()
                regular_bytes += row["bytes"]
            elif row.get("type") == "directory":
                if set(row) != {"path", "type", "bytes", "mode"} or type(row.get("bytes")) is not int or row["bytes"] != 0 or row.get("mode") != "0755":
                    _fail()
            else:
                _fail()
            entries[name] = row
        if not 0 < regular_bytes <= MAX_EXPANDED:
            _fail()
        for name in entries:
            for parent in PurePosixPath(name).parents:
                if str(parent) != "." and entries.get(str(parent), {}).get("type") != "directory":
                    _fail()
        required = {"run-tool", "SHA256SUMS", "bin/iw", "bin/wpa_supplicant", "bin/wpa_cli", "bin/nft", "lib/ld-linux-aarch64.so.1"}
        if any(entries.get(name, {}).get("type") != "file" for name in required):
            _fail()
        if entries["SHA256SUMS"]["bytes"] > MAX_SUMS:
            _fail()
        if (type(manifest.get("total_regular_bytes")) is not int or manifest["total_regular_bytes"] != regular_bytes
                or type(manifest.get("regular_file_count")) is not int
                or manifest["regular_file_count"] != sum(row["type"] == "file" for row in rows)
                or type(manifest.get("total_entry_count")) is not int or manifest["total_entry_count"] != len(rows)):
            _fail()
        compressed = _read_file(archive_path, MAX_COMPRESSED)
        if len(compressed) != archive["bytes"] or not hmac.compare_digest(hashlib.sha256(compressed).hexdigest(), archive["sha256"]):
            _fail()
        # Parse raw headers to reject hidden GNU/PAX extension entries and to
        # bound decompression even when extra data follows the tar terminator.
        maximum_tar = sum(512 + ((r["bytes"] + 511) // 512) * 512 for r in rows) + 10240
        seen = set()
        consumed = 0
        sums = None
        with gzip.GzipFile(fileobj=io.BytesIO(compressed), mode="rb") as stream:
            def read(size):
                nonlocal consumed
                if consumed + size > maximum_tar:
                    _fail()
                data = stream.read(size)
                consumed += len(data)
                if len(data) != size:
                    _fail()
                return data

            while True:
                header = read(512)
                if header == bytes(512):
                    if read(512) != bytes(512):
                        _fail()
                    while True:
                        remaining = maximum_tar - consumed
                        tail = stream.read(min(65536, remaining + 1))
                        if not tail:
                            break
                        consumed += len(tail)
                        if consumed > maximum_tar or any(tail):
                            _fail()
                    break
                if header[257:265] != b"ustar\x0000" or header[156:157] not in (b"0", b"5"):
                    _fail()
                member = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
                name = _path(member.name)
                if name in seen or name not in entries:
                    _fail()
                seen.add(name)
                row = entries[name]
                if (member.linkname or member.uid != 0 or member.gid != 0 or member.mtime != 0
                        or member.mode != int(row["mode"], 8) or member.size != row["bytes"]
                        or member.type != (tarfile.REGTYPE if row["type"] == "file" else tarfile.DIRTYPE)):
                    _fail()
                digest = hashlib.sha256()
                remaining = member.size
                collected = bytearray()
                while remaining:
                    chunk = read(min(131072, remaining))
                    remaining -= len(chunk)
                    digest.update(chunk)
                    if name == "SHA256SUMS":
                        collected.extend(chunk)
                padding = (-member.size) % 512
                if padding and any(read(padding)):
                    _fail()
                if row["type"] == "file" and not hmac.compare_digest(digest.hexdigest(), row["sha256"]):
                    _fail()
                if name == "SHA256SUMS":
                    sums = bytes(collected)
        if seen != set(entries) or sums is None:
            _fail()
        expected = {name: row["sha256"] for name, row in entries.items() if row["type"] == "file" and name != "SHA256SUMS"}
        actual = {}
        for line in sums.decode("ascii").splitlines():
            if len(line) < 67 or line[64:66] != "  " or not HEX.fullmatch(line[:64]):
                _fail()
            name = _path(line[66:])
            if name in actual:
                _fail()
            actual[name] = line[:64]
        if actual != expected:
            _fail()
        return manifest
    except StageError:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, EOFError, RecursionError, tarfile.TarError, zlib.error):
        raise StageError("The Wi-Fi tools archive or manifest failed validation.") from None


def _guard(run_id):
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        _fail("The private Wi-Fi run identifier is invalid.")
    return "\n".join([
        "set -eu", "set -f", "export LC_ALL=C", "umask 077",
        "[ \"$(/bin/busybox id -u)\" = 0 ]",
        "[ \"$(/bin/busybox uname -r)\" = '" + KERNEL + "' ]",
        "[ \"$(/bin/busybox tr '\\000' '\\n' </proc/device-tree/compatible)\" = \"$(printf 'apple,j81\\napple,t7001\\napple,arm-platform')\" ]",
        "[ \"$(/bin/busybox tr -d '\\000' </proc/device-tree/model)\" = 'Apple iPad Air 2 (Wi-Fi)' ]",
        "[ -d /run ] && [ ! -L /run ]",
        "/bin/busybox awk '$2 == \"/run\" {n++; if ($3 != \"tmpfs\") bad=1} END {exit !(n == 1 && !bad)}' /proc/mounts",
        "[ \"$(/bin/busybox tr ' ' '\\n' </proc/cmdline | /bin/busybox grep -c '^j81.wifi_run=')\" = 1 ]",
        "/bin/busybox tr ' ' '\\n' </proc/cmdline | /bin/busybox grep -Fqx 'j81.wifi_run=" + run_id + "'",
    ])


@contextlib.contextmanager
def _shell(shell_class):
    shell = shell_class()
    try:
        yield shell
    finally:
        with contextlib.suppress(Exception):
            shell.close()


def _run(shell_class, run_id, body, *, seconds=20, error):
    try:
        command = _guard(run_id) + "\n" + body
        if any(len(line.encode("utf-8")) > 900 for line in command.splitlines()):
            _fail("A staging command exceeded the safe USB shell line limit. Nothing was sent.")
        with _shell(shell_class) as shell:
            output, status = shell.run(command, seconds=seconds, check=False)
        if not isinstance(output, str) or len(output) > 65536 or type(status) is not int or status != 0:
            _fail(error)
        return output.strip()
    except StageError:
        raise
    except Exception:
        raise StageError(error) from None


class _PayloadServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request, client_address):
        pass


def _handler(payload, capability):
    allowed_path = "/" + capability + "/wifi-tools.tar.gz"

    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, *args):
            pass

        def do_GET(self):
            code = 200
            if self.client_address[0] != IPAD:
                code = 403
            elif not hmac.compare_digest(self.path.encode("utf-8"), allowed_path.encode("ascii")):
                code = 404
            self.send_response(code)
            self.send_header("Content-Length", str(len(payload) if code == 200 else 0))
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if code == 200:
                try:
                    for offset in range(0, len(payload), 131072):
                        self.wfile.write(payload[offset:offset + 131072])
                except OSError:
                    pass

    return Handler


def _start_payload_server(payload):
    capability = secrets.token_hex(32)
    server = _PayloadServer((MAC, 0), _handler(payload, capability))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    try:
        thread.start()
    except BaseException:
        server.server_close()
        raise
    return server, thread, f"http://{MAC}:{server.server_port}/{capability}/wifi-tools.tar.gz"


def _no_mount(root):
    return "/bin/busybox awk -v root=" + shlex.quote(root) + " '($2 == root || index($2, root \"/\") == 1) {bad=1} END {exit bad}' /proc/mounts"


def _owned(directory, token):
    q = shlex.quote(directory)
    marker = shlex.quote(directory + "/.owner")
    return "\n".join([
        "[ -d " + q + " ] && [ ! -L " + q + " ]", _no_mount(directory),
        "[ \"$(/bin/busybox stat -c '%u:%g:%a' " + q + ")\" = '0:0:700' ]",
        "[ -f " + marker + " ] && [ ! -L " + marker + " ]",
        "[ \"$(/bin/busybox stat -c '%u:%g:%a:%h:%s' " + marker + ")\" = '0:0:600:1:65' ]",
        "[ \"$(/bin/busybox cat " + marker + ")\" = '" + token + "' ]",
    ])


def _verify(root, manifest):
    q = shlex.quote(root)
    lines = ["# J81_STAGE_VERIFY", "[ -d " + q + " ] && [ ! -L " + q + " ]", _no_mount(root),
             "j81_run_dev=$(/bin/busybox stat -c '%d' /run)",
             "[ \"$(/bin/busybox stat -c '%u:%g:%a:%d' " + q + ")\" = \"0:0:700:$j81_run_dev\" ]",
             "[ \"$(/bin/busybox find " + q + " -mindepth 1 -print | /bin/busybox wc -l)\" -eq " + str(manifest["total_entry_count"]) + " ]"]
    for row in manifest["entries"]:
        path = shlex.quote(root + "/" + row["path"])
        lines.append("[ ! -L " + path + " ]")
        if row["type"] == "directory":
            lines.extend(["[ -d " + path + " ]",
                          "[ \"$(/bin/busybox stat -c '%u:%g:%a:%d' " + path + ")\" = \"0:0:755:$j81_run_dev\" ]"])
        else:
            expected = "0:0:" + row["mode"][1:] + ":1:" + str(row["bytes"]) + ":$j81_run_dev"
            lines.extend(["[ -f " + path + " ]",
                          "[ \"$(/bin/busybox stat -c '%u:%g:%a:%h:%s:%d' " + path + ")\" = \"" + expected + "\" ]"])
    sums = next(row for row in manifest["entries"] if row["path"] == "SHA256SUMS")
    lines.extend(["printf '%s\\n' " + shlex.quote(sums["sha256"] + "  " + root + "/SHA256SUMS") + " | /bin/busybox sha256sum -c - >/dev/null",
                  "(cd " + q + " && /bin/busybox sha256sum -c SHA256SUMS >/dev/null)", "printf 'J81_STAGE_VERIFIED\\n'"])
    return "\n".join(lines)


def _cleanup(shell_class, run_id, stage_path, token, log):
    # Each branch proves ownership before removing its own private directory.
    body = "\n".join(["# J81_STAGE_CLEANUP", "if (\n" + _owned(stage_path, token) + "\n); then",
                       "  /bin/busybox rm -rf " + shlex.quote(stage_path), "fi",
                       "if (\n" + _owned(LOCK, token) + "\n); then",
                       "  /bin/busybox rm -f " + shlex.quote(LOCK + "/.owner"),
                       "  /bin/busybox rmdir " + shlex.quote(LOCK), "fi",
                       "[ ! -e " + shlex.quote(stage_path) + " ] && [ ! -L " + shlex.quote(stage_path) + " ]",
                       "[ ! -e " + shlex.quote(LOCK) + " ] && [ ! -L " + shlex.quote(LOCK) + " ]"])
    try:
        _run(shell_class, run_id, body, error="The private RAM staging cleanup did not complete.")
    except Exception:
        with contextlib.suppress(Exception):
            log("The private staging cleanup could not be confirmed. Keep the iPad running; no unrelated directory was removed.")


def stage(shell_class, run_id, archive_path, manifest_path, log=print):
    """Return True after a verified RAM publication or verified reuse.

    Raise StageError on failure. All remote commands use check=False and fixed
    error messages. Cleanup cannot replace the original failure.
    """
    _guard(run_id)
    manifest = validate_archive(archive_path, manifest_path)
    minimum_kib = (2 * manifest["total_regular_bytes"] + 64 * 1024 * 1024 + 1023) // 1024
    probe = "\n".join(["# J81_STAGE_PROBE",
        "if [ -e '" + FINAL + "' ] || [ -L '" + FINAL + "' ]; then printf 'J81_STAGE_EXISTS\\n'; else",
        "/bin/busybox awk '/^MemAvailable:/ {n++; if ($2 < " + str(minimum_kib) + ") bad=1} END {exit !(n == 1 && !bad)}' /proc/meminfo",
        "printf 'J81_STAGE_ABSENT\\n'; fi"])
    state = _run(shell_class, run_id, probe, error="The exact Wi-Fi RAM session or available memory could not be verified. Nothing was uploaded.")
    if state == "J81_STAGE_EXISTS":
        result = _run(shell_class, run_id, _verify(FINAL, manifest), seconds=45,
                      error="An existing tools directory did not match this package. It was left unchanged.")
        if result != "J81_STAGE_VERIFIED":
            _fail("An existing tools directory could not be verified. It was left unchanged.")
        log("The matching Wi-Fi tools are already verified in iPad RAM.")
        return True
    if state != "J81_STAGE_ABSENT":
        _fail("The exact Wi-Fi RAM session could not be verified. Nothing was uploaded.")
    payload = _read_file(archive_path, MAX_COMPRESSED)
    if len(payload) != manifest["archive"]["bytes"] or not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), manifest["archive"]["sha256"]):
        _fail("The Wi-Fi tools archive changed after validation. Nothing was uploaded.")
    stage_path = "/run/j81-wifi-tools-stage." + run_id
    destination = stage_path + "/payload"
    download = stage_path + "/tools.tar.gz"
    token = secrets.token_hex(32)
    server = thread = None
    cleanup_needed = False
    try:
        create = ["# J81_STAGE_CREATE"]
        for path in (LOCK, stage_path, FINAL):
            create.append("[ ! -e " + shlex.quote(path) + " ] && [ ! -L " + shlex.quote(path) + " ]")
        create.extend(["/bin/busybox mkdir -m 700 '" + LOCK + "'",
                       "(set -C; printf '%s\\n' '" + token + "' >'" + LOCK + "/.owner')",
                       "/bin/busybox mkdir -m 700 '" + stage_path + "'",
                       "(set -C; printf '%s\\n' '" + token + "' >'" + stage_path + "/.owner')",
                       "/bin/busybox mkdir -m 700 '" + destination + "'"])
        cleanup_needed = True
        _run(shell_class, run_id, "\n".join(create), error="A private RAM staging directory could not be created. Existing directories were left unchanged.")
        server, thread, url = _start_payload_server(payload)
        log("Transferring the verified Wi-Fi tools into iPad RAM…")
        transfer = "\n".join(["# J81_STAGE_TRANSFER", _owned(LOCK, token), _owned(stage_path, token),
            "[ ! -e '" + download + "' ] && [ ! -L '" + download + "' ]",
            "(ulimit -f " + str((len(payload) + 511) // 512) + "; /bin/busybox timeout 90 /bin/busybox wget -q -Y off -T 15 -O '" + download + "' " + shlex.quote(url) + ")",
            "[ -f '" + download + "' ] && [ ! -L '" + download + "' ]",
            "[ \"$(/bin/busybox stat -c '%s:%h' '" + download + "')\" = '" + str(len(payload)) + ":1' ]",
            "printf '%s\\n' '" + manifest["archive"]["sha256"] + "  " + download + "' | /bin/busybox sha256sum -c - >/dev/null",
            "umask 022", "/bin/busybox tar -xzkf '" + download + "' -C '" + destination + "'", "umask 077",
            _verify(destination, manifest), "/bin/busybox rm -f '" + download + "'"])
        result = _run(shell_class, run_id, transfer, seconds=150,
                      error="The Wi-Fi tools transfer or RAM verification did not complete. The tools were not activated.")
        if result != "J81_STAGE_VERIFIED":
            _fail("The transferred Wi-Fi tools could not be verified. The tools were not activated.")
        publish = "\n".join(["# J81_STAGE_PUBLISH", _owned(LOCK, token), _owned(stage_path, token),
            _verify(destination, manifest), "[ ! -e '" + FINAL + "' ] && [ ! -L '" + FINAL + "' ]",
            "/bin/busybox mv -n '" + destination + "' '" + FINAL + "'",
            "[ ! -e '" + destination + "' ] && [ ! -L '" + destination + "' ]",
            _verify(FINAL, manifest), "printf 'J81_STAGE_READY\\n'"])
        result = _run(shell_class, run_id, publish, seconds=60,
                      error="The verified tools could not be published safely. No Wi-Fi tool was executed.")
        if result.splitlines() != ["J81_STAGE_VERIFIED", "J81_STAGE_VERIFIED", "J81_STAGE_READY"]:
            _fail("The published tools could not be confirmed. No Wi-Fi tool was executed.")
        log("The Wi-Fi tools are verified and ready in iPad RAM.")
        return True
    except StageError:
        raise
    except Exception:
        raise StageError("The private USB staging service was interrupted. No Wi-Fi tool was executed.") from None
    finally:
        if server is not None:
            with contextlib.suppress(Exception):
                server.shutdown()
            with contextlib.suppress(Exception):
                server.server_close()
        if thread is not None:
            with contextlib.suppress(Exception):
                thread.join(timeout=2)
        if cleanup_needed:
            _cleanup(shell_class, run_id, stage_path, token, log)

#!/usr/bin/env python3
"""Create the J81 RAM-test initramfs without executing downloaded programs.

The source is an exact, hash-pinned postmarketOS debug archive. Only BusyBox,
BusyBox-extras and their matching musl runtime are carried into the output.
All startup scripts and metadata are supplied by this directory. No original
postmarketOS init scripts, hooks, kpartx, or libdevmapper are retained.
"""

import argparse
import gzip
import hashlib
import io
import json
import pathlib
import stat
import struct


SOURCE_SHA256 = "af3fc3c7c57c775095fea2df7930961c92f73ec95f64d4c7ef6cae9c02dee9c6"
SOURCE_URL = "https://raw.githubusercontent.com/SoMainline/linux-apple-resources/30780ec0fecdab849bb812e1dde52b87e614f45b/debug_initrd.img"
SOURCE_NAMES = (
    "bin/busybox",
    "bin/busybox-extras",
    "lib/ld-musl-aarch64.so.1",
    "lib/libc.musl-aarch64.so.1",
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_newc(data):
    result = {}
    offset = 0
    while offset + 110 <= len(data):
        if data[offset:offset + 6] != b"070701":
            raise ValueError("Unexpected newc header at %d" % offset)
        fields = [int(data[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        size, name_size = fields[6], fields[11]
        if not 1 <= name_size <= 4096:
            raise ValueError("Invalid entry name size")
        start = offset + 110
        name_bytes = data[start:start + name_size]
        if len(name_bytes) != name_size or name_bytes[-1:] != b"\0":
            raise ValueError("Truncated archive name")
        name = name_bytes[:-1].decode("utf-8")
        if name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
            raise ValueError("Unsafe archive name: " + name)
        body_start = (start + name_size + 3) & ~3
        body = data[body_start:body_start + size]
        if len(body) != size:
            raise ValueError("Truncated archive content")
        offset = (body_start + size + 3) & ~3
        if name == "TRAILER!!!":
            if any(data[offset:]):
                raise ValueError("Unexpected extra archive data")
            return result
        if name in result:
            raise ValueError("Duplicate archive name: " + name)
        result[name] = {"mode": fields[1], "rdevmajor": fields[9], "rdevminor": fields[10], "data": body}
    raise ValueError("Missing archive trailer")


def elf_runtime(data):
    """Inspect AArch64 ELF interpreter and dynamic dependencies; execute none."""
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected little-endian AArch64 ELF64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    if phsize != 56 or phnum > 64:
        raise ValueError("Unexpected ELF program headers")
    segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize) for i in range(phnum)]
    interp = None
    dynamic = []
    for kind, _, off, _, _, filesz, _, _ in segments:
        if off + filesz > len(data):
            raise ValueError("Truncated ELF segment")
        if kind == 3:
            interp = data[off:off + filesz].rstrip(b"\0").decode()
        elif kind == 2:
            for pos in range(off, off + filesz, 16):
                tag, val = struct.unpack_from("<QQ", data, pos)
                if tag == 0:
                    break
                dynamic.append((tag, val))
    string_address = next((value for tag, value in dynamic if tag == 5), None)
    strings = None
    if string_address is not None:
        for kind, _, off, vaddr, _, filesz, _, _ in segments:
            if kind == 1 and vaddr <= string_address < vaddr + filesz:
                strings = off + string_address - vaddr
                break
    needed = []
    for tag, val in dynamic:
        if tag == 1:
            if strings is None:
                raise ValueError("ELF dependency string table missing")
            end = data.index(b"\0", strings + val)
            needed.append(data[strings + val:end].decode())
    return {"interpreter": interp, "needed": needed, "machine": "AArch64"}


def newc_entry(name, entry, inode):
    name_bytes = name.encode() + b"\0"
    body = entry["data"]
    fields = (inode, entry["mode"], 0, 0, 2 if stat.S_ISDIR(entry["mode"]) else 1,
              1, len(body), 0, 0, entry.get("rdevmajor", 0), entry.get("rdevminor", 0), len(name_bytes), 0)
    header = b"070701" + b"".join(("%08x" % field).encode() for field in fields)
    prefix = header + name_bytes
    prefix += b"\0" * ((-len(prefix)) % 4)
    return prefix + body + b"\0" * ((-len(body)) % 4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path(__file__).with_name("initramfs-j81-ram.gz"))
    args = parser.parse_args()
    compressed = args.source.read_bytes()
    if sha256(compressed) != SOURCE_SHA256:
        raise SystemExit("Source archive hash mismatch; no output written")
    original = parse_newc(gzip.decompress(compressed))
    entries = {name: original[name] for name in SOURCE_NAMES}
    expected_types = {"bin/busybox": stat.S_IFREG, "bin/busybox-extras": stat.S_IFREG,
                      "lib/ld-musl-aarch64.so.1": stat.S_IFREG, "lib/libc.musl-aarch64.so.1": stat.S_IFLNK}
    for name, mode_type in expected_types.items():
        if stat.S_IFMT(entries[name]["mode"]) != mode_type:
            raise ValueError("Unexpected source entry type: " + name)
    if entries["lib/libc.musl-aarch64.so.1"]["data"] != b"ld-musl-aarch64.so.1":
        # The source archive's alias can also contain the absolute path.
        if entries["lib/libc.musl-aarch64.so.1"]["data"] != b"/lib/ld-musl-aarch64.so.1":
            raise ValueError("Unexpected musl symlink")

    binaries = {}
    for name in ("bin/busybox", "bin/busybox-extras", "lib/ld-musl-aarch64.so.1"):
        runtime = elf_runtime(entries[name]["data"])
        if runtime["interpreter"] not in (None, "/lib/ld-musl-aarch64.so.1"):
            raise ValueError("Unexpected interpreter: " + name)
        if set(runtime["needed"]) - {"libc.musl-aarch64.so.1"}:
            raise ValueError("Unbundled runtime dependency: " + name)
        binaries[name] = runtime

    for name in ("bin", "sbin", "usr", "usr/bin", "usr/sbin", "lib", "etc", "root", "dev", "dev/pts", "proc", "sys", "run", "tmp", "config"):
        entries[name] = {"mode": stat.S_IFDIR | (0o1777 if name == "tmp" else 0o755), "data": b""}
    for name, target in (("bin/sh", "busybox"), ("usr/sbin/telnetd", "/bin/busybox-extras")):
        entries[name] = {"mode": stat.S_IFLNK | 0o777, "data": target.encode()}
    for name, major, minor in (("dev/console", 5, 1), ("dev/null", 1, 3), ("dev/tty", 5, 0),
                               ("dev/zero", 1, 5), ("dev/random", 1, 8), ("dev/urandom", 1, 9)):
        entries[name] = {"mode": stat.S_IFCHR | 0o600, "data": b"", "rdevmajor": major, "rdevminor": minor}
    here = pathlib.Path(__file__).resolve().parent
    for archive_name, source_name in (("init", "init"), ("bin/ram-shell", "ram-shell")):
        entries[archive_name] = {"mode": stat.S_IFREG | 0o755, "data": (here / source_name).read_bytes()}
    metadata = {
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
        "etc/group": "root:x:0:\n",
        "etc/issue": "\nJ81 experimental Linux RAM test\nUSB shell: 172.16.42.1:23 (no authentication)\nAll regular files and logs are temporary.\n\n",
    }
    for name, contents in metadata.items():
        entries[name] = {"mode": stat.S_IFREG | 0o644, "data": contents.encode()}

    # Parents precede children; deterministic inode numbers, uid/gid/mtime,
    # archive padding and gzip header make byte-for-byte rebuilds possible.
    ordered_names = sorted(entries, key=lambda name: (name.count("/"), name))
    archive = b"".join(newc_entry(name, entries[name], index + 1) for index, name in enumerate(ordered_names))
    archive += newc_entry("TRAILER!!!", {"mode": 0, "data": b""}, len(entries) + 1)
    archive += b"\0" * ((-len(archive)) % 512)
    restored = parse_newc(archive)
    if set(restored) != set(entries):
        raise ValueError("Generated archive entry list failed round-trip")
    for name in entries:
        expected = {"mode": entries[name]["mode"], "rdevmajor": entries[name].get("rdevmajor", 0),
                    "rdevminor": entries[name].get("rdevminor", 0), "data": entries[name]["data"]}
        if restored[name] != expected:
            raise ValueError("Generated archive failed round-trip: " + name)

    stream = io.BytesIO()
    with gzip.GzipFile(fileobj=stream, mode="wb", compresslevel=9, mtime=0, filename="") as encoder:
        encoder.write(archive)
    result = stream.getvalue()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result)
    manifest = {
        "artifact": args.output.name, "sha256": sha256(result), "compressed_bytes": len(result),
        "uncompressed_bytes": len(archive), "board": "apple,j81", "platform": "apple,t7001",
        "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256, "source_entries_retained": list(SOURCE_NAMES),
        "runtime_dependencies": binaries,
        "files": [{"path": name, "mode": oct(entries[name]["mode"]), "bytes": len(entries[name]["data"]),
                   "sha256": sha256(entries[name]["data"])} for name in ordered_names],
        "hardware_validation": "NOT BOOTED; archive and startup code checked only",
        "network": {"device_ip": "172.16.42.1", "host_ip": "172.16.42.2", "protocol": "USB CDC ECM",
                    "shell": "telnet TCP23 bound to 172.16.42.1; no authentication", "ssh": False},
    }
    manifest_path = args.output.with_suffix(args.output.suffix + ".json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "manifest": str(manifest_path), "sha256": sha256(result),
                      "compressed_bytes": len(result), "archive_entries": len(entries)}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Build separate J81 radio-ID and firmware-free Wi-Fi RAM payloads offline.

The hardware-confirmed Pongo/m1n1/USB userspace binaries are retained. New
kernels and device trees are experimental until tested on the user's iPad.
No device, network, partition, flash, or USB operation is performed here.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess

HERE = Path(__file__).resolve().parent
BASE_RAM_SHA = "cf1c17b3a9403331511ebcdb01a6a6c96549b2e89dbd44372097c57362b291d3"
BASE_INIT_SHA = "4de8a744f30c16a1f00b84ab577efff262b314306459cb95d97cd13ef8c49a7c"
SUPPORT_SHA = "86958125b3a4a111dd0a724d80f1bd2d0631c30b02c5bebbe4a4217a1f1d608a"
PINNED = {
    "Pongo.bin": "1e5543fd8e6dbd84c334b87d71aa473f4d347c2ba8a5e863b6e10f18461c7575",
    "m1n1.bin": "2e377fb72a8555c944bf30e08f1604cc2b889678250df34ca2d61d0dda8fb0a1",
}
PROFILES = {
    "radio-id": {"release": "7.3.0-rc1-j81-radio-id", "label": "radio identification", "extra": ""},
    "wifi-base": {"release": "7.3.0-rc1-j81-wifi-ram", "label": "Wi-Fi preparation", "extra": "pcie_aspm=off pcie_apple_t7000.device_wake=1 fbcon=font:TER16x32"},
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pinned_bytes(path, expected):
    data = Path(path).read_bytes()
    if sha(data) != expected:
        raise RuntimeError("Pinned component changed: " + Path(path).name)
    return data


def archive_module():
    path = HERE / "ramdisk/archive_support.py"
    blob = pinned_bytes(path, SUPPORT_SHA)
    spec = importlib.util.spec_from_file_location("j81_archive_support", path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(blob, str(path), "exec"), module.__dict__)
    return module


def compressed(data, level=9):
    stream = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=stream, compresslevel=level, mtime=0) as output:
        output.write(data)
    return stream.getvalue()


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise RuntimeError("Expected one exact init edit: " + old[:60])
    return text.replace(old, new)


def make_ramdisk(profile, output):
    support = archive_module()
    original = pinned_bytes(HERE / "ramdisk/base-initramfs.gz", BASE_RAM_SHA)
    entries = support.parse_newc(gzip.decompress(original))
    init = pinned_bytes(HERE / "ramdisk/init-base", BASE_INIT_SHA).decode()
    if entries["init"]["data"] != init.encode():
        raise RuntimeError("Base init does not match the verified archive")
    settings = PROFILES[profile]
    marker = "# No mdev scans, block-device discovery, filesystem checks, partition tools,\n"
    addition = (
        f'if [ "$(uname -r)" != "{settings["release"]}" ]; then\n'
        "    j81_stop 'kernel release does not match this RAM test'\n"
        "fi\n\n"
    )
    if profile == "radio-id":
        addition += (
            "# Expose only the bounded probe result captured by the kernel.\n"
            "# The host reads this file; no userspace hardware-register tool runs.\n"
            "mkdir -p /sys/kernel/debug\n"
            "mount -t debugfs -o ro,nosuid,nodev,noexec debugfs /sys/kernel/debug || "
            "j81_stop 'radio report debugfs mount failed'\n\n"
        )
    init = replace_once(init, marker, addition + marker)
    # Preserve the proven ECM descriptors and generic serial so macOS can
    # reuse its USB network service. The exact kernel + host run nonce,
    # rather than this generic USB descriptor, identifies the new session.
    init = replace_once(
        init,
        "j81_log 'Startup mounts only proc, sysfs, devtmpfs, devpts, tmpfs, and configfs.'",
        "j81_log 'Temporary RAM session. Internal block and raw-flash support are disabled.'",
    )
    (output / "init").write_text(init)
    subprocess.run(["/bin/sh", "-n", str(output / "init")], check=True)
    entries["init"]["data"] = init.encode()
    entries["etc/issue"]["data"] = (
        f"\nJ81 {settings['label']} RAM test\n"
        "USB shell: 172.16.42.1:23 (USB interface only)\n"
        "All regular files and logs are temporary.\n"
        "Use the Mac helper to collect the result.\n\n"
    ).encode()
    entries["etc/j81-test-profile"] = {"mode": stat.S_IFREG | 0o644, "data": (profile + "\n").encode()}
    names = sorted(entries, key=lambda name: (name.count("/"), name))
    archive = b"".join(support.newc_entry(name, entries[name], index + 1) for index, name in enumerate(names))
    archive += support.newc_entry("TRAILER!!!", {"mode": 0, "data": b""}, len(entries) + 1)
    archive += b"\0" * (-len(archive) % 512)
    checked = support.parse_newc(archive)
    if set(checked) != set(entries) or any(checked[name]["data"] != entries[name]["data"] for name in names):
        raise RuntimeError("Generated initramfs did not round-trip")
    # Existing binaries and USB-shell launcher must be byte-for-byte unchanged.
    original_entries = support.parse_newc(gzip.decompress(original))
    for name in ("bin/busybox", "bin/busybox-extras", "lib/ld-musl-aarch64.so.1", "bin/ram-shell"):
        if entries[name] != original_entries[name]:
            raise RuntimeError("Unexpected userspace binary/script modification: " + name)
    forbidden = ("firmware/", "wpa_supplicant", "hostapd", "iw", "iwd", "NetworkManager", "mount.apfs", "fdisk")
    for name in names:
        if any(part in name for part in forbidden):
            raise RuntimeError("Unexpected wireless/storage utility in minimal initramfs: " + name)
    blob = compressed(archive)
    (output / "initramfs.gz").write_bytes(blob)
    return {"sha256": sha(blob), "bytes": len(blob), "uncompressed_bytes": len(archive),
            "base_sha256": BASE_RAM_SHA, "entry_count": len(entries), "profile": profile,
            "shell_bound_to_usb_address": "172.16.42.1:23", "contains_wifi_firmware": False,
            "automatic_scan_or_association": False, "debugfs_readonly": profile == "radio-id"}


def values(config):
    result = {}
    for line in config.splitlines():
        if line.startswith("CONFIG_"):
            key, value = line[7:].split("=", 1)
            result[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            result[line[9:-11]] = "n"
    return result


def assemble(profile, products, output, tools, pinned):
    products, output = Path(products), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    config = (products / "kernel.config").read_bytes()
    cfg = values(config.decode())
    if cfg.get("LOCALVERSION") != '"' + PROFILES[profile]["release"].removeprefix("7.3.0-rc1") + '"':
        raise RuntimeError("Kernel configuration has an unexpected release")
    for key in ("BLOCK", "MTD", "MMC", "BLK_DEV_NVME", "NVME_APPLE", "APPLE_ASP"):
        if cfg.get(key, "n") != "n":
            raise RuntimeError("Internal/block/raw-flash access is enabled: " + key)
    for key in ("ARM64_4K_PAGES", "DEVTMPFS", "TMPFS", "PROC_FS", "SYSFS", "USB_CONFIGFS_ECM", "USB_DWC2"):
        if cfg.get(key) != "y":
            raise RuntimeError("Required compatibility feature missing: " + key)
    if profile == "radio-id":
        if cfg.get("WIRELESS", "n") != "n" or cfg.get("BRCMFMAC", "n") != "n" or cfg.get("DEBUG_FS") != "y":
            raise RuntimeError("Radio-ID configuration must expose the read-only probe without a wireless driver")
    else:
        for key in ("WIRELESS", "WLAN", "BRCMFMAC", "BRCMFMAC_PCIE", "PCIE_APPLE_T7000_DEVICE_WAKE_TEST"):
            if cfg.get(key) != "y":
                raise RuntimeError("Wi-Fi base lacks " + key)
    image = (products / "Image").read_bytes()
    if image[56:60] != b"ARM\x64":
        raise RuntimeError("Expected an AArch64 Linux Image")
    offset, size, flags = struct.unpack_from("<QQQ", image, 8)
    if ((flags >> 1) & 3) != 1:
        raise RuntimeError("The image does not use the expected 4 KiB pages")
    for name, digest in PINNED.items():
        (output / name).write_bytes(pinned_bytes(Path(pinned) / name, digest))

    def tool(name, *args):
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = str(Path(tools).parent / "lib/x86_64-linux-gnu")
        return subprocess.run([str(Path(tools) / name), *map(str, args)], env=env, check=True, capture_output=True)

    dts = tool("dtc", "-I", "dtb", "-O", "dts", products / "t7001-j81.dtb").stdout.decode()
    lines, chosen, changed = [], False, 0
    for line in dts.splitlines(keepends=True):
        if line.rstrip("\n") == "\tchosen {":
            chosen = True
        if chosen and "framebuffer@0 {" in line:
            changed += line.count("framebuffer@0 {")
            line = line.replace("framebuffer@0 {", "framebuffer {")
        if chosen and line.rstrip("\n") == "\t};":
            chosen = False
        lines.append(line)
    if changed != 1:
        raise RuntimeError("Expected one framebuffer path adjustment for m1n1")
    (output / "t7001-j81.dts").write_text("".join(lines))
    tool("dtc", "-I", "dts", "-O", "dtb", "-p", "0x10000", "-o", output / "t7001-j81.dtb", output / "t7001-j81.dts")
    compatible = tool("fdtget", "-t", "s", output / "t7001-j81.dtb", "/", "compatible").stdout.decode().strip().split()
    if compatible != ["apple,j81", "apple,t7001", "apple,arm-platform"]:
        raise RuntimeError("Unexpected device-tree board compatibility")
    if profile == "wifi-base":
        wifi_path = tool("fdtget", "-t", "s", output / "t7001-j81.dtb", "/aliases", "wifi0").stdout.decode().strip()
        mac = tool("fdtget", "-t", "bx", output / "t7001-j81.dtb", wifi_path, "local-mac-address").stdout.decode().split()
        if mac != ["0"] * 6:
            raise RuntimeError("The Wi-Fi node must have the zero placeholder for m1n1's local ADT MAC provisioning")
    (output / "Image.gz").write_bytes(compressed(image, 6))
    (output / "kernel.config").write_bytes(config)
    ramdisk = make_ramdisk(profile, output)
    console = "loglevel=8 ignore_loglevel" if profile == "radio-id" else "loglevel=7"
    extra = PROFILES[profile]["extra"]
    bootargs = (
        "chosen.bootargs=console=tty0 " + console + " rdinit=/init PMOS_NO_OUTPUT_REDIRECT "
        "pd_ignore_unused clk_ignore_unused" + (" " + extra if extra else "") + "\n"
    )
    (output / "bootargs").write_text(bootargs)
    order = ["m1n1.bin", "bootargs", "t7001-j81.dtb", "Image.gz", "initramfs.gz"]
    payload = b"".join((output / name).read_bytes() for name in order)
    if not 0 < len(payload) <= 128 * 1024 * 1024:
        raise RuntimeError("Payload exceeds the bounded RAM upload size")
    (output / "m1n1-linux.bin").write_bytes(payload)
    validation = {
        "profile": profile, "kernel_release": PROFILES[profile]["release"], "hardware_tested": False,
        "linux_image_text_offset": offset, "linux_image_size": size, "linux_image_flags": flags,
        "page_size": 4096, "compatible": compatible, "concatenation_order": order,
        "block_devices_disabled": True, "raw_flash_disabled": True, "initramfs": ramdisk,
        "pinned_loader_components": PINNED, "payload_sha256": sha(payload),
        "payload_bytes": len(payload), "firmware_included": False,
        "scope": "Radio identification only" if profile == "radio-id" else "Firmware-free preparation template; not a Wi-Fi connection test",
    }
    (output / "validation.json").write_text(json.dumps(validation, indent=2) + "\n")
    files = {path.name: {"sha256": sha(path.read_bytes()), "bytes": path.stat().st_size}
             for path in sorted(output.iterdir()) if path.is_file() and path.name not in ("manifest.json", "SHA256SUMS")}
    manifest = {"format_version": 1, "target": {"product_type": "iPad5,3", "hardware_model": "J81AP", "chip_id": "0x7001", "board_id": "0x06"},
                "profile": profile, "scope": validation["scope"], "hardware_linux_boot_tested": False,
                "kernel_release": PROFILES[profile]["release"], "files": files}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "SHA256SUMS").write_text("".join(f"{entry['sha256']}  {name}\n" for name, entry in files.items()))
    print(json.dumps(validation, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=PROFILES)
    parser.add_argument("--products", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--pinned", type=Path, required=True, help="Directory with verified Pongo.bin and m1n1.bin")
    args = parser.parse_args()
    assemble(args.profile, args.products, args.output, args.tools, args.pinned)


if __name__ == "__main__":
    main()

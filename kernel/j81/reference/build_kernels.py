#!/usr/bin/env python3
"""Reproducible, isolated J81 radio-identification and Wi-Fi RAM kernel builds.

No device is opened. Each variant extracts pristine pinned Linux, applies its
complete upstream recipe, and builds with a separately installed cross-toolchain.
The produced binaries are compile-verified experiments, not hardware-tested builds.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent
LINUX_REV = "6831bc701a6ce059e71e5aaa9488c9195bea6927"
PROJECT_REV = "b94d42f78e04c5465e290340a5b6879bbc5956b6"
ARCHIVE_SHA256 = "5eca8c1a096009ef867451d08433735ff29548220adb880f85b9840de65bf15f"
BASE_CONFIG_SHA256 = "a5cbcb0d3fe655888106672e6fe03477b63d51bd36bbcfc4f5145627d906b208"
EPOCH = 1788414569
VARIANTS = {
    "radio-id": ("hoolock-pcie-j81-bcm-shadow.nix", 26, "-j81-radio-id"),
    "wifi": ("hoolock-pcie-j81-wifi-h1b.nix", 63, "-j81-wifi-ram"),
}
COMMON = {
    "ARM64_4K_PAGES": "y", "ARM64_16K_PAGES": "n", "I2C_CHARDEV": "y",
    "DEBUG_INFO": "n", "DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT": "n",
    "DEBUG_INFO_COMPRESSED_NONE": "n", "DEBUG_INFO_NONE": "y",
    "INPUT_TOUCHSCREEN": "y", "BATTERY_BQ27XXX_HDQ_UART": "y",
    "CHARGER_J81_D2207": "y", "TOUCHSCREEN_APPLE_Z2": "y",
    "PCIE_APPLE_T7000": "y", "BLOCK": "n", "MTD": "n",
    "LOCALVERSION_AUTO": "n",
}
WIFI = {
    "WIRELESS": "y", "CFG80211": "y", "CFG80211_REQUIRE_SIGNED_REGDB": "n",
    "WLAN": "y", "WLAN_VENDOR_BROADCOM": "y", "BRCMUTIL": "y",
    "BRCMFMAC": "y", "BRCMFMAC_PCIE": "y", "BRCMDBG": "y",
    "PCIE_APPLE_T7000_DEVICE_WAKE_TEST": "y", "FONTS": "y", "FONT_TER16x32": "y",
    "FW_LOADER_USER_HELPER_FALLBACK": "n", "FW_LOADER_USER_HELPER": "n",
    "BRCMFMAC_PCIE_H1B_DIAG": "n", "APPLE_DART_H1B_DIAG": "n",
    "PCIE_APPLE_T7000_DEBUGFS_DIAG": "n", "PCIE_APPLE_T7000_BCM_PROBE": "n",
    "PCIE_APPLE_T7000_BCM_PROBE_SHADOW": "n", "PCIE_APPLE_T7000_MSI_SELFTEST": "n",
    # Preserve upstream production options compatible with BLOCK=n. SquashFS,
    # EROFS and loop disks intentionally remain absent in this radio milestone.
    "SQUASHFS": "n", "EROFS_FS": "n", "OVERLAY_FS": "y", "CGROUP_BPF": "y",
    "FUSE_FS": "y", "SPI_SPIDEV": "y",
}
PROBE = {
    "PCIE_APPLE_T7000_BCM_PROBE": "y", "PCIE_APPLE_T7000_BCM_PROBE_SHADOW": "y",
    "DEBUG_FS": "y", "WIRELESS": "n", "WLAN": "n", "BRCMFMAC": "n",
    "PCIE_APPLE_T7000_MSI_SELFTEST": "n",
}


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n")


def set_config(text, key, value):
    pattern = re.compile(r"^(?:CONFIG_" + re.escape(key) + r"=.*|# CONFIG_" + re.escape(key) + r" is not set)$", re.M)
    if len(pattern.findall(text)) > 1:
        raise RuntimeError("Duplicate base config setting: " + key)
    line = "# CONFIG_" + key + " is not set" if value == "n" else "CONFIG_" + key + "=" + value
    return pattern.sub(lambda _: line, text) if pattern.search(text) else text + "\n" + line + "\n"


def values(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        if line.startswith("CONFIG_"):
            key, val = line[7:].split("=", 1)
            result[key] = val
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            result[line[9:-11]] = "n"
    return result


def apply_exact_patch(source, patch, log):
    """GNU zero-fuzz first; uniquely exact rejected context handles EOF quirks.

    Some upstream handcrafted hunks have fewer trailing than leading context
    lines, which GNU patch interprets as an end-of-file constraint. If the
    complete old hunk occurs exactly once elsewhere, replacing that exact text
    preserves every context byte without GNU's default fuzzy context removal.
    """
    process = subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch)], cwd=source, stdout=log, stderr=subprocess.STDOUT)
    if process.returncode == 0:
        return []
    if process.returncode != 1:
        raise RuntimeError("GNU patch reported a non-hunk failure: " + str(patch))
    repaired = []
    touched = re.findall(r"^diff --git a/(.+) b/\1$", patch.read_text(), re.M)
    for rel in touched:
        reject = source / (rel + ".rej")
        if not reject.exists():
            continue
        path = source / rel
        text = path.read_text()
        chunks = re.split(r"(?m)^@@[^\n]*\n", reject.read_text())[1:]
        if not chunks:
            raise RuntimeError("Unrecognized rejected patch format")
        for chunk in chunks:
            lines = chunk.splitlines(keepends=True)
            if any(line.startswith("\\") for line in lines):
                raise RuntimeError("No-newline rejected context needs manual review")
            old = "".join(line[1:] for line in lines if line.startswith((" ", "-")))
            new = "".join(line[1:] for line in lines if line.startswith((" ", "+")))
            if not old or text.count(old) != 1:
                raise RuntimeError("Rejected patch is not a unique exact-context match: " + str(reject))
            text = text.replace(old, new, 1)
            repaired.append({"file": rel, "old_context_sha256": hashlib.sha256(old.encode()).hexdigest(), "new_context_sha256": hashlib.sha256(new.encode()).hexdigest()})
        path.write_text(text)
        reject.unlink()
    if not repaired:
        raise RuntimeError("Patch failed without repairable exact-context rejects: " + str(patch))
    log.write("Strict exact-context fallback: " + json.dumps(repaired) + "\n")
    log.flush()
    return repaired


def build(args, variant):
    recipe_name, expected_count, suffix = VARIANTS[variant]
    work = ROOT / variant
    source_parent = work / "source"
    source = source_parent / ("linux-" + LINUX_REV)
    output = work / "output"
    products = work / "products"
    config_name = "j81_" + variant.replace("-", "_") + "_ram_defconfig"
    recipe = args.project / "kernel" / recipe_name
    recipe_text = recipe.read_text()
    patch_names = re.findall(r'patch -d "\$out" -p1 < \$\{\./patches/([^}]+)\}', recipe_text)
    if len(patch_names) != expected_count or len(set(patch_names)) != expected_count:
        raise RuntimeError("Unexpected ordered upstream patch list")
    if digest(args.archive) != ARCHIVE_SHA256 or digest(args.base_config) != BASE_CONFIG_SHA256:
        raise RuntimeError("Pinned Linux archive or base config differs")
    work.mkdir(parents=True, exist_ok=True)
    manifest = work / "source-prepared.json"
    if not manifest.exists():
        if source_parent.exists():
            raise RuntimeError("Incomplete previous source preparation; inspect it before retry")
        source_parent.mkdir()
        with tarfile.open(args.archive, "r:gz") as archive:
            archive.extractall(source_parent, filter="data")
        backlight = source / "drivers/video/backlight/apple_pmic_bl.c"
        text = backlight.read_text()
        needle = "return ((cmd[1] & 7) << 8) | (cmd[0] & 0xff);"
        if text.count(needle) != 1:
            raise RuntimeError("Backlight compatibility-fix context differs")
        backlight.write_text(text.replace(needle, needle + "\n\t\tdefault:\n\t\t\treturn -EINVAL;"))
        patches = []
        patch_copy = work / "patches"
        patch_copy.mkdir()
        with (work / "prepare.log").open("w") as log:
            for name in patch_names:
                original = args.project / "kernel/patches" / name
                patch = patch_copy / name
                shutil.copyfile(original, patch)
                exact_fallback = apply_exact_patch(source, patch, log)
                patches.append({"name": name, "sha256": digest(patch), "exact_context_fallback": exact_fallback})
        changes = {**COMMON, **(PROBE if variant == "radio-id" else WIFI), "LOCALVERSION": json.dumps(suffix)}
        config = args.base_config.read_text()
        for key, val in changes.items():
            config = set_config(config, key, val)
        (source / "arch/arm64/configs" / config_name).write_text(config)
        (work / "requested.config").write_text(config)
        shutil.copyfile(recipe, work / recipe_name)
        shutil.copyfile(args.base_config, work / "config_16k.original")
        write_json(manifest, {
            "variant": variant, "linux_revision": LINUX_REV, "project_revision": PROJECT_REV,
            "linux_archive_sha256": ARCHIVE_SHA256, "base_config_sha256": BASE_CONFIG_SHA256,
            "upstream_recipe": recipe_name, "recipe_sha256": digest(recipe), "patches": patches,
            "configuration_changes": changes,
            "backlight_fix": "Exact default-return fix carried by upstream Nix recipe",
            "build_method": "isolated fresh make build, not a Nix-produced binary",
            "hardware_tested": False,
        })
        print(f"{variant}: prepared {len(patches)} exact ordered patches", flush=True)
    output.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update({
        "PATH": str(args.toolchain / "usr/bin") + ":" + env["PATH"],
        "LD_LIBRARY_PATH": str(args.toolchain / "usr/lib/x86_64-linux-gnu"),
        "BISON_PKGDATADIR": str(args.toolchain / "usr/share/bison"),
        "M4": str(args.toolchain / "usr/bin/m4"), "LC_ALL": "C",
        "KBUILD_BUILD_USER": "j81-ram", "KBUILD_BUILD_HOST": "isolated-linux",
        "KBUILD_BUILD_VERSION": "1", "SOURCE_DATE_EPOCH": str(EPOCH),
        "KBUILD_BUILD_TIMESTAMP": datetime.datetime.fromtimestamp(EPOCH, datetime.timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y"),
    })
    make = ["make", "-C", str(source), "O=" + str(output), "ARCH=arm64",
            "CROSS_COMPILE=" + str(args.toolchain / "usr/bin/aarch64-linux-gnu-"),
            "HOSTCC=/usr/bin/gcc", "HOSTCXX=/usr/bin/g++",
            "HOSTCFLAGS=-I" + str(args.toolchain / "usr/include"),
            "HOSTLDFLAGS=-L" + str(args.toolchain / "usr/lib/x86_64-linux-gnu")]
    with (work / "configure.log").open("w") as log:
        subprocess.run(make + [config_name], env=env, check=True, stdout=log, stderr=subprocess.STDOUT)
    effective = values(output / ".config")
    required = ["ARM64_4K_PAGES", "BLK_DEV_INITRD", "RD_GZIP", "DEVTMPFS", "PROC_FS", "SYSFS", "TMPFS", "UNIX98_PTYS", "NET", "INET", "CONFIGFS_FS", "USB_GADGET", "USB_CONFIGFS", "USB_CONFIGFS_ECM", "USB_DWC2", "DRM_SIMPLEDRM", "INPUT_UINPUT", "PCIE_APPLE_T7000", "APPLE_DART", "DEBUG_FS"]
    forbidden = ["BLOCK", "MTD", "MMC", "APPLE_ASP", "NVME_APPLE", "BLK_DEV_NVME", "ARM64_16K_PAGES", "ARM64_64K_PAGES", "DEBUG_INFO", "PCIE_APPLE_T7000_MSI_SELFTEST"]
    if variant == "radio-id":
        required += ["PCIE_APPLE_T7000_BCM_PROBE", "PCIE_APPLE_T7000_BCM_PROBE_SHADOW"]
        forbidden += ["WIRELESS", "WLAN", "BRCMFMAC"]
    else:
        required += ["WIRELESS", "WLAN", "CFG80211", "BRCMUTIL", "BRCMFMAC", "BRCMFMAC_PCIE", "PCIE_APPLE_T7000_DEVICE_WAKE_TEST"]
        forbidden += ["BRCMFMAC_PCIE_H1B_DIAG", "APPLE_DART_H1B_DIAG", "PCIE_APPLE_T7000_DEBUGFS_DIAG", "PCIE_APPLE_T7000_BCM_PROBE", "PCIE_APPLE_T7000_BCM_PROBE_SHADOW", "FW_LOADER_USER_HELPER", "FW_LOADER_USER_HELPER_FALLBACK"]
    problems = [key + " must be built in" for key in required if effective.get(key) != "y"]
    problems += [key + " must be disabled" for key in forbidden if effective.get(key, "n") != "n"]
    if effective.get("LOCALVERSION") != json.dumps(suffix):
        problems.append("Incorrect unique local version")
    write_json(work / "config-verification.json", {"required_builtins": {k:effective.get(k) for k in required}, "required_disabled": {k:effective.get(k,"n") for k in forbidden}, "config_sha256": digest(output / ".config"), "problems": problems})
    if problems:
        raise RuntimeError("; ".join(problems))
    command = make + ["-j" + str(args.jobs), "Image", "apple/t7001-j81.dtb"]
    write_json(work / "build-command.json", command)
    print(f"{variant}: configuration verified, building with {args.jobs} jobs; log {work / 'build.log'}", flush=True)
    with (work / "build.log").open("w") as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            status = process.wait(timeout=2400)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            status = 124
    write_json(work / "build-result.json", {"returncode": status, "hardware_tested": False})
    if status:
        raise RuntimeError(f"{variant} build failed ({status}); see build.log")
    products.mkdir(exist_ok=True)
    for src, name in [(output / "arch/arm64/boot/Image", "Image"), (output / "arch/arm64/boot/dts/apple/t7001-j81.dtb", "t7001-j81.dtb"), (output / ".config", "kernel.config")]:
        shutil.copyfile(src, products / name)
    release = (output / "include/config/kernel.release").read_text().strip()
    if release != "7.3.0-rc1" + suffix:
        raise RuntimeError("Built kernel release differs: " + release)
    header = (products / "Image").read_bytes()[:64]
    if header[56:60] != b"ARM\x64":
        raise RuntimeError("Built image lacks arm64 Image magic")
    result = {"kernel_release": release, "variant": variant, "hardware_tested": False,
              "files": {p.name:{"bytes":p.stat().st_size,"sha256":digest(p)} for p in products.iterdir() if p.is_file()}}
    write_json(work / "products.json", result)
    print(json.dumps(result), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("variant", choices=["radio-id", "wifi", "all"])
    parser.add_argument("--archive", type=Path, default=Path("/tmp/air2-linux-build/linux-" + LINUX_REV + ".tar.gz"))
    parser.add_argument("--base-config", type=Path, default=Path("/tmp/air2-linux-build/config_16k.original"))
    parser.add_argument("--project", type=Path, default=Path("/tmp/air2-route-audit/mattonik-ipad-nixos-b94d42f"))
    parser.add_argument("--toolchain", type=Path, default=Path("/tmp/air2-linux-build/toolchain"))
    parser.add_argument("--jobs", type=int, default=6)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 6:
        parser.error("jobs must be from 1 to 6")
    for variant in (["radio-id", "wifi"] if args.variant == "all" else [args.variant]):
        build(args, variant)


if __name__ == "__main__":
    main()

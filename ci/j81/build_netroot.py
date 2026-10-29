#!/usr/bin/env python3
"""Build isolated J81 Wi-Fi plus NFSv3-client kernel; never touch the iPad.

Uses the pinned source and unchanged 63-patch Wi-Fi recipe. The original
builder is imported and parameterized in memory, not edited on disk.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

PINNED_REPO = "7ea2b2b0f5c070690bf0efafd25a69d6ea345454"
ARCHIVE_SHA256 = "5eca8c1a096009ef867451d08433735ff29548220adb880f85b9840de65bf15f"
BASE_SHA256 = "a5cbcb0d3fe655888106672e6fe03477b63d51bd36bbcfc4f5145627d906b208"
LOCALVERSION = "-j81-omarchy-netroot"
NETROOT_CONFIG = {
    "NETWORK_FILESYSTEMS": "y",
    "NFS_FS": "y",
    "NFS_V3": "y",
    "SUNRPC": "y",
    "LOCKD": "y",
    "NFS_V4": "n",
    "ROOT_NFS": "n",
    "IP_PNP": "n",
}
REQUIRED = (
    "ARM64_4K_PAGES", "NET", "INET", "USB_GADGET", "USB_CONFIGFS",
    "USB_CONFIGFS_ECM", "NFS_FS", "NFS_V3", "SUNRPC", "LOCKD",
    "NETWORK_FILESYSTEMS", "OVERLAY_FS", "FUSE_FS", "TMPFS",
    "BRCMFMAC", "BRCMFMAC_PCIE", "DRM_SIMPLEDRM",
)
FORBIDDEN = (
    "BLOCK", "MTD", "MMC", "APPLE_ASP", "NVME_APPLE", "BLK_DEV_NVME",
    "ARM64_16K_PAGES", "ARM64_64K_PAGES", "ROOT_NFS", "IP_PNP",
)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def require(condition, description):
    if not condition:
        raise ValueError(description)


def validate_inputs(repo, archive, toolchain):
    repo = repo.resolve(strict=True)
    require((repo / "kernel/j81/reference/build_kernels.py").is_file(), "J81 producer missing")
    require((repo / "kernel/j81/reference/verify_built.py").is_file(), "J81 binary verifier missing")
    require((repo / "kernel/j81/upstream/kernel/hoolock-pcie-j81-wifi-h1b.nix").is_file(), "J81 Wi-Fi recipe missing")
    require((repo / "kernel/j81/configs/baseline.config").is_file(), "J81 base config missing")
    require(sha256(archive) == ARCHIVE_SHA256, "Pinned Linux source hash mismatch")
    require(sha256(repo / "kernel/j81/configs/baseline.config") == BASE_SHA256, "Pinned base config hash mismatch")
    commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True
    ).stdout.strip()
    require(commit == PINNED_REPO, "J81 checkout differs from the qualified source commit")
    patches = json.loads(
        (repo / "kernel/j81/reference/wifi-source-prepared.json").read_text()
    )["patches"]
    require(len(patches) == 63, "Unexpected J81 Wi-Fi patch count")
    for patch in patches:
        file = repo / "kernel/j81/upstream/kernel/patches" / patch["name"]
        require(file.is_file() and sha256(file) == patch["sha256"], "J81 patch differs: " + patch["name"])
    for executable in ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-ld", "bison", "m4", "dtc", "fdtget"):
        require((toolchain / "usr/bin" / executable).is_file(), "Cross-tool not found: " + executable)


def patch_verifier(original, modified):
    code = original.read_text()
    swaps = (
        ('choices=("radio-id", "wifi")', 'choices=("radio-id", "wifi", "netroot")'),
        ('suffix = "-j81-radio-id" if args.variant == "radio-id" else "-j81-wifi-ram"',
         'suffix = "-j81-radio-id" if args.variant == "radio-id" else ("-j81-omarchy-netroot" if args.variant == "netroot" else "-j81-wifi-ram")'),
    )
    for old, new in swaps:
        require(code.count(old) == 1, "Original verifier changed: " + old)
        code = code.replace(old, new)
    modified.write_text(code)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True, type=Path)
    ap.add_argument("--linux-archive", required=True, type=Path)
    ap.add_argument("--toolchain", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--jobs", type=int, choices=range(1, 7), default=4)
    ap.add_argument("--check-inputs", action="store_true")
    args = ap.parse_args()
    if sys.platform != "linux" or platform.machine() != "x86_64":
        ap.error("This kernel recipe requires Linux x86_64")
    repo = args.repo.resolve(strict=True)
    archive = args.linux_archive.resolve(strict=True)
    toolchain = args.toolchain.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or output == repo or repo in output.parents:
        ap.error("Output must be a NEW directory outside the source checkout")
    validate_inputs(repo, archive, toolchain)
    print("J81 source commit, 63 Wi-Fi patches, Linux archive and build tools verified.")
    if args.check_inputs:
        return
    output.mkdir(parents=True)
    source = repo / "kernel/j81/reference/build_kernels.py"
    spec = importlib.util.spec_from_file_location("original_j81_kernel_builder", source)
    require(spec is not None and spec.loader is not None, "Cannot load pinned J81 builder")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    require(builder.VARIANTS["wifi"] == ("hoolock-pcie-j81-wifi-h1b.nix", 63, "-j81-wifi-ram"),
            "Original Wi-Fi build profile changed")
    require(builder.COMMON.get("BLOCK") == "n" and builder.COMMON.get("MTD") == "n",
            "Baseline storage safety changed")
    builder.ROOT = output
    builder.VARIANTS = dict(builder.VARIANTS, netroot=(builder.VARIANTS["wifi"][0], 63, LOCALVERSION))
    builder.WIFI = dict(builder.WIFI, **NETROOT_CONFIG)
    options = argparse.Namespace(
        archive=archive,
        base_config=repo / "kernel/j81/configs/baseline.config",
        project=repo / "kernel/j81/upstream",
        toolchain=toolchain,
        jobs=args.jobs
    )
    builder.build(options, "netroot")
    products = output / "netroot/products"
    config = builder.values(products / "kernel.config")
    errors = [name + " must be built in" for name in REQUIRED if config.get(name) != "y"]
    errors += [name + " must stay disabled" for name in FORBIDDEN if config.get(name, "n") != "n"]
    require(not errors, "; ".join(errors))
    verifier = output / "verify_netroot.py"
    patch_verifier(repo / "kernel/j81/reference/verify_built.py", verifier)
    subprocess.run(
        [sys.executable, "-B", str(verifier), "netroot", "--project", str(repo / "kernel/j81/upstream")],
        check=True
    )
    with (products / "Image").open("rb") as image, (products / "Image.gz").open("wb") as compressed:
        with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, compresslevel=9, mtime=0) as gz:
            shutil.copyfileobj(image, gz)
    manifest = {
        "stage": "compiled-j81-netroot-kernel-not-boot-tested",
        "source_commit": PINNED_REPO,
        "kernel_release": "7.3.0-rc1" + LOCALVERSION,
        "hardware_tested": False,
        "config_required_builtins": list(REQUIRED),
        "config_required_disabled": list(FORBIDDEN),
        "files": {name: {"bytes": (products / name).stat().st_size, "sha256": sha256(products / name)}
                  for name in ("Image", "Image.gz", "t7001-j81.dtb", "kernel.config")},
        "note": "NOT bootable alone. J81 private firmware, USB ECM/NFS initramfs, and systemd adaptation remain.",
    }
    (products / "netroot-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Built and checked J81 network-root kernel:", products)
    print("Not a boot payload. Do not replace the working wifi-base files.")


if __name__ == "__main__":
    main()

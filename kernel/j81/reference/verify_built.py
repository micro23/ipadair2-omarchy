#!/usr/bin/env python3
"""Check the built J81 kernel/DT contract without contacting hardware."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("variant", choices=("radio-id", "wifi"))
    parser.add_argument("--project", type=Path, default=Path("/tmp/air2-route-audit/mattonik-ipad-nixos-b94d42f"))
    args = parser.parse_args()
    work = Path(__file__).resolve().parent / args.variant
    products = work / "products"
    spec = importlib.util.spec_from_file_location("upstream_j81_payload_verifier", args.project / "boot/verify_pcie_j81_reg_on_payload.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    image = (products / "Image").read_bytes()
    dtb = (products / "t7001-j81.dtb").read_bytes()
    nodes = verifier.fdt_nodes(dtb)
    suffix = "-j81-radio-id" if args.variant == "radio-id" else "-j81-wifi-ram"
    problems = []
    checks = []

    def need(condition, detail):
        (checks if condition else problems).append(detail)

    def cell(data):
        return struct.unpack(">I", data)[0] if len(data) == 4 else None

    def cells(data):
        return struct.unpack(">" + "I" * (len(data) // 4), data) if len(data) % 4 == 0 else ()

    root = nodes.get("/", {})
    compatible = root.get("compatible", b"").split(b"\0")
    need(b"apple,j81" in compatible and b"apple,t7001" in compatible, "Correct J81/T7001 compatible")
    need(image[56:60] == b"ARM\x64", "ARM64 Image magic")
    need(("Linux version 7.3.0-rc1" + suffix + " ").encode() in image, "Unique expected kernel version embedded")
    holders = [(p, v) for p, v in nodes.items() if "apple,reg-on-pmic" in v]
    need(len(holders) == 1, "Exactly one board-bound Wi-Fi REG_ON declaration")
    if len(holders) == 1:
        path, props = holders[0]
        need(path.endswith("pcie@610000000"), "REG_ON belongs to the J81 PCIe node")
        need(props.get("status") == b"okay\0", "PCIe node enabled")
        target = [p for p, v in nodes.items() if v.get("phandle") == props["apple,reg-on-pmic"]]
        need(len(target) == 1 and target[0].endswith("pmic@3c"), "REG_ON phandle resolves to D2207 PMIC")
        if len(target) == 1:
            need(b"apple,i2c-pmic" in nodes[target[0]].get("compatible", b""), "REG_ON target is the expected Apple PMIC")
        need(cells(props.get("apple,msi-doorbell", b"")) == (0, 0xbffff000), "MSI doorbell is the proven reserved address")
        need("msi-controller" in props and "msi-parent" in props and props.get("msi-parent") == props.get("phandle"), "PCIe MSI parent points to itself")
        msi = cells(props.get("msi-ranges", b""))
        need(len(msi) == 5 and msi[1:] == (0, 224, 1, 32), "MSI interrupt range matches the J81 source")
        if args.variant == "wifi":
            need(cells(props.get("apple,iova-window", b"")) == (0, 0x80000000, 0, 0xbffff000), "Proven PCI DMA IOVA window")
            need("apple,iova-rebase" in props, "Apple IOVA rebase enabled")

    for token in (b"failed to assert declared J81 Wi-Fi REG_ON", b"J81 Wi-Fi REG_ON: 0x%04x", b"t7000-pcie: link active=", b"t7000-pcie: MSI domain:"):
        need(token in image, "Kernel includes " + token.decode())
    for token in (b"reg-on-test: no PMU node", b"reg-on-test: unexpected config", b"tuning-baseline-test", b"dbi-write-test", b"link-wait-test", b"link-speed-test", b"dbi-ecam-read-test", b"t7000-msi-selftest"):
        need(token not in image, "Kernel excludes obsolete/self-test path " + token.decode())

    if args.variant == "radio-id":
        for token in (b"t7000-bcm-probe: ", b"BAR0 window restore", b"t7000-bcm-otp-shadow", b"private, not for Git"):
            need(token in image, "Identification kernel contains " + token.decode())
        need(b"brcmfmac" not in image, "No brcmfmac driver in identification kernel")
    else:
        for token in (b"brcmfmac4350c2-pcie", b"brcmf_pcie", b"brcmfmac", b"t7000-pcie: DEVICE_WAKE asserted", b"J81 PCIe DART options"):
            need(token in image, "Wi-Fi kernel contains " + token.decode())
        for token in (b"t7000-bcm-probe", b"t7000-bcm-otp-shadow", b"ROM reads unlocked", b"h1b_hold", b"h1b_rxpost", b"h1b_sync_ms", b"Falling back to sysfs fallback"):
            need(token not in image, "Production kernel excludes diagnostic/fallback path " + token.decode())
        dart_nodes = [(p, v) for p, v in nodes.items() if p.endswith("iommu@602002000")]
        need(len(dart_nodes) == 1, "Exactly one J81 PCIe DART node")
        if len(dart_nodes) == 1:
            dart = dart_nodes[0][1]
            for prop in ("apple,ios-pte", "apple,pci-alias"):
                need(prop in dart, "DART carries " + prop)
            for prop, expected in (("apple,error-reflector", 0x20ffff), ("apple,fetch-config", 0xe0303), ("apple,diag-config", 0x100)):
                need(cell(dart.get(prop, b"")) == expected, "DART carries exact " + prop)
        alias = nodes.get("/aliases", {}).get("wifi0", b"").rstrip(b"\0").decode()
        endpoint = nodes.get(alias, {})
        need(bool(endpoint), "wifi0 alias resolves to a device-tree endpoint")
        need(endpoint.get("compatible") == b"pci14e4,43a3\0", "Wi-Fi endpoint identifies BCM4350 PCI device")
        need(cells(endpoint.get("reg", b"")) == (0x10000, 0, 0, 0, 0), "Wi-Fi endpoint has the proven bus address")
        need(endpoint.get("local-mac-address") == b"\0" * 6, "Public image contains only a zero MAC placeholder for m1n1")

    dtc_warnings = [line for line in (work / "build.log").read_text().splitlines() if ": Warning (" in line]
    result = {"variant": args.variant, "passed": not problems, "checks": checks, "problems": problems,
              "retained_upstream_dtc_warnings": dtc_warnings,
              "Image_sha256": hashlib.sha256(image).hexdigest(), "dtb_sha256": hashlib.sha256(dtb).hexdigest(), "hardware_tested": False}
    (work / "binary-dtb-validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"variant": args.variant, "passed": not problems, "passed_checks": len(checks), "problems": problems}))
    raise SystemExit(bool(problems))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Static verification of the Wi-Fi-only J81 REG_ON staging payload (stdlib only).

Usage: python3 boot/verify_pcie_j81_reg_on_payload.py PAYLOAD_DIR [--dllla | --clean | --doorbell | --msi | --msi-selftest | --msi-diag | --bcm-probe | --bcm-shadow | --dma-rebase | --dma-raw | --wifi-h1b-base | --wifi-h1b-base-raw]

--dllla additionally requires the 0053 DLLLA link-wait strings and rejects the old
`link-wait-test: link_up=` poll output. --clean (patch 0054) requires the durable
`t7000-pcie: link active=` string and rejects every test-stage log prefix. --doorbell
(patch 0055) is --clean plus the PCIe node's `apple,msi-doorbell` = 0xbffff000. --msi (patch
0057) is --doorbell plus the one-vector MSI domain: `msi-controller`, `msi-parent` and `msi-ranges`
(AIC 224, 32 vectors, edge) on the PCIe node and the driver's domain string. --msi-selftest (patch
0058, TEST payload) is --msi plus the self-test driver's strings.

Checks the built `m1n1-hoolock-pcie-j81-reg-on` output without any device:
checksums and m1n1-linux.bin composition; the DTB names the D2207 PMIC for the PCIe
node exactly once; the initramfs carries no Bluetooth userland or I2C tools; the
kernel contains the board-gated REG_ON strings and not the earlier test-stage ones.
"""
import gzip
import hashlib
from pathlib import Path
import struct
import sys

I2C_TOOLS = {"i2cget", "i2cset", "i2cdetect", "i2cdump", "i2ctransfer"}
FORBIDDEN_BINARIES = I2C_TOOLS | {"btattach", "hciattach", "hciconfig", "hcitool"}


J81_BASE_EXECUTABLES = ("usr/bin/charging-policy", "usr/bin/tablet-status", "usr/bin/tablet-dashboard",
                        "etc/postmarketos-mkinitfs/hooks/20-debug-shell.sh")
J81_BASE_BOOTARGS = ("console=tty0", "ignore_loglevel", "rdinit=/init", "PMOS_NO_OUTPUT_REDIRECT", "pd_ignore_unused",
                     "clk_ignore_unused")


def j81_base_problems(entries, image, bootargs):
    """What every J81 payload must carry (docs/plans/2026-10-08-j81-base-package.md): charging policy plus the writable
    charger in the kernel, telnet + key-only SSH, the debug console arguments and the tablet tools."""
    problems = []
    for name in J81_BASE_EXECUTABLES:
        if name not in entries:
            problems.append(f"J81 base: {name} missing from the initramfs")
        elif not entries[name][0] & 0o111:
            problems.append(f"J81 base: {name} is not executable")
    hook = entries.get("etc/postmarketos-mkinitfs/hooks/20-debug-shell.sh", (0, b""))[1]
    for needle in (b"telnetd", b"dropbear", b"/usr/bin/charging-policy", b"loop_forever"):
        if needle not in hook:
            problems.append(f"J81 base: the debug-shell hook lacks {needle.decode()!r}")
    if b"@DROPBEAR@" in hook:
        problems.append("J81 base: the hook still has the @DROPBEAR@ placeholder")
    if "root/.ssh/authorized_keys" not in entries or not entries["root/.ssh/authorized_keys"][1].strip():
        problems.append("J81 base: root/.ssh/authorized_keys missing or empty")
    if not any(n.startswith("nix/store/") and n.endswith("/bin/dropbear") for n in entries):
        problems.append("J81 base: the Dropbear binary is not in the initramfs")
    if b"j81-d2207-charger" not in image:
        problems.append("J81 base: the kernel lacks the J81 D2207 charger driver")
    for token in J81_BASE_BOOTARGS:
        if token not in bootargs:
            problems.append(f"J81 base: bootargs lack {token!r}")
    return problems


def cpio_entries(data):
    """Read concatenated newc archives (same parser as boot/test_usb_diagnostic.py)."""
    result, offset = {}, 0
    while offset < len(data):
        if data[offset] == 0:
            offset += 1
            continue
        assert data[offset:offset + 6] == b"070701", offset
        fields = [int(data[offset + 6 + i * 8:offset + 14 + i * 8], 16) for i in range(13)]
        mode, size, namesize = fields[1], fields[6], fields[11]
        start = offset + 110
        name = data[start:start + namesize - 1].decode().removeprefix("./")
        start = (start + namesize + 3) & ~3
        if name != "TRAILER!!!":
            result[name] = (mode, data[start:start + size])
        offset = (start + size + 3) & ~3
    return result


def fdt_nodes(blob):
    """Return {path: {property: bytes}} for a flattened device tree."""
    magic, _total, off_struct, off_strings = struct.unpack(">4I", blob[:16])
    assert magic == 0xD00DFEED, "not a DTB"
    pos, path, nodes = off_struct, [], {}
    align = lambda x: (x + 3) & ~3  # noqa: E731
    while True:
        tag = struct.unpack(">I", blob[pos:pos + 4])[0]
        pos += 4
        if tag == 1:
            end = blob.index(b"\0", pos)
            path.append(blob[pos:end].decode())
            pos = align(end + 1)
            nodes["/".join(path) or "/"] = {}
        elif tag == 2:
            path.pop()
        elif tag == 3:
            length, nameoff = struct.unpack(">II", blob[pos:pos + 8])
            pos += 8
            name_start = off_strings + nameoff
            name = blob[name_start:blob.index(b"\0", name_start)].decode()
            nodes["/".join(path) or "/"][name] = blob[pos:pos + length]
            pos = align(pos + length)
        elif tag == 9:
            return nodes


def main(argv):
    payload = Path(argv[1])
    flags = set(argv[2:])
    selftest = "--msi-selftest" in flags
    diag = "--msi-diag" in flags
    shadow = "--bcm-shadow" in flags
    wifi_raw = "--wifi-h1b-base-raw" in flags
    wifi_base = "--wifi-h1b-base" in flags or wifi_raw
    dma_rebase, dma_raw = "--dma-rebase" in flags or ("--wifi-h1b-base" in flags), "--dma-raw" in flags or wifi_raw
    msi_extra = dma_rebase or dma_raw
    bcm = "--bcm-probe" in flags or shadow
    msi = "--msi" in flags or selftest or diag or bcm or msi_extra
    doorbell = "--doorbell" in flags or msi
    clean = "--clean" in flags or doorbell
    dllla = "--dllla" in flags or clean
    problems = []

    # Checksums and composition.
    for line in (payload / "SHA256SUMS").read_text().splitlines():
        digest, path = line.split()
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            problems.append(f"checksum mismatch: {path}")
    parts = ("m1n1.bin", "bootargs", "t7001-j81.dtb", "Image.gz", "initramfs.gz")
    if (payload / "m1n1-linux.bin").read_bytes() != b"".join((payload / p).read_bytes() for p in parts):
        problems.append("m1n1-linux.bin is not the concatenation of its parts")

    # DTB: the PMIC phandle appears only on the PCIe node, and resolves to the D2207.
    nodes = fdt_nodes((payload / "t7001-j81.dtb").read_bytes())
    holders = {p: v for p, v in nodes.items() if "apple,reg-on-pmic" in v}
    if len(holders) != 1:
        problems.append(f"apple,reg-on-pmic must appear exactly once, found {sorted(holders)}")
    else:
        (holder, props), = holders.items()
        if "pcie@610000000" not in holder:
            problems.append(f"apple,reg-on-pmic is on {holder}, not the PCIe node")
        handle = struct.unpack(">I", props["apple,reg-on-pmic"])[0]
        targets = [p for p, v in nodes.items() if v.get("phandle") == struct.pack(">I", handle)]
        if len(targets) != 1 or not targets[0].endswith("pmic@3c"):
            problems.append(f"phandle resolves to {targets}, expected the D2207 pmic@3c")
        else:
            compat = nodes[targets[0]].get("compatible", b"")
            if b"apple,i2c-pmic" not in compat:
                problems.append("target is not an apple,i2c-pmic")
        if holders and nodes[holder].get("status", b"").rstrip(b"\0") != b"okay":
            problems.append("PCIe node is not enabled in this payload")
    for forbidden in ("touch", "bluetooth", "bt"):
        for p, v in nodes.items():
            comp = v.get("compatible", b"")
            if b"apple,reg-on" in comp and forbidden in comp.decode(errors="ignore"):
                problems.append(f"unexpected compatible on {p}")

    # initramfs: no Bluetooth userland or I2C tools anywhere.
    entries = cpio_entries(gzip.decompress((payload / "initramfs.gz").read_bytes()))
    present = sorted(n for n in entries if n.rsplit("/", 1)[-1] in FORBIDDEN_BINARIES)
    if present:
        problems.append(f"forbidden binaries in initramfs: {present}")
    if "etc/deviceinfo" not in entries or b"ecm.usb0" not in entries["etc/deviceinfo"][1]:
        problems.append("ECM deviceinfo override missing")
    if wifi_base:
        problems += j81_base_problems(entries, gzip.decompress((payload / "Image.gz").read_bytes()),
                                      (payload / "bootargs").read_text())

    # Kernel: board-gated strings present, test-stage REG_ON strings absent.
    image = gzip.decompress((payload / "Image.gz").read_bytes())
    for needle in (b"failed to assert declared J81 Wi-Fi REG_ON", b"J81 Wi-Fi REG_ON: 0x%04x"):
        if needle not in image:
            problems.append(f"kernel lacks {needle.decode()!r}")
    for stale in (b"reg-on-test: no PMU node", b"reg-on-test: unexpected config"):
        if stale in image:
            problems.append(f"kernel still has test-stage string {stale.decode()!r}")

    if dllla:
        link_string = b"t7000-pcie: link active=" if clean else b"t7000-pcie link-wait: link active="
        if link_string not in image:
            problems.append(f"kernel lacks the DLLLA link-wait log string {link_string.decode()!r}")
        if b"link-wait-test: link_up=" in image:
            problems.append("kernel still has the +0x88 bit-6 link-up poll output")
    if clean:
        for stale in (b"tuning-baseline-test", b"dbi-write-test", b"link-wait-test", b"link-speed-test",
                      b"dbi-ecam-read-test", b"t7000-pcie link-wait:"):
            if stale in image:
                problems.append(f"kernel still has test-stage string {stale.decode()!r}")
    if doorbell:
        if b"apple,msi-doorbell" not in image:
            problems.append("kernel lacks the apple,msi-doorbell property lookup")
        holder = [p for p, v in nodes.items() if "apple,msi-doorbell" in v]
        if len(holder) != 1 or "pcie@610000000" not in holder[0]:
            problems.append(f"apple,msi-doorbell must be on the PCIe node only, found {holder}")
        else:
            value = nodes[holder[0]]["apple,msi-doorbell"]
            if struct.unpack(">II", value) != (0, 0xBFFFF000):
                problems.append(f"apple,msi-doorbell is {value.hex()}, expected 00000000bffff000")

    if msi:
        pcie = [p for p in nodes if p.endswith("pcie@610000000")]
        props = nodes[pcie[0]] if len(pcie) == 1 else {}
        if "msi-controller" not in props:
            problems.append("PCIe node lacks msi-controller")
        if "msi-parent" in props:
            handle = struct.unpack(">I", props["msi-parent"])[0]
            if nodes[pcie[0]].get("phandle") != struct.pack(">I", handle):
                problems.append("msi-parent does not point at the PCIe node itself")
        else:
            problems.append("PCIe node lacks msi-parent")
        ranges = props.get("msi-ranges", b"")
        cells = struct.unpack(f">{len(ranges) // 4}I", ranges) if ranges and len(ranges) % 4 == 0 else ()
        # <&aic type=0 irq=224 flags=1 (edge rising) count=32>
        if len(cells) != 5 or cells[1:] != (0, 224, 1, 32):
            problems.append(f"msi-ranges is {cells}, expected <&aic 0 224 1 32>")
        for needle in (b"t7000-pcie: MSI domain:", b"apple,msi-doorbell"):
            if needle not in image:
                problems.append(f"kernel lacks {needle.decode()!r}")

    if selftest:
        for needle in (b"t7000-msi-selftest: ", b"t7000-msi-selftest"):
            if needle not in image:
                problems.append(f"kernel lacks {needle.decode()!r}")
    if diag:
        if b"(MSIADDR, read-only)" not in image:
            problems.append("kernel lacks the read-only +0x168 diagnostic string")
    elif msi and b"(MSIADDR, read-only)" in image:
        problems.append("test-only +0x168 diagnostic is present in a non-diag payload")
    if selftest:
        pass
    elif msi and b"t7000-msi-selftest" in image:
        problems.append("test-only MSI self-test driver is present in a non-selftest payload")

    if bcm:
        for needle in (b"t7000-bcm-probe: ", b"BAR0 window restore"):
            if needle not in image:
                problems.append(f"kernel lacks {needle.decode()!r}")
        # Observation only: the Wi-Fi driver and any firmware loading must be absent.
        for needle in (b"brcmfmac", b"brcm/brcmfmac"):
            if needle in image:
                problems.append(f"kernel contains {needle.decode()!r}: the probe payload must not carry brcmfmac")
    if shadow:
        for needle in (b"t7000-bcm-otp-shadow", b"private, not for Git"):
            if needle not in image:
                problems.append(f"kernel lacks {needle.decode()!r}")
    elif bcm and b"t7000-bcm-otp-shadow" in image:
        problems.append("OTP shadow capture is present in a probe-only payload")
    if not bcm and msi and b"t7000-bcm-probe" in image:
        problems.append("test-only BCM4350 probe is present in a non-probe payload")

    if wifi_base:
        # Public base of the Wi-Fi H1B payload: brcmfmac PCIe built in, no firmware, no supplicant/scan tools,
        # no probe drivers, USB recovery (ECM) intact. The private overlay is added by the local assembler.
        for needle in (b"brcmfmac4350c2-pcie", b"brcmf_pcie", b"brcmfmac"):
            if needle not in image:
                problems.append(f"kernel lacks {needle.decode()!r}: brcmfmac PCIe is not built in")
        for needle in (b"apple-dart-%s", b"t7000-pcie", b"port1_regs"):
            if needle not in image:
                problems.append(f"kernel lacks the 0066 debugfs diagnostics ({needle.decode()!r})")
        if not wifi_raw:
            for needle in (b"t7000-h1b: shared: version", b"t7000-h1b: deep sleep request NOT acknowledged", b"t7000-pcie: DEVICE_WAKE asserted", b"h1b_ds_ack", b"t7000-h1b: chipcommon gpio", b"h1b_apple_shared", b"brcmfmac-h1b", b"h1b_hold", b"h1b_ring_ids", b"ROM reads unlocked", b"h1b_defer_s", b"pci iova model forced", b"h1b_fast_poll_us", b"h1b_step_s", b"bell-only test", b"raw-index alias", b"ios_pte", b"h1b_rxpost", b"h1b_sync_ms", b"h1b_no_bell", b"h1b_apple_init", b"ios_leaf_bits"):
                if needle not in image:
                    problems.append(f"kernel lacks the 0067 toggles ({needle.decode()!r})")
        if b"t7000-h1b: " not in image:
            problems.append("kernel lacks the 0065 H1B diagnostics")
        if b"Falling back to sysfs fallback" in image:
            problems.append("firmware sysfs fallback is still built in (60 s stall on a missing board-suffixed file)")
        wifi_tools = {"wpa_supplicant", "wpa_cli", "hostapd", "iw", "iwctl", "iwd", "NetworkManager", "nmcli", "connmand", "wpa_passphrase"}
        found = sorted(n for n in entries if n.rsplit("/", 1)[-1] in wifi_tools)
        if found:
            problems.append(f"Wi-Fi client/scan tools in the initramfs: {found}")
        fw = sorted(n for n in entries if n.startswith("lib/firmware/brcm/") and n.rsplit("/", 1)[-1].startswith("brcmfmac"))
        if fw:
            problems.append(f"public base must not carry brcmfmac firmware/NVRAM: {fw}")
        if b"t7000-bcm-otp-shadow" in image:
            problems.append("OTP shadow capture must not be in the Wi-Fi payload")
        bootargs = (payload / "bootargs").read_text()
        if "brcmfmac.debug=" not in bootargs:
            problems.append("bootargs lack brcmfmac.debug (the H1B run needs the PCIe/MSGBUF/FWCON log)")
    if msi_extra:
        pcie = [p for p in nodes if p.endswith("pcie@610000000")]
        props = nodes[pcie[0]] if len(pcie) == 1 else {}
        window = props.get("apple,iova-window", b"")
        if len(window) != 16 or struct.unpack(">4I", window) != (0, 0x80000000, 0, 0xBFFFF000):
            problems.append(f"apple,iova-window is {window.hex()}, expected <0 0x80000000 0 0xbffff000>")
        if dma_rebase and "apple,iova-rebase" not in props:
            problems.append("DMA model A requires apple,iova-rebase on the PCIe node")
        if dma_raw and "apple,iova-rebase" in props:
            problems.append("DMA model B (raw) must not carry apple,iova-rebase")
        if b"apple,iova-window" not in image:
            problems.append("kernel lacks the apple,iova-window lookup")
        if b"t7000-bcm-probe" in image or b"t7000-msi-selftest" in image:
            problems.append("DMA payloads must not carry the probe/self-test drivers")

    if problems:
        print("FAIL")
        for p in problems:
            print(" -", p)
        return 1
    print("PASS: checksums, composition, DT phandle (PCIe node only, resolves to D2207),")
    print("      no btattach/I2C tools in the initramfs, board-gated REG_ON strings only")
    if msi:
        print("      one-vector MSI domain declared on the PCIe node (msi-ranges AIC 224 x32); doorbell 0xbffff000")
    elif doorbell:
        print("      clean-up strings only; per-controller MSI doorbell 0xbffff000 on the PCIe node")
    elif clean:
        print("      clean-up strings only (no test-stage log prefixes)")
    elif dllla:
        print("      DLLLA link wait present; the +0x88 bit-6 poll is gone")
    else:
        print("NOTE: the inherited Stage-5F link wait still polls +0x88 bit 6 (technical debt, not a pass/fail signal)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] not in ("--dllla", "--clean", "--doorbell", "--msi", "--msi-selftest", "--msi-diag", "--bcm-probe", "--bcm-shadow", "--dma-rebase", "--dma-raw", "--wifi-h1b-base", "--wifi-h1b-base-raw")):
        sys.exit(__doc__)
    sys.exit(main(sys.argv))

# TEST ONLY (Wi-Fi H1B base): the MSI series (0052-0057), DMA model A (0063 DART window + 0064 Apple rebase) and
# brcmfmac built in with the PCIe bus (CONFIG_BRCMFMAC_PCIE, BRCMDBG) plus 0065 and 0066, read-only DMA/MSI diagnostics, 0068 (firmware console poll, shared-state snapshot), 0069 (read-only ChipCommon GPIO snapshot), 0070 (test toggle: Apple shared-memory parity), 0071 (read-only debugfs query interface and hold toggle), 0072 (ring id/type toggle, safe-register list for core reads), 0073 (RAM snapshot/diff, ARM state, gated ROM reads), 0074 (deferred PCIe driver registration for log streaming), 0075 (drop the unsafe ChipCommon 0xc40/0xe00 reads), 0076 (boot-time override of the DART PCI IOVA model A/B), 0077 (fast firmware-console poll thread), 0078 (pauses between setup phases), 0079 (TCM indices and bell-only tests), 0080 (DART alias mapping at the raw index), 0081 (iOS-style S5L8960X DART entry format), 0082 (split buffer feeding at attach), 0083 (sync sleeps in the attach path), 0084 (skip the host-to-device doorbell toggle), 0085 (Apple DART start-up order and fetch/diag-config toggle), 0086 (DART fault interrupt NULL dereference fix), 0087 (page-table walk on a DART fault), 0088 (extra iOS-format leaf bits toggle), 0089 (J81 PCIe DART options from the device tree, leaf |3 default), 0090 (DT: DART options, wifi0 endpoint node with local-mac-address) and 0067 (boot-argument toggles for the deep-sleep ACK and the DEVICE_WAKE GPIO; both off by default) (0066: debugfs register dumps of the DART and the T7000 port)
# (ring IOVAs and their IOMMU translation, MSI capability while bound, per-interrupt log, ring snapshot at the crash). NO 0060, no probe/self-test drivers. The public base
# payload carries no firmware; the private C2 rieslinga firmware/CLM/TxCap/NVRAM overlay is added locally by
# boot/assemble_private_wifi_payload.py and never enters Git or the Nix store. See research/2026-10-07-wifi-h1b-payload.md.
{ buildLinux
, runCommand
, source
, hoolockConfig
, ...
} @ args:

let
  configuredSource = runCommand "linux-hoolock-pcie-j81-wifi-h1b-t7001-source" {} ''
    mkdir -p "$out"
    cp -R ${source}/. "$out/"
    chmod -R u+w "$out"
    cp ${hoolockConfig} "$out/arch/arm64/configs/ipad_t7001_hoolock_pcie_j81_wifi_h1b_defconfig"

    file="$out/drivers/video/backlight/apple_pmic_bl.c"
    grep -q 'return ((cmd\[1\] & 7) << 8) | (cmd\[0\] & 0xff);' "$file"
    sed -i \
      's/return ((cmd\[1\] \& 7) << 8) | (cmd\[0\] \& 0xff);/&\n\t\tdefault:\n\t\t\treturn -EINVAL;/' \
      "$file"

    patch -d "$out" -p1 < ${./patches/0001-t7001-add-uart3-node.patch}
    patch -d "$out" -p1 < ${./patches/0002-t7001-air2-enable-uart3.patch}
    patch -d "$out" -p1 < ${./patches/0003-serdev-add-stop-bit-selection.patch}
    patch -d "$out" -p1 < ${./patches/0004-add-bq27xxx-hdq-uart-frontend.patch}
    patch -d "$out" -p1 < ${./patches/0005-t7001-add-uart5-node.patch}
    patch -d "$out" -p1 < ${./patches/0006-t7001-air2-enable-uart5-battery.patch}
    patch -d "$out" -p1 < ${./patches/0010-j81-d2207-readonly-charger.patch}
    patch -d "$out" -p1 < ${./patches/0007-spi-apple-add-s5l8960x-support.patch}
    patch -d "$out" -p1 < ${./patches/0008-t7001-add-spi3-node.patch}
    patch -d "$out" -p1 < ${./patches/0009-t7001-air2-enable-spi3.patch}
    patch -d "$out" -p1 < ${./patches/0011-touchscreen-apple-z2-add-j81.patch}
    # J81 base feature set (docs/plans/2026-10-08-j81-base-package.md): writable charger input current limit, needed by the
    # boot-time charging policy that every payload carries. Enforced by kernel/test_j81_base_contract.py.
    patch -d "$out" -p1 < ${./patches/0017-j81-d2207-charger-writable-input-current-limit.patch}

    # Build the known hardware-proven Stage 5F base, then replace its global
    # PMIC search with the J81-only board resource path. Do not stack 0050.
    # This intentionally retains Stage 5F's test-stage link wait; DLLLA,
    # rather than that poll, remains the hardware-proven success signal.
    patch -d "$out" -p1 < ${./patches/0016-pcie-apple-t7000-compile-only-skeleton.patch}
    patch -d "$out" -p1 < ${./patches/0040-pcie-apple-t7000-tuning-baseline-test.patch}
    patch -d "$out" -p1 < ${./patches/0041-pcie-apple-t7000-dbi-ecam-read-test.patch}
    patch -d "$out" -p1 < ${./patches/0042-pcie-apple-t7000-dbi-tunables-write-test.patch}
    patch -d "$out" -p1 < ${./patches/0043-pcie-apple-t7000-link-state-probe-test.patch}
    patch -d "$out" -p1 < ${./patches/0044-pcie-apple-t7000-link-wait-write-test.patch}
    patch -d "$out" -p1 < ${./patches/0045-pcie-apple-t7000-link-speed-write-test.patch}
    patch -d "$out" -p1 < ${./patches/0052-pcie-apple-t7000-j81-reg-on.patch}
    patch -d "$out" -p1 < ${./patches/0053-pcie-apple-t7000-link-wait-dllla.patch}
    patch -d "$out" -p1 < ${./patches/0054-pcie-apple-t7000-clean-up.patch}
    patch -d "$out" -p1 < ${./patches/0055-apple-dart-per-controller-msi-doorbell.patch}
    patch -d "$out" -p1 < ${./patches/0056-pcie-apple-t7000-derive-msi-port-values.patch}
    patch -d "$out" -p1 < ${./patches/0057-pcie-apple-t7000-msi-domain.patch}
    patch -d "$out" -p1 < ${./patches/0063-apple-dart-pci-iova-window.patch}
    patch -d "$out" -p1 < ${./patches/0064-t7001-air2-pcie-iova-rebase.patch}
    patch -d "$out" -p1 < ${./patches/0065-brcmfmac-pcie-h1b-diag.patch}
    patch -d "$out" -p1 < ${./patches/0066-readonly-debugfs-diag-dart-and-t7000-port.patch}
    patch -d "$out" -p1 < ${./patches/0067-j81-wifi-deep-sleep-and-device-wake-toggles.patch}
    patch -d "$out" -p1 < ${./patches/0068-brcmfmac-h1b-console-poll-and-shared-state.patch}
    patch -d "$out" -p1 < ${./patches/0069-brcmfmac-h1b-chipcommon-gpio-snapshot.patch}
    patch -d "$out" -p1 < ${./patches/0070-brcmfmac-h1b-apple-shared-memory-parity.patch}
    patch -d "$out" -p1 < ${./patches/0071-brcmfmac-h1b-readonly-query-interface.patch}
    patch -d "$out" -p1 < ${./patches/0072-brcmfmac-h1b-ring-ids-and-safe-register-reads.patch}
    patch -d "$out" -p1 < ${./patches/0073-brcmfmac-h1b-query-snapshot-arm-and-gated-rom.patch}
    patch -d "$out" -p1 < ${./patches/0074-brcmfmac-h1b-deferred-pcie-registration.patch}
    patch -d "$out" -p1 < ${./patches/0075-brcmfmac-h1b-drop-unsafe-chipcommon-reads.patch}
    patch -d "$out" -p1 < ${./patches/0076-apple-dart-pci-rebase-boot-override.patch}
    patch -d "$out" -p1 < ${./patches/0077-brcmfmac-h1b-fast-console-poll.patch}
    patch -d "$out" -p1 < ${./patches/0078-brcmfmac-h1b-setup-step-pauses.patch}
    patch -d "$out" -p1 < ${./patches/0079-brcmfmac-h1b-tcm-indices-and-bell-only.patch}
    patch -d "$out" -p1 < ${./patches/0080-apple-dart-pci-alias-raw-index-mapping.patch}
    patch -d "$out" -p1 < ${./patches/0081-apple-dart-s5l8960x-ios-pte-format.patch}
    patch -d "$out" -p1 < ${./patches/0082-brcmfmac-h1b-split-buffer-feeding.patch}
    patch -d "$out" -p1 < ${./patches/0083-brcmfmac-h1b-sync-sleeps.patch}
    patch -d "$out" -p1 < ${./patches/0084-brcmfmac-h1b-skip-doorbell.patch}
    patch -d "$out" -p1 < ${./patches/0085-apple-dart-h1b-apple-init-order.patch}
    patch -d "$out" -p1 < ${./patches/0086-apple-dart-s5l8960x-irq-null-cfg.patch}
    patch -d "$out" -p1 < ${./patches/0087-apple-dart-h1b-fault-page-walk.patch}
    patch -d "$out" -p1 < ${./patches/0088-io-pgtable-dart-ios-leaf-bits.patch}
    patch -d "$out" -p1 < ${./patches/0089-apple-dart-j81-options-from-device-tree.patch}
    patch -d "$out" -p1 < ${./patches/0090-t7001-air2-pcie-dart-options-and-wifi-node.patch}
    patch -d "$out" -p1 < ${./patches/0091-bq27xxx-hdq-uart-retry-identification.patch}
    patch -d "$out" -p1 < ${./patches/0092-samsung-tty-apple-s5l-sampling-factor-baud.patch}
    patch -d "$out" -p1 < ${./patches/0093-t7001-air2-serial3-baud-factor-select.patch}
    patch -d "$out" -p1 < ${./patches/0094-brcmfmac-msgbuf-h1b-toggles-only-with-diag.patch}
    patch -d "$out" -p1 < ${./patches/0095-t7001-air2-spi3-touch-spidev-child-disabled.patch}
    patch -d "$out" -p1 < ${./patches/0096-spi-apple-s5l-word-delay.patch}
    patch -d "$out" -p1 < ${./patches/0097-t7001-air2-touch-diag-cs-delays.patch}
    patch -d "$out" -p1 < ${./patches/0098-spi-apple-s5l-do-not-end-large-transfers-after-one-fifo.patch}
    patch -d "$out" -p1 < ${./patches/0099-j81-d2207-charger-vbus-adc-measurement.patch}
    patch -d "$out" -p1 < ${./patches/0100-t7001-spi3-60mhz-functional-clock.patch}
  '';
  buildArgs = builtins.removeAttrs args [ "source" "hoolockConfig" "runCommand" ];
in
buildLinux (buildArgs // {
  version = "7.3.0-rc1";
  modDirVersion = "7.3.0-rc1";
  src = configuredSource;
  defconfig = "ipad_t7001_hoolock_pcie_j81_wifi_h1b_defconfig";
  enableCommonConfig = false;
  autoModules = false;
  ignoreConfigErrors = true;
  buildDTBs = true;
  extraMeta = {
    branch = "hoolock-pcie-j81-wifi-h1b";
    description = "TEST kernel: J81 MSI domain, DMA model A (Apple rebase) and brcmfmac PCIe";
    platforms = [ "aarch64-linux" ];
  };
} // (args.argsOverride or {}))

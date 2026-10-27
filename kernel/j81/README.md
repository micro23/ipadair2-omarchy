# J81 RAM kernel producers

The preserved producer applies pinned Hoolock Linux sources and the exact
ordered iPad NixOS patch recipes. `radio-id` applies 26 patches and has no
wireless driver; `wifi` applies 63 patches and builds the production
brcmfmac/DART/PCIe path. Their union contains 65 patch files. Earlier diagnostic
patches that the production recipe subsequently changes remain part of the
ordered source history; deleting them would change the resulting source.

`configs/baseline.config` is the original input. `configs/radio-id.config`
and `configs/wifi.config` are the **effective** configurations from the
qualified builds, after Kconfig dependency resolution. In particular, the
Wi-Fi effective config requires a signed regulatory database and has
`NF_TABLES` and `NF_TABLES_INET` built in. The requested-config dictionary in
the preserved producer is not a substitute for checking the effective config.

Both variants use 4 KiB pages and disable block devices and raw flash. The
Wi-Fi kernel retains simpleDRM, evdev, uinput, virtual terminals, USB ECM,
basic battery/backlight drivers and the upstream charger driver. No charging
policy is activated by the build scripts.

## Build on Linux x86_64

Requires Python 3.12+, make, GCC/G++, patch and the unpacked AArch64 cross
toolchain layout documented by `reference/toolchain-packages.json`. The
reference toolchain uses Ubuntu GCC 13.3 and binutils 2.42; its manifest records
exact package versions and hashes. System host compiler programs are
`/usr/bin/gcc` and `/usr/bin/g++`. The producer is not a native macOS compiler.

Obtain the Linux archive pinned in
[`provenance/public-inputs.json`](../../provenance/public-inputs.json).
Then run from the repository root with explicit absolute input paths:

```sh
python3 -B kernel/j81/build all \
  --linux-archive /work/inputs/linux-6831bc701a6ce059e71e5aaa9488c9195bea6927.tar.gz \
  --toolchain /work/toolchain \
  --output /work/j81-kernel-build \
  --check-inputs

python3 -B kernel/j81/build all \
  --linux-archive /work/inputs/linux-6831bc701a6ce059e71e5aaa9488c9195bea6927.tar.gz \
  --toolchain /work/toolchain \
  --output /work/j81-kernel-build \
  --jobs 6
```

The output directory must be new or empty and outside the checkout. The
adapter copies unchanged build/verification scripts there and passes every
path explicitly. It never opens a USB device. Products are under
`/work/j81-kernel-build/{radio-id,wifi}/products/`: `Image`,
`t7001-j81.dtb`, and `kernel.config`.

The builder applies GNU patch with zero fuzz. A small number of handcrafted
upstream hunks have an artificial end-of-file constraint; the preserved
fallback requires a unique, complete, exact old-context match and records
its old/new hashes. It does not silently remove context. The verifier checks
the Image/DT contract, reserved MSI doorbell, production IOVA/DART settings,
wifi0 alias and zero MAC placeholder. Existing upstream DT compiler warnings
remain recorded rather than being cosmetically removed.

## Device trees and result identity

`device-tree/` holds **public compiled-tree text references**, not Apple
device trees captured from an iPad. The assembler renames the chosen
framebuffer node as required by the qualified m1n1. The public Wi-Fi DT has
an all-zero local MAC placeholder, which must be populated from the current
owner-device ADT at private boot composition.

`reference/*-products.json` records the original kernel outputs and
`reference/*-source-prepared.json` records the ordered source changes. Their
historical `hardware_tested: false` means compilation had finished before
the physical trials; later qualification is recorded separately at the root.

The new path adapter's preflight and payload reconstruction have been tested.
It has not rerun a full kernel compilation from a clean OS. The preserved
producer and exact inputs previously produced the qualified kernels; another
compiler environment is not assumed to generate byte-identical output.

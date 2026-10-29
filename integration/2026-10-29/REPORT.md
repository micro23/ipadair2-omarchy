# Developer integration validation and fixes — 2026-10-29

The maintainer's requested order was followed: test the ported hardware stack,
then add measured fixes on top. The unchanged developer integration at
`e2b1b591b495ae479951b06c18b99d3c86a0a7a9` booted on the owner's Wi-Fi J81 with
the pinned Hoolock Pongo, kernel `7.3.0-rc1-orchard-apple-4k` and CLI
`158f1da86de6dbe55f1d76b45a53601a98672e33`. Later upstream revisions have not
been silently substituted for that tested baseline.

## Upstream incorporation, verified again for this update

- [Kernel-wheel input fix](https://github.com/OrchardLinux/hardware/commit/0ac1e6d86f0309f5b5871c2329ed0d5bfa66162a): on `main`, credited to micro23.
- [J81 qualification/evidence](https://github.com/OrchardLinux/hardware/commit/a6f033384ee7cd8e87bf78d889a071a62612f39c): on `main`, credited to micro23.
- [Air 2 integration merge](https://github.com/OrchardLinux/hardware/commit/4bf26bac34b2270660ad71eb59c005266dd4f3d2): experimental J81/J82 support merged to `main`.
- [Current upstream device guide](https://github.com/OrchardLinux/hardware/blob/main/docs/integration/j81.md).

PR [OrchardLinux/hardware#27](https://github.com/OrchardLinux/hardware/pull/27)
is closed with its GitHub `merged` flag false. This does **not** mean the work
was discarded: the maintainer incorporated the changes separately, as the
commits above and the PR comments document. The old feature branch is gone.
At this check upstream `main` was `8fecbb6`; the historical local CI-wait state
is no longer the appropriate description of incorporation.

## Measured J81 results

| Check | Evidence |
| --- | --- |
| PCIe/Wi-Fi | `14e4:43a3`, BCM4350; scans, WPA2 association, DHCP and gateway ping passed |
| USB | Device identity/release checks, serial shell and HTTP 200 report retrieval passed |
| Battery | Ten complete property-reading sets passed |
| Display/backlight | Owner saw Linux text; backlight writes read back and original brightness was restored |
| Buttons | 344 raw events / 8256 bytes; Home, Power, Volume Up and Volume Down press/release events present |
| Kernel log | The example's error gate passed; no DART fault/oops claim is being inferred from build success |
| Installed wheel | All 281 selected J81 patches plus series inputs present after the fix; original wheel regression failed, fixed wheel passed |
| Local tests | 68 hardware tests passed; 235 CLI tests passed with separately exported local CLI fixes |

The sanitized original evidence is retained upstream under
[`docs/integration/j81-2026-10-29/`](https://github.com/OrchardLinux/hardware/tree/a6f033384ee7cd8e87bf78d889a071a62612f39c/docs/integration/j81-2026-10-29).
No J82 hardware, charging policy, touch, hardware audio, Bluetooth, suspend or
sustained Wi-Fi throughput qualification is claimed.

## How the observed problems were handled

1. **Wheel omitted layered inputs:** recursive package data now includes all
   nested patches, `kernel/series.py` and platform series files. CI checks the
   actual wheel rather than just the source tree. This fix is upstream.
2. **Buttons falsely reported absent:** timed streaming `hexdump` lost its
   buffered output. Capturing raw `input_event` bytes first showed every button.
   A controlled replay of 96 raw bytes yielded zero streaming output when
   killed before EOF and 288 formatted bytes after EOF.
3. **Pongo source build fails before USB:** retain the proven Hoolock prebuilt.
   The fresh [quiet/normal comparison](../../docs/pongo/COMPARISON.md) shows
   disabling quiet mode alone does not solve it. No root-cause fix is claimed.
4. **USB host-name spelling:** accept the actual underscore product
   `Orchard hardware_check`, not only the example's hyphenated directory name.
5. **Descriptor language query:** explicit serial-descriptor language `0x0409`
   avoids the optional PyUSB LANGID-table failure while retaining strict
   CPID/BDID/ECID/Pongo-version checks. The published helper has identity tests.
6. **Error-gate false positive:** `BUG:` must have a word boundary; a normal
   `printk: debug:` line is not a kernel BUG. The regression test preserves
   rejection of actual BUG/Oops/panic indicators.

The four [patch exports](patches/) preserve the hardware packaging/CI and
separate CLI test fixes. The CLI fixes are not claimed as upstream-merged.
New ANS1 work is isolated under `experimental/`; it changes the kernel baseline
and is not retroactively part of the original integration test.

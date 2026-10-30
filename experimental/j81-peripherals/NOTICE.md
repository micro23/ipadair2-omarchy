# Source and runtime attribution

The local owner-control relay, J81-only input-budget policy, bounded probe,
tests and documentation use the repository's existing host-glue MIT terms.
The register conversions and research references are identified in README.md
and TOUCH-PORT-NOTES.md; no Apple firmware or calibration is copied.

The compiled 0003-spi-apple-add-t7000.patch is authored by Shayne Legault
from OrchardLinux/hardware ae1457edee7d2e52213e4d979aee02dbbeb90ce0. It modifies
the GPL-2.0 Apple SPI driver, preserving Asahi Linux and earlier attribution.
The kernel GPL text is already retained under the repository's LICENSES.
Only the compile-result receipt and pinned upstream reference are included,
not the patch snapshot or compiled module.

Separately obtained runtime projects retain their own terms: noVNC MPL-2.0,
WayVNC ISC, websockify LGPLv3, and Paramiko LGPL. SOURCE-PINS.json records the
selected versions/revision. None of those runtime source trees or binaries is
vendored in this folder. Preserve their upstream notices when assembling a
local runtime or distributing a package.

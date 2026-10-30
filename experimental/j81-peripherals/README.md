# J81 desktop control and conservative USB charging

The owner confirmed working Mac mouse and keyboard control in the local noVNC
viewer on 2026-10-29. The full original Omarchy desktop remains on internal p2.
The working native kernel and storage write fence are unchanged.

The owner workspace has `Start-iPad-Control.command` to reopen control.
The public source requires a local noVNC checkout, its pinned owner-key files
and the source workspace layout; it is not a packaged portable launcher. The iPad must already be in
its native desktop with USB connected. It does not boot or install Linux.
The local viewer listens on Mac localhost only, with a random WebSocket token.
Screen and input travel through a pinned owner-key SSH exec channel to WayVNC
on the iPad's localhost. No SSH forwarding permissions, LAN VNC listener,
remote password login or unauthenticated USB VNC endpoint was enabled.
The current panel is also open in the Codex browser beside the chat.

## Charging measured on this J81

Read-only D2207 observations found input code 2 = 100 mA, USB input suspend clear,
active battery charge code 60 = 3000 mA, hardware maximum 3150 mA, configured
ceiling 3000 mA. The input budget was the useful target; the active battery
charge-current register did not need changing.

A bounded probe advertised 500 mA to the USB host before setting the input
ceiling to 500 mA. The host returned to configured state. At brightness 800/2047,
battery telemetry became positive (+66 mA), and the test restored its original
input code, descriptor and brightness. The retained conservative policy later
reported +110 mA and `Charging` at about31 C with the lower brightness setting.
Telemetry is cached by the gauge driver; repeated identical samples are not
independent measurements. This is slow net charging under this measured load,
not a high-current charger qualification.

`j81-usb-charge.service` keeps a maximum500 mA input allowance only while the USB
host has configured the matching500 mA descriptor and telemetry is within the
conservative temperature/voltage window. It backs off to the original100 mA
otherwise and on stop. It never changes battery charge current/voltage, gauge
NVM, factory storage or the ASP write window. Wall chargers, BC1.2 detection,
Apple high-current negotiation and charger efficiency remain unqualified.
Brightness was left at 800/2047 for net charging; the desktop slider remains
adjustable. Higher screen/CPU load may still discharge at this USB budget.

First-boot package setup fixed: `/var/cache/pacman` and `pkg` needed0755 for
Arch's `alpm` downloader; the packaged Arch ARM signing keyring needed normal
initialization. Required signature checking was kept enabled. Signed packages
added: WayVNC0.10.2-1, neatvnc1.0.3-1, aml1.0.0-1. The owner WayVNC user service
is enabled for later desktop boots. Desktop timezone is America/New_York.

## Physical touch remains a separate driver port

Latest inspected upstream: OrchardLinux/hardware ae1457ed. Its A8/N61 patches
add T7000 legacy SPI FIFO support, a T7000 touch-clock compatible and Gen1
firmware/input handling. These are a more relevant transport reference than
copying the A9/S8003 board configuration.

Our running kernel lacks the T7000 SPI match, and the runtime has no SPI/touch
input device. J81 uses SPI3, GPIO51 chip select, reset82, interrupt84 and a
D2207 analog rail, whereas N61 uses SPI2, different GPIOs and D2186/Chestnut
supplies. J81's N1 firmware personality and per-unit calibration must be supplied
from its own assets. The public J81 research also leaves dedicated touch-clock
resource mapping unresolved; N61's address must not simply be copied.

An isolated compile-only SPI compatibility build passed in
`work/j81-peripheral-candidates/spi`. It is not a loadable replacement for the
already-built-in live SPI driver and is not a touchscreen qualification.
Physical touch, hardware audio, Bluetooth, GPU, suspend and fast charging remain
unfinished. The research/source URLs and exact revisions are recorded in the
public peripheral report. Session tokens, owner keys, screenshots, raw Apple
assets and private logs stay out of public source.


Later desktop activity still produced negative battery current at the500 mA
ceiling. The measured positive idle/dimmed results qualify a low-current input
path, not sustained charging under every workload. Do not describe fast or
wall charging as fixed. See [touch port mapping](TOUCH-PORT-NOTES.md) for the
compiled transport lead and exact missing board resources.

Third-party runtime code is not vendored here: [noVNC](https://github.com/novnc/noVNC)
is MPL-2.0, [WayVNC](https://github.com/any1/wayvnc) is ISC, and
[websockify](https://github.com/novnc/websockify) retains its upstream LGPL terms.
Keep their original licenses when assembling a local runtime. This source
contains no VNC/SSH session tokens, firmware, captured calibration or owner keys.

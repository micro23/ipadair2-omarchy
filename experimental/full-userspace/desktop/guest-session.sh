
set -eu
D=@@D@@
mount -t nfs -o ro,vers=3,proto=tcp,nolock,soft,timeo=10,retrans=1 172.16.42.2:/Volumes/J81_OMARCHY_A_V011/rootfs "$D/lower"
mount -t tmpfs -o size=384m,nosuid tmpfs "$D/ram"
mkdir "$D/ram/upper" "$D/ram/work"
mount -t overlay overlay -o lowerdir="$D/lower",upperdir="$D/ram/upper",workdir="$D/ram/work" "$D/root"
R="$D/root"
for x in dev proc sys run tmp; do mkdir -p "$R/$x"; done
mount -t tmpfs -o size=1m,nosuid,noexec tmpfs "$R/dev"
mkdir "$R/dev/dri" "$R/dev/input" "$R/dev/pts" "$R/dev/shm"
mount -t tmpfs -o size=64m,mode=1777,nosuid,nodev tmpfs "$R/dev/shm"
mknod "$R/dev/null" c 1 3; chmod 666 "$R/dev/null"
mknod "$R/dev/zero" c 1 5; chmod 666 "$R/dev/zero"
mknod "$R/dev/random" c 1 8; mknod "$R/dev/urandom" c 1 9
mknod "$R/dev/tty" c 5 0; mknod "$R/dev/console" c 5 1
mknod "$R/dev/tty0" c 4 0; mknod "$R/dev/tty1" c 4 1
mknod "$R/dev/dri/card0" c 226 0
mknod "$R/dev/input/event0" c 13 64
mount -t devpts -o newinstance,ptmxmode=0666,mode=0620 devpts "$R/dev/pts"
ln -s pts/ptmx "$R/dev/ptmx"
ln -s /proc/self/fd "$R/dev/fd"
mount --bind /proc "$R/proc"
mount --bind /sys "$R/sys"
mount -o remount,bind,ro "$R/sys"
mount -t tmpfs -o size=16m,nosuid,nodev tmpfs "$R/run"
mount -t tmpfs -o size=32m,nosuid,nodev tmpfs "$R/tmp"
mkdir -p "$R/run/j81-demo" "$R/run/j81-config"
chmod 700 "$R/run/j81-demo"
chroot "$R" /usr/bin/dbus-uuidgen > "$R/etc/machine-id"
chmod 644 "$R/etc/machine-id"
mkdir -p "$R/var/lib/dbus"
ln -sf /etc/machine-id "$R/var/lib/dbus/machine-id"
cat > "$R/run/j81-config/rc.xml" <<'XML'
<?xml version="1.0"?><labwc_config><core><gap>20</gap></core><theme><name>Default</name></theme></labwc_config>
XML
cat > "$R/run/j81-client" <<'CLIENT'
#!/bin/sh
set -eu
chown 1000:1000 /run/j81-demo /run/j81-demo/wayland-0
exec /usr/bin/setpriv --reuid=1000 --regid=1000 --init-groups --reset-env /usr/bin/env XDG_RUNTIME_DIR=/run/j81-demo WAYLAND_DISPLAY=wayland-0 XDG_CURRENT_DESKTOP=labwc XDG_SESSION_TYPE=wayland QT_QPA_PLATFORM=wayland QT_QUICK_BACKEND=software LIBGL_ALWAYS_SOFTWARE=1 OMARCHY_TOUCH_MODE=1 OMARCHY_PATH=/home/tablet/.local/share/omarchy-ipad PATH=/usr/local/bin:/usr/bin LANG=C.UTF-8 /usr/bin/dbus-run-session -- /bin/bash -c '
  /usr/local/libexec/arch-ipad-first-theme
  mkdir -p /home/tablet/.cache/j81-firefox-test
  pipewire > /run/j81-demo/pipewire.log 2>&1 </dev/null &
  wireplumber > /run/j81-demo/wireplumber.log 2>&1 </dev/null &
  exec /usr/bin/quickshell -p /home/tablet/.local/share/omarchy-ipad/shell/shell.qml
' > /run/j81-demo/ui.log 2>&1
CLIENT
chmod 755 "$R/run/j81-client"
SEATD_VTBOUND=0 chroot "$R" /usr/bin/seatd -l debug > "$D/seatd.log" 2>&1 &
seat=$!
for n in 1 2 3 4 5 6 7 8 9 10; do [ ! -S "$R/run/seatd.sock" ] || break; sleep 1; done
[ -S "$R/run/seatd.sock" ] || { echo J81_ERROR_SEATD; exit 40; }
echo J81_SEATD_READY
set +e
XDG_RUNTIME_DIR=/run/j81-demo XDG_CONFIG_HOME=/run/j81-config LIBSEAT_BACKEND=seatd SEATD_SOCK=/run/seatd.sock WLR_BACKENDS=drm,libinput WLR_RENDERER=pixman WLR_NO_HARDWARE_CURSORS=1 WLR_DRM_DEVICES=/dev/dri/card0 WLR_LIBINPUT_NO_DEVICES=1 timeout -s TERM 540 chroot "$R" /usr/bin/labwc -C /run/j81-config -d -s /run/j81-client > "$D/labwc.log" 2>&1
rc=$?
printf 'J81_LABWC_STATUS=%s\n' "$rc"
kill "$seat" 2>/dev/null
wait "$seat" 2>/dev/null
exit 0

#!/bin/busybox sh
# J81 native-root handoff. The installer mounts /newroot separately.
# This script never loads ASP, widens a write range, formats or edits a GPT.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mode=${1:---check}
serial_open=0
case "$mode" in --check|--handoff) ;; *) exit 64 ;; esac
if [ "$mode" = --handoff ] && [ "$$" -ne 1 ]; then
    echo 'J81: only global PID 1 may hand off the root' >&2
    exit 65
fi
fail() {
    echo "J81 native-root refusal: $*" >&2
    if [ "$mode" = --handoff ]; then
        # Keep the RAM diagnostic environment alive after a preflight refusal.
        while :; do
            if [ "$serial_open" -eq 1 ]; then
                setsid -c sh -i <&9 >&9 2>&9 || true
            else
                setsid -c sh -i </dev/ttyGS0 >/dev/ttyGS0 2>&1 || true
            fi
            sleep 1
        done
    fi
    exit 1
}
config=/etc/j81-native-root.conf
[ -f "$config" ] && [ ! -L "$config" ] || fail 'native-root policy absent'
[ "$(stat -c %u "$config")" = 0 ] || fail 'policy is not owned by root'
permissions=$(stat -c %a "$config")
case "$permissions" in 400|600) ;; *) fail 'policy permissions must be 0400 or 0600' ;; esac
value() {
    result=$(sed -n "s/^$1=//p" "$config")
    [ -n "$result" ] && [ "$(printf '%s\n' "$result" | wc -l)" -eq 1 ] || return 1
    printf '%s' "$result"
}
device=$(value ROOT_DEVICE) || fail 'missing or duplicate root device'
uuid=$(value ROOT_UUID) || fail 'missing or duplicate root UUID'
release=$(value KERNEL_RELEASE) || fail 'missing or duplicate kernel release'
first=$(value FIRST_LBA) || fail 'missing or duplicate first LBA'
count=$(value LBA_COUNT) || fail 'missing or duplicate LBA count'
module_hash=$(value ASP_MODULE_SHA256) || fail 'missing or duplicate module digest'
case "$device" in /dev/asp0n1p1|/dev/asp0n1p2) ;; *) fail 'unexpected root device' ;; esac
printf '%s\n' "$uuid" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || fail 'invalid root UUID'
printf '%s\n' "$module_hash" | grep -Eq '^[0-9a-f]{64}$' || fail 'invalid module digest'
[ "$module_hash" = 3e36f4b045a38ba4eeb46cce3a24a9d19955568b5831cd37e4124b5d6d6961f9 ] || fail 'unqualified ASP module policy'
case "$first:$count" in *[!0-9:]*|:*|*:) fail 'invalid write extent' ;; esac
[ "$release" = '7.3.0-rc1-orchard-j81-storage-ro-v2mod' ] || fail 'unqualified kernel policy'
[ "$(uname -r)" = "$release" ] || fail 'running kernel mismatch'
tr '\000' '\n' </proc/device-tree/compatible | grep -Fxq apple,j81 || fail 'wrong board'
tr '\000' '\n' </proc/device-tree/compatible | grep -Fxq apple,t7001 || fail 'wrong SoC'
[ -b "$device" ] || fail 'native-root partition absent'
block=${device##*/}
[ "$(cat /sys/class/block/asp0n1/queue/logical_block_size)" = 4096 ] || fail 'unexpected logical sector size'
[ "$(cat /sys/class/block/asp0n1/size)" = 125000000 ] || fail 'USERAREA capacity changed'
start=$(cat /sys/class/block/"$block"/start)
size=$(cat /sys/class/block/"$block"/size)
[ "$((start % 8))" -eq 0 ] && [ "$((size % 8))" -eq 0 ] || fail 'unaligned partition'
[ "$first" -eq "$((start / 8))" ] && [ "$count" -eq "$((size / 8))" ] || fail 'policy differs from partition'
[ "$count" -gt 0 ] && [ "$first" -ge 6 ] && [ "$((first + count - 1))" -le 15624994 ] || fail 'root overlaps GPT metadata'
[ "$(cat /sys/module/asp/parameters/allow_userarea_writes)" = Y ] || fail 'ASP write mode absent'
[ "$(cat /sys/module/asp/parameters/write_first_lba)" = "$first" ] || fail 'ASP first LBA differs'
[ "$(cat /sys/module/asp/parameters/write_lba_count)" = "$count" ] || fail 'ASP range differs'
[ "$(cat /sys/class/block/asp0n1/ro)" = 0 ] || fail 'USERAREA read-only'
for n in 2 3 4 5 6 7 8 9 10; do
    [ "$(cat /sys/class/block/asp0n$n/ro)" = 1 ] || fail 'auxiliary namespace writable'
done
[ "$(/usr/bin/blkid -s UUID -o value "$device")" = "$uuid" ] || fail 'filesystem UUID mismatch'
awk -v dev="$device" '$1 == dev && $2 == "/newroot" && $3 == "ext4" && $4 ~ /(^|,)(rw|ro)(,|$)/ {ok=1} END {exit !ok}' /proc/mounts || fail 'expected native ext4 root is not mounted'
for dir in proc sys dev run; do
    [ -d "/newroot/$dir" ] && [ ! -L "/newroot/$dir" ] || fail 'root mountpoint missing or symlinked'
done
[ -x /newroot/usr/lib/systemd/systemd ] || fail 'systemd absent'
[ -f /newroot/etc/j81/internal-root.conf ] && [ ! -L /newroot/etc/j81/internal-root.conf ] || fail 'installed identity absent'
grep -Fxq "ROOT_UUID=$uuid" /newroot/etc/j81/internal-root.conf || fail 'installed UUID policy differs'
grep -Fxq "KERNEL_RELEASE=$release" /newroot/etc/j81/internal-root.conf || fail 'installed kernel policy differs'
grep -Fxq "ROOT_DEVICE=$device" /newroot/etc/j81/internal-root.conf || fail 'installed root-device policy differs'
actual=$(sha256sum "/newroot/lib/modules/$release/kernel/drivers/block/asp.ko")
[ "${actual%% *}" = "$module_hash" ] || fail 'installed ASP module differs'
# A released root normally has an empty /dev before the real mount moves.
# Supply the current device tree only for this version check, then retire it.
if awk '$2 == "/newroot/dev" {found=1} END {exit !found}' /proc/mounts; then
    fail 'installer left a temporary /newroot/dev mount attached'
fi
mount -o bind /dev /newroot/dev || fail 'cannot prepare native systemd device access'
native_status=0
chroot /newroot /usr/lib/systemd/systemd --version >/dev/null || native_status=$?
umount /newroot/dev || fail 'cannot retire temporary native device access'
[ "$native_status" -eq 0 ] || fail 'native systemd cannot execute'
echo 'J81: native ext4 root, UUID, kernel, ASP fence and systemd preflight passed'
[ "$mode" = --handoff ] || exit 0
cd /
exec 9<>/dev/ttyGS0
serial_open=1
exec </dev/console >/dev/console 2>&1
sync
for dir in proc sys dev run; do
    mount -o move "/$dir" "/newroot/$dir" || fail "could not move $dir; use the retained serial shell to recover"
done
exec switch_root /newroot /usr/lib/systemd/systemd

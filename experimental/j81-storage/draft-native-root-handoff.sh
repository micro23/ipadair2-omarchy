#!/bin/busybox sh
# J81 native-root handoff. The installer mounts /newroot separately.
# This script never loads ASP, widens a write range, formats or edits a GPT.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mode=${1:---check}
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
            setsid -c sh -i </dev/ttyGS0 >/dev/ttyGS0 2>&1 || true
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
    [ "$(printf '%s\n' "$result" | wc -l)" -eq 1 ] || fail 'duplicate policy key'
    printf '%s' "$result"
}
device=$(value ROOT_DEVICE)
uuid=$(value ROOT_UUID)
release=$(value KERNEL_RELEASE)
first=$(value FIRST_LBA)
count=$(value LBA_COUNT)
module_hash=$(value ASP_MODULE_SHA256)
case "$device" in /dev/asp0n1p1|/dev/asp0n1p2) ;; *) fail 'unexpected root device' ;; esac
printf '%s\n' "$uuid" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || fail 'invalid root UUID'
printf '%s\n' "$module_hash" | grep -Eq '^[0-9a-f]{64}$' || fail 'invalid module digest'
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
[ "$(blkid -s UUID -o value "$device")" = "$uuid" ] || fail 'filesystem UUID mismatch'
awk -v dev="$device" '$1 == dev && $2 == "/newroot" && $3 == "ext4" && $4 ~ /(^|,)rw(,|$)/ {ok=1} END {exit !ok}' /proc/mounts || fail 'expected ext4 root is not mounted read-write'
for dir in proc sys dev run; do
    [ -d "/newroot/$dir" ] && [ ! -L "/newroot/$dir" ] || fail 'root mountpoint missing or symlinked'
done
[ -x /newroot/usr/lib/systemd/systemd ] || fail 'systemd absent'
[ -f /newroot/etc/j81/internal-root.conf ] && [ ! -L /newroot/etc/j81/internal-root.conf ] || fail 'installed identity absent'
grep -Fxq "ROOT_UUID=$uuid" /newroot/etc/j81/internal-root.conf || fail 'installed UUID policy differs'
grep -Fxq "KERNEL_RELEASE=$release" /newroot/etc/j81/internal-root.conf || fail 'installed kernel policy differs'
actual=$(sha256sum "/newroot/lib/modules/$release/kernel/drivers/block/asp.ko")
[ "${actual%% *}" = "$module_hash" ] || fail 'installed ASP module differs'
# Confirm the native loader and complete systemd library closure before moves.
chroot /newroot /usr/lib/systemd/systemd --version >/dev/null || fail 'native systemd cannot execute'
echo 'J81: native ext4 root, UUID, kernel, ASP fence and systemd preflight passed'
[ "$mode" = --handoff ] || exit 0
cd /
exec </dev/console >/dev/console 2>&1
sync
for dir in proc sys dev run; do
    mount -o move "/$dir" "/newroot/$dir"
done
exec switch_root /newroot /usr/lib/systemd/systemd

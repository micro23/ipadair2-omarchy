#!/bin/busybox sh
# Post-install cold-boot stage. Never formats, resizes or edits a GPT.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
fail() { echo "J81 native boot refusal: $*" >&2; exit 1; }
config=/etc/j81-native-root.conf
[ -f "$config" ] && [ ! -L "$config" ] && [ "$(stat -c %u "$config")" = 0 ] && [ "$(stat -c %a "$config")" = 600 ] || fail 'untrusted policy'
value() {
    result=$(sed -n "s/^$1=//p" "$config")
    [ -n "$result" ] && [ "$(printf '%s\n' "$result" | wc -l)" -eq 1 ] || return 1
    printf '%s' "$result"
}
[ "$(value ROOT_DEVICE)" = /dev/asp0n1p2 ] || fail 'unexpected root device'
[ "$(value KERNEL_RELEASE)" = 7.3.0-rc1-orchard-j81-storage-ro-v2mod ] || fail 'unqualified kernel policy'
[ "$(uname -r)" = "$(value KERNEL_RELEASE)" ] || fail 'wrong running kernel'
tr '\000' '\n' </proc/device-tree/compatible | grep -Fxq apple,j81 || fail 'wrong board'
tr '\000' '\n' </proc/device-tree/compatible | grep -Fxq apple,t7001 || fail 'wrong SoC'
[ "$(value FIRST_LBA)" = 4194816 ] && [ "$(value LBA_COUNT)" = 11429888 ] || fail 'unexpected partition extent'
uuid=$(value ROOT_UUID)
printf '%s\n' "$uuid" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || fail 'invalid root UUID'
[ ! -d /sys/module/asp ] || fail 'ASP was already loaded; no reconfiguration attempted'
module=/lib/modules/7.3.0-rc1-orchard-j81-storage-ro-v2mod/kernel/drivers/block/asp.ko
hash=$(sha256sum "$module")
[ "${hash%% *}" = 3e36f4b045a38ba4eeb46cce3a24a9d19955568b5831cd37e4124b5d6d6961f9 ] || fail 'unqualified ASP module'
timeout 45 modprobe asp allow_userarea_writes=1 write_first_lba=4194816 write_lba_count=11429888 || fail 'ASP probe failed'
i=0
while [ ! -b /dev/asp0n1p2 ] || [ ! -e /sys/class/block/asp0n10/ro ]; do
    i=$((i+1)); [ "$i" -lt 30 ] || fail 'partition discovery timed out'
    sleep 1
done
[ "$(cat /sys/class/block/asp0n1/size)" = 125000000 ] && [ "$(cat /sys/class/block/asp0n1/queue/logical_block_size)" = 4096 ] || fail 'capacity or sector size differs'
[ "$(cat /sys/class/block/asp0n1p2/start)" = 33558528 ] && [ "$(cat /sys/class/block/asp0n1p2/size)" = 91439104 ] || fail 'Linux partition geometry differs'
[ "$(cat /sys/module/asp/parameters/write_first_lba)" = 4194816 ] && [ "$(cat /sys/module/asp/parameters/write_lba_count)" = 11429888 ] || fail 'write fence differs'
for n in 2 3 4 5 6 7 8 9 10; do
    [ "$(cat /sys/class/block/asp0n$n/ro)" = 1 ] || fail 'auxiliary namespace writable'
done
mkdir -p /run/j81 /newroot
for copy in primary backup; do
    case "$copy" in primary) lba=1; field=GPT_PRIMARY_SHA256;; backup) lba=15624995; field=GPT_BACKUP_SHA256;; esac
    timeout 20 dd if=/dev/asp0n1 of=/run/j81/gpt-"$copy" bs=4096 skip="$lba" count=5 2>/dev/null || fail 'GPT read failed'
    actual=$(sha256sum /run/j81/gpt-"$copy")
    [ "${actual%% *}" = "$(value "$field")" ] || fail 'GPT differs from installed layout'
done
[ "$(/usr/bin/blkid -s TYPE -o value /dev/asp0n1p2)" = ext4 ] || fail 'root is not ext4'
[ "$(/usr/bin/blkid -s UUID -o value /dev/asp0n1p2)" = "$uuid" ] || fail 'root UUID differs'
# Let real PID 1 perform its normal root fsck/remount before the root guard.
mount -t ext4 -o ro,noatime,nodiscard /dev/asp0n1p2 /newroot || fail 'native root mount failed'

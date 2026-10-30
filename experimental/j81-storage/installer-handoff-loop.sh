# Appended to the known-working diagnostic setup. ASP remains deferred.
# The host installer may request handoff only after installing /newroot.
mkdir -p /run/j81
while :; do
    setsid -c sh -i </dev/ttyGS0 >/dev/ttyGS0 2>&1 &
    serial_pid=$!
    while kill -0 "$serial_pid" 2>/dev/null; do
        if [ -f /run/j81/handoff.ready ]; then
            rm -f /run/j81/handoff.ready
            if /sbin/j81-native-handoff --check >/run/j81/handoff-check.log 2>&1; then
                # Stop only children launched by this init, never broad killall.
                kill "$serial_pid" 2>/dev/null || true
                wait "$serial_pid" 2>/dev/null || true
                kill "$dhcp_pid" "$http_pid" 2>/dev/null || true
                wait "$dhcp_pid" "$http_pid" 2>/dev/null || true
                exec /sbin/j81-native-handoff --handoff
            else
                echo 'J81: native-root preflight refused; serial shell remains available.' >/dev/ttyGS0
            fi
        fi
        sleep 1
    done
    wait "$serial_pid" 2>/dev/null || true
    sleep 1
done

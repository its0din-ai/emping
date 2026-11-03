#!/usr/bin/env bash
#
# Root-only security smoke tests for emping.
#
# Run from the repository root:
#   cargo build --release
#   sudo TARGET_USER="$USER" ./contrib/security/run.sh
#
# The script creates temporary services under /tmp, sends malformed socket
# requests and forged ICMP traffic, races concurrent starts, and checks symlink
# resistance. It never touches the default /run/emping service.
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
EMPING=${EMPING:-$ROOT/target/release/emping}
TARGET_USER=${TARGET_USER:-${SUDO_USER:-}}
BASE=/tmp/emping-security-$$
SOCK=$BASE.sock
PID=$BASE.pid
LOG=$BASE.log
EVENTS=$BASE.events
CLIENT_ERR=$BASE.client.err
PASS=0
FAIL=0
CLIENT_PID=

if [ "$(id -u)" -ne 0 ]; then
    echo "run this script as root (it needs CAP_NET_RAW and service management)" >&2
    exit 2
fi
if [ ! -x "$EMPING" ]; then
    echo "emping binary not found: $EMPING" >&2
    exit 2
fi

mkdir -p "$BASE"

stop_service() {
    local socket=$1
    local pids

    "$EMPING" stop --socket "$socket" >/dev/null 2>&1 || true
    sleep 0.2
    pids=$(pgrep -f "emping daemon.*--socket $socket" 2>/dev/null || true)
    if [ -n "$pids" ]; then
        kill $pids 2>/dev/null || true
    fi
}

cleanup() {
    if [ -n "${CLIENT_PID:-}" ]; then
        kill "$CLIENT_PID" >/dev/null 2>&1 || true
    fi
    stop_service "$SOCK"
    if [ -n "$TARGET_USER" ] && command -v runuser >/dev/null 2>&1; then
        runuser -u "$TARGET_USER" -- "$EMPING" stop --socket "$BASE.user.sock" >/dev/null 2>&1 || true
        pids=$(pgrep -f "emping daemon.*--socket $BASE.user.sock" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            kill $pids 2>/dev/null || true
        fi
    fi
    rm -f "$SOCK" "$PID" "$LOG" "$EVENTS" "$CLIENT_ERR" "$SOCK.lock" \
        "$BASE.user.sock" "$BASE.user.pid" "$BASE.user.log" "$BASE.user.sock.lock" \
        "$BASE/target"
    rm -rf "$BASE"
    setcap -r "$EMPING" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ok() {
    PASS=$((PASS + 1))
    echo "PASS: $*"
}

bad() {
    FAIL=$((FAIL + 1))
    echo "FAIL: $*"
}

check_eq() {
    label=$1
    expected=$2
    actual=$3
    if [ "$expected" = "$actual" ]; then
        ok "$label ($actual)"
    else
        bad "$label (expected $expected, got $actual)"
    fi
}

count_unique_requests() {
    grep '"event":"echo_request"' "$1" 2>/dev/null | grep -c '"duplicate":false' || true
}

echo "== service lifecycle and permissions =="
"$EMPING" start -i lo --ipv6 --socket "$SOCK" --pid-file "$PID" --log-file "$LOG" >"$BASE/start.out" 2>&1
RC=$?
check_eq "start exit" 0 "$RC"

"$EMPING" status --socket "$SOCK" >/dev/null 2>&1
RC=$?
check_eq "status exit" 0 "$RC"
check_eq "socket mode" 600 "$(stat -c %a "$SOCK" 2>/dev/null || echo missing)"
check_eq "pid mode" 644 "$(stat -c %a "$PID" 2>/dev/null || echo missing)"
check_eq "log mode" 640 "$(stat -c %a "$LOG" 2>/dev/null || echo missing)"
check_eq "lock mode" 600 "$(stat -c %a "$SOCK.lock" 2>/dev/null || echo missing)"

echo "== malformed Unix-socket input =="
python3 "$SCRIPT_DIR/socket_fuzz.py" "$SOCK"
RC=$?
check_eq "socket fuzz exit" 0 "$RC"
"$EMPING" status --socket "$SOCK" >/dev/null 2>&1
RC=$?
check_eq "service alive after socket fuzz" 0 "$RC"

echo "== forged ICMP traffic =="
"$EMPING" --json --socket "$SOCK" >"$EVENTS" 2>"$CLIENT_ERR" &
CLIENT_PID=$!
sleep 0.7
python3 "$SCRIPT_DIR/forge_packets.py"
RC=$?
check_eq "packet forge exit" 0 "$RC"
sleep 1
"$EMPING" status --socket "$SOCK" >/dev/null 2>&1
RC=$?
check_eq "service alive after packet forge" 0 "$RC"
kill "$CLIENT_PID" >/dev/null 2>&1 || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=

if grep -Eiq 'panic|backtrace|segmentation|double free' "$LOG" "$CLIENT_ERR" "$EVENTS"; then
    bad "crash signature found in logs"
else
    ok "no crash signatures in logs"
fi
echo "observed event lines: $(grep -c '"event":' "$EVENTS" 2>/dev/null || echo 0)"
echo "ipv6 event lines: $(grep -c '::1' "$EVENTS" 2>/dev/null || echo 0)"

echo "== flood limiter =="
"$EMPING" --json --socket "$SOCK" >"$BASE/flood.limited" 2>"$BASE/flood.limited.err" &
CLIENT_PID=$!
sleep 0.5
python3 "$SCRIPT_DIR/flood_test.py"
sleep 1
kill "$CLIENT_PID" >/dev/null 2>&1 || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=
check_eq "limited echo_request events" 15 "$(count_unique_requests "$BASE/flood.limited")"
check_eq "limited flood events" 1 "$(grep -c '"event":"flood_skipped"' "$BASE/flood.limited" 2>/dev/null || true)"
"$EMPING" status --socket "$SOCK" >/dev/null 2>&1
RC=$?
check_eq "service alive after limited flood" 0 "$RC"

"$EMPING" stop --socket "$SOCK" >/dev/null 2>&1
"$EMPING" start -i lo --socket "$SOCK" --pid-file "$PID" --log-file "$LOG" --no-limit \
    >"$BASE/flood.unlimited.start" 2>&1
RC=$?
check_eq "no-limit start exit" 0 "$RC"
"$EMPING" --json --socket "$SOCK" >"$BASE/flood.unlimited" 2>"$BASE/flood.unlimited.err" &
CLIENT_PID=$!
sleep 0.5
python3 "$SCRIPT_DIR/flood_test.py"
sleep 1
kill "$CLIENT_PID" >/dev/null 2>&1 || true
wait "$CLIENT_PID" 2>/dev/null || true
CLIENT_PID=
check_eq "no-limit echo_request events" 20 "$(count_unique_requests "$BASE/flood.unlimited")"
check_eq "no-limit flood events" 0 "$(grep -c '"event":"flood_skipped"' "$BASE/flood.unlimited" 2>/dev/null || true)"

echo "== concurrent start race with stale socket =="
stop_service "$SOCK"
python3 - "$SOCK" <<'PY'
import socket
import sys

value = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
value.bind(sys.argv[1])
value.close()
PY
for index in 1 2 3 4 5 6 7 8; do
    "$EMPING" start -i lo --ipv6 --socket "$SOCK" --pid-file "$PID" --log-file "$LOG" \
        >"$BASE/race.$index" 2>&1 &
done
wait
sleep 0.5
DAEMONS=$(pgrep -f "emping daemon.*--socket $SOCK" 2>/dev/null | wc -l)
check_eq "daemon count after concurrent start" 1 "$DAEMONS"
"$EMPING" status --socket "$SOCK" >/dev/null 2>&1
RC=$?
check_eq "status after concurrent start" 0 "$RC"
"$EMPING" stop --socket "$SOCK" >/dev/null 2>&1
RC=$?
check_eq "stop after concurrent start" 0 "$RC"
if [ ! -e "$SOCK" ]; then
    ok "socket removed"
else
    bad "socket still exists"
fi

echo "== symlink resistance =="
echo "sentinel" >"$BASE/target"
ln -s "$BASE/target" "$SOCK"
"$EMPING" start -i lo --socket "$SOCK" --pid-file "$PID" --log-file "$LOG" \
    >"$BASE/symlink.socket" 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
    ok "socket symlink rejected (exit $RC)"
else
    bad "socket symlink was accepted"
fi
check_eq "socket symlink target unchanged" "sentinel" "$(cat "$BASE/target")"
rm -f "$SOCK" "$SOCK.lock"

ln -s "$BASE/target" "$SOCK.lock"
"$EMPING" start -i lo --socket "$SOCK" --pid-file "$PID" --log-file "$LOG" \
    >"$BASE/symlink.lock" 2>&1
RC=$?
if [ "$RC" -ne 0 ]; then
    ok "lock symlink rejected (exit $RC)"
else
    bad "lock symlink was accepted"
fi
check_eq "lock symlink target unchanged" "sentinel" "$(cat "$BASE/target")"
rm -f "$SOCK" "$SOCK.lock"

echo "== non-root service with file capability =="
if [ -n "$TARGET_USER" ] && [ "$TARGET_USER" != "root" ] && command -v runuser >/dev/null 2>&1 && command -v setcap >/dev/null 2>&1; then
    if setcap cap_net_raw=eip "$EMPING" 2>/dev/null; then
        runuser -u "$TARGET_USER" -- "$EMPING" start -i lo \
            --socket "$BASE.user.sock" --pid-file "$BASE.user.pid" --log-file "$BASE.user.log" \
            >"$BASE/user.start" 2>&1
        RC=$?
        check_eq "non-root start" 0 "$RC"
        runuser -u "$TARGET_USER" -- "$EMPING" status --socket "$BASE.user.sock" >/dev/null 2>&1
        RC=$?
        check_eq "non-root status" 0 "$RC"
        check_eq "non-root socket mode" 600 "$(stat -c %a "$BASE.user.sock" 2>/dev/null || echo missing)"
        check_eq "non-root socket owner" "$TARGET_USER" "$(stat -c %U "$BASE.user.sock" 2>/dev/null || echo missing)"
        runuser -u "$TARGET_USER" -- "$EMPING" stop --socket "$BASE.user.sock" >/dev/null 2>&1
        RC=$?
        check_eq "non-root stop" 0 "$RC"
        setcap -r "$EMPING"
    else
        echo "SKIP: setcap unavailable"
    fi
else
    echo "SKIP: TARGET_USER or runuser/setcap unavailable"
fi

echo "== summary =="
echo "passed: $PASS"
echo "failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi

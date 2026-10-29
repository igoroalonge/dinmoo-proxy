#!/bin/sh
# Verify restart ordering and pin rotation without touching a desktop application.
set -eu
binary=${1:?Pass an absolute path to the CLI binary}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
export DINMOO_RESTART_TEST_DIR="$test_dir"
unset DINMOO_VOICE_IDENTITY_DIR
mkdir "$test_dir/bin"
mkdir -p "$test_dir/home/Applications/Discord.app/Contents/MacOS"
# Another user's Discord can be neither signalled nor waited for, so both tools
# must match only this user's processes.
cat >"$test_dir/bin/pkill" <<'SH'
#!/bin/sh
[ "$*" = "-U $(id -u) -x Discord" ] || { echo "unexpected pkill arguments: $*" >&2; exit 2; }
printf 'stop\n' >>"$DINMOO_RESTART_TEST_DIR/events"
printf '0\n' >"$DINMOO_RESTART_TEST_DIR/count"
SH
cat >"$test_dir/bin/pgrep" <<'SH'
#!/bin/sh
[ "$*" = "-U $(id -u) -x Discord" ] || { echo "unexpected pgrep arguments: $*" >&2; exit 2; }
if [ "${DINMOO_RESTART_TEST_ERROR:-}" = yes ]; then exit 2; fi
count=$(cat "$DINMOO_RESTART_TEST_DIR/count")
count=$((count + 1))
printf '%s\n' "$count" >"$DINMOO_RESTART_TEST_DIR/count"
[ "$count" -lt 3 ]
SH
cat >"$test_dir/home/Applications/Discord.app/Contents/MacOS/Discord" <<'SH'
#!/bin/sh
[ "$(cat "$DINMOO_RESTART_TEST_DIR/count")" -ge 3 ] || exit 99
printf 'launch\n' >>"$DINMOO_RESTART_TEST_DIR/events"
printf '%s\n' "$@" >"$DINMOO_RESTART_TEST_DIR/launch"
SH
chmod 755 "$test_dir/bin/"* "$test_dir/home/Applications/Discord.app/Contents/MacOS/Discord"
export HOME="$test_dir/home"
export PATH="$test_dir/bin:$PATH"
fail() {
    echo "FAIL: $*" >&2
    [ ! -e "$test_dir/events" ] || sed 's/^/  event: /' "$test_dir/events" >&2
    exit 1
}
wait_for_launch() {
    for attempt in $(seq 50); do
        [ ! -e "$test_dir/launch" ] || return 0
        sleep 0.1
    done
    fail 'Discord was not launched'
}
assert_before() {
    first=$(grep -n -x -m1 -- "$1" "$test_dir/events" | cut -d: -f1)
    second=$(grep -n -x -m1 -- "$2" "$test_dir/events" | cut -d: -f1)
    [ -n "$first" ] && [ -n "$second" ] && [ "$first" -lt "$second" ] || fail "expected '$1' before '$2'"
}
pin() {
    grep -- '--ignore-certificate-errors-spki-list=' "$test_dir/launch" || fail 'Discord launch has no voice pin'
}
"$binary" discord
wait_for_launch
grep -q -- '--proxy-server=socks5://127.0.0.1:1080' "$test_dir/launch"
grep -q -- '--force-webrtc-ip-handling-policy=disable_non_proxied_udp' "$test_dir/launch"
if grep -q -- '--host-resolver-rules=' "$test_dir/launch"; then
    echo 'FAIL: Discord launch overrides the host resolver' >&2
    exit 1
fi
assert_before stop launch
first_pin=$(pin)
rm "$test_dir/launch" "$test_dir/events"
"$binary" discord
wait_for_launch
assert_before stop launch
second_pin=$(pin)
[ "$second_pin" != "$first_pin" ] || fail 'consecutive Discord launches reused the voice pin'
rm "$test_dir/launch"
if DINMOO_RESTART_TEST_ERROR=yes "$binary" discord 2>"$test_dir/error"; then
    echo 'FAIL: a process-inspection error was ignored' >&2
    exit 1
fi
[ ! -e "$test_dir/launch" ]
grep -q 'could not check whether Discord has exited' "$test_dir/error"

# A voice identity that cannot rotate must not leave Discord stopped.
voice="$HOME/.config/dinmoo-proxy/voice"
chmod 755 "$voice"
rm -f "$test_dir/events"
if "$binary" discord 2>"$test_dir/error"; then
    fail 'discord ignored a voice identity error'
fi
wait_for_launch
assert_before stop launch
grep -q 'voice identity directory must have mode 0700' "$test_dir/error" || fail 'identity error not reported'
if grep -q -e '--proxy-server=' -e '--ignore-certificate-errors-spki-list=' "$test_dir/launch"; then
    fail 'Discord was relaunched through the proxy after the identity failed to rotate'
fi
chmod 700 "$voice"
rm "$test_dir/launch"

# A Discord carrying the pin must be gone before the client releases its port.
cat >"$test_dir/bin/launchctl" <<'SH'
#!/bin/sh
printf 'launchctl %s\n' "$1" >>"$DINMOO_RESTART_TEST_DIR/events"
[ "$1" != "${DINMOO_RESTART_TEST_LAUNCHCTL_FAIL:-}" ] || exit 5
SH
chmod 755 "$test_dir/bin/launchctl"
plist="$HOME/Library/LaunchAgents/com.dinmoo.proxy.plist"
mkdir -p "$HOME/Library/LaunchAgents"
: >"$plist"
rm -f "$test_dir/events"
if DINMOO_RESTART_TEST_ERROR=yes "$binary" off 2>"$test_dir/error"; then
    fail 'off ignored a process-inspection error'
fi
if grep -q '^launch' "$test_dir/events"; then
    fail 'off changed the client or launched Discord before Discord exited'
fi
rm -f "$test_dir/events"
"$binary" off
wait_for_launch
assert_before stop 'launchctl disable'
assert_before 'launchctl bootout' launch
if grep -q -- '--ignore-certificate-errors-spki-list=' "$test_dir/launch"; then
    fail 'off relaunched Discord with the voice pin'
fi
rm "$test_dir/launch" "$test_dir/events"
# A client that cannot be stopped must not be reported as removed.
if DINMOO_RESTART_TEST_LAUNCHCTL_FAIL=bootout "$binary" uninstall >"$test_dir/output" 2>&1; then
    fail 'uninstall ignored a failed launchctl bootout'
fi
wait_for_launch
! grep -q 'Removed' "$test_dir/output" || fail 'uninstall reported removal while the client kept running'
[ -e "$plist" ] || fail 'uninstall removed the launch agent of a client it could not stop'
rm "$test_dir/launch" "$test_dir/events"
"$binary" uninstall >/dev/null
wait_for_launch
assert_before stop 'launchctl bootout'
assert_before 'launchctl bootout' launch
[ ! -e "$plist" ] || fail 'uninstall left the launch agent'
echo 'PASS: Discord exit is awaited before launch; each launch rotates the pin; process errors prevent relaunch; a failed rotation relaunches Discord directly'
echo 'PASS: off and uninstall stop Discord before the client and relaunch it directly; a client that cannot be stopped is not reported removed'

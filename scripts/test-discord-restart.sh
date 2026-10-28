#!/bin/sh
# Verify restart ordering without touching a desktop application.
set -eu
binary=${1:?Pass an absolute path to the CLI binary}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
export DINMOO_RESTART_TEST_DIR="$test_dir"
mkdir "$test_dir/bin"
mkdir -p "$test_dir/home/Applications/Discord.app/Contents/MacOS"
cat >"$test_dir/bin/pkill" <<'SH'
#!/bin/sh
printf '0\n' >"$DINMOO_RESTART_TEST_DIR/count"
SH
cat >"$test_dir/bin/pgrep" <<'SH'
#!/bin/sh
if [ "${DINMOO_RESTART_TEST_ERROR:-}" = yes ]; then exit 2; fi
count=$(cat "$DINMOO_RESTART_TEST_DIR/count")
count=$((count + 1))
printf '%s\n' "$count" >"$DINMOO_RESTART_TEST_DIR/count"
[ "$count" -lt 3 ]
SH
cat >"$test_dir/home/Applications/Discord.app/Contents/MacOS/Discord" <<'SH'
#!/bin/sh
[ "$(cat "$DINMOO_RESTART_TEST_DIR/count")" -ge 3 ] || exit 99
printf '%s\n' "$@" >"$DINMOO_RESTART_TEST_DIR/launch"
SH
chmod 755 "$test_dir/bin/"* "$test_dir/home/Applications/Discord.app/Contents/MacOS/Discord"
export HOME="$test_dir/home"
export PATH="$test_dir/bin:$PATH"
"$binary" discord
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ ! -e "$test_dir/launch" ] || break
    sleep 0.1
done
grep -q -- '--proxy-server=socks5://127.0.0.1:1080' "$test_dir/launch"
grep -q -- '--force-webrtc-ip-handling-policy=disable_non_proxied_udp' "$test_dir/launch"
if grep -q -- '--host-resolver-rules=' "$test_dir/launch"; then
    echo 'FAIL: Discord launch overrides the host resolver' >&2
    exit 1
fi
rm "$test_dir/launch"
if DINMOO_RESTART_TEST_ERROR=yes "$binary" discord 2>"$test_dir/error"; then
    echo 'FAIL: a process-inspection error was ignored' >&2
    exit 1
fi
[ ! -e "$test_dir/launch" ]
grep -q 'could not check whether Discord has exited' "$test_dir/error"
echo 'PASS: Discord exit is awaited before launch; process errors prevent relaunch'

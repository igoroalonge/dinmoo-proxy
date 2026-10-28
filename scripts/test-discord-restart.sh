#!/bin/sh
# Verify restart ordering without touching a desktop application.
set -eu
binary=${1:?Pass an absolute path to the CLI binary}
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
export DINMOO_RESTART_TEST_DIR="$test_dir"
mkdir "$test_dir/bin"
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
cat >"$test_dir/bin/open" <<'SH'
#!/bin/sh
[ "$(cat "$DINMOO_RESTART_TEST_DIR/count")" -ge 3 ] || exit 99
printf '%s\n' "$@" >"$DINMOO_RESTART_TEST_DIR/launch"
SH
cp "$test_dir/bin/open" "$test_dir/bin/discord"
chmod 755 "$test_dir/bin/"*
export PATH="$test_dir/bin:$PATH"
"$binary" discord
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    [ ! -e "$test_dir/launch" ] || break
    sleep 0.1
done
grep -q -- '--proxy-server=socks5://127.0.0.1:1080' "$test_dir/launch"
grep -q -- '--force-webrtc-ip-handling-policy=disable_non_proxied_udp' "$test_dir/launch"
rm "$test_dir/launch"
if DINMOO_RESTART_TEST_ERROR=yes "$binary" discord; then
    echo 'FAIL: a process-inspection error was ignored' >&2
    exit 1
fi
[ ! -e "$test_dir/launch" ]
echo 'PASS: Discord exit is awaited before launch; process errors prevent relaunch'

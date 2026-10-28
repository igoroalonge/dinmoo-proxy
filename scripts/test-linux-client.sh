#!/bin/sh
set -eu
binary=${1:?Pass the absolute path to the Linux CLI binary}
[ ! -e "$HOME/.config/systemd/user/dinmoo-proxy.service" ]
[ ! -e "$HOME/.config/dinmoo-proxy" ]
[ ! -e "$HOME/.local/bin/dinmoo-proxy" ]
work=$(mktemp -d /tmp/dinmoo-lifecycle.XXXXXX)
cleanup() {
 systemctl --user disable --now dinmoo-proxy.service >/dev/null 2>&1 || true
 rm -f "$HOME/.config/systemd/user/dinmoo-proxy.service" "$HOME/.config/dinmoo-proxy/client.env"
 rmdir "$HOME/.config/dinmoo-proxy" 2>/dev/null || true
 systemctl --user daemon-reload
 rm -rf "$work"
}
trap cleanup EXIT
mkdir "$work/bin"
printf '#!/bin/sh\necho "Headless Discord launch stub"\n' >"$work/bin/discord"
printf '#!/bin/sh\nexit 0\n' >"$work/bin/pkill"
chmod 755 "$work/bin/discord" "$work/bin/pkill"
export PATH="$work/bin:$PATH"
"$binary" install-local
"$binary" status | grep 'proxy is on'
"$binary" off
"$binary" status | grep 'proxy is off'
if systemctl --user is-enabled --quiet dinmoo-proxy.service; then echo 'FAIL: off left startup enabled'; exit 1; fi
"$binary" on
"$binary" status | grep 'proxy is on'
"$binary" uninstall
[ ! -e "$HOME/.config/systemd/user/dinmoo-proxy.service" ]
[ ! -e "$HOME/.config/dinmoo-proxy/client.env" ]
echo 'PASS: Linux systemd user client install, status, off, on, and uninstall against live gateway; Discord launches stubbed'

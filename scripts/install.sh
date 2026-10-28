#!/bin/sh
set -eu
os=$(uname -s); arch=$(uname -m)
case "$os" in Darwin) os=macos;; Linux) os=linux;; *) echo "Unsupported OS: $os" >&2; exit 1;; esac
case "$arch" in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=aarch64;; *) echo "Unsupported architecture: $arch" >&2; exit 1;; esac
key="$os-$arch"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT HUP INT TERM
base='https://github.com/igoroalonge/dinmoo-proxy/releases/latest/download'
name="dinmoo-proxy-$key"
curl --fail --silent --show-error --location --max-redirs 10 --proto '=https' --proto-redir '=https' --max-filesize 1048576 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
expected=$(awk -v name="$name" '$2 == name { print $1 }' "$tmp/SHA256SUMS")
[ "${#expected}" = 64 ] || { echo 'Missing or invalid asset checksum' >&2; exit 1; }
case "$expected" in *[!0-9a-f]*) echo 'Invalid asset checksum' >&2; exit 1;; esac
url="$base/$name"
curl --fail --silent --show-error --location --max-redirs 10 --proto '=https' --proto-redir '=https' --tlsv1.2 --max-filesize 52428800 "$url" -o "$tmp/dinmoo-proxy"
[ "$(wc -c < "$tmp/dinmoo-proxy")" -le 52428800 ] || { echo 'Binary exceeds 50 MiB' >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$tmp/dinmoo-proxy" | cut -d' ' -f1); else actual=$(shasum -a 256 "$tmp/dinmoo-proxy" | cut -d' ' -f1); fi
[ "$actual" = "$expected" ] || { echo 'Binary checksum mismatch' >&2; exit 1; }
bin="$HOME/.local/bin"; mkdir -p "$bin"; install -m 755 "$tmp/dinmoo-proxy" "$bin/dinmoo-proxy"
path_line='export PATH="$HOME/.local/bin:$PATH"'
profile="$HOME/.profile"
case "${SHELL:-}" in */zsh) profile="$HOME/.zshrc";; */bash) profile="$HOME/.bashrc";; esac
touch "$profile"
if ! grep -Fqx "$path_line" "$profile"; then printf '\n%s\n' "$path_line" >> "$profile"; fi
echo 'Installed dinmoo-proxy. Open a new terminal to use: dinmoo-proxy on | off | status | uninstall'
exec "$bin/dinmoo-proxy" install-local

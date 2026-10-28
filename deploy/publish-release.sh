#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <release-assets-directory> <release-tag>" >&2
    exit 2
fi

assets_dir=$1
tag=$2
web_root=${DINMOO_WEB_ROOT:-/srv/dinmoo-proxy}
manifest="$assets_dir/latest.json"

case "$tag" in
    v[0-9]*) ;;
    *) echo "Invalid release tag: $tag" >&2; exit 2 ;;
esac
case "$tag" in
    *[!A-Za-z0-9._-]*) echo "Invalid release tag: $tag" >&2; exit 2 ;;
esac
[ -d "$assets_dir" ] || { echo "Assets directory not found: $assets_dir" >&2; exit 1; }
[ -f "$manifest" ] || { echo "Release manifest not found: $manifest" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }

releases="$web_root/releases"
mkdir -p "$releases"
mkdir -p "$web_root/scripts"
target="$releases/$tag"
[ ! -e "$target" ] || { echo "Refusing to replace published release: $target" >&2; exit 1; }
stage=$(mktemp -d "$releases/.${tag}.XXXXXX")
latest_tmp=$(mktemp "$releases/.latest.XXXXXX")
cleanup() {
    rm -rf "$stage"
    rm -f "$latest_tmp"
}
trap cleanup EXIT HUP INT TERM

python3 - "$manifest" "$tag" <<'PY' > "$stage/assets.tsv"
import json, pathlib, re, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
tag = sys.argv[2]
assets = manifest.get('assets')
if not isinstance(assets, dict) or not assets:
    raise SystemExit('manifest has no assets')
required = {f'{os}-{arch}' for os in ('linux', 'macos', 'windows') for arch in ('x86_64', 'aarch64')}
if set(assets) != required:
    raise SystemExit(f'manifest platform set mismatch: expected {sorted(required)}')
for key, asset in sorted(assets.items()):
    if not re.fullmatch(r'(linux|macos|windows)-(x86_64|aarch64)', key):
        raise SystemExit(f'invalid platform key: {key}')
    name = f'dinmoo-proxy-{key}' + ('.exe' if key.startswith('windows-') else '')
    expected = f'https://github.com/igoroalonge/dinmoo-proxy/releases/download/{tag}/{name}'
    if not isinstance(asset, dict) or asset.get('url') != expected:
        raise SystemExit(f'unexpected URL for {key}; expected {expected}')
    digest = asset.get('sha256', '')
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise SystemExit(f'invalid SHA-256 for {key}')
    print(f'{name}\t{digest}')
PY

while IFS="$(printf '\t')" read -r name expected; do
    [ -n "$name" ] || continue
    source="$assets_dir/$name"
    [ -f "$source" ] || { echo "Missing release asset: $source" >&2; exit 1; }
    actual=$(sha256sum "$source" | cut -d ' ' -f 1)
    [ "$actual" = "$expected" ] || { echo "Checksum mismatch: $name" >&2; exit 1; }
    cp "$source" "$stage/$name"
done < "$stage/assets.tsv"

rm "$stage/assets.tsv"
cp "$manifest" "$stage/latest.json"
mv "$stage" "$target"
install -m 0644 "$(dirname "$0")/../scripts/install.sh" "$web_root/scripts/install.sh"
install -m 0644 "$(dirname "$0")/../scripts/install.ps1" "$web_root/scripts/install.ps1"
cp "$manifest" "$latest_tmp"
mv -f "$latest_tmp" "$releases/latest.json"
echo "Published immutable $tag under $target and updated $releases/latest.json"

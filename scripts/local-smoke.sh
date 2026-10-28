#!/bin/sh
set -eu

repo_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
gateway_port=${DINMOO_LOCAL_GATEWAY_PORT:-18443}
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/dinmoo-proxy-smoke.XXXXXX")
gateway_pid=
client_pid=

cleanup() {
    if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
    if [ -n "$gateway_pid" ]; then kill "$gateway_pid" 2>/dev/null || true; wait "$gateway_pid" 2>/dev/null || true; fi
    rm -rf "$test_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

command -v openssl >/dev/null 2>&1 || { echo "openssl is required" >&2; exit 1; }
cargo build --offline --manifest-path "$repo_root/Cargo.toml" --bin dinmoo-proxy
binary="$repo_root/target/debug/dinmoo-proxy"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$test_dir/ca-key.pem" -out "$test_dir/ca.pem" \
    -subj '/CN=Dinmoo disposable test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes \
    -keyout "$test_dir/key.pem" -out "$test_dir/server.csr" \
    -subj '/CN=127.0.0.1' >/dev/null 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'subjectAltName=IP:127.0.0.1' 'extendedKeyUsage=serverAuth' >"$test_dir/extensions"
openssl x509 -req -in "$test_dir/server.csr" -CA "$test_dir/ca.pem" \
    -CAkey "$test_dir/ca-key.pem" -CAcreateserial -days 1 \
    -extfile "$test_dir/extensions" -out "$test_dir/cert.pem" >/dev/null 2>&1
openssl x509 -in "$test_dir/cert.pem" -outform DER -out "$test_dir/cert.der"
openssl x509 -in "$test_dir/ca.pem" -outform DER -out "$test_dir/ca.der"
openssl pkcs8 -topk8 -nocrypt -in "$test_dir/key.pem" -outform DER -out "$test_dir/key.der"
token=$(openssl rand -hex 32)
chmod 600 "$test_dir/key.pem" "$test_dir/key.der"

export DINMOO_PROXY_TOKEN=$token
export DINMOO_TLS_CERT_DER="$test_dir/cert.der"
export DINMOO_TLS_KEY_DER="$test_dir/key.der"
export DINMOO_TLS_ROOT_DER="$test_dir/ca.der"

"$binary" gateway "127.0.0.1:$gateway_port" >"$test_dir/gateway.log" 2>&1 &
gateway_pid=$!
"$binary" client 127.0.0.1:1080 "127.0.0.1:$gateway_port" >"$test_dir/client.log" 2>&1 &
client_pid=$!

if "$binary" check; then
    echo "PASS: local client, TLS-authenticated gateway, and SOCKS route to discord.com:443 work."
else
    echo "FAIL: local proxy smoke test failed." >&2
    echo "Gateway log:" >&2
    cat "$test_dir/gateway.log" >&2
    echo "Client log:" >&2
    cat "$test_dir/client.log" >&2
    exit 1
fi

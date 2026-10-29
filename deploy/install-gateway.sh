#!/bin/sh
# Use - as token-file for public access.
# Run as root: sh install-gateway.sh <linux-binary> <token-file> <systemd-unit>
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root' >&2; exit 1; }
[ "$#" = 3 ] || { echo 'Expected binary, token file, and systemd unit' >&2; exit 2; }
binary=$1
token_file=$2
unit=$3
cert=/etc/letsencrypt/live/api-proxy.dinmoo.com
test -s "$cert/fullchain.pem"
id dinmoo-proxy >/dev/null 2>&1 || useradd --system --home /var/lib/dinmoo-proxy --create-home --shell /usr/sbin/nologin dinmoo-proxy
install -d -m 750 -o root -g dinmoo-proxy /etc/dinmoo-proxy
install -m 755 "$binary" /usr/local/bin/dinmoo-proxy.new
/usr/local/bin/dinmoo-proxy.new --help >/dev/null
mv /usr/local/bin/dinmoo-proxy.new /usr/local/bin/dinmoo-proxy
python3 - "$token_file" <<'PY'
import os, pathlib, re, sys
token = '' if sys.argv[1] == '-' else pathlib.Path(sys.argv[1]).read_text().strip()
if token and not re.fullmatch(r'[A-Za-z0-9_-]{32,1024}', token):
    raise SystemExit('Invalid token')
path = pathlib.Path('/etc/dinmoo-proxy/gateway.env')
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as file:
    file.write(f'DINMOO_PROXY_TOKEN={token}\nDINMOO_TLS_CERT_DER=/etc/dinmoo-proxy/chain-0.der,/etc/dinmoo-proxy/chain-1.der\nDINMOO_TLS_KEY_DER=/etc/dinmoo-proxy/private-key.der\nDINMOO_MAX_SESSIONS=256\nDINMOO_MAX_SESSIONS_PER_IP=16\nDINMOO_CONNECTIONS_PER_IP_PER_MINUTE=120\nDINMOO_IDLE_TIMEOUT_SECS=600\nDINMOO_ADMIN_SOCKET=/run/dinmoo-proxy/admin.sock\n')
PY
install -m 644 "$unit" /etc/systemd/system/dinmoo-proxy-gateway.service
mkdir -p /etc/systemd/system/dinmoo-proxy-gateway.service.d
cat >/etc/systemd/system/dinmoo-proxy-gateway.service.d/direct-tls.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/dinmoo-proxy gateway 0.0.0.0:443
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
MemoryMax=128M
TasksMax=128
LimitNOFILE=8192
EOF
mkdir -p /etc/letsencrypt/renewal-hooks/pre /etc/letsencrypt/renewal-hooks/post /etc/letsencrypt/renewal-hooks/deploy
cat >/etc/letsencrypt/renewal-hooks/deploy/dinmoo-certificates <<'EOF'
#!/bin/sh
set -eu
python3 - <<'PY'
import grp, os, pathlib, re, subprocess, tempfile
source = pathlib.Path('/etc/letsencrypt/live/api-proxy.dinmoo.com')
destination = pathlib.Path('/etc/dinmoo-proxy')
certificates = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', (source / 'fullchain.pem').read_bytes(), re.S)
if not 1 <= len(certificates) <= 10:
    raise SystemExit('Invalid certificate chain length')
gid = grp.getgrnam('dinmoo-proxy').gr_gid
for index, certificate in enumerate(certificates):
    der = subprocess.run(['openssl', 'x509', '-outform', 'DER'], input=certificate, check=True, capture_output=True).stdout
    path = destination / f'chain-{index}.der'
    path.write_bytes(der)
    os.chmod(path, 0o640)
    os.chown(path, 0, gid)
with tempfile.NamedTemporaryFile(dir=destination, delete=False) as temporary:
    path = pathlib.Path(temporary.name)
try:
    subprocess.run(['openssl', 'pkcs8', '-topk8', '-nocrypt', '-in', str(source / 'privkey.pem'), '-outform', 'DER', '-out', str(path)], check=True)
    os.chmod(path, 0o640)
    os.chown(path, 0, gid)
    os.replace(path, destination / 'private-key.der')
finally:
    path.unlink(missing_ok=True)
environment = destination / 'gateway.env'
lines = [line for line in environment.read_text().splitlines() if not line.startswith('DINMOO_TLS_CERT_DER=')]
lines.append('DINMOO_TLS_CERT_DER=' + ','.join(str(destination / f'chain-{index}.der') for index in range(len(certificates))))
environment.write_text('\n'.join(lines) + '\n')
PY
systemctl try-restart dinmoo-proxy-gateway.service
EOF
cat >/etc/letsencrypt/renewal-hooks/pre/dinmoo-http <<'EOF'
#!/bin/sh
set -eu
ufw allow 80/tcp >/dev/null
EOF
cat >/etc/letsencrypt/renewal-hooks/post/dinmoo-http <<'EOF'
#!/bin/sh
set -eu
ufw --force delete allow 80/tcp >/dev/null
EOF
chmod 750 /etc/letsencrypt/renewal-hooks/deploy/dinmoo-certificates /etc/letsencrypt/renewal-hooks/pre/dinmoo-http /etc/letsencrypt/renewal-hooks/post/dinmoo-http
systemctl daemon-reload
/etc/letsencrypt/renewal-hooks/deploy/dinmoo-certificates
ufw allow 9022/tcp
ufw allow 443/tcp
ufw --force delete allow 80/tcp
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
systemctl enable --now dinmoo-proxy-gateway.service
systemctl is-active dinmoo-proxy-gateway.service

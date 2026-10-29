#!/usr/bin/env python3
"""Isolated VM UDP smoke test. --keep holds the tunnel for native testing."""
import argparse
import io
import ipaddress
import os
from pathlib import Path
import socket
import re
import struct
import subprocess
import tarfile
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent
SSH_OPTIONS = ["-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
               "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes",
               "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2"]


def discover_media():
    targets = []
    directory = Path.home()/"Library/Application Support/discord/logs"
    for name in ["discord-webrtc_1", "discord-webrtc_0"]:
        try:
            with (directory/name).open("rb") as stream:
                stream.seek(0, 2)
                stream.seek(max(0, stream.tell()-512*1024))
                text = stream.read(512*1024).decode(errors="replace")
        except FileNotFoundError:
            continue
        pattern = r"\((?:voice_connection\.cpp:\d+\): Create connection to|udp_socket\.cpp:\d+\): Sending ping to) ([0-9.]+:\d+)"
        for endpoint in re.findall(pattern, text):
            ip, port = endpoint.rsplit(":", 1)
            try:
                if not ipaddress.ip_address(ip).is_global or not 0 < int(port) <= 65535:
                    continue
            except ValueError:
                continue
            if endpoint in targets:
                targets.remove(endpoint)
            targets.append(endpoint)
            targets = targets[-64:]
    return ",".join(targets)


def sync_media(ssh, host, remote, targets):
    subprocess.run(ssh+[host, f"umask 077; cat > {remote}/media.targets.new && mv {remote}/media.targets.new {remote}/media.targets"],
                   input=targets.encode(), check=True, timeout=15)


def exact(stream, size):
    data = b""
    while len(data) < size:
        chunk = stream.recv(size-len(data))
        if not chunk:
            raise RuntimeError("SOCKS connection closed")
        data += chunk
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--host", required=True, help="SSH destination, such as root@test-vm.example.com")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--identity", default="~/.ssh/id_ed25519", help="SSH private key path")
    args = parser.parse_args()
    ssh = ["ssh", "-p", str(args.port), "-i", str(Path(args.identity).expanduser())] + SSH_OPTIONS
    host = args.host
    remote = "/tmp/dinmoo-media-" + uuid.uuid4().hex
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        for source, name in [
            (ROOT/"target/x86_64-unknown-linux-musl/release/dinmoo-proxy", "gateway"),
            (ROOT/"crates/proxy/tests/fixtures/localhost-cert.der", "cert.der"),
            (ROOT/"crates/proxy/tests/fixtures/localhost-key.der", "key.der"),
        ]:
            tar.add(source, arcname=name)
        echo = b'''import socket,select
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("138.186.9.192",0))
d=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
d.bind(("138.186.9.192",0))
with open("echo.target","w") as f: f.write("%s:%s" % s.getsockname())
with open("echo.denied","w") as f: f.write("%s:%s" % d.getsockname())
while True:
 for sock in select.select([s,d],[],[])[0]:
  data,peer=sock.recvfrom(2048)
  sock.sendto(data,peer)
'''
        info = tarfile.TarInfo("echo.py")
        info.size = len(echo)
        tar.addfile(info, io.BytesIO(echo))
    subprocess.run(ssh+[host, f"umask 077; mkdir {remote}; tar -xzf - -C {remote}"],
                   input=archive.getvalue(), check=True)
    current_media = discover_media()
    sync_media(ssh, host, remote, current_media)
    command = f'''set -eu
cd {remote}
python3 echo.py &
echo_pid=$!
gateway_pid=
trap 'kill "$echo_pid" ${{gateway_pid:-}} 2>/dev/null || true' EXIT HUP INT TERM
for attempt in $(seq 1 50); do test -s echo.target && break; sleep 0.1; done
export DINMOO_MEDIA_TARGETS="$(cat echo.target)"
export DINMOO_MEDIA_TARGETS_FILE="$PWD/media.targets"
export DINMOO_TLS_CERT_DER="$PWD/cert.der"
export DINMOO_TLS_KEY_DER="$PWD/key.der"
export DINMOO_MAX_SESSIONS=64
export DINMOO_VOICE_TRACE=1
./gateway gateway 127.0.0.1:18446 >gateway.log 2>&1 &
gateway_pid=$!
echo "ECHO $(cat echo.target) $(cat echo.denied)"
cat >/dev/null
'''
    ssh_process = subprocess.Popen(ssh+["-L", "127.0.0.1:18446:127.0.0.1:18446", host, command],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    client = None
    try:
        announcement = ssh_process.stdout.readline().strip()
        if not announcement.startswith("ECHO "):
            raise RuntimeError("VM test gateway did not start")
        target, denied_target = announcement[5:].split()
        env = os.environ.copy()
        env.pop("DINMOO_PROXY_TOKEN", None)
        env["DINMOO_TLS_ROOT_DER"] = str(ROOT/"crates/proxy/tests/fixtures/test-ca.der")
        log = tempfile.TemporaryFile()
        client = subprocess.Popen([str(ROOT/"target/release/dinmoo-proxy"), "client",
                                   "127.0.0.1:11080", "localhost:18446"], env=env,
                                  stdout=log, stderr=log)
        for attempt in range(50):
            try:
                control = socket.create_connection(("127.0.0.1",11080), timeout=3)
                break
            except OSError:
                if client.poll() is not None:
                    raise RuntimeError("local test client exited")
                time.sleep(0.1)
        else:
            raise RuntimeError("local test listener unavailable")
        with control:
            control.sendall(bytes([5,1,0]))
            assert exact(control,2) == bytes([5,0])
            control.sendall(bytes([5,3,0,1,0,0,0,0,0,0]))
            reply = exact(control,10)
            assert reply[:4] == bytes([5,0,0,1]), reply
            relay = (socket.inet_ntoa(reply[4:8]),struct.unpack("!H",reply[8:])[0])
            ip,port = target.rsplit(":",1)
            header = bytes([0,0,0,1])+socket.inet_aton(ip)+struct.pack("!H",int(port))
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                udp.settimeout(5)
                for index in range(64):
                    udp.sendto(header+struct.pack("!I",index)+b"x"*996,relay)
                seen = set()
                while len(seen) < 64:
                    packet,source = udp.recvfrom(2048)
                    assert source == relay and packet[:10] == header
                    assert packet[14:] == b"x"*996
                    seen.add(struct.unpack("!I",packet[10:14])[0])
                assert seen == set(range(64))
                denied_ip, denied_port = denied_target.rsplit(":",1)
                denied_header = bytes([0,0,0,1])+socket.inet_aton(denied_ip)+struct.pack("!H",int(denied_port))
                udp.settimeout(0.75)
                udp.sendto(denied_header+b"must-not-reach-other-ports",relay)
                try:
                    udp.recvfrom(2048)
                except socket.timeout:
                    pass
                else:
                    raise RuntimeError("Gateway accepted an unapproved UDP port")
        print("PASS: 64 x 1000-byte UDP payloads round-tripped through local SOCKS, TLS, and the isolated VM gateway.", flush=True)
        print("PASS: a second live UDP echo port on the same IP was denied.", flush=True)
        if args.keep:
            print("Native test command:\nsudo env DINMOO_MEDIA_SOCKS=127.0.0.1:11080 "
                  + str(ROOT/"target/release/dinmoo-proxy")+" media --watch '"+str(Path.home()/"Library/Application Support/discord/logs")+"'", flush=True)
            print("Reconnect the Discord call/stream after starting it. Ctrl-C stops this isolated test.",flush=True)
            while ssh_process.poll() is None:
                discovered = discover_media()
                if discovered != current_media:
                    try:
                        sync_media(ssh, host, remote, discovered)
                    except (subprocess.SubprocessError, OSError) as error:
                        print(f"Media grant update failed; will retry: {error}",flush=True)
                    else:
                        current_media = discovered
                        print(f"Updated test gateway media grants ({len(discovered.split(',')) if discovered else 0} endpoints)",flush=True)
                time.sleep(1)
    finally:
        if client:
            client.terminate()
            client.wait(timeout=5)
        ssh_process.stdin.close()
        try:
            ssh_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ssh_process.terminate()
            ssh_process.wait(timeout=5)


if __name__ == "__main__":
    main()

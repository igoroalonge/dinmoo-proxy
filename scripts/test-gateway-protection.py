#!/usr/bin/env python3
"""Exercise the real gateway's admission and idle cleanup on loopback only."""
import contextlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / 'target/debug/dinmoo-proxy'
FIXTURES = ROOT / 'crates/proxy/tests/fixtures'
CONTEXT = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert((FIXTURES / 'test-ca.der').read_bytes()))
# The existing test CA omits AKI; retain chain, hostname and validity checks.
CONTEXT.verify_flags &= ~ssl.VERIFY_X509_STRICT


@contextlib.contextmanager
def gateway(per_ip, rate, idle, admin_path=None):
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    environment = {key: value for key, value in os.environ.items() if not key.startswith('DINMOO_')}
    environment.update({
        'DINMOO_TLS_CERT_DER': str(FIXTURES / 'localhost-cert.der'),
        'DINMOO_TLS_KEY_DER': str(FIXTURES / 'localhost-key.der'),
        'DINMOO_MAX_SESSIONS': '6',
        'DINMOO_MAX_SESSIONS_PER_IP': str(per_ip),
        'DINMOO_CONNECTIONS_PER_IP_PER_MINUTE': str(rate),
        'DINMOO_IDLE_TIMEOUT_SECS': str(idle),
    })
    if admin_path is not None:
        environment['DINMOO_ADMIN_SOCKET'] = str(admin_path)
    with tempfile.TemporaryDirectory(prefix='dinmoo-protection-') as directory:
        log_path = Path(directory) / 'gateway.log'
        with log_path.open('w') as log:
            process = subprocess.Popen([str(BINARY), 'gateway', f'127.0.0.1:{port}'], env=environment, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while 'gateway listening on' not in log_path.read_text():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(f'gateway did not start: {log_path.read_text()}')
                    time.sleep(0.02)
                yield port, log_path
                assert process.poll() is None, 'gateway exited during protection checks'
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def exact(stream, count):
    result = b''
    while len(result) < count:
        chunk = stream.recv(count - len(result))
        assert chunk, 'gateway closed unexpectedly'
        result += chunk
    return result


def connect(port):
    raw = socket.create_connection(('127.0.0.1', port), timeout=3)
    try:
        stream = CONTEXT.wrap_socket(raw, server_hostname='localhost')
    except BaseException:
        raw.close()
        raise
    try:
        stream.sendall(b'DMPX\x01\x00\x00')
        assert exact(stream, 1) == b'\x01'
        return stream
    except BaseException:
        stream.close()
        raise


def rejected_before_tls(port):
    try:
        with connect(port):
            raise AssertionError('over-limit connection was admitted')
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
        return
    raise AssertionError('connection was not rejected before TLS')


with gateway(per_ip=1, rate=120, idle=1) as (port, log_path):
    with connect(port) as first:
        first.sendall(b'\x05\x01\x00')
        assert exact(first, 2) == b'\x05\x00'
        first.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        assert exact(first, 10)[:2] == b'\x05\x00'
        rejected_before_tls(port)
        assert first.recv(1) == b'', 'idle UDP association remained open'
    # Allow the session task to finish dropping its admission permit.
    time.sleep(0.05)
    with connect(port):
        pass
    print('PASS: per-IP cap rejects before TLS; idle UDP cleanup releases the slot')
    time.sleep(0.05)
    # Idle timeouts and closes without TLS close_notify are routine, not per-connection log lines.
    noisy = [line for line in log_path.read_text().splitlines() if line.startswith('session:')]
    assert not noisy, f'routine disconnects were logged: {noisy}'
    print('PASS: routine disconnects and idle timeouts are not logged per connection')

with gateway(per_ip=4, rate=2, idle=5) as (port, _):
    for _ in range(2):
        with connect(port):
            pass
    rejected_before_tls(port)
    print('PASS: connection-rate budget survives disconnect/reconnect')


# Updated clients use a separate control channel and attach every data tunnel to it.
with tempfile.TemporaryDirectory(prefix='dinmoo-sessions-') as directory:
    directory = Path(directory)
    admin_path = directory / 'admin.sock'
    operator_env = dict(os.environ, DINMOO_ADMIN_SOCKET=str(admin_path))

    def operator(*arguments):
        result = subprocess.run([str(BINARY), *arguments], env=operator_env,
                                capture_output=True, text=True, timeout=5, check=True)
        return result.stdout.strip()

    def wait_session(previous=None):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            sessions = json.loads(operator('gateway-sessions'))
            current = [item for item in sessions if item['session_id'] != previous]
            if current:
                assert len(sessions) == 1, 'old control session was not removed'
                return current[0]['session_id']
            time.sleep(0.03)
        raise AssertionError('client failed to establish a fresh control session')

    def association(port):
        deadline = time.monotonic() + 3
        while True:
            try:
                stream = socket.create_connection(('127.0.0.1', port), timeout=3)
                break
            except ConnectionRefusedError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.02)
        try:
            stream.sendall(b'\x05\x01\x00')
            assert exact(stream, 2) == b'\x05\x00'
            stream.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
            assert exact(stream, 10)[:2] == b'\x05\x00'
            return stream
        except BaseException:
            stream.close()
            raise

    with gateway(per_ip=8, rate=120, idle=3, admin_path=admin_path) as (port, _):
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            client_port = reservation.getsockname()[1]
        client_env = {key: value for key, value in os.environ.items() if not key.startswith('DINMOO_')}
        client_env.update({
            'DINMOO_TLS_ROOT_DER': str(FIXTURES / 'test-ca.der'),
            'DINMOO_VOICE_IDENTITY_DIR': str(directory / 'voice'),
        })
        with (directory / 'client.log').open('w') as log:
            client = subprocess.Popen([str(BINARY), 'client', f'127.0.0.1:{client_port}', f'localhost:{port}'],
                                      env=client_env, stdout=log, stderr=log)
            try:
                original = wait_session()
                with association(client_port) as first, association(client_port) as other:
                    assert operator('gateway-terminate', original) == 'terminated'
                    assert first.recv(1) == b'', 'operator termination left a local tunnel open'
                    assert other.recv(1) == b'', 'operator termination failed to close every tunnel'
                replacement = wait_session(original)
                assert client.poll() is None, 'termination killed the client instead of reconnecting'
                print('PASS: operator termination closes client tunnels and automatically reconnects')

                with association(client_port) as second:
                    second.settimeout(6)
                    assert second.recv(1) == b'', 'idle client session was not disconnected'
                wait_session(replacement)
                assert client.poll() is None, 'idle termination killed the reconnecting client'
                print('PASS: aggregate client inactivity terminates the session and reconnects')

            except BaseException:
                print((directory / 'client.log').read_text(), file=sys.stderr)
                raise
            finally:
                client.terminate()
                try:
                    client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.wait(timeout=5)

#!/usr/bin/env python3
"""Repeat the ignored CPU benchmarks, report medians, and measure idle CPU.

Loopback only: never contacts Discord or any other internet host.

  python3 scripts/bench-cpu.py                    # 5 benchmark runs + 30 s idle check
  python3 scripts/bench-cpu.py --runs 3 --idle 0  # benchmarks only
  python3 scripts/bench-cpu.py --runs 0           # idle check only

Benchmarks: cargo test --release --locked -- --ignored --test-threads=1 <filter> --nocapture
(see crates/proxy/src/bench.rs). Idle: builds the release binary, starts a gateway with
the test fixtures and a client on free loopback ports, opens the client's gateway session
with one local SOCKS greeting, then samples their CPU with ps. Pass --raw FILE to keep
every BENCH line.
"""
import argparse
import os
from pathlib import Path
import re
import socket
import statistics
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'crates/proxy/tests/fixtures'
# libtest prints 'test <name> ... ' without a newline, so a BENCH line may share a line.
BENCH = re.compile(r'BENCH name=(\S+) ops=(\S+) cpu_us_per_op=(\S+) wall_ms=(\S+) extra=(\S*)')


def number(value):
    try:
        return float(value)
    except ValueError:
        return None


def run_benchmarks(runs, pattern, raw):
    command = ['cargo', 'test', '--release', '--locked', '--', '--ignored',
               '--test-threads=1', pattern, '--nocapture']
    names, rows = [], {}
    for index in range(runs):
        print(f'# run {index + 1}/{runs}: {" ".join(command)}', file=sys.stderr, flush=True)
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if result.returncode != 0:
            sys.stderr.write(result.stdout[-6000:] + result.stderr[-6000:])
            sys.exit(result.returncode)
        for line in result.stdout.splitlines():
            match = BENCH.search(line)
            if not match:
                continue
            if raw:
                raw.write(f'run={index + 1} {match.group(0)}\n')
                raw.flush()
            name, ops, cpu, wall, extra = match.groups()
            row = {'ops': ops, 'cpu_us_per_op': cpu, 'wall_ms': wall}
            for item in filter(None, extra.split(',')):
                key, _, value = item.partition(':')
                if key != '-':
                    row[key] = value
            if name not in rows:
                names.append(name)
                rows[name] = []
            rows[name].append(row)
    return names, rows


def summarize(names, rows):
    print('| Benchmark | Unit | ops | CPU µs/op median (min–max) | Code-under-test µs/op | Wall ms | Notes |')
    print('|---|---|---:|---:|---:|---:|---|')
    for name in names:
        samples = rows[name]
        cpu = [float(row['cpu_us_per_op']) for row in samples]
        wall = [float(row['wall_ms']) for row in samples]
        sides = sorted({key for row in samples for key in row if key.endswith('_us_per_op') and key != 'cpu_us_per_op'})
        side_text = ', '.join(
            f'{key[:-len("_us_per_op")]} {statistics.median(float(row[key]) for row in samples if key in row):.2f}'
            for key in sides)
        notes = []
        for key in samples[0]:
            if key in ('ops', 'cpu_us_per_op', 'wall_ms', 'unit') or key in sides:
                continue
            values = [row.get(key, '') for row in samples]
            numeric = [number(value) for value in values]
            if all(value is not None for value in numeric):
                median = statistics.median(numeric)
                notes.append(f'{key}={median:g}')
            else:
                notes.append(f'{key}={"/".join(dict.fromkeys(values))}')
        print(f'| {name} | {samples[0].get("unit", "")} | {samples[0]["ops"]} | '
              f'{statistics.median(cpu):.2f} ({min(cpu):.2f}–{max(cpu):.2f}) | {side_text} | '
              f'{statistics.median(wall):.1f} | {", ".join(notes)} (n={len(samples)}) |')


def free_port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def ps_value(pid, field):
    return subprocess.run(['ps', '-o', f'{field}=', '-p', str(pid)],
                          capture_output=True, text=True, check=True).stdout.strip()


def cpu_seconds(pid):
    """ps TIME is user+sys as [[dd-]hh:]mm:ss.ss (10 ms resolution)."""
    value, days = ps_value(pid, 'time'), 0
    if '-' in value:
        prefix, value = value.split('-', 1)
        days = int(prefix)
    seconds = 0.0
    for part in value.split(':'):
        seconds = seconds * 60 + float(part)
    return days * 86400 + seconds


def start(command, environment, log_path, ready, timeout=15):
    log = log_path.open('w')
    process = subprocess.Popen(command, env=environment, stdout=log, stderr=log)
    deadline = time.monotonic() + timeout
    while ready not in log_path.read_text():
        if process.poll() is not None or time.monotonic() > deadline:
            process.kill()
            raise SystemExit(f'{command[1]} did not become ready:\n{log_path.read_text()}')
        time.sleep(0.05)
    return process


def idle(seconds, settle):
    subprocess.run(['cargo', 'build', '--release', '--locked'], cwd=ROOT, check=True)
    binary = ROOT / 'target/release/dinmoo-proxy'
    with tempfile.TemporaryDirectory(prefix='dinmoo-idle-') as directory:
        directory = Path(directory)
        base = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'HOME': str(directory)}
        gateway_port, client_port = free_port(), free_port()
        processes = {}
        try:
            processes['gateway'] = start(
                [str(binary), 'gateway', f'127.0.0.1:{gateway_port}'],
                dict(base, DINMOO_TLS_CERT_DER=str(FIXTURES / 'localhost-cert.der'),
                     DINMOO_TLS_KEY_DER=str(FIXTURES / 'localhost-key.der')),
                directory / 'gateway.log', 'gateway listening on')
            processes['client'] = start(
                [str(binary), 'client', f'127.0.0.1:{client_port}', f'localhost:{gateway_port}'],
                dict(base, DINMOO_TLS_ROOT_DER=str(FIXTURES / 'test-ca.der'),
                     DINMOO_VOICE_IDENTITY_DIR=str(directory / 'voice')),
                directory / 'client.log', 'SOCKS listening on')
            # The client opens its gateway session for the first local connection, and
            # answers the SOCKS greeting only once that session is up.
            with socket.create_connection(('127.0.0.1', client_port), timeout=5) as app:
                app.sendall(b'\x05\x01\x00')
                if app.recv(2) != b'\x05\x00':
                    raise SystemExit(f'client session did not open:\n{(directory / "client.log").read_text()}')
            time.sleep(settle)
            before = {name: cpu_seconds(process.pid) for name, process in processes.items()}
            started = time.monotonic()
            time.sleep(seconds)
            elapsed = time.monotonic() - started
            after = {name: cpu_seconds(process.pid) for name, process in processes.items()}
            for name, process in processes.items():
                if process.poll() is not None:
                    raise SystemExit(f'{name} exited during the idle window')
            print(f'| Process | CPU over {elapsed:.0f} s idle | CPU ms per s | Lifetime CPU s | RSS MiB |')
            print('|---|---:|---:|---:|---:|')
            for name, process in processes.items():
                used = after[name] - before[name]
                rss = int(ps_value(process.pid, 'rss')) / 1024
                print(f'| {name} | {used:.2f} s | {used / elapsed * 1000:.2f} | {after[name]:.2f} | {rss:.1f} |')
        finally:
            for process in processes.values():
                process.terminate()
            for process in processes.values():
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--runs', type=int, default=5, help='benchmark repetitions (0 skips them)')
    parser.add_argument('--filter', default='bench_', help='test-name filter')
    parser.add_argument('--idle', type=float, default=30, help='idle window in seconds (0 skips it)')
    parser.add_argument('--settle', type=float, default=3, help='seconds to wait before the idle window')
    parser.add_argument('--raw', type=argparse.FileType('w'), help='also write every BENCH line here')
    arguments = parser.parse_args()
    if arguments.runs > 0:
        names, rows = run_benchmarks(arguments.runs, arguments.filter, arguments.raw)
        summarize(names, rows)
    if arguments.idle > 0:
        print()
        idle(arguments.idle, arguments.settle)


if __name__ == '__main__':
    main()

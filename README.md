# Dinmoo Proxy

A Rust client and TLS gateway for routing Discord connections through a shared server. The client exposes a loopback SOCKS5 listener; other applications keep their existing network configuration.

## Install

The public gateway requires no account or token. Install from your terminal:

macOS / Linux:

```sh
curl -fsSL https://download-proxy.dinmoo.com/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://download-proxy.dinmoo.com/install.ps1 | iex
```

The installer detects OS and CPU architecture, downloads the matching binary, verifies SHA-256, registers a user startup service, checks the gateway, and restarts Discord with proxy settings. On Unix, open a new terminal after installation to load the CLI path. Linux requires a working systemd user session. The Unix bootstrap requires curl and SHA-256 tooling.

```sh
dinmoo-proxy status
dinmoo-proxy off
dinmoo-proxy on
dinmoo-proxy check
dinmoo-proxy install     # update the installed client
dinmoo-proxy uninstall
```

`off` stops the client, disables automatic startup, and relaunches Discord directly. `on` enables startup, starts the client, verifies the route, and relaunches Discord through the proxy. `status` checks the service and gateway route. Windows uses a per-user Startup entry; macOS uses launchd; Linux uses systemd user services.

## Run without installing

```sh
cargo build --locked --release
./target/release/dinmoo-proxy client 127.0.0.1:1080 api-proxy.dinmoo.com:443
```

In another terminal, run `dinmoo-proxy check` or point a SOCKS-capable application at `127.0.0.1:1080`. This mode does not change system proxy settings or restart Discord. `dinmoo-proxy discord` explicitly relaunches Discord with the local proxy.

## Gateway

Provide a publicly trusted TLS certificate chain and PKCS#8 private key in DER format:

```sh
export DINMOO_TLS_CERT_DER='/etc/dinmoo-proxy/leaf.der,/etc/dinmoo-proxy/intermediate.der'
export DINMOO_TLS_KEY_DER='/etc/dinmoo-proxy/private-key.der'
export DINMOO_MAX_SESSIONS=128
./target/release/dinmoo-proxy gateway 0.0.0.0:8443
```

The default client endpoint is `api-proxy.dinmoo.com:443`. Keep its Cloudflare DNS record **DNS only**: the gateway uses a custom TLS protocol. The gateway resolves an explicit Discord domain allowlist, rejects private and special-use destination addresses, and accepts public clients without enrollment. TLS protects the client-to-gateway connection. Individual bandwidth fairness is not implemented.

For an Ubuntu host with an existing Certbot certificate for that endpoint, `deploy/install-gateway.sh <binary> - <systemd-unit>` installs a direct port-443 system service, a 128-session limit, certificate conversion/renewal hooks, and UFW rules for TCP 443 and SSH 9022. This script is specific to that hostname and SSH port; review it before using another host. It runs as root. The service itself runs as an unprivileged account. The optional Nginx configuration supports SNI routing when sharing 443 with a web host; do not use it alongside the direct-port override without reconfiguring the listener.

## Capacity and limitations

The implementation supports many simultaneous client connections with asynchronous Tokio tasks, bounded session counts, handshake/connect timeouts, and TCP backpressure. The default limit is 1,024 sessions, configurable from 1 to 4,096. Each TCP tunnel uses two 32 KiB copy buffers plus TLS, socket, and task memory. A 512 MB VM should use a conservative limit and be measured under representative load; no high-bandwidth SLA is claimed.

SOCKS5 CONNECT and UDP ASSOCIATE are implemented. UDP domains are allowlisted and cached per association for 30 seconds. Literal UDP addresses must have been reached recently via an allowed Discord TCP hostname. Discord is launched with Chromium proxy and WebRTC IP-handling flags. Voice/video, complete traffic isolation, and Windows/macOS/Linux desktop behavior require native acceptance testing; a successful API tunnel does not establish those properties.

Releases use HTTPS and SHA-256 checksums; manifests are not separately signed. Private gateway operators can optionally set `DINMOO_PROXY_TOKEN` on both ends; the public service leaves it unset. The test-only localhost key under `crates/proxy/tests/fixtures` is public test data and must never be used in deployment.

## Development and releases

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

Pushing a `v*` tag builds binaries for macOS, Linux, and Windows on x86_64 and arm64, then publishes binaries, terminal installers, and `latest.json` in GitHub Releases. GitHub-hosted CI provides build checks; it does not validate native Discord voice/video behavior. See [download redirect setup](docs/downloads.md) for the optional branded download host.

Licensed under [MIT](LICENSE).

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
export DINMOO_MAX_SESSIONS_PER_IP=32
export DINMOO_CONNECTIONS_PER_IP_PER_MINUTE=120
export DINMOO_IDLE_TIMEOUT_SECS=600
./target/release/dinmoo-proxy gateway 0.0.0.0:8443
```

The default client endpoint is `api-proxy.dinmoo.com:443`. Keep its Cloudflare DNS record **DNS only**: the gateway uses a custom TLS protocol. The gateway resolves an explicit Discord domain allowlist, rejects private and special-use destination addresses, and accepts public clients without enrollment. TLS protects the client-to-gateway connection. Individual bandwidth fairness is not implemented.

For an Ubuntu host with an existing Certbot certificate for that endpoint, `deploy/install-gateway.sh <binary> - <systemd-unit>` installs a direct port-443 system service, a 128-session limit, certificate conversion/renewal hooks, and UFW rules for TCP 443 and SSH 9022. This script is specific to that hostname and SSH port; review it before using another host. It runs as root. The service itself runs as an unprivileged account. The optional Nginx configuration supports SNI routing when sharing 443 with a web host; do not use it alongside the direct-port override without reconfiguring the listener.

## Capacity and limitations

The implementation supports many simultaneous client connections with asynchronous Tokio tasks, bounded session counts, handshake/connect timeouts, and TCP backpressure. The default limit is 1,024 sessions, configurable from 1 to 4,096. Each TCP tunnel uses two 32 KiB copy buffers plus TLS, socket, and task memory. A 512 MB VM should use a conservative limit and be measured under representative load; no high-bandwidth SLA is claimed.

Gateway admission limits apply before TLS handshakes and task allocation. Defaults are 32 concurrent gateway connections per IPv4 address or IPv6 /64, plus a token bucket allowing a burst of 120 connection attempts and replenishing 120 tokens per minute. IPv4-mapped IPv6 addresses share the IPv4 quota. Concurrency permits are released on disconnect, failure, or cancellation; reconnecting does not reset the rate budget. The last quarter of the global cap admits only sources holding fewer than a quarter of their per-source limit (8 by default), so a few addresses cannot take every slot. Source tracking is bounded to 4,096 entries; when full, the least recently seen source without an open connection is forgotten.

The global and per-source admission caps count both control and data connections. Updated clients establish an authenticated TLS control connection. The gateway ends the entire client session after 10 minutes (600 seconds) without proxy traffic across any of its data tunnels. Control heartbeats do not extend this deadline. Losing the control connection also cancels every attached data tunnel. Voice relay writes have a separate 15-second deadline. Set `DINMOO_MAX_SESSIONS_PER_IP` (1–4,096), `DINMOO_CONNECTIONS_PER_IP_PER_MINUTE` (1–10,000), and `DINMOO_IDLE_TIMEOUT_SECS` (1–3,600) to tune these defaults. A Discord client can use many simultaneous connections; users behind the same NAT share a quota, so tune limits against normal traffic and available memory.

Limits use the actual TCP peer address and do not trust forwarded headers. The optional Nginx stream configuration hides client addresses, so all connections forwarded by it share Nginx's quota; use the direct gateway listener for client-specific limits. These application safeguards do not replace upstream DDoS protection or bandwidth controls against distributed attacks. Oversized SOCKS UDP replies are dropped without closing the association; the complete SOCKS UDP frame must fit within 1,500 bytes.

On session termination, the client closes every local TCP, UDP, and voice tunnel, pauses its SOCKS listener, and reconnects automatically with exponential backoff from 1 to 30 seconds. It keeps the startup service enabled and does not relaunch Discord directly. Existing streams are not replayed; Discord must establish new connections. Both client and gateway need this build for the control protocol. Legacy clients remain supported with per-tunnel expiry but cannot receive full client-session termination.

Unix gateway operators can list and terminate a specific client session using a private local admin socket:

```sh
# The systemd deployment creates /run/dinmoo-proxy with mode 0700.
# For a manual gateway, create a private directory and set DINMOO_ADMIN_SOCKET.
export DINMOO_ADMIN_SOCKET=/run/dinmoo-proxy/admin.sock
sudo dinmoo-proxy gateway-sessions
sudo dinmoo-proxy gateway-terminate <session-id>
```

The socket is enabled only when `DINMOO_ADMIN_SOCKET` is configured on the gateway; its parent must be a real private directory and the socket has mode 0600. The installer configures the default path above. For a custom path, pass the variable explicitly to the operator command (for example `sudo env DINMOO_ADMIN_SOCKET=/private/path/admin.sock dinmoo-proxy gateway-sessions`). There is no public admin endpoint. Listing sessions reports a random session ID, source IP, and idle duration; it does not expose proxy tokens or Discord credentials. IDs are bound to the actual control connection's source IP, so clients sharing a NAT remain separately terminable.

SOCKS5 CONNECT and UDP ASSOCIATE are implemented. UDP domains are allowlisted and cached per association for 30 seconds. The client also bridges Discord voice WebSockets: the gateway validates Discord's TLS certificate, reads the voice `Ready` allocation, and forwards UDP only to that exact server IP and port. It rewrites that allocation to a per-call loopback socket on the client, so native Discord media uses the proxy without administrator routes. Media payloads remain unchanged and Discord's voice encryption remains end-to-end. The gateway sees temporary voice session credentials and call metadata; it does not receive the Discord account token.

The bridge uses a client-local certificate and a Chromium SPKI pin; it does not add a system CA or disable general certificate checks. The gateway must run the matching voice-bridge build. Local protocol and packet tests pass, but native screen-share playback still needs a live Discord call acceptance test. The older macOS `media` TUN command remains an experimental diagnostic path. See [media routing and test evidence](docs/media-routing.md).

Releases use HTTPS and SHA-256 checksums; manifests are not separately signed. Private gateway operators can optionally set `DINMOO_PROXY_TOKEN` on both ends; the public service leaves it unset. The test-only localhost key under `crates/proxy/tests/fixtures` is public test data and must never be used in deployment.

## Development and releases

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build --locked
python3 scripts/test-gateway-protection.py  # isolated loopback TLS checks
```

Pushing a `v*` tag builds binaries for macOS, Linux, and Windows on x86_64 and arm64, then publishes binaries, terminal installers, and `latest.json` in GitHub Releases. GitHub-hosted CI provides build checks; it does not validate native Discord voice/video behavior. See [download redirect setup](docs/downloads.md) for the optional branded download host.

Licensed under [MIT](LICENSE).

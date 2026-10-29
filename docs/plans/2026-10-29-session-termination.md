# Server session termination

User decisions: terminate after 10 minutes of aggregate client traffic inactivity or an operator command; client automatically reconnects. Control heartbeats do not count as proxy traffic. Do not disable the startup service or switch Discord to direct connections.

Use an authenticated TLS control connection with a server-generated random 128-bit session ID. Data tunnels carry the ID over TLS and are bound to the control connection's TCP peer IP. A registry bounds sessions through existing gateway admission limits. Dropping the control connection cancels and removes all its data tunnels. Explicit idle/operator termination sends a bounded reason before closing; ordinary failures also close data tunnels and trigger bounded exponential client reconnect delay. The local SOCKS listener only accepts while its control session is ready.

Keep legacy DMPX v1 data tunnels compatible, with their existing per-tunnel idle timeout; full session termination requires the updated client. New control and data connections use separate protocol versions. Handshake timeouts, destination policy, IP limits and connection-rate limits remain in force.

Operator commands: `gateway-sessions` and `gateway-terminate <session-id>` through a Unix-domain admin socket configured by `DINMOO_ADMIN_SOCKET`. The parent directory must be private; socket permissions are 0600. No public admin listener and no shell-command messages over the client control channel. Linux deployment uses a private systemd runtime directory. No live deployment.

Tests/checks:
- [x] Session registration, peer binding, removal, cancellation and operator targeting.
- [x] Aggregate traffic extends expiry; heartbeat-only activity does not.
- [x] Client detects explicit termination and EOF, tears down tunnels, and reconnects with backoff.
- [x] Real loopback binary test for operator termination, automatic reconnect and idle termination.
- [x] Full Rust tests, Clippy, formatting and existing protection integration test.

Validation: Rust suite, Clippy, formatting and shell syntax passed; isolated real client/gateway TLS tests verified pre-TLS limits, idle cleanup, operator termination, all-tunnel disconnect and automatic reconnection. Full client termination requires matching updated client and gateway; no live deployment or native Discord acceptance test was performed.

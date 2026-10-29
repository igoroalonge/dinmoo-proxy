# Gateway protection

Implement the reviewed safeguards in the existing checkout. No deployment or firewall changes on a live server.

- Retain the global session cap; add configurable concurrent and connection-rate limits before TLS. Defaults: 32 concurrent connections per source, 120 new connections/minute (token bucket, burst 120), 600-second (10-minute) network inactivity timeout.
- Normalize IPv4-mapped addresses and group IPv6 sources by /64 to limit address rotation. Bound the source tracking table, retain rate history after disconnects, reclaim inactive entries after refill, and release concurrency permits on every exit including cancellation.
- Run a separate idle watchdog around gateway sessions so a blocked relay write cannot prevent expiration. Successful reads or writes reset activity; polling, empty reads, and flushes do not.
- Add a 15-second write deadline to the voice gateway relay so a stalled client cannot indefinitely retain a UDP grant while upstream heartbeats reset activity.
- Validate every SOCKS UDP address before indexing. Keep the 1500-byte tunnel-frame limit; drop responses that cannot fit and detect receive truncation with an extra byte. Pin local UDP peers only after a valid packet.
- Configure deployment defaults and document NAT/Nginx sharing, operational tuning, and limitations against distributed or volumetric attacks.

Implementation/checklist:
- [x] Failing regression tests for admission, rate history/refill, source normalization, bounded tracking, cancellation release, watchdog inactivity/activity/stalled writes, and UDP parsing/size.
- [x] Implement focused protection module and integrate gateway accept loop.
- [x] Fix UDP boundaries and voice write deadlines.
- [x] Update documentation/deployment defaults.
- [x] Run full tests, Clippy, formatting, shell syntax, and review the diff.

Validation: full Rust suite, Clippy, formatting, shell syntax, and the isolated real-binary loopback TLS integration check. The integration check also runs in Unix release CI. No live server deployment or native Discord call acceptance test performed.

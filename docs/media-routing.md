# Native Discord media routing

## Voice WebSocket bridge

The supported design no longer tries to infer UDP authorization from client logs.
For `*.discord.media` SOCKS connections, the local client terminates a TLS
connection with a per-user self-signed leaf certificate. Discord is launched
with a Chromium SPKI pin for that certificate. The client forwards the selected
WebSocket path over its TLS tunnel; the gateway opens its own certificate-verified
Discord WSS connection and forwards text/binary frames without changing voice
payloads.

Only an upstream Discord `Ready` message can create a media grant. The gateway
chooses a random per-allocation ID and binds it to that WSS session, one exact
UDP IP and port, and a short expiration. It sends `Ready` to the local client,
which rewrites the advertised endpoint to a per-call loopback UDP socket. UDP
packets carry the grant ID through the TLS tunnel; neither the client nor its
SOCKS request can select a destination. A new allocation or WSS close revokes
the previous socket/grant. The gateway handles media transport and temporary
voice-session credentials, while media payload encryption remains end-to-end.

This design requires the matching gateway build on the server. A local certificate
identity is stored under the user's Dinmoo Proxy configuration directory, with
restricted file permissions on Unix. Discord's per-SPKI Chromium exception is
needed only for the client-local TLS hop; upstream Discord TLS verification stays
enabled. The gateway can see temporary voice credentials and call metadata, so
the feature is opt-in at the product trust level even though the current client
build routes voice WSS through it by default.

The local protocol tests cover certificate pin material, local TLS/WebSocket
handshake, Ready rewriting, loopback UDP relay, flow ID/source checks, expiration,
and preservation of binary DAVE frames. Native acceptance is still needed to
confirm that stock Discord uses this WebSocket path and that a real screen share
plays successfully.

## Diagnosis

The desktop application's native C++ media engine does not follow the Chromium
SOCKS proxy configuration. On the affected Mac, Discord logs showed stream UDP
connections reporting the home public address, followed by
`video-stream-receiver-ready-timeout`. The proxy process had TCP tunnels and no
SOCKS UDP association. Chromium launch flags therefore did not capture media.

A second restriction existed at the gateway: it approved literal UDP IPs only
after connecting to a Discord hostname resolving to that IP. Discord's observed
WebSocket names resolved to Cloudflare addresses different from the UDP endpoints
provided during media negotiation. That rule could not authorize those media
endpoints.

## Local diagnostic implementation

The experimental macOS `media` command creates a temporary utun interface and
explicit host routes. An IP stack converts captured UDP packets into SOCKS UDP
associations through the existing TLS client and gateway. Media payloads remain
unchanged. The gateway accepts operator-configured exact UDP destinations through
`DINMOO_MEDIA_TARGETS`, a comma-separated list of public IP and port pairs. An
explicit grant does not authorize other ports on that IP.

The local `media --watch <Discord log directory>` mode polls the two native
WebRTC log files and tracks the latest 64 distinct public IPv4 media endpoints.
The isolated VM test runner can copy these observations into an operator-owned
`DINMOO_MEDIA_TARGETS_FILE`, which the test gateway reloads. This trusts the test
administrator's machine. It is not independent proof of Discord ownership and
must not become an unauthenticated public endpoint-enrollment API.

This is a foreground diagnostic mode, not an automatic production installer
upgrade. It currently supports IPv4 media endpoints and at most 64 local media
sessions. Administrator access is required to create the interface and routes.
The routes apply to all applications reaching the listed destination IPs; this
is not process-specific capture. Direct TCP traffic to these media IPs is not
handled by this UDP adapter. Other destination routes and the default route are
unchanged. Ctrl-C or SIGTERM shuts down the adapter and removes its routes;
`dinmoo-proxy off` does not manage this separate foreground command.

Server-verified media authorization, Windows/Linux capture, privileged service
installation, and fully automatic on/off integration remain unimplemented.
Media endpoint changes require matching client route and gateway grant updates;
the watch mode and administrator-controlled test runner automate these only for
the local test. UDP frames still travel over TLS/TCP, which can increase latency
when packets are lost; these tests do not establish high-bandwidth capacity.

## Verification

- Local packet test: kernel-style IPv4/UDP input, including macOS's mandatory
  four-byte address-family header, traverses the actual macOS TUN reader/writer,
  IP adapter, and SOCKS UDP client, returning with the original payload and
  reversed IP addresses. A socket-pair fixture replaces the privileged kernel
  descriptor and the gateway is simulated. The previous raw-IP-only fixture
  missed a header-handling failure that caused native Discord's "No Route";
  the strengthened test failed before enabling the TUN header handling and
  passed after the correction.
- Regression test: partial tunnel frames survive cancellation when the opposite
  UDP direction becomes readable. Previously the discarded read state could
  corrupt subsequent frames.
- Media startup regression: the preflight connects to the configured SOCKS
  listener, including a nondefault port. It must not depend on port 1080 when
  `DINMOO_MEDIA_SOCKS` selects a separate test service.
- Discovery regression: changing IPs and ports are retained, repeated endpoints
  are deduplicated, and private addresses and port zero are rejected.
- Gateway reload regression: changing the operator-owned file replaces dynamic
  grants, keeps static grants, and retains the last valid state on invalid input.
- Full local suite: 19 tests passed.
- Local macOS release build and Linux musl cross build completed.
- VM test: 64 payloads of 1,000 bytes round-tripped through a local client, TLS,
  isolated VM gateway, and VM UDP echo socket, with payload and sequence checks.
  The live gateway service was not replaced.

Actual utun routing and Discord screen-share playback still require the native
administrator-authorized acceptance test. A working API tunnel, packet adapter
test, or UDP echo test does not establish successful screen-share playback.

## Reproduce the isolated VM test

After building `target/release/dinmoo-proxy` and
`target/x86_64-unknown-linux-musl/release/dinmoo-proxy` locally, run the
isolated test against a VM you control:

```sh
python3 scripts/test-vm-udp.py --host root@test-vm.example.com --port 9022 --keep
```

Pass your own VM's SSH destination and port. The test uses your SSH key and
known_hosts, a test certificate trusted only by the isolated client, and separate
loopback listeners.
It prints the administrator command for the native test. The watch mode discovers
endpoints from the affected Mac's native Discord logs and the test runner updates
the isolated gateway's grants when they change. Stop the native media command first, then
stop the VM test to close its temporary client, gateway, and UDP echo processes.
The temporary uploaded artifacts remain under `/tmp` on the VM.

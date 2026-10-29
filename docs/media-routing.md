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
the previous socket/grant, so media flows are tied to one bridge. A voice
WebSocket that resumes (op 7, answered by op 9) gets no `Ready` and so no media
path. When a bridge drops (network change, sleep, gateway restart, write timeout,
Discord closing upstream), the client therefore closes Discord's voice WebSocket
with 4006 ("Session no longer valid") rather than 1005, and closes a bridge
the same way if Discord sends op 7 on it before any `Ready`. Discord then
identifies again instead of resuming, so media returns after a short re-join
(about 1-3 s) instead of about 50 s. True resume, keeping media sockets across
bridges, is planned.

The loopback socket drops everything until a Discord IP discovery request
(74 bytes, type 1, carrying the `Ready` SSRC) arrives from a loopback address,
then accepts only that sender. The pin never moves. Discord appears to repeat
discovery about every 60 seconds from new sockets; those attempts never complete
through the bridge while the original socket keeps working, and SSRCs are small
and sequential, so re-pinning would reopen the takeover. This narrows the race for the local port; it does not
authenticate the sender, because any local user can see the port and guess the
SSRC.

The gateway is trusted with the call's transport. Discord's session description
(op 4) gives it the voice `secret_key`, so it can read and forge transport-layer
RTP/RTCP, including the audio-level and speaking extensions, and can inject
silence. Discord's DAVE end-to-end encryption, where Discord applies it (not in
stage channels), keeps media content from a gateway that only relays traffic.
DAVE's key exchange also travels over the voice WebSocket that the gateway
relays, though, so a gateway that tampers with it could substitute its own keys
and read or forge media. Only comparing the call's Voice Privacy Code, or a
user's verification code, in Discord would reveal that. The gateway also sees call
metadata, the voice session credentials and session IDs. It never receives the
Discord account token.

This design requires the matching gateway build on the server. The local
certificate identity is stored under `.config/dinmoo-proxy/voice` in the user's
home directory, with owner-only permissions on Unix. Every Discord launch made
by `dinmoo-proxy` replaces it with a new key; if that fails, Discord is
relaunched without the proxy. A running client reloads the identity when the
file's content changes.

Chromium's `--ignore-certificate-errors-spki-list` exception is not scoped to the
client-local hop. Discord's network service accepts any presented chain that
contains the pinned public key, for every host and without a name check, so
whoever learns that key and can intercept Discord's TLS could impersonate any
HTTPS site to Discord. Chains without the pinned key still get normal
verification, and the gateway verifies Discord's certificate on its own upstream
WSS. The client therefore completes the local TLS handshake, which reveals the
certificate, only for a peer the OS reports as the same user: the socket owner
from `/proc` on Linux, the owning process from libproc on macOS (which must also
run from /Applications/Discord.app or ~/Applications/Discord.app; a Discord
installed elsewhere is launched without the pin and gets a plain tunnel, so its
voice media is not proxied), and the owner SID on Windows, with the process
bound to the socket's age. Other peers get a plain tunnel. `on`, `install` and
`discord` pin Discord to 127.0.0.1:1080 only after the same lookups confirm that
a process of the same user answers there, and otherwise relaunch Discord without
the proxy. The client keeps that port bound for as long as it runs, while `off`,
`uninstall` and updates close Discord before stopping it. If the client process
dies while a proxied Discord is running, the port stays free until the service
restarts the client (about 3 s on Linux, up to 10 s on macOS, and not until the
next sign-in on Windows), so close Discord in that case. Because the gateway
sees the call's transport and metadata, using a gateway means trusting its
operator with your calls; the current client routes voice WSS through the
bridge whenever the peer check passes and has no setting to turn it off.

The local protocol tests cover certificate pin material, identity rotation, the
peer-check fallback, local TLS/WebSocket handshake, Ready rewriting, loopback
UDP relay and discovery pinning, flow ID/source checks, expiration, and
preservation of binary DAVE frames. Native acceptance is still needed to
confirm that stock Discord uses this WebSocket path and that a real screen share
plays successfully.

## Gateway CONNECT gate

Discord's TCP names resolve to shared Cloudflare addresses, so the gateway
relays a CONNECT only after the client's TLS ClientHello names an allowlisted
host. It reads only the cleartext server name. An Encrypted Client Hello's inner
name and the HTTP `Host` header inside the TLS session are invisible to it, and
the ECH extension cannot be refused while Chromium sends a GREASE one by
default. If Cloudflare's edge served another site behind an outer Discord name,
the gateway would relay to it. `scripts/probe-cloudflare-fronting.sh` checks the
`Host` case by hand; probing ECH needs a client that sets the outer name itself.

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

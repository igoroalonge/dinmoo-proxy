# Preventing the public gateway from accepting arbitrary destinations

Research date: 2026-10-28. This is a design recommendation, not a claim that the
current gateway implements these guarantees.

## Recommendation

Use a **default-deny, server-owned destination policy**. A public client must
never be able to authorize an IP by sending a log line, hostname claim, locally
signed statement, or self-selected IP/port. Separate two decisions:

1. **Can this client use the gateway?** Anonymous access, an account, a rate limit,
   or a gateway-issued session identifier can answer this.
2. **Is this destination an authorized Discord service?** Only a trusted server
   policy or independently authenticated Discord allocation can answer this.

The second decision remains necessary even if users need no enrollment token.
An internal short-lived grant can be automatic and invisible to the user.

For the current transparent SOCKS/TLS architecture, strict independently verified
UDP allocation is **not available from client logs alone**. Retain operator-owned
exact endpoint grants for a controlled pilot. Do not expose the local test
watcher's grant update mechanism as a public client API. A general public media
service needs a trusted allocation source or a deliberate control-plane redesign.

## What Discord actually supplies

Discord first supplies a voice hostname and a voice-session token. The client
authenticates a secure voice WebSocket using session identifiers and that token;
the server's Opcode 2 Ready message supplies the UDP IP and port. These allocations
can change, and Discord explicitly advises against caching voice-server results.
The reviewed public protocol documents no detached signature on Ready and no
side-effect-free API for validating an arbitrary copied allocation. This is a
finding about the documented interface, not proof that no private facility exists.
[Discord voice protocol](https://docs.discord.com/developers/topics/voice-connections#establishing-a-voice-websocket-connection)

The existing gateway passes the application's TLS bytes through unchanged. TLS
protects application data with connection keys, so a forwarding gateway cannot
read the authenticated Ready message merely because the bytes cross its socket.
[TLS 1.3 protocol](https://www.rfc-editor.org/rfc/rfc8446.html#section-2)

## Why common shortcuts do not establish the required identity

| Candidate check | Useful evidence | Remaining limitation |
| --- | --- | --- |
| Client's native log or reported Ready JSON | Locates the endpoint used by an honest client | A modified client can fabricate it. Parsing a plausible address does not authenticate its source. |
| WHOIS, RDAP, ASN, or all Cloudflare networks | Identifies a network operator | Does not identify a customer or application. Cloudflare documents shared proxy addresses. |
| PTR suffix alone | A reverse-DNS label | Does not prove the address is authorized by the forward-domain owner. |
| Forward-confirmed Discord name and IP | A stronger DNS association, when present | Does not prove a particular UDP port or live voice allocation. It also cannot cover endpoints whose media IP differs from the WebSocket DNS result. |
| SNI in a client TLS hello | The name the client requests | The field is a client statement. It is a useful filter, not evidence that the server authenticated or that encrypted HTTP authority and subsequent use comply. |
| UDP IP-discovery response | The endpoint responds like the expected protocol and is reachable | The documented format has type, length, SSRC, address, and port, with no detached signature. A compatible responder can imitate the format. |
| A signed grant issued from client-supplied data | The gateway approved a statement | Signing an unverified claim does not make its destination trustworthy. |
| Client login or authentication | Identifies or limits the gateway user | An authenticated malicious user can still ask for a forbidden destination. |

The Cloudflare ownership limitation follows from its documented shared-address
model; it does not establish whether any specific observed media prefix is shared
or dedicated. Do not infer exclusivity for `104.29.x.x` without an authoritative
statement covering that service and range.
[Cloudflare IP addresses](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)

Forward/reverse consistency is an operational DNS check, not an application
authentication protocol. TLS service identity instead checks a certificate against
the independently expected service name. These are distinct guarantees.
[RFC 1912 §2.1](https://www.rfc-editor.org/rfc/rfc1912.html#section-2.1),
[RFC 9525 §6](https://www.rfc-editor.org/rfc/rfc9525.html#section-6)

The IP-discovery weakness above is an inference from Discord's documented packet
fields. It is not a demonstrated exploit against Discord's production server.
[Discord IP discovery](https://docs.discord.com/developers/topics/voice-connections#ip-discovery)

Local DNS evidence supplied by the live investigation on 2026-10-28: both
`c-lhr01-7309a55b.discord.media` and `c-lhr01-76e30b49.discord.media` resolved to
`162.159.128.235`, `162.159.129.235`, `162.159.130.235`, `162.159.137.234`, and
`162.159.138.234`, rather than the native log's media addresses
`104.29.151.152` and `104.29.144.166`. Reverse lookups for those media addresses
returned no PTR data. These observations demonstrate why hostname-to-IP equality
and PTR matching do not currently solve this call's media authorization; they are
a dated runtime snapshot, not an authoritative service-ownership statement.

## An official Discord IP feed exists, but its scope matters

Discord's link-preview crawler verification article links an official JSON feed.
The feed identifies itself as `discord egress` and contains service labels such as
`media` and `api`. Its purpose is recognizing outbound Discord-originated requests.
Neither that article nor the feed states that it enumerates the inbound voice
servers to which desktop users should send UDP. The `media` label is insufficient
to repurpose it as a voice-ingress allowlist. I found no authoritative complete
voice-ingress range list in the reviewed Discord documentation and searches.
[Discordbot verification article](https://support.discord.com/hc/en-us/articles/42500550752919-About-Discord-Link-Previews-and-the-Discordbot),
[Official Discord egress feed](https://cdn.discordapp.com/ipranges/discord.json)

## Production design that can give a strong destination guarantee

The gateway should own the decision, and its relay API should use an authorized
service/session handle rather than a client-selected raw destination:

1. For HTTPS/WebSocket services, accept only canonical Discord domain names and
   documented service ports. Resolve on the gateway, filter every returned address,
   and connect to one of those exact results. Recheck on each new connection;
   never turn a name lookup into a permanent IP-wide grant.
2. For a strict application-service guarantee, the gateway must terminate the
   upstream application connection and validate its TLS certificate for the
   expected Discord name, then constrain the requested HTTP authority/protocol.
   A transparent CONNECT tunnel plus DNS checks has a weaker guarantee: it
   restricts the network destination selected by the gateway.
3. For media, receive Ready **directly on the authenticated upstream Discord voice
   WebSocket** which the gateway operates for that actual client session. Create
   a grant for exactly `(gateway session, UDP, IP, port, expiry)` from that message.
4. Bind the grant to the originating tunnel/session; expire it when the control
   connection closes, when the allocation changes, or after a short timeout.
   Repeated arbitrary UDP traffic must not renew an unverified grant.
5. Relay only to the grant's stored destination. Accept responses only from that
   destination, apply per-session/IP byte and packet budgets, and cap concurrent
   sessions. Reject private, loopback, link-local, multicast, and other special-use
   addresses even if upstream input unexpectedly supplies them.

These are proposed requirements. Their strong guarantee depends on step 3's
authenticated source and on validating the control-plane implementation; steps 4
and 5 alone cannot manufacture origin trust.

### Client integration cost

Operating the existing voice WebSocket on the gateway requires an explicit
client/control-plane integration. An unmodified desktop client expects TLS to end
at Discord. A generic network tunnel cannot expose plaintext Ready to the relay.
Changing that means either integrating a voice-control proxy into the client or
deliberately intercepting that TLS connection with locally trusted certificates.
The latter changes the trust/privacy model and must not be introduced silently.
The gateway would process sensitive voice-session credentials and call metadata.

Do not implement a supposed validation shortcut by opening a second WebSocket with
the user's existing credentials and assume that it cannot disturb the call. The
public flow is connection establishment/resumption, not a documented read-only
allocation-validation operation. Its concurrent-session semantics would require
separate investigation and acceptance tests.
[Voice close/resume status definitions](https://docs.discord.com/developers/topics/opcodes-and-status-codes#voice)

### A future provenance-proof alternative

Client-provided ordinary TLS transcripts or traffic keys are not detached server
signatures over Ready: a client controlling session keys can fabricate claimed
application responses. TLSNotary explicitly addresses that problem with a
participating verifier. Its documentation describes MPC-TLS and a proxy proof
mode, but currently lists TLS 1.2 support with TLS 1.3 still on the roadmap. This
would require participating client software, verified parsing/freshness binding,
and real resource measurements. It is a research option, not an available switch
for the existing Discord desktop client or a validated 512 MB deployment design.
[TLSNotary provenance model](https://tlsnotary.org/docs/intro/),
[TLSNotary forgery explanation](https://tlsnotary.org/docs/faq/#why-does-tlsnotary-need-an-online-verifier-cant-this-be-done-serverlessly-in-the-browser-with-zero-knowledge)

## Current code gaps to close before claiming Discord-only public access

Inspected `crates/proxy/src/main.rs` in the working tree on the research date:

- `handle_socks` checks a hostname allowlist but permits a client-selected TCP
  port. It should authorize `(service, port)` combinations explicitly.
- `approved_udp_ips` is shared in `Config` across clients. A successful allowed
  TCP hostname can therefore authorize UDP for another client.
- This grant is IP-only: the UDP path accepts arbitrary destination ports on that
  IP and refreshes the five-minute approval from accepted UDP traffic.
- The TCP byte-copy relay does not inspect SNI or HTTP authority; name lookup is
  destination selection, not verification of the encrypted application's use.
- The new `DINMOO_MEDIA_TARGETS_FILE` is operator-owned test configuration. Its
  exact IP/port entries are narrower than the old IP-only grants, but neither the
  file nor a local log watcher is an independent Discord allocation oracle.

Immediate containment: remove the shared IP-only UDP authorization; keep exact,
expiring, session-scoped grants from trusted inputs; restrict TCP services/ports;
and default-deny missing authority. Do not widen to every Cloudflare address to
make calls connect. The long-term strong design is authenticated voice-control
allocation, subject to the client-integration work above. Until then, describe the
pilot as an operator-approved destination proxy rather than verified Discord-only
media access.

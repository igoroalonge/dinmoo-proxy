//! Gateway server: TLS accept loop, tunnel authentication and SOCKS relay.
use crate::{
    policy::{allowed_destination, allowed_tcp_destination, is_public_ip, parse_media_targets},
    protection, session,
    socks::{read_socks_request, reply, reply_bound, socks_request_target, Address},
    tunnel::read_string,
    udp::{forward_udp_response, parse_socks_udp, FrameReader},
    voice, Config, ContextExt, Result, AUTH_HANDSHAKE_TIMEOUT, DESTINATION_CONNECT_TIMEOUT,
    SOCKS_HANDSHAKE_TIMEOUT, TCP_COPY_BUFFER_SIZE, TLS_HANDSHAKE_TIMEOUT,
};
use rustls::server::Acceptor;
use std::{
    collections::{HashMap, VecDeque},
    env,
    error::Error,
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    time::Instant,
};
use tokio_rustls::server::TlsStream;

/// Logs a policy denial through `DENIALS` and returns it as a `Denied` error.
macro_rules! deny {
    ($($arg:tt)*) => { return Err(denied(format_args!($($arg)*))) };
}

const CLIENT_READ_BUFFER: usize = 16 * 1024;
/// One maximum-size handshake record plus a few record headers of fragmentation.
const CLIENT_HELLO_LIMIT: usize = 16 * 1024 + 4 * 5;
const ACCEPT_BACKOFF: (Duration, Duration) = (Duration::from_millis(100), Duration::from_secs(1));
const LOG_INTERVAL: Duration = Duration::from_secs(10);
const DNS_CACHE_ENTRIES: usize = 256;
const DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const REPLY_WINDOW: Duration = Duration::from_secs(30);
const REPLY_SOURCES: usize = 32;

static ACCEPT_ERRORS: LogLimiter = LogLimiter::new();
static DENIALS: LogLimiter = LogLimiter::new();
static HANDSHAKE_ERRORS: LogLimiter = LogLimiter::new();

pub(crate) async fn serve(
    config: Arc<Config>,
    settings: protection::Settings,
    max_sessions: usize,
) -> Result<()> {
    let admission = protection::Admission::new(max_sessions, settings.per_ip, settings.per_minute);
    let _admin = match env::var_os("DINMOO_ADMIN_SOCKET") {
        Some(path) => Some(session::admin::start(config.sessions.clone(), path.into())?),
        None => None,
    };
    eprintln!("gateway safeguards: {} sessions/source, {} connections/minute/source, {}s client idle timeout (IPv6 grouped by /64)", settings.per_ip, settings.per_minute, settings.idle.as_secs());
    let listener = TcpListener::bind(config.listen).await?;
    eprintln!(
        "gateway listening on {} (max sessions: {max_sessions})",
        config.listen
    );
    let mut rejected_sessions = 0u64;
    loop {
        let (stream, peer) = next_connection(|| listener.accept()).await;
        let Some(permit) = admission.acquire(peer.ip()) else {
            rejected_sessions = rejected_sessions.saturating_add(1);
            if rejected_sessions == 1 || rejected_sessions.is_multiple_of(1000) {
                eprintln!(
                    "session admission limit reached; rejected {rejected_sessions} connections"
                );
            }
            drop(stream);
            continue;
        };
        let cfg = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // TCP_NODELAY fails only on a socket that is already shut down.
            if stream.set_nodelay(true).is_ok() {
                // Logs its own failures.
                let _ = handle_gateway_connection(buffered(stream), &cfg, peer.ip()).await;
            }
        });
    }
}

/// rustls reads at most 4 KiB of TLS input per call; buffering beneath it turns a
/// 16 KiB record into one `recv` instead of four or five.
pub(crate) fn buffered(stream: TcpStream) -> BufReader<TcpStream> {
    BufReader::with_capacity(CLIENT_READ_BUFFER, stream)
}

/// Accept errors never stop the gateway. Errors other than a failed pending connection
/// usually mean descriptor or memory exhaustion, so back off while sessions drain.
async fn next_connection<T, F, A>(mut accept: F) -> T
where
    F: FnMut() -> A,
    A: Future<Output = io::Result<T>>,
{
    use io::ErrorKind::*;
    let mut delay = None;
    loop {
        let error = match accept().await {
            Ok(connection) => return connection,
            Err(error) => error,
        };
        ACCEPT_ERRORS.log(format_args!("gateway accept: {error}"));
        if !matches!(
            error.kind(),
            ConnectionAborted
                | ConnectionReset
                | Interrupted
                | WouldBlock
                | PermissionDenied
                | HostUnreachable
                | NetworkUnreachable
                | NetworkDown
        ) {
            let next = delay.map_or(ACCEPT_BACKOFF.0, |delay: Duration| {
                (delay * 2).min(ACCEPT_BACKOFF.1)
            });
            delay = Some(next);
            tokio::time::sleep(next).await;
        }
    }
}

/// Connections routinely end without close_notify, by reset or by timeout; logging each
/// one costs more CPU than a resumed handshake and floods the journal.
fn benign(error: &(dyn Error + 'static)) -> bool {
    use io::ErrorKind::*;
    error.is::<tokio::time::error::Elapsed>()
        || error.downcast_ref::<io::Error>().is_some_and(|error| {
            matches!(
                error.kind(),
                UnexpectedEof
                    | ConnectionReset
                    | ConnectionAborted
                    | BrokenPipe
                    | NotConnected
                    | TimedOut
            )
        })
}

/// A policy denial, already logged through `DENIALS`.
#[derive(Debug)]
struct Denied(String);
impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl Error for Denied {}

fn denied(reason: fmt::Arguments) -> Box<dyn Error + Send + Sync> {
    let reason = reason.to_string();
    DENIALS.log(format_args!("{reason}"));
    Box::new(Denied(reason))
}

/// At most one line per interval for per-connection events, counting the rest.
struct LogLimiter(Mutex<(Option<Instant>, u64)>);
impl LogLimiter {
    const fn new() -> Self {
        Self(Mutex::new((None, 0)))
    }
    /// Returns how many events were suppressed since the last allowed one.
    fn check(&self) -> Option<u64> {
        let now = Instant::now();
        let mut state = self.0.lock().unwrap();
        if state
            .0
            .is_some_and(|last| now.duration_since(last) < LOG_INTERVAL)
        {
            state.1 += 1;
            return None;
        }
        state.0 = Some(now);
        Some(std::mem::take(&mut state.1))
    }
    fn log(&self, message: fmt::Arguments) {
        match self.check() {
            Some(0) => eprintln!("{message}"),
            Some(suppressed) => eprintln!("{message} (+{suppressed} suppressed)"),
            None => {}
        }
    }
}

pub(crate) async fn reload_media_targets(
    cfg: &Config,
    base: &[SocketAddr],
    path: &std::path::Path,
) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let mut value = String::new();
    tokio::fs::File::open(path)
        .await?
        .take(16385)
        .read_to_string(&mut value)
        .await?;
    if value.len() > 16384 {
        bail!("media grant file exceeds 16 KiB");
    }
    let mut targets = parse_media_targets(&value)?;
    for target in base {
        if !targets.contains(target) {
            targets.push(*target);
        }
    }
    if targets.len() > 128 {
        bail!("at most 128 combined media targets are allowed");
    }
    cfg.media_targets.replace(targets);
    Ok(())
}

pub(crate) async fn handle_gateway_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    cfg: &Config,
    peer: IpAddr,
) -> Result<()> {
    // Scanners fail before authentication constantly, so those failures share one rate
    // limit; an authenticated session's failure is rare and always logged.
    let (stream, version) = open_gateway_connection(stream, cfg)
        .await
        .inspect_err(|error| {
            if !benign(&**error) {
                HANDSHAKE_ERRORS.log(format_args!("session: {error:#}"));
            }
        })?;
    serve_gateway_connection(stream, version, cfg, peer)
        .await
        .inspect_err(|error| {
            if !benign(&**error) && !error.is::<Denied>() {
                eprintln!("session: {error:#}");
            }
        })
}

/// TLS accept and DMPX authentication; returns the protocol version.
async fn open_gateway_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    cfg: &Config,
) -> Result<(TlsStream<S>, u8)> {
    let acceptor = cfg
        .server_tls
        .as_ref()
        .ok_or("gateway TLS is not configured")?;
    let mut stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS client handshake timed out")?
        .context("TLS client handshake")?;
    let version = tokio::time::timeout(
        AUTH_HANDSHAKE_TIMEOUT,
        authenticate_gateway(&mut stream, cfg),
    )
    .await
    .context("gateway authentication timed out")??;
    Ok((stream, version))
}

async fn serve_gateway_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: TlsStream<S>,
    version: u8,
    cfg: &Config,
    peer: IpAddr,
) -> Result<()> {
    match version {
        2 => session::serve_control(&mut stream, cfg.sessions.clone(), peer).await,
        3 => {
            let mut id = [0; 16];
            tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, stream.read_exact(&mut id)).await??;
            let session = match cfg.sessions.attach(id, peer) {
                Ok(session) => session,
                Err(error) => {
                    let _ = tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, stream.write_u8(0)).await;
                    return Err(error);
                }
            };
            tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, stream.write_u8(1)).await??;
            let mut stream = session::tracked_data(stream, &session);
            tokio::select! {
                biased;
                _ = session.cancel.cancelled() => Ok(()),
                result = handle_socks(&mut stream, cfg) => result,
            }
        }
        // Legacy clients have no control channel and retain per-tunnel expiry.
        1 => {
            let (mut stream, activity) = protection::ActivityStream::new(stream);
            protection::guard_idle(handle_socks(&mut stream, cfg), activity, cfg.sessions.idle)
                .await
        }
        _ => unreachable!(),
    }
}

async fn authenticate_gateway<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
) -> Result<u8> {
    let mut magic = [0u8; 5];
    stream.read_exact(&mut magic).await?;
    if &magic[..4] != b"DMPX" || !(1..=3).contains(&magic[4]) {
        bail!("invalid protocol header");
    }
    let token = read_string(stream).await?;
    if !cfg.token.is_empty()
        && (token.len() != cfg.token.len()
            || !bool::from(token.as_bytes().ct_eq(cfg.token.as_bytes())))
    {
        stream.write_all(&[0]).await?;
        bail!("invalid token");
    }
    stream.write_all(&[1]).await?;
    Ok(magic[4])
}

async fn handle_socks<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
) -> Result<()> {
    let connect = |host: String, port| async move { connect_destination(cfg, &host, port).await };
    handle_socks_with(stream, cfg, connect).await
}

/// `connect` opens an approved CONNECT destination, so tests can supply the upstream.
async fn handle_socks_with<S, T, F, C>(stream: &mut S, cfg: &Config, connect: F) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(String, u16) -> C,
    C: Future<Output = Result<Option<T>>>,
{
    let request = tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, async {
        let version = stream.read_u8().await?;
        if version != 5 {
            bail!("unsupported SOCKS version");
        }
        let nmethods = stream.read_u8().await? as usize;
        let mut methods = vec![0; nmethods];
        stream.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            stream.write_all(&[5, 0xff]).await?;
            bail!("SOCKS no-auth method required");
        }
        stream.write_all(&[5, 0]).await?;
        read_socks_request(stream).await
    })
    .await
    .context("SOCKS handshake timed out")??;
    let command = request[1];
    let (host, port) = socks_request_target(&request)?;
    if command == voice::SOCKS_VOICE_COMMAND {
        return voice::gateway::run(stream, cfg, &host, port).await;
    }
    if command == 1 {
        if !allowed_tcp_destination(&host, port) {
            reply(stream, 2).await?;
            deny!("SOCKS TCP destination denied: {host:?}:{port}");
        }
        let Some(mut target) = connect(host, port).await? else {
            reply(stream, 5).await?;
            bail!("Discord destination did not resolve to a reachable public address");
        };
        reply(stream, 0).await?;
        return relay_tls(stream, &mut target, port).await;
    }
    if command == 3 {
        let socket_v4 = UdpSocket::bind("0.0.0.0:0").await?;
        let socket_v6 = UdpSocket::bind("[::]:0").await.ok();
        let port = socket_v4.local_addr()?.port();
        reply_bound(stream, port).await?;
        return relay_udp_gateway(stream, socket_v4, socket_v6, cfg).await;
    }
    reply(stream, 7).await?;
    bail!("unsupported SOCKS command");
}

async fn connect_destination(cfg: &Config, host: &str, port: u16) -> Result<Option<TcpStream>> {
    for &ip in cfg.dns.resolve(host, port).await?.iter() {
        if let Ok(Ok(connection)) =
            tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, TcpStream::connect((ip, port))).await
        {
            connection.set_nodelay(true)?;
            return Ok(Some(connection));
        }
    }
    Ok(None)
}

/// Public addresses of allowlisted Discord names, shared by every session so most
/// connections skip the blocking-pool `getaddrinfo`.
#[derive(Default)]
pub(crate) struct DnsCache(Mutex<HashMap<Box<str>, DnsEntry>>);
type DnsEntry = (Instant, Arc<[IpAddr]>);
impl DnsCache {
    /// Failed and empty lookups are never cached.
    pub(crate) async fn resolve(&self, host: &str, port: u16) -> io::Result<Arc<[IpAddr]>> {
        self.resolve_with(host, || tokio::net::lookup_host((host, port)))
            .await
    }
    async fn resolve_with<F, L, A>(&self, host: &str, lookup: F) -> io::Result<Arc<[IpAddr]>>
    where
        F: FnOnce() -> L,
        L: Future<Output = io::Result<A>>,
        A: Iterator<Item = SocketAddr>,
    {
        // Spell the key the way the allowlist reads names, so case and trailing-dot
        // variants of one name cannot fill the cache.
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(addresses) = self.get(&key, Instant::now()) {
            return Ok(addresses);
        }
        let addresses: Arc<[IpAddr]> = tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, lookup())
            .await
            // A stalled resolver is an operator problem, so keep it out of the benign kinds.
            .map_err(|_| io::Error::other("destination DNS lookup timed out"))??
            .map(|address| address.ip())
            .filter(|ip| is_public_ip(*ip))
            .collect();
        if !addresses.is_empty() && allowed_destination(host) {
            self.insert(&key, addresses.clone(), Instant::now());
        }
        Ok(addresses)
    }
    fn get(&self, host: &str, now: Instant) -> Option<Arc<[IpAddr]>> {
        let entries = self.0.lock().unwrap();
        let (expires, addresses) = entries.get(host)?;
        (*expires > now).then(|| addresses.clone())
    }
    fn insert(&self, host: &str, addresses: Arc<[IpAddr]>, now: Instant) {
        let mut entries = self.0.lock().unwrap();
        if entries.len() >= DNS_CACHE_ENTRIES && !entries.contains_key(host) {
            entries.retain(|_, (expires, _)| *expires > now);
            if entries.len() >= DNS_CACHE_ENTRIES {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, (expires, _))| *expires)
                    .map(|(host, _)| host.clone());
                if let Some(oldest) = oldest {
                    entries.remove(&oldest);
                }
            }
        }
        entries.insert(host.into(), (now + DNS_CACHE_TTL, addresses));
    }
}

/// Relays a client TLS connection once its ClientHello names an allowed host. The SOCKS
/// reply comes first, so a route check that never speaks TLS still sees success.
async fn relay_tls<C, T>(client: &mut C, target: &mut T, port: u16) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let hello = tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, read_client_hello(client, port))
        .await
        .context("TLS ClientHello timed out")??;
    target.write_all(&hello).await?;
    drop(hello);
    tokio::io::copy_bidirectional_with_sizes(
        client,
        target,
        TCP_COPY_BUFFER_SIZE,
        TCP_COPY_BUFFER_SIZE,
    )
    .await?;
    Ok(())
}

// Discord names resolve to shared Cloudflare anycast addresses that route by SNI, so the
// approved SOCKS host name alone would let anyone reach any Cloudflare-hosted site.
async fn read_client_hello<S: AsyncRead + Unpin>(stream: &mut S, port: u16) -> Result<Vec<u8>> {
    let mut hello = Vec::new();
    let mut chunk = [0; 4096];
    let mut acceptor = Acceptor::default();
    loop {
        let room = CLIENT_HELLO_LIMIT - hello.len();
        if room == 0 {
            deny!("SOCKS TLS ClientHello too large (port {port})");
        }
        let limit = room.min(chunk.len());
        let read = stream.read(&mut chunk[..limit]).await?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        if hello.is_empty() && chunk[0] != 0x16 {
            deny!("SOCKS TCP stream is not TLS (port {port})");
        }
        hello.extend_from_slice(&chunk[..read]);
        let mut fresh = &chunk[..read];
        while !fresh.is_empty() {
            if !matches!(acceptor.read_tls(&mut fresh), Ok(1..)) {
                deny!("invalid SOCKS TLS record (port {port})");
            }
        }
        let accepted = match acceptor.accept() {
            Ok(None) => continue,
            Ok(Some(accepted)) => accepted,
            Err((error, _)) => {
                deny!("invalid SOCKS TLS ClientHello (port {port}): {error}");
            }
        };
        return match accepted.client_hello().server_name() {
            Some(name) if allowed_tcp_destination(name, port) => Ok(hello),
            name => deny!("SOCKS TLS server name denied: {name:?}:{port}"),
        };
    }
}

/// Only destinations an association recently sent to may answer it.
#[derive(Default)]
struct ReplyFilter(VecDeque<(SocketAddr, Instant)>);
impl ReplyFilter {
    fn sent(&mut self, destination: SocketAddr, now: Instant) {
        self.0.retain(|(peer, seen)| {
            *peer != destination && now.duration_since(*seen) <= REPLY_WINDOW
        });
        if self.0.len() >= REPLY_SOURCES {
            self.0.pop_front();
        }
        self.0.push_back((destination, now));
    }
    fn permits(&self, source: SocketAddr, now: Instant) -> bool {
        self.0
            .iter()
            .any(|(peer, seen)| *peer == source && now.duration_since(*seen) <= REPLY_WINDOW)
    }
}

async fn relay_udp_gateway<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    socket_v4: UdpSocket,
    socket_v6: Option<UdpSocket>,
    cfg: &Config,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer_v4 = vec![0; 1501];
    let mut buffer_v6 = vec![0; 1501];
    let mut replies = ReplyFilter::default();
    let mut frames = FrameReader::default();
    loop {
        let (length, source, is_v6) = tokio::select! {
            received = socket_v4.recv_from(&mut buffer_v4) => {
                let (length, source) = received?;
                (length, source, false)
            }
            received = receive_optional_udp(socket_v6.as_ref(), &mut buffer_v6) => {
                let (length, source) = received?;
                (length, source, true)
            }
            frame = frames.next(&mut reader) => {
                let sockets = (&socket_v4, socket_v6.as_ref());
                if let Some(destination) = send_udp_frame(frame?, sockets, cfg).await {
                    replies.sent(destination, Instant::now());
                }
                continue;
            }
        };
        if !replies.permits(source, Instant::now()) {
            continue;
        }
        let buffer = if is_v6 { &buffer_v6 } else { &buffer_v4 };
        forward_udp_response(&mut writer, source, &buffer[..length]).await?;
    }
}

/// Sends one client datagram and returns the destination that accepted it.
async fn send_udp_frame(
    packet: &[u8],
    sockets: (&UdpSocket, Option<&UdpSocket>),
    cfg: &Config,
) -> Option<SocketAddr> {
    let (host, port, payload) = parse_socks_udp(packet).ok()?;
    if payload.is_empty() {
        return None;
    }
    let ip = match host {
        Address::Ip(ip) => ip,
        Address::Domain(name) => match name.parse() {
            Ok(ip) => ip,
            Err(_) if allowed_destination(name) => {
                let addresses = cfg.dns.resolve(name, port).await.ok()?;
                for &ip in addresses.iter() {
                    let destination = SocketAddr::new(ip, port);
                    if send_granted(destination, payload, sockets, cfg).await {
                        return Some(destination);
                    }
                }
                return None;
            }
            Err(_) => return None,
        },
    };
    let destination = SocketAddr::new(ip, port);
    send_granted(destination, payload, sockets, cfg)
        .await
        .then_some(destination)
}

async fn send_granted(
    destination: SocketAddr,
    payload: &[u8],
    (socket_v4, socket_v6): (&UdpSocket, Option<&UdpSocket>),
    cfg: &Config,
) -> bool {
    // DNS resolution and prior TCP use never create UDP authority.
    if !allowed_udp_destination(cfg, destination) {
        return false;
    }
    let socket = match (destination, socket_v6) {
        (SocketAddr::V4(_), _) => socket_v4,
        (SocketAddr::V6(_), Some(socket)) => socket,
        (SocketAddr::V6(_), None) => return false,
    };
    socket.send_to(payload, destination).await.is_ok()
}

async fn receive_optional_udp(
    socket: Option<&UdpSocket>,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr)> {
    match socket {
        Some(socket) => socket.recv_from(buffer).await,
        None => std::future::pending().await,
    }
}

fn allowed_udp_destination(cfg: &Config, destination: SocketAddr) -> bool {
    is_public_ip(destination.ip()) && cfg.media_targets.contains(&destination)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        socks::read_socks_reply,
        test_config,
        tunnel::{proxy_socks, write_string},
    };
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    };
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn fixture_tls() -> (TlsAcceptor, Arc<ClientConfig>) {
        let certificate =
            CertificateDer::from(include_bytes!("../tests/fixtures/localhost-cert.der").to_vec());
        let private_key =
            PrivateKeyDer::try_from(include_bytes!("../tests/fixtures/localhost-key.der").to_vec())
                .unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                include_bytes!("../tests/fixtures/test-ca.der").to_vec(),
            ))
            .unwrap();
        (
            TlsAcceptor::from(Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(vec![certificate], private_key)
                    .unwrap(),
            )),
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ),
        )
    }

    fn client_hello(name: &str, sni: bool) -> Vec<u8> {
        let mut config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        config.enable_sni = sni;
        let name = ServerName::try_from(name.to_owned()).unwrap();
        let mut connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut hello = Vec::new();
        while connection.wants_write() {
            connection.write_tls(&mut hello).unwrap();
        }
        hello
    }

    /// Relays `sent` from a client that then disconnects; returns the relay result and
    /// everything the upstream received.
    async fn relay_first_bytes(sent: &[u8], port: u16, chunk: usize) -> (Result<()>, Vec<u8>) {
        let (mut client, mut gateway_client) = tokio::io::duplex(chunk);
        let (mut gateway_upstream, mut upstream) = tokio::io::duplex(64 * 1024);
        let relay = tokio::spawn(async move {
            relay_tls(&mut gateway_client, &mut gateway_upstream, port).await
        });
        let sent = sent.to_vec();
        tokio::spawn(async move { client.write_all(&sent).await });
        let mut received = Vec::new();
        upstream.read_to_end(&mut received).await.unwrap();
        drop(upstream);
        (relay.await.unwrap(), received)
    }

    #[tokio::test]
    async fn allowed_tls_server_name_is_forwarded_byte_for_byte() {
        for (name, port) in [
            ("discord.com", 443),
            ("c-lhr01.example.discord.media", 2053),
        ] {
            let mut sent = client_hello(name, true);
            sent.extend_from_slice(b"\x17\x03\x03\x00\x01X");
            let (result, received) = relay_first_bytes(&sent, port, 64 * 1024).await;
            assert!(result.is_ok(), "{name}: {result:?}");
            assert_eq!(received, sent, "{name}");
        }
    }

    #[tokio::test]
    async fn client_hello_split_across_many_reads_is_accepted() {
        let sent = client_hello("gateway.discord.gg", true);
        let (result, received) = relay_first_bytes(&sent, 443, 7).await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(received, sent);
    }

    #[tokio::test]
    async fn tls_to_a_non_discord_server_name_is_not_relayed() {
        for (sent, port) in [
            (client_hello("example.com", true), 443),
            (client_hello("discord.com.attacker.example", true), 443),
            (client_hello("discord.com", true), 2053),
            (client_hello("discord.com", false), 443),
            (b"GET / HTTP/1.1\r\nHost: discord.com\r\n\r\n".to_vec(), 443),
            (b"\x17\x03\x03\x00\x05hello".to_vec(), 443),
        ] {
            let (result, received) = relay_first_bytes(&sent, port, 64 * 1024).await;
            assert!(result.is_err(), "relayed {:?}", &sent[..8]);
            assert!(received.is_empty());
        }
    }

    #[tokio::test]
    async fn oversized_client_hello_is_rejected() {
        let mut sent = vec![0x16, 3, 1, 0x40, 0, 1, 0, 0xff, 0];
        sent.resize(5 + 0x4000, 0);
        sent.extend_from_slice(&[0x16, 3, 1, 0x40, 0]);
        sent.resize(sent.len() + 0x4000, 0);
        let (result, received) = relay_first_bytes(&sent, 443, 64 * 1024).await;
        assert!(result.unwrap_err().to_string().contains("too large"));
        assert!(received.is_empty());
    }

    /// Runs a SOCKS CONNECT to discord.com:443, reachable only if `upstream`, then sends
    /// `first` and disconnects; returns the result, the SOCKS reply and the upstream's bytes.
    async fn socks_connect(upstream: bool, first: Vec<u8>) -> (Result<()>, [u8; 10], Vec<u8>) {
        let (mut client, mut gateway) = tokio::io::duplex(64 * 1024);
        let (gateway_upstream, mut upstream_end) = tokio::io::duplex(64 * 1024);
        let socks = tokio::spawn(async move {
            let connect = |host: String, port| async move {
                assert_eq!((host.as_str(), port), ("discord.com", 443));
                Ok(upstream.then_some(gateway_upstream))
            };
            handle_socks_with(&mut gateway, &test_config(), connect).await
        });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"discord.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let reply = read_socks_reply(&mut client)
            .await
            .unwrap()
            .try_into()
            .unwrap();
        // A refused CONNECT closes the stream before this write.
        let _ = client.write_all(&first).await;
        drop(client);
        let mut received = Vec::new();
        upstream_end.read_to_end(&mut received).await.unwrap();
        drop(upstream_end);
        (socks.await.unwrap(), reply, received)
    }

    #[tokio::test]
    async fn socks_connect_relays_only_tls_for_an_allowed_server_name() {
        let hello = client_hello("discord.com", true);
        let (result, reply, received) = socks_connect(true, hello.clone()).await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(received, hello);

        let fronted = client_hello("example.com", true);
        let (result, reply, received) = socks_connect(true, fronted).await;
        assert!(result.unwrap_err().is::<Denied>());
        assert_eq!(reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(received.is_empty());

        let (result, reply, received) = socks_connect(false, hello).await;
        assert!(result.is_err());
        assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(received.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn accept_errors_back_off_without_stopping_the_gateway() {
        use io::ErrorKind::*;
        let mut results = VecDeque::from([
            Err(io::Error::other("too many open files")),
            Err(io::Error::from(OutOfMemory)),
            Err(io::Error::from(ConnectionAborted)),
            Err(io::Error::other("too many open files")),
            Err(io::Error::other("too many open files")),
            Err(io::Error::other("too many open files")),
            Err(io::Error::other("too many open files")),
            Ok(7),
        ]);
        let started = Instant::now();
        let accepted = next_connection(|| std::future::ready(results.pop_front().unwrap())).await;
        assert_eq!(accepted, 7);
        assert_eq!(started.elapsed(), Duration::from_millis(3500));
        let started = Instant::now();
        let mut results = VecDeque::from([Err(io::Error::from(ConnectionReset)), Ok(8)]);
        assert_eq!(
            next_connection(|| std::future::ready(results.pop_front().unwrap())).await,
            8
        );
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn disconnects_and_timeouts_are_not_logged_per_connection() {
        let (acceptor, client_tls) = fixture_tls();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server).await.unwrap();
            tls.write_u8(1).await.unwrap();
            tls.read_u8().await.unwrap_err()
        });
        let mut tls = TlsConnector::from(client_tls)
            .connect(ServerName::try_from("localhost").unwrap(), client)
            .await
            .unwrap();
        tls.read_u8().await.unwrap();
        drop(tls);
        let missing_close_notify: Box<dyn Error + Send + Sync> = server.await.unwrap().into();
        assert!(benign(&*missing_close_notify), "{missing_close_notify}");

        let (_client, mut control) = tokio::io::duplex(64);
        let registry = session::Registry::new(Duration::from_secs(600));
        let vanished = session::serve_control(&mut control, registry, [127, 0, 0, 1].into())
            .await
            .unwrap_err();
        assert!(benign(&*vanished), "{vanished}");

        let elapsed = || tokio::time::timeout(Duration::ZERO, std::future::pending::<()>());
        for error in [
            elapsed().await.unwrap_err().into(),
            elapsed()
                .await
                .context("TLS client handshake timed out")
                .unwrap_err(),
            io::Error::from(io::ErrorKind::ConnectionReset).into(),
            io::Error::from(io::ErrorKind::BrokenPipe).into(),
            Err::<(), _>(io::Error::from(io::ErrorKind::UnexpectedEof))
                .context("TLS client handshake")
                .unwrap_err(),
        ] {
            assert!(benign(&*error), "{error}");
        }
        for error in [
            Box::<dyn Error + Send + Sync>::from("invalid protocol header"),
            io::Error::from(io::ErrorKind::InvalidData).into(),
            Err::<(), _>(io::Error::other("corrupt message"))
                .context("TLS client handshake")
                .unwrap_err(),
        ] {
            assert!(!benign(&*error), "{error}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn repeated_log_lines_are_limited_and_counted() {
        let limiter = LogLimiter::new();
        assert_eq!(limiter.check(), Some(0));
        assert_eq!(limiter.check(), None);
        assert_eq!(limiter.check(), None);
        tokio::time::advance(LOG_INTERVAL - Duration::from_millis(1)).await;
        assert_eq!(limiter.check(), None);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(limiter.check(), Some(3));
        assert_eq!(limiter.check(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn missing_client_hello_times_out() {
        let (_client, mut gateway_client) = tokio::io::duplex(64);
        let (mut gateway_upstream, _upstream) = tokio::io::duplex(64);
        let error = relay_tls(&mut gateway_client, &mut gateway_upstream, 443)
            .await
            .unwrap_err();
        assert!(benign(&*error), "{error}");
    }

    #[test]
    fn udp_policy_requires_exact_current_operator_grant() {
        let cfg = test_config();
        let endpoint = "104.29.151.152:19317".parse().unwrap();
        assert!(!allowed_udp_destination(&cfg, endpoint));
        cfg.media_targets.replace(vec![endpoint]);
        assert!(allowed_udp_destination(&cfg, endpoint));
        assert!(!allowed_udp_destination(
            &cfg,
            "104.29.151.152:19318".parse().unwrap()
        ));
        assert!(!allowed_udp_destination(
            &cfg,
            "104.29.144.166:19317".parse().unwrap()
        ));
        cfg.media_targets.replace(Vec::new());
        assert!(!allowed_udp_destination(&cfg, endpoint));
        cfg.media_targets
            .replace(vec!["127.0.0.1:19317".parse().unwrap()]);
        assert!(!allowed_udp_destination(
            &cfg,
            "127.0.0.1:19317".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn media_grant_file_replaces_dynamic_endpoints_without_widening_ports() {
        let cfg = test_config();
        let base = ["8.8.8.8:1234".parse().unwrap()];
        let path = std::env::temp_dir().join(format!(
            "dinmoo-media-grants-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "104.29.151.152:19317").unwrap();
        reload_media_targets(&cfg, &base, &path).await.unwrap();
        assert!(cfg
            .media_targets
            .contains(&"104.29.151.152:19317".parse().unwrap()));
        std::fs::write(&path, "104.29.144.166:19307").unwrap();
        reload_media_targets(&cfg, &base, &path).await.unwrap();
        let targets = cfg.media_targets.snapshot();
        assert_eq!(*targets, ["104.29.144.166:19307".parse().unwrap(), base[0]]);
        std::fs::write(&path, "127.0.0.1:19307").unwrap();
        assert!(reload_media_targets(&cfg, &base, &path).await.is_err());
        assert_eq!(cfg.media_targets.snapshot(), targets);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn udp_replies_are_accepted_only_from_recent_destinations() {
        let now = Instant::now();
        let media: SocketAddr = "104.29.151.152:19317".parse().unwrap();
        let other: SocketAddr = "104.29.151.152:19318".parse().unwrap();
        let mut replies = ReplyFilter::default();
        assert!(!replies.permits(media, now));
        replies.sent(media, now);
        assert!(replies.permits(media, now + REPLY_WINDOW));
        assert!(!replies.permits(other, now));
        assert!(!replies.permits(media, now + REPLY_WINDOW + Duration::from_millis(1)));
        replies.sent(media, now + REPLY_WINDOW);
        assert!(replies.permits(media, now + 2 * REPLY_WINDOW));
        assert_eq!(replies.0.len(), 1);
    }

    #[test]
    fn udp_reply_filter_evicts_the_least_recently_used_destination() {
        let now = Instant::now();
        let target = |port: u16| SocketAddr::from(([104, 29, 151, 152], port));
        let mut replies = ReplyFilter::default();
        for port in 0..REPLY_SOURCES as u16 {
            replies.sent(target(port), now);
        }
        replies.sent(target(0), now);
        replies.sent(target(1000), now);
        assert_eq!(replies.0.len(), REPLY_SOURCES);
        assert!(replies.permits(target(0), now));
        assert!(!replies.permits(target(1), now));
        assert!(replies.permits(target(1000), now));
    }

    #[tokio::test]
    async fn dns_cache_serves_fresh_answers_without_a_lookup() {
        let cache = DnsCache::default();
        let now = Instant::now();
        let ip: IpAddr = "162.159.135.232".parse().unwrap();
        cache.insert("discord.com", Arc::from([ip]), now);
        assert_eq!(*cache.resolve("discord.com", 443).await.unwrap(), [ip]);
        assert!(cache
            .get(
                "discord.com",
                now + DNS_CACHE_TTL - Duration::from_millis(1)
            )
            .is_some());
        assert!(cache.get("discord.com", now + DNS_CACHE_TTL).is_none());
    }

    #[test]
    fn dns_cache_is_bounded_and_evicts_the_oldest_entry() {
        let cache = DnsCache::default();
        let now = Instant::now();
        let ip: Arc<[IpAddr]> = Arc::from(["162.159.135.232".parse::<IpAddr>().unwrap()]);
        for i in 0..DNS_CACHE_ENTRIES {
            let at = now + Duration::from_millis(i as u64);
            cache.insert(&format!("{i}.discord.com"), ip.clone(), at);
        }
        cache.insert("new.discord.com", ip.clone(), now + Duration::from_secs(1));
        assert_eq!(cache.0.lock().unwrap().len(), DNS_CACHE_ENTRIES);
        assert!(cache.get("0.discord.com", now).is_none());
        assert!(cache.get("1.discord.com", now).is_some());
        assert!(cache.get("new.discord.com", now).is_some());
    }

    type Answers = std::vec::IntoIter<SocketAddr>;

    fn answers(addresses: &[&str]) -> impl FnOnce() -> std::future::Ready<io::Result<Answers>> {
        let addresses: Vec<SocketAddr> = addresses.iter().map(|a| a.parse().unwrap()).collect();
        move || std::future::ready(Ok(addresses.into_iter()))
    }

    fn cached_lookup() -> std::future::Ready<io::Result<Answers>> {
        panic!("a cached name was looked up again")
    }

    #[tokio::test]
    async fn dns_cache_keeps_only_public_answers_for_allowlisted_names() {
        let cache = DnsCache::default();
        let public: IpAddr = "162.159.135.232".parse().unwrap();
        let failed = || std::future::ready(Err::<Answers, _>(io::Error::other("SERVFAIL")));
        assert!(cache.resolve_with("discord.com", failed).await.is_err());
        let private = answers(&["10.0.0.1:443", "127.0.0.1:443"]);
        assert!(cache
            .resolve_with("discord.com", private)
            .await
            .unwrap()
            .is_empty());
        let outside = answers(&["93.184.215.14:443"]);
        assert_eq!(
            cache
                .resolve_with("example.com", outside)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(cache.0.lock().unwrap().is_empty());

        let mixed = answers(&["10.0.0.1:443", "162.159.135.232:443"]);
        assert_eq!(
            *cache.resolve_with("discord.com", mixed).await.unwrap(),
            [public]
        );
        assert_eq!(
            *cache
                .resolve_with("discord.com", cached_lookup)
                .await
                .unwrap(),
            [public]
        );
    }

    #[tokio::test]
    async fn dns_cache_spellings_of_one_name_share_an_entry() {
        let cache = DnsCache::default();
        let mixed = answers(&["162.159.135.232:443"]);
        cache.resolve_with("Discord.COM.", mixed).await.unwrap();
        for host in ["discord.com", "DISCORD.com..", "discord.COM"] {
            cache.resolve_with(host, cached_lookup).await.unwrap();
        }
        assert_eq!(cache.0.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn local_client_forwards_gateway_destination_denial() {
        let (mut application, mut client_local) = tokio::io::duplex(4096);
        let (mut client_tunnel, mut gateway_tunnel) = tokio::io::duplex(4096);
        let config = test_config();

        let client_task =
            tokio::spawn(async move { proxy_socks(&mut client_local, &mut client_tunnel).await });
        let gateway_task =
            tokio::spawn(async move { handle_socks(&mut gateway_tunnel, &config).await });

        application.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        application.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let mut request = vec![5, 1, 0, 3, 12];
        request.extend_from_slice(b"evil.example");
        request.extend_from_slice(&443u16.to_be_bytes());
        application.write_all(&request).await.unwrap();
        let reply = read_socks_reply(&mut application).await.unwrap();
        assert_eq!(reply, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);

        client_task.await.unwrap().unwrap();
        assert!(gateway_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn loopback_gateway_serves_buffered_tls_sessions() {
        let (server_tls, client_tls) = fixture_tls();
        let mut config = test_config();
        config.token.clear();
        config.server_tls = Some(server_tls);
        config.listen = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let listen = config.listen;
        let settings = protection::Settings {
            per_ip: 8,
            per_minute: 120,
            idle: Duration::from_secs(60),
        };
        let gateway = tokio::spawn(serve(Arc::new(config), settings, 8));
        let tcp = loop {
            match TcpStream::connect(listen).await {
                Ok(tcp) => break tcp,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        let mut tls = TlsConnector::from(client_tls)
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(b"DMPX\x01").await.unwrap();
        write_string(&mut tls, "").await.unwrap();
        assert_eq!(tls.read_u8().await.unwrap(), 1);
        tls.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        tls.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 12];
        request.extend_from_slice(b"evil.example");
        request.extend_from_slice(&443u16.to_be_bytes());
        tls.write_all(&request).await.unwrap();
        assert_eq!(
            read_socks_reply(&mut tls).await.unwrap(),
            [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        gateway.abort();
    }

    #[tokio::test]
    async fn public_gateway_accepts_a_client_without_a_token() {
        let mut config = test_config();
        config.token.clear();
        let (mut client, mut gateway) = tokio::io::duplex(256);
        let gateway_task =
            tokio::spawn(async move { authenticate_gateway(&mut gateway, &config).await });
        client.write_all(b"DMPX\x01").await.unwrap();
        write_string(&mut client, "").await.unwrap();
        let mut response = [0];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        gateway_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn gateway_authenticates_the_configured_tunnel_token() {
        let config = test_config();
        let (mut client, mut gateway) = tokio::io::duplex(256);
        let gateway_task =
            tokio::spawn(async move { authenticate_gateway(&mut gateway, &config).await });

        client.write_all(b"DMPX\x01").await.unwrap();
        write_string(&mut client, "test-token-for-in-memory-protocol")
            .await
            .unwrap();
        let mut response = [0];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        gateway_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn gateway_rejects_a_wrong_tunnel_token() {
        let config = test_config();
        let (mut client, mut gateway) = tokio::io::duplex(256);
        let gateway_task =
            tokio::spawn(async move { authenticate_gateway(&mut gateway, &config).await });

        client.write_all(b"DMPX\x01").await.unwrap();
        write_string(&mut client, "not-the-configured-token")
            .await
            .unwrap();
        let mut response = [0];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [0]);
        assert!(gateway_task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn tls_public_gateway_accepts_tokenless_client_and_enforces_socks_policy() {
        let (server_tls, client_tls) = fixture_tls();
        let mut config = test_config();
        config.token.clear();
        config.server_tls = Some(server_tls);
        config.client_tls = client_tls.clone();

        let (mut application, client_local) = tokio::io::duplex(4096);
        let (client_tunnel, gateway_tunnel) = tokio::io::duplex(64 * 1024);
        let gateway_config = config.clone();
        let gateway_task = tokio::spawn(async move {
            handle_gateway_connection(
                gateway_tunnel,
                &gateway_config,
                "127.0.0.1".parse().unwrap(),
            )
            .await
        });

        let server_name = ServerName::try_from("localhost".to_owned()).unwrap();
        let mut secure_tunnel = TlsConnector::from(client_tls)
            .connect(server_name, client_tunnel)
            .await
            .unwrap();
        secure_tunnel.write_all(b"DMPX\x01").await.unwrap();
        write_string(&mut secure_tunnel, &config.token)
            .await
            .unwrap();
        let mut authenticated = [0];
        secure_tunnel.read_exact(&mut authenticated).await.unwrap();
        assert_eq!(authenticated, [1]);

        let client_task = tokio::spawn(async move {
            let mut local = client_local;
            proxy_socks(&mut local, &mut secure_tunnel).await
        });
        application.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        application.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 12];
        request.extend_from_slice(b"evil.example");
        request.extend_from_slice(&443u16.to_be_bytes());
        application.write_all(&request).await.unwrap();
        let reply = read_socks_reply(&mut application).await.unwrap();
        assert_eq!(reply, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);

        client_task.await.unwrap().unwrap();
        assert!(gateway_task.await.unwrap().is_err());
    }
}

//! Local SOCKS client data path: authenticated gateway tunnels and request forwarding.
use crate::{
    policy::allowed_tcp_destination,
    session,
    socks::{read_socks_reply, read_socks_request, reply, socks_request_target},
    udp::{valid_socks_udp_packet, write_frame, FrameReader},
    voice, Config, ContextExt, Result, AUTH_HANDSHAKE_TIMEOUT, DESTINATION_CONNECT_TIMEOUT,
    SOCKS_HANDSHAKE_TIMEOUT, TCP_COPY_BUFFER_SIZE, TLS_HANDSHAKE_TIMEOUT,
};
use rustls::pki_types::ServerName;
use std::{
    error::Error,
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpStream, UdpSocket},
    sync::Mutex,
    time::Instant,
};
use tokio_rustls::TlsConnector;

// rustls reads at most 4 KiB per call; buffering saves syscalls on large records.
const GATEWAY_READ_BUFFER: usize = 16 * 1024;
const GATEWAY_ADDRESS_TTL: Duration = Duration::from_secs(60);

pub(crate) type GatewayStream = tokio_rustls::client::TlsStream<BufReader<TcpStream>>;

/// The gateway refused a data tunnel's session ID, so the client session is gone.
#[derive(Debug)]
pub(crate) struct AttachRejected;
impl fmt::Display for AttachRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("gateway rejected the client session")
    }
}
impl Error for AttachRejected {}

/// Gateway endpoint shared by the control and data tunnels.
pub(crate) struct Gateway {
    host: String,
    port: u16,
    name: ServerName<'static>,
    tls: TlsConnector,
    token: String,
    resolved: Mutex<Option<(Instant, Arc<[SocketAddr]>)>>,
}

impl Gateway {
    pub(crate) fn new(cfg: &Config) -> Result<Self> {
        let upstream = cfg
            .upstream
            .as_deref()
            .ok_or("gateway endpoint not configured")?;
        let (host, port) = upstream
            .rsplit_once(':')
            .ok_or("gateway must be host:port")?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        Ok(Self {
            host: host.to_owned(),
            port: port.parse()?,
            name: ServerName::try_from(host.to_owned())?,
            tls: TlsConnector::from(cfg.client_tls.clone()),
            token: cfg.token.clone(),
            resolved: Mutex::new(None),
        })
    }

    async fn addresses(&self) -> Result<Arc<[SocketAddr]>> {
        let mut resolved = self.resolved.lock().await;
        if let Some((at, addresses)) = &*resolved {
            if at.elapsed() < GATEWAY_ADDRESS_TTL {
                return Ok(addresses.clone());
            }
        }
        let addresses: Arc<[SocketAddr]> = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .context("resolve gateway")?
            .collect();
        if addresses.is_empty() {
            bail!("gateway name resolved to no addresses");
        }
        *resolved = Some((Instant::now(), addresses.clone()));
        Ok(addresses)
    }

    pub(crate) async fn connect(&self) -> Result<GatewayStream> {
        let connected = tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, async {
            let addresses = self.addresses().await?;
            TcpStream::connect(&addresses[..])
                .await
                .context("connect gateway")
        })
        .await
        .unwrap_or_else(|_| Err("gateway connection timed out".into()));
        let remote = match connected {
            Ok(remote) => remote,
            Err(error) => {
                *self.resolved.lock().await = None;
                return Err(error);
            }
        };
        remote.set_nodelay(true)?;
        let remote = BufReader::with_capacity(GATEWAY_READ_BUFFER, remote);
        tokio::time::timeout(
            TLS_HANDSHAKE_TIMEOUT,
            self.tls.connect(self.name.clone(), remote),
        )
        .await
        .context("TLS gateway handshake timed out")?
        .context("TLS gateway handshake")
    }

    async fn hello(&self, version: u8) -> Result<Vec<u8>> {
        let mut hello = vec![b'D', b'M', b'P', b'X', version];
        write_string(&mut hello, &self.token).await?;
        Ok(hello)
    }

    /// Opens an authenticated control session and returns its ID.
    pub(crate) async fn control(&self) -> Result<(GatewayStream, session::Id)> {
        let mut remote = self.connect().await?;
        let hello = self.hello(2).await?;
        let mut id = [0; 16];
        tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, async {
            remote.write_all(&hello).await?;
            remote.flush().await?;
            if remote.read_u8().await? != 1 {
                bail!("gateway rejected authentication");
            }
            remote.read_exact(&mut id).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .await
        .context("gateway authentication timed out")??;
        Ok((remote, id))
    }
}

pub(crate) async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    cfg: Arc<Config>,
    gateway: Arc<Gateway>,
    session_id: session::Id,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let local = stream.local_addr()?;
    let mut hello = gateway.hello(3).await?;
    hello.extend_from_slice(&session_id);
    relay(
        &mut stream,
        || gateway.connect(),
        Some(hello),
        cfg.voice_identity.as_deref(),
        || crate::peer::verify_voice_peer(peer, local),
    )
    .await
}

#[cfg(test)]
pub(crate) async fn proxy_socks<L, R>(local: &mut L, remote: &mut R) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    relay(
        local,
        || async { Ok(remote) },
        None,
        None,
        || async { false },
    )
    .await
}

/// Serves one local SOCKS connection. The app's greeting and request are handled
/// locally first, so `hello` (data tunnel header and session ID), a SOCKS greeting
/// and the request reach the gateway in one write. Gateways read them in order.
async fn relay<L, R, C, CF, V, VF>(
    local: &mut L,
    connect: C,
    hello: Option<Vec<u8>>,
    voice_identity: Option<&voice::identity::Store>,
    verify_peer: V,
) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
    C: FnOnce() -> CF,
    CF: Future<Output = Result<R>>,
    V: FnOnce() -> VF,
    VF: Future<Output = bool>,
{
    let mut request = tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, read_local_request(local))
        .await
        .context("SOCKS handshake timed out")??;
    let command = request[1];
    let (host, port) = socks_request_target(&request)?;
    if command != 1 && command != 3 {
        reply(local, 7).await?;
        return Ok(());
    }
    let mut udp_source = None;
    if command == 3 {
        let Some(declared) = declared_udp_source(&host, port) else {
            reply(local, 2).await?;
            return Ok(());
        };
        udp_source = Some(declared);
    }
    let mut identity = None;
    if let Some(store) = voice_identity.filter(|_| command == 1 && voice::allowed_host(&host)) {
        if !allowed_tcp_destination(&host, port) {
            reply(local, 2).await?;
            return Ok(());
        }
        // The local certificate is revealed only to a verified peer.
        match store.current().await {
            Ok(current) if verify_peer().await => identity = Some(current),
            Ok(_) => eprintln!("voice peer check failed; plain tunnel to {host}:{port}"),
            Err(error) => {
                eprintln!("voice bridge unavailable; plain tunnel to {host}:{port}: {error}")
            }
        }
    }
    if identity.is_some() {
        request[1] = voice::SOCKS_VOICE_COMMAND;
    }
    let attach = hello.is_some();
    let mut message = hello.unwrap_or_default();
    message.extend_from_slice(&[5, 1, 0]);
    message.extend_from_slice(&request);
    let opened = async {
        let mut remote = connect().await?;
        remote.write_all(&message).await?;
        remote.flush().await?;
        if attach {
            tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, read_attach(&mut remote))
                .await
                .context("data session handshake timed out")??;
        }
        let mut method = [0; 2];
        tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, remote.read_exact(&mut method))
            .await
            .context("SOCKS handshake timed out")??;
        if method != [5, 0] {
            bail!("gateway did not accept SOCKS no-auth method");
        }
        let response = read_socks_reply(&mut remote).await?;
        Ok::<_, Box<dyn Error + Send + Sync>>((remote, response))
    }
    .await;
    let (mut remote, response) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            let _ = reply(local, 1).await;
            return Err(error);
        }
    };
    if response[1] != 0 {
        local.write_all(&response).await?;
        return Ok(());
    }
    if let Some(declared) = udp_source {
        return proxy_udp_associate(local, &mut remote, declared).await;
    }
    local.write_all(&response).await?;
    if let Some(identity) = identity {
        return voice::local::run(local, &mut remote, &identity, &host, port).await;
    }
    tokio::io::copy_bidirectional_with_sizes(
        local,
        &mut remote,
        TCP_COPY_BUFFER_SIZE,
        TCP_COPY_BUFFER_SIZE,
    )
    .await?;
    Ok(())
}

async fn read_local_request<L: AsyncRead + AsyncWrite + Unpin>(local: &mut L) -> Result<Vec<u8>> {
    let mut greeting = [0; 2];
    local.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        bail!("unsupported SOCKS version");
    }
    let mut methods = vec![0; greeting[1] as usize];
    local.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        local.write_all(&[5, 0xff]).await?;
        bail!("SOCKS no-auth method required");
    }
    local.write_all(&[5, 0]).await?;
    read_socks_request(local).await
}

async fn read_attach<R: AsyncRead + Unpin>(remote: &mut R) -> Result<()> {
    if remote.read_u8().await? != 1 {
        bail!("gateway rejected authentication");
    }
    match remote.read_u8().await? {
        1 => Ok(()),
        0 => Err(AttachRejected.into()),
        _ => bail!("invalid gateway data session status"),
    }
}

/// The source a UDP ASSOCIATE request declares, if any datagram could come from
/// it: the relay listens on 127.0.0.1, so only IPv4 loopback or zeros can match.
fn declared_udp_source(host: &str, port: u16) -> Option<SocketAddr> {
    let ip = match host.parse::<IpAddr>() {
        Ok(ip) => ip.to_canonical(),
        Err(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let deliverable = ip.is_unspecified() || matches!(ip, IpAddr::V4(ip) if ip.is_loopback());
    deliverable.then_some(SocketAddr::new(ip, port))
}

/// Relays one UDP association. RFC 1928 section 6 lets the client declare the
/// address it will send from, with zeros when it does not know it yet; zero parts
/// match any loopback sender, and the first valid matching sender is pinned.
/// `declared` comes from `declared_udp_source`.
async fn proxy_udp_associate<L, R>(
    local: &mut L,
    remote: &mut R,
    declared: SocketAddr,
) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let SocketAddr::V4(relay) = socket.local_addr()? else {
        bail!("UDP relay must be IPv4");
    };
    local.write_all(&bound_reply(relay)).await?;

    let admits = |source: SocketAddr| {
        source.ip().is_loopback()
            && (declared.ip().is_unspecified() || source.ip() == declared.ip())
            && (declared.port() == 0 || source.port() == declared.port())
    };
    let mut peer = (declared.port() != 0 && admits(declared)).then_some(declared);
    let (mut reader, mut writer) = tokio::io::split(remote);
    let mut datagram = vec![0; 1501];
    let mut frames = FrameReader::default();
    let mut control = [0u8; 1];
    loop {
        tokio::select! {
            result = local.read(&mut control) => {
                result?;
                return Ok(());
            }
            result = socket.recv_from(&mut datagram) => {
                let (length, source) = result?;
                let packet = &datagram[..length];
                let accepted = admits(source)
                    && valid_socks_udp_packet(packet)
                    && *peer.get_or_insert(source) == source;
                if accepted {
                    write_frame(&mut writer, packet).await?;
                }
            }
            result = frames.read(&mut reader) => {
                let frame = result?;
                if let Some(peer) = peer {
                    socket.send_to(&frame, peer).await?;
                }
            }
        }
    }
}

fn bound_reply(address: SocketAddrV4) -> [u8; 10] {
    let [a, b, c, d] = address.ip().octets();
    let [high, low] = address.port().to_be_bytes();
    [5, 0, 0, 1, a, b, c, d, high, low]
}

pub(crate) async fn write_string<S: AsyncWrite + Unpin>(s: &mut S, value: &str) -> Result<()> {
    let n = u16::try_from(value.len())?;
    s.write_u16(n).await?;
    s.write_all(value.as_bytes()).await?;
    Ok(())
}
pub(crate) async fn read_string<S: AsyncRead + Unpin>(s: &mut S) -> Result<String> {
    let n = s.read_u16().await? as usize;
    if n > 1024 {
        bail!("invalid protocol string length");
    }
    let mut b = vec![0; n];
    s.read_exact(&mut b).await?;
    Ok(String::from_utf8(b)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::encode_socks_udp_packet;
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer},
        ClientConfig, RootCertStore, ServerConfig,
    };
    use std::{
        io,
        path::PathBuf,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::{
        io::{DuplexStream, ReadBuf},
        net::TcpListener,
        task::JoinHandle,
    };
    use tokio_rustls::TlsAcceptor;

    fn temporary_directory(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dinmoo-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn fixture_tls() -> (TlsAcceptor, Arc<ClientConfig>) {
        let certificate =
            CertificateDer::from(include_bytes!("../tests/fixtures/localhost-cert.der").to_vec());
        let key =
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
                    .with_single_cert(vec![certificate], key)
                    .unwrap(),
            )),
            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ),
        )
    }

    fn client_config(upstream: &str) -> Config {
        let mut cfg = crate::test_config();
        cfg.upstream = Some(upstream.into());
        cfg
    }

    fn connect_request(host: &str, port: u16) -> Vec<u8> {
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    async fn socks<S: AsyncRead + AsyncWrite + Unpin>(app: &mut S, request: &[u8]) -> Vec<u8> {
        app.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        app.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        app.write_all(request).await.unwrap();
        read_socks_reply(app).await.unwrap()
    }

    /// Records each write so a test can see which bytes left together.
    struct Recorder<S> {
        inner: S,
        writes: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }
    impl<S: AsyncRead + Unpin> AsyncRead for Recorder<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
    impl<S: AsyncWrite + Unpin> AsyncWrite for Recorder<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let result = Pin::new(&mut self.inner).poll_write(cx, buf);
            if let Poll::Ready(Ok(written)) = result {
                self.writes.lock().unwrap().push(buf[..written].to_vec());
            }
            result
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn pipelined_data_tunnels_work_with_the_gateway_over_tls() {
        let (acceptor, client_tls) = fixture_tls();
        let mut server = crate::test_config();
        server.server_tls = Some(acceptor);
        let server = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept_config = server.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = listener.accept().await.unwrap();
                let cfg = accept_config.clone();
                tokio::spawn(async move {
                    let _ =
                        crate::gateway::handle_gateway_connection(stream, &cfg, peer.ip()).await;
                });
            }
        });
        let mut client = client_config(&format!("localhost:{port}"));
        client.client_tls = client_tls;
        let client = Arc::new(client);
        let gateway = Arc::new(Gateway::new(&client).unwrap());
        let (_control, id) = gateway.control().await.unwrap();
        assert_eq!(server.sessions.list().len(), 1);

        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = |id: session::Id| {
            let (local, client, gateway) = (&local, client.clone(), gateway.clone());
            async move {
                let app = TcpStream::connect(local.local_addr().unwrap())
                    .await
                    .unwrap();
                let (stream, peer) = local.accept().await.unwrap();
                let tunnel: JoinHandle<Result<()>> =
                    tokio::spawn(handle(stream, peer, client, gateway, id));
                (app, tunnel)
            }
        };

        // A 0.2.5 gateway reads the header, session ID, greeting and request in order.
        let (mut app, tunnel) = open(id).await;
        let reply = socks(&mut app, &connect_request("evil.example", 443)).await;
        assert_eq!(reply, [5, 2, 0, 1, 0, 0, 0, 0, 0, 0]);
        tunnel.await.unwrap().unwrap();

        let (mut app, tunnel) = open(id).await;
        let reply = socks(&mut app, &[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        assert_eq!(reply[..8], [5, 0, 0, 1, 127, 0, 0, 1]);
        assert_ne!(u16::from_be_bytes([reply[8], reply[9]]), 0);
        drop(app);
        tunnel.await.unwrap().unwrap();

        let (mut app, tunnel) = open([0; 16]).await;
        let reply = socks(&mut app, &connect_request("discord.com", 443)).await;
        assert_eq!(reply, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert!(tunnel.await.unwrap().unwrap_err().is::<AttachRejected>());
        assert!(gateway.resolved.lock().await.is_some());
    }

    #[tokio::test]
    async fn voice_request_uses_a_plain_tunnel_when_the_peer_check_fails() {
        let directory = temporary_directory("voice-peer-fallback");
        let store = voice::identity::Store::open(directory.clone()).unwrap();
        let (mut app, mut local) = tokio::io::duplex(64 * 1024);
        let (remote, mut gateway) = tokio::io::duplex(64 * 1024);
        let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let remote = Recorder {
            inner: remote,
            writes: writes.clone(),
        };
        let mut hello = b"DMPX\x03".to_vec();
        write_string(&mut hello, "test-token-for-in-memory-protocol")
            .await
            .unwrap();
        hello.extend_from_slice(&[7; 16]);
        let attach = hello.clone();
        let relay = tokio::spawn(async move {
            relay(
                &mut local,
                || async { Ok(remote) },
                Some(attach),
                Some(&store),
                || async { false },
            )
            .await
        });

        let request = connect_request("voice.discord.media", 443);
        app.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        app.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        app.write_all(&request).await.unwrap();
        let mut expected = hello;
        expected.extend_from_slice(&[5, 1, 0]);
        expected.extend_from_slice(&request);
        let mut received = vec![0; expected.len()];
        gateway.read_exact(&mut received).await.unwrap();
        assert_eq!(
            received, expected,
            "original CONNECT, not the voice command"
        );
        assert_eq!(
            writes.lock().unwrap()[0],
            expected,
            "one write per handshake"
        );
        gateway
            .write_all(&[1, 1, 5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        assert_eq!(
            read_socks_reply(&mut app).await.unwrap(),
            [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        // No local TLS: the app's bytes reach the gateway unchanged.
        app.write_all(b"\x16\x03\x01client hello").await.unwrap();
        let mut forwarded = [0; 15];
        gateway.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(&forwarded, b"\x16\x03\x01client hello");
        drop(app);
        drop(gateway);
        relay.await.unwrap().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn voice_socks_request_upgrades_to_pinned_local_websocket_bridge() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::protocol::Message;

        let directory = temporary_directory("voice-client-pipeline");
        let store = voice::identity::Store::open(directory.clone()).unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(voice::identity::certificate_der(
                &directory,
            )))
            .unwrap();
        let client_tls = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        let (mut app, mut local) = tokio::io::duplex(64 * 1024);
        let (remote, mut gateway) = tokio::io::duplex(64 * 1024);
        let bridge = tokio::spawn(async move {
            relay(
                &mut local,
                || async { Ok(remote) },
                None,
                Some(&store),
                || async { true },
            )
            .await
        });
        let host = "voice.discord.media";
        app.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 2];
        app.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        app.write_all(&connect_request(host, 443)).await.unwrap();
        let mut greeting = [0; 3];
        gateway.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        let forwarded = read_socks_request(&mut gateway).await.unwrap();
        assert_eq!(forwarded[1], voice::SOCKS_VOICE_COMMAND);
        assert_eq!(
            socks_request_target(&forwarded).unwrap(),
            (host.into(), 443)
        );
        gateway
            .write_all(&[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        assert_eq!(
            read_socks_reply(&mut app).await.unwrap(),
            [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        );

        let tls = TlsConnector::from(client_tls)
            .connect(ServerName::try_from(host).unwrap(), app)
            .await
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async("wss://voice.discord.media/?v=8", tls)
            .await
            .unwrap();
        let mut gateway_wire = voice::wire::framed(gateway);
        let path = gateway_wire.next().await.unwrap().unwrap();
        assert_eq!(
            voice::wire::unpack(&path).unwrap(),
            (voice::wire::PATH, b"/?v=8".as_slice())
        );
        gateway_wire
            .send(voice::wire::record(voice::wire::CLOSE, &[]))
            .await
            .unwrap();
        assert!(matches!(
            ws.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));
        assert!(bridge.await.unwrap().is_ok());
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Runs one local connection whose bytes are all sent up front; the gateway
    /// must never be contacted. Returns everything the app received before EOF.
    async fn answered_locally(sent: &[u8]) -> (Vec<u8>, Result<()>) {
        let (mut app, mut local) = tokio::io::duplex(1024);
        app.write_all(sent).await.unwrap();
        let result = relay(
            &mut local,
            || -> std::future::Ready<Result<DuplexStream>> { panic!("gateway contacted") },
            None,
            None,
            || async { false },
        )
        .await;
        drop(local);
        let mut received = Vec::new();
        app.read_to_end(&mut received).await.unwrap();
        (received, result)
    }

    #[tokio::test]
    async fn apps_without_no_auth_are_refused_locally() {
        let (received, result) = answered_locally(&[5, 1, 2]).await;
        assert_eq!(received, [5, 0xff]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn unsupported_and_internal_commands_are_refused_locally() {
        for command in [2, voice::SOCKS_VOICE_COMMAND] {
            let mut request = connect_request("voice.discord.media", 443);
            request[1] = command;
            let (received, result) = answered_locally(&[&[5, 1, 0], &request[..]].concat()).await;
            assert_eq!(received, [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0], "{command}");
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn udp_association_from_an_undeliverable_address_is_refused() {
        // The relay listens on 127.0.0.1, so these senders could never match.
        for declared in ["192.168.1.5:5000", "[::1]:5000", "[::ffff:10.0.0.1]:0"] {
            let mut request = encode_socks_udp_packet(declared.parse().unwrap(), &[]);
            request[..2].copy_from_slice(&[5, 3]);
            let (received, result) = answered_locally(&[&[5, 1, 0], &request[..]].concat()).await;
            assert_eq!(received, [5, 0, 5, 2, 0, 1, 0, 0, 0, 0, 0, 0], "{declared}");
            result.unwrap();
        }
    }

    /// Opens a UDP association declaring `declared` against a fake gateway.
    async fn associate(
        declared: SocketAddr,
    ) -> (
        DuplexStream,
        DuplexStream,
        SocketAddr,
        JoinHandle<Result<()>>,
    ) {
        let (mut app, mut local) = tokio::io::duplex(4096);
        let (mut remote, mut gateway) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { proxy_socks(&mut local, &mut remote).await });
        let mut request = encode_socks_udp_packet(declared, &[]);
        request[..2].copy_from_slice(&[5, 3]);
        gateway
            .write_all(&[5, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let reply = socks(&mut app, &request).await;
        let mut forwarded = vec![0; 3 + request.len()];
        gateway.read_exact(&mut forwarded).await.unwrap();
        assert_eq!(forwarded, [&[5, 1, 0], &request[..]].concat());
        let (host, port) = socks_request_target(&reply).unwrap();
        (
            app,
            gateway,
            SocketAddr::new(host.parse().unwrap(), port),
            task,
        )
    }

    const UDP_WAIT: Duration = Duration::from_secs(5);

    fn media(payload: &[u8]) -> Vec<u8> {
        encode_socks_udp_packet("104.29.151.152:19317".parse().unwrap(), payload)
    }

    async fn received(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buffer = [0; 1500];
        let (length, source) = tokio::time::timeout(UDP_WAIT, socket.recv_from(&mut buffer))
            .await
            .expect("no datagram from the relay")
            .unwrap();
        (buffer[..length].to_vec(), source)
    }

    async fn frame(frames: &mut FrameReader, gateway: &mut DuplexStream) -> Vec<u8> {
        tokio::time::timeout(UDP_WAIT, frames.read(gateway))
            .await
            .expect("no frame from the relay")
            .unwrap()
    }

    #[tokio::test]
    async fn udp_association_accepts_only_the_declared_loopback_sender() {
        let app_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (app, mut gateway, relay, task) = associate(app_udp.local_addr().unwrap()).await;
        let mut frames = FrameReader::default();
        assert!(relay.ip().is_loopback() && relay.port() != 0);

        // The declared sender receives gateway frames before it sends anything.
        write_frame(&mut gateway, &media(b"first reply"))
            .await
            .unwrap();
        assert_eq!(received(&app_udp).await, (media(b"first reply"), relay));
        stranger.send_to(&media(b"stranger"), relay).await.unwrap();
        app_udp.send_to(&media(b"app"), relay).await.unwrap();
        stranger.send_to(&media(b"stranger"), relay).await.unwrap();
        app_udp.send_to(&media(b"app again"), relay).await.unwrap();
        assert_eq!(frame(&mut frames, &mut gateway).await, media(b"app"));
        assert_eq!(frame(&mut frames, &mut gateway).await, media(b"app again"));
        drop(app);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_association_without_a_declared_sender_pins_the_first_valid_one() {
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (app, mut gateway, relay, task) = associate("0.0.0.0:0".parse().unwrap()).await;
        let mut frames = FrameReader::default();
        first.send_to(b"not socks", relay).await.unwrap();
        second.send_to(&media(b"second"), relay).await.unwrap();
        first.send_to(&media(b"first"), relay).await.unwrap();
        second
            .send_to(&media(b"second again"), relay)
            .await
            .unwrap();
        assert_eq!(frame(&mut frames, &mut gateway).await, media(b"second"));
        assert_eq!(
            frame(&mut frames, &mut gateway).await,
            media(b"second again")
        );
        write_frame(&mut gateway, &media(b"reply")).await.unwrap();
        assert_eq!(received(&second).await, (media(b"reply"), relay));
        drop(app);
        task.await.unwrap().unwrap();
    }

    #[test]
    fn gateway_endpoint_keeps_the_host_name_for_tls() {
        for (endpoint, host, port) in [
            ("api-proxy.dinmoo.com:443", "api-proxy.dinmoo.com", 443),
            ("[::1]:8443", "::1", 8443),
            ("127.0.0.1:443", "127.0.0.1", 443),
        ] {
            let gateway = Gateway::new(&client_config(endpoint)).unwrap();
            assert_eq!((gateway.host.as_str(), gateway.port), (host, port));
            assert_eq!(gateway.name, ServerName::try_from(host.to_owned()).unwrap());
        }
        for endpoint in ["api-proxy.dinmoo.com", "[::1]", "localhost:https"] {
            assert!(
                Gateway::new(&client_config(endpoint)).is_err(),
                "{endpoint}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn gateway_addresses_are_reused_until_a_minute_passes_or_a_connect_fails() {
        // Nothing listens on port 1, so connecting fails without leaving the host.
        let gateway = Gateway::new(&client_config("127.0.0.1:1")).unwrap();
        let first = gateway.addresses().await.unwrap();
        assert_eq!(*first, ["127.0.0.1:1".parse().unwrap()]);
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(Arc::ptr_eq(&first, &gateway.addresses().await.unwrap()));
        tokio::time::advance(Duration::from_secs(1)).await;
        let refreshed = gateway.addresses().await.unwrap();
        assert!(!Arc::ptr_eq(&first, &refreshed));
        assert!(gateway.connect().await.is_err());
        assert!(gateway.resolved.lock().await.is_none());
    }
}

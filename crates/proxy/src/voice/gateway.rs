//! The gateway alone authenticates Discord and selects the media destination.
use super::wire;
use crate::{ContextExt, DESTINATION_CONNECT_TIMEOUT};
use futures_util::{SinkExt, StreamExt};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
    time::Instant,
};
use tokio_tungstenite::{
    tungstenite::{Message, Utf8Bytes},
    WebSocketStream,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct Flow {
    id: [u8; wire::FLOW_ID_LEN],
    socket: UdpSocket,
    endpoint: SocketAddr,
    expires: Instant,
}

/// Which upstream `Ready` endpoints may receive a UDP grant, and where the grant's
/// socket binds. Production always uses `PUBLIC_GRANTS`; only the ignored CPU
/// benchmarks (`crate::bench`) substitute a loopback scope.
#[derive(Clone, Copy)]
pub(crate) struct GrantScope {
    pub allow: fn(IpAddr) -> bool,
    pub bind_v4: &'static str,
    pub bind_v6: &'static str,
}
const PUBLIC_GRANTS: GrantScope = GrantScope {
    allow: crate::policy::is_public_ip,
    bind_v4: "0.0.0.0:0",
    bind_v6: "[::]:0",
};

#[cfg(test)]
fn ready_endpoint(text: &str) -> crate::Result<Option<SocketAddr>> {
    ready_endpoint_with(text, PUBLIC_GRANTS)
}

fn ready_endpoint_with(text: &str, scope: GrantScope) -> crate::Result<Option<SocketAddr>> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Ok(None);
    };
    if value.get("op").and_then(|v| v.as_u64()) != Some(2) {
        return Ok(None);
    }
    let data = value.get("d").ok_or("missing voice Ready data")?;
    let ip = data
        .get("ip")
        .and_then(|v| v.as_str())
        .ok_or("missing voice Ready IP")?
        .parse()?;
    let port = data
        .get("port")
        .and_then(|v| v.as_u64())
        .and_then(|v| u16::try_from(v).ok())
        .filter(|v| *v != 0)
        .ok_or("invalid voice Ready port")?;
    if !(scope.allow)(ip) {
        return Err("non-public voice Ready destination".into());
    }
    Ok(Some(SocketAddr::new(ip, port)))
}

fn valid_path(path: &str) -> bool {
    (path == "/" || path.starts_with("/?"))
        && path.len() <= 2048
        && !path.contains('#')
        && !path
            .chars()
            .any(|c| c.is_control() || c == '\\' || c.is_whitespace())
}

pub async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &crate::Config,
    host: &str,
    port: u16,
) -> crate::Result<()> {
    if !super::allowed_host(host) || !crate::policy::allowed_tcp_destination(host, port) {
        return Err("voice destination denied".into());
    }
    let trace = std::env::var("DINMOO_VOICE_TRACE").as_deref() == Ok("1");
    if trace {
        eprintln!("voice bridge opening Discord control WebSocket to {host}:{port}");
    }
    crate::socks::reply(stream, 0).await?;
    let mut control = wire::framed(stream);
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, control.next())
        .await
        .context("voice path timed out")?
        .ok_or("missing voice path")?
        .context("read voice path")?;
    let (tag, data) = wire::unpack(&first)?;
    let path = std::str::from_utf8(data)?;
    if tag != wire::PATH || !valid_path(path) {
        return Err("invalid voice path".into());
    }
    let addresses: Vec<_> = tokio::time::timeout(
        DESTINATION_CONNECT_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    .context("voice DNS lookup timed out")?
    .context("voice DNS lookup")?
    .collect();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|a| !crate::policy::is_public_ip(a.ip()))
    {
        return Err("voice DNS destination denied".into());
    }
    let remote = tokio::time::timeout(
        DESTINATION_CONNECT_TIMEOUT,
        TcpStream::connect(addresses.as_slice()),
    )
    .await
    .context("voice server connection timed out")?
    .context("connect voice server")?;
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(cfg.client_tls.clone()).connect(name, remote),
    )
    .await
    .context("voice server TLS handshake timed out")?
    .context("voice server TLS handshake")?;
    let url = format!("wss://{host}:{port}{path}");
    let config = wire::websocket_config();
    let (ws, _) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::client_async_with_config(url, tls, Some(config)),
    )
    .await
    .context("voice WebSocket handshake timed out")?
    .context("voice WebSocket handshake")?;
    if trace {
        eprintln!("voice bridge connected to Discord control WebSocket at {host}:{port}");
    }
    relay(&mut control, ws, trace).await
}

async fn receive(flow: &Option<Flow>, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    match flow {
        Some(flow) => flow.socket.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

async fn relay_write<F, E, T>(future: F) -> crate::Result<T>
where
    F: std::future::Future<Output = std::result::Result<T, E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    Ok(tokio::time::timeout(wire::WRITE_TIMEOUT, future).await??)
}

async fn relay<S, T>(
    control: &mut tokio_util::codec::Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    ws: WebSocketStream<T>,
    trace: bool,
) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    relay_with(control, ws, trace, PUBLIC_GRANTS).await
}

pub(crate) async fn relay_with<S, T>(
    control: &mut tokio_util::codec::Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    mut ws: WebSocketStream<T>,
    trace: bool,
    scope: GrantScope,
) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut flow: Option<Flow> = None;
    let mut udp = wire::UdpRecords::new(wire::UDP_RECV);
    // One timer for the grant: WebSocket activity only moves `expires`, and the timer
    // catches up when it fires, instead of a new timer registration per loop turn.
    let expiry = tokio::time::sleep(wire::GRANT_TTL);
    tokio::pin!(expiry);
    loop {
        tokio::select! {
            () = &mut expiry, if flow.is_some() => {
                match flow.as_ref().map(|f| f.expires) {
                    Some(expires) if Instant::now() < expires => expiry.as_mut().reset(expires),
                    _ => {
                        flow = None;
                        relay_write(control.send(wire::record(wire::REVOKE, &[]))).await?;
                    }
                }
            }
            record = control.next() => {
                let Some(record) = record else { break }; let record = record?.freeze();
                let (tag, data) = wire::unpack(&record)?;
                match tag {
                    wire::TEXT if data.len() <= wire::MAX_WS => relay_write(ws.send(Message::Text(Utf8Bytes::try_from(record.slice(1..))?))).await?,
                    wire::BINARY if data.len() <= wire::MAX_WS => relay_write(ws.send(Message::Binary(record.slice(1..)))).await?,
                    wire::CLOSE => { let _ = relay_write(ws.close(None)).await; break; }
                    wire::UDP_SEND => {
                        if let Some(f) = &flow {
                            // UDP is lossy; a failed send drops one datagram, not the call.
                            if authorized_udp(f, data) { let _ = f.socket.send_to(&data[wire::FLOW_ID_LEN..], f.endpoint).await; }
                        }
                    }
                    _ => return Err("invalid voice client record".into()),
                }
            }
            message = ws.next() => {
                let Some(message) = message else { break }; let message = message?;
                if let Some(f) = flow.as_mut() { f.expires = Instant::now() + wire::GRANT_TTL; }
                match message {
                    Message::Text(text) => {
                        if let Some(endpoint) = ready_endpoint_with(&text, scope)? {
                            if trace {
                                eprintln!("voice bridge received Discord Ready for {endpoint}");
                            }
                            drop(flow.take());
                            relay_write(control.send(wire::record(wire::REVOKE, &[]))).await?;
                            let bind = if endpoint.is_ipv4() { scope.bind_v4 } else { scope.bind_v6 };
                            let socket = UdpSocket::bind(bind).await?;
                            let mut id = [0; wire::FLOW_ID_LEN];
                            rustls::crypto::ring::default_provider().secure_random.fill(&mut id).map_err(|_| "flow randomness failed")?;
                            let expires = Instant::now() + wire::GRANT_TTL;
                            expiry.as_mut().reset(expires);
                            flow = Some(Flow { id, socket, endpoint, expires });
                            let mut ready = id.to_vec(); ready.extend_from_slice(text.as_bytes());
                            relay_write(control.send(wire::record(wire::READY, &ready))).await?;
                        } else { relay_write(control.send(wire::record(wire::TEXT, text.as_bytes()))).await?; }
                    }
                    Message::Binary(data) => relay_write(control.send(wire::record(wire::BINARY, &data))).await?,
                    // tungstenite has already queued the Pong.
                    Message::Ping(_) => relay_write(ws.flush()).await?,
                    Message::Pong(_) => {},
                    Message::Close(_) => { let _ = relay_write(control.send(wire::record(wire::CLOSE, &[]))).await; break; }
                    Message::Frame(_) => {},
                }
            }
            result = receive(&flow, udp.datagram()) => {
                if let Some(f) = &flow {
                    udp.forward(control, &f.socket, &f.id, result, |source, _| {
                        source == f.endpoint && Instant::now() < f.expires
                    }).await?;
                }
            }
        }
    }
    Ok(())
}
fn authorized_udp(flow: &Flow, data: &[u8]) -> bool {
    data.len() >= wire::FLOW_ID_LEN
        && data.len() <= wire::FLOW_ID_LEN + wire::MAX_UDP
        && data[..wire::FLOW_ID_LEN] == flow.id
        && Instant::now() < flow.expires
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voice::wire::tests::{flush_count, CountFlushes};
    use std::sync::{atomic::AtomicUsize, Arc};
    use tokio::{io::DuplexStream, task::JoinHandle};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    type Tunnel = Framed<DuplexStream, LengthDelimitedCodec>;

    fn any_ip(_: IpAddr) -> bool {
        true
    }
    const TEST_GRANTS: GrantScope = GrantScope {
        allow: any_ip,
        bind_v4: "127.0.0.1:0",
        bind_v6: "[::1]:0",
    };

    async fn start_relay() -> (
        Tunnel,
        WebSocketStream<DuplexStream>,
        Arc<AtomicUsize>,
        JoinHandle<crate::Result<()>>,
    ) {
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (local, gateway) = tokio::io::duplex(65536);
        let (upstream, server) = tokio::io::duplex(65536);
        let (gateway, flushes) = CountFlushes::new(gateway);
        let ws = WebSocketStream::from_raw_socket(upstream, Role::Client, None).await;
        let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let task = tokio::spawn(async move {
            relay_with(&mut wire::framed(gateway), ws, false, TEST_GRANTS).await
        });
        (wire::framed(local), server, flushes, task)
    }

    async fn next(client: &mut Tunnel) -> (u8, Vec<u8>) {
        let record = client.next().await.unwrap().unwrap();
        let (tag, payload) = wire::unpack(&record).unwrap();
        (tag, payload.to_vec())
    }

    /// Sends Discord's Ready for `endpoint`; returns the flow ID the client receives.
    async fn grant(
        client: &mut Tunnel,
        server: &mut WebSocketStream<DuplexStream>,
        endpoint: SocketAddr,
    ) -> Vec<u8> {
        let ready = format!(
            r#"{{"op":2,"d":{{"ip":"{}","port":{},"ssrc":1}}}}"#,
            endpoint.ip(),
            endpoint.port()
        );
        server.send(Message::Text(ready.into())).await.unwrap();
        assert_eq!(next(client).await.0, wire::REVOKE);
        let (tag, payload) = next(client).await;
        assert_eq!(tag, wire::READY);
        payload[..wire::FLOW_ID_LEN].to_vec()
    }

    async fn close(mut client: Tunnel, task: JoinHandle<crate::Result<()>>) {
        client.send(wire::record(wire::CLOSE, &[])).await.unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn websocket_activity_extends_grant_until_idle_expiry() {
        let (mut client, mut server, _, task) = start_relay().await;
        let start = Instant::now();
        grant(&mut client, &mut server, "127.0.0.1:9".parse().unwrap()).await;
        tokio::time::sleep(Duration::from_secs(100)).await;
        server.send(Message::Text("{}".into())).await.unwrap();
        assert_eq!(next(&mut client).await, (wire::TEXT, b"{}".to_vec()));
        assert_eq!(next(&mut client).await.0, wire::REVOKE);
        assert_eq!(start.elapsed(), Duration::from_secs(100) + wire::GRANT_TTL);
        close(client, task).await;
    }

    #[tokio::test]
    async fn failed_discord_udp_send_keeps_session() {
        let (mut client, mut server, _, task) = start_relay().await;
        // A socket bound to loopback cannot send to TEST-NET-1: the kernel rejects it.
        let mut send = grant(&mut client, &mut server, "192.0.2.1:9".parse().unwrap()).await;
        send.extend_from_slice(b"lost");
        client
            .send(wire::record(wire::UDP_SEND, &send))
            .await
            .unwrap();
        client
            .send(wire::record(wire::BINARY, &[1, 2]))
            .await
            .unwrap();
        assert_eq!(
            server.next().await.unwrap().unwrap().into_data().as_ref(),
            &[1, 2]
        );
        close(client, task).await;
    }

    #[tokio::test]
    async fn discord_ping_is_answered() {
        let (client, mut server, _, task) = start_relay().await;
        server
            .send(Message::Ping(b"p".as_slice().into()))
            .await
            .unwrap();
        assert_eq!(
            server.next().await.unwrap().unwrap(),
            Message::Pong(b"p".as_slice().into())
        );
        close(client, task).await;
    }

    #[tokio::test]
    async fn queued_discord_datagrams_share_one_flush_with_per_datagram_checks() {
        let (mut client, mut server, flushes, task) = start_relay().await;
        let media = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stranger = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let id = grant(&mut client, &mut server, media.local_addr().unwrap()).await;
        let mut send = id.clone();
        send.extend_from_slice(b"hello");
        client
            .send(wire::record(wire::UDP_SEND, &send))
            .await
            .unwrap();
        let mut buf = [0; 16];
        let (len, relay_udp) = media.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello");
        media.writable().await.unwrap();
        let before = flush_count(&flushes);
        media.try_send_to(&[1; 50], relay_udp).unwrap();
        stranger.send_to(&[2; 50], relay_udp).unwrap();
        media
            .try_send_to(&[3; wire::MAX_UDP + 1], relay_udp)
            .unwrap();
        media.try_send_to(&[4; 50], relay_udp).unwrap();
        for byte in [1, 4] {
            let mut expected = id.clone();
            expected.extend_from_slice(&[byte; 50]);
            assert_eq!(next(&mut client).await, (wire::UDP_RECV, expected));
        }
        assert_eq!(flush_count(&flushes) - before, 1);
        close(client, task).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_client_write_closes_voice_session() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (_client, gateway) = tokio::io::duplex(1);
        let (upstream, server) = tokio::io::duplex(4096);
        let mut control = wire::framed(gateway);
        let ws = WebSocketStream::from_raw_socket(upstream, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        server
            .send(Message::Binary(vec![1; 128].into()))
            .await
            .unwrap();
        let start = Instant::now();
        let result =
            tokio::time::timeout(Duration::from_secs(16), relay(&mut control, ws, false)).await;
        assert!(
            result.is_ok(),
            "stalled relay did not enforce its write timeout"
        );
        assert!(result.unwrap().is_err());
        assert_eq!(start.elapsed(), Duration::from_secs(15));
    }

    #[test]
    fn ready_only_accepts_public_fixed_endpoint() {
        assert_eq!(
            ready_endpoint(r#"{"op":2,"d":{"ip":"1.1.1.1","port":5000}}"#).unwrap(),
            Some("1.1.1.1:5000".parse().unwrap())
        );
        for ip in ["127.0.0.1", "10.0.0.1", "::1", "169.254.169.254"] {
            assert!(
                ready_endpoint(&format!(r#"{{"op":2,"d":{{"ip":"{ip}","port":5000}}}}"#)).is_err()
            );
        }
        for port in [0, 65536] {
            assert!(ready_endpoint(&format!(
                r#"{{"op":2,"d":{{"ip":"1.1.1.1","port":{port}}}}}"#
            ))
            .is_err());
        }
    }
    #[tokio::test]
    async fn udp_grants_reject_stale_identity_and_expiry() {
        let mut flow = Flow {
            id: [1; 16],
            socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            endpoint: "1.1.1.1:5000".parse().unwrap(),
            expires: Instant::now() + wire::GRANT_TTL,
        };
        assert!(authorized_udp(&flow, &[1; 17]));
        assert!(!authorized_udp(&flow, &[2; 17]));
        assert!(!authorized_udp(&flow, &[1; 15]));
        flow.expires = Instant::now();
        assert!(!authorized_udp(&flow, &[1; 17]));
    }
    #[tokio::test]
    async fn client_ready_cannot_grant_udp_and_binary_is_preserved() {
        use tokio_tungstenite::tungstenite::protocol::Role;
        let (local, gateway) = tokio::io::duplex(65536);
        let (upstream, server) = tokio::io::duplex(65536);
        let mut client = wire::framed(local);
        let mut gateway = wire::framed(gateway);
        let ws = WebSocketStream::from_raw_socket(upstream, Role::Client, None).await;
        let mut server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let task = tokio::spawn(async move { relay(&mut gateway, ws, false).await });
        let spoof = br#"{"op":2,"d":{"ip":"1.1.1.1","port":5000}}"#;
        client.send(wire::record(wire::TEXT, spoof)).await.unwrap();
        assert_eq!(
            server
                .next()
                .await
                .unwrap()
                .unwrap()
                .into_text()
                .unwrap()
                .as_bytes(),
            spoof
        );
        client
            .send(wire::record(wire::UDP_SEND, &[1; 20]))
            .await
            .unwrap();
        server
            .send(Message::Binary(vec![0, 255, 17, 42].into()))
            .await
            .unwrap();
        let message = client.next().await.unwrap().unwrap();
        assert_eq!(&message[..], &[wire::BINARY, 0, 255, 17, 42]);
        client
            .send(wire::record(wire::BINARY, &[255, 0, 9]))
            .await
            .unwrap();
        assert_eq!(
            server.next().await.unwrap().unwrap().into_data().as_ref(),
            &[255, 0, 9]
        );
        client.send(wire::record(wire::CLOSE, &[])).await.unwrap();
        task.await.unwrap().unwrap();
    }
    #[test]
    fn paths_cannot_replace_authority() {
        assert!(valid_path("/?v=8"));
        for path in [
            "/other",
            "//evil.test/",
            "https://evil.test/",
            "/#fragment",
            "/\r\nHost: evil",
            "/\\evil",
        ] {
            assert!(!valid_path(path));
        }
    }
}

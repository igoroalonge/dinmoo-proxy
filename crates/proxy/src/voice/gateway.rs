//! The gateway alone authenticates Discord and selects the media destination.
use super::wire;
use futures_util::{SinkExt, StreamExt};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
    time::Instant,
};
use tokio_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Message},
    WebSocketStream,
};

struct Flow {
    id: [u8; wire::FLOW_ID_LEN],
    socket: UdpSocket,
    endpoint: SocketAddr,
    expires: Instant,
}

fn ready_endpoint(text: &str) -> crate::Result<Option<SocketAddr>> {
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
    if !crate::is_public_ip(ip) {
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
    if !super::allowed_host(host) || !crate::allowed_tcp_destination(host, port) {
        return Err("voice destination denied".into());
    }
    let trace = std::env::var("DINMOO_VOICE_TRACE").as_deref() == Ok("1");
    if trace {
        eprintln!("voice bridge opening Discord control WebSocket to {host}:{port}");
    }
    crate::reply(stream, 0).await?;
    let mut control = wire::framed(stream);
    let first = tokio::time::timeout(Duration::from_secs(10), control.next())
        .await?
        .ok_or("missing voice path")??;
    let (tag, data) = wire::unpack(&first)?;
    let path = std::str::from_utf8(data)?;
    if tag != wire::PATH || !valid_path(path) {
        return Err("invalid voice path".into());
    }
    let addresses: Vec<_> = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host, port)),
    )
    .await??
    .collect();
    if addresses.is_empty() || addresses.iter().any(|a| !crate::is_public_ip(a.ip())) {
        return Err("voice DNS destination denied".into());
    }
    let remote = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(addresses.as_slice()),
    )
    .await??;
    let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
    let tls = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_rustls::TlsConnector::from(cfg.client_tls.clone()).connect(name, remote),
    )
    .await??;
    let url = format!("wss://{host}:{port}{path}");
    let config = WebSocketConfig::default()
        .max_message_size(Some(wire::MAX_WS))
        .max_frame_size(Some(wire::MAX_WS));
    let (ws, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::client_async_with_config(url, tls, Some(config)),
    )
    .await??;
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
    Ok(tokio::time::timeout(Duration::from_secs(15), future).await??)
}

async fn relay<S, T>(
    control: &mut tokio_util::codec::Framed<S, tokio_util::codec::LengthDelimitedCodec>,
    mut ws: WebSocketStream<T>,
    trace: bool,
) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut flow: Option<Flow> = None;
    let mut udp = vec![0; wire::MAX_UDP + 1];
    loop {
        let deadline = flow
            .as_ref()
            .map(|f| f.expires)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(86400));
        tokio::select! {
            _ = tokio::time::sleep_until(deadline), if flow.is_some() => {
                flow = None;
                relay_write(control.send(wire::record(wire::REVOKE, &[]))).await?;
            }
            record = control.next() => {
                let Some(record) = record else { break }; let record = record?;
                let (tag, data) = wire::unpack(&record)?;
                match tag {
                    wire::TEXT if data.len() <= wire::MAX_WS => relay_write(ws.send(Message::Text(std::str::from_utf8(data)?.to_owned().into()))).await?,
                    wire::BINARY if data.len() <= wire::MAX_WS => relay_write(ws.send(Message::Binary(data.to_vec().into()))).await?,
                    wire::CLOSE => { let _ = relay_write(ws.close(None)).await; break; }
                    wire::UDP_SEND => {
                        if let Some(f) = &flow {
                            if authorized_udp(f, data) { f.socket.send_to(&data[wire::FLOW_ID_LEN..], f.endpoint).await?; }
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
                        if let Some(endpoint) = ready_endpoint(&text)? {
                            if trace {
                                eprintln!("voice bridge received Discord Ready for {endpoint}");
                            }
                            drop(flow.take());
                            relay_write(control.send(wire::record(wire::REVOKE, &[]))).await?;
                            let bind = if endpoint.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                            let socket = UdpSocket::bind(bind).await?;
                            let mut id = [0; wire::FLOW_ID_LEN];
                            rustls::crypto::ring::default_provider().secure_random.fill(&mut id).map_err(|_| "flow randomness failed")?;
                            flow = Some(Flow { id, socket, endpoint, expires: Instant::now() + wire::GRANT_TTL });
                            let mut ready = id.to_vec(); ready.extend_from_slice(text.as_bytes());
                            relay_write(control.send(wire::record(wire::READY, &ready))).await?;
                        } else { relay_write(control.send(wire::record(wire::TEXT, text.as_bytes()))).await?; }
                    }
                    Message::Binary(data) => relay_write(control.send(wire::record(wire::BINARY, &data))).await?,
                    Message::Ping(data) => relay_write(ws.send(Message::Pong(data))).await?,
                    Message::Pong(_) => {},
                    Message::Close(_) => { let _ = relay_write(control.send(wire::record(wire::CLOSE, &[]))).await; break; }
                    Message::Frame(_) => {},
                }
            }
            result = receive(&flow, &mut udp) => {
                let (len, source) = result?;
                if let Some(f) = &flow {
                    if source == f.endpoint && len <= wire::MAX_UDP && Instant::now() < f.expires {
                        let mut data = f.id.to_vec(); data.extend_from_slice(&udp[..len]);
                        relay_write(control.send(wire::record(wire::UDP_RECV, &data))).await?;
                    }
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

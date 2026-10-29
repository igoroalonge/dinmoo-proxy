use super::wire::{self, WRITE_TIMEOUT};
use crate::ContextExt;
use futures_util::{SinkExt, StreamExt};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UdpSocket,
    time::timeout,
};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{self, Message, Utf8Bytes},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn valid_target(path: &str, authority: &str, host: &str, port: u16) -> bool {
    if path.len() > 2048 || !(path == "/" || path.starts_with("/?")) {
        return false;
    }
    let Ok(authority) = authority.parse::<tungstenite::http::uri::Authority>() else {
        return false;
    };
    authority.host().eq_ignore_ascii_case(host) && authority.port_u16().unwrap_or(443) == port
}

/// Returns Discord's Ready pointing at the local UDP `port`, and the Ready SSRC.
fn rewrite_ready(raw: &[u8], port: u16) -> crate::Result<(String, u32)> {
    let mut value: serde_json::Value = serde_json::from_slice(raw)?;
    if value.get("op").and_then(|v| v.as_u64()) != Some(2) {
        return Err("invalid voice Ready opcode".into());
    }
    let data = value
        .get_mut("d")
        .and_then(|v| v.as_object_mut())
        .ok_or("invalid voice Ready data")?;
    if !data.get("ip").is_some_and(|v| v.is_string())
        || !data
            .get("port")
            .is_some_and(|v| v.as_u64().is_some_and(|p| p > 0 && p <= 65535))
    {
        return Err("invalid voice Ready endpoint".into());
    }
    let ssrc = data
        .get("ssrc")
        .and_then(|v| v.as_u64())
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("invalid voice Ready SSRC")?;
    data.insert("ip".into(), "127.0.0.1".into());
    data.insert("port".into(), port.into());
    Ok((serde_json::to_string(&value)?, ssrc))
}

struct Flow {
    id: [u8; wire::FLOW_ID_LEN],
    socket: UdpSocket,
    peer: Peer,
}

/// The local socket allowed to use a flow: the loopback sender of the first IP discovery
/// request that carries the Ready SSRC. Discord repeats discovery from new sockets, but
/// the pin never moves: SSRCs are small and sequential, so re-pinning would reopen the
/// takeover. This narrows the race for the local UDP port but is not authentication;
/// any local user can see the port and guess the SSRC.
struct Peer {
    ssrc: u32,
    pinned: Option<SocketAddr>,
}
impl Peer {
    fn new(ssrc: u32) -> Self {
        Self { ssrc, pinned: None }
    }
    fn accept(&mut self, from: SocketAddr, datagram: &[u8]) -> bool {
        match self.pinned {
            Some(pinned) => pinned == from,
            None if from.ip().is_loopback() && self.discovery(datagram) => {
                self.pinned = Some(from);
                true
            }
            None => false,
        }
    }
    /// Discord IP discovery request: type 1, length 70, SSRC, then a 64-byte address.
    fn discovery(&self, datagram: &[u8]) -> bool {
        datagram.len() == 74
            && datagram[..4] == [0x00, 0x01, 0x00, 0x46]
            && datagram[4..8] == self.ssrc.to_be_bytes()
    }
}

impl Flow {
    fn packet<'a>(&self, payload: &'a [u8]) -> Option<&'a [u8]> {
        if payload.len() < wire::FLOW_ID_LEN
            || payload.len() > wire::FLOW_ID_LEN + wire::MAX_UDP
            || payload[..wire::FLOW_ID_LEN] != self.id
        {
            return None;
        }
        Some(&payload[wire::FLOW_ID_LEN..])
    }
}

#[allow(clippy::result_large_err)]
pub async fn run<L, R>(
    local: &mut L,
    remote: &mut R,
    identity: &super::identity::VoiceIdentity,
    host: &str,
    port: u16,
) -> crate::Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let tls = timeout(HANDSHAKE_TIMEOUT, identity.acceptor.accept(local))
        .await
        .context("local voice TLS handshake timed out")?
        .context("local voice TLS handshake")?;
    if tls.get_ref().1.server_name() != Some(host) {
        return Err("voice TLS server name mismatch".into());
    }
    let selected_path = Arc::new(Mutex::new(None));
    let capture = selected_path.clone();
    let config = wire::websocket_config();
    let mut ws = timeout(
        HANDSHAKE_TIMEOUT,
        accept_hdr_async_with_config(
            tls,
            move |request: &tungstenite::handshake::server::Request, response| {
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|v| v.as_str())
                    .unwrap_or("");
                let authorities: Vec<_> = request.headers().get_all("host").iter().collect();
                let authority = if authorities.len() == 1 {
                    authorities[0].to_str().ok()
                } else {
                    None
                };
                if request.uri().scheme().is_some()
                    || request.uri().authority().is_some()
                    || authority.is_none_or(|authority| !valid_target(path, authority, host, port))
                {
                    return Err(tungstenite::http::Response::builder()
                        .status(400)
                        .body(Some("invalid voice target".into()))
                        .unwrap());
                }
                *capture.lock().unwrap() = Some(path.to_owned());
                Ok(response)
            },
            Some(config),
        ),
    )
    .await
    .context("local voice WebSocket handshake timed out")?
    .context("local voice WebSocket handshake")?;
    let path = selected_path
        .lock()
        .unwrap()
        .take()
        .ok_or("missing voice websocket path")?;
    let mut tunnel = wire::framed(remote);
    timeout(
        WRITE_TIMEOUT,
        tunnel.send(wire::record(wire::PATH, path.as_bytes())),
    )
    .await
    .context("voice path write timed out")?
    .context("write voice path")?;
    let mut flow: Option<Flow> = None;
    let mut udp = wire::UdpRecords::new(wire::UDP_SEND);
    let result: crate::Result<()> = async {
        loop {
            tokio::select! {
                incoming = ws.next() => {
                    match incoming {
                        Some(Ok(Message::Text(text))) => timeout(WRITE_TIMEOUT, tunnel.send(wire::record(wire::TEXT, text.as_bytes()))).await??,
                        Some(Ok(Message::Binary(data))) => timeout(WRITE_TIMEOUT, tunnel.send(wire::record(wire::BINARY, &data))).await??,
                        Some(Ok(Message::Ping(_))) => { timeout(WRITE_TIMEOUT, ws.flush()).await??; }
                        Some(Ok(Message::Pong(_))) => {},
                        Some(Ok(Message::Close(_))) | None => { let _ = timeout(WRITE_TIMEOUT, tunnel.send(wire::record(wire::CLOSE, &[]))).await; return Ok(()); }
                        Some(Err(error)) => return Err(error.into()),
                        Some(Ok(Message::Frame(_))) => return Err("unexpected voice websocket frame".into()),
                    }
                }
                incoming = tunnel.next() => {
                    let Some(incoming) = incoming else { return Ok(()); };
                    let incoming = incoming?.freeze();
                    let (tag, payload) = wire::unpack(&incoming)?;
                    if matches!(tag, wire::TEXT | wire::BINARY) && payload.len() > wire::MAX_WS { return Err("oversized voice websocket message".into()); }
                    match tag {
                        wire::TEXT => { let text = Utf8Bytes::try_from(incoming.slice(1..))?; timeout(WRITE_TIMEOUT, ws.send(Message::Text(text))).await??; }
                        wire::BINARY => { timeout(WRITE_TIMEOUT, ws.send(Message::Binary(incoming.slice(1..)))).await??; }
                        wire::READY => {
                            if payload.len() <= wire::FLOW_ID_LEN { return Err("invalid voice Ready record".into()); }
                            let id = payload[..wire::FLOW_ID_LEN].try_into().unwrap();
                            let socket = UdpSocket::bind("127.0.0.1:0").await?;
                            let (ready, ssrc) = rewrite_ready(&payload[wire::FLOW_ID_LEN..], socket.local_addr()?.port())?;
                            flow = Some(Flow { id, socket, peer: Peer::new(ssrc) });
                            timeout(WRITE_TIMEOUT, ws.send(Message::Text(ready.into()))).await??;
                        }
                        wire::UDP_RECV => {
                            let current = flow.as_ref().ok_or("voice UDP before Ready")?;
                            if let (Some(raw), Some(peer)) = (current.packet(payload), current.peer.pinned) {
                                // UDP is lossy; a failed send drops one datagram, not the call.
                                let _ = timeout(WRITE_TIMEOUT, current.socket.send_to(raw, peer)).await;
                            }
                        }
                        wire::REVOKE if payload.is_empty() => { flow = None; }
                        wire::CLOSE if payload.is_empty() => return Ok(()),
                        _ => return Err("unexpected voice tunnel record".into()),
                    }
                }
                received = async {
                    match flow.as_ref() {
                        Some(current) => current.socket.recv_from(udp.datagram()).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let current = flow.as_mut().ok_or("voice UDP before Ready")?;
                    let peer = &mut current.peer;
                    udp.forward(&mut tunnel, &current.socket, &current.id, received, |from, datagram| peer.accept(from, datagram)).await?;
                }
            }
        }
    }.await;
    let _ = timeout(WRITE_TIMEOUT, ws.close(None)).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::voice::wire::tests::{flush_count, CountFlushes};
    use std::sync::atomic::AtomicUsize;
    use tokio::{io::DuplexStream, task::JoinHandle};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};
    #[test]
    fn ready_preserves_every_field_except_endpoint() {
        let raw = br#"{"op":2,"d":{"ip":"203.0.113.5","port":5000,"ssrc":42,"modes":["a"],"extra":{"x":true}},"extra":7}"#;
        let (ready, ssrc) = rewrite_ready(raw, 4567).unwrap();
        let value: serde_json::Value = serde_json::from_str(&ready).unwrap();
        let mut expected: serde_json::Value = serde_json::from_slice(raw).unwrap();
        expected["d"]["ip"] = "127.0.0.1".into();
        expected["d"]["port"] = 4567.into();
        assert_eq!(value, expected);
        assert_eq!(ssrc, 42);
    }
    #[test]
    fn rejects_non_ready_and_invalid_ready() {
        for raw in [
            br#"{"op":3,"d":{"ip":"x","port":3}}"#.as_slice(),
            br#"{"op":2,"d":null}"#,
            br#"{"op":2,"d":{"ip":"x","port":3}}"#,
            br#"{"op":2,"d":{"ip":"x","port":3,"ssrc":-1}}"#,
            br#"{"op":2,"d":{"ip":"x","port":3,"ssrc":4294967296}}"#,
            br#"{"op":2,"d":{"ip":"x","port":3,"ssrc":"42"}}"#,
        ] {
            assert!(rewrite_ready(raw, 123).is_err());
        }
    }
    #[tokio::test]
    async fn udp_flow_pins_only_a_loopback_discovery_for_its_ssrc() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut flow = Flow {
            id: [7; 16],
            socket,
            peer: Peer::new(42),
        };
        let app: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let mut addressed = discovery(42);
        addressed[8..17].copy_from_slice(b"127.0.0.1");
        assert!(!flow.peer.accept(app, b"rtp"));
        assert!(!flow.peer.accept(app, &discovery(43)));
        assert!(!flow.peer.accept(app, &discovery(42)[..73]));
        assert!(!flow.peer.accept(app, &[discovery(42), vec![0]].concat()));
        assert!(!flow
            .peer
            .accept("192.0.2.1:4000".parse().unwrap(), &discovery(42)));
        assert!(flow.peer.accept(app, &addressed));
        assert!(flow.peer.accept(app, b"rtp"));
        assert!(!flow
            .peer
            .accept("127.0.0.1:4001".parse().unwrap(), &discovery(42)));
        assert_eq!(flow.peer.pinned, Some(app));
        let mut packet = vec![7; 16];
        packet.extend_from_slice(b"raw udp");
        assert_eq!(flow.packet(&packet), Some(b"raw udp".as_slice()));
        packet[0] = 8;
        assert!(flow.packet(&packet).is_none());
        assert!(flow.packet(&[7; 15]).is_none());
    }
    type App = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<DuplexStream>>;
    type Tunnel = Framed<DuplexStream, LengthDelimitedCodec>;

    fn discovery(ssrc: u32) -> Vec<u8> {
        let mut packet = vec![0; 74];
        packet[..4].copy_from_slice(&[0, 1, 0, 70]);
        packet[4..8].copy_from_slice(&ssrc.to_be_bytes());
        packet
    }

    async fn next(gateway: &mut Tunnel) -> (u8, Vec<u8>) {
        let record = timeout(Duration::from_secs(2), gateway.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let (tag, payload) = wire::unpack(&record).unwrap();
        (tag, payload.to_vec())
    }

    /// Runs the bridge behind a Discord-like TLS WebSocket and delivers Ready for SSRC 42
    /// with flow ID [5; 16]. Returns the bridge's UDP endpoint and its tunnel flush count.
    async fn start_bridge() -> (
        App,
        Tunnel,
        SocketAddr,
        Arc<AtomicUsize>,
        JoinHandle<crate::Result<()>>,
    ) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["voice.discord.media".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        let identity = super::super::identity::VoiceIdentity {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
            spki_pin: String::new(),
        };
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(cert.der().to_vec()))
            .unwrap();
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let (client, mut local) = tokio::io::duplex(64 * 1024);
        let (remote, gateway) = tokio::io::duplex(64 * 1024);
        let (mut remote, flushes) = CountFlushes::new(remote);
        let task = tokio::spawn(async move {
            run(
                &mut local,
                &mut remote,
                &identity,
                "voice.discord.media",
                443,
            )
            .await
        });
        let tls = connector
            .connect(ServerName::try_from("voice.discord.media").unwrap(), client)
            .await
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async("wss://voice.discord.media/?v=8", tls)
            .await
            .unwrap();
        let mut gateway = wire::framed(gateway);
        assert_eq!(next(&mut gateway).await, (wire::PATH, b"/?v=8".to_vec()));
        let mut ready = vec![5; 16];
        ready.extend_from_slice(
            br#"{"op":2,"d":{"ip":"203.0.113.1","port":5000,"ssrc":42,"modes":["a"]}}"#,
        );
        gateway
            .send(wire::record(wire::READY, &ready))
            .await
            .unwrap();
        let message = ws.next().await.unwrap().unwrap().into_text().unwrap();
        let value: serde_json::Value = serde_json::from_str(&message).unwrap();
        assert_eq!(value["d"]["ip"], "127.0.0.1");
        assert_eq!(value["d"]["ssrc"], 42);
        let endpoint = format!("127.0.0.1:{}", value["d"]["port"].as_u64().unwrap())
            .parse()
            .unwrap();
        (ws, gateway, endpoint, flushes, task)
    }

    #[tokio::test]
    async fn tls_websocket_ready_and_udp_round_trip() {
        let (mut ws, mut gateway, endpoint, _, task) = start_bridge().await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&discovery(42), endpoint).await.unwrap();
        let (tag, payload) = next(&mut gateway).await;
        assert_eq!(tag, wire::UDP_SEND);
        assert_eq!(&payload[..16], &[5; 16]);
        assert_eq!(payload[16..], discovery(42));
        let mut reply = vec![5; 16];
        reply.extend_from_slice(b"reply");
        gateway
            .send(wire::record(wire::UDP_RECV, &reply))
            .await
            .unwrap();
        let mut raw = [0; 100];
        let (len, _) = timeout(Duration::from_secs(2), udp.recv_from(&mut raw))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&raw[..len], b"reply");
        // Messages larger than the WebSocket read buffer pass both ways.
        let large = vec![7; 100 * 1024];
        ws.send(Message::Binary(large.clone().into()))
            .await
            .unwrap();
        assert_eq!(next(&mut gateway).await, (wire::BINARY, large.clone()));
        gateway
            .send(wire::record(wire::BINARY, &large))
            .await
            .unwrap();
        assert_eq!(
            ws.next().await.unwrap().unwrap().into_data().as_ref(),
            &large[..]
        );
        ws.close(None).await.unwrap();
        assert!(timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
    }

    #[tokio::test]
    async fn udp_pins_only_the_discovery_sender_and_batches_records() {
        let (_ws, mut gateway, endpoint, flushes, task) = start_bridge().await;
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let attacker = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        app.writable().await.unwrap();
        let before = flush_count(&flushes);
        attacker.send_to(b"first", endpoint).unwrap();
        app.try_send_to(&discovery(41), endpoint).unwrap();
        app.try_send_to(b"early", endpoint).unwrap();
        app.try_send_to(&discovery(42), endpoint).unwrap();
        attacker.send_to(&discovery(42), endpoint).unwrap();
        app.try_send_to(b"media", endpoint).unwrap();
        for expected in [discovery(42), b"media".to_vec()] {
            let (tag, payload) = next(&mut gateway).await;
            assert_eq!(tag, wire::UDP_SEND);
            assert_eq!(payload[16..], expected[..]);
        }
        assert_eq!(flush_count(&flushes) - before, 1);
        let mut reply = vec![5; 16];
        reply.extend_from_slice(b"reply");
        gateway
            .send(wire::record(wire::UDP_RECV, &reply))
            .await
            .unwrap();
        let mut raw = [0; 16];
        let (len, from) = timeout(Duration::from_secs(2), app.recv_from(&mut raw))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((&raw[..len], from), (b"reply".as_slice(), endpoint));
        gateway.send(wire::record(wire::CLOSE, &[])).await.unwrap();
        assert!(timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .is_ok());
    }
    #[test]
    fn host_and_path_are_restricted() {
        assert!(valid_target(
            "/?v=8",
            "voice.discord.media",
            "voice.discord.media",
            443
        ));
        assert!(valid_target(
            "/",
            "voice.discord.media:443",
            "voice.discord.media",
            443
        ));
        assert!(!valid_target(
            "/other",
            "voice.discord.media",
            "voice.discord.media",
            443
        ));
        assert!(!valid_target(
            "/",
            "other.discord.media",
            "voice.discord.media",
            443
        ));
        assert!(!valid_target(
            "/",
            "voice.discord.media",
            "voice.discord.media",
            8443
        ));
    }
}

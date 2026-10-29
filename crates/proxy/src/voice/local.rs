use super::wire;
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
    tungstenite::{self, protocol::WebSocketConfig, Message},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);

fn valid_target(path: &str, authority: &str, host: &str, port: u16) -> bool {
    if path.len() > 2048 || !(path == "/" || path.starts_with("/?")) {
        return false;
    }
    let Ok(authority) = authority.parse::<tungstenite::http::uri::Authority>() else {
        return false;
    };
    authority.host().eq_ignore_ascii_case(host) && authority.port_u16().unwrap_or(443) == port
}

fn rewrite_ready(raw: &[u8], port: u16) -> crate::Result<Vec<u8>> {
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
    data.insert("ip".into(), "127.0.0.1".into());
    data.insert("port".into(), port.into());
    Ok(serde_json::to_vec(&value)?)
}

struct Flow {
    id: [u8; wire::FLOW_ID_LEN],
    socket: UdpSocket,
    peer: Option<SocketAddr>,
}
impl Flow {
    fn pin_peer(&mut self, peer: SocketAddr) -> bool {
        if !peer.ip().is_loopback() {
            return false;
        }
        match self.peer {
            Some(pinned) => pinned == peer,
            None => {
                self.peer = Some(peer);
                true
            }
        }
    }
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
    let tls = timeout(HANDSHAKE_TIMEOUT, identity.acceptor.accept(local)).await??;
    if tls.get_ref().1.server_name() != Some(host) {
        return Err("voice TLS server name mismatch".into());
    }
    let selected_path = Arc::new(Mutex::new(None));
    let capture = selected_path.clone();
    let config = WebSocketConfig::default()
        .max_message_size(Some(wire::MAX_WS))
        .max_frame_size(Some(wire::MAX_WS));
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
    .await??;
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
    .await??;
    let mut flow: Option<Flow> = None;
    let mut datagram = vec![0u8; wire::MAX_UDP + 1];
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
                    let incoming = incoming?;
                    let (tag, payload) = wire::unpack(&incoming)?;
                    if matches!(tag, wire::TEXT | wire::BINARY) && payload.len() > wire::MAX_WS { return Err("oversized voice websocket message".into()); }
                    match tag {
                        wire::TEXT => { let text = std::str::from_utf8(payload)?; timeout(WRITE_TIMEOUT, ws.send(Message::Text(text.to_owned().into()))).await??; }
                        wire::BINARY => { timeout(WRITE_TIMEOUT, ws.send(Message::Binary(payload.to_vec().into()))).await??; }
                        wire::READY => {
                            if payload.len() <= wire::FLOW_ID_LEN { return Err("invalid voice Ready record".into()); }
                            let id = payload[..wire::FLOW_ID_LEN].try_into().unwrap();
                            let socket = UdpSocket::bind("127.0.0.1:0").await?;
                            let ready = rewrite_ready(&payload[wire::FLOW_ID_LEN..], socket.local_addr()?.port())?;
                            flow = Some(Flow { id, socket, peer: None });
                            timeout(WRITE_TIMEOUT, ws.send(Message::Text(String::from_utf8(ready)?.into()))).await??;
                        }
                        wire::UDP_RECV => {
                            let current = flow.as_ref().ok_or("voice UDP before Ready")?;
                            if let (Some(raw), Some(peer)) = (current.packet(payload), current.peer) {
                                timeout(WRITE_TIMEOUT, current.socket.send_to(raw, peer)).await??;
                            }
                        }
                        wire::REVOKE if payload.is_empty() => { flow = None; }
                        wire::CLOSE if payload.is_empty() => return Ok(()),
                        _ => return Err("unexpected voice tunnel record".into()),
                    }
                }
                received = async {
                    match flow.as_ref() {
                        Some(current) => current.socket.recv_from(&mut datagram).await,
                        None => std::future::pending().await,
                    }
                } => {
                    let (len, peer) = received?;
                    let current = flow.as_mut().ok_or("voice UDP before Ready")?;
                    if len <= wire::MAX_UDP && current.pin_peer(peer) {
                        let mut payload = Vec::with_capacity(wire::FLOW_ID_LEN + len);
                        payload.extend_from_slice(&current.id);
                        payload.extend_from_slice(&datagram[..len]);
                        timeout(WRITE_TIMEOUT, tunnel.send(wire::record(wire::UDP_SEND, &payload))).await??;
                    }
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
    #[test]
    fn ready_preserves_every_field_except_endpoint() {
        let raw = br#"{"op":2,"d":{"ip":"203.0.113.5","port":5000,"ssrc":42,"modes":["a"],"extra":{"x":true}},"extra":7}"#;
        let value: serde_json::Value =
            serde_json::from_slice(&rewrite_ready(raw, 4567).unwrap()).unwrap();
        let mut expected: serde_json::Value = serde_json::from_slice(raw).unwrap();
        expected["d"]["ip"] = "127.0.0.1".into();
        expected["d"]["port"] = 4567.into();
        assert_eq!(value, expected);
    }
    #[test]
    fn rejects_non_ready_and_invalid_ready() {
        for raw in [
            br#"{"op":3,"d":{"ip":"x","port":3}}"#.as_slice(),
            br#"{"op":2,"d":null}"#,
        ] {
            assert!(rewrite_ready(raw, 123).is_err());
        }
    }
    #[tokio::test]
    async fn udp_flow_pins_source_and_rejects_stale_flow() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut flow = Flow {
            id: [7; 16],
            socket,
            peer: None,
        };
        let peer: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        assert!(!flow.pin_peer("192.0.2.1:4000".parse().unwrap()));
        assert!(flow.pin_peer(peer));
        assert!(flow.pin_peer(peer));
        assert!(!flow.pin_peer("127.0.0.1:4001".parse().unwrap()));
        let mut packet = vec![7; 16];
        packet.extend_from_slice(b"raw udp");
        assert_eq!(flow.packet(&packet), Some(b"raw udp".as_slice()));
        packet[0] = 8;
        assert!(flow.packet(&packet).is_none());
        assert!(flow.packet(&[7; 15]).is_none());
    }
    #[tokio::test]
    async fn tls_websocket_ready_and_udp_round_trip() {
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
        let (mut remote, gateway) = tokio::io::duplex(64 * 1024);
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
        let path = gateway.next().await.unwrap().unwrap();
        assert_eq!(
            wire::unpack(&path).unwrap(),
            (wire::PATH, b"/?v=8".as_slice())
        );
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
        let endpoint = format!("127.0.0.1:{}", value["d"]["port"].as_u64().unwrap());
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(b"discovery", &endpoint).await.unwrap();
        let outgoing = timeout(Duration::from_secs(2), gateway.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let (tag, payload) = wire::unpack(&outgoing).unwrap();
        assert_eq!(tag, wire::UDP_SEND);
        assert_eq!(&payload[..16], &[5; 16]);
        assert_eq!(&payload[16..], b"discovery");
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
        ws.close(None).await.unwrap();
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

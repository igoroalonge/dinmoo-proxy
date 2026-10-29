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
use std::{error::Error, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
use tokio_rustls::TlsConnector;

pub(crate) async fn connect_gateway(
    cfg: &Config,
    version: u8,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let upstream = cfg
        .upstream
        .as_ref()
        .ok_or("gateway endpoint not configured")?;
    let remote = tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, TcpStream::connect(upstream))
        .await
        .context("gateway connection timed out")?
        .context("connect gateway")?;
    remote.set_nodelay(true)?;
    let (host, _) = upstream
        .rsplit_once(':')
        .ok_or("gateway must be host:port")?;
    let server_name = ServerName::try_from(host.to_owned())?;
    let mut remote = tokio::time::timeout(
        TLS_HANDSHAKE_TIMEOUT,
        TlsConnector::from(cfg.client_tls.clone()).connect(server_name, remote),
    )
    .await
    .context("TLS gateway handshake timed out")?
    .context("TLS gateway handshake")?;
    tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, async {
        remote.write_all(&[b'D', b'M', b'P', b'X', version]).await?;
        write_string(&mut remote, &cfg.token).await?;
        if remote.read_u8().await? != 1 {
            bail!("gateway rejected authentication");
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    })
    .await
    .context("gateway authentication timed out")??;
    Ok(remote)
}

pub(crate) async fn handle(
    mut stream: TcpStream,
    cfg: Arc<Config>,
    session_id: session::Id,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut remote = connect_gateway(&cfg, 3).await?;
    tokio::time::timeout(AUTH_HANDSHAKE_TIMEOUT, async {
        remote.write_all(&session_id).await?;
        if remote.read_u8().await? != 1 {
            bail!("gateway rejected data session");
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    })
    .await
    .context("data session handshake timed out")??;
    let identity = match &cfg.voice_identity {
        Some(store) => store
            .current()
            .await
            .inspect_err(|error| eprintln!("voice bridge unavailable: {error}"))
            .ok(),
        None => None,
    };
    proxy_socks_with_identity(&mut stream, &mut remote, identity.as_deref()).await
}

#[cfg(test)]
pub(crate) async fn proxy_socks<L, R>(local: &mut L, remote: &mut R) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    proxy_socks_with_identity(local, remote, None).await
}

async fn proxy_socks_with_identity<L, R>(
    local: &mut L,
    remote: &mut R,
    identity: Option<&voice::identity::VoiceIdentity>,
) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, async {
        let version = local.read_u8().await?;
        let nmethods = local.read_u8().await? as usize;
        let mut methods = vec![0; nmethods];
        local.read_exact(&mut methods).await?;
        remote.write_all(&[version, nmethods as u8]).await?;
        remote.write_all(&methods).await?;
        let mut method_reply = [0; 2];
        remote.read_exact(&mut method_reply).await?;
        local.write_all(&method_reply).await?;
        if method_reply != [5, 0] {
            bail!("gateway did not accept SOCKS no-auth method");
        }
        read_socks_request(local).await
    })
    .await
    .context("SOCKS handshake timed out")??;
    let command = request[1];
    let (host, port) = socks_request_target(&request)?;
    if command == 1 && voice::allowed_host(&host) {
        if let Some(identity) = identity {
            if !allowed_tcp_destination(&host, port) {
                reply(local, 2).await?;
                return Ok(());
            }
            request[1] = voice::SOCKS_VOICE_COMMAND;
            remote.write_all(&request).await?;
            let response = read_socks_reply(remote).await?;
            local.write_all(&response).await?;
            if response[1] != 0 {
                return Ok(());
            }
            return voice::local::run(local, remote, identity, &host, port).await;
        }
    }
    remote.write_all(&request).await?;
    match command {
        1 => {
            let reply = read_socks_reply(remote).await?;
            local.write_all(&reply).await?;
            if reply[1] != 0 {
                return Ok(());
            }
            tokio::io::copy_bidirectional_with_sizes(
                local,
                remote,
                TCP_COPY_BUFFER_SIZE,
                TCP_COPY_BUFFER_SIZE,
            )
            .await?;
        }
        3 => proxy_udp_associate(local, remote).await?,
        _ => {
            let reply = read_socks_reply(remote).await?;
            local.write_all(&reply).await?;
        }
    }
    Ok(())
}

async fn proxy_udp_associate<L, R>(local: &mut L, remote: &mut R) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    let reply = read_socks_reply(remote).await?;
    if reply[1] != 0 {
        local.write_all(&reply).await?;
        return Ok(());
    }
    let mut local_reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
    local_reply.extend_from_slice(&local_addr.port().to_be_bytes());
    local.write_all(&local_reply).await?;

    let (mut reader, mut writer) = tokio::io::split(remote);
    let mut peer = None;
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
                if !source.ip().is_loopback() || !valid_socks_udp_packet(&datagram[..length]) { continue; }
                if let Some(known_peer) = peer {
                    if source != known_peer { continue; }
                } else {
                    peer = Some(source);
                }
                if valid_socks_udp_packet(&datagram[..length]) {
                    write_frame(&mut writer, &datagram[..length]).await?;
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
    use rustls::{pki_types::CertificateDer, ClientConfig, RootCertStore};

    #[tokio::test]
    async fn voice_socks_request_upgrades_to_pinned_local_websocket_bridge() {
        use futures_util::{SinkExt, StreamExt};
        use rustls::pki_types::ServerName;
        use tokio_tungstenite::tungstenite::protocol::Message;

        let directory = std::env::temp_dir().join(format!(
            "dinmoo-voice-client-pipeline-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let identity =
            Arc::new(voice::identity::VoiceIdentity::load_or_create(&directory).unwrap());
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

        let (app, mut local) = tokio::io::duplex(64 * 1024);
        let (mut remote, gateway) = tokio::io::duplex(64 * 1024);
        let bridge_identity = identity.clone();
        let bridge = tokio::spawn(async move {
            proxy_socks_with_identity(&mut local, &mut remote, Some(&bridge_identity)).await
        });
        let mut app = app;
        let mut gateway = gateway;
        app.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0; 3];
        gateway.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 1, 0]);
        gateway.write_all(&[5, 0]).await.unwrap();
        let mut method_reply = [0; 2];
        app.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [5, 0]);

        let host = b"voice.discord.media";
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&443u16.to_be_bytes());
        app.write_all(&request).await.unwrap();
        let forwarded = read_socks_request(&mut gateway).await.unwrap();
        assert_eq!(forwarded[1], voice::SOCKS_VOICE_COMMAND);
        assert_eq!(
            socks_request_target(&forwarded).unwrap(),
            ("voice.discord.media".into(), 443)
        );
        gateway
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut request_reply = [0; 10];
        app.read_exact(&mut request_reply).await.unwrap();
        assert_eq!(request_reply, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

        let tls = TlsConnector::from(client_tls)
            .connect(ServerName::try_from("voice.discord.media").unwrap(), app)
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
        drop(identity);
        std::fs::remove_dir_all(directory).unwrap();
    }
}

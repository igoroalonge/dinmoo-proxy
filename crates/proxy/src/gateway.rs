//! Gateway server: TLS accept loop, tunnel authentication and SOCKS relay.
use crate::{
    policy::{allowed_destination, allowed_tcp_destination, is_public_ip, parse_media_targets},
    protection, session,
    socks::{read_socks_request, reply, reply_bound, socks_request_target},
    tunnel::read_string,
    udp::{forward_udp_response, parse_socks_udp_packet, valid_socks_udp_packet, FrameReader},
    voice, Config, ContextExt, Result, AUTH_HANDSHAKE_TIMEOUT, DESTINATION_CONNECT_TIMEOUT,
    SOCKS_HANDSHAKE_TIMEOUT, TCP_COPY_BUFFER_SIZE, TLS_HANDSHAKE_TIMEOUT,
};
use std::{
    collections::{HashMap, VecDeque},
    env, io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

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
        let (stream, peer) = listener.accept().await?;
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
            let result = async {
                stream.set_nodelay(true)?;
                handle_gateway_connection(stream, &cfg, peer.ip()).await
            }
            .await;
            if let Err(e) = result {
                eprintln!("session: {e:#}");
            }
        });
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
    *cfg.media_targets.write().await = targets;
    Ok(())
}

pub(crate) async fn handle_gateway_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    cfg: &Config,
    peer: IpAddr,
) -> Result<()> {
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
            eprintln!("SOCKS TCP destination denied: {host:?}:{port}");
            reply(stream, 2).await?;
            bail!("destination denied by policy");
        }
        let dest = format!("{host}:{port}");
        let mut target = None;
        for address in
            tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, tokio::net::lookup_host(&dest))
                .await
                .context("destination DNS lookup timed out")??
        {
            if !is_public_ip(address.ip()) {
                continue;
            }
            if let Ok(Ok(connection)) =
                tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, TcpStream::connect(address)).await
            {
                connection.set_nodelay(true)?;
                target = Some(connection);
                break;
            }
        }
        if let Some(mut target) = target {
            reply(stream, 0).await?;
            tokio::io::copy_bidirectional_with_sizes(
                stream,
                &mut target,
                TCP_COPY_BUFFER_SIZE,
                TCP_COPY_BUFFER_SIZE,
            )
            .await?;
        } else {
            reply(stream, 5).await?;
            bail!("Discord destination did not resolve to a reachable public address");
        }
        return Ok(());
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

async fn relay_udp_gateway<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    socket_v4: UdpSocket,
    socket_v6: Option<UdpSocket>,
    cfg: &Config,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer_v4 = vec![0; 1501];
    let mut buffer_v6 = vec![0; 1501];
    let mut permitted_targets: VecDeque<(SocketAddr, tokio::time::Instant)> = VecDeque::new();
    let mut dns_cache: HashMap<(String, u16), (tokio::time::Instant, Vec<SocketAddr>)> =
        HashMap::new();
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
            frame = frames.read(&mut reader) => {
                let packet = frame?;
                if !valid_socks_udp_packet(&packet) { continue; }
                let Ok((host, port, payload)) = parse_socks_udp_packet(&packet) else { continue; };
                if payload.is_empty() { continue; }
                if host.parse::<IpAddr>().is_err() && !allowed_destination(&host) {
                    continue;
                }
                let addresses = resolve_udp_addresses(&host, port, &mut dns_cache).await;
                if addresses.is_empty() { continue; }
                let mut destination = None;
                for address in addresses {
                    // DNS resolution and prior TCP use never create UDP authority.
                    if !allowed_udp_destination(cfg, address).await { continue; }
                    let sent = match address.ip() {
                        IpAddr::V4(_) => socket_v4.send_to(&payload, address).await,
                        IpAddr::V6(_) => match socket_v6.as_ref() {
                            Some(socket) => socket.send_to(&payload, address).await,
                            None => continue,
                        },
                    };
                    if sent.is_ok() {
                        destination = Some(address);
                        break;
                    }
                }
                if let Some(destination) = destination {
                    let now = tokio::time::Instant::now();
                    permitted_targets.retain(|(_, seen)| now.duration_since(*seen) <= Duration::from_secs(30));
                    if let Some(entry) = permitted_targets.iter_mut().find(|(peer, _)| *peer == destination) {
                        entry.1 = now;
                    } else {
                        if permitted_targets.len() >= 32 { permitted_targets.pop_front(); }
                        permitted_targets.push_back((destination, now));
                    }
                }
                continue;
            }
        };
        let buffer = if is_v6 { &buffer_v6 } else { &buffer_v4 };
        let now = tokio::time::Instant::now();
        permitted_targets.retain(|(_, seen)| now.duration_since(*seen) <= Duration::from_secs(30));
        if !permitted_targets.iter().any(|(peer, _)| *peer == source) {
            continue;
        }
        forward_udp_response(&mut writer, source, &buffer[..length]).await?;
    }
}

async fn resolve_udp_addresses(
    host: &str,
    port: u16,
    cache: &mut HashMap<(String, u16), (tokio::time::Instant, Vec<SocketAddr>)>,
) -> Vec<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    let key = (host.to_owned(), port);
    let now = tokio::time::Instant::now();
    if let Some((expires, addresses)) = cache.get(&key) {
        if *expires > now {
            return addresses.clone();
        }
    }
    cache.remove(&key);
    let Ok(Ok(addresses)) = tokio::time::timeout(
        DESTINATION_CONNECT_TIMEOUT,
        tokio::net::lookup_host((host, port)),
    )
    .await
    else {
        return Vec::new();
    };
    let addresses = addresses
        .filter(|address| is_public_ip(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return addresses;
    }
    if cache.len() >= 32 {
        cache.retain(|_, (expires, _)| *expires > now);
        if cache.len() >= 32 {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (expires, _))| *expires)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
    }
    cache.insert(key, (now + Duration::from_secs(30), addresses.clone()));
    addresses
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

async fn allowed_udp_destination(cfg: &Config, destination: SocketAddr) -> bool {
    is_public_ip(destination.ip()) && cfg.media_targets.read().await.contains(&destination)
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

    #[tokio::test]
    async fn udp_policy_requires_exact_current_operator_grant() {
        let cfg = test_config();
        let endpoint = "104.29.151.152:19317".parse().unwrap();
        assert!(!allowed_udp_destination(&cfg, endpoint).await);
        cfg.media_targets.write().await.push(endpoint);
        assert!(allowed_udp_destination(&cfg, endpoint).await);
        assert!(!allowed_udp_destination(&cfg, "104.29.151.152:19318".parse().unwrap()).await);
        assert!(!allowed_udp_destination(&cfg, "104.29.144.166:19317".parse().unwrap()).await);
        cfg.media_targets.write().await.clear();
        assert!(!allowed_udp_destination(&cfg, endpoint).await);
        cfg.media_targets
            .write()
            .await
            .push("127.0.0.1:19317".parse().unwrap());
        assert!(!allowed_udp_destination(&cfg, "127.0.0.1:19317".parse().unwrap()).await);
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
            .read()
            .await
            .contains(&"104.29.151.152:19317".parse().unwrap()));
        std::fs::write(&path, "104.29.144.166:19307").unwrap();
        reload_media_targets(&cfg, &base, &path).await.unwrap();
        let targets = cfg.media_targets.read().await.clone();
        assert_eq!(targets, ["104.29.144.166:19307".parse().unwrap(), base[0]]);
        std::fs::write(&path, "127.0.0.1:19307").unwrap();
        assert!(reload_media_targets(&cfg, &base, &path).await.is_err());
        assert_eq!(*cfg.media_targets.read().await, targets);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn udp_domain_resolution_uses_a_session_cache() {
        let destination: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let mut cache = HashMap::from([(
            ("discord.com".to_owned(), 443),
            (
                tokio::time::Instant::now() + Duration::from_secs(30),
                vec![destination],
            ),
        )]);
        assert_eq!(
            resolve_udp_addresses("discord.com", 443, &mut cache).await,
            [destination]
        );
        assert_eq!(cache.len(), 1);
        assert!(resolve_udp_addresses("1.1.1.1", 443, &mut cache)
            .await
            .contains(&destination));
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
        let certificate =
            CertificateDer::from(include_bytes!("../tests/fixtures/localhost-cert.der").to_vec());
        let root_certificate =
            CertificateDer::from(include_bytes!("../tests/fixtures/test-ca.der").to_vec());
        let private_key =
            PrivateKeyDer::try_from(include_bytes!("../tests/fixtures/localhost-key.der").to_vec())
                .unwrap();
        let server_tls = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], private_key)
                .unwrap(),
        ));
        let mut roots = RootCertStore::empty();
        roots.add(root_certificate).unwrap();
        let client_tls = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
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

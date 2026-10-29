//! Explicit, foreground macOS media routing. Does not install a default route.
use crate::{policy::parse_media_targets, socks::Address, Result};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tun::AbstractDevice;

pub async fn run(arguments: Vec<String>) -> Result<()> {
    let mut watch = if arguments.first().map(String::as_str) == Some("--watch") {
        if arguments.len() != 2 {
            return Err("usage: dinmoo-proxy media --watch <Discord log directory>".into());
        }
        Some(LogWatch::new(PathBuf::from(&arguments[1])))
    } else {
        None
    };
    let targets = match &mut watch {
        Some(watch) => watch.poll()?.unwrap_or_default(),
        None => parse_media_targets(&arguments.join(","))?,
    };
    let proxy = match std::env::var("DINMOO_MEDIA_SOCKS") {
        Ok(proxy) => proxy.parse()?,
        Err(_) => crate::DEFAULT_SOCKS_LISTEN,
    };
    if !proxy.ip().is_loopback() || proxy.port() == 0 {
        return Err("DINMOO_MEDIA_SOCKS must be a loopback address with a nonzero port".into());
    }
    if targets.is_empty() && watch.is_none() {
        return Err("usage: sudo dinmoo-proxy media <media-ip:port> [...]; the gateway must approve the same DINMOO_MEDIA_TARGETS".into());
    }
    if targets.iter().any(|target| target.is_ipv6()) {
        return Err(
            "this experimental macOS media command currently supports IPv4 endpoints".into(),
        );
    }
    let uid = Command::new("/usr/bin/id").arg("-u").output()?;
    if uid.stdout != b"0\n" {
        return Err("media capture requires administrator access: run with sudo".into());
    }
    // Verify the selected SOCKS service before changing any routes.
    verify_proxy(proxy).await?;
    let configuration = device_configuration();
    let device = tun::create_as_async(&configuration)?;
    let interface = device.tun_name()?;
    let mut routes = Routes {
        interface: interface.clone(),
        ips: Vec::new(),
    };
    routes.sync(&targets)?;
    eprintln!("Media routes on {interface}: {:?}. Destination IP routes apply to every app reaching those IPs. Ctrl-C removes the routes.", routes.ips);
    let cancellation = CancellationToken::new();
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let stop = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
        stop.cancel();
    });
    let adapter = run_packets(device, proxy, cancellation);
    tokio::pin!(adapter);
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    let result = loop {
        tokio::select! {
            result = &mut adapter => break result,
            _ = interval.tick(), if watch.is_some() => {
                let mut current = watch.take().expect("log watch");
                let (current, polled) = tokio::task::spawn_blocking(move || {
                    let polled = current.poll();
                    (current, polled)
                })
                .await?;
                watch = Some(current);
                let synced = polled.and_then(|targets| match targets {
                    Some(targets) => routes.sync(&targets),
                    None => Ok(()),
                });
                if let Err(error) = synced {
                    eprintln!("media endpoint tracking: {error}");
                }
            }
        }
    };
    signal_task.abort();
    drop(routes);
    result
}

const WEBRTC_LOGS: [&str; 2] = ["discord-webrtc_1", "discord-webrtc_0"];

/// Follows Discord's native WebRTC logs, rereading them only after one changes.
struct LogWatch {
    directory: PathBuf,
    seen: Vec<Option<(u64, SystemTime)>>,
}
impl LogWatch {
    fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            seen: Vec::new(),
        }
    }
    /// The current targets, or None while neither log has changed.
    fn poll(&mut self) -> Result<Option<Vec<SocketAddr>>> {
        let stamps: Vec<_> = WEBRTC_LOGS
            .iter()
            .map(|name| {
                let metadata = std::fs::metadata(self.directory.join(name)).ok()?;
                Some((metadata.len(), metadata.modified().ok()?))
            })
            .collect();
        if stamps == self.seen {
            return Ok(None);
        }
        let targets = read_media_targets(&self.directory)?;
        self.seen = stamps;
        Ok(Some(targets))
    }
}

fn read_media_targets(directory: &Path) -> Result<Vec<SocketAddr>> {
    use std::io::{Read, Seek, SeekFrom};
    if !directory.is_dir() {
        return Err("Discord log directory does not exist or is inaccessible".into());
    }
    let mut text = String::new();
    for name in WEBRTC_LOGS {
        let path = directory.join(name);
        let mut file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let size = file.metadata()?.len();
        file.seek(SeekFrom::Start(size.saturating_sub(512 * 1024)))?;
        let mut bytes = Vec::new();
        file.take(512 * 1024).read_to_end(&mut bytes)?;
        text.push_str(&String::from_utf8_lossy(&bytes));
        text.push('\n');
    }
    Ok(discover_targets(&text))
}

fn discover_targets(text: &str) -> Vec<std::net::SocketAddr> {
    let mut targets = Vec::new();
    for line in text.lines() {
        let marker = if line.contains("(voice_connection.cpp:") {
            "): Create connection to "
        } else if line.contains("(udp_socket.cpp:") {
            "): Sending ping to "
        } else {
            continue;
        };
        let Some((_, endpoint)) = line.split_once(marker) else {
            continue;
        };
        let Some(endpoint) = endpoint.split_whitespace().next() else {
            continue;
        };
        let Ok(target) = endpoint
            .trim_end_matches(',')
            .parse::<std::net::SocketAddr>()
        else {
            continue;
        };
        if !target.is_ipv4() || !crate::policy::is_public_ip(target.ip()) || target.port() == 0 {
            continue;
        }
        targets.retain(|known| *known != target);
        targets.push(target);
        if targets.len() > 64 {
            targets.remove(0);
        }
    }
    targets
}

fn device_configuration() -> tun::Configuration {
    let mut configuration = tun::Configuration::default();
    configuration
        .address((198, 18, 0, 1))
        .destination((198, 18, 0, 2))
        .netmask((255, 255, 255, 252))
        .mtu(1400)
        .up();
    // macOS utun always supplies a four-byte address-family header. Let the
    // TUN adapter strip it on reads and restore it on writes; ipstack sees IP.
    configuration.platform_config(|config| {
        config.packet_information(true);
    });
    configuration
}

async fn verify_proxy(proxy: std::net::SocketAddr) -> Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::desktop::check_discord_route_at(proxy),
    )
    .await
    .map_err(|_| format!("SOCKS preflight timed out at {proxy}"))??;
    Ok(())
}

pub(super) async fn run_packets<D>(
    device: D,
    proxy: std::net::SocketAddr,
    cancellation: CancellationToken,
) -> Result<()>
where
    D: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut config = ipstack::IpStackConfig::default();
    config.mtu(1400)?;
    config.udp_timeout(std::time::Duration::from_secs(60));
    let mut stack = ipstack::IpStack::new(config, device);
    let mut sessions = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                match result {
                    Ok(Ok(())) => {},
                    Ok(Err(error)) => eprintln!("media session: {error}"),
                    Err(error) => eprintln!("media task: {error}"),
                }
            }
            stream = stack.accept() => {
                if let ipstack::IpStackStream::Udp(stream) = stream? {
                    if sessions.len() < 64 {
                        sessions.spawn(relay_packet_stream(stream, proxy));
                    }
                }
            }
        }
    }
    Ok(())
}

async fn relay_packet_stream(
    mut stream: ipstack::IpStackUdpStream,
    proxy: std::net::SocketAddr,
) -> Result<()> {
    const IDLE: Duration = Duration::from_secs(60);
    let destination = stream.peer_addr();
    let mut control = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(proxy),
    )
    .await??;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let [high, low] = socket.local_addr()?.port().to_be_bytes();
    let relay = tokio::time::timeout(Duration::from_secs(10), async {
        control.write_all(&[5, 1, 0]).await?;
        let mut method = [0; 2];
        control.read_exact(&mut method).await?;
        if method != [5, 0] {
            return Err::<std::net::SocketAddr, Box<dyn std::error::Error + Send + Sync>>(
                "SOCKS UDP authentication failed".into(),
            );
        }
        // Declare the sending socket so the relay accepts datagrams only from it.
        control
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, high, low])
            .await?;
        let reply = crate::socks::read_socks_reply(&mut control).await?;
        if reply[1] != 0 {
            return Err("SOCKS UDP association rejected".into());
        }
        let (host, port) = crate::socks::socks_request_target(&reply)?;
        let relay = std::net::SocketAddr::new(host.parse()?, port);
        if !relay.ip().is_loopback() || port == 0 {
            return Err("SOCKS relay must be a loopback endpoint".into());
        }
        Ok(relay)
    })
    .await??;
    let mut packet = [0; 1500];
    let mut response = [0; 1500];
    let mut closed = [0];
    // Only relayed traffic keeps the association open.
    let idle = tokio::time::sleep(IDLE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            length = stream.read(&mut packet) => {
                let length = length?;
                if length == 0 { break; }
                let frame = crate::udp::encode_socks_udp_packet(destination, &packet[..length]);
                if frame.len() <= 1500 { socket.send_to(&frame, relay).await?; }
                idle.as_mut().reset(tokio::time::Instant::now() + IDLE);
            }
            received = socket.recv_from(&mut response) => {
                let (length, source) = received?;
                if source != relay { continue; }
                let (host, port, payload) = crate::udp::parse_socks_udp(&response[..length])?;
                if host == Address::Ip(destination.ip()) && port == destination.port() {
                    stream.write_all(payload).await?;
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE);
                }
            }
            _ = control.read(&mut closed) => break,
            _ = &mut idle => break,
        }
    }
    Ok(())
}

struct Routes {
    interface: String,
    ips: Vec<IpAddr>,
}
impl Routes {
    fn sync(&mut self, targets: &[std::net::SocketAddr]) -> Result<()> {
        let desired = targets
            .iter()
            .map(|target| target.ip())
            .collect::<BTreeSet<_>>();
        for ip in &desired {
            if self.ips.contains(ip) {
                continue;
            }
            let output = Command::new("/sbin/route")
                .args([
                    "-n",
                    "add",
                    "-inet",
                    "-host",
                    &ip.to_string(),
                    "-interface",
                    &self.interface,
                ])
                .output()?;
            if !output.status.success() {
                return Err(format!(
                    "could not add media route for {ip}: {}",
                    String::from_utf8_lossy(&output.stderr)
                )
                .into());
            }
            self.ips.push(*ip);
            eprintln!("Tracking Discord media IP {ip} on {}", self.interface);
        }
        let mut retained = Vec::new();
        for ip in &self.ips {
            if !desired.contains(ip) {
                let output = Command::new("/sbin/route")
                    .args([
                        "-n",
                        "delete",
                        "-inet",
                        "-host",
                        &ip.to_string(),
                        "-interface",
                        &self.interface,
                    ])
                    .output()?;
                if !output.status.success() {
                    retained.push(*ip);
                }
            } else {
                retained.push(*ip);
            }
        }
        self.ips = retained;
        Ok(())
    }
}
impl Drop for Routes {
    fn drop(&mut self) {
        for ip in &self.ips {
            let family = if ip.is_ipv6() { "-inet6" } else { "-inet" };
            let result = Command::new("/sbin/route")
                .args([
                    "-n",
                    "delete",
                    family,
                    "-host",
                    &ip.to_string(),
                    "-interface",
                    &self.interface,
                ])
                .output();
            if let Err(error) = result {
                eprintln!("media route cleanup for {ip}: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn discovery_follows_changed_media_ips_and_ports() {
        let text = "[now] [1] (voice_connection.cpp:728): Create connection to 104.29.143.52:19332 with ssrc: 1\n\
            [now] [1] (voice_connection.cpp:728): Create connection to 104.29.151.152:19317 with ssrc: 2\n\
            [now] [1] (voice_connection.cpp:728): Create connection to 104.29.151.152:19318 with ssrc: 3\n\
            [now] [1] (voice_connection.cpp:728): Create connection to 127.0.0.1:443 with ssrc: 4\n\
            [now] [1] (voice_connection.cpp:728): Create connection to 104.29.143.52:19332 with ssrc: 5\n\
            [now] [1] (voice_connection.cpp:728): Create connection to 104.29.151.152:0 with ssrc: 6";
        let targets = discover_targets(text);
        assert_eq!(
            targets,
            [
                "104.29.151.152:19317".parse().unwrap(),
                "104.29.151.152:19318".parse().unwrap(),
                "104.29.143.52:19332".parse().unwrap()
            ]
        );
    }

    #[test]
    fn discovery_keeps_active_servers_from_native_pings() {
        assert_eq!(
            discover_targets(
                "[now] [1] (udp_socket.cpp:1222): Sending ping to 104.29.151.152:19317, seq: 50"
            ),
            ["104.29.151.152:19317".parse().unwrap()]
        );
        assert!(
            discover_targets("[now] [1] JS console: Sending ping to 104.29.151.152:19317")
                .is_empty()
        );
    }

    #[test]
    fn watched_logs_are_reread_only_after_they_change() {
        let directory = std::env::temp_dir().join(format!(
            "dinmoo-media-watch-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let line = |port: u16| {
            format!("[now] [1] (voice_connection.cpp:728): Create connection to 104.29.151.152:{port} with ssrc: 1\n")
        };
        let log = directory.join("discord-webrtc_0");
        std::fs::write(&log, line(19317)).unwrap();
        let mut watch = LogWatch::new(directory.clone());
        let first = watch.poll().unwrap();
        let unchanged = watch.poll().unwrap();
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::io::Write::write_all(&mut file, line(19318).as_bytes()).unwrap();
        let appended = watch.poll().unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        let target = |port| std::net::SocketAddr::from(([104, 29, 151, 152], port));
        assert_eq!(first, Some(vec![target(19317)]));
        assert_eq!(unchanged, None);
        assert_eq!(appended, Some(vec![target(19317), target(19318)]));
    }

    #[tokio::test]
    async fn media_preflight_checks_selected_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let selected = listener.local_addr().unwrap();
        assert_ne!(selected.port(), 1080);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            socket.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            socket.write_all(&[5, 0]).await.unwrap();
            let request = crate::socks::read_socks_request(&mut socket).await.unwrap();
            assert_eq!(
                crate::socks::socks_request_target(&request).unwrap(),
                ("discord.com".into(), 443)
            );
            crate::socks::reply(&mut socket, 0).await.unwrap();
        });
        verify_proxy(selected).await.unwrap();
        server.await.unwrap();
    }

    // Drives the real packet adapter and local SOCKS UDP tunnel without creating
    // a privileged utun or touching the host routing table.
    #[tokio::test]
    async fn native_udp_packet_with_macos_headers_round_trips_through_socks_tunnel() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = listener.local_addr().unwrap();
            let payload = b"screen-share-packet";
            let server = tokio::spawn(async move {
                let (mut application, _) = listener.accept().await.unwrap();
                let (mut client, mut gateway) = tokio::io::duplex(4096);
                let relay = tokio::spawn(async move {
                    crate::tunnel::proxy_socks(&mut application, &mut client).await
                });
                let mut greeting = [0; 2];
                gateway.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting[0], 5);
                let mut methods = vec![0; greeting[1] as usize];
                gateway.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&0));
                gateway.write_all(&[5, 0]).await.unwrap();
                let request = crate::socks::read_socks_request(&mut gateway)
                    .await
                    .unwrap();
                assert_eq!(request[1], 3, "native UDP must use SOCKS UDP ASSOCIATE");
                let (host, port) = crate::socks::socks_request_target(&request).unwrap();
                assert_eq!(host, "127.0.0.1", "the request declares its UDP socket");
                assert_ne!(port, 0);
                gateway
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let packet = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    crate::udp::read_frame(&mut gateway),
                )
                .await
                .expect("adapter never sent UDP frame")
                .unwrap();
                let (host, port, received) = crate::udp::parse_socks_udp_packet(&packet).unwrap();
                assert_eq!(host, "104.29.143.52");
                assert_eq!(port, 19332);
                assert_eq!(received, payload);
                crate::udp::write_frame(&mut gateway, &packet)
                    .await
                    .unwrap();
                // Keep the control connection alive until the caller verifies the reply.
                std::future::pending::<()>().await;
                relay.abort();
            });
            // Exercise the actual macOS tun reader/writer, with utun's mandatory
            // four-byte AF_INET prefix on the kernel side. The socket pair is
            // a fixture for the kernel descriptor and requires no root access.
            use std::os::fd::IntoRawFd;
            let (host, kernel) = std::os::unix::net::UnixDatagram::pair().unwrap();
            host.set_nonblocking(true).unwrap();
            let host = tokio::net::UnixDatagram::from_std(host).unwrap();
            let mut configuration = device_configuration();
            configuration.raw_fd(kernel.into_raw_fd());
            let device = tun::create_as_async(&configuration).unwrap();
            let cancel = CancellationToken::new();
            let adapter = tokio::spawn(run_packets(device, proxy, cancel.clone()));
            let mut packet = vec![0u8; 28 + payload.len()];
            packet[0] = 0x45;
            let length = packet.len() as u16;
            packet[2..4].copy_from_slice(&length.to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&[198, 18, 0, 1]);
            packet[16..20].copy_from_slice(&[104, 29, 143, 52]);
            packet[20..22].copy_from_slice(&54000u16.to_be_bytes());
            packet[22..24].copy_from_slice(&19332u16.to_be_bytes());
            packet[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            packet[28..].copy_from_slice(payload);
            let mut sum: u32 = packet[..20]
                .chunks_exact(2)
                .map(|word| u16::from_be_bytes([word[0], word[1]]) as u32)
                .sum();
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            let mut kernel_packet = vec![0, 0, 0, 2];
            kernel_packet.extend_from_slice(&packet);
            host.send(&kernel_packet).await.unwrap();
            let mut response = vec![0; packet.len() + 4];
            let length =
                tokio::time::timeout(std::time::Duration::from_secs(3), host.recv(&mut response))
                    .await
                    .expect("adapter did not return IP packet")
                    .unwrap();
            assert_eq!(length, kernel_packet.len());
            assert_eq!(&response[..4], &[0, 0, 0, 2]);
            let response = &response[4..];
            assert_eq!(&response[12..16], &[104, 29, 143, 52]);
            assert_eq!(&response[16..20], &[198, 18, 0, 1]);
            assert_eq!(&response[28..], payload);
            cancel.cancel();
            adapter.await.unwrap().unwrap();
            server.abort();
        })
        .await
        .expect("native packet round trip timed out");
    }
}

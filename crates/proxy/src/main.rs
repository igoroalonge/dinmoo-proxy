use std::{error::Error, io};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*).into()) } }
trait ContextExt<T> {
    fn context(self, message: &'static str) -> Result<T>;
}
impl<T, E: Error + Send + Sync + 'static> ContextExt<T> for std::result::Result<T, E> {
    // Keeps the error kind so callers can still tell disconnects and timeouts apart.
    fn context(self, message: &'static str) -> Result<T> {
        self.map_err(|e| {
            let source: &(dyn Error + 'static) = &e;
            let kind = match source.downcast_ref::<io::Error>() {
                Some(error) => error.kind(),
                None if source.is::<tokio::time::error::Elapsed>() => io::ErrorKind::TimedOut,
                None => io::ErrorKind::Other,
            };
            io::Error::new(kind, format!("{message}: {e}")).into()
        })
    }
}
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{
    env,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio_rustls::TlsAcceptor;
#[cfg(test)]
mod bench;
mod desktop;
mod gateway;
mod peer;
mod policy;
mod protection;
mod session;
mod socks;
mod tunnel;
mod udp;
mod voice;

#[cfg(target_os = "macos")]
mod media;

const DEFAULT_MAX_SESSIONS: usize = 1024;
const MAX_MAX_SESSIONS: usize = 4096;
const TCP_COPY_BUFFER_SIZE: usize = 32 * 1024;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AUTH_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SOCKS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DESTINATION_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Where the client services listen and where Discord is pointed.
const DEFAULT_SOCKS_LISTEN: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1080));

fn discord_proxy_url(listen: SocketAddr) -> String {
    format!("socks5://{listen}")
}

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    upstream: Option<String>,
    token: String,
    client_tls: Arc<ClientConfig>,
    upstream_tls: Arc<ClientConfig>,
    server_tls: Option<TlsAcceptor>,
    media_targets: policy::MediaTargets,
    dns: Arc<gateway::DnsCache>,
    voice_identity: Option<Arc<voice::identity::Store>>,
    sessions: session::Registry,
}

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next().unwrap_or_else(|| "client".into());
    runtime(&first)?.block_on(run(first, args))
}

fn runtime(mode: &str) -> io::Result<tokio::runtime::Runtime> {
    let mut builder = match mode {
        // spawn_blocking (getaddrinfo) panics when no blocking thread can be created;
        // stay well inside the gateway unit's TasksMax.
        "gateway" => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.max_blocking_threads(32);
            builder
        }
        "media" => tokio::runtime::Builder::new_multi_thread(),
        _ => tokio::runtime::Builder::new_current_thread(),
    };
    builder.enable_all().build()
}

async fn run(first: String, mut args: std::iter::Skip<env::Args>) -> Result<()> {
    if first == "gateway-sessions" {
        println!("{}", session::admin::request("LIST").await?);
        return Ok(());
    }
    if first == "gateway-terminate" {
        let id = args
            .next()
            .ok_or("usage: dinmoo-proxy gateway-terminate <session-id>")?;
        if id.len() != 32 || hex::decode(&id).is_err() {
            bail!("session ID must contain 32 hex characters");
        }
        println!(
            "{}",
            session::admin::request(&format!("TERMINATE {id}")).await?
        );
        return Ok(());
    }
    if first == "voice-identity" {
        let identity = voice::identity::VoiceIdentity::load_or_create(
            &voice::identity::identity_directory()?,
        )?;
        println!(
            "Voice bridge identity ready; SPKI pin: {}",
            identity.spki_pin
        );
        return Ok(());
    }
    if first == "media" {
        #[cfg(target_os = "macos")]
        return media::run(args.collect()).await;
        #[cfg(not(target_os = "macos"))]
        bail!("native media capture is currently supported only on macOS");
    }
    if first == "on" || first == "off" {
        let enabled = first == "on";
        if enabled {
            desktop::set_client_enabled(true)?;
            desktop::wait_for_discord_route().await?;
            desktop::restart_discord(&discord_proxy_url(DEFAULT_SOCKS_LISTEN)).await?;
        } else {
            desktop::disable_proxy()?;
        }
        println!("Discord proxy is {}.", if enabled { "on" } else { "off" });
        return Ok(());
    }
    if first == "status" {
        if !desktop::client_service_running()? {
            println!("Discord proxy is off.");
            return Ok(());
        }
        match tokio::time::timeout(Duration::from_secs(5), desktop::check_discord_route()).await {
            Ok(Ok(())) => println!("Discord proxy is on; gateway reaches Discord over TCP. Native media is not verified by this check."),
            _ => bail!("client service is running, but the Discord route is unavailable"),
        }
        return Ok(());
    }
    if first == "--help" || first == "-h" || first == "help" {
        println!("dinmoo-proxy\nUsage:\n  dinmoo-proxy install\n  dinmoo-proxy install-local\n  dinmoo-proxy check\n  dinmoo-proxy on\n  dinmoo-proxy off\n  dinmoo-proxy status\n  dinmoo-proxy uninstall\n  dinmoo-proxy client [listen-address] [gateway-address]\n  dinmoo-proxy gateway [listen-address]\n  dinmoo-proxy gateway-sessions\n  dinmoo-proxy gateway-terminate <session-id>\n  dinmoo-proxy discord [socks5-url]\n  sudo dinmoo-proxy media <media-ip:port> [...] (experimental macOS)\n\nPublic access: no token required. Optional private gateway: DINMOO_PROXY_TOKEN (minimum 32 bytes); DINMOO_MAX_SESSIONS (default 1024, maximum 4096); gateway also requires DINMOO_TLS_CERT_DER and DINMOO_TLS_KEY_DER files.");
        return Ok(());
    }
    if first == "install" {
        return desktop::install().await;
    }
    if first == "install-local" {
        let path = env::current_exe()?;
        let token = env::var("DINMOO_PROXY_TOKEN").unwrap_or_default();
        desktop::validate_install_token(&token)?;
        return desktop::install_local(&path, &token).await;
    }
    if first == "check" {
        return desktop::wait_for_discord_route().await;
    }
    if first == "uninstall" {
        return desktop::uninstall();
    }
    if first == "discord" {
        let proxy = args
            .next()
            .unwrap_or_else(|| discord_proxy_url(DEFAULT_SOCKS_LISTEN));
        return desktop::restart_discord(&proxy).await;
    }
    let mode = first;
    if mode != "client" && mode != "gateway" {
        bail!("unknown mode '{mode}'. Use --help.");
    }
    let listen: SocketAddr = match args.next() {
        Some(listen) => listen.parse()?,
        None if mode == "gateway" => "0.0.0.0:8443".parse()?,
        None => DEFAULT_SOCKS_LISTEN,
    };
    if mode == "client" && !listen.ip().is_loopback() {
        bail!("local SOCKS listener must bind to a loopback address");
    }
    let token = env::var("DINMOO_PROXY_TOKEN").unwrap_or_default();
    if !token.is_empty() && (token.len() < 32 || token.len() > 1024) {
        bail!("DINMOO_PROXY_TOKEN must be 32 to 1024 bytes");
    }
    let extra_root = match env::var("DINMOO_TLS_ROOT_DER") {
        Ok(path) => Some(CertificateDer::from(std::fs::read(path)?)),
        Err(_) => None,
    };
    let (client_tls, upstream_tls) = tls_clients(extra_root)?;
    let server_tls = if mode == "gateway" {
        let cert_paths = env::var("DINMOO_TLS_CERT_DER").context(
            "set DINMOO_TLS_CERT_DER to comma-separated DER certificate files (leaf first)",
        )?;
        let key_path = env::var("DINMOO_TLS_KEY_DER")
            .context("set DINMOO_TLS_KEY_DER to a DER private key file")?;
        let certs = cert_paths
            .split(',')
            .map(|path| std::fs::read(path.trim()).map(CertificateDer::from))
            .collect::<std::io::Result<Vec<_>>>()?;
        if certs.is_empty() {
            bail!("DINMOO_TLS_CERT_DER must include a leaf certificate");
        }
        let key = PrivateKeyDer::try_from(std::fs::read(key_path)?)?;
        Some(TlsAcceptor::from(Arc::new(gateway_tls(certs, key)?)))
    } else {
        None
    };
    let settings = if mode == "gateway" {
        Some(protection::Settings::from_env()?)
    } else {
        None
    };
    let config = Arc::new(Config {
        listen,
        sessions: session::Registry::new(
            settings
                .as_ref()
                .map(|s| s.idle)
                .unwrap_or(Duration::from_secs(600)),
        ),
        upstream: if mode == "client" {
            Some(
                args.next()
                    .unwrap_or_else(|| "api-proxy.dinmoo.com:443".into()),
            )
        } else {
            None
        },
        token,
        client_tls,
        upstream_tls,
        server_tls,
        media_targets: policy::MediaTargets::new(policy::parse_media_targets(
            &env::var("DINMOO_MEDIA_TARGETS").unwrap_or_default(),
        )?),
        dns: Default::default(),
        voice_identity: if mode == "client" {
            match voice::identity::identity_directory().and_then(voice::identity::Store::open) {
                Ok(store) => Some(Arc::new(store)),
                Err(error) => {
                    eprintln!("voice bridge disabled: {error}");
                    None
                }
            }
        } else {
            None
        },
    });
    if mode == "gateway" {
        if let Some(path) = env::var_os("DINMOO_MEDIA_TARGETS_FILE") {
            let path = std::path::PathBuf::from(path);
            let base = config.media_targets.snapshot();
            gateway::reload_media_targets(&config, &base, &path).await?;
            let cfg = config.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    if let Err(error) = gateway::reload_media_targets(&cfg, &base, &path).await {
                        eprintln!("media target reload: {error}");
                    }
                }
            });
        }
    }
    let max_sessions = configured_max_sessions()?;
    if mode == "client" {
        return session::client::run(config, max_sessions).await;
    }
    let settings = settings.ok_or("gateway safeguards not configured")?;
    gateway::serve(config, settings, max_sessions).await
}

/// Returns (client trust for the dinmoo gateway, trust for Discord upstreams). A test or
/// private root extends only the former.
fn tls_clients(
    extra_root: Option<CertificateDer<'static>>,
) -> Result<(Arc<ClientConfig>, Arc<ClientConfig>)> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let upstream = ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    if let Some(root) = extra_root {
        roots.add(root)?;
    }
    let gateway = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok((Arc::new(gateway), Arc::new(upstream)))
}

fn gateway_tls(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // Stateless TLS 1.3 tickets survive server cache churn. Resumed connections still
    // authenticate with DMPX, and early data stays disabled (no replayable 0-RTT).
    config.ticketer = rustls::crypto::ring::Ticketer::new()?;
    Ok(config)
}

fn configured_max_sessions() -> Result<usize> {
    match env::var("DINMOO_MAX_SESSIONS") {
        Ok(value) => parse_max_sessions(&value),
        Err(env::VarError::NotPresent) => Ok(DEFAULT_MAX_SESSIONS),
        Err(error) => Err(error.into()),
    }
}

fn parse_max_sessions(value: &str) -> Result<usize> {
    let value = value.parse::<usize>()?;
    if !(1..=MAX_MAX_SESSIONS).contains(&value) {
        bail!("DINMOO_MAX_SESSIONS must be between 1 and {MAX_MAX_SESSIONS}");
    }
    Ok(value)
}

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    let client_tls = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    );
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        upstream: None,
        token: "test-token-for-in-memory-protocol".into(),
        client_tls: client_tls.clone(),
        upstream_tls: client_tls,
        server_tls: None,
        media_targets: Default::default(),
        dns: Default::default(),
        voice_identity: None,
        sessions: session::Registry::new(Duration::from_secs(600)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{pki_types::ServerName, HandshakeKind};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        runtime::RuntimeFlavor,
    };
    use tokio_rustls::TlsConnector;

    const FIXTURE_CERT: &[u8] = include_bytes!("../tests/fixtures/localhost-cert.der");
    const FIXTURE_KEY: &[u8] = include_bytes!("../tests/fixtures/localhost-key.der");
    const FIXTURE_CA: &[u8] = include_bytes!("../tests/fixtures/test-ca.der");

    fn fixture_server() -> ServerConfig {
        gateway_tls(
            vec![CertificateDer::from(FIXTURE_CERT.to_vec())],
            PrivateKeyDer::try_from(FIXTURE_KEY.to_vec()).unwrap(),
        )
        .unwrap()
    }

    /// Connects to `acceptor` in memory; returns the client's handshake kind.
    async fn handshake(
        acceptor: TlsAcceptor,
        client: Arc<ClientConfig>,
    ) -> std::io::Result<Option<HandshakeKind>> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await?;
            tls.write_u8(1).await?;
            tls.flush().await?;
            Ok::<_, std::io::Error>(tls)
        });
        let mut tls = TlsConnector::from(client)
            .connect(ServerName::try_from("localhost").unwrap(), client_io)
            .await?;
        tls.read_u8().await?;
        drop(server.await.unwrap()?);
        Ok(tls.get_ref().1.handshake_kind())
    }

    #[tokio::test]
    async fn gateway_tls_resumes_from_stateless_tickets_without_early_data() {
        let mut server = fixture_server();
        assert!(server.ticketer.enabled());
        assert_eq!(server.max_early_data_size, 0);
        // Without a server-side session cache, only tickets can resume.
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let (gateway, _) = tls_clients(Some(CertificateDer::from(FIXTURE_CA.to_vec()))).unwrap();
        let mut kinds = Vec::new();
        for _ in 0..2 {
            kinds.push(handshake(acceptor.clone(), gateway.clone()).await.unwrap());
        }
        assert_eq!(
            kinds,
            [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
        );
    }

    #[tokio::test]
    async fn extra_root_extends_only_the_gateway_trust() {
        let acceptor = TlsAcceptor::from(Arc::new(fixture_server()));
        let (gateway, upstream) =
            tls_clients(Some(CertificateDer::from(FIXTURE_CA.to_vec()))).unwrap();
        assert!(handshake(acceptor.clone(), gateway).await.is_ok());
        assert!(handshake(acceptor.clone(), upstream).await.is_err());
        let (gateway, _) = tls_clients(None).unwrap();
        assert!(handshake(acceptor, gateway).await.is_err());
    }

    #[test]
    fn each_mode_gets_its_own_runtime_flavor() {
        for (mode, flavor) in [
            ("client", RuntimeFlavor::CurrentThread),
            ("status", RuntimeFlavor::CurrentThread),
            ("gateway-sessions", RuntimeFlavor::CurrentThread),
            ("gateway", RuntimeFlavor::MultiThread),
            ("media", RuntimeFlavor::MultiThread),
        ] {
            assert_eq!(
                runtime(mode).unwrap().handle().runtime_flavor(),
                flavor,
                "{mode}"
            );
        }
    }

    #[test]
    fn discord_is_pointed_at_the_default_client_listener() {
        assert_eq!(
            discord_proxy_url(DEFAULT_SOCKS_LISTEN),
            "socks5://127.0.0.1:1080"
        );
    }

    #[test]
    fn session_capacity_is_bounded_and_rejects_invalid_values() {
        assert_eq!(parse_max_sessions("1").unwrap(), 1);
        assert_eq!(parse_max_sessions("4096").unwrap(), MAX_MAX_SESSIONS);
        for value in ["0", "4097", "many", "-1"] {
            assert!(parse_max_sessions(value).is_err(), "accepted {value}");
        }
    }
}

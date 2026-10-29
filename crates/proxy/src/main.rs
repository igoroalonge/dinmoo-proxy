use std::{error::Error, io};
type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*).into()) } }
trait ContextExt<T> {
    fn context(self, message: &'static str) -> Result<T>;
}
impl<T, E: Error + Send + Sync + 'static> ContextExt<T> for std::result::Result<T, E> {
    fn context(self, message: &'static str) -> Result<T> {
        self.map_err(|e| io::Error::other(format!("{message}: {e}")).into())
    }
}
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
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

#[derive(Clone)]
struct Config {
    listen: SocketAddr,
    upstream: Option<String>,
    token: String,
    client_tls: Arc<ClientConfig>,
    server_tls: Option<TlsAcceptor>,
    media_targets: Arc<tokio::sync::RwLock<Vec<SocketAddr>>>,
    voice_identity: Option<Arc<voice::identity::Store>>,
    sessions: session::Registry,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next().unwrap_or_else(|| "client".into());
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
        desktop::set_client_enabled(enabled)?;
        if enabled {
            desktop::wait_for_discord_route().await?;
            desktop::restart_discord("socks5://127.0.0.1:1080")?;
        } else {
            desktop::restart_discord_direct()?;
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
        desktop::install_user_service(&path, &token)?;
        desktop::wait_for_discord_route().await?;
        return desktop::restart_discord("socks5://127.0.0.1:1080");
    }
    if first == "check" {
        return desktop::wait_for_discord_route().await;
    }
    if first == "uninstall" {
        return desktop::uninstall();
    }
    if first == "discord" {
        return desktop::restart_discord(
            args.next().as_deref().unwrap_or("socks5://127.0.0.1:1080"),
        );
    }
    let mode = first;
    if mode != "client" && mode != "gateway" {
        bail!("unknown mode '{mode}'. Use --help.");
    }
    let listen: SocketAddr = args
        .next()
        .unwrap_or_else(|| {
            if mode == "gateway" {
                "0.0.0.0:8443"
            } else {
                "127.0.0.1:1080"
            }
            .into()
        })
        .parse()?;
    if mode == "client" && !listen.ip().is_loopback() {
        bail!("local SOCKS listener must bind to a loopback address");
    }
    let token = env::var("DINMOO_PROXY_TOKEN").unwrap_or_default();
    if !token.is_empty() && (token.len() < 32 || token.len() > 1024) {
        bail!("DINMOO_PROXY_TOKEN must be 32 to 1024 bytes");
    }
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Ok(root_path) = env::var("DINMOO_TLS_ROOT_DER") {
        root_store.add(CertificateDer::from(std::fs::read(root_path)?))?;
    }
    let client_tls = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
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
        Some(TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?,
        )))
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
        server_tls,
        media_targets: Arc::new(tokio::sync::RwLock::new(policy::parse_media_targets(
            &env::var("DINMOO_MEDIA_TARGETS").unwrap_or_default(),
        )?)),
        voice_identity: if mode == "client" {
            Some(Arc::new(voice::identity::Store::open(
                voice::identity::identity_directory()?,
            )?))
        } else {
            None
        },
    });
    if mode == "gateway" {
        if let Some(path) = env::var_os("DINMOO_MEDIA_TARGETS_FILE") {
            let path = std::path::PathBuf::from(path);
            let base = config.media_targets.read().await.clone();
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
        client_tls,
        server_tls: None,
        media_targets: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        voice_identity: None,
        sessions: session::Registry::new(Duration::from_secs(600)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_capacity_is_bounded_and_rejects_invalid_values() {
        assert_eq!(parse_max_sessions("1").unwrap(), 1);
        assert_eq!(parse_max_sessions("4096").unwrap(), MAX_MAX_SESSIONS);
        for value in ["0", "4097", "many", "-1"] {
            assert!(parse_max_sessions(value).is_err(), "accepted {value}");
        }
    }
}

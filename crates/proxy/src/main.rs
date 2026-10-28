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
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    env,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
    approved_udp_ips: Arc<tokio::sync::RwLock<HashMap<IpAddr, tokio::time::Instant>>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let first = args.next().unwrap_or_else(|| "client".into());
    if first == "on" || first == "off" {
        let enabled = first == "on";
        set_client_enabled(enabled)?;
        if enabled {
            wait_for_discord_route().await?;
            restart_discord("socks5://127.0.0.1:1080")?;
        } else {
            restart_discord_direct()?;
        }
        println!("Discord proxy is {}.", if enabled { "on" } else { "off" });
        return Ok(());
    }
    if first == "status" {
        if !client_service_running()? {
            println!("Discord proxy is off.");
            return Ok(());
        }
        match tokio::time::timeout(Duration::from_secs(5), check_discord_route()).await {
            Ok(Ok(())) => println!("Discord proxy is on; gateway reaches Discord."),
            _ => bail!("client service is running, but the Discord route is unavailable"),
        }
        return Ok(());
    }
    if first == "--help" || first == "-h" || first == "help" {
        println!("dinmoo-proxy\nUsage:\n  dinmoo-proxy install\n  dinmoo-proxy install-local\n  dinmoo-proxy check\n  dinmoo-proxy on\n  dinmoo-proxy off\n  dinmoo-proxy status\n  dinmoo-proxy uninstall\n  dinmoo-proxy client [listen-address] [gateway-address]\n  dinmoo-proxy gateway [listen-address]\n  dinmoo-proxy discord [socks5-url]\n\nPublic access: no token required. Optional private gateway: DINMOO_PROXY_TOKEN (minimum 32 bytes); DINMOO_MAX_SESSIONS (default 1024, maximum 4096); gateway also requires DINMOO_TLS_CERT_DER and DINMOO_TLS_KEY_DER files.");
        return Ok(());
    }
    if first == "install" {
        return install().await;
    }
    if first == "install-local" {
        let path = env::current_exe()?;
        let token = env::var("DINMOO_PROXY_TOKEN").unwrap_or_default();
        validate_install_token(&token)?;
        install_user_service(&path, &token)?;
        wait_for_discord_route().await?;
        return restart_discord("socks5://127.0.0.1:1080");
    }
    if first == "check" {
        return wait_for_discord_route().await;
    }
    if first == "uninstall" {
        return uninstall();
    }
    if first == "discord" {
        return restart_discord(args.next().as_deref().unwrap_or("socks5://127.0.0.1:1080"));
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
    let config = Arc::new(Config {
        listen,
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
        approved_udp_ips: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
    });
    let max_sessions = configured_max_sessions()?;
    let listener = TcpListener::bind(config.listen).await?;
    eprintln!(
        "{mode} listening on {} (max sessions: {max_sessions})",
        config.listen
    );
    let sessions = Arc::new(tokio::sync::Semaphore::new(max_sessions));
    let mut rejected_sessions = 0u64;
    let mut next_rejection_log = 1001u64;
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = sessions.clone().try_acquire_owned() else {
            rejected_sessions = rejected_sessions.saturating_add(1);
            if rejected_sessions == 1 || rejected_sessions == next_rejection_log {
                eprintln!("session capacity reached; rejected {rejected_sessions} connections");
                next_rejection_log = next_rejection_log.saturating_add(1000);
            }
            drop(stream);
            continue;
        };
        let cfg = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(stream, cfg).await {
                eprintln!("session: {e:#}");
            }
        });
    }
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

#[derive(Deserialize)]
struct ReleaseAsset {
    url: String,
    sha256: String,
}
#[derive(Deserialize)]
struct ReleaseManifest {
    assets: std::collections::HashMap<String, ReleaseAsset>,
}

async fn install() -> Result<()> {
    let token = env::var("DINMOO_PROXY_TOKEN").unwrap_or_default();
    validate_install_token(&token)?;
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        bail!("unsupported operating system")
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => bail!("unsupported CPU architecture: {other}"),
    };
    let key = format!("{os}-{arch}");
    let manifest_url =
        "https://github.com/igoroalonge/dinmoo-proxy/releases/latest/download/latest.json";
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let allowed = attempt.url().scheme() == "https"
                && matches!(
                    attempt.url().host_str(),
                    Some(
                        "github.com"
                            | "release-assets.githubusercontent.com"
                            | "objects.githubusercontent.com"
                    )
                );
            if attempt.previous().len() >= 10 || !allowed {
                attempt.error("untrusted release redirect")
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    let manifest_response = http.get(manifest_url).send().await?.error_for_status()?;
    if manifest_response.content_length().unwrap_or(0) > 1_048_576 {
        bail!("release manifest exceeds 1 MiB");
    }
    let manifest_bytes = read_limited_body(manifest_response, 1_048_576).await?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)?;
    let asset = manifest
        .assets
        .get(&key)
        .ok_or_else(|| format!("release has no asset for {key}"))?;
    let parsed_url = reqwest::Url::parse(&asset.url)?;
    if parsed_url.scheme() != "https"
        || parsed_url.host_str() != Some("github.com")
        || !parsed_url
            .path()
            .starts_with("/igoroalonge/dinmoo-proxy/releases/download/")
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
    {
        bail!("release asset URL is outside the trusted download host");
    }
    let response = http.get(parsed_url).send().await?.error_for_status()?;
    if response.content_length().unwrap_or(0) > 50 * 1024 * 1024 {
        bail!("release binary exceeds 50 MiB");
    }
    let bytes = read_limited_body(response, 50 * 1024 * 1024).await?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != asset.sha256.to_ascii_lowercase() {
        bail!("download hash mismatch; refusing to install");
    }
    let root = if cfg!(target_os = "windows") {
        std::env::var("LOCALAPPDATA")?
    } else {
        std::env::var("HOME")?
    };
    let bin = if cfg!(target_os = "windows") {
        std::path::PathBuf::from(root)
            .join("Programs")
            .join("DinmooProxy")
    } else {
        std::path::PathBuf::from(root).join(".local").join("bin")
    };
    std::fs::create_dir_all(&bin)?;
    let filename = if cfg!(target_os = "windows") {
        "dinmoo-proxy.exe"
    } else {
        "dinmoo-proxy"
    };
    let target = bin.join(filename);
    let temp = bin.join(format!("{filename}.download"));
    std::fs::write(&temp, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(target_os = "windows")]
    if target.exists() {
        let updater = "$ErrorActionPreference='Stop'; Wait-Process -Id ([int]$env:DINMOO_PARENT_PID); $running=@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:DINMOO_UPDATE_TARGET }); foreach ($p in $running) { Stop-Process -Id $p.ProcessId -Force; Wait-Process -Id $p.ProcessId -ErrorAction SilentlyContinue }; Move-Item -LiteralPath $env:DINMOO_UPDATE_FILE -Destination $env:DINMOO_UPDATE_TARGET -Force; & $env:DINMOO_UPDATE_TARGET install-local; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }";
        std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", updater])
            .env("DINMOO_PARENT_PID", std::process::id().to_string())
            .env("DINMOO_UPDATE_FILE", &temp)
            .env("DINMOO_UPDATE_TARGET", &target)
            .env("DINMOO_PROXY_TOKEN", &token)
            .spawn()?;
        println!("Update queued; the Windows client will restart after this command exits.");
        return Ok(());
    }
    std::fs::rename(temp, &target)?;
    install_user_service(&target, &token)?;
    println!("Installed verified {key} binary at {}", target.display());
    wait_for_discord_route().await?;
    restart_discord("socks5://127.0.0.1:1080")?;
    Ok(())
}

async fn read_limited_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut body =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(limit as u64) as usize);
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > limit {
            bail!("download exceeds configured size limit");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn wait_for_discord_route() -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut last_error = String::from("local SOCKS listener did not accept connections");
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("proxy service did not reach discord.com:443: {last_error}");
        }
        let attempt =
            tokio::time::timeout(remaining.min(Duration::from_secs(3)), check_discord_route())
                .await;
        match attempt {
            Ok(Ok(())) => {
                eprintln!("Verified SOCKS tunnel to discord.com:443");
                return Ok(());
            }
            Ok(Err(error)) => last_error = error.to_string(),
            Err(_) => last_error = "connection attempt timed out".into(),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn check_discord_route() -> Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:1080").await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        bail!("local SOCKS listener rejected no-auth");
    }
    let mut request = vec![5, 1, 0, 3, 11];
    request.extend_from_slice(b"discord.com");
    request.extend_from_slice(&443u16.to_be_bytes());
    stream.write_all(&request).await?;
    let reply = read_socks_reply(&mut stream).await?;
    if reply[1] != 0 {
        bail!("gateway returned SOCKS error {}", reply[1]);
    }
    Ok(())
}

fn validate_install_token(token: &str) -> Result<()> {
    if token.is_empty() {
        return Ok(());
    }
    if !(32..=1024).contains(&token.len())
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        bail!("DINMOO_PROXY_TOKEN must be 32 to 1024 URL-safe characters");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemd_quote(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('"', r#"\""#)
        .replace('%', "%%")
}

fn install_user_service(binary: &std::path::Path, token: &str) -> Result<()> {
    validate_install_token(token)?;
    let home = std::path::PathBuf::from(if cfg!(target_os = "windows") {
        env::var("APPDATA")?
    } else {
        env::var("HOME")?
    });
    #[cfg(target_os = "macos")]
    {
        let dir = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&dir)?;
        let plist = dir.join("com.dinmoo.proxy.plist");
        let xml = |s: &str| {
            s.replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('\"', "&quot;")
                .replace('\'', "&apos;")
        };
        let body=format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>com.dinmoo.proxy</string><key>ProgramArguments</key><array><string>{}</string><string>client</string></array><key>EnvironmentVariables</key><dict><key>DINMOO_PROXY_TOKEN</key><string>{}</string></dict><key>RunAtLoad</key><true/><key>KeepAlive</key><true/></dict></plist>",xml(&binary.display().to_string()),xml(token));
        std::fs::write(&plist, body)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&plist, std::fs::Permissions::from_mode(0o600))?;
        let uid = std::process::Command::new("id").arg("-u").output()?;
        let uid = String::from_utf8(uid.stdout)?.trim().to_owned();
        let domain = format!("gui/{uid}");
        let enabled = std::process::Command::new("launchctl")
            .args(["enable", &format!("{domain}/com.dinmoo.proxy")])
            .status()?;
        if !enabled.success() {
            bail!("launchctl could not enable the user service");
        }
        let _ = std::process::Command::new("launchctl")
            .args([
                "bootout",
                &domain,
                plist.to_str().ok_or("invalid plist path")?,
            ])
            .status();
        let status = std::process::Command::new("launchctl")
            .args([
                "bootstrap",
                &domain,
                plist.to_str().ok_or("invalid plist path")?,
            ])
            .status()?;
        if !status.success() {
            bail!("launchctl could not start the user service")
        }
    }
    #[cfg(target_os = "linux")]
    {
        let config = home.join(".config/dinmoo-proxy");
        let units = home.join(".config/systemd/user");
        std::fs::create_dir_all(&config)?;
        std::fs::create_dir_all(&units)?;
        let envfile = config.join("client.env");
        std::fs::write(&envfile, format!("DINMOO_PROXY_TOKEN={token}\n"))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&envfile, std::fs::Permissions::from_mode(0o600))?;
        let envpath = envfile.display().to_string();
        if envpath.contains(['\n', '\r']) {
            bail!("client configuration path cannot contain newlines");
        }
        let envpath = envpath.replace('%', "%%");
        let executable = systemd_quote(&binary.display().to_string());
        let unit = format!("[Unit]\nDescription=Dinmoo Discord proxy client\nAfter=network-online.target\n[Service]\nEnvironmentFile={envpath}\nExecStart=\"{executable}\" client\nRestart=on-failure\nRestartSec=3\n[Install]\nWantedBy=default.target\n");
        std::fs::write(units.join("dinmoo-proxy.service"), unit)?;
        let status = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status()?;
        if !status.success() {
            bail!("systemctl user daemon-reload failed")
        }
        let status = std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "dinmoo-proxy.service"])
            .status()?;
        if !status.success() {
            bail!("systemd could not enable/start user service")
        }
        let status = std::process::Command::new("systemctl")
            .args(["--user", "restart", "dinmoo-proxy.service"])
            .status()?;
        if !status.success() {
            bail!("systemd could not restart user service")
        }
    }
    #[cfg(target_os = "windows")]
    {
        let startup = home.join("Microsoft/Windows/Start Menu/Programs/Startup");
        std::fs::create_dir_all(&startup)?;
        let cmd = startup.join("DinmooProxy.cmd");
        let config_dir =
            std::path::PathBuf::from(env::var("LOCALAPPDATA")?).join("Programs/DinmooProxy");
        std::fs::create_dir_all(&config_dir)?;
        let envfile = config_dir.join("client.env");
        std::fs::write(&envfile, format!("DINMOO_PROXY_TOKEN={token}\r\n"))?;
        let username = env::var("USERNAME")?;
        let acl = std::process::Command::new("icacls.exe")
            .arg(&envfile)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{username}:(R,W)"))
            .status()?;
        if !acl.success() {
            let _ = std::fs::remove_file(envfile);
            bail!("could not restrict access to the Windows client credential file");
        }
        let command = format!(
            "@echo off\r\nfor /f \"usebackq tokens=1,* delims==\" %%A in (\"%LOCALAPPDATA%\\Programs\\DinmooProxy\\client.env\") do set \"%%A=%%B\"\r\n\"{}\" client\r\n",
            binary.display()
        );
        std::fs::write(&cmd, command)?;
        if cmd.with_extension("cmd.disabled").exists() {
            std::fs::remove_file(cmd.with_extension("cmd.disabled"))?;
        }
        if !client_service_running()? {
            use std::os::windows::process::CommandExt;
            std::process::Command::new(binary)
                .arg("client")
                .env("DINMOO_PROXY_TOKEN", token)
                .creation_flags(0x08000000)
                .spawn()?;
        }
    }
    Ok(())
}

fn client_service_running() -> Result<bool> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("launchctl");
        command.args(["print", &mac_client_service_target()?]);
        command
    };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = std::process::Command::new("systemctl");
        command.args(["--user", "is-active", "--quiet", "dinmoo-proxy.service"]);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = std::process::Command::new("powershell.exe");
        command.args(["-NoProfile", "-NonInteractive", "-Command", "if (Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:DINMOO_CLIENT_EXE -and $_.CommandLine -match '\\sclient(\\s|$)' }) { exit 0 } else { exit 1 }"]);
        command.env("DINMOO_CLIENT_EXE", env::current_exe()?);
        command
    };
    Ok(command.output()?.status.success())
}

#[cfg(target_os = "macos")]
fn mac_client_service_target() -> Result<String> {
    let uid = std::process::Command::new("id").arg("-u").output()?;
    if !uid.status.success() {
        bail!("could not determine the current user ID");
    }
    Ok(format!(
        "gui/{}/com.dinmoo.proxy",
        String::from_utf8(uid.stdout)?.trim()
    ))
}

fn set_client_enabled(enabled: bool) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let target = mac_client_service_target()?;
        let plist = std::path::PathBuf::from(env::var("HOME")?)
            .join("Library/LaunchAgents/com.dinmoo.proxy.plist");
        if !plist.is_file() {
            bail!("client is not installed; run the terminal installer first");
        }
        let status = std::process::Command::new("launchctl")
            .args([if enabled { "enable" } else { "disable" }, &target])
            .status()?;
        if !status.success() {
            bail!("could not change client startup state");
        }
        if enabled {
            if !client_service_running()? {
                let domain = target.rsplit_once('/').ok_or("invalid launchd target")?.0;
                let status = std::process::Command::new("launchctl")
                    .args(["bootstrap", domain])
                    .arg(plist)
                    .status()?;
                if !status.success() {
                    bail!("could not start the client service");
                }
            }
        } else if client_service_running()? {
            let status = std::process::Command::new("launchctl")
                .args(["bootout", &target])
                .status()?;
            if !status.success() {
                bail!("could not stop the client service");
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let unit = std::path::PathBuf::from(env::var("HOME")?)
            .join(".config/systemd/user/dinmoo-proxy.service");
        if !unit.is_file() {
            bail!("client is not installed; run the terminal installer first");
        }
        let status = std::process::Command::new("systemctl")
            .args([
                "--user",
                if enabled { "enable" } else { "disable" },
                "--now",
                "dinmoo-proxy.service",
            ])
            .status()?;
        if !status.success() {
            bail!("could not change client service state");
        }
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        let startup = std::path::PathBuf::from(env::var("APPDATA")?)
            .join("Microsoft/Windows/Start Menu/Programs/Startup/DinmooProxy.cmd");
        let disabled = startup.with_extension("cmd.disabled");
        if !startup.is_file() && !disabled.is_file() {
            bail!("client is not installed; run the terminal installer first");
        }
        if enabled {
            if !client_service_running()? {
                let config = std::path::PathBuf::from(env::var("LOCALAPPDATA")?)
                    .join("Programs/DinmooProxy/client.env");
                let body = std::fs::read_to_string(config)?;
                let token = body
                    .lines()
                    .find_map(|line| line.strip_prefix("DINMOO_PROXY_TOKEN="))
                    .ok_or("missing installed client token")?;
                validate_install_token(token)?;
                std::process::Command::new(env::current_exe()?)
                    .arg("client")
                    .env("DINMOO_PROXY_TOKEN", token)
                    .creation_flags(0x08000000)
                    .spawn()?;
            }
            if disabled.is_file() {
                std::fs::rename(disabled, startup)?;
            }
        } else {
            if startup.is_file() {
                std::fs::rename(&startup, disabled)?;
            }
            let status = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-Command", "Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:DINMOO_CLIENT_EXE -and $_.CommandLine -match '\\sclient(\\s|$)' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop }"])
                .env("DINMOO_CLIENT_EXE", env::current_exe()?).status()?;
            if !status.success() {
                bail!("could not stop the client process");
            }
        }
    }
    Ok(())
}

fn uninstall() -> Result<()> {
    let home = std::path::PathBuf::from(if cfg!(target_os = "windows") {
        env::var("APPDATA")?
    } else {
        env::var("HOME")?
    });
    #[cfg(target_os = "macos")]
    {
        let path = home.join("Library/LaunchAgents/com.dinmoo.proxy.plist");
        let uid = std::process::Command::new("id").arg("-u").output()?;
        let uid = String::from_utf8(uid.stdout)?.trim().to_owned();
        let domain = format!("gui/{uid}");
        if path.exists() {
            let _ = std::process::Command::new("launchctl")
                .args([
                    "bootout",
                    &domain,
                    path.to_str().ok_or("invalid service path")?,
                ])
                .status();
            std::fs::remove_file(path)?;
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "dinmoo-proxy.service"])
            .status();
        let _ = std::fs::remove_file(home.join(".config/systemd/user/dinmoo-proxy.service"));
        let _ = std::fs::remove_file(home.join(".config/dinmoo-proxy/client.env"));
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::fs::remove_file(
            home.join("Microsoft/Windows/Start Menu/Programs/Startup/DinmooProxy.cmd"),
        );
        let _ = std::fs::remove_file(
            home.join("Microsoft/Windows/Start Menu/Programs/Startup/DinmooProxy.cmd.disabled"),
        );
        if let Ok(local) = env::var("LOCALAPPDATA") {
            let _ = std::fs::remove_file(
                std::path::PathBuf::from(local).join("Programs/DinmooProxy/client.env"),
            );
        }
        let this_pid = std::process::id();
        let stop_clients=format!("Get-CimInstance Win32_Process | Where-Object {{ $_.ProcessId -ne {this_pid} -and $_.CommandLine -match 'dinmoo-proxy(\\.exe)? client' }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force }}");
        let _ = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &stop_clients])
            .status();
        if let Ok(local) = env::var("LOCALAPPDATA") {
            let exe = std::path::PathBuf::from(local).join("Programs/DinmooProxy/dinmoo-proxy.exe");
            if exe.exists() {
                let cleanup=format!("Wait-Process -Id {this_pid} -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $env:DINMOO_DELETE_PATH -Force -ErrorAction SilentlyContinue");
                std::process::Command::new("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-Command", &cleanup])
                    .env("DINMOO_DELETE_PATH", exe)
                    .spawn()?;
            }
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = std::fs::remove_file(home.join(".local/bin/dinmoo-proxy"));
        let _ = std::fs::remove_dir_all(home.join(".config/dinmoo-proxy"));
    }
    println!("Removed the Dinmoo Proxy user service and installed binary.");
    restart_discord_direct()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn stop_discord() -> Result<()> {
    let stopped = std::process::Command::new("pkill")
        .args(["-x", "Discord"])
        .output()?;
    if !stopped.status.success() && stopped.status.code() != Some(1) {
        bail!(
            "could not stop Discord: {}",
            String::from_utf8_lossy(&stopped.stderr)
        );
    }
    for _ in 0..50 {
        let status = std::process::Command::new("pgrep")
            .args(["-x", "Discord"])
            .output()?
            .status;
        if status.code() == Some(1) {
            return Ok(());
        }
        if !status.success() {
            bail!("could not check whether Discord has exited");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("Discord did not exit within five seconds; retry the command after closing Discord")
}

fn restart_discord_direct() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        stop_discord()?;
        let s = std::process::Command::new("open")
            .args(["-a", "Discord"])
            .status()?;
        if !s.success() {
            bail!("could not relaunch Discord")
        }
    }
    #[cfg(target_os = "linux")]
    {
        stop_discord()?;
        std::process::Command::new("discord")
            .spawn()
            .map_err(|_| "could not relaunch Discord")?;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", "Discord.exe", "/F"])
            .status();
        let p = std::path::PathBuf::from(env::var("LOCALAPPDATA")?).join(r"Discord\Update.exe");
        std::process::Command::new(p)
            .args(["--processStart", "Discord.exe"])
            .spawn()
            .map_err(|_| "could not relaunch Discord")?;
    }
    Ok(())
}

fn restart_discord(proxy: &str) -> Result<()> {
    if !proxy.starts_with("socks5://127.0.0.1:") {
        bail!("Discord proxy must use the local loopback SOCKS5 listener");
    }
    #[cfg(target_os = "macos")]
    {
        stop_discord()?;
        let status = std::process::Command::new("open")
            .args([
                "-n",
                "-a",
                "Discord",
                "--args",
                &format!("--proxy-server={proxy}"),
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE api-proxy.dinmoo.com",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            ])
            .status()?;
        if !status.success() {
            bail!("could not launch Discord; install Discord.app first");
        }
    }
    #[cfg(target_os = "linux")]
    {
        stop_discord()?;
        let status = std::process::Command::new("discord")
            .args([
                format!("--proxy-server={proxy}"),
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE api-proxy.dinmoo.com".to_owned(),
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_owned(),
            ])
            .spawn();
        if status.is_err() {
            bail!("could not launch Discord; install the 'discord' desktop command first");
        }
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/IM", "Discord.exe", "/F"])
            .status();
        let local = std::env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA is not set")?;
        let exe = std::path::PathBuf::from(local).join(r"Discord\Update.exe");
        let status = std::process::Command::new(exe).args(["--processStart", "Discord.exe", "--process-start-args", &format!("--proxy-server={proxy} --host-resolver-rules=\"MAP * ~NOTFOUND, EXCLUDE api-proxy.dinmoo.com\" --force-webrtc-ip-handling-policy=disable_non_proxied_udp")]).spawn();
        if status.is_err() {
            bail!("could not launch Discord; install the desktop client first");
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = proxy;
        bail!("Discord launching is unsupported on this operating system");
    }
    Ok(())
}

async fn handle(mut stream: TcpStream, cfg: Arc<Config>) -> Result<()> {
    stream.set_nodelay(true)?;
    if let Some(upstream) = &cfg.upstream {
        let remote =
            tokio::time::timeout(DESTINATION_CONNECT_TIMEOUT, TcpStream::connect(upstream))
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
            remote.write_all(b"DMPX\x01").await?;
            write_string(&mut remote, &cfg.token).await?;
            let mut ok = [0u8; 1];
            remote.read_exact(&mut ok).await?;
            if ok[0] != 1 {
                bail!("gateway rejected authentication");
            }
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        })
        .await
        .context("gateway authentication timed out")??;
        return proxy_socks(&mut stream, &mut remote).await;
    }
    handle_gateway_connection(stream, &cfg).await
}

async fn handle_gateway_connection<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    cfg: &Config,
) -> Result<()> {
    let acceptor = cfg
        .server_tls
        .as_ref()
        .ok_or("gateway TLS is not configured")?;
    let mut stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .context("TLS client handshake timed out")?
        .context("TLS client handshake")?;
    tokio::time::timeout(
        AUTH_HANDSHAKE_TIMEOUT,
        authenticate_gateway(&mut stream, cfg),
    )
    .await
    .context("gateway authentication timed out")??;
    handle_socks(&mut stream, cfg).await
}

async fn authenticate_gateway<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    cfg: &Config,
) -> Result<()> {
    let mut magic = [0u8; 5];
    stream.read_exact(&mut magic).await?;
    if &magic != b"DMPX\x01" {
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
    Ok(())
}

async fn proxy_socks<L, R>(local: &mut L, remote: &mut R) -> Result<()>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    let request = tokio::time::timeout(SOCKS_HANDSHAKE_TIMEOUT, async {
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

async fn read_socks_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        bail!("invalid SOCKS request header");
    }
    let mut bytes = request.to_vec();
    match request[3] {
        1 => {
            let mut address = [0; 6];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        4 => {
            let mut address = [0; 18];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut address = vec![0; len + 2];
            stream.read_exact(&mut address).await?;
            bytes.push(len as u8);
            bytes.extend_from_slice(&address);
        }
        _ => bail!("invalid SOCKS address type"),
    }
    Ok(bytes)
}

async fn read_socks_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    let mut bytes = reply.to_vec();
    match reply[3] {
        1 => {
            let mut address = [0; 6];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        4 => {
            let mut address = [0; 18];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut address = vec![0; len + 2];
            stream.read_exact(&mut address).await?;
            bytes.push(len as u8);
            bytes.extend_from_slice(&address);
        }
        _ => bail!("invalid SOCKS reply address type"),
    }
    Ok(bytes)
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
    let mut datagram = vec![0; 1500];
    loop {
        tokio::select! {
            result = socket.recv_from(&mut datagram) => {
                let (length, source) = result?;
                if !source.ip().is_loopback() || length > 1500 { continue; }
                if let Some(known_peer) = peer {
                    if source != known_peer { continue; }
                } else {
                    peer = Some(source);
                }
                if valid_socks_udp_packet(&datagram[..length]) {
                    write_frame(&mut writer, &datagram[..length]).await?;
                }
            }
            result = read_frame(&mut reader) => {
                let frame = result?;
                if let Some(peer) = peer {
                    socket.send_to(&frame, peer).await?;
                }
            }
        }
    }
}

fn valid_socks_udp_packet(packet: &[u8]) -> bool {
    packet.len() >= 10 && packet.len() <= 1500 && packet[..2] == [0, 0] && packet[2] == 0
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > 1500 {
        bail!("invalid UDP frame length");
    }
    writer.write_u16(frame.len() as u16).await?;
    writer.write_all(frame).await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let length = reader.read_u16().await? as usize;
    if length == 0 || length > 1500 {
        bail!("invalid UDP frame length");
    }
    let mut frame = vec![0; length];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
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
    if command == 1 {
        if !allowed_destination(&host) {
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
                target = Some((connection, address.ip()));
                break;
            }
        }
        if let Some((mut target, ip)) = target {
            if host.parse::<IpAddr>().is_err() {
                approve_udp_ip(cfg, ip).await;
            }
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

fn socks_request_target(request: &[u8]) -> Result<(String, u16)> {
    let mut offset = 4;
    let host = match request[3] {
        1 => {
            let ip = IpAddr::from(<[u8; 4]>::try_from(&request[offset..offset + 4])?);
            offset += 4;
            ip.to_string()
        }
        4 => {
            let ip = IpAddr::from(<[u8; 16]>::try_from(&request[offset..offset + 16])?);
            offset += 16;
            ip.to_string()
        }
        3 => {
            let length = request[offset] as usize;
            offset += 1;
            let host = std::str::from_utf8(&request[offset..offset + length])?.to_owned();
            offset += length;
            host
        }
        _ => bail!("invalid SOCKS address type"),
    };
    let port = u16::from_be_bytes([request[offset], request[offset + 1]]);
    Ok((host, port))
}

async fn reply_bound<S: AsyncWrite + Unpin>(stream: &mut S, port: u16) -> Result<()> {
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0]).await?;
    stream.write_u16(port).await?;
    Ok(())
}

async fn relay_udp_gateway<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    socket_v4: UdpSocket,
    socket_v6: Option<UdpSocket>,
    cfg: &Config,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut buffer_v4 = vec![0; 1500];
    let mut buffer_v6 = vec![0; 1500];
    let mut permitted_targets: VecDeque<(SocketAddr, tokio::time::Instant)> = VecDeque::new();
    let mut dns_cache: HashMap<(String, u16), (tokio::time::Instant, Vec<SocketAddr>)> =
        HashMap::new();
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
            frame = read_frame(&mut reader) => {
                let packet = frame?;
                if !valid_socks_udp_packet(&packet) { continue; }
                let Ok((host, port, payload)) = parse_socks_udp_packet(&packet) else { continue; };
                if payload.is_empty() { continue; }
                if let Ok(ip) = host.parse::<IpAddr>() {
                    if !is_public_ip(ip) || !is_approved_udp_ip(cfg, ip).await { continue; }
                    approve_udp_ip(cfg, ip).await;
                } else if !allowed_destination(&host) {
                    continue;
                }
                let addresses = resolve_udp_addresses(&host, port, &mut dns_cache).await;
                if addresses.is_empty() { continue; }
                let mut destination = None;
                for address in addresses {
                    if !is_public_ip(address.ip()) { continue; }
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
        let response = encode_socks_udp_packet(source, &buffer[..length]);
        write_frame(&mut writer, &response).await?;
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

async fn is_approved_udp_ip(cfg: &Config, ip: IpAddr) -> bool {
    let now = tokio::time::Instant::now();
    let mut approved = cfg.approved_udp_ips.write().await;
    approved.retain(|_, expires| *expires > now);
    approved.contains_key(&ip)
}

async fn approve_udp_ip(cfg: &Config, ip: IpAddr) {
    let now = tokio::time::Instant::now();
    let mut approved = cfg.approved_udp_ips.write().await;
    approved.retain(|_, expires| *expires > now);
    if approved.len() >= 1024 && !approved.contains_key(&ip) {
        if let Some(oldest) = approved
            .iter()
            .min_by_key(|(_, expires)| *expires)
            .map(|(ip, _)| *ip)
        {
            approved.remove(&oldest);
        }
    }
    approved.insert(ip, now + Duration::from_secs(300));
}

fn parse_socks_udp_packet(packet: &[u8]) -> Result<(String, u16, Vec<u8>)> {
    if !valid_socks_udp_packet(packet) {
        bail!("invalid SOCKS UDP packet");
    }
    let (host, offset) = match packet[3] {
        1 => (
            IpAddr::from(<[u8; 4]>::try_from(&packet[4..8])?).to_string(),
            8,
        ),
        4 => (
            IpAddr::from(<[u8; 16]>::try_from(&packet[4..20])?).to_string(),
            20,
        ),
        3 => {
            if packet.len() < 5 {
                bail!("invalid SOCKS UDP domain length");
            }
            let n = packet[4] as usize;
            if packet.len() < 5 + n + 2 {
                bail!("truncated SOCKS UDP domain");
            }
            (std::str::from_utf8(&packet[5..5 + n])?.to_owned(), 5 + n)
        }
        _ => bail!("invalid SOCKS UDP address type"),
    };
    if packet.len() < offset + 2 {
        bail!("truncated SOCKS UDP port");
    }
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    Ok((host, port, packet[offset + 2..].to_vec()))
}

fn encode_socks_udp_packet(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match source.ip() {
        IpAddr::V4(ip) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !(a == 0
                    || (a == 100 && (64..=127).contains(&b))
                    || (a == 192
                        && ((b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99) || b == 168))
                    || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                    || (a == 203 && b == 0 && c == 113)
                    || a >= 224)
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            let segments = ip.segments();
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && segments[0] & 0xe000 == 0x2000
                // Exclude special-use ranges within global-unicast space (IANA IPv6 registry).
                && !(segments[0] == 0x2001
                    && (segments[1] <= 0x01ff
                        || segments[1] == 0x0db8
                        || segments[1] & 0xfff0 == 0x0010
                        || segments[1] & 0xfff0 == 0x0020
                        || segments[1] & 0xfff0 == 0x0030))
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
        }
    }
}

fn allowed_destination(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == "discord.com"
        || h.ends_with(".discord.com")
        || h == "discordapp.com"
        || h.ends_with(".discordapp.com")
        || h == "discord.media"
        || h.ends_with(".discord.media")
        || h == "discord.gg"
        || h.ends_with(".discord.gg")
        || h == "discordcdn.com"
        || h.ends_with(".discordcdn.com")
        || h.ends_with(".discordapp.net")
}
async fn reply<S: AsyncWrite + Unpin>(s: &mut S, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}
async fn write_string<S: AsyncWrite + Unpin>(s: &mut S, value: &str) -> Result<()> {
    let n = u16::try_from(value.len())?;
    s.write_u16(n).await?;
    s.write_all(value.as_bytes()).await?;
    Ok(())
}
async fn read_string<S: AsyncRead + Unpin>(s: &mut S) -> Result<String> {
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

    #[test]
    fn session_capacity_is_bounded_and_rejects_invalid_values() {
        assert_eq!(parse_max_sessions("1").unwrap(), 1);
        assert_eq!(parse_max_sessions("4096").unwrap(), MAX_MAX_SESSIONS);
        for value in ["0", "4097", "many", "-1"] {
            assert!(parse_max_sessions(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn destination_policy_accepts_discord_hosts_and_rejects_suffix_spoofing() {
        assert!(allowed_destination("discord.com"));
        assert!(allowed_destination("API.DISCORD.COM."));
        assert!(allowed_destination("voice.discord.media"));
        assert!(allowed_destination("cdn.discordapp.net"));
        assert!(!allowed_destination("discord.com.attacker.example"));
        assert!(!allowed_destination("notdiscord.com"));
        assert!(!allowed_destination("discordapp.net.attacker.example"));
    }

    #[test]
    fn destination_policy_rejects_private_and_special_use_addresses() {
        for address in [
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            let ip = address.parse().expect("literal IP address");
            assert!(!is_public_ip(ip), "{address} must not be public");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn socks_udp_domain_packet_parses_to_host_port_and_payload() {
        let packet = [
            0, 0, 0, 3, 11, b'd', b'i', b's', b'c', b'o', b'r', b'd', b'.', b'c', b'o', b'm', 0x01,
            0xbb, 0x61, 0x62,
        ];
        let (host, port, payload) = parse_socks_udp_packet(&packet).unwrap();
        assert_eq!(host, "discord.com");
        assert_eq!(port, 443);
        assert_eq!(payload, b"ab");
    }

    #[test]
    fn socks_udp_parser_rejects_fragments_and_truncated_domain_packets() {
        let fragmented = [0, 0, 1, 1, 1, 2, 3, 4, 0, 53, 1];
        assert!(parse_socks_udp_packet(&fragmented).is_err());

        let truncated = [0, 0, 0, 3, 8, b'd', b'i', b's', b's', b'c', b'o', b'r'];
        assert!(parse_socks_udp_packet(&truncated).is_err());
    }

    #[test]
    fn udp_response_encoding_uses_socks_ipv4_header() {
        let packet = encode_socks_udp_packet("8.8.8.8:53".parse().unwrap(), &[0xaa, 0xbb]);
        assert_eq!(packet, [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 0xaa, 0xbb]);
    }

    #[tokio::test]
    async fn udp_frames_preserve_packet_boundaries() {
        let (mut sender, mut receiver) = tokio::io::duplex(64);
        write_frame(&mut sender, &[0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42])
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut receiver).await.unwrap(),
            [0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42]
        );
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
            handle_gateway_connection(gateway_tunnel, &gateway_config).await
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

    fn test_config() -> Config {
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
            approved_udp_ips: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
}

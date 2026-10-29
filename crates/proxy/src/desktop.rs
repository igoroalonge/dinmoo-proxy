//! Desktop integration: release install, user service management and Discord relaunch.
#[cfg(target_os = "macos")]
use crate::ContextExt;
use crate::{socks::read_socks_reply, voice, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{env, io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Deserialize)]
struct ReleaseAsset {
    url: String,
    sha256: String,
}
#[derive(Deserialize)]
struct ReleaseManifest {
    assets: std::collections::HashMap<String, ReleaseAsset>,
}

pub(crate) async fn install() -> Result<()> {
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

pub(crate) async fn wait_for_discord_route() -> Result<()> {
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

pub(crate) async fn check_discord_route() -> Result<()> {
    check_discord_route_at("127.0.0.1:1080".parse()?).await
}

pub(crate) async fn check_discord_route_at(proxy: SocketAddr) -> Result<()> {
    let mut stream = TcpStream::connect(proxy).await.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("could not connect to local SOCKS proxy at {proxy}: {error}"),
        )
    })?;
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

pub(crate) fn validate_install_token(token: &str) -> Result<()> {
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

pub(crate) fn install_user_service(binary: &std::path::Path, token: &str) -> Result<()> {
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

pub(crate) fn client_service_running() -> Result<bool> {
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

pub(crate) fn set_client_enabled(enabled: bool) -> Result<()> {
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

pub(crate) fn uninstall() -> Result<()> {
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

#[cfg(target_os = "macos")]
fn macos_discord_executable() -> Result<std::path::PathBuf> {
    let home = std::path::PathBuf::from(env::var("HOME")?);
    for bundle in [
        home.join("Applications/Discord.app"),
        std::path::PathBuf::from("/Applications/Discord.app"),
    ] {
        let executable = bundle.join("Contents/MacOS/Discord");
        if executable.is_file() {
            return Ok(executable);
        }
    }

    let result = std::process::Command::new("mdfind")
        .arg("kMDItemCFBundleIdentifier == \"com.hnc.Discord\"")
        .output()
        .context("could not locate Discord with Spotlight")?;
    if !result.status.success() {
        bail!("could not locate Discord; install Discord.app first");
    }
    for bundle in String::from_utf8_lossy(&result.stdout).lines() {
        let executable = std::path::Path::new(bundle.trim()).join("Contents/MacOS/Discord");
        if executable.is_file() {
            return Ok(executable);
        }
    }
    bail!("could not locate Discord.app; install it in /Applications or ~/Applications")
}

pub(crate) fn restart_discord_direct() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        stop_discord()?;
        std::process::Command::new(macos_discord_executable()?)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| "could not relaunch Discord")?;
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

pub(crate) fn restart_discord(proxy: &str) -> Result<()> {
    let proxy_address = proxy
        .strip_prefix("socks5://")
        .ok_or("Discord proxy must use a local loopback SOCKS5 listener")?;
    let proxy_address: SocketAddr = proxy_address
        .parse()
        .map_err(|_| "Discord proxy must be a valid SOCKS5 socket address")?;
    if !proxy_address.ip().is_loopback() || proxy_address.port() == 0 {
        bail!("Discord proxy must use the local loopback SOCKS5 listener");
    }
    let mut discord_args = vec![
        format!("--proxy-server={proxy}"),
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_owned(),
    ];
    let identity = voice::identity::rotate(&voice::identity::identity_directory()?)?;
    discord_args.push(format!(
        "--ignore-certificate-errors-spki-list={}",
        identity.spki_pin
    ));
    #[cfg(target_os = "macos")]
    {
        stop_discord()?;
        std::process::Command::new("open")
            .args(["-n", "-a"])
            .arg(macos_discord_executable()?)
            .arg("--args")
            .args(&discord_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| "could not launch Discord through Launch Services")?;
    }
    #[cfg(target_os = "linux")]
    {
        stop_discord()?;
        let status = std::process::Command::new("discord")
            .args(&discord_args)
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
        let process_args = discord_args.join(" ");
        let status = std::process::Command::new(exe)
            .args([
                "--processStart",
                "Discord.exe",
                "--process-start-args",
                &process_args,
            ])
            .spawn();
        if status.is_err() {
            bail!("could not launch Discord; install the desktop client first");
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = discord_args;
        bail!("Discord launching is unsupported on this operating system");
    }
    Ok(())
}

//! Client-local identity for the opt-in Discord voice TLS bridge.
//! This certificate is never used to configure upstream trust.
use base64::{engine::general_purpose::STANDARD, Engine};
use rcgen::PublicKeyData;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate, pem::Pem};

const IDENTITY: &str = "identity.pem";
const LEGACY_CERTIFICATE: &str = "certificate.der";
const LEGACY_KEY: &str = "private-key.der";
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);

pub struct VoiceIdentity {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub spki_pin: String,
}

impl VoiceIdentity {
    pub fn load_or_create(directory: &Path) -> crate::Result<Self> {
        load_or_create(directory)
    }
}

/// The client's identity, reloaded when another process rotates it.
pub struct Store {
    directory: PathBuf,
    cached: tokio::sync::Mutex<(Option<Stamp>, Arc<VoiceIdentity>)>,
}

impl Store {
    pub fn open(directory: PathBuf) -> crate::Result<Self> {
        let (identity, stamp) = load(&directory)?;
        Ok(Self {
            directory,
            cached: tokio::sync::Mutex::new((stamp, Arc::new(identity))),
        })
    }

    pub async fn current(&self) -> crate::Result<Arc<VoiceIdentity>> {
        let mut cached = self.cached.lock().await;
        if cached.0 != Stamp::of(&self.directory.join(IDENTITY))? {
            let directory = self.directory.clone();
            let (identity, stamp) = tokio::task::spawn_blocking(move || load(&directory)).await??;
            *cached = (stamp, Arc::new(identity));
        }
        Ok(cached.1.clone())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<SystemTime>,
    inode: u64,
}

impl Stamp {
    fn of(path: &Path) -> io::Result<Option<Self>> {
        match fs::symlink_metadata(path) {
            Ok(meta) => Ok(Some(Self::from(&meta))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

impl From<&fs::Metadata> for Stamp {
    fn from(meta: &fs::Metadata) -> Self {
        #[cfg(unix)]
        let inode = std::os::unix::fs::MetadataExt::ino(meta);
        #[cfg(not(unix))]
        let inode = 0;
        Self {
            len: meta.len(),
            modified: meta.modified().ok(),
            inode,
        }
    }
}

pub fn identity_directory() -> crate::Result<PathBuf> {
    if let Some(path) = std::env::var_os("DINMOO_VOICE_IDENTITY_DIR") {
        if path.is_empty() {
            return Err("DINMOO_VOICE_IDENTITY_DIR is empty".into());
        }
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
        .ok_or("cannot locate home directory for voice identity")?;
    Ok(PathBuf::from(home).join(".config/dinmoo-proxy/voice"))
}

pub fn load_or_create(directory: &Path) -> crate::Result<VoiceIdentity> {
    Ok(load(directory)?.0)
}

/// Replaces the identity with a fresh key, so a pin learned earlier stops matching.
pub fn rotate(directory: &Path) -> crate::Result<VoiceIdentity> {
    create_private_directory(directory)?;
    let _lock = lock(directory, LOCK_TIMEOUT)?;
    Ok(generate(directory)?.0)
}

fn load(directory: &Path) -> crate::Result<(VoiceIdentity, Option<Stamp>)> {
    create_private_directory(directory)?;
    let _lock = lock(directory, LOCK_TIMEOUT)?;
    match read_stored(directory) {
        Ok(Some(stored)) => Ok(stored),
        Ok(None) => generate(directory),
        Err(error) => {
            // Only a Discord launched by our CLI uses the pin, and every launch rotates.
            eprintln!("voice identity is unusable ({error}); generating a new one");
            generate(directory)
        }
    }
}

fn read_stored(directory: &Path) -> crate::Result<Option<(VoiceIdentity, Option<Stamp>)>> {
    let path = directory.join(IDENTITY);
    match check_private_file(&path) {
        Ok(meta) => {
            let identity = identity_from_pem(&fs::read(path)?)?;
            return Ok(Some((identity, Some(Stamp::from(&meta)))));
        }
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
        Err(_) => {}
    }
    let cert_path = directory.join(LEGACY_CERTIFICATE);
    let key_path = directory.join(LEGACY_KEY);
    match (cert_path.try_exists()?, key_path.try_exists()?) {
        (false, false) => Ok(None),
        (true, true) => {
            check_private_file(&cert_path)?;
            check_private_file(&key_path)?;
            let identity = identity_from_der(fs::read(cert_path)?, fs::read(key_path)?)?;
            Ok(Some((identity, None)))
        }
        _ => Err("incomplete legacy voice identity".into()),
    }
}

fn generate(directory: &Path) -> crate::Result<(VoiceIdentity, Option<Stamp>)> {
    let key = rcgen::KeyPair::generate()?;
    let params = rcgen::CertificateParams::new(vec!["*.discord.media".to_owned()])?;
    let cert = params.self_signed(&key)?.der().to_vec();
    let key = key.serialize_der();
    let contents = pem("CERTIFICATE", &cert) + &pem("PRIVATE KEY", &key);
    let identity = identity_from_der(cert, key)?;
    publish(directory, IDENTITY, contents.as_bytes())?;
    for legacy in [LEGACY_CERTIFICATE, LEGACY_KEY] {
        let _ = fs::remove_file(directory.join(legacy));
        let _ = fs::remove_file(directory.join(format!(".{legacy}.tmp")));
    }
    let meta = fs::symlink_metadata(directory.join(IDENTITY))?;
    Ok((identity, Some(Stamp::from(&meta))))
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let lines: Vec<_> = encoded
        .as_bytes()
        .chunks(64)
        .map(String::from_utf8_lossy)
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

fn identity_from_pem(bytes: &[u8]) -> crate::Result<VoiceIdentity> {
    let mut sections = Pem::iter_from_buffer(bytes);
    match (sections.next(), sections.next(), sections.next()) {
        (Some(Ok(cert)), Some(Ok(key)), None)
            if cert.label == "CERTIFICATE" && key.label == "PRIVATE KEY" =>
        {
            identity_from_der(cert.contents, key.contents)
        }
        _ => Err("malformed voice identity file".into()),
    }
}

#[cfg(test)]
pub fn certificate_der(directory: &Path) -> Vec<u8> {
    let contents = fs::read(directory.join(IDENTITY)).unwrap();
    Pem::iter_from_buffer(&contents)
        .next()
        .unwrap()
        .unwrap()
        .contents
}

fn identity_from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> crate::Result<VoiceIdentity> {
    let key = rcgen::KeyPair::try_from(key_der.as_slice())?;
    let spki = key.subject_public_key_info();
    let (remaining, cert) =
        parse_x509_certificate(&cert_der).map_err(|_| "invalid voice certificate")?;
    if !remaining.is_empty()
        || cert.public_key().raw != spki
        || !cert.validity().is_valid()
        || cert.subject() != cert.issuer()
    {
        return Err("invalid, expired, or mismatched voice identity".into());
    }
    cert.verify_signature(None)
        .map_err(|_| "invalid voice certificate self-signature")?;
    if cert
        .basic_constraints()
        .map_err(|_| "invalid certificate constraints")?
        .is_some_and(|extension| extension.value.ca)
    {
        return Err("voice identity must be a leaf certificate".into());
    }
    let san = cert
        .subject_alternative_name()
        .map_err(|_| "invalid certificate SAN")?
        .ok_or("voice certificate has no SAN")?;
    if san.value.general_names.len() != 1
        || !matches!(
            san.value.general_names[0],
            GeneralName::DNSName("*.discord.media")
        )
    {
        return Err("voice certificate must cover only *.discord.media".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let certs = vec![CertificateDer::from(cert_der)];
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
    let certified =
        rustls::sign::CertifiedKey::from_der(certs.clone(), private.clone_key(), &provider)?;
    certified.keys_match()?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, private)?;
    Ok(VoiceIdentity {
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        spki_pin: STANDARD.encode(Sha256::digest(&spki)),
    })
}

fn create_private_directory(directory: &Path) -> io::Result<()> {
    if !directory.try_exists()? {
        if let Some(parent) = directory.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    let meta = fs::symlink_metadata(directory)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(io::Error::other(
            "voice identity directory must be a real directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "voice identity directory must have mode 0700",
            ));
        }
    }
    Ok(())
}
fn check_private_file(path: &Path) -> io::Result<fs::Metadata> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(io::Error::other(
            "voice identity must contain regular files",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other("voice identity files must have mode 0600"));
        }
    }
    Ok(meta)
}
fn publish(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temporary = directory.join(format!(".{name}.tmp"));
    // Writers hold the lock, so a leftover temporary file is from an interrupted write.
    match fs::remove_file(&temporary) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, directory.join(name))?;
    #[cfg(unix)]
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}
/// An advisory lock the OS releases when the file is dropped or the process dies.
fn lock(directory: &Path, timeout: Duration) -> io::Result<fs::File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(directory.join(".lock"))?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => break,
            Err(fs::TryLockError::WouldBlock) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(fs::TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "voice identity is locked by another dinmoo-proxy process",
                ))
            }
            Err(fs::TryLockError::Error(error)) => return Err(error),
        }
    }
    // 0.2.5 locked with a directory that a crash could leave behind forever.
    let legacy = directory.join(".identity.lock");
    if fs::symlink_metadata(&legacy).is_ok_and(|meta| {
        meta.is_dir()
            && meta
                .modified()
                .ok()
                .and_then(|time| time.elapsed().ok())
                .is_some_and(|age| age > Duration::from_secs(60))
    }) {
        let _ = fs::remove_dir(legacy);
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "dinmoo-identity-{}-{}",
            std::process::id(),
            rcgen::KeyPair::generate()
                .unwrap()
                .subject_public_key_info()
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        ));
        path
    }
    fn stored(path: &Path) -> Vec<u8> {
        fs::read(path.join(IDENTITY)).unwrap()
    }
    fn write_legacy(path: &Path) -> String {
        create_private_directory(path).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["*.discord.media".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        publish(path, "private-key.der", &key.serialize_der()).unwrap();
        publish(path, "certificate.der", cert.der()).unwrap();
        STANDARD.encode(Sha256::digest(key.subject_public_key_info()))
    }
    #[test]
    fn persistent_identity_and_pin_match_certificate() {
        let path = directory();
        let first = load_or_create(&path).unwrap();
        let contents = stored(&path);
        let cert_bytes = certificate_der(&path);
        let (_, cert) = parse_x509_certificate(&cert_bytes).unwrap();
        assert_eq!(
            first.spki_pin,
            STANDARD.encode(Sha256::digest(cert.public_key().raw))
        );
        assert_eq!(load_or_create(&path).unwrap().spki_pin, first.spki_pin);
        assert_eq!(stored(&path), contents);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(path.join(IDENTITY))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn rotation_replaces_identity_with_a_new_key() {
        let path = directory();
        let first = load_or_create(&path).unwrap();
        let before = stored(&path);
        let rotated = rotate(&path).unwrap();
        assert_ne!(rotated.spki_pin, first.spki_pin);
        assert_ne!(stored(&path), before);
        assert_eq!(load_or_create(&path).unwrap().spki_pin, rotated.spki_pin);
        assert_ne!(rotate(&path).unwrap().spki_pin, rotated.spki_pin);
        assert!(!path.join(format!(".{IDENTITY}.tmp")).exists());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn reads_legacy_layout_and_migrates_on_rotation() {
        let path = directory();
        let pin = write_legacy(&path);
        assert_eq!(load_or_create(&path).unwrap().spki_pin, pin);
        assert!(path.join("certificate.der").exists() && !path.join(IDENTITY).exists());
        let rotated = rotate(&path).unwrap();
        assert_ne!(rotated.spki_pin, pin);
        assert!(!path.join("certificate.der").exists());
        assert!(!path.join("private-key.der").exists());
        assert_eq!(load_or_create(&path).unwrap().spki_pin, rotated.spki_pin);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn leftover_temporary_files_do_not_break_loading_or_rotation() {
        let path = directory();
        let first = load_or_create(&path).unwrap();
        for name in [
            ".identity.pem.tmp",
            ".certificate.der.tmp",
            ".private-key.der.tmp",
        ] {
            fs::write(path.join(name), b"partial").unwrap();
        }
        assert_eq!(load_or_create(&path).unwrap().spki_pin, first.spki_pin);
        let rotated = rotate(&path).unwrap();
        assert_eq!(load_or_create(&path).unwrap().spki_pin, rotated.spki_pin);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn regenerates_unreadable_mismatched_or_incomplete_identity() {
        let path = directory();
        let first = load_or_create(&path).unwrap();
        fs::write(path.join(IDENTITY), b"broken").unwrap();
        let second = load_or_create(&path).unwrap();
        assert_ne!(second.spki_pin, first.spki_pin);
        assert!(identity_from_pem(&stored(&path)).is_ok());

        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["*.discord.media".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let other = rcgen::KeyPair::generate().unwrap();
        let mismatched =
            pem("CERTIFICATE", cert.der()) + &pem("PRIVATE KEY", &other.serialize_der());
        fs::write(path.join(IDENTITY), &mismatched).unwrap();
        assert_ne!(load_or_create(&path).unwrap().spki_pin, second.spki_pin);
        assert_ne!(stored(&path), mismatched.as_bytes());

        // A 0.2.5 generation interrupted between its two renames.
        fs::remove_file(path.join(IDENTITY)).unwrap();
        publish(&path, "private-key.der", &other.serialize_der()).unwrap();
        load_or_create(&path).unwrap();
        assert!(identity_from_pem(&stored(&path)).is_ok());
        assert!(!path.join("private-key.der").exists());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn lock_times_out_while_held_and_is_released_on_drop() {
        let path = directory();
        create_private_directory(&path).unwrap();
        let held = lock(&path, Duration::ZERO).unwrap();
        let error = lock(&path, Duration::from_millis(50)).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        drop(held);
        drop(lock(&path, Duration::ZERO).unwrap());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn legacy_lock_directory_does_not_block_and_is_removed_once_stale() {
        let path = directory();
        create_private_directory(&path).unwrap();
        let legacy = path.join(".identity.lock");
        fs::create_dir(&legacy).unwrap();
        drop(lock(&path, LOCK_TIMEOUT).unwrap());
        assert!(legacy.exists());
        #[cfg(unix)]
        {
            fs::File::open(&legacy)
                .unwrap()
                .set_modified(SystemTime::now() - Duration::from_secs(120))
                .unwrap();
            drop(lock(&path, LOCK_TIMEOUT).unwrap());
            assert!(!legacy.exists());
        }
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn concurrent_startups_share_one_identity() {
        let path = directory();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create(&path).unwrap().spki_pin
                })
            })
            .collect();
        let pins: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(pins[0], pins[1]);
        fs::remove_dir_all(path).unwrap();
    }
    #[tokio::test]
    async fn store_caches_identity_until_it_is_rotated() {
        let path = directory();
        let store = Store::open(path.clone()).unwrap();
        let first = store.current().await.unwrap();
        assert!(Arc::ptr_eq(&first, &store.current().await.unwrap()));
        let rotated = rotate(&path).unwrap();
        let reloaded = store.current().await.unwrap();
        assert_eq!(reloaded.spki_pin, rotated.spki_pin);
        assert_ne!(reloaded.spki_pin, first.spki_pin);
        assert!(Arc::ptr_eq(&reloaded, &store.current().await.unwrap()));
        fs::remove_dir_all(path).unwrap();
    }
    #[tokio::test]
    async fn store_reloads_after_legacy_identity_is_rotated() {
        let path = directory();
        let pin = write_legacy(&path);
        let store = Store::open(path.clone()).unwrap();
        let first = store.current().await.unwrap();
        assert_eq!(first.spki_pin, pin);
        assert!(Arc::ptr_eq(&first, &store.current().await.unwrap()));
        let rotated = rotate(&path).unwrap();
        assert_eq!(store.current().await.unwrap().spki_pin, rotated.spki_pin);
        fs::remove_dir_all(path).unwrap();
    }
    #[tokio::test]
    async fn trusted_local_tls_handshake() {
        use rustls::pki_types::ServerName;
        let path = directory();
        let identity = load_or_create(&path).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificate_der(&path)))
            .unwrap();
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (accepted, connected) = tokio::join!(
            identity.acceptor.accept(server),
            connector.connect(ServerName::try_from("voice.discord.media").unwrap(), client)
        );
        assert!(accepted.is_ok(), "{:?}", accepted.err());
        assert!(connected.is_ok(), "{:?}", connected.err());
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn rejects_certificate_with_modified_signature() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["*.discord.media".into()]).unwrap();
        let mut cert = params.self_signed(&key).unwrap().der().to_vec();
        let last = cert.len() - 1;
        cert[last] ^= 1;
        assert!(identity_from_der(cert, key.serialize_der()).is_err());
    }
    #[test]
    fn rejects_wrong_san_and_ca() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        assert!(identity_from_der(
            params.self_signed(&key).unwrap().der().to_vec(),
            key.serialize_der()
        )
        .is_err());
        let mut params = rcgen::CertificateParams::new(vec!["*.discord.media".into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        assert!(identity_from_der(
            params.self_signed(&key).unwrap().der().to_vec(),
            key.serialize_der()
        )
        .is_err());
    }
}

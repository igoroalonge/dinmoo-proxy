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
    time::{Duration, Instant},
};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

pub struct VoiceIdentity {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub spki_pin: String,
}

impl VoiceIdentity {
    pub fn load_or_create(directory: &Path) -> crate::Result<Self> {
        load_or_create(directory)
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
    create_private_directory(directory)?;
    let _lock = IdentityLock::acquire(directory)?;
    let cert_path = directory.join("certificate.der");
    let key_path = directory.join("private-key.der");
    let cert_exists = cert_path.try_exists()?;
    let key_exists = key_path.try_exists()?;
    match (cert_exists, key_exists) {
        (false, false) => {
            let key = rcgen::KeyPair::generate()?;
            let params = rcgen::CertificateParams::new(vec!["*.discord.media".to_owned()])?;
            let cert = params.self_signed(&key)?;
            // Both files are published under the lock. Interrupted writes are deliberately
            // rejected on the next startup instead of silently changing the pinned key.
            publish(directory, "private-key.der", &key.serialize_der())?;
            publish(directory, "certificate.der", cert.der().as_ref())?;
        }
        (true, true) => {}
        _ => {
            return Err(
                "incomplete voice identity: preserve and repair the identity directory".into(),
            )
        }
    }
    check_private_file(&cert_path)?;
    check_private_file(&key_path)?;
    identity_from_der(fs::read(cert_path)?, fs::read(key_path)?)
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
fn check_private_file(path: &Path) -> io::Result<()> {
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
    Ok(())
}
fn publish(directory: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temporary = directory.join(format!(".{name}.tmp"));
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
    Ok(())
}
struct IdentityLock(PathBuf);
impl IdentityLock {
    fn acquire(directory: &Path) -> io::Result<Self> {
        let path = directory.join(".identity.lock");
        let started = Instant::now();
        loop {
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists && started.elapsed() < Duration::from_secs(5) => std::thread::sleep(Duration::from_millis(25)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Err(io::Error::new(io::ErrorKind::TimedOut, "voice identity is locked; another startup or interrupted generation needs attention")),
                Err(error) => return Err(error),
            }
        }
    }
}
impl Drop for IdentityLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
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
    #[test]
    fn persistent_identity_and_pin_match_certificate() {
        let path = directory();
        let first = load_or_create(&path).unwrap();
        let key = fs::read(path.join("private-key.der")).unwrap();
        let cert_bytes = fs::read(path.join("certificate.der")).unwrap();
        let (_, cert) = parse_x509_certificate(&cert_bytes).unwrap();
        assert_eq!(
            first.spki_pin,
            STANDARD.encode(Sha256::digest(cert.public_key().raw))
        );
        assert_eq!(load_or_create(&path).unwrap().spki_pin, first.spki_pin);
        assert_eq!(fs::read(path.join("private-key.der")).unwrap(), key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(path.join("private-key.der"))
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
    fn refuses_partial_corrupt_and_mismatched_identity() {
        let path = directory();
        load_or_create(&path).unwrap();
        let original_key = fs::read(path.join("private-key.der")).unwrap();
        fs::write(
            path.join("private-key.der"),
            rcgen::KeyPair::generate().unwrap().serialize_der(),
        )
        .unwrap();
        assert!(load_or_create(&path).is_err());
        fs::write(path.join("private-key.der"), original_key).unwrap();
        fs::write(path.join("certificate.der"), b"broken").unwrap();
        assert!(load_or_create(&path).is_err());
        assert_eq!(fs::read(path.join("certificate.der")).unwrap(), b"broken");
        fs::remove_file(path.join("certificate.der")).unwrap();
        assert!(load_or_create(&path).is_err());
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
    async fn trusted_local_tls_handshake() {
        use rustls::pki_types::ServerName;
        let path = directory();
        let identity = load_or_create(&path).unwrap();
        let cert = fs::read(path.join("certificate.der")).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(cert)).unwrap();
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

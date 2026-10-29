//! Private local operator interface; no public administration endpoint.

#[cfg(unix)]
mod unix {
    use super::super::Registry;
    use std::{
        io,
        os::unix::fs::{FileTypeExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
    };

    pub(super) struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    pub struct Handle {
        task: tokio::task::JoinHandle<()>,
        _cleanup: Cleanup,
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub(super) fn bind(path: &Path) -> crate::Result<(UnixListener, Cleanup)> {
        let parent = path
            .parent()
            .ok_or("admin socket needs a private parent directory")?;
        let metadata = std::fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("admin socket parent must be a real directory with mode 0700".into());
        }
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if !metadata.file_type().is_socket() {
                return Err("admin socket path already exists and is not a socket".into());
            }
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => return Err("admin socket is already in use".into()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)?
                }
                Err(error) => return Err(error.into()),
            }
        }
        let listener = UnixListener::bind(path)?;
        let cleanup = Cleanup(path.to_owned());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok((listener, cleanup))
    }
    pub(super) fn dispatch(command: &str, registry: &Registry) -> crate::Result<String> {
        if command == "LIST" {
            return Ok(serde_json::to_string(&registry.list())?);
        }
        let id = command
            .strip_prefix("TERMINATE ")
            .ok_or("unknown admin command")?;
        let id: [u8; 16] = hex::decode(id)?
            .try_into()
            .map_err(|_| "session ID must contain 32 hex characters")?;
        if !registry.terminate(id) {
            return Err("session not found".into());
        }
        Ok("terminated".into())
    }
    async fn serve(mut stream: UnixStream, registry: Registry) -> crate::Result<()> {
        let mut command = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if byte == b'\n' {
                break;
            }
            if command.len() >= 128 {
                return Err("admin command too long".into());
            }
            command.push(byte);
        }
        let response = match std::str::from_utf8(&command)
            .map_err(Into::into)
            .and_then(|command| dispatch(command, &registry))
        {
            Ok(response) => response,
            Err(error) => format!("ERROR {error}"),
        };
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await?;
        Ok(())
    }
    pub fn start(registry: Registry, path: PathBuf) -> crate::Result<Handle> {
        let (listener, cleanup) = bind(&path)?;
        let task = tokio::spawn(async move {
            let capacity = Arc::new(tokio::sync::Semaphore::new(16));
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let Ok(permit) = capacity.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let registry = registry.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), serve(stream, registry)).await;
                });
            }
        });
        Ok(Handle {
            task,
            _cleanup: cleanup,
        })
    }
    pub async fn request(command: &str) -> crate::Result<String> {
        let path = std::env::var_os("DINMOO_ADMIN_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/run/dinmoo-proxy/admin.sock"));
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut stream = UnixStream::connect(path).await?;
            stream.write_all(format!("{command}\n").as_bytes()).await?;
            let mut response = Vec::new();
            stream.take(1_048_577).read_to_end(&mut response).await?;
            if response.len() > 1_048_576 {
                return Err("admin response too large".into());
            }
            let response = String::from_utf8(response)?;
            if response.starts_with("ERROR ") {
                return Err(response.into());
            }
            Ok(response)
        })
        .await?
    }
}
#[cfg(all(test, unix))]
use unix::{bind, dispatch};
#[cfg(unix)]
pub use unix::{request, start};

#[cfg(not(unix))]
pub struct Handle;
#[cfg(not(unix))]
pub fn start(_registry: super::Registry, _path: std::path::PathBuf) -> crate::Result<Handle> {
    Err("operator socket is supported only on Unix gateways".into())
}
#[cfg(not(unix))]
pub async fn request(_command: &str) -> crate::Result<String> {
    Err("operator commands are supported only on Unix gateways".into())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn local_commands_list_and_terminate_only_requested_session() {
        let registry = super::super::Registry::new(std::time::Duration::from_secs(600));
        let first = registry.register("1.1.1.1".parse().unwrap()).unwrap();
        let second = registry.register("8.8.8.8".parse().unwrap()).unwrap();
        let listed = dispatch("LIST", &registry).unwrap();
        let listed: serde_json::Value = serde_json::from_str(&listed).unwrap();
        assert_eq!(listed.as_array().unwrap().len(), 2);
        dispatch(
            &format!("TERMINATE {}", hex::encode(first.session.id)),
            &registry,
        )
        .unwrap();
        assert!(first.session.cancel.is_cancelled());
        assert!(!second.session.cancel.is_cancelled());
        assert!(dispatch("TERMINATE not-a-session", &registry).is_err());
        assert!(dispatch("EXEC shell", &registry).is_err());
    }

    #[tokio::test]
    async fn admin_socket_requires_private_parent_and_is_not_world_accessible() {
        let directory = std::env::temp_dir().join(format!(
            "dma-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.join("admin.sock");
        assert!(bind(&path).is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let (_listener, cleanup) = bind(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(bind(&path).is_err(), "must not replace a live admin socket");
        drop(cleanup);
        assert!(!path.exists());
        std::fs::remove_dir(directory).unwrap();
    }
}

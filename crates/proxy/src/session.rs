//! Authenticated client sessions and server-initiated termination.

use crate::protection::{Activity, ActivityStream};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

pub mod admin;
pub mod client;

pub type Id = [u8; 16];
const PING: u8 = 1;
const PONG: u8 = 2;
const TERMINATE: u8 = 3;
pub(crate) const CONTROL_TIMEOUT: Duration = Duration::from_secs(45);
pub(crate) const CLIENT_PING_INTERVAL: Duration = Duration::from_secs(15);
// Each side must tolerate one lost or delayed ping before declaring the peer gone.
const _: () = assert!(CONTROL_TIMEOUT.as_millis() > 2 * CLIENT_PING_INTERVAL.as_millis());
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CLIENTS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    Idle = 1,
    Operator = 2,
}
impl TryFrom<u8> for Reason {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Idle),
            2 => Ok(Self::Operator),
            _ => Err("unknown gateway termination reason"),
        }
    }
}

pub struct ServerSession {
    pub id: Id,
    pub peer: IpAddr,
    pub cancel: CancellationToken,
    activity: Activity,
    reason: Mutex<Option<Reason>>,
}
impl ServerSession {
    fn terminate(&self, reason: Reason) {
        let mut current = self.reason.lock().unwrap();
        if current.is_none() {
            *current = Some(reason);
        }
        self.cancel.cancel();
    }
}

#[derive(Clone)]
pub struct Registry {
    sessions: Arc<Mutex<HashMap<Id, Arc<ServerSession>>>>,
    pub idle: Duration,
}
pub struct Lease {
    pub session: Arc<ServerSession>,
    registry: Registry,
}
// Operator listing and termination are served only by the Unix admin socket.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(serde::Serialize)]
pub struct Summary {
    pub session_id: String,
    pub peer_ip: IpAddr,
    pub idle_secs: u64,
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}
impl Registry {
    pub fn new(idle: Duration) -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            idle,
        }
    }
    pub fn register(&self, peer: IpAddr) -> crate::Result<Lease> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= MAX_CLIENTS {
            return Err("client session capacity reached".into());
        }
        let id = loop {
            let mut id = [0; 16];
            rustls::crypto::ring::default_provider()
                .secure_random
                .fill(&mut id)
                .map_err(|_| "session randomness failed")?;
            if !sessions.contains_key(&id) {
                break id;
            }
        };
        let (_, activity) = ActivityStream::new(());
        let session = Arc::new(ServerSession {
            id,
            peer: canonical_ip(peer),
            cancel: CancellationToken::new(),
            activity,
            reason: Mutex::new(None),
        });
        sessions.insert(id, session.clone());
        Ok(Lease {
            session,
            registry: self.clone(),
        })
    }
    pub fn attach(&self, id: Id, peer: IpAddr) -> crate::Result<Arc<ServerSession>> {
        self.sessions
            .lock()
            .unwrap()
            .get(&id)
            .filter(|session| session.peer == canonical_ip(peer) && !session.cancel.is_cancelled())
            .cloned()
            .ok_or_else(|| "unknown, terminated, or mismatched client session".into())
    }
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn terminate(&self, id: Id) -> bool {
        let sessions = self.sessions.lock().unwrap();
        if let Some(session) = sessions.get(&id) {
            session.terminate(Reason::Operator);
            true
        } else {
            false
        }
    }
    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn list(&self) -> Vec<Summary> {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .map(|session| Summary {
                session_id: hex::encode(session.id),
                peer_ip: session.peer,
                idle_secs: session.activity.last().elapsed().as_secs(),
            })
            .collect()
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.session.cancel.cancel();
        self.registry
            .sessions
            .lock()
            .unwrap()
            .remove(&self.session.id);
    }
}

pub fn tracked_data<S>(inner: S, session: &ServerSession) -> ActivityStream<S> {
    ActivityStream::with_activity(inner, session.activity.clone())
}

pub async fn serve_control<S>(stream: &mut S, registry: Registry, peer: IpAddr) -> crate::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let lease = registry.register(peer)?;
    let session = &lease.session;
    tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&session.id)).await??;
    let mut heartbeat_deadline = Instant::now() + CONTROL_TIMEOUT;
    loop {
        let idle_deadline = session.activity.last() + registry.idle;
        tokio::select! {
            _ = session.cancel.cancelled() => {
                let reason = *session.reason.lock().unwrap();
                if let Some(reason) = reason {
                    tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(&[TERMINATE, reason as u8])).await??;
                    let _ = tokio::time::timeout(WRITE_TIMEOUT, stream.shutdown()).await;
                }
                return Ok(());
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                if session.activity.last().elapsed() >= registry.idle { session.terminate(Reason::Idle); }
            }
            _ = tokio::time::sleep_until(heartbeat_deadline) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "client control heartbeat timed out").into()),
            message = stream.read_u8() => {
                if message? != PING { return Err("invalid client control message".into()); }
                tokio::time::timeout(WRITE_TIMEOUT, stream.write_u8(PONG)).await??;
                heartbeat_deadline = Instant::now() + CONTROL_TIMEOUT;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn registry_binds_data_to_peer_and_cleans_up_on_control_drop() {
        let registry = Registry::new(Duration::from_secs(600));
        let lease = registry.register("1.1.1.1".parse().unwrap()).unwrap();
        let id = lease.session.id;
        let data = registry.attach(id, "1.1.1.1".parse().unwrap()).unwrap();
        assert!(registry.attach(id, "8.8.8.8".parse().unwrap()).is_err());
        assert!(registry
            .attach([0; 16], "1.1.1.1".parse().unwrap())
            .is_err());
        drop(lease);
        assert!(data.cancel.is_cancelled());
        assert!(registry.list().is_empty());
        assert!(registry.attach(id, "1.1.1.1".parse().unwrap()).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn operator_terminates_only_selected_session() {
        let registry = Registry::new(Duration::from_secs(600));
        let first = registry.register("1.1.1.1".parse().unwrap()).unwrap();
        let second = registry.register("1.1.1.1".parse().unwrap()).unwrap();
        assert!(registry.terminate(first.session.id));
        assert!(first.session.cancel.is_cancelled());
        assert!(!second.session.cancel.is_cancelled());
        assert!(!registry.terminate([0; 16]));
        assert!(registry
            .attach(first.session.id, first.session.peer)
            .is_err());
    }

    #[test]
    fn termination_reasons_round_trip_and_reject_unknown_bytes() {
        for reason in [Reason::Idle, Reason::Operator] {
            assert_eq!(Reason::try_from(reason as u8), Ok(reason));
        }
        for byte in [0, 3, 255] {
            assert!(Reason::try_from(byte).is_err());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn pings_at_the_client_interval_keep_control_alive_until_they_stop() {
        let registry = Registry::new(Duration::from_secs(600));
        let (mut client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            serve_control(&mut server, registry, "1.1.1.1".parse().unwrap()).await
        });
        let mut id = [0; 16];
        client.read_exact(&mut id).await.unwrap();
        for _ in 0..4 {
            tokio::time::sleep(CLIENT_PING_INTERVAL).await;
            client.write_u8(PING).await.unwrap();
            assert_eq!(client.read_u8().await.unwrap(), PONG);
        }
        let silent = Instant::now();
        assert!(task.await.unwrap().is_err());
        assert_eq!(silent.elapsed(), CONTROL_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_does_not_prevent_idle_termination() {
        let registry = Registry::new(Duration::from_secs(10));
        let (mut client, mut server) = tokio::io::duplex(256);
        let task = tokio::spawn(async move {
            serve_control(&mut server, registry, "1.1.1.1".parse().unwrap()).await
        });
        let mut id = [0; 16];
        client.read_exact(&mut id).await.unwrap();
        let started = tokio::time::Instant::now();
        for _ in 0..2 {
            tokio::time::sleep(Duration::from_secs(4)).await;
            client.write_u8(PING).await.unwrap();
            assert_eq!(client.read_u8().await.unwrap(), PONG);
        }
        assert_eq!(client.read_u8().await.unwrap(), TERMINATE);
        assert_eq!(client.read_u8().await.unwrap(), Reason::Idle as u8);
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        task.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn data_activity_on_any_tunnel_extends_client_expiry() {
        let registry = Registry::new(Duration::from_secs(10));
        let (mut client, mut server) = tokio::io::duplex(256);
        let copy = registry.clone();
        let task = tokio::spawn(async move {
            serve_control(&mut server, copy, "1.1.1.1".parse().unwrap()).await
        });
        let mut id = [0; 16];
        client.read_exact(&mut id).await.unwrap();
        let session = registry.attach(id, "1.1.1.1".parse().unwrap()).unwrap();
        let (raw, mut peer) = tokio::io::duplex(64);
        let mut data = tracked_data(raw, &session);
        tokio::time::sleep(Duration::from_secs(8)).await;
        peer.write_u8(42).await.unwrap();
        assert_eq!(data.read_u8().await.unwrap(), 42);
        tokio::time::sleep(Duration::from_secs(8)).await;
        data.write_u8(43).await.unwrap();
        assert_eq!(peer.read_u8().await.unwrap(), 43);
        assert!(!session.cancel.is_cancelled());
        assert!(registry.terminate(id));
        assert_eq!(client.read_u8().await.unwrap(), TERMINATE);
        assert_eq!(client.read_u8().await.unwrap(), Reason::Operator as u8);
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn client_control_messages_cannot_terminate_another_session() {
        let registry = Registry::new(Duration::from_secs(600));
        let other = registry.register("1.1.1.1".parse().unwrap()).unwrap();
        let (mut client, mut server) = tokio::io::duplex(256);
        let copy = registry.clone();
        let task = tokio::spawn(async move {
            serve_control(&mut server, copy, "1.1.1.1".parse().unwrap()).await
        });
        let mut id = [0; 16];
        client.read_exact(&mut id).await.unwrap();
        client
            .write_all(&[TERMINATE, Reason::Operator as u8])
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
        assert!(!other.session.cancel.is_cancelled());
        assert_eq!(registry.list().len(), 1);
    }

    #[tokio::test]
    async fn control_eof_cancels_every_attached_data_tunnel() {
        let registry = Registry::new(Duration::from_secs(600));
        let (mut client, mut server) = tokio::io::duplex(256);
        let copy = registry.clone();
        let task = tokio::spawn(async move {
            serve_control(&mut server, copy, "1.1.1.1".parse().unwrap()).await
        });
        let mut id = [0; 16];
        client.read_exact(&mut id).await.unwrap();
        let data = registry.attach(id, "1.1.1.1".parse().unwrap()).unwrap();
        drop(client);
        assert!(task.await.unwrap().is_err());
        assert!(data.cancel.is_cancelled());
        assert!(registry.list().is_empty());
    }
}

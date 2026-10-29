//! Gateway admission and activity safeguards.

use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

const MAX_TRACKED_SOURCES: usize = 4096;

pub struct Settings {
    pub per_ip: usize,
    pub per_minute: usize,
    pub idle: Duration,
}
impl Settings {
    pub fn from_env() -> crate::Result<Self> {
        let read = |name, default| -> crate::Result<usize> {
            match std::env::var(name) {
                Ok(value) => parse_setting(name, &value),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(error) => Err(error.into()),
            }
        };
        Ok(Self {
            per_ip: read("DINMOO_MAX_SESSIONS_PER_IP", 32)?,
            per_minute: read("DINMOO_CONNECTIONS_PER_IP_PER_MINUTE", 120)?,
            idle: Duration::from_secs(read("DINMOO_IDLE_TIMEOUT_SECS", 600)? as u64),
        })
    }
}
fn parse_setting(name: &str, value: &str) -> crate::Result<usize> {
    let maximum = match name {
        "DINMOO_MAX_SESSIONS_PER_IP" => 4096,
        "DINMOO_CONNECTIONS_PER_IP_PER_MINUTE" => 10000,
        "DINMOO_IDLE_TIMEOUT_SECS" => 3600,
        _ => return Err("unknown protection setting".into()),
    };
    let parsed = value.parse::<usize>()?;
    if !(1..=maximum).contains(&parsed) {
        return Err(format!("{name} must be between 1 and {maximum}").into());
    }
    Ok(parsed)
}

struct Source {
    active: usize,
    tokens: f64,
    updated: Instant,
}
struct State {
    active: usize,
    sources: HashMap<IpAddr, Source>,
}
/// Admission is checked before allocating a TLS session or spawning its task.
/// A permit releases concurrency even when a task panics or is cancelled.
pub struct Admission {
    global: usize,
    per_ip: usize,
    rate: usize,
    state: Arc<Mutex<State>>,
}
pub struct Permit {
    source: IpAddr,
    state: Arc<Mutex<State>>,
}
fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ip.into(),
            None => {
                let [a, b, c, d, _, _, _, _] = ip.segments();
                Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0).into()
            }
        },
        ip => ip,
    }
}
impl Admission {
    pub fn new(global: usize, per_ip: usize, rate: usize) -> Self {
        Self {
            global,
            per_ip,
            rate,
            state: Arc::new(Mutex::new(State {
                active: 0,
                sources: HashMap::new(),
            })),
        }
    }
    pub fn acquire(&self, ip: IpAddr) -> Option<Permit> {
        let ip = source_key(ip);
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        // Expire only inactive, fully refilled sources. Never discard live counters
        // or let disconnect/reconnect reset a depleted rate bucket.
        if !state.sources.contains_key(&ip) {
            if state.sources.len() >= MAX_TRACKED_SOURCES {
                state.sources.retain(|_, source| {
                    source.active != 0
                        || now.duration_since(source.updated) < Duration::from_secs(60)
                });
                if state.sources.len() >= MAX_TRACKED_SOURCES {
                    return None;
                }
            }
            state.sources.insert(
                ip,
                Source {
                    active: 0,
                    tokens: self.rate as f64,
                    updated: now,
                },
            );
        }
        let source = state.sources.get_mut(&ip).unwrap();
        source.tokens = (source.tokens
            + now.duration_since(source.updated).as_secs_f64() * self.rate as f64 / 60.0)
            .min(self.rate as f64);
        source.updated = now;
        if source.tokens < 1.0 {
            return None;
        }
        // Attempts rejected for concurrency still consume their rate budget.
        source.tokens -= 1.0;
        if source.active >= self.per_ip {
            return None;
        }
        if state.active >= self.global {
            return None;
        }
        state.sources.get_mut(&ip).unwrap().active += 1;
        state.active += 1;
        Some(Permit {
            source: ip,
            state: self.state.clone(),
        })
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap();
        state.active -= 1;
        state.sources.get_mut(&self.source).unwrap().active -= 1;
    }
}

#[derive(Clone)]
pub struct Activity(Arc<Mutex<Instant>>);
impl Activity {
    pub fn last(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}
pub struct ActivityStream<S> {
    inner: S,
    activity: Activity,
}
impl<S> ActivityStream<S> {
    pub fn new(inner: S) -> (Self, Activity) {
        let activity = Activity(Arc::new(Mutex::new(Instant::now())));
        (
            Self {
                inner,
                activity: activity.clone(),
            },
            activity,
        )
    }
    pub fn with_activity(inner: S, activity: Activity) -> Self {
        Self { inner, activity }
    }
    fn touch(&self) {
        *self.activity.0.lock().unwrap() = Instant::now();
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for ActivityStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.touch();
        }
        result
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, bytes);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.touch();
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
/// The watchdog runs independently of relay reads/writes, including stalled sends.
pub async fn guard_idle<F>(future: F, activity: Activity, timeout: Duration) -> crate::Result<()>
where
    F: Future<Output = crate::Result<()>>,
{
    tokio::pin!(future);
    loop {
        let deadline = *activity.0.lock().unwrap() + timeout;
        tokio::select! {
            result = &mut future => return result,
            _ = tokio::time::sleep_until(deadline) => {
                if Instant::now().duration_since(*activity.0.lock().unwrap()) >= timeout {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "gateway session idle timeout").into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn ip(value: &str) -> std::net::IpAddr {
        value.parse().unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn admission_enforces_source_and_global_caps_and_releases_on_drop() {
        let limits = Admission::new(3, 2, 120);
        let first = limits.acquire(ip("1.1.1.1")).unwrap();
        let second = limits.acquire(ip("1.1.1.1")).unwrap();
        assert!(limits.acquire(ip("1.1.1.1")).is_none());
        let other = limits.acquire(ip("8.8.8.8")).unwrap();
        assert!(limits.acquire(ip("9.9.9.9")).is_none());
        drop(first);
        let replacement = limits.acquire(ip("1.1.1.1")).unwrap();
        drop((second, other, replacement));
        assert!(limits.acquire(ip("9.9.9.9")).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn rate_history_survives_disconnect_and_refills() {
        let limits = Admission::new(10, 10, 2);
        drop(limits.acquire(ip("1.1.1.1")).unwrap());
        drop(limits.acquire(ip("1.1.1.1")).unwrap());
        assert!(limits.acquire(ip("1.1.1.1")).is_none());
        assert!(limits.acquire(ip("8.8.8.8")).is_some());
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        assert!(limits.acquire(ip("1.1.1.1")).is_some());
        assert!(limits.acquire(ip("1.1.1.1")).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn over_concurrency_attempts_consume_the_rate_budget() {
        let limits = Admission::new(10, 1, 2);
        let active = limits.acquire(ip("1.1.1.1")).unwrap();
        assert!(limits.acquire(ip("1.1.1.1")).is_none());
        drop(active);
        assert!(limits.acquire(ip("1.1.1.1")).is_none());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(limits.acquire(ip("1.1.1.1")).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn mapped_ipv4_and_rotating_ipv6_share_source_limits() {
        let limits = Admission::new(10, 1, 120);
        let v4 = limits.acquire(ip("1.1.1.1")).unwrap();
        assert!(limits.acquire(ip("::ffff:1.1.1.1")).is_none());
        let v6 = limits.acquire(ip("2606:4700:1:2::1")).unwrap();
        assert!(limits.acquire(ip("2606:4700:1:2::2")).is_none());
        assert!(limits.acquire(ip("2606:4700:1:3::2")).is_some());
        drop((v4, v6));
    }

    #[tokio::test(start_paused = true)]
    async fn source_tracking_is_bounded_and_reclaims_only_idle_refilled_entries() {
        let limits = Admission::new(10, 2, 2);
        let active = limits.acquire(ip("1.1.1.1")).unwrap();
        for n in 1..MAX_TRACKED_SOURCES {
            let addr = std::net::Ipv4Addr::from(0x08000000 + n as u32);
            drop(limits.acquire(addr.into()).unwrap());
        }
        assert!(limits.acquire(ip("9.9.9.9")).is_none());
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        assert!(limits.acquire(ip("9.9.9.9")).is_some());
        let second = limits.acquire(ip("1.1.1.1")).unwrap();
        assert!(limits.acquire(ip("1.1.1.1")).is_none());
        drop((active, second));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_releases_admission() {
        let limits = Admission::new(1, 1, 120);
        let permit = limits.acquire(ip("1.1.1.1")).unwrap();
        let task = tokio::spawn(async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        });
        task.abort();
        let _ = task.await;
        assert!(limits.acquire(ip("1.1.1.1")).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn idle_watchdog_stops_inactive_and_blocked_write_sessions() {
        for blocked_write in [false, true] {
            let (stream, _peer) = tokio::io::duplex(1);
            let (mut stream, activity) = ActivityStream::new(stream);
            let future = async move {
                if blocked_write {
                    stream.write_all(&[1; 10]).await?;
                } else {
                    stream.read_u8().await?;
                }
                Ok(())
            };
            let started = tokio::time::Instant::now();
            assert!(
                guard_idle(future, activity, std::time::Duration::from_secs(10))
                    .await
                    .is_err()
            );
            assert_eq!(started.elapsed(), std::time::Duration::from_secs(10));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn incoming_and_outgoing_activity_each_extend_idle_deadline() {
        for outgoing in [false, true] {
            let (stream, mut peer) = tokio::io::duplex(64);
            let (mut stream, activity) = ActivityStream::new(stream);
            let task = tokio::spawn(guard_idle(
                async move {
                    for _ in 0..3 {
                        tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                        if outgoing {
                            stream.write_all(&[1]).await?;
                        } else {
                            stream.read_u8().await?;
                        }
                    }
                    Ok(())
                },
                activity,
                std::time::Duration::from_secs(10),
            ));
            if !outgoing {
                peer.write_all(&[1; 3]).await.unwrap();
            }
            assert!(task.await.unwrap().is_ok());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn flush_without_transferring_bytes_cannot_extend_idle_deadline() {
        let (stream, _peer) = tokio::io::duplex(64);
        let (mut stream, activity) = ActivityStream::new(stream);
        let started = Instant::now();
        let result = guard_idle(
            async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    stream.flush().await?;
                }
            },
            activity,
            Duration::from_secs(10),
        )
        .await;
        assert!(result.is_err());
        assert_eq!(started.elapsed(), Duration::from_secs(10));
    }

    #[test]
    fn settings_reject_invalid_or_unbounded_values() {
        for name in [
            "DINMOO_MAX_SESSIONS_PER_IP",
            "DINMOO_CONNECTIONS_PER_IP_PER_MINUTE",
            "DINMOO_IDLE_TIMEOUT_SECS",
        ] {
            for value in ["0", "-1", "oops", "999999999"] {
                assert!(parse_setting(name, value).is_err());
            }
        }
    }
}

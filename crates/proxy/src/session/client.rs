//! Reconnecting client session controller.
use super::{Id, Reason, PING, PONG, TERMINATE, WRITE_TIMEOUT};
use crate::tunnel::Gateway;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
    time::Instant,
};

#[derive(Default)]
struct Backoff {
    attempt: u32,
}
impl Backoff {
    fn next(&mut self) -> Duration {
        let seconds = (1u64 << self.attempt.min(5)).min(30);
        self.attempt = self.attempt.saturating_add(1);
        Duration::from_secs(seconds)
    }
}

async fn watch_control<S>(stream: &mut S) -> crate::Result<Reason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ping = tokio::time::interval(Duration::from_secs(15));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut deadline = Instant::now() + Duration::from_secs(45);
    loop {
        tokio::select! {
            _ = ping.tick() => { tokio::time::timeout(WRITE_TIMEOUT, stream.write_u8(PING)).await??; }
            _ = tokio::time::sleep_until(deadline) => return Err("gateway control heartbeat timed out".into()),
            message = stream.read_u8() => match message? {
                PONG => { deadline = Instant::now() + Duration::from_secs(45); }
                TERMINATE => return match tokio::time::timeout(WRITE_TIMEOUT, stream.read_u8()).await?? {
                    1 => Ok(Reason::Idle),
                    2 => Ok(Reason::Operator),
                    _ => Err("unknown gateway termination reason".into()),
                },
                _ => return Err("invalid gateway control message".into()),
            }
        }
    }
}

async fn connected<S>(
    control: &mut S,
    id: Id,
    cfg: Arc<crate::Config>,
    gateway: Arc<Gateway>,
    maximum: usize,
) -> crate::Result<Reason>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let listener = TcpListener::bind(cfg.listen).await?;
    eprintln!("client session ready; SOCKS listening on {}", cfg.listen);
    let capacity = Arc::new(tokio::sync::Semaphore::new(maximum));
    let mut tunnels = JoinSet::new();
    let watch = watch_control(control);
    tokio::pin!(watch);
    let result = loop {
        tokio::select! {
            // Stop accepting data as soon as the control session ends.
            biased;
            reason = &mut watch => break reason,
            Some(result) = tunnels.join_next(), if !tunnels.is_empty() => {
                if let Ok(Err(error)) = result { eprintln!("client tunnel: {error}"); }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(pair) => pair, Err(error) => break Err(error.into()) };
                let Ok(permit) = capacity.clone().try_acquire_owned() else { drop(stream); continue; };
                let tunnel = crate::tunnel::handle(stream, peer, cfg.clone(), gateway.clone(), id);
                tunnels.spawn(async move {
                    let _permit = permit;
                    tunnel.await
                });
            }
        }
    };
    drop(listener);
    tunnels.abort_all();
    while tunnels.join_next().await.is_some() {}
    result
}

pub async fn run(cfg: Arc<crate::Config>, maximum: usize) -> crate::Result<()> {
    let gateway = Arc::new(Gateway::new(&cfg)?);
    let mut backoff = Backoff::default();
    loop {
        let started = Instant::now();
        let result = async {
            let (mut control, id) = gateway.control().await?;
            connected(&mut control, id, cfg.clone(), gateway.clone(), maximum).await
        }
        .await;
        match result {
            Ok(reason) => {
                eprintln!("gateway ended client session ({reason:?}); all local tunnels closed")
            }
            Err(error) => eprintln!("client session unavailable: {error}"),
        }
        if started.elapsed() >= Duration::from_secs(60) {
            backoff = Backoff::default();
        }
        let delay = backoff.next();
        eprintln!("reconnecting to gateway in {}s", delay.as_secs());
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn explicit_termination_returns_reason_without_waiting_for_heartbeat() {
        for reason in [Reason::Idle, Reason::Operator] {
            let (mut client, mut server) = tokio::io::duplex(64);
            server.write_all(&[TERMINATE, reason as u8]).await.unwrap();
            assert_eq!(watch_control(&mut client).await.unwrap(), reason);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn eof_and_unknown_control_messages_fail_without_becoming_operator_commands() {
        let (mut client, server) = tokio::io::duplex(64);
        drop(server);
        assert!(watch_control(&mut client).await.is_err());
        let (mut client, mut server) = tokio::io::duplex(64);
        server.write_all(&[TERMINATE, 255]).await.unwrap();
        assert!(watch_control(&mut client).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn lost_control_peer_is_detected_without_data_traffic() {
        let (mut client, _server) = tokio::io::duplex(64);
        let start = Instant::now();
        assert!(watch_control(&mut client).await.is_err());
        assert!(start.elapsed() <= Duration::from_secs(45));
    }

    #[test]
    fn reconnect_backoff_is_bounded_and_can_reset_after_a_stable_session() {
        let mut backoff = Backoff::default();
        for seconds in [1, 2, 4, 8, 16, 30, 30, 30] {
            assert_eq!(backoff.next(), Duration::from_secs(seconds));
        }
        backoff = Backoff::default();
        assert_eq!(backoff.next(), Duration::from_secs(1));
    }
}

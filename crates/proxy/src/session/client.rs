//! Client session controller.
//!
//! The local SOCKS listener is held for the life of the process: Discord trusts
//! whatever answers on it, and a released port can be taken over by a process
//! that bound a wildcard address in advance.
use super::{Id, Reason, PING, PONG, TERMINATE, WRITE_TIMEOUT};
use crate::tunnel::{self, Gateway};
use std::{future::Future, io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::Instant,
};

const BIND_RETRY: Duration = Duration::from_secs(2);
const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(250);

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

fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    let socket = match address {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    // Never SO_REUSEPORT, which lets other sockets share the port. On Windows,
    // SO_REUSEADDR would allow hijacking; SO_EXCLUSIVEADDRUSE refuses later binds.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    #[cfg(windows)]
    exclusive_address_use(&socket)?;
    socket.bind(address)?;
    socket.listen(128)
}

#[cfg(windows)]
fn exclusive_address_use(socket: &TcpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    };
    let enabled: i32 = 1;
    // SAFETY: `socket` owns the handle and `enabled` outlives the call.
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            std::ptr::from_ref(&enabled).cast(),
            size_of::<i32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

async fn bind_listener(address: SocketAddr) -> TcpListener {
    let mut attempt = 0u32;
    loop {
        match bind(address) {
            Ok(listener) => return listener,
            Err(error) => {
                if attempt.is_multiple_of(30) {
                    eprintln!(
                        "WARNING: cannot listen on {address}: {error}. Another program may hold \
                         the Discord proxy port; retrying every {}s.",
                        BIND_RETRY.as_secs()
                    );
                }
                attempt = attempt.wrapping_add(1);
                tokio::time::sleep(BIND_RETRY).await;
            }
        }
    }
}

/// Waits for the next local connection; accept errors never reach the caller.
async fn next_connection<F, A>(mut accept: F) -> (TcpStream, SocketAddr)
where
    F: FnMut() -> A,
    A: Future<Output = io::Result<(TcpStream, SocketAddr)>>,
{
    loop {
        match accept().await {
            Ok(accepted) => return accepted,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => {
                // Usually EMFILE/ENFILE: wait for descriptors instead of spinning.
                eprintln!("local SOCKS accept: {error}");
                tokio::time::sleep(ACCEPT_ERROR_PAUSE).await;
            }
        }
    }
}

pub async fn run(cfg: Arc<crate::Config>, maximum: usize) -> crate::Result<()> {
    let gateway = Arc::new(Gateway::new(&cfg)?);
    let listener = bind_listener(cfg.listen).await;
    eprintln!(
        "SOCKS listening on {}; the gateway session opens on first use",
        cfg.listen
    );
    let control = gateway.clone();
    serve(
        listener,
        maximum,
        || control.control(),
        move |stream, peer, id| tunnel::handle(stream, peer, cfg.clone(), gateway.clone(), id),
    )
    .await
}

/// Serves local connections until the process exits. A gateway session opens
/// only for a waiting local connection; after a session ends or fails to open,
/// connections are closed at once until the backoff delay passes.
async fn serve<O, OF, S, H, HF>(
    listener: TcpListener,
    maximum: usize,
    mut open: O,
    handle: H,
) -> crate::Result<()>
where
    O: FnMut() -> OF,
    OF: Future<Output = crate::Result<(S, Id)>>,
    S: AsyncRead + AsyncWrite + Unpin,
    H: Fn(TcpStream, SocketAddr, Id) -> HF,
    HF: Future<Output = crate::Result<()>> + Send + 'static,
{
    let capacity = Arc::new(Semaphore::new(maximum));
    let mut backoff = Backoff::default();
    loop {
        let first = next_connection(|| listener.accept()).await;
        let started = Instant::now();
        // Further connections wait in the kernel backlog while the session opens.
        match open().await {
            Ok((mut control, id)) => {
                match session(&listener, &mut control, id, first, &capacity, &handle).await {
                    Ok(reason) => eprintln!(
                        "gateway ended client session ({reason:?}); all local tunnels closed"
                    ),
                    Err(error) => {
                        eprintln!("client session ended: {error}; all local tunnels closed")
                    }
                }
            }
            Err(error) => {
                drop(first);
                eprintln!("client session unavailable: {error}");
            }
        }
        if started.elapsed() >= Duration::from_secs(60) {
            backoff = Backoff::default();
        }
        let delay = backoff.next();
        eprintln!(
            "closing local SOCKS connections for {}s, then reconnecting on demand",
            delay.as_secs()
        );
        let _ = tokio::time::timeout(delay, async {
            loop {
                drop(next_connection(|| listener.accept()).await);
            }
        })
        .await;
    }
}

async fn session<S, H, HF>(
    listener: &TcpListener,
    control: &mut S,
    id: Id,
    first: (TcpStream, SocketAddr),
    capacity: &Arc<Semaphore>,
    handle: &H,
) -> crate::Result<Reason>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: Fn(TcpStream, SocketAddr, Id) -> HF,
    HF: Future<Output = crate::Result<()>> + Send + 'static,
{
    eprintln!("client session ready");
    let mut tunnels = JoinSet::new();
    let spawn = |tunnels: &mut JoinSet<_>, (stream, peer): (TcpStream, SocketAddr)| {
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            return;
        };
        let tunnel = handle(stream, peer, id);
        tunnels.spawn(async move {
            let _permit = permit;
            tunnel.await
        });
    };
    spawn(&mut tunnels, first);
    let watch = watch_control(control);
    tokio::pin!(watch);
    let result = loop {
        tokio::select! {
            // Stop accepting data as soon as the control session ends.
            biased;
            reason = &mut watch => break reason,
            Some(result) = tunnels.join_next(), if !tunnels.is_empty() => match result {
                // The gateway no longer knows this session; reconnect on next demand.
                Ok(Err(error)) if error.is::<tunnel::AttachRejected>() => break Err(error),
                Ok(Err(error)) => eprintln!("client tunnel: {error}"),
                _ => {}
            },
            accepted = next_connection(|| listener.accept()) => spawn(&mut tunnels, accepted),
        }
    };
    tunnels.abort_all();
    while tunnels.join_next().await.is_some() {}
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use tokio::{io::DuplexStream, sync::mpsc};

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

    // App-side sockets are blocking and run on a blocking thread: a paused clock
    // does not auto-advance while one runs, so backoff windows stay observable.
    async fn app<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        tokio::task::spawn_blocking(f).await.unwrap()
    }

    fn connect(address: SocketAddr) -> std::net::TcpStream {
        let stream = std::net::TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
    }

    /// Connects and waits for the tunnel's marker byte.
    fn served(address: SocketAddr) -> std::net::TcpStream {
        let mut stream = connect(address);
        let mut marker = [0];
        stream.read_exact(&mut marker).unwrap();
        assert_eq!(marker, [7]);
        stream
    }

    fn assert_closed(mut stream: std::net::TcpStream) {
        match stream.read(&mut [0]) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            other => panic!("local connection left open: {other:?}"),
        }
    }

    fn held(address: SocketAddr) -> bool {
        std::net::TcpListener::bind(address).is_err()
    }

    async fn open_session(
        opened: mpsc::UnboundedSender<DuplexStream>,
    ) -> crate::Result<(DuplexStream, Id)> {
        let (client, gateway) = tokio::io::duplex(64);
        opened.send(gateway).unwrap();
        Ok((client, [7; 16]))
    }

    /// Writes a marker, then acts on the app's first byte: `r` is an attach
    /// rejection, `e` another tunnel error; anything else keeps the tunnel open.
    async fn tunnel(mut stream: TcpStream, _peer: SocketAddr, id: Id) -> crate::Result<()> {
        stream.write_all(&id[..1]).await?;
        match stream.read_u8().await? {
            b'r' => Err(tunnel::AttachRejected.into()),
            b'e' => Err("tunnel failed".into()),
            _ => std::future::pending().await,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn session_opens_on_first_demand_and_the_listener_outlives_it() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let (opened, mut sessions) = mpsc::unbounded_channel();
        let controller = tokio::spawn(serve(
            listener,
            8,
            move || open_session(opened.clone()),
            tunnel,
        ));
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(sessions.try_recv().is_err(), "no session without demand");
        assert!(held(address));

        let first = app(move || served(address)).await;
        let mut control = sessions.try_recv().unwrap();
        let second = app(move || served(address)).await;
        assert!(sessions.try_recv().is_err(), "connections share a session");

        control
            .write_all(&[TERMINATE, Reason::Idle as u8])
            .await
            .unwrap();
        app(move || {
            assert_closed(first);
            assert_closed(second);
            assert!(held(address));
            // Backing off: closed at once, without opening a session.
            assert_closed(connect(address));
        })
        .await;
        assert!(sessions.try_recv().is_err());

        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(sessions.try_recv().is_err(), "idle termination stays idle");
        assert!(held(address));
        let third = app(move || served(address)).await;
        assert!(sessions.try_recv().is_ok());
        drop(third);
        controller.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn failed_session_closes_the_waiting_connection_and_backs_off() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let (attempted, mut attempts) = mpsc::unbounded_channel();
        let open = move || {
            let attempted = attempted.clone();
            async move {
                attempted.send(()).unwrap();
                Err::<(DuplexStream, Id), _>("gateway unavailable".into())
            }
        };
        let controller = tokio::spawn(serve(listener, 8, open, tunnel));
        app(move || {
            assert_closed(connect(address));
            assert_closed(connect(address));
            assert!(held(address));
        })
        .await;
        assert!(attempts.try_recv().is_ok());
        assert!(attempts.try_recv().is_err(), "no attempt while backing off");
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(attempts.try_recv().is_err(), "no attempt without demand");
        app(move || assert_closed(connect(address))).await;
        assert!(attempts.try_recv().is_ok());
        controller.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn attach_rejection_ends_the_session_but_other_tunnel_errors_do_not() {
        let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = listener.local_addr().unwrap();
        let (opened, mut sessions) = mpsc::unbounded_channel();
        let controller = tokio::spawn(serve(
            listener,
            8,
            move || open_session(opened.clone()),
            tunnel,
        ));
        let kept = app(move || {
            let kept = served(address);
            let mut failing = served(address);
            failing.write_all(b"e").unwrap();
            assert_closed(failing);
            kept
        })
        .await;
        let mut control = sessions.try_recv().unwrap();
        let (kept, rejected) = app(move || (kept, served(address))).await;
        assert!(
            sessions.try_recv().is_err(),
            "tunnel errors keep the session"
        );

        app(move || {
            let mut rejected = rejected;
            rejected.write_all(b"r").unwrap();
            assert_closed(rejected);
            assert_closed(kept);
        })
        .await;
        let mut ended = Vec::new();
        control.read_to_end(&mut ended).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(sessions.try_recv().is_err());
        let next = app(move || served(address)).await;
        assert!(sessions.try_recv().is_ok(), "the next demand reconnects");
        drop(next);
        controller.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn accept_errors_pause_or_retry_without_failing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = app(move || connect(address)).await;
        let mut errors = [
            io::Error::from(io::ErrorKind::ConnectionAborted),
            io::Error::from_raw_os_error(24), // EMFILE
        ]
        .into_iter();
        let listener = &listener;
        let started = Instant::now();
        let (_stream, peer) = next_connection(|| {
            let error = errors.next();
            async move {
                match error {
                    Some(error) => Err(error),
                    None => listener.accept().await,
                }
            }
        })
        .await;
        assert_eq!(started.elapsed(), ACCEPT_ERROR_PAUSE);
        assert_eq!(peer, client.local_addr().unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn listener_bind_retries_until_the_address_is_free() {
        let squatter = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = squatter.local_addr().unwrap();
        let binding = tokio::spawn(bind_listener(address));
        tokio::time::sleep(BIND_RETRY * 5).await;
        assert!(!binding.is_finished());
        drop(squatter);
        let listener = binding.await.unwrap();
        assert_eq!(listener.local_addr().unwrap(), address);
        assert!(held(address));
    }
}

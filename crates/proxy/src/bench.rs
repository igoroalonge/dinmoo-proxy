//! Ignored CPU benchmarks for the 0.2.6 optimisation work.
//!
//! Run in release, one benchmark at a time:
//!
//! ```text
//! cargo test --release --locked -- --ignored --test-threads=1 bench_ --nocapture
//! ```
//!
//! Every measurement prints one line:
//!
//! ```text
//! BENCH name=<name> ops=<n> cpu_us_per_op=<f> wall_ms=<f> extra=<key:value,...>
//! ```
//!
//! `cpu_us_per_op` is whole-process user+sys CPU (`getrusage(RUSAGE_SELF)`) over the
//! measured window divided by `ops`, so it includes the in-process load generators.
//! `extra` adds `<side>_us_per_op`: CPU of the threads of the runtime hosting the code
//! under test (Mach `thread_info` on macOS, per-thread CPU clocks on Linux).
//! Topologies use real TLS (test fixtures) over loopback TCP and loopback UDP only.
//! `DINMOO_BENCH_SCALE` (default 1) multiplies every operation count; keep it at or
//! below 10 for `bench_handshakes`, whose closed client sockets sit in TIME_WAIT and
//! can exhaust the ephemeral port range. Benchmarks run in the test binary, where
//! tokio's `test-util` feature is on; its clock fast path applies while no test pauses
//! time, which holds because `--ignored` runs only these benchmarks.
//! `scripts/bench-cpu.py` repeats the run and reports medians; results live in
//! `docs/perf/`.
#![cfg(unix)]

use crate::{
    gateway, protection, session,
    tunnel::write_string,
    udp::{write_frame, FrameReader},
    voice::{self, gateway::GrantScope, wire},
    TCP_COPY_BUFFER_SIZE,
};
use bytes::{Bytes, BytesMut};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use rustls::{
    client::Resumption,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, HandshakeKind, RootCertStore, ServerConfig,
};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    runtime::{Builder, Handle, Runtime},
    sync::{oneshot, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::tungstenite::Message;

const FIXTURE_CERT: &[u8] = include_bytes!("../tests/fixtures/localhost-cert.der");
const FIXTURE_KEY: &[u8] = include_bytes!("../tests/fixtures/localhost-key.der");
const FIXTURE_CA: &[u8] = include_bytes!("../tests/fixtures/test-ca.der");
const MIB: usize = 1 << 20;
/// Voice media datagram size used by every UDP benchmark.
const PAYLOAD: usize = 1000;
/// Datagrams in flight for "blast" phases; small enough that loopback UDP never drops.
const WINDOW: usize = 128;
const STALL: Duration = Duration::from_secs(2);
/// Upper bound for any benchmark phase, so a harness bug fails instead of hanging.
const DEADLINE: Duration = Duration::from_secs(120);
const VOICE_HOST: &str = "voice.discord.media";

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

fn scaled(count: u64) -> u64 {
    let scale = std::env::var("DINMOO_BENCH_SCALE")
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| *value > 0.0)
        .unwrap_or(1.0);
    ((count as f64) * scale).round().max(1.0) as u64
}

fn process_cpu() -> Duration {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: getrusage fully initialises `usage` when it returns 0.
    let usage = unsafe {
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()), 0);
        usage.assume_init()
    };
    let time = |value: libc::timeval| {
        Duration::from_secs(value.tv_sec as u64) + Duration::from_micros(value.tv_usec as u64)
    };
    time(usage.ru_utime) + time(usage.ru_stime)
}

#[cfg(target_os = "macos")]
mod thread_cpu {
    use std::time::Duration;
    pub type Id = libc::mach_port_t;
    pub fn current() -> Option<Id> {
        // SAFETY: returns the calling thread's port name without transferring a right.
        Some(unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) })
    }
    pub fn used(id: Id) -> Option<Duration> {
        let mut info = std::mem::MaybeUninit::<libc::thread_basic_info>::zeroed();
        let mut count = libc::THREAD_BASIC_INFO_COUNT;
        // SAFETY: `info` has room for THREAD_BASIC_INFO_COUNT integers; a dead thread
        // only yields an error code.
        let status = unsafe {
            libc::thread_info(
                id,
                libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
                info.as_mut_ptr().cast(),
                &mut count,
            )
        };
        if status != libc::KERN_SUCCESS {
            return None;
        }
        // SAFETY: initialised by the successful call above.
        let info = unsafe { info.assume_init() };
        let time = |value: libc::time_value_t| {
            Duration::from_secs(value.seconds as u64)
                + Duration::from_micros(value.microseconds as u64)
        };
        Some(time(info.user_time) + time(info.system_time))
    }
}

#[cfg(target_os = "linux")]
mod thread_cpu {
    use std::time::Duration;
    pub type Id = libc::clockid_t;
    pub fn current() -> Option<Id> {
        let mut id: libc::clockid_t = 0;
        // SAFETY: writes the calling thread's CPU clock id into `id`.
        (unsafe { libc::pthread_getcpuclockid(libc::pthread_self(), &mut id) } == 0).then_some(id)
    }
    pub fn used(id: Id) -> Option<Duration> {
        let mut time = std::mem::MaybeUninit::<libc::timespec>::zeroed();
        // SAFETY: clock_gettime initialises `time` when it returns 0.
        if unsafe { libc::clock_gettime(id, time.as_mut_ptr()) } != 0 {
            return None;
        }
        // SAFETY: initialised by the successful call above.
        let time = unsafe { time.assume_init() };
        Some(Duration::new(time.tv_sec as u64, time.tv_nsec as u32))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod thread_cpu {
    use std::time::Duration;
    pub type Id = u8;
    pub fn current() -> Option<Id> {
        None
    }
    pub fn used(_: Id) -> Option<Duration> {
        None
    }
}

/// Threads owned by one runtime, so its CPU can be separated from the harness.
#[derive(Clone, Default)]
struct Threads(Arc<Mutex<Vec<thread_cpu::Id>>>);
impl Threads {
    fn register_current(&self) {
        if let Some(id) = thread_cpu::current() {
            self.0.lock().unwrap().push(id);
        }
    }
    fn snapshot(&self) -> HashMap<thread_cpu::Id, Duration> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|id| thread_cpu::used(*id).map(|used| (*id, used)))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Flavor {
    CurrentThread,
    MultiThread,
}

/// A runtime hosting code under test. A dedicated driver thread blocks on it, so a
/// current-thread runtime runs spawned tasks exactly like `block_on` in `main`.
struct Side {
    name: &'static str,
    handle: Handle,
    threads: Threads,
    stop: Option<oneshot::Sender<()>>,
    driver: Option<std::thread::JoinHandle<()>>,
}
impl Side {
    fn new(name: &'static str, flavor: Flavor) -> Self {
        let threads = Threads::default();
        let mut builder = match flavor {
            Flavor::CurrentThread => Builder::new_current_thread(),
            Flavor::MultiThread => Builder::new_multi_thread(),
        };
        let registered = threads.clone();
        let runtime = builder
            .enable_all()
            .thread_name(format!("bench-{name}"))
            .on_thread_start(move || registered.register_current())
            .build()
            .unwrap();
        let handle = runtime.handle().clone();
        let (stop, stopped) = oneshot::channel::<()>();
        let registered = threads.clone();
        let driver = std::thread::Builder::new()
            .name(format!("bench-{name}-driver"))
            .spawn(move || {
                registered.register_current();
                runtime.block_on(async {
                    let _ = stopped.await;
                });
                runtime.shutdown_background();
            })
            .unwrap();
        Self {
            name,
            handle,
            threads,
            stop: Some(stop),
            driver: Some(driver),
        }
    }
    fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.handle.spawn(future)
    }
}
impl Drop for Side {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(driver) = self.driver.take() {
            let _ = driver.join();
        }
    }
}

/// Load generators and fakes run here; their CPU is process CPU minus the sides.
fn harness() -> Runtime {
    Builder::new_multi_thread()
        .enable_all()
        .thread_name("bench-harness")
        .build()
        .unwrap()
}

struct Window<'a> {
    cpu: Duration,
    wall: Instant,
    sides: Vec<(&'a Side, HashMap<thread_cpu::Id, Duration>)>,
}
fn window<'a>(sides: &[&'a Side]) -> Window<'a> {
    let sides = sides
        .iter()
        .map(|side| (*side, side.threads.snapshot()))
        .collect();
    Window {
        cpu: process_cpu(),
        wall: Instant::now(),
        sides,
    }
}
impl Window<'_> {
    fn finish(self, name: &str, ops: u64) -> Sample {
        let wall = self.wall.elapsed();
        let cpu = process_cpu().saturating_sub(self.cpu);
        let per_op = |used: Duration| used.as_secs_f64() * 1e6 / ops.max(1) as f64;
        let sides = self
            .sides
            .iter()
            .filter(|(_, start)| !start.is_empty())
            .map(|(side, start)| {
                let used = side
                    .threads
                    .snapshot()
                    .iter()
                    .map(|(id, now)| now.saturating_sub(start.get(id).copied().unwrap_or_default()))
                    .sum();
                (side.name, per_op(used))
            })
            .collect();
        Sample {
            name: name.to_owned(),
            ops,
            cpu_us_per_op: per_op(cpu),
            wall_ms: wall.as_secs_f64() * 1e3,
            sides,
            extra: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct Sample {
    name: String,
    ops: u64,
    cpu_us_per_op: f64,
    wall_ms: f64,
    sides: Vec<(&'static str, f64)>,
    extra: Vec<(String, String)>,
}
impl Sample {
    fn with(mut self, key: &str, value: impl std::fmt::Display) -> Self {
        self.extra.push((key.to_owned(), value.to_string()));
        self
    }
    fn side(&self, name: &str) -> Option<f64> {
        self.sides
            .iter()
            .find(|(side, _)| *side == name)
            .map(|(_, value)| *value)
    }
    fn print(&self) {
        let extra: Vec<String> = self
            .sides
            .iter()
            .map(|(side, value)| format!("{side}_us_per_op:{value:.3}"))
            .chain(
                self.extra
                    .iter()
                    .map(|(key, value)| format!("{key}:{value}")),
            )
            .collect();
        println!(
            "BENCH name={} ops={} cpu_us_per_op={:.3} wall_ms={:.1} extra={}",
            self.name,
            self.ops,
            self.cpu_us_per_op,
            self.wall_ms,
            if extra.is_empty() {
                "-".to_owned()
            } else {
                extra.join(",")
            }
        );
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn fixture_server() -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(FIXTURE_CERT.to_vec())],
                PrivateKeyDer::try_from(FIXTURE_KEY.to_vec()).unwrap(),
            )
            .unwrap(),
    )
}

fn fixture_client() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(FIXTURE_CA.to_vec()))
        .unwrap();
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A "localhost" ECDSA P-256 identity, the key type Certbot issues by default.
fn ecdsa_pair() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    (Arc::new(server), Arc::new(client))
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").unwrap()
}

async fn tls_connect(
    address: SocketAddr,
    config: Arc<ClientConfig>,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(address).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    TlsConnector::from(config)
        .connect(localhost(), tcp)
        .await
        .unwrap()
}

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "dinmoo-bench-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

async fn bounded<F: Future>(what: &str, future: F) -> F::Output {
    tokio::time::timeout(DEADLINE, future)
        .await
        .unwrap_or_else(|_| panic!("{what} stalled for {DEADLINE:?}"))
}

fn loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

/// Lets the gateway relay grant a loopback "Discord media" socket (see `GrantScope`).
const LOOPBACK_GRANTS: GrantScope = GrantScope {
    allow: loopback,
    bind_v4: "127.0.0.1:0",
    bind_v6: "[::1]:0",
};

// ---------------------------------------------------------------------------
// Windowed UDP <-> voice-record transfers (shared by both voice benchmarks)
// ---------------------------------------------------------------------------

/// The harness sends `count` datagrams and counts the `tag` records they become.
async fn udp_to_records<S>(
    socket: Arc<UdpSocket>,
    destination: SocketAddr,
    mut records: S,
    tag: u8,
    count: u64,
    window: usize,
) -> (u64, S)
where
    S: Stream<Item = io::Result<BytesMut>> + Unpin + Send + 'static,
{
    let credit = Arc::new(Semaphore::new(window));
    let counter = tokio::spawn({
        let credit = credit.clone();
        async move {
            let mut received = 0;
            while received < count {
                let Ok(Some(Ok(record))) = tokio::time::timeout(STALL, records.next()).await else {
                    break;
                };
                let (kind, payload) = wire::unpack(&record).unwrap();
                if kind == tag {
                    assert_eq!(payload.len(), wire::FLOW_ID_LEN + PAYLOAD);
                    received += 1;
                    credit.add_permits(1);
                }
            }
            (received, records)
        }
    });
    let payload = [0x5a; PAYLOAD];
    for _ in 0..count {
        match tokio::time::timeout(STALL, credit.acquire()).await {
            Ok(permit) => permit.unwrap().forget(),
            Err(_) => break,
        }
        socket.send_to(&payload, destination).await.unwrap();
    }
    counter.await.unwrap()
}

/// The harness sends `count` copies of `record` and counts the datagrams they become.
/// Returns the delivered count and the datagrams' source address.
async fn records_to_udp<K>(
    sink: &mut K,
    record: Bytes,
    socket: Arc<UdpSocket>,
    count: u64,
    window: usize,
) -> (u64, Option<SocketAddr>)
where
    K: Sink<Bytes, Error = io::Error> + Unpin,
{
    let credit = Arc::new(Semaphore::new(window));
    let counter = tokio::spawn({
        let credit = credit.clone();
        async move {
            let mut buffer = vec![0; 2048];
            let (mut received, mut source) = (0, None);
            while received < count {
                let Ok(Ok((length, from))) =
                    tokio::time::timeout(STALL, socket.recv_from(&mut buffer)).await
                else {
                    break;
                };
                assert_eq!(length, PAYLOAD);
                received += 1;
                source = Some(from);
                credit.add_permits(1);
            }
            (received, source)
        }
    });
    for _ in 0..count {
        match tokio::time::timeout(STALL, credit.acquire()).await {
            Ok(permit) => permit.unwrap().forget(),
            Err(_) => break,
        }
        sink.send(record.clone()).await.unwrap();
    }
    counter.await.unwrap()
}

fn packet_sample(
    window: Window<'_>,
    name: String,
    sent: u64,
    delivered: u64,
    credit: usize,
) -> Sample {
    window
        .finish(&name, delivered)
        .with("unit", "packet")
        .with("lost", sent - delivered)
        .with("window", credit)
}

// ---------------------------------------------------------------------------
// 1. Gateway TCP data tunnel
// ---------------------------------------------------------------------------

/// Gateway data-tunnel shape: TLS server stream in the session `ActivityStream`, relayed
/// with `copy_bidirectional_with_sizes` to a loopback TCP echo. All tunnels share one
/// client session, hence one `Activity` mutex, on a multi-thread runtime.
#[test]
#[ignore = "CPU benchmark; see module docs"]
fn bench_tcp_tunnel() {
    let mib = scaled(256) as usize;
    for tunnels in [1, 8] {
        tcp_tunnel(tunnels, mib).print();
    }
}

fn tcp_tunnel(tunnels: usize, mib_each_way: usize) -> Sample {
    let gateway = Side::new("gateway", Flavor::MultiThread);
    let harness = harness();
    let sample = harness.block_on(async {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((stream, _)) = echo.accept().await {
                tokio::spawn(async move {
                    stream.set_nodelay(true).unwrap();
                    let (read, mut write) = stream.into_split();
                    let mut read = tokio::io::BufReader::with_capacity(64 * 1024, read);
                    let _ = tokio::io::copy_buf(&mut read, &mut write).await;
                });
            }
        });

        let registry = session::Registry::new(Duration::from_secs(600));
        let lease = registry.register("127.0.0.1".parse().unwrap()).unwrap();
        let session = lease.session.clone();
        let acceptor = TlsAcceptor::from(fixture_server());
        let gateway_address = gateway
            .spawn(async move {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                tokio::spawn(async move {
                    while let Ok((stream, _)) = listener.accept().await {
                        let (acceptor, session) = (acceptor.clone(), session.clone());
                        tokio::spawn(async move {
                            stream.set_nodelay(true).unwrap();
                            let tls = acceptor.accept(stream).await.unwrap();
                            let mut stream = session::tracked_data(tls, &session);
                            let mut target = TcpStream::connect(echo_address).await.unwrap();
                            target.set_nodelay(true).unwrap();
                            tokio::select! {
                                biased;
                                _ = session.cancel.cancelled() => {}
                                _ = tokio::io::copy_bidirectional_with_sizes(
                                    &mut stream,
                                    &mut target,
                                    TCP_COPY_BUFFER_SIZE,
                                    TCP_COPY_BUFFER_SIZE,
                                ) => {}
                            }
                        });
                    }
                });
                address
            })
            .await
            .unwrap();

        let client = fixture_client();
        let mut streams = Vec::new();
        for _ in 0..tunnels {
            let mut tls = tls_connect(gateway_address, client.clone()).await;
            tls.write_all(&[7]).await.unwrap();
            assert_eq!(tls.read_u8().await.unwrap(), 7);
            streams.push(tls);
        }
        let per_tunnel = mib_each_way * MIB / tunnels;
        let chunk: Arc<[u8]> = (0..TCP_COPY_BUFFER_SIZE)
            .map(|i| (i * 31 % 251) as u8)
            .collect();

        let measured = window(&[&gateway]);
        let mut transfers = JoinSet::new();
        for tls in streams {
            let chunk = chunk.clone();
            transfers.spawn(async move {
                let (mut read, mut write) = tokio::io::split(tls);
                let send = async {
                    let mut left = per_tunnel;
                    while left > 0 {
                        let n = left.min(chunk.len());
                        write.write_all(&chunk[..n]).await.unwrap();
                        left -= n;
                    }
                    // tokio-rustls may hold the last TLS records until flushed.
                    write.flush().await.unwrap();
                };
                let receive = async {
                    let mut buffer = vec![0; 64 * 1024];
                    let mut received = 0;
                    while received < per_tunnel {
                        let n = read.read(&mut buffer).await.unwrap();
                        assert!(n > 0, "tunnel closed early");
                        received += n;
                    }
                };
                tokio::join!(send, receive);
                (read, write)
            });
        }
        let mut finished = Vec::new();
        while let Some(result) = bounded("TCP tunnel transfer", transfers.join_next()).await {
            finished.push(result.unwrap());
        }
        let sample = measured
            .finish(&format!("tcp_tunnel_x{tunnels}"), (2 * mib_each_way) as u64)
            .with("unit", "MiB_relayed")
            .with("mib_each_way", mib_each_way)
            .with("tunnels", tunnels);
        drop(finished);
        drop(lease);
        sample
    });
    harness.shutdown_timeout(Duration::from_secs(1));
    drop(gateway);
    sample
}

// ---------------------------------------------------------------------------
// 2. Gateway connection handshakes
// ---------------------------------------------------------------------------

/// Sequential connections against the real accept loop (`gateway::serve` →
/// `handle_gateway_connection`): TCP connect, TLS, DMPX v1 auth, close. One shared
/// `ClientConfig` per variant, like the real client, so TLS resumption can occur.
#[test]
#[ignore = "CPU benchmark; see module docs"]
fn bench_handshakes() {
    let count = scaled(300);
    handshakes("handshakes", fixture_server(), fixture_client(), count).print();
    let mut no_resumption = (*fixture_client()).clone();
    no_resumption.resumption = Resumption::disabled();
    handshakes(
        "handshakes_no_resumption",
        fixture_server(),
        Arc::new(no_resumption),
        count,
    )
    .print();
    let (server, client) = ecdsa_pair();
    handshakes("handshakes_ecdsa_p256", server, client, count).print();
}

async fn dmpx_v1(connector: &TlsConnector, address: SocketAddr) -> io::Result<bool> {
    let tcp = TcpStream::connect(address).await?;
    tcp.set_nodelay(true)?;
    let mut tls = connector.connect(localhost(), tcp).await?;
    tls.write_all(b"DMPX\x01").await?;
    write_string(&mut tls, "").await.map_err(io::Error::other)?;
    tls.flush().await?;
    if tls.read_u8().await? != 1 {
        return Err(io::Error::other("gateway rejected authentication"));
    }
    Ok(tls.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed))
}

fn handshakes(
    name: &str,
    server: Arc<ServerConfig>,
    client: Arc<ClientConfig>,
    count: u64,
) -> Sample {
    let gateway_side = Side::new("gateway", Flavor::MultiThread);
    let listen = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut config = crate::test_config();
    config.token.clear();
    config.listen = listen;
    config.server_tls = Some(TlsAcceptor::from(server));
    let settings = protection::Settings {
        per_ip: 4096,
        per_minute: 10_000,
        idle: Duration::from_secs(600),
    };
    gateway_side.spawn(gateway::serve(Arc::new(config), settings, 4096));
    let harness = harness();
    let sample = harness.block_on(async {
        let connector = TlsConnector::from(client);
        let deadline = Instant::now() + Duration::from_secs(5);
        while dmpx_v1(&connector, listen).await.is_err() {
            assert!(Instant::now() < deadline, "gateway did not start");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let measured = window(&[&gateway_side]);
        let mut resumed = 0;
        for _ in 0..count {
            if bounded("gateway connection", dmpx_v1(&connector, listen))
                .await
                .unwrap()
            {
                resumed += 1;
            }
        }
        measured
            .finish(name, count)
            .with("unit", "connection")
            .with("resumed", format!("{resumed}/{count}"))
    });
    harness.shutdown_timeout(Duration::from_secs(1));
    drop(gateway_side);
    sample
}

// ---------------------------------------------------------------------------
// 3. + 6. Client voice bridge UDP (voice::local::run)
// ---------------------------------------------------------------------------

/// Real local TLS + WebSocket from a fake Discord, real TLS tunnel to a fake gateway
/// speaking `wire` records; measures per-packet cost of the client bridge.
#[test]
#[ignore = "CPU benchmark; see module docs"]
fn bench_voice_client_udp() {
    for sample in voice_client(
        Flavor::MultiThread,
        "voice_client_udp",
        scaled(100_000),
        scaled(20_000),
    ) {
        sample.print();
    }
}

/// The client voice bridge on a current-thread vs a default multi-thread runtime.
#[test]
#[ignore = "CPU benchmark; see module docs"]
fn bench_runtime_flavor() {
    let (blast, lockstep) = (scaled(50_000), scaled(10_000));
    let current = voice_client(
        Flavor::CurrentThread,
        "runtime_flavor_current",
        blast,
        lockstep,
    );
    let multi = voice_client(Flavor::MultiThread, "runtime_flavor_multi", blast, lockstep);
    let change = |a: f64, b: f64| format!("{:+.1}", (a - b) / b * 100.0);
    for (current, multi) in current.iter().zip(&multi) {
        let mut sample = current.clone().with(
            "cpu_vs_multi_pct",
            change(current.cpu_us_per_op, multi.cpu_us_per_op),
        );
        if let (Some(a), Some(b)) = (current.side("client"), multi.side("client")) {
            sample = sample.with("client_vs_multi_pct", change(a, b));
        }
        sample.print();
    }
    for sample in multi {
        sample.print();
    }
}

fn voice_client(flavor: Flavor, prefix: &str, blast: u64, lockstep: u64) -> Vec<Sample> {
    let client = Side::new("client", flavor);
    let harness = harness();
    let directory = temp_dir("voice-identity");
    let samples = harness.block_on(async {
        let identity =
            Arc::new(voice::identity::VoiceIdentity::load_or_create(&directory).unwrap());
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(
                std::fs::read(directory.join("certificate.der")).unwrap(),
            ))
            .unwrap();
        let discord_tls = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        // Fake gateway end of the client's TLS tunnel.
        let gateway_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway_address = gateway_listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(fixture_server());
        let gateway_connection = tokio::spawn(async move {
            let (stream, _) = gateway_listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            wire::framed(acceptor.accept(stream).await.unwrap())
        });

        // Client bridge under test.
        let (local_tx, local_rx) = oneshot::channel();
        let tunnel_tls = fixture_client();
        let bridge_identity = identity.clone();
        let bridge = client.spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            local_tx.send(listener.local_addr().unwrap()).unwrap();
            let (mut local, _) = listener.accept().await.unwrap();
            local.set_nodelay(true).unwrap();
            let mut remote = tls_connect(gateway_address, tunnel_tls).await;
            voice::local::run(&mut local, &mut remote, &bridge_identity, VOICE_HOST, 443).await
        });

        // Fake Discord: TLS + WebSocket to the bridge, then a UDP media socket.
        let tcp = TcpStream::connect(local_rx.await.unwrap()).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let tls = TlsConnector::from(discord_tls)
            .connect(ServerName::try_from(VOICE_HOST).unwrap(), tcp)
            .await
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::client_async(format!("wss://{VOICE_HOST}/?v=8"), tls)
            .await
            .unwrap();
        let mut gateway = gateway_connection.await.unwrap();
        let path = gateway.next().await.unwrap().unwrap();
        assert_eq!(wire::unpack(&path).unwrap().0, wire::PATH);
        let flow = [9u8; wire::FLOW_ID_LEN];
        let mut ready = flow.to_vec();
        // TEST-NET-3 address: the bridge rewrites it to loopback and never contacts it.
        ready.extend_from_slice(
            br#"{"op":2,"d":{"ssrc":1,"ip":"203.0.113.1","port":50000,"modes":["aead_aes256_gcm_rtpsize"]}}"#,
        );
        gateway
            .send(wire::record(wire::READY, &ready))
            .await
            .unwrap();
        let text = ws.next().await.unwrap().unwrap().into_text().unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let bridge_udp: SocketAddr = format!("127.0.0.1:{}", value["d"]["port"].as_u64().unwrap())
            .parse()
            .unwrap();
        let discord = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (mut to_bridge, mut from_bridge) = gateway.split();
        let mut downstream = flow.to_vec();
        downstream.extend_from_slice(&[0xa5; PAYLOAD]);
        let downstream = wire::record(wire::UDP_RECV, &downstream);

        // IP discovery for the Ready SSRC pins the Discord socket as the bridge's UDP peer.
        let mut discovery = [0; 74];
        discovery[..8].copy_from_slice(&[0, 1, 0, 70, 0, 0, 0, 1]);
        discord.send_to(&discovery, bridge_udp).await.unwrap();
        let record = from_bridge.next().await.unwrap().unwrap();
        let (tag, payload) = wire::unpack(&record).unwrap();
        assert_eq!((tag, &payload[wire::FLOW_ID_LEN..]), (wire::UDP_SEND, &discovery[..]));
        let (warm, rest) =
            udp_to_records(discord.clone(), bridge_udp, from_bridge, wire::UDP_SEND, 100, WINDOW)
                .await;
        from_bridge = rest;
        assert_eq!(warm, 100);
        let (warm, _) =
            records_to_udp(&mut to_bridge, downstream.clone(), discord.clone(), 100, WINDOW).await;
        assert_eq!(warm, 100);

        let mut samples = Vec::new();
        for (suffix, count, credit) in [("", blast, WINDOW), ("_lockstep", lockstep, 1)] {
            let measured = window(&[&client]);
            let (delivered, rest) = udp_to_records(
                discord.clone(),
                bridge_udp,
                from_bridge,
                wire::UDP_SEND,
                count,
                credit,
            )
            .await;
            from_bridge = rest;
            samples.push(packet_sample(
                measured,
                format!("{prefix}_up{suffix}"),
                count,
                delivered,
                credit,
            ));
            let measured = window(&[&client]);
            let (delivered, _) =
                records_to_udp(&mut to_bridge, downstream.clone(), discord.clone(), count, credit)
                    .await;
            samples.push(packet_sample(
                measured,
                format!("{prefix}_down{suffix}"),
                count,
                delivered,
                credit,
            ));
        }
        let _ = ws.close(None).await;
        let result = tokio::time::timeout(Duration::from_secs(5), bridge).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "voice bridge did not close cleanly"
        );
        drop((to_bridge, from_bridge));
        samples
    });
    harness.shutdown_timeout(Duration::from_secs(1));
    drop(client);
    let _ = std::fs::remove_dir_all(directory);
    samples
}

// ---------------------------------------------------------------------------
// 4. Gateway voice relay UDP (voice::gateway::relay_with)
// ---------------------------------------------------------------------------

/// The gateway relay between a client TLS tunnel (session `ActivityStream`) and a fake
/// Discord voice server (TLS WebSocket + UDP media socket), with a loopback grant scope.
#[test]
#[ignore = "CPU benchmark; see module docs"]
fn bench_voice_gateway_udp() {
    let (blast, lockstep) = (scaled(100_000), scaled(20_000));
    let gateway = Side::new("gateway", Flavor::MultiThread);
    let harness = harness();
    let samples = harness.block_on(async {
        // Fake Discord voice server.
        let discord_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let discord_address = discord_listener.local_addr().unwrap();
        let media = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let media_address = media.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(fixture_server());
        let discord = tokio::spawn(async move {
            let (stream, _) = discord_listener.accept().await.unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            tokio_tungstenite::accept_async(tls).await.unwrap()
        });

        // Gateway relay under test.
        let (control_tx, control_rx) = oneshot::channel();
        let control_acceptor = TlsAcceptor::from(fixture_server());
        let upstream_tls = fixture_client();
        let relay = gateway.spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            control_tx.send(listener.local_addr().unwrap()).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let tls = control_acceptor.accept(stream).await.unwrap();
            let registry = session::Registry::new(Duration::from_secs(600));
            let lease = registry.register("127.0.0.1".parse().unwrap()).unwrap();
            let mut stream = session::tracked_data(tls, &lease.session);
            let mut control = wire::framed(&mut stream);
            let remote = TcpStream::connect(discord_address).await.unwrap();
            let tls = TlsConnector::from(upstream_tls)
                .connect(localhost(), remote)
                .await
                .unwrap();
            let config = wire::websocket_config();
            let url = format!("wss://localhost:{}/?v=8", discord_address.port());
            let (ws, _) = tokio_tungstenite::client_async_with_config(url, tls, Some(config))
                .await
                .unwrap();
            voice::gateway::relay_with(&mut control, ws, false, LOOPBACK_GRANTS).await
        });

        // Fake client end of the tunnel.
        let tunnel = tls_connect(control_rx.await.unwrap(), fixture_client()).await;
        let (mut to_gateway, mut from_gateway) = wire::framed(tunnel).split();
        let mut discord = discord.await.unwrap();
        let ready = format!(
            r#"{{"op":2,"d":{{"ssrc":1,"ip":"127.0.0.1","port":{},"modes":["aead_aes256_gcm_rtpsize"]}}}}"#,
            media_address.port()
        );
        discord.send(Message::Text(ready.into())).await.unwrap();
        let flow = loop {
            let record = from_gateway.next().await.unwrap().unwrap();
            let (tag, payload) = wire::unpack(&record).unwrap();
            if tag == wire::READY {
                break payload[..wire::FLOW_ID_LEN].to_vec();
            }
        };
        let mut upstream = flow.clone();
        upstream.extend_from_slice(&[0xa5; PAYLOAD]);
        let upstream = wire::record(wire::UDP_SEND, &upstream);

        // Warm-up also tells the fake media server the relay's UDP source address.
        let (warm, relay_udp) =
            records_to_udp(&mut to_gateway, upstream.clone(), media.clone(), 100, WINDOW).await;
        assert_eq!(warm, 100);
        let relay_udp = relay_udp.unwrap();
        let (warm, rest) =
            udp_to_records(media.clone(), relay_udp, from_gateway, wire::UDP_RECV, 100, WINDOW)
                .await;
        from_gateway = rest;
        assert_eq!(warm, 100);

        let mut samples = Vec::new();
        for (suffix, count, credit) in [("", blast, WINDOW), ("_lockstep", lockstep, 1)] {
            let measured = window(&[&gateway]);
            let (delivered, _) =
                records_to_udp(&mut to_gateway, upstream.clone(), media.clone(), count, credit)
                    .await;
            samples.push(packet_sample(
                measured,
                format!("voice_gateway_udp_up{suffix}"),
                count,
                delivered,
                credit,
            ));
            let measured = window(&[&gateway]);
            let (delivered, rest) = udp_to_records(
                media.clone(),
                relay_udp,
                from_gateway,
                wire::UDP_RECV,
                count,
                credit,
            )
            .await;
            from_gateway = rest;
            samples.push(packet_sample(
                measured,
                format!("voice_gateway_udp_down{suffix}"),
                count,
                delivered,
                credit,
            ));
        }
        to_gateway
            .send(wire::record(wire::CLOSE, &[]))
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), relay).await;
        assert!(
            matches!(result, Ok(Ok(Ok(())))),
            "voice relay did not close cleanly"
        );
        drop((to_gateway, from_gateway, discord));
        samples
    });
    harness.shutdown_timeout(Duration::from_secs(1));
    drop(gateway);
    for sample in samples {
        sample.print();
    }
}

// ---------------------------------------------------------------------------
// 5. SOCKS UDP frames over TLS
// ---------------------------------------------------------------------------

/// `udp::write_frame` on a split client TLS stream → loopback TCP → gateway
/// `udp::FrameReader` on a split `ActivityStream<TlsStream>`, as in UDP ASSOCIATE.
#[test]
#[ignore = "CPU benchmark; see module docs"]
fn bench_socks_udp_frames() {
    let count = scaled(100_000);
    let client = Side::new("client", Flavor::MultiThread);
    let gateway = Side::new("gateway", Flavor::MultiThread);
    let harness = harness();
    let sample = harness.block_on(async {
        let acceptor = TlsAcceptor::from(fixture_server());
        let (address_tx, address_rx) = oneshot::channel();
        let (warm_tx, warm_rx) = oneshot::channel();
        let reader = gateway.spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            address_tx.send(listener.local_addr().unwrap()).unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            let tls = acceptor.accept(stream).await.unwrap();
            let (mut stream, _activity) = protection::ActivityStream::new(tls);
            let (mut reader, _writer) = tokio::io::split(&mut stream);
            let mut frames = FrameReader::default();
            frames.read(&mut reader).await.unwrap();
            warm_tx.send(()).unwrap();
            let (mut received, mut bytes) = (0u64, 0usize);
            while received < count {
                bytes += frames.read(&mut reader).await.unwrap().len();
                received += 1;
            }
            (received, bytes)
        });
        let address = address_rx.await.unwrap();
        let client_tls = fixture_client();
        let (go_tx, go_rx) = oneshot::channel::<()>();
        let writer = client.spawn(async move {
            let tls = tls_connect(address, client_tls).await;
            let (read, mut write) = tokio::io::split(tls);
            // SOCKS UDP header for 127.0.0.1:5000 followed by a voice-sized payload.
            let mut frame = vec![0, 0, 0, 1, 127, 0, 0, 1, 0x13, 0x88];
            frame.extend_from_slice(&[0x5a; PAYLOAD]);
            write_frame(&mut write, &frame).await.unwrap();
            go_rx.await.unwrap();
            for _ in 0..count {
                write_frame(&mut write, &frame).await.unwrap();
            }
            write.flush().await.unwrap();
            (read, write)
        });
        warm_rx.await.unwrap();
        let measured = window(&[&client, &gateway]);
        go_tx.send(()).unwrap();
        let (received, bytes) = bounded("SOCKS UDP frames", reader).await.unwrap();
        let sample = measured
            .finish("socks_udp_frames", received)
            .with("unit", "frame")
            .with("frame_bytes", bytes / received.max(1) as usize);
        drop(bounded("SOCKS UDP writer", writer).await.unwrap());
        sample
    });
    harness.shutdown_timeout(Duration::from_secs(1));
    drop((client, gateway));
    sample.print();
}

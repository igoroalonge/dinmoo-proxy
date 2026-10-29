//! Bounded records inside the authenticated client-to-gateway TLS tunnel.
use crate::ContextExt;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::SinkExt;
use std::{io, net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UdpSocket,
};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub const TEXT: u8 = 1;
pub const BINARY: u8 = 2;
pub const CLOSE: u8 = 3;
pub const READY: u8 = 4;
pub const UDP_SEND: u8 = 5;
pub const UDP_RECV: u8 = 6;
pub const PATH: u8 = 7;
pub const REVOKE: u8 = 8;
pub const FLOW_ID_LEN: usize = 16;
pub const MAX_UDP: usize = 8192;
pub const MAX_WS: usize = 512 * 1024;
pub const MAX_RECORD: usize = MAX_WS + FLOW_ID_LEN + 1;
pub const GRANT_TTL: Duration = Duration::from_secs(120);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_HEADER: usize = 1 + FLOW_ID_LEN;
const UDP_BATCH_DATAGRAMS: usize = 32;
const UDP_BATCH_BYTES: usize = 64 * 1024;

pub fn framed<T: AsyncRead + AsyncWrite>(stream: T) -> Framed<T, LengthDelimitedCodec> {
    LengthDelimitedCodec::builder()
        .max_frame_length(MAX_RECORD)
        .new_framed(stream)
}

pub fn record(tag: u8, payload: &[u8]) -> Bytes {
    let mut value = BytesMut::with_capacity(1 + payload.len());
    value.put_u8(tag);
    value.extend_from_slice(payload);
    value.freeze()
}

pub fn unpack(value: &[u8]) -> crate::Result<(u8, &[u8])> {
    if value.is_empty() || value.len() > MAX_RECORD {
        return Err("invalid voice record length".into());
    }
    Ok((value[0], &value[1..]))
}

/// tungstenite zero-fills the free part of its read buffer before every read, so the
/// 128 KiB default costs more CPU than small voice messages need. Larger messages still
/// fit: the buffer grows to the announced frame length.
pub fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .max_message_size(Some(MAX_WS))
        .max_frame_size(Some(MAX_WS))
}

/// Binds a UDP socket for `try_send_to`, which tokio refuses with `WouldBlock` until the
/// runtime has seen the socket writable once.
pub async fn bind_udp(address: &str) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(address).await?;
    socket.writable().await?;
    Ok(socket)
}

/// A reused `[tag | flow ID | datagram]` record whose datagram slot receives in place.
pub struct UdpRecords(Vec<u8>);

impl UdpRecords {
    pub fn new(tag: u8) -> Self {
        let mut record = vec![0; UDP_HEADER + MAX_UDP + 1];
        record[0] = tag;
        Self(record)
    }

    pub fn datagram(&mut self) -> &mut [u8] {
        &mut self.0[UDP_HEADER..]
    }

    /// Forwards `first` (received into `datagram()`) and the datagrams already queued on
    /// `socket`, up to a bound, each only if it fits and passes `accept`. The batch shares
    /// one flush and one write deadline, so a stalled tunnel still ends the session.
    pub async fn forward<T: AsyncWrite + Unpin>(
        &mut self,
        tunnel: &mut Framed<T, LengthDelimitedCodec>,
        socket: &UdpSocket,
        id: &[u8; FLOW_ID_LEN],
        first: io::Result<(usize, SocketAddr)>,
        accept: impl FnMut(SocketAddr, &[u8]) -> bool,
    ) -> crate::Result<()> {
        let queued = |datagram: &mut [u8]| socket.try_recv_from(datagram);
        tokio::time::timeout(WRITE_TIMEOUT, self.batch(tunnel, id, first, queued, accept))
            .await
            .context("voice tunnel write timed out")?
    }

    /// `queued` receives the next datagram without waiting.
    async fn batch<T: AsyncWrite + Unpin>(
        &mut self,
        tunnel: &mut Framed<T, LengthDelimitedCodec>,
        id: &[u8; FLOW_ID_LEN],
        first: io::Result<(usize, SocketAddr)>,
        mut queued: impl FnMut(&mut [u8]) -> io::Result<(usize, SocketAddr)>,
        mut accept: impl FnMut(SocketAddr, &[u8]) -> bool,
    ) -> crate::Result<()> {
        self.0[1..UDP_HEADER].copy_from_slice(id);
        let (mut received, mut bytes) = (first, 0);
        for count in 1.. {
            match received {
                Ok((len, source)) if len <= MAX_UDP => {
                    let record = &self.0[..UDP_HEADER + len];
                    if accept(source, &record[UDP_HEADER..]) {
                        tunnel.feed(record).await?;
                        bytes += record.len();
                    }
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if skippable(&error) => {}
                Err(error) => return Err(error.into()),
            }
            if count == UDP_BATCH_DATAGRAMS || bytes >= UDP_BATCH_BYTES {
                break;
            }
            received = queued(&mut self.0[UDP_HEADER..]);
        }
        if bytes > 0 {
            SinkExt::<&[u8]>::flush(tunnel).await?;
        }
        Ok(())
    }
}

/// Receive errors that report one event and leave the socket usable: Windows reports ICMP
/// port unreachable for an earlier send on the next receive, and fails the receive of a
/// datagram larger than the buffer with WSAEMSGSIZE after discarding it (Unix truncates).
fn skippable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
    ) || (cfg!(windows) && error.raw_os_error() == Some(10040))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::collections::VecDeque;
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
    };
    use tokio::{io::ReadBuf, time::timeout};

    const ID: [u8; FLOW_ID_LEN] = [7; FLOW_ID_LEN];

    async fn sockets() -> (UdpSocket, std::net::UdpSocket, SocketAddr) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        (socket, sender, address)
    }

    fn udp_record(payload: &[u8]) -> Vec<u8> {
        [&[UDP_SEND][..], &ID, payload].concat()
    }

    /// A scripted receive queue, so batch bounds do not depend on kernel buffering.
    type Queue = VecDeque<io::Result<(Vec<u8>, SocketAddr)>>;

    /// Receives like a nonblocking `recv_from`: truncates to the buffer, then `WouldBlock`.
    fn pop(queue: &mut Queue, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (data, from) = queue
            .pop_front()
            .unwrap_or_else(|| Err(io::ErrorKind::WouldBlock.into()))?;
        let len = data.len().min(buf.len());
        buf[..len].copy_from_slice(&data[..len]);
        Ok((len, from))
    }

    async fn drain<T: AsyncWrite + Unpin>(
        records: &mut UdpRecords,
        tunnel: &mut Framed<T, LengthDelimitedCodec>,
        queue: &mut Queue,
        accept: impl FnMut(SocketAddr, &[u8]) -> bool,
    ) -> crate::Result<()> {
        let first = pop(queue, records.datagram());
        records
            .batch(tunnel, &ID, first, |buf| pop(queue, buf), accept)
            .await
    }

    async fn next<T: AsyncRead + Unpin>(
        far: &mut Framed<T, LengthDelimitedCodec>,
    ) -> Option<Vec<u8>> {
        let record = timeout(Duration::from_secs(2), far.next()).await.unwrap();
        record.map(|record| record.unwrap().to_vec())
    }

    #[tokio::test]
    async fn udp_batch_checks_every_datagram_and_shares_one_flush() {
        let source: SocketAddr = "127.0.0.1:4000".parse().unwrap();
        let stranger: SocketAddr = "127.0.0.1:4001".parse().unwrap();
        let mut queue: Queue = (0..40u8)
            .map(|i| match i {
                3 => Ok((vec![i; 100], stranger)),
                5 => Ok((vec![i; MAX_UDP + 1], source)),
                _ => Ok((vec![i; 100], source)),
            })
            .collect();
        let (near, far) = tokio::io::duplex(1 << 20);
        let (near, flushes) = CountFlushes::new(near);
        let (mut tunnel, mut far) = (framed(near), framed(far));
        let mut records = UdpRecords::new(UDP_SEND);
        for (batch, expected, left) in [(1, 0..32u8, 8), (2, 32..40, 0)] {
            drain(&mut records, &mut tunnel, &mut queue, |from, _| {
                from == source
            })
            .await
            .unwrap();
            assert_eq!((flush_count(&flushes), queue.len()), (batch, left));
            for i in expected.filter(|i| ![3, 5].contains(i)) {
                assert_eq!(next(&mut far).await, Some(udp_record(&[i; 100])));
            }
        }
        drop(tunnel);
        assert_eq!(next(&mut far).await, None);
    }

    #[tokio::test]
    async fn udp_batch_is_bounded_in_bytes() {
        let source = "127.0.0.1:4000".parse().unwrap();
        let mut queue: Queue = (0..10).map(|_| Ok((vec![1; MAX_UDP], source))).collect();
        let (near, far) = tokio::io::duplex(1 << 20);
        let (mut tunnel, mut far) = (framed(near), framed(far));
        let mut records = UdpRecords::new(UDP_SEND);
        drain(&mut records, &mut tunnel, &mut queue, |_, _| true)
            .await
            .unwrap();
        assert_eq!(queue.len(), 2);
        drop(tunnel);
        let mut forwarded = 0;
        while next(&mut far).await.is_some() {
            forwarded += 1;
        }
        assert_eq!(forwarded, 8);
    }

    #[tokio::test]
    async fn udp_receive_resets_are_skipped_and_other_errors_are_fatal() {
        let source = "127.0.0.1:4000".parse().unwrap();
        let (near, far) = tokio::io::duplex(1 << 20);
        let (mut tunnel, mut far) = (framed(near), framed(far));
        let mut records = UdpRecords::new(UDP_SEND);
        let mut queue: Queue = VecDeque::from([
            Err(io::ErrorKind::ConnectionReset.into()),
            Ok((b"one".to_vec(), source)),
            Err(io::ErrorKind::ConnectionRefused.into()),
            Ok((b"two".to_vec(), source)),
        ]);
        drain(&mut records, &mut tunnel, &mut queue, |_, _| true)
            .await
            .unwrap();
        assert_eq!(next(&mut far).await, Some(udp_record(b"one")));
        assert_eq!(next(&mut far).await, Some(udp_record(b"two")));
        let mut queue: Queue = VecDeque::from([
            Ok((b"three".to_vec(), source)),
            Err(io::ErrorKind::PermissionDenied.into()),
        ]);
        assert!(drain(&mut records, &mut tunnel, &mut queue, |_, _| true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn oversized_datagram_is_dropped_without_ending_the_batch() {
        let (socket, sender, address) = sockets().await;
        let source = sender.local_addr().unwrap();
        sender.send_to(&[1; MAX_UDP + 100], address).unwrap();
        let mut records = UdpRecords::new(UDP_SEND);
        // Unix truncates the datagram to the buffer; Windows fails with WSAEMSGSIZE.
        let oversized = socket.recv_from(records.datagram()).await;
        let mut queue: Queue = VecDeque::from([Ok((b"next".to_vec(), source))]);
        let (near, far) = tokio::io::duplex(1 << 20);
        let (mut tunnel, mut far) = (framed(near), framed(far));
        records
            .batch(
                &mut tunnel,
                &ID,
                oversized,
                |buf| pop(&mut queue, buf),
                |_, _| true,
            )
            .await
            .unwrap();
        assert_eq!(next(&mut far).await, Some(udp_record(b"next")));
    }

    #[tokio::test]
    async fn bound_udp_socket_sends_without_waiting() {
        let socket = bind_udp("127.0.0.1:0").await.unwrap();
        let (target, _, address) = sockets().await;
        socket.try_send_to(b"first", address).unwrap();
        let mut buf = [0; 8];
        let (len, _) = timeout(Duration::from_secs(2), target.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], b"first");
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_tunnel_ends_udp_batch_at_write_timeout() {
        let (socket, sender, address) = sockets().await;
        for _ in 0..10 {
            sender.send_to(&[1; 1000], address).unwrap();
        }
        let (near, _far) = tokio::io::duplex(1);
        let mut tunnel = framed(near);
        let mut records = UdpRecords::new(UDP_SEND);
        let first = socket.recv_from(records.datagram()).await;
        let start = tokio::time::Instant::now();
        assert!(records
            .forward(&mut tunnel, &socket, &ID, first, |_, _| true)
            .await
            .is_err());
        assert_eq!(start.elapsed(), WRITE_TIMEOUT);
    }

    /// A tunnel stream that counts the flushes reaching it.
    pub struct CountFlushes<T>(T, Arc<AtomicUsize>);

    impl<T> CountFlushes<T> {
        pub fn new(inner: T) -> (Self, Arc<AtomicUsize>) {
            let count = Arc::new(AtomicUsize::new(0));
            (Self(inner, count.clone()), count)
        }
    }

    pub fn flush_count(count: &AtomicUsize) -> usize {
        count.load(Ordering::SeqCst)
    }

    impl<T: AsyncRead + Unpin> AsyncRead for CountFlushes<T> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for CountFlushes<T> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            self.1.fetch_add(1, Ordering::SeqCst);
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}

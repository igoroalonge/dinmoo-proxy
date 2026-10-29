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
        tokio::time::timeout(WRITE_TIMEOUT, self.batch(tunnel, socket, id, first, accept))
            .await
            .context("voice tunnel write timed out")?
    }

    async fn batch<T: AsyncWrite + Unpin>(
        &mut self,
        tunnel: &mut Framed<T, LengthDelimitedCodec>,
        socket: &UdpSocket,
        id: &[u8; FLOW_ID_LEN],
        first: io::Result<(usize, SocketAddr)>,
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
                // Windows reports ICMP port unreachable for an earlier send on the next receive.
                Err(error) if transient(&error) => {}
                Err(error) => return Err(error.into()),
            }
            if count == UDP_BATCH_DATAGRAMS || bytes >= UDP_BATCH_BYTES {
                break;
            }
            received = socket.try_recv_from(&mut self.0[UDP_HEADER..]);
        }
        if bytes > 0 {
            SinkExt::<&[u8]>::flush(tunnel).await?;
        }
        Ok(())
    }
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionRefused
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        task::{Context, Poll},
    };
    use tokio::io::ReadBuf;

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

    #[tokio::test]
    async fn udp_batch_checks_every_datagram_and_shares_one_flush() {
        let (socket, sender, address) = sockets().await;
        let stranger = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = sender.local_addr().unwrap();
        for i in 0..40u8 {
            match i {
                3 => stranger.send_to(&[i; 100], address),
                5 => sender.send_to(&[i; MAX_UDP + 1], address),
                _ => sender.send_to(&[i; 100], address),
            }
            .unwrap();
        }
        let (near, far) = tokio::io::duplex(1 << 20);
        let (near, flushes) = CountFlushes::new(near);
        let (mut tunnel, mut far) = (framed(near), framed(far));
        let mut records = UdpRecords::new(UDP_SEND);
        for (batch, expected) in [(1, 0..32u8), (2, 32..40)] {
            let first = socket.recv_from(records.datagram()).await;
            records
                .forward(&mut tunnel, &socket, &ID, first, |from, _| from == source)
                .await
                .unwrap();
            assert_eq!(flush_count(&flushes), batch);
            for i in expected.filter(|i| ![3, 5].contains(i)) {
                assert_eq!(far.next().await.unwrap().unwrap(), udp_record(&[i; 100]));
            }
        }
        drop(tunnel);
        assert!(far.next().await.is_none());
    }

    #[tokio::test]
    async fn udp_batch_is_bounded_in_bytes() {
        let (socket, sender, address) = sockets().await;
        for _ in 0..10 {
            sender.send_to(&[1; MAX_UDP], address).unwrap();
        }
        let (near, far) = tokio::io::duplex(1 << 20);
        let (mut tunnel, mut far) = (framed(near), framed(far));
        let mut records = UdpRecords::new(UDP_SEND);
        let first = socket.recv_from(records.datagram()).await;
        records
            .forward(&mut tunnel, &socket, &ID, first, |_, _| true)
            .await
            .unwrap();
        drop(tunnel);
        let mut forwarded = 0;
        while far.next().await.is_some() {
            forwarded += 1;
        }
        assert_eq!(forwarded, 8);
    }

    #[tokio::test]
    async fn udp_receive_resets_are_transient() {
        let (socket, sender, address) = sockets().await;
        sender.send_to(b"after reset", address).unwrap();
        socket.readable().await.unwrap();
        let (near, far) = tokio::io::duplex(1 << 20);
        let (mut tunnel, mut far) = (framed(near), framed(far));
        let mut records = UdpRecords::new(UDP_SEND);
        for kind in [
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::ConnectionRefused,
        ] {
            records
                .forward(&mut tunnel, &socket, &ID, Err(kind.into()), |_, _| true)
                .await
                .unwrap();
        }
        assert_eq!(
            far.next().await.unwrap().unwrap(),
            udp_record(b"after reset")
        );
        let fatal = Err(io::ErrorKind::PermissionDenied.into());
        assert!(records
            .forward(&mut tunnel, &socket, &ID, fatal, |_, _| true)
            .await
            .is_err());
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

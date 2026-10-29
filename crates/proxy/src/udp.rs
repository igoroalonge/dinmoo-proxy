//! SOCKS5 UDP packet codec and length-prefixed tunnel framing.
use crate::{
    socks::{parse_address, Address},
    Result,
};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_FRAME: usize = 1500;
/// One extra byte detects truncated datagrams: anything that fills it is too long.
pub(crate) const UDP_RECV_BUF: usize = MAX_FRAME + 1;
/// A TLS stream yields at most one 16 KiB record per read.
const FRAME_READ_BUFFER: usize = 16 * 1024;

pub(crate) fn valid_socks_udp_packet(packet: &[u8]) -> bool {
    if !(4..=MAX_FRAME).contains(&packet.len()) || packet[..3] != [0, 0, 0] {
        return false;
    }
    match packet[3] {
        1 => packet.len() >= 10,
        4 => packet.len() >= 22,
        3 => packet.len() >= 5 && packet[4] > 0 && packet.len() >= 7 + packet[4] as usize,
        _ => false,
    }
}

/// Writes the length prefix and frame together, so a TLS stream sends one record.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME {
        bail!("invalid UDP frame length");
    }
    let mut wire = [0; 2 + MAX_FRAME];
    wire[..2].copy_from_slice(&(frame.len() as u16).to_be_bytes());
    wire[2..2 + frame.len()].copy_from_slice(frame);
    writer.write_all(&wire[..2 + frame.len()]).await?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    FrameReader::default().read(reader).await
}

// A select branch can be cancelled whenever a UDP socket becomes readable.
// Keep partially received TLS frames across those cancellations.
pub(crate) struct FrameReader {
    buffer: Box<[u8]>,
    start: usize,
    end: usize,
}
impl Default for FrameReader {
    fn default() -> Self {
        Self {
            buffer: vec![0; FRAME_READ_BUFFER].into(),
            start: 0,
            end: 0,
        }
    }
}
impl FrameReader {
    pub(crate) async fn read<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        self.next(reader).await.map(<[u8]>::to_vec)
    }

    /// The next frame, borrowed until the following call.
    pub(crate) async fn next<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<&[u8]> {
        loop {
            let pending = &self.buffer[self.start..self.end];
            if pending.len() >= 2 {
                let length = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                if length == 0 || length > MAX_FRAME {
                    bail!("invalid UDP frame length");
                }
                if pending.len() >= 2 + length {
                    let frame = self.start + 2..self.start + 2 + length;
                    self.start = frame.end;
                    return Ok(&self.buffer[frame]);
                }
            }
            if self.start == self.end {
                (self.start, self.end) = (0, 0);
            } else if self.buffer.len() - self.end < 2 + MAX_FRAME {
                self.buffer.copy_within(self.start..self.end, 0);
                (self.start, self.end) = (0, self.end - self.start);
            }
            let length = reader.read(&mut self.buffer[self.end..]).await?;
            if length == 0 {
                bail!("UDP tunnel closed during frame read");
            }
            self.end += length;
        }
    }
}

/// Borrowed view of a SOCKS UDP packet: destination, port and payload.
pub(crate) fn parse_socks_udp(packet: &[u8]) -> Result<(Address<'_>, u16, &[u8])> {
    if !valid_socks_udp_packet(packet) {
        bail!("invalid SOCKS UDP packet");
    }
    let (address, port, length) = parse_address(&packet[3..])?;
    Ok((address, port, &packet[3 + length..]))
}

#[cfg(test)]
pub(crate) fn parse_socks_udp_packet(packet: &[u8]) -> Result<(String, u16, Vec<u8>)> {
    let (address, port, payload) = parse_socks_udp(packet)?;
    Ok((address.to_string(), port, payload.to_vec()))
}

/// Encodes a reply from `source` and writes it as one frame; oversized replies are dropped.
pub(crate) async fn forward_udp_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    source: SocketAddr,
    payload: &[u8],
) -> Result<bool> {
    let (header, header_length) = socks_udp_header(source);
    let length = header_length + payload.len();
    if length > MAX_FRAME {
        return Ok(false);
    }
    let mut wire = [0; 2 + MAX_FRAME];
    wire[..2].copy_from_slice(&(length as u16).to_be_bytes());
    wire[2..2 + header_length].copy_from_slice(&header[..header_length]);
    wire[2 + header_length..2 + length].copy_from_slice(payload);
    writer.write_all(&wire[..2 + length]).await?;
    Ok(true)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn encode_socks_udp_packet(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let (header, header_length) = socks_udp_header(source);
    let mut packet = Vec::with_capacity(header_length + payload.len());
    packet.extend_from_slice(&header[..header_length]);
    packet.extend_from_slice(payload);
    packet
}

fn socks_udp_header(source: SocketAddr) -> ([u8; 22], usize) {
    let mut header = [0; 22];
    let address_end = match source.ip() {
        IpAddr::V4(ip) => {
            header[3] = 1;
            header[4..8].copy_from_slice(&ip.octets());
            8
        }
        IpAddr::V6(ip) => {
            header[3] = 4;
            header[4..20].copy_from_slice(&ip.octets());
            20
        }
    };
    header[address_end..address_end + 2].copy_from_slice(&source.port().to_be_bytes());
    (header, address_end + 2)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    /// Records every `poll_write` call so tests can count TLS records.
    #[derive(Default)]
    pub(crate) struct Writes(pub(crate) Vec<Vec<u8>>);
    impl AsyncWrite for Writes {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.push(bytes.to_vec());
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn socks_udp_domain_packet_parses_to_host_port_and_payload() {
        let packet = [
            0, 0, 0, 3, 11, b'd', b'i', b's', b'c', b'o', b'r', b'd', b'.', b'c', b'o', b'm', 0x01,
            0xbb, 0x61, 0x62,
        ];
        let (host, port, payload) = parse_socks_udp_packet(&packet).unwrap();
        assert_eq!(host, "discord.com");
        assert_eq!(port, 443);
        assert_eq!(payload, b"ab");
        let (address, port, payload) = parse_socks_udp(&packet).unwrap();
        assert!(matches!(address, Address::Domain("discord.com")));
        assert_eq!((port, payload), (443, &b"ab"[..]));
    }

    #[test]
    fn socks_udp_ip_packets_parse_without_text_round_trips() {
        let packet = encode_socks_udp_packet("104.29.151.152:19317".parse().unwrap(), &[7, 8]);
        let (address, port, payload) = parse_socks_udp(&packet).unwrap();
        assert_eq!(address, Address::Ip([104, 29, 151, 152].into()));
        assert_eq!((port, payload), (19317, &[7, 8][..]));
        let source: SocketAddr = "[2606:4700:4700::1111]:5000".parse().unwrap();
        let packet = encode_socks_udp_packet(source, &[9]);
        let (address, port, payload) = parse_socks_udp(&packet).unwrap();
        assert!(matches!(address, Address::Ip(ip) if ip == source.ip()));
        assert_eq!((port, payload), (5000, &[9][..]));
    }

    #[test]
    fn socks_udp_parser_rejects_fragments_and_truncated_domain_packets() {
        let fragmented = [0, 0, 1, 1, 1, 2, 3, 4, 0, 53, 1];
        assert!(parse_socks_udp_packet(&fragmented).is_err());

        let truncated = [0, 0, 0, 3, 8, b'd', b'i', b's', b's', b'c', b'o', b'r'];
        assert!(parse_socks_udp_packet(&truncated).is_err());
    }

    #[test]
    fn udp_parser_rejects_every_truncated_address_without_panicking() {
        for (kind, length) in [(1, 10), (4, 22)] {
            for size in 4..length {
                let mut packet = vec![0; size];
                packet[3] = kind;
                assert!(parse_socks_udp_packet(&packet).is_err());
            }
        }
    }

    #[tokio::test]
    async fn oversized_udp_reply_is_dropped_and_next_reply_survives() {
        let (mut sender, mut receiver) = tokio::io::duplex(4096);
        for source in ["1.1.1.1:5000", "[2606:4700:4700::1111]:5000"] {
            let source = source.parse().unwrap();
            assert!(!forward_udp_response(&mut sender, source, &[1; 1491])
                .await
                .unwrap());
            assert!(forward_udp_response(&mut sender, source, &[42])
                .await
                .unwrap());
            let frame = read_frame(&mut receiver).await.unwrap();
            assert_eq!(parse_socks_udp_packet(&frame).unwrap().2, [42]);
        }
    }

    #[test]
    fn udp_response_encoding_uses_socks_ipv4_header() {
        let packet = encode_socks_udp_packet("8.8.8.8:53".parse().unwrap(), &[0xaa, 0xbb]);
        assert_eq!(packet, [0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 0xaa, 0xbb]);
    }

    #[tokio::test]
    async fn each_frame_is_a_single_write() {
        let mut writes = Writes::default();
        write_frame(&mut writes, &[0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42])
            .await
            .unwrap();
        forward_udp_response(&mut writes, "8.8.8.8:53".parse().unwrap(), &[0xaa])
            .await
            .unwrap();
        assert_eq!(
            writes.0,
            [
                vec![0, 11, 0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42],
                vec![0, 11, 0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 0xaa],
            ]
        );
    }

    #[tokio::test]
    async fn udp_frames_preserve_packet_boundaries() {
        let (mut sender, mut receiver) = tokio::io::duplex(64);
        write_frame(&mut sender, &[0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42])
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut receiver).await.unwrap(),
            [0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 42]
        );
    }

    #[tokio::test]
    async fn many_frames_per_read_and_frames_across_buffer_ends_survive() {
        let (mut sender, mut receiver) = tokio::io::duplex(256 * 1024);
        let frames: Vec<Vec<u8>> = (0..200u32)
            .map(|i| vec![i as u8; 1 + (i as usize * 37) % MAX_FRAME])
            .collect();
        for frame in &frames {
            write_frame(&mut sender, frame).await.unwrap();
        }
        let mut reader = FrameReader::default();
        for frame in &frames {
            assert_eq!(reader.next(&mut receiver).await.unwrap(), &frame[..]);
        }
    }

    #[tokio::test]
    async fn udp_frame_read_survives_interleaved_datagrams() {
        for split in 1..6 {
            let (mut sender, mut receiver) = tokio::io::duplex(64);
            let wire = [0, 4, 1, 2, 3, 4];
            let mut frames = FrameReader::default();
            sender.write_all(&wire[..split]).await.unwrap();
            // Simulate the UDP socket winning select after a partial TLS read.
            tokio::select! {
                biased;
                result = frames.next(&mut receiver) => panic!("incomplete frame returned: {result:?}"),
                _ = std::future::ready(()) => {}
            }
            sender.write_all(&wire[split..]).await.unwrap();
            write_frame(&mut sender, &[5, 6]).await.unwrap();
            assert_eq!(frames.next(&mut receiver).await.unwrap(), [1, 2, 3, 4]);
            assert_eq!(frames.read(&mut receiver).await.unwrap(), [5, 6]);
        }
    }

    #[tokio::test]
    async fn invalid_frame_lengths_are_rejected() {
        for wire in [[0, 0, 1], [0x05, 0xdd, 1]] {
            let (mut sender, mut receiver) = tokio::io::duplex(64);
            sender.write_all(&wire).await.unwrap();
            assert!(FrameReader::default().next(&mut receiver).await.is_err());
        }
    }
}

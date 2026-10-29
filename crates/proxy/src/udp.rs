//! SOCKS5 UDP packet codec and length-prefixed tunnel framing.
use crate::Result;
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) fn valid_socks_udp_packet(packet: &[u8]) -> bool {
    if !(4..=1500).contains(&packet.len()) || packet[..3] != [0, 0, 0] {
        return false;
    }
    match packet[3] {
        1 => packet.len() >= 10,
        4 => packet.len() >= 22,
        3 => packet.len() >= 5 && packet[4] > 0 && packet.len() >= 7 + packet[4] as usize,
        _ => false,
    }
}

pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > 1500 {
        bail!("invalid UDP frame length");
    }
    writer.write_u16(frame.len() as u16).await?;
    writer.write_all(frame).await?;
    Ok(())
}

#[cfg(test)]
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    FrameReader::default().read(reader).await
}

// A select branch can be cancelled whenever a UDP socket becomes readable.
// Keep partially received TLS frames across those cancellations.
#[derive(Default)]
pub(crate) struct FrameReader {
    pending: Vec<u8>,
}
impl FrameReader {
    pub(crate) async fn read<R: AsyncRead + Unpin>(&mut self, reader: &mut R) -> Result<Vec<u8>> {
        loop {
            if self.pending.len() >= 2 {
                let length = u16::from_be_bytes([self.pending[0], self.pending[1]]) as usize;
                if length == 0 || length > 1500 {
                    bail!("invalid UDP frame length");
                }
                if self.pending.len() >= length + 2 {
                    let frame = self.pending[2..length + 2].to_vec();
                    self.pending.drain(..length + 2);
                    return Ok(frame);
                }
            }
            let mut buffer = [0u8; 1502];
            let capacity = buffer.len() - self.pending.len();
            let length = reader.read(&mut buffer[..capacity]).await?;
            if length == 0 {
                bail!("UDP tunnel closed during frame read");
            }
            self.pending.extend_from_slice(&buffer[..length]);
        }
    }
}

pub(crate) fn parse_socks_udp_packet(packet: &[u8]) -> Result<(String, u16, Vec<u8>)> {
    if !valid_socks_udp_packet(packet) {
        bail!("invalid SOCKS UDP packet");
    }
    let (host, offset) = match packet[3] {
        1 => (
            IpAddr::from(<[u8; 4]>::try_from(&packet[4..8])?).to_string(),
            8,
        ),
        4 => (
            IpAddr::from(<[u8; 16]>::try_from(&packet[4..20])?).to_string(),
            20,
        ),
        3 => {
            if packet.len() < 5 {
                bail!("invalid SOCKS UDP domain length");
            }
            let n = packet[4] as usize;
            if packet.len() < 5 + n + 2 {
                bail!("truncated SOCKS UDP domain");
            }
            (std::str::from_utf8(&packet[5..5 + n])?.to_owned(), 5 + n)
        }
        _ => bail!("invalid SOCKS UDP address type"),
    };
    if packet.len() < offset + 2 {
        bail!("truncated SOCKS UDP port");
    }
    let port = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    Ok((host, port, packet[offset + 2..].to_vec()))
}

pub(crate) async fn forward_udp_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    source: SocketAddr,
    payload: &[u8],
) -> Result<bool> {
    let response = encode_socks_udp_packet(source, payload);
    if response.len() > 1500 {
        return Ok(false);
    }
    write_frame(writer, &response).await?;
    Ok(true)
}

pub(crate) fn encode_socks_udp_packet(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match source.ip() {
        IpAddr::V4(ip) => {
            packet.push(1);
            packet.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(4);
            packet.extend_from_slice(&ip.octets());
        }
    }
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn udp_frame_read_survives_interleaved_datagrams() {
        for split in 1..6 {
            let (mut sender, mut receiver) = tokio::io::duplex(64);
            let wire = [0, 4, 1, 2, 3, 4];
            let mut frames = FrameReader::default();
            sender.write_all(&wire[..split]).await.unwrap();
            // Simulate the UDP socket winning select after a partial TLS read.
            tokio::select! {
                biased;
                result = frames.read(&mut receiver) => panic!("incomplete frame returned: {result:?}"),
                _ = std::future::ready(()) => {}
            }
            sender.write_all(&wire[split..]).await.unwrap();
            write_frame(&mut sender, &[5, 6]).await.unwrap();
            assert_eq!(frames.read(&mut receiver).await.unwrap(), [1, 2, 3, 4]);
            assert_eq!(frames.read(&mut receiver).await.unwrap(), [5, 6]);
        }
    }
}

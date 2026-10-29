//! SOCKS5 request and reply parsing and encoding.
use crate::Result;
use std::{fmt, net::IpAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A SOCKS destination, borrowed from the message it was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Address<'a> {
    Ip(IpAddr),
    Domain(&'a str),
}
impl fmt::Display for Address<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Domain(name) => f.write_str(name),
        }
    }
}

/// Parses `ATYP | address | port`; returns the address, port and bytes consumed.
pub(crate) fn parse_address(bytes: &[u8]) -> Result<(Address<'_>, u16, usize)> {
    let (address, end) = match bytes.first() {
        Some(1) if bytes.len() >= 7 => (Address::Ip(<[u8; 4]>::try_from(&bytes[1..5])?.into()), 5),
        Some(4) if bytes.len() >= 19 => {
            (Address::Ip(<[u8; 16]>::try_from(&bytes[1..17])?.into()), 17)
        }
        Some(3) if bytes.len() >= 2 && bytes.len() >= 4 + bytes[1] as usize => {
            let end = 2 + bytes[1] as usize;
            (Address::Domain(std::str::from_utf8(&bytes[2..end])?), end)
        }
        Some(1 | 3 | 4) => bail!("truncated SOCKS address"),
        _ => bail!("invalid SOCKS address type"),
    };
    Ok((
        address,
        u16::from_be_bytes([bytes[end], bytes[end + 1]]),
        end + 2,
    ))
}

/// Reads the address and port after a 4-byte header that ends in ATYP.
async fn read_with_address<S: AsyncRead + Unpin>(
    stream: &mut S,
    header: [u8; 4],
) -> Result<Vec<u8>> {
    let mut bytes = header.to_vec();
    let length = match header[3] {
        1 => 6,
        4 => 18,
        3 => {
            let length = stream.read_u8().await?;
            bytes.push(length);
            length as usize + 2
        }
        _ => bail!("invalid SOCKS address type"),
    };
    let start = bytes.len();
    bytes.resize(start + length, 0);
    stream.read_exact(&mut bytes[start..]).await?;
    Ok(bytes)
}

pub(crate) async fn read_socks_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        bail!("invalid SOCKS request header");
    }
    read_with_address(stream, header).await
}

pub(crate) async fn read_socks_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    read_with_address(stream, header).await
}

pub(crate) fn socks_request_target(request: &[u8]) -> Result<(String, u16)> {
    let (address, port, _) = parse_address(request.get(3..).unwrap_or_default())?;
    Ok((address.to_string(), port))
}

pub(crate) async fn reply_bound<S: AsyncWrite + Unpin>(stream: &mut S, port: u16) -> Result<()> {
    let [high, low] = port.to_be_bytes();
    stream
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, high, low])
        .await?;
    Ok(())
}

pub(crate) async fn reply<S: AsyncWrite + Unpin>(s: &mut S, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::tests::Writes;

    #[tokio::test]
    async fn requests_and_replies_share_one_address_reader() {
        let mut domain = vec![5, 1, 0, 3, 11];
        domain.extend_from_slice(b"discord.com");
        domain.extend_from_slice(&443u16.to_be_bytes());
        let ipv4 = vec![5, 0, 0, 1, 104, 29, 151, 152, 0x4b, 0x75];
        let mut ipv6 = vec![5, 0, 0, 4];
        ipv6.extend_from_slice(
            &"2606:4700::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        ipv6.extend_from_slice(&8443u16.to_be_bytes());
        for (message, target) in [
            (&domain, ("discord.com", 443)),
            (&ipv4, ("104.29.151.152", 19317)),
            (&ipv6, ("2606:4700::1", 8443)),
        ] {
            let mut trailing = message.clone();
            trailing.push(0xee);
            assert_eq!(
                &read_socks_reply(&mut &trailing[..]).await.unwrap(),
                message
            );
            assert_eq!(
                &read_socks_request(&mut &trailing[..]).await.unwrap(),
                message
            );
            assert_eq!(
                socks_request_target(message).unwrap(),
                (target.0.to_owned(), target.1)
            );
        }
        assert!(read_socks_request(&mut &[4, 1, 0, 1][..]).await.is_err());
        assert!(read_socks_reply(&mut &[5, 0, 0, 2, 0, 0][..])
            .await
            .is_err());
        assert!(read_socks_reply(&mut &ipv4[..9]).await.is_err());
    }

    #[test]
    fn truncated_targets_are_errors_not_panics() {
        let mut domain = vec![5, 1, 0, 3, 11];
        domain.extend_from_slice(b"discord.com");
        domain.extend_from_slice(&443u16.to_be_bytes());
        for message in [
            &domain[..],
            &[5, 0, 0, 1, 1, 2, 3, 4, 0, 53][..],
            &[5, 0, 0, 4][..],
        ] {
            for length in 0..message.len() {
                assert!(socks_request_target(&message[..length]).is_err());
            }
        }
        assert!(parse_address(&[3, 1, 0xff, 0, 1]).is_err());
        assert!(parse_address(&[9, 0, 0]).is_err());
        assert_eq!(
            parse_address(&[3, 0, 0, 80, 1]).unwrap(),
            (Address::Domain(""), 80, 4)
        );
    }

    #[tokio::test]
    async fn replies_are_single_writes() {
        let mut writes = Writes::default();
        reply(&mut writes, 2).await.unwrap();
        reply_bound(&mut writes, 0x1234).await.unwrap();
        assert_eq!(
            writes.0,
            [
                vec![5, 2, 0, 1, 0, 0, 0, 0, 0, 0],
                vec![5, 0, 0, 1, 0, 0, 0, 0, 0x12, 0x34]
            ]
        );
    }
}

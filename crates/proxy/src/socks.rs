//! SOCKS5 request and reply parsing and encoding.
use crate::Result;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) async fn read_socks_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 5 || request[2] != 0 {
        bail!("invalid SOCKS request header");
    }
    let mut bytes = request.to_vec();
    match request[3] {
        1 => {
            let mut address = [0; 6];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        4 => {
            let mut address = [0; 18];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut address = vec![0; len + 2];
            stream.read_exact(&mut address).await?;
            bytes.push(len as u8);
            bytes.extend_from_slice(&address);
        }
        _ => bail!("invalid SOCKS address type"),
    }
    Ok(bytes)
}

pub(crate) async fn read_socks_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    let mut bytes = reply.to_vec();
    match reply[3] {
        1 => {
            let mut address = [0; 6];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        4 => {
            let mut address = [0; 18];
            stream.read_exact(&mut address).await?;
            bytes.extend_from_slice(&address);
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut address = vec![0; len + 2];
            stream.read_exact(&mut address).await?;
            bytes.push(len as u8);
            bytes.extend_from_slice(&address);
        }
        _ => bail!("invalid SOCKS reply address type"),
    }
    Ok(bytes)
}

pub(crate) fn socks_request_target(request: &[u8]) -> Result<(String, u16)> {
    let mut offset = 4;
    let host = match request[3] {
        1 => {
            let ip = IpAddr::from(<[u8; 4]>::try_from(&request[offset..offset + 4])?);
            offset += 4;
            ip.to_string()
        }
        4 => {
            let ip = IpAddr::from(<[u8; 16]>::try_from(&request[offset..offset + 16])?);
            offset += 16;
            ip.to_string()
        }
        3 => {
            let length = request[offset] as usize;
            offset += 1;
            let host = std::str::from_utf8(&request[offset..offset + length])?.to_owned();
            offset += length;
            host
        }
        _ => bail!("invalid SOCKS address type"),
    };
    let port = u16::from_be_bytes([request[offset], request[offset + 1]]);
    Ok((host, port))
}

pub(crate) async fn reply_bound<S: AsyncWrite + Unpin>(stream: &mut S, port: u16) -> Result<()> {
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0]).await?;
    stream.write_u16(port).await?;
    Ok(())
}

pub(crate) async fn reply<S: AsyncWrite + Unpin>(s: &mut S, code: u8) -> Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

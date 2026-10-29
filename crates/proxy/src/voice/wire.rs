//! Bounded records inside the authenticated client-to-gateway TLS tunnel.
use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
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
pub const GRANT_TTL: std::time::Duration = std::time::Duration::from_secs(120);

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

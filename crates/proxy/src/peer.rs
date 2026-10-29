// TEMP shim: the peer stream replaces this with the real voice peer check.
use std::net::SocketAddr;

pub async fn verify_voice_peer(_peer: SocketAddr, _local: SocketAddr) -> bool {
    true
}

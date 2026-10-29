pub mod gateway;
pub mod identity;
pub mod local;
pub mod wire;

pub const SOCKS_VOICE_COMMAND: u8 = 0xf0;

pub fn allowed_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.ends_with(".discord.media") && !host[..host.len() - ".discord.media".len()].is_empty()
}

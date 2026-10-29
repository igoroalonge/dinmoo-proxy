//! Destination policy: public IP checks, Discord host allowlist and media grants.
use crate::Result;
use std::net::{IpAddr, SocketAddr};

pub(crate) fn parse_media_targets(value: &str) -> Result<Vec<SocketAddr>> {
    let mut targets = Vec::new();
    for item in value.split(',').filter(|item| !item.trim().is_empty()) {
        let target: SocketAddr = item.trim().parse()?;
        if !is_public_ip(target.ip()) || target.port() == 0 {
            bail!("media targets must be public IP addresses with a nonzero port");
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
        if targets.len() > 128 {
            bail!("at most 128 explicit media targets are allowed");
        }
    }
    Ok(targets)
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !(a == 0
                    || (a == 100 && (64..=127).contains(&b))
                    || (a == 192
                        && ((b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99) || b == 168))
                    || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                    || (a == 203 && b == 0 && c == 113)
                    || a >= 224)
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            let segments = ip.segments();
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && segments[0] & 0xe000 == 0x2000
                // Exclude special-use ranges within global-unicast space (IANA IPv6 registry).
                && !(segments[0] == 0x2001
                    && (segments[1] <= 0x01ff
                        || segments[1] == 0x0db8
                        || segments[1] & 0xfff0 == 0x0010
                        || segments[1] & 0xfff0 == 0x0020
                        || segments[1] & 0xfff0 == 0x0030))
                && segments[0] != 0x2002
                && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
        }
    }
}

/// `host` is `domain` or one of its subdomains, ignoring ASCII case and trailing dots.
fn within(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').as_bytes();
    let Some(split) = host.len().checked_sub(domain.len()) else {
        return false;
    };
    host[split..].eq_ignore_ascii_case(domain.as_bytes()) && (split == 0 || host[split - 1] == b'.')
}

fn subdomain(host: &str, domain: &str) -> bool {
    within(host, domain) && host.trim_end_matches('.').len() > domain.len()
}

pub(crate) fn allowed_destination(host: &str) -> bool {
    within(host, "discord.com")
        || within(host, "discordapp.com")
        || within(host, "discord.media")
        || within(host, "discord.gg")
        || within(host, "discordcdn.com")
        || subdomain(host, "discordapp.net")
}

pub(crate) fn allowed_tcp_destination(host: &str, port: u16) -> bool {
    allowed_destination(host)
        && (port == 443
            || (subdomain(host, "discord.media")
                && matches!(port, 2053 | 2083 | 2087 | 2096 | 8443)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_policy_accepts_discord_hosts_and_rejects_suffix_spoofing() {
        assert!(allowed_destination("discord.com"));
        assert!(allowed_destination("API.DISCORD.COM."));
        assert!(allowed_destination("voice.discord.media"));
        assert!(allowed_destination("cdn.discordapp.net"));
        assert!(!allowed_destination("discord.com.attacker.example"));
        assert!(!allowed_destination("notdiscord.com"));
        assert!(!allowed_destination("discordapp.net.attacker.example"));
        assert!(!allowed_destination("discordapp.net"));
        assert!(!allowed_destination("xdiscord.gg"));
        assert!(!allowed_destination("."));
        assert!(!allowed_destination("é.discord.co"));
        assert!(allowed_destination("é.discord.gg"));
    }

    #[test]
    fn tcp_policy_restricts_ports_by_service() {
        assert!(allowed_tcp_destination("discord.com", 443));
        assert!(allowed_tcp_destination(
            "c-lhr01.example.discord.media",
            2053
        ));
        assert!(allowed_tcp_destination(
            "c-lhr01.example.discord.media",
            2083
        ));
        assert!(allowed_tcp_destination("discord.media", 443));
        assert!(!allowed_tcp_destination("discord.media", 2053));
        assert!(!allowed_tcp_destination("DISCORD.MEDIA.", 8443));
        assert!(!allowed_tcp_destination("discord.com", 22));
        assert!(!allowed_tcp_destination("discord.com", 2053));
        assert!(!allowed_tcp_destination(
            "discord.media.attacker.example",
            443
        ));
        assert!(!allowed_tcp_destination("104.29.151.152", 443));
    }

    #[test]
    fn destination_policy_rejects_private_and_special_use_addresses() {
        for address in [
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.0.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
        ] {
            let ip = address.parse().expect("literal IP address");
            assert!(!is_public_ip(ip), "{address} must not be public");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn media_grants_reject_private_targets_and_zero_ports() {
        assert!(parse_media_targets("127.0.0.1:19332").is_err());
        assert!(parse_media_targets("104.29.143.52:0").is_err());
        let grants = parse_media_targets("104.29.143.52:19332,104.29.143.52:19332").unwrap();
        assert_eq!(grants.len(), 1);
        assert!(!grants.contains(&"104.29.143.52:443".parse().unwrap()));
    }
}

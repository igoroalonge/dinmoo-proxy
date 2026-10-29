#!/bin/sh
# Manual acceptance probe for the gateway's SNI gate. Run it by hand from a
# workstation, never in CI: it contacts Discord's Cloudflare edge directly.
#
# The gateway relays a CONNECT once the ClientHello's cleartext server name is a
# Discord host. This asks Discord's edge, under the TLS name discord.com, for a
# page of another Cloudflare-hosted site named only in the HTTP Host header. If
# the edge serves it, the SNI gate alone does not keep the relay on Discord.
# Encrypted Client Hello needs a client that sets its own outer name, which curl
# cannot, so this covers only the Host header.
#
# Usage: scripts/probe-cloudflare-fronting.sh [other-cloudflare-host] [path]
set -eu
other=${1:-www.cloudflare.com}
path=${2:-/robots.txt}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
curl -fsS --max-time 15 -o "$work/direct" "https://$other$path"
status=$(curl -sS --max-time 15 -o "$work/fronted" -w '%{http_code}' \
    -H "Host: $other" "https://discord.com$path")
if [ -s "$work/direct" ] && cmp -s "$work/direct" "$work/fronted"; then
    echo "FRONTED: discord.com served $other$path (HTTP $status); the SNI gate does not confine the relay"
    exit 1
fi
echo "not fronted: discord.com answered HTTP $status with other content for Host: $other"

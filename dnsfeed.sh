#!/bin/bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEED="$DIR/dns-feed.log"
: > "$FEED"
stdbuf -oL tcpdump -i wlan0 -nn -l udp port 53 2>/dev/null | while read -r line; do
  case "$line" in *" A? "*|*" AAAA? "*) ;; *) continue ;; esac
  dom=$(echo "$line" | grep -oE ' A+\? [^ ]+' | head -1 | awk '{print $2}' | sed 's/\.$//')
  src=$(echo "$line" | awk '{print $3}' | sed 's/\.[0-9]*$//')
  [ -z "$dom" ] && continue
  echo "$(date +%H:%M:%S) $src -> $dom" >> "$FEED"
  tail -n 200 "$FEED" > "$FEED.tmp" 2>/dev/null && mv "$FEED.tmp" "$FEED" 2>/dev/null
done

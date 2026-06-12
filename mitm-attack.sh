#!/bin/bash
DIR="${DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "$DIR/.env" ] && . "$DIR/.env"
AP_IF="${AP_IF:-wlan0}"
MON_IF="${MON_IF:-wlan1}"
# Pineapple Express - Rogue AP monitor.
# El Pi YA es el AP ($AP_IF). Da internet a los clientes (NAT $AP_IF -> eth0) y esnifa
# su DNS / TLS-SNI / QUIC-SNI. El Pi es el gateway, asi que ve TODO sin asociarse a
# nada ni hacer ARP spoof. NO usa $MON_IF (Kismet sigue corriendo).
# USE ONLY on your own AP / authorized clients.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FEED="$DIR/mitm-feed.log"
STATE="$DIR/mitm-attack.state"
AP_IF=$AP_IF
UP_IF=eth0
AP_NET=192.168.66.0/24

ts(){ date +%H:%M:%S; }
log(){ echo "[$(ts)] $*" >> "$FEED"; tail -200 "$FEED" > "$FEED.tmp" && mv "$FEED.tmp" "$FEED"; }

cleanup(){
  pkill -f "tshark.*$AP_IF" 2>/dev/null
  echo "stopped" > "$STATE"
  # Se deja el NAT puesto a proposito: el AP debe seguir con internet aunque pares el monitor.
}
trap cleanup EXIT

echo "starting" > "$STATE"
: > "$FEED"

# 1) Asegurar internet para los clientes del AP (idempotente).
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -C POSTROUTING -s $AP_NET -o $UP_IF -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s $AP_NET -o $UP_IF -j MASQUERADE
iptables -C FORWARD -i $AP_IF -o $UP_IF -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD -i $AP_IF -o $UP_IF -j ACCEPT
iptables -C FORWARD -i $UP_IF -o $AP_IF -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
  || iptables -I FORWARD -i $UP_IF -o $AP_IF -m state --state RELATED,ESTABLISHED -j ACCEPT

NCLI=$(iw dev $AP_IF station dump 2>/dev/null | grep -c Station)
log "Rogue AP activo: $AP_IF -> NAT por $UP_IF | $NCLI cliente(s) asociado(s)."
[ "$NCLI" = 0 ] && log "(esperando clientes... conecta un dispositivo a la red y navega)"
log "Esnifando DNS / TLS-SNI / QUIC-SNI de los clientes..."
echo "running" > "$STATE"

# 2) Sniff en $AP_IF. El Pi es el gateway -> ve el trafico en claro de los clientes.
#    Una linea por paquete; solo uno de los 3 campos de nombre viene relleno.
tshark -i "$AP_IF" -l -Q \
  -Y "dns.flags.response==0 || tls.handshake.type==1 || quic.tls.handshake.extensions_server_name" \
  -T fields -e ip.src \
  -e dns.qry.name \
  -e tls.handshake.extensions_server_name \
  -e quic.tls.handshake.extensions_server_name \
  2>/dev/null | while IFS= read -r line; do
    src=${line%%$'\t'*}
    rest=${line#*$'\t'}                       # dns \t tls \t quic
    name=$(printf '%s' "$rest" | tr '\t' '\n' | grep -m1 .)
    [ -z "$name" ] && continue
    echo "[$(ts)]  $src -> $name" >> "$FEED"
    tail -200 "$FEED" > "$FEED.tmp" && mv "$FEED.tmp" "$FEED"
done

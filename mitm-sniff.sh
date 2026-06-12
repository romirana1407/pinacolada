#!/bin/bash
# Esnifa a que destinos habla el target (el device MITM) y lo escribe al feed.
# Muestra DNS en claro (puerto 53) SI lo hay + las IPs destino con reverse-DNS de los
# SYN salientes -> funciona aunque el target use DNS cifrado (DoT/DoH), que es lo
# normal en moviles modernos. tcpdump NO cambia el modo de wlan1 (tshark si lo flipa).
# Uso: mitm-sniff.sh <target_ip> <feed_file>
T="$1"; FEED="$2"; IF=wlan1
[ -z "$T" ] && exit 1
declare -A SEEN
emit(){ echo "[$(date +%H:%M:%S)] $1" >> "$FEED"; tail -200 "$FEED" > "$FEED.tmp" 2>/dev/null && mv "$FEED.tmp" "$FEED"; }

# SYN salientes del target (nueva conexion) + DNS en claro
tcpdump -i "$IF" -l -n "host $T and (udp port 53 or (tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0))" 2>/dev/null \
| while read -r ln; do
  # 1) DNS en claro: "... A? dominio. ..."
  dom=$(printf '%s' "$ln" | grep -oiE '\b(A|AAAA)\? [A-Za-z0-9._-]+' | head -1 | awk '{print $2}' | sed 's/\.$//')
  if [ -n "$dom" ]; then emit "$T  DNS  $dom"; continue; fi

  # 2) SYN saliente: tomar el campo destino tras ">" -> "A.B.C.D.PORT:"
  dstfield=$(printf '%s' "$ln" | awk '{for(i=1;i<=NF;i++) if($i==">"){print $(i+1); exit}}')
  dstfield=${dstfield%:}
  [ -z "$dstfield" ] && continue
  port=${dstfield##*.}
  dst=${dstfield%.*}
  # solo SYN salientes (origen = target); ignorar destinos privados/multicast
  echo "$ln" | grep -q " $T\." || continue
  case "$dst" in
    192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|169.254.*|224.*|239.*|255.*|127.*) continue;;
  esac
  echo "$port" | grep -qE '^[0-9]+$' || continue
  key="$dst:$port"
  [ -n "${SEEN[$key]}" ] && continue
  SEEN[$key]=1
  rev=$(timeout 2 getent hosts "$dst" 2>/dev/null | awk '{print $2}' | head -1)
  [ -z "$rev" ] && rev="$dst"
  emit "$T  ->  $rev :$port"
done

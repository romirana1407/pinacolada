import os

AP_IF   = os.environ.get("AP_IF")  or "wlan0"   # rogue-AP / gateway radio
MON_IF  = os.environ.get("MON_IF") or "wlan1"   # monitor / injection radio

BASE    = os.environ.get("PINACOLA_HOME") or os.path.dirname(os.path.abspath(__file__))
CRED    = BASE + "/captured-creds.log"
PORTAL  = BASE + "/portal-server.py"
FEED    = BASE + "/dns-feed.log"
WTRESULT= BASE + "/wifitest.result"
MITMFEED= BASE + "/mitm-feed.log"
MITMREADY  = BASE + "/mitm-ready"
MITMSTATE  = BASE + "/mitm-attack.state"
MITMATTACK = BASE + "/mitm-attack.sh"
MITMROUTER  = BASE + "/mitm-router.sh"      # motor MITM contra router externo
MITMDEVICES = BASE + "/mitm-devices.txt"    # devices descubiertos (ip|mac|vendor|host)
MITMTARGET  = BASE + "/mitm-target"         # IP del device target seleccionado
MITMINFO    = BASE + "/mitm-info"           # SSID/IP/GW/SUBNET de la sesion MITM
MITMAUDIT   = BASE + "/mitm-audit.log"      # resultado de la ultima accion de auditoria
BLESCAN = BASE + "/ble-scan.json"
BLESTATE= BASE + "/ble-scan.state"
BLEPY   = BASE + "/ble-scan.py"
BEACONSH= BASE + "/beacon-spam.sh"
PORTALS_DIR   = BASE + "/portals"
ACTIVE_TPL    = PORTALS_DIR + "/active.html"
ACTIVE_NAME_F = PORTALS_DIR + "/.active-name"
CREDS_JSON    = BASE + "/captured-creds.json"
AUTH_FILE     = BASE + "/.htpasswd"

DEF_CH  = "6"

LEASES  = "/var/lib/misc/dnsmasq.leases"
DNSCFG  = "/etc/pinacola-dnsmasq.conf"
HOSTAPD = "/etc/hostapd/pinacola.conf"
KCONF   = "/root/.kismet/kismet_httpd.conf"

DNS_PORTAL = (
    f"interface={AP_IF}\nbind-interfaces\nno-resolv\n"
    "dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\n"
    "dhcp-option=option:router,192.168.66.1\n"
    "dhcp-option=option:dns-server,192.168.66.1\n"
    "address=/#/192.168.66.1\n"
)
DNS_NORMAL = (
    f"interface={AP_IF}\nbind-interfaces\n"
    "dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\n"
    "dhcp-option=option:router,192.168.66.1\n"
    "dhcp-option=option:dns-server,1.1.1.1\nserver=1.1.1.1\n"
)
HOSTAPD_WPA = (
    f"interface={AP_IF}\ndriver=nl80211\nssid=PinaColada-Lab\nhw_mode=g\n"
    "channel=6\nauth_algs=1\nwpa=2\nwpa_passphrase=pineapple123\n"
    "wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"
)

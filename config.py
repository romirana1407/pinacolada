import os

BASE    = "/opt/pinacola"
CRED    = BASE + "/captured-creds.log"
PORTAL  = BASE + "/portal-server.py"
FEED    = BASE + "/dns-feed.log"
WTRESULT= BASE + "/wifitest.result"
MITMFEED= BASE + "/mitm-feed.log"
MITMREADY  = BASE + "/mitm-ready"
MITMSTATE  = BASE + "/mitm-attack.state"
MITMATTACK = BASE + "/mitm-attack.sh"
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
    "interface=wlan0\nbind-interfaces\nno-resolv\n"
    "dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\n"
    "dhcp-option=option:router,192.168.66.1\n"
    "dhcp-option=option:dns-server,192.168.66.1\n"
    "address=/#/192.168.66.1\n"
)
DNS_NORMAL = (
    "interface=wlan0\nbind-interfaces\n"
    "dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\n"
    "dhcp-option=option:router,192.168.66.1\n"
    "dhcp-option=option:dns-server,1.1.1.1\nserver=1.1.1.1\n"
)
HOSTAPD_WPA = (
    "interface=wlan0\ndriver=nl80211\nssid=PinaColada-Lab\nhw_mode=g\n"
    "channel=6\nauth_algs=1\nwpa=2\nwpa_passphrase=pineapple123\n"
    "wpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"
)

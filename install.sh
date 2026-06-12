#!/bin/bash
# Piña Colada installer
# Run as root: sudo bash install.sh

set -e
export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'; NC='\033[0m'
info(){ echo -e "${GRN}[+]${NC} $*"; }
warn(){ echo -e "${YEL}[!]${NC} $*"; }
die(){ echo -e "${RED}[✗]${NC} $*"; exit 1; }

echo ""
echo "  🍍  Piña Colada — WiFi Security Lab"
echo "  ======================================"
echo ""

# ── Root check ──────────────────────────────────────────────
[ "$EUID" -eq 0 ] || die "Run as root: sudo bash install.sh"

# ── Interfaces (override: AP_IF=... MON_IF=... sudo -E bash install.sh) ───────
AP_IF="${AP_IF:-wlan0}"
MON_IF="${MON_IF:-wlan1}"

info "Detected interfaces:"
ip -br link show type ether 2>/dev/null || true
iw dev 2>/dev/null | grep -E "Interface|type" || true

warn "Assuming AP interface = ${AP_IF}, monitor interface = ${MON_IF}"
warn "Edit /opt/pinacola/conf/hostapd.conf to change these after install."
echo ""

# ── Dependencies ─────────────────────────────────────────────
info "Installing system dependencies..."
apt-get update -qq
# tshark asks (debconf) whether non-root users may capture — preseed "no" to avoid a hang
echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections 2>/dev/null || true
apt-get install -y --no-install-recommends \
  aircrack-ng \
  hcxdumptool \
  hcxtools \
  hashcat \
  mdk4 \
  hostapd \
  dnsmasq \
  python3 \
  iw \
  iptables \
  tcpdump \
  tshark \
  dsniff 2>&1 | grep -E "^(Get|Setting|Unpacking|Selecting)" || true

# Kismet is optional (IDS tab) — don't fail if unavailable
apt-get install -y --no-install-recommends kismet 2>/dev/null \
  && info "Kismet installed" \
  || warn "Kismet not available — IDS tab will be limited"

# bleak for BLE (optional)
python3 -m pip install --quiet bleak 2>/dev/null \
  && info "bleak installed (rich BLE data enabled)" \
  || warn "bleak not installed — BLE fallback to hcitool lescan"

# ── Install files ─────────────────────────────────────────────
DEST=${PINACOLA_HOME:-/opt/pinacola}
info "Installing to ${DEST}..."
mkdir -p "${DEST}/portals" "${DEST}/conf"

# Copy ALL dashboard modules + scripts.
# pinacola.py imports config.py / engine.py / ui.py — they must all land in DEST,
# or the dashboard crashes with ModuleNotFoundError on first start.
shopt -s nullglob
for f in *.py *.sh; do
  cp "$f" "${DEST}/"
done
shopt -u nullglob

# Copy portal templates
[ -d portals ] && cp portals/*.html "${DEST}/portals/" 2>/dev/null || true

# Persist interface names so the dashboard + scripts pick them up at runtime.
# (config.py / the .sh scripts read AP_IF / MON_IF from here; default wlan0/wlan1)
touch "${DEST}/.env"
grep -q '^AP_IF='  "${DEST}/.env" || echo "AP_IF=${AP_IF}"   >> "${DEST}/.env"
grep -q '^MON_IF=' "${DEST}/.env" || echo "MON_IF=${MON_IF}" >> "${DEST}/.env"

# ── Rename / compat symlink ───────────────────────────────────
# wifitest.sh and beacon-spam.sh reference paths — keep them consistent
chmod +x "${DEST}"/*.sh "${DEST}"/*.py 2>/dev/null || true

# ── hostapd config ───────────────────────────────────────────
HOSTAPD_CONF="/etc/hostapd/pinacola.conf"
if [ ! -f "${HOSTAPD_CONF}" ]; then
  info "Writing hostapd config → ${HOSTAPD_CONF}"
  cat > "${HOSTAPD_CONF}" << CONF
interface=${AP_IF}
driver=nl80211
ssid=PinaColada-Lab
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=pineapple123
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
CONF
else
  warn "Keeping existing hostapd config at ${HOSTAPD_CONF}"
fi
cp "${HOSTAPD_CONF}" "${DEST}/conf/hostapd.conf" 2>/dev/null || true

# ── dnsmasq configs ───────────────────────────────────────────
info "Writing dnsmasq configs..."
cat > /etc/pinacola-dnsmasq-normal.conf << CONF
interface=${AP_IF}
bind-interfaces
dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h
dhcp-option=option:router,192.168.66.1
dhcp-option=option:dns-server,1.1.1.1
server=1.1.1.1
CONF

cat > /etc/pinacola-dnsmasq-portal.conf << CONF
interface=${AP_IF}
bind-interfaces
no-resolv
dhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h
dhcp-option=option:router,192.168.66.1
dhcp-option=option:dns-server,192.168.66.1
address=/#/192.168.66.1
CONF

# Active config starts as normal
cp /etc/pinacola-dnsmasq-normal.conf /etc/pinacola-dnsmasq.conf

# ── AP static IP (Pi → dhcpcd; laptop/Kali → NetworkManager) ─────────────────
# The AP systemd service also sets 192.168.66.1/24 in ExecStartPre, so this step
# only needs to stop the host's network manager from fighting hostapd over ${AP_IF}.
info "Configuring AP interface static IP..."
if [ -f /etc/dhcpcd.conf ]; then
  if ! grep -q "pinacola" /etc/dhcpcd.conf 2>/dev/null; then
    cat >> /etc/dhcpcd.conf << CONF

# Piña Colada AP interface
interface ${AP_IF}
static ip_address=192.168.66.1/24
nohook wpa_supplicant
CONF
  fi
elif command -v nmcli >/dev/null 2>&1; then
  warn "NetworkManager detected — telling it to stop managing ${AP_IF}"
  nmcli device set "${AP_IF}" managed no 2>/dev/null || true
else
  warn "No dhcpcd or NetworkManager found — the AP service will set the static IP itself"
fi

# ── AP systemd service ────────────────────────────────────────
info "Installing pinacola-ap.service..."
cat > /etc/systemd/system/pinacola-ap.service << UNIT
[Unit]
Description=Piña Colada Rogue AP
After=network.target

[Service]
Type=forking
ExecStartPre=/sbin/ip link set ${AP_IF} up
ExecStartPre=/sbin/ip addr add 192.168.66.1/24 dev ${AP_IF} || true
ExecStart=/usr/sbin/hostapd -B ${HOSTAPD_CONF}
ExecStartPost=/usr/sbin/dnsmasq --conf-file=/etc/pinacola-dnsmasq.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

# ── Dashboard systemd service ─────────────────────────────────
info "Installing pinacola.service..."
cat > /etc/systemd/system/pinacola.service << UNIT
[Unit]
Description=Piña Colada Dashboard
After=network.target

[Service]
EnvironmentFile=-${DEST}/.env
ExecStart=/usr/bin/python3 ${DEST}/pinacola.py
WorkingDirectory=${DEST}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

# ── Enable and start ──────────────────────────────────────────
systemctl daemon-reload
systemctl enable pinacola

info "Starting dashboard..."
systemctl restart pinacola

# ── Get Pi IP ─────────────────────────────────────────────────
IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet )[^/]+' | head -1)
[ -z "$IP" ] && IP=$(ip -4 addr show ${AP_IF} 2>/dev/null | grep -oP '(?<=inet )[^/]+' | head -1)
[ -z "$IP" ] && IP=$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oP '(?<=src )[^ ]+' | head -1)
[ -z "$IP" ] && IP="<host-ip>"

echo ""
echo -e "${GRN}  ✓ Piña Colada installed successfully!${NC}"
echo ""
echo "  Dashboard → http://${IP}:8080"
echo ""
echo "  Quick start:"
echo "    sudo systemctl start pinacola-ap   # start the rogue AP"
echo "    sudo systemctl stop  pinacola-ap   # stop it"
echo ""
echo "  Logs:"
echo "    journalctl -u pinacola -f"
echo ""
warn "Edit /etc/hostapd/pinacola.conf to change the AP SSID / password."
warn "Only use on networks you own or have written authorization to test."
echo ""

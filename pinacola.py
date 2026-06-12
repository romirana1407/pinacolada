"""Piña Colada — entry point and HTTP handler."""
import http.server, hashlib, secrets, os, json, re, shlex, urllib.parse
from config import *
from engine import (
    sh, ap_start, portal_on, portal_off, set_eviltwin, set_normal_ap,
    deauth, recon_scan, ble_scan_start, beacon_spam_active,
    save_portal_html, delete_portal_file, activate_portal_file,
    read_portal_html, api_live, crack_gpu,
    mitm_router_start, mitm_router_stop, mitm_set_target, mitm_audit,
)
from ui import render, MANIFEST

# ── Auth ─────────────────────────────────────────────────────────────────────

def _init_auth():
    """Generate a random password on first run and print it once."""
    if not os.path.exists(AUTH_FILE):
        pwd = secrets.token_urlsafe(12)
        h = hashlib.sha256(pwd.encode()).hexdigest()
        with open(AUTH_FILE, "w") as f:
            f.write(h)
        os.chmod(AUTH_FILE, 0o600)
        print(f"\n  🍍  First run — dashboard password: {pwd}")
        print(f"      (stored at {AUTH_FILE})\n")

def _check_auth(headers) -> bool:
    auth = headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return False
    try:
        import base64
        raw = base64.b64decode(auth[6:]).decode("utf-8", "replace")
        _, pwd = raw.split(":", 1)
        stored = open(AUTH_FILE).read().strip()
        return hashlib.sha256(pwd.encode()).hexdigest() == stored
    except Exception:
        return False

# ── HTTP handler ─────────────────────────────────────────────────────────────

DEF_CH = "6"

class H(http.server.BaseHTTPRequestHandler):

    def _auth(self) -> bool:
        if _check_auth(self.headers):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Piña Colada"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send(self, body: bytes, ct: str = "text/html; charset=utf-8", code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, loc: str = "/"):
        self.send_response(303)
        self.send_header("Location", loc)
        self.end_headers()

    def do_GET(self):
        if not self._auth():
            return
        p = self.path.split("?")[0]
        if p == "/manifest.webmanifest":
            self._send(MANIFEST.encode(), "application/manifest+json")
        elif p == "/logo.png" or (p.startswith("/icon-") and p.endswith(".png")):
            try:
                body = open(BASE + p, "rb").read()
            except Exception:
                body = b""
            self._send(body, "image/png")
        elif p == "/api/live":
            self._send(json.dumps(api_live()).encode(), "application/json")
        elif p == "/api/portal_template":
            qs = urllib.parse.parse_qs(
                self.path.split("?", 1)[1] if "?" in self.path else ""
            )
            name = qs.get("name", [""])[0]
            body = json.dumps({"name": name, "html": read_portal_html(name)}).encode()
            self._send(body, "application/json")
        else:
            host = self.headers.get("Host", "127.0.0.1:8080").split(":")[0]
            self._send(render("http://" + host + ":2502"))

    def do_POST(self):
        if not self._auth():
            return
        n = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        q = urllib.parse.parse_qs(body)
        p = self.path

        # ── AP ──
        if p == "/ap_stop":
            sh(f"pkill hostapd; pkill -f {shlex.quote(PORTAL)}; "
               "pkill -f 'conf-file=.*pinacola-dnsmasq'")
        elif p == "/ap_start":
            ap_start()
        elif p == "/apboot_on":
            sh("systemctl enable pinacola-ap.service")
        elif p == "/apboot_off":
            sh("systemctl disable pinacola-ap.service")

        # ── Portal ──
        elif p == "/portal_on":
            portal_on()
        elif p == "/portal_off":
            portal_off()
        elif p == "/portal_save":
            name = q.get("name", [""])[0].strip()
            html_body = q.get("html", [""])[0]
            activate = q.get("activate", ["0"])[0] == "1"
            if name:
                saved = save_portal_html(name, html_body)
                if activate:
                    activate_portal_file(saved)
        elif p == "/portal_delete":
            name = q.get("name", [""])[0].strip()
            if name:
                delete_portal_file(name)
        elif p == "/portal_activate":
            name = q.get("name", [""])[0].strip()
            if name:
                activate_portal_file(name)
        elif p == "/portal_creds_clear":
            sh(f"rm -f {shlex.quote(CREDS_JSON)} {shlex.quote(CRED)}")

        # ── Evil twin / AP config ──
        elif p == "/eviltwin":
            ssid = q.get("ssid", [""])[0].replace("\n", "").replace("\r", "")[:32]
            if ssid:
                set_eviltwin(ssid)
        elif p == "/normalap":
            set_normal_ap()

        # ── Recon / audit ──
        elif p == "/recon_scan":
            recon_scan()
        elif p == "/wifitest":
            bssid = q.get("bssid", [""])[0].strip()
            ch = q.get("ch", [""])[0].strip()
            # Strict validation before any shell use
            if bssid and not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", bssid):
                bssid = ""
            if not ch.isdigit() or not (1 <= int(ch) <= 13):
                ch = ""
            sh(f"nohup bash /opt/pinacola/wifitest.sh {shlex.quote(bssid)} "
               f"{shlex.quote(ch)} >/dev/null 2>&1 &")
        elif p == "/crack_gpu":
            # Captura + crack en la GPU del portatil (via crack-agent). Misma
            # validacion que /wifitest. bssid vacio = mi AP (lo resuelve el agente).
            bssid = q.get("bssid", [""])[0].strip()
            ch = q.get("ch", [""])[0].strip()
            if bssid and not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", bssid):
                bssid = ""
            if ch and (not ch.isdigit() or not (1 <= int(ch) <= 13)):
                ch = ""
            crack_gpu(bssid, ch)

        # ── Attack / MITM contra router externo ──
        elif p == "/mitmattack":
            # Target manual opcional: si llegan bssid+key validos, se escribe
            # mitm-ready antes de lanzar (SSID/canal los auto-resuelve el motor).
            bssid = q.get("bssid", [""])[0].strip()
            key = q.get("key", [""])[0].replace("\n", "").replace("\r", "")[:63]
            if re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", bssid) and len(key) >= 8:
                with open(MITMREADY, "w") as f:
                    f.write(f"BSSID={bssid.upper()}\nKEY={key}\nSSID=\nCHANNEL=\n")
            mitm_router_start()
        elif p == "/mitm_target":
            # seleccionar el device a envenenar (ARP-spoof dirigido). IP validada.
            ip = q.get("ip", [""])[0].strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                mitm_set_target(ip)
        elif p == "/mitm_audit":
            ip = q.get("ip", [""])[0].strip()
            action = q.get("action", [""])[0].strip()
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) and action in ("ports", "os", "services"):
                mitm_audit(ip, action)
        elif p == "/mitmattack_stop":
            mitm_router_stop()
        elif p == "/deauth":
            bssid = q.get("bssid", [""])[0]
            ch = q.get("ch", [DEF_CH])[0]
            if re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", bssid) and ch.isdigit():
                deauth(bssid, ch)

        # ── BLE / Beacon ──
        elif p == "/ble_scan":
            ble_scan_start()
        elif p == "/beacon_spam":
            sh(f"nohup bash {shlex.quote(BEACONSH)} >/dev/null 2>&1 &")
        elif p == "/beacon_spam_stop":
            sh("pkill -9 -f mdk4; nohup bash -c 'sleep 1; systemctl start kismet-sensor.service' >/dev/null 2>&1 &")

        # ── Misc ──
        elif p == "/clear":
            sh(f"rm -f {shlex.quote(CRED)}")

        self._redirect()

    def log_message(self, *a):
        pass


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _init_auth()
    print(f"  🍍  Piña Colada running on http://0.0.0.0:8080")
    http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()

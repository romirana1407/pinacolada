#!/usr/bin/env python3
import urllib.request, base64, json, re, time, os
KCONF="/root/.kismet/kismet_httpd.conf"
TOPIC=os.environ.get("NTFY_TOPIC","").strip()
if not TOPIC:
    raise SystemExit("NTFY_TOPIC not set (see .env.example) — refusing to start.")
STATE="/opt/pineapple/.alert-last"
NOTIFY_CLASSES={"DENIAL","SPOOF","PROBE","CRYPTO"}
def kcreds():
    u=p=""
    if os.path.exists(KCONF):
        t=open(KCONF).read()
        mu=re.search(r"httpd_username=(.*)",t); mp=re.search(r"httpd_password=(.*)",t)
        if mu: u=mu.group(1).strip()
        if mp: p=mp.group(1).strip()
    return u,p
def kget(path):
    u,p=kcreds()
    try:
        r=urllib.request.Request("http://127.0.0.1:2502"+path)
        if u: r.add_header("Authorization","Basic "+base64.b64encode(("%s:%s"%(u,p)).encode()).decode())
        return json.load(urllib.request.urlopen(r,timeout=6))
    except Exception: return None
def push(title,msg,tags="warning"):
    try:
        r=urllib.request.Request("https://ntfy.sh/"+TOPIC,data=msg.encode("utf-8"),
            headers={"Title":title.encode("utf-8"),"Tags":tags,"Priority":"high"})
        urllib.request.urlopen(r,timeout=8)
    except Exception: pass
last=0.0
if os.path.exists(STATE):
    try: last=float(open(STATE).read().strip())
    except: last=0.0
if last==0.0:
    last=time.time(); open(STATE,"w").write(str(last))
push("Pineapple Express","Vigilancia de Kismet ACTIVA. Te avisare aqui de deauth floods y APs sospechosos.","white_check_mark")
while True:
    d=kget("/alerts/last-time/0/alerts.json")
    if isinstance(d,list):
        newlast=last
        for a in d:
            ts=float(a.get("kismet.alert.timestamp",0) or 0)
            if ts>last:
                cls=a.get("kismet.alert.class","")
                if cls in NOTIFY_CLASSES:
                    push("ALERTA: "+a.get("kismet.alert.header","?"), a.get("kismet.alert.text","")[:200])
                if ts>newlast: newlast=ts
        if newlast>last:
            last=newlast; open(STATE,"w").write(str(last))
    time.sleep(20)

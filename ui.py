"""HTML rendering — CSS, JavaScript, and page builder."""
import html as _html
from config import *
from engine import (
    ap_state, ap_cfg, clients, creds, dnsfeed, mitmfeed, wifitest_result,
    mitm_ready, mitm_attack_state, portal_on_state, portal_active_name,
    read_creds_json, k_alerts, k_count, sys_stats, parse_scan,
    parse_channel_stats, ble_scan_state, ble_scan_results, beacon_spam_active,
    list_portals, read_portal_html, sh,
)

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:system-ui,-apple-system,sans-serif;display:flex;flex-direction:column;min-height:100vh}
a{color:#1f6feb;text-decoration:none}
#header{background:#161b22;border-bottom:1px solid #30363d;padding:0 20px;display:flex;align-items:center;height:96px;gap:18px;flex-shrink:0}
#logo{display:flex;align-items:center;white-space:nowrap;margin-right:8px;text-decoration:none}
#logo img{height:82px;width:auto;filter:drop-shadow(0 0 10px #00c8c840)}
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
    return'<p class="muted">No channel data. Run a scan first.</p>';
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
  if(!devs||!devs.length)return'<p class="muted">No devices. Run a BLE scan (12s).</p>';
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
  return'<table><thead><tr><th>MAC</th><th>Name</th><th>RSSI</th><th>Flags</th></tr></thead>'
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
  if(!name.trim()){alert('Name is required');return;}
  var fd=new FormData();
  fd.append('name',name.trim());
  fd.append('html',html2);
  fd.append('activate',activate?'1':'0');
  fetch('/portal_save',{method:'POST',body:new URLSearchParams(fd)})
    .then(function(){location.reload();});
};
window.portalDelete=function(name){
  if(!confirm('Delete template "'+name+'"?'))return;
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
  if(n)n.value='my-portal';
  if(t)t.value='<!doctype html>\n<html><head><meta charset=utf-8>\n<meta name=viewport content="width=device-width,initial-scale=1">\n<title>WiFi Login</title>\n<style>\nbody{font-family:sans-serif;max-width:360px;margin:60px auto;text-align:center;background:#f5f5f5}\n.box{background:#fff;border-radius:12px;padding:28px;box-shadow:0 2px 12px #0002}\nh2{margin-bottom:6px}p{color:#666;font-size:14px;margin-bottom:20px}\ninput{display:block;width:100%;padding:11px;margin:8px 0;border:1px solid #ddd;border-radius:6px;font-size:15px;box-sizing:border-box}\nbutton{width:100%;padding:12px;background:#1a73e8;color:#fff;border:0;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer;margin-top:4px}\n</style></head>\n<body><div class=box>\n<h2>&#127760; WiFi Login</h2>\n<p>Sign in to access the internet</p>\n<form method=POST action=/login>\n<input name=email placeholder="Email" type=email required>\n<input name=password placeholder="Password" type=password required>\n<button type=submit>Connect</button>\n</form>\n</div></body></html>';
  showTab('portal');
};
function renderPortalCreds(creds){
  var el=document.getElementById('portal-creds');
  if(!el)return;
  if(!creds||!creds.length){el.innerHTML='<p class="muted">No captures yet.</p>';return;}
  var h='';
  [...creds].reverse().forEach(function(c){
    var fields=Object.entries(c.data||{}).map(function(e){return esc(e[0])+'=<b>'+esc(e[1])+'</b>';}).join(' &nbsp;');
    h+='<div class=cred-row><span class=muted>'+esc(c.ts||'')+'</span><span class=muted>'+esc(c.ip||'')+'</span><span>'+fields+'</span></div>';
  });
  el.innerHTML=h;
}

function devRow(dv,gw,target){
  var isgw=dv.ip===gw, istgt=dv.ip===target;
  var tag=isgw?' <span class="muted">(gateway)</span>':(istgt?' <span class="pill pon">&#x25cf;</span>':'');
  var btn=isgw?'<span class="muted">&mdash;</span>'
    :'<form method=POST action=/mitm_target style="display:inline;margin:0"><input type=hidden name=ip value="'+esc(dv.ip)+'"><button class="btn btn-sm '+(istgt?'btn-r':'btn-p')+'" type=submit>'+(istgt?'target':'&#127919;')+'</button></form>';
  return'<tr><td class=mono>'+esc(dv.ip)+tag+'</td><td class=mono>'+esc(dv.mac)+'</td><td>'+esc(dv.vendor||'')+'</td><td>'+btn+'</td></tr>';
}
function mcard(d){
  var r=d.mitm_ready,st=d.mitm_state,info=d.mitm_info||{},devs=d.mitm_devices||[],tgt=d.mitm_target||'';
  if(st==='associated'||st==='running'){
    var head=(st==='running'?pill(true,'MITM &rarr; '+esc(tgt),''):pill(true,'ASSOCIATED',''))+' &nbsp;<span class=muted>Kismet paused</span>';
    var inf='<p style="margin:6px 0">Router <b>'+esc(info.SSID||'?')+'</b> &middot; Pi '+esc(info.IP||'')+' &middot; gw '+esc(info.GW||'')+'</p>';
    var tbl=devs.length?'<table><thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th><th></th></tr></thead><tbody>'+devs.map(function(dv){return devRow(dv,info.GW||'',tgt);}).join('')+'</tbody></table>':'<p class=muted>Descubriendo dispositivos...</p>';
    var extra='';
    if(st==='running'&&tgt){
      var mfeed=(d.mitm_feed||[]).filter(function(x){return x.indexOf(tgt)>=0;});
      extra='<div style="margin-top:12px"><b>&#128065; Monitoreo en vivo de '+esc(tgt)+'</b>'
        +'<div style="max-height:180px;overflow:auto;margin-top:4px">'+fl(mfeed,'esperando tráfico del target (navega en el device)...')+'</div></div>'
        +'<div style="margin-top:12px"><b>&#128269; Auditar '+esc(tgt)+':</b> '
        +['ports','os','services'].map(function(a){return'<form method=POST action=/mitm_audit style="display:inline;margin:0 2px"><input type=hidden name=ip value="'+esc(tgt)+'"><input type=hidden name=action value="'+a+'"><button class="btn btn-sm btn-p" type=submit>'+a+'</button></form>';}).join('')
        +'</div>'+(d.mitm_audit?'<pre style="white-space:pre-wrap;font-size:11px;color:#3fb950;max-height:220px;overflow:auto;margin-top:6px">'+esc(d.mitm_audit)+'</pre>':'');
    }
    return'<div style="margin-bottom:8px">'+head+'</div>'+inf+tbl+extra
      +'<form method="POST" action="/mitmattack_stop" style="margin-top:10px"><button class="btn btn-r">Stop MITM</button></form>';
  }
  if(st==='starting')
    return'<p><span class="pill pwarn">&#x25cf; asociando al router...</span></p><form method="POST" action="/mitmattack_stop"><button class="btn btn-r">Cancel</button></form>';
  if(r&&r.KEY){
    return'<table style="margin-bottom:12px"><tr><th>BSSID</th><td class="muted mono">'+esc(r.BSSID||'')+'</td></tr>'
      +'<tr><th>Key</th><td style="color:#f5c542;font-family:monospace">'+esc(r.KEY)+'</td></tr></table>'
      +'<form method="POST" action="/mitmattack"><button class="btn btn-r">&#9889; Launch MITM (router)</button></form>'
      +'<p class="muted" style="font-size:11px;margin-top:8px">Asocia la Pi al router, descubre devices, ARP-spoof dirigido al que elijas. Pausa Kismet. Solo redes propias.</p>';
  }
  return'<p class="muted">Mete BSSID+Key del router abajo y pulsa Launch (o crackéalo en Recon).</p>';
}

function clientsTable(cl){
  if(!cl||!cl.length)return'<p class="muted">(none associated)</p>';
  return'<table><thead><tr><th>MAC</th><th>IP</th><th>Name</th><th>Signal</th></tr></thead><tbody>'
    +cl.map(c=>'<tr><td class="mono">'+esc(c.mac)+'</td><td>'+esc(c.ip)+'</td><td>'+esc(c.name)+'</td><td>'+esc(c.signal)+'</td></tr>').join('')
    +'</tbody></table>';
}

function scanTable(sc){
  if(!sc||!sc.length)return'<p class="muted">No results. Run a scan to see nearby networks.</p>';
  return'<table><thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>ENC</th><th>Signal</th><th></th></tr></thead><tbody>'
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
    var apst=d.ap_up?pill(true,'ACTIVE','')+' <b>'+esc(d.ap_ssid||'')+'</b>':pill(false,'','stopped');
    set('dash-ap',apst);
    var kst=d.kismet==='active'?pill(true,'active','')+' <span class="muted">'+esc(d.k_count)+' devs</span>':pill(false,'',''+esc(d.kismet));
    set('dash-kismet',kst);
    set('dash-portal',d.portal?pill(true,'ON',''):pill(false,'','off'));
    var mst=d.mitm_state==='running'?pill(true,'RUNNING',''):d.mitm_state==='starting'?'<span class="pill pwarn">&#x25cf; connecting</span>':pill(false,'','idle');
    set('dash-mitm',mst);
    set('dash-wt','<pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0">'+esc(d.wt_result)+'</pre>');
    txt('dash-creds',d.creds);
    // recon
    set('wt-result','<pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0 0 12px">'+esc(d.wt_result)+'</pre>');
    set('scan-table',scanTable(d.scan));
    set('channel-chart',channelChart(d.channel_stats||{}));
    // ap tab
    set('client-table',clientsTable(d.clients_data||[]));txt('client-count',d.clients);
    set('dns-feed',fl(d.dns,'no DNS traffic yet'));txt('cred-count',d.creds);
    // attack
    set('mitm-inner',mcard(d));
    set('mitm-feed',fl(d.mitm_feed,'no HTTPS yet'));
    var bspam=d.beacon_spam;
    set('beacon-state',bspam?'<span class="pill pwarn">&#x25cf; ACTIVE &mdash; flooding airspace</span>':pill(false,'','stopped'));
    set('beacon-btn',bspam?'<form method="POST" action="/beacon_spam_stop"><button class="btn btn-r">Stop Beacon Spam</button></form>'
      :'<form method="POST" action="/beacon_spam"><button class="btn btn-r">&#128246; Launch Beacon Spam</button></form>');
    // defense
    var ks2=d.kismet==='active'?pill(true,'active','')+' &nbsp;devices: <b>'+esc(d.k_count)+'</b>':pill(false,'',''+esc(d.kismet));
    set('k-state',ks2);
    // ble tab
    var bst=d.ble_state||'idle';
    var bspill=bst==='running'?'<span class="pill pwarn">&#x25cf; scanning... (12s)</span>'
      :bst==='done'?'<span class="pill pon">&#x25cf; done</span>'
      :pill(false,'','idle');
    set('ble-state',bspill);
    set('ble-table',bleTable(d.ble_devices||[]));
    var skimmers=(d.ble_devices||[]).filter(function(x){return x.flags&&x.flags.includes('SKIMMER');});
    var airtags=(d.ble_devices||[]).filter(function(x){return x.flags&&x.flags.includes('AIRTAG');});
    set('ble-summary',
      (skimmers.length?'<span class="pill poff" style="margin-right:6px">&#9888; '+skimmers.length+' SKIMMER'+(skimmers.length>1?'S':'')+'</span>':'')
      +(airtags.length?'<span class="pill pon" style="margin-right:6px">'+airtags.length+' AIRTAG'+(airtags.length>1?'S':'')+'</span>':'')
      +((!skimmers.length&&!airtags.length&&bst==='done')
        ?'<span class="muted" style="font-size:12px">No threats detected</span>':''));
    // portal tab
    var pname=d.portal_active_name||'';
    set('portal-status',d.portal
      ?pill(true,'ACTIVE','')+'&nbsp;<span class="muted">template: <b>'+esc(pname)+'</b></span>'
      :pill(false,'','off'));
    set('portal-toggle-btn',d.portal
      ?'<form method="POST" action="/portal_off"><button class="btn btn-r">Stop portal</button></form>'
      :'<form method="POST" action="/portal_on"><button class="btn btn-p">Activate active portal</button></form>');
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

MANIFEST='{"name":"Piña Colada","short_name":"Piña Colada","start_url":"/","display":"standalone","background_color":"#0d1117","theme_color":"#0d1117","icons":[{"src":"/icon-192.png","sizes":"192x192","type":"image/png"},{"src":"/icon-512.png","sizes":"512x512","type":"image/png"}]}'


def hp(on,ton,toff):
    if on: return '<span class="pill pon">&#x25cf; '+ton+'</span>'
    return '<span class="pill poff">&#x25cf; '+toff+'</span>'

def hfl(items,empty):
    if not items: return '<p class="muted">'+empty+'</p>'
    return ''.join('<div class="fl">'+_html.escape(x)+'</div>' for x in reversed(items))


def render(klink):
    up,ssid,ch=ap_state(); cpu,ram,uptime_s=sys_stats()
    k=sh("systemctl is-active kismet-sensor.service") or "?"
    al=k_alerts(); kc_n=k_count(); cl=clients(); cr=creds()
    fd=dnsfeed(); mf=mitmfeed(); wtr=wifitest_result()
    mr=mitm_ready(); mas=mitm_attack_state(); pst=portal_on_state()
    scan=parse_scan(); ch_stats=parse_channel_stats()
    cssid,csec=ap_cfg(); eth=sh("ip -br addr show eth0 | awk '{print $3}'")
    abe=sh("systemctl is-enabled pinacola-ap.service 2>/dev/null")=="enabled"
    ble_st=ble_scan_state(); ble_devs=ble_scan_results()
    bspam=beacon_spam_active()

    def ccolor(v): return "#f85149" if v>80 else "#f5c542" if v>60 else "#3fb950"

    p=[]
    p.append('<!doctype html><html><head>'
        '<meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">'
        '<title>Piña Colada</title><link rel=manifest href=/manifest.webmanifest>'
        '<meta name=theme-color content="#0d1117"><link rel=apple-touch-icon href=/icon-192.png>'
        '<meta name=mobile-web-app-capable content=yes><meta name=apple-mobile-web-app-capable content=yes>'
        '<style>'+CSS+'</style></head><body>')

    # ── Header ──
    p.append('<div id=header><a id=logo href="/"><img src="/logo.png" alt="Piña Colada"></a><div class=hdiv></div>'
        '<div class=hst><div class=hst-val><span id=hdr-cpu>'+str(round(cpu))+'%</span></div>'
        '<div class=hst-lbl>CPU</div><div class=hst-bar>'
        '<div id=bar-cpu class=hst-bar-fill style="width:'+str(min(100,cpu))+'%;background:'+ccolor(cpu)+'"></div></div></div>'
        '<div class=hst><div class=hst-val><span id=hdr-ram>'+str(round(ram))+'%</span></div>'
        '<div class=hst-lbl>RAM</div><div class=hst-bar>'
        '<div id=bar-ram class=hst-bar-fill style="width:'+str(min(100,ram))+'%;background:'+ccolor(ram)+'"></div></div></div>'
        '<div class=hdiv></div>'
        '<div class=hst><div class=hst-val><span id=hdr-clients>'+str(len(cl))+'</span></div><div class=hst-lbl>Clients</div></div>'
        '<div class=hst><div class=hst-val><span id=hdr-kismet>'+_html.escape(str(kc_n))+'</span></div><div class=hst-lbl>Kismet</div></div>'
        '</div>')

    p.append('<div id=layout>')

    # ── Sidebar ──
    p.append('<nav id=sidebar>'
        '<div class=nav-item id=nav-dashboard><span class=nav-icon>&#8861;</span>Dashboard</div>'
        '<div class=nav-item id=nav-recon><span class=nav-icon>&#128225;</span>Recon</div>'
        '<div class=nav-item id=nav-ap><span class=nav-icon>&#128246;</span>Rogue AP</div>'
        '<div class=nav-sep></div>'
        '<div class=nav-item id=nav-attack><span class=nav-icon>&#9889;</span>Attack</div>'
        '<div class=nav-item id=nav-defense><span class=nav-icon>&#128737;</span>Defense</div>'
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
        '<div class=stat-card><div class=stat-val style="font-size:14px;padding-top:6px"><span id=s-uptime>'+_html.escape(uptime_s)+'</span></div>'
        '<div class=stat-lbl>Uptime</div></div>'
        '<div class=stat-card><div class=stat-val><span id=s-kdevs>'+_html.escape(str(kc_n))+'</span></div><div class=stat-lbl>Kismet devs</div></div>'
        '</div>')
    p.append('<div class=grid-4>'
        '<div class=mod-card><div class=mod-label>Rogue AP</div><div id=dash-ap>'+hp(up,'ACTIVE','stopped')+(' <b>'+_html.escape(ssid)+'</b>' if up and ssid else '')+'</div></div>'
        '<div class=mod-card><div class=mod-label>Kismet</div><div id=dash-kismet>'+hp(k=='active','active',k)+'</div></div>'
        '<div class=mod-card><div class=mod-label>Evil Portal</div><div id=dash-portal>'+hp(pst,'ON','off')+'</div></div>'
        '<div class=mod-card><div class=mod-label>MITM Attack</div><div id=dash-mitm>'+hp(mas=='running','RUNNING','idle')+'</div></div>'
        '</div>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>Last WiFi Test</div>'
        '<div id=dash-wt><pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0">'+_html.escape(wtr)+'</pre></div></div>'
        '<div class=card><div class=card-h>Captured Credentials &nbsp;<b id=dash-creds style="color:#e6edf3">'+str(len(cr))+'</b></div>'
        +(''.join('<div class=cred>'+_html.escape(c)+'</div>' for c in cr[-3:]) if cr else '<p class=muted>(none yet)</p>')
        +'</div></div>')
    p.append('<div class=card><div class=card-h>Quick Actions</div>'
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
        ch_html='<p class=muted>No channel data. Run a scan first.</p>'

    if scan:
        scan_html='<table><thead><tr><th>BSSID</th><th>SSID</th><th>CH</th><th>ENC</th><th>Signal</th><th></th></tr></thead><tbody>'
        for ap in scan:
            bssid_e=_html.escape(ap["bssid"]); ch_e=_html.escape(ap["ch"])
            scan_html+=('<tr><td class=mono>'+bssid_e+'</td><td>'+_html.escape(ap["ssid"])+'</td>'
                '<td>'+ch_e+'</td><td>'+_html.escape(ap["enc"])+'</td><td>'+_html.escape(ap["power"])+' dBm</td>'
                '<td><button class="btn btn-sm btn-p" type=button '
                'onclick="setTarget(\''+ap["bssid"].replace("'","\\'")+'\',\''+ap["ch"].replace("'","\\'")+'\')">Target</button></td></tr>')
        scan_html+='</tbody></table>'
    else:
        scan_html='<p class=muted>No results. Run a scan to see nearby networks.</p>'

    p.append('<div id=tab-recon class=tab-page>')
    p.append('<div class=card><div class=card-h>Test WiFi</div>'
        '<div id=wt-result><pre style="white-space:pre-wrap;font-family:monospace;font-size:12px;color:#3fb950;margin:0 0 12px">'+_html.escape(wtr)+'</pre></div>'
        '<form method=POST action=/wifitest><div class=form-row>'
        '<div><label>BSSID (empty = my AP)</label><input type=text id=wt-bssid name=bssid placeholder="empty = your AP" size=18></div>'
        '<div><label>Channel</label><input type=text id=wt-ch name=ch placeholder=auto size=4></div>'
        '</div><button class="btn btn-p">Run Test</button>'
        '<button class="btn btn-p" formaction=/crack_gpu '
        'style="margin-left:8px;background:#8957e5;border-color:#8957e5" '
        'title="Captura + crackea en la GPU del portatil (RTX 3050)">'
        '&#127918; Crack en GPU</button>'
        '<span class=muted style="font-size:11px;margin-left:8px">Authorized networks only. &#127918; usa la GPU del portatil.</span>'
        '</form></div>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>WiFi Scan <span class=muted style="text-transform:none;font-weight:400;font-size:12px">(airodump-ng 15s)</span></div>'
        '<form method=POST action=/recon_scan style="margin-bottom:12px">'
        '<button class="btn btn-p">&#9654; Run Scan</button>'
        '<span class=muted style="font-size:12px;margin-left:10px">Pauses Kismet ~17s</span></form>'
        '<div id=scan-table>'+scan_html+'</div></div>'
        '<div class=card><div class=card-h>2.4 GHz Channel Analyzer</div>'
        '<div id=channel-chart>'+ch_html+'</div></div>'
        '</div>')
    p.append('</div>')

    # ════════════ ROGUE AP ════════════
    if up:
        ap_ctrl=(hp(True,'ACTIVE','')+'<span style="margin-left:8px">SSID: <b>'+_html.escape(ssid)+'</b> &middot; Channel '+_html.escape(ch)+'</span>'
            '<br><form method=POST action=/ap_stop style="margin-top:8px"><button class="btn btn-r">Stop AP</button></form>')
    else:
        ap_ctrl=(hp(False,'','stopped')+'<br><form method=POST action=/ap_start style="margin-top:8px">'
            '<button class="btn btn-p">Start AP</button></form>')
    if pst:
        portal_ctrl=(hp(True,'ON','')+'<span class=muted style="margin-left:8px">capturing logins</span>'
            '<br><form method=POST action=/portal_off style="margin-top:8px"><button class="btn btn-r">Stop portal</button></form>')
    else:
        portal_ctrl=(hp(False,'','off')+'<span class=muted style="margin-left:8px">normal internet</span>'
            '<br><form method=POST action=/portal_on style="margin-top:8px"><button class="btn btn-p">Activate portal</button></form>')
    ct_html=''
    if cl:
        ct_html='<table><thead><tr><th>MAC</th><th>IP</th><th>Name</th><th>Signal</th></tr></thead><tbody>'
        for m,i,n,sg in cl:
            ct_html+='<tr><td class=mono>'+_html.escape(m)+'</td><td>'+_html.escape(i)+'</td><td>'+_html.escape(n)+'</td><td>'+_html.escape(sg)+'</td></tr>'
        ct_html+='</tbody></table>'
    else:
        ct_html='<p class=muted>(none associated)</p>'
    crt=''.join('<div class=cred>'+_html.escape(c)+'</div>' for c in cr) if cr else '<p class=muted>(none yet)</p>'

    p.append('<div id=tab-ap class=tab-page>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>AP Control</div>'+ap_ctrl
        +'<p class=muted style="font-size:11px;margin-top:12px">Auto-start on boot: '
        +'<form method=POST action=/apboot_'+('off' if abe else 'on')+' style=display:inline>'
        +'<button class="btn btn-sm btn-g" style="margin-left:6px">'+('ON &rarr; off' if abe else 'off &rarr; ON')+'</button></form></p></div>'
        '<div class=card><div class=card-h>Evil Twin</div>'
        '<p style="margin-bottom:8px">Broadcasting: <b>'+_html.escape(cssid)+'</b> &nbsp;'
        +('<span class="pill pon" style="font-size:11px">WPA2</span>' if csec else '<span class="pill pwarn" style="font-size:11px">ABIERTO</span>')+'</p>'
        '<form method=POST action=/eviltwin><div class=form-row>'
        '<div><label>Clone SSID</label><input type=text name=ssid placeholder="network name" size=18></div>'
        '<button class="btn btn-r" style="align-self:flex-end">Evil-twin</button></div></form>'
        '<form method=POST action=/normalap style="margin-top:4px"><button class="btn btn-sm btn-g">Restore WPA2</button></form>'
        '</div></div>')
    p.append('<div class=card><div class=card-h>Captive Portal</div>'+portal_ctrl+'</div>')
    p.append('<div class=card><div class=card-h>Associated Clients &nbsp;<b id=client-count style="color:#e6edf3">'+str(len(cl))+'</b>'
        ' &nbsp;<span class=muted style="font-size:11px">uplink eth0: '+_html.escape(eth)+'</span></div>'
        '<div id=client-table>'+ct_html+'</div></div>')
    p.append('<div class=card><div class=card-h>Live DNS Traffic</div>'
        '<div id=dns-feed>'+hfl(fd,'no DNS traffic yet – connect a client to the AP')+'</div></div>')
    p.append('<div class=card><div class=card-h>Captured Credentials &nbsp;<b id=cred-count style="color:#e6edf3">'+str(len(cr))+'</b></div>'
        +crt+'<form method=POST action=/clear style="margin-top:10px"><button class="btn btn-r btn-sm">Clear log</button></form></div>')
    p.append('</div>')

    # ════════════ ATAQUE ════════════
    if mas=="running":
        tgt=mr.get('SSID','?') if mr else '?'
        mrac=(hp(True,'RUNNING','')+'<span class=muted style="margin-left:8px">Kismet paused</span>'
            '<br><p style="margin:8px 0">Conectado a <b>'+_html.escape(tgt)+'</b></p>'
            +hfl(mf,'no traffic yet...')
            +'<form method=POST action=/mitmattack_stop style="margin-top:10px"><button class="btn btn-r">Stop MITM</button></form>')
    elif mas in("starting","stopped:error"):
        mrac=(hp(False,'',mas)+hfl(mf,'')
            +'<form method=POST action=/mitmattack_stop><button class="btn btn-r">Cancel</button></form>')
    elif mr:
        mrac=('<table style="margin-bottom:12px"><tr><th>SSID</th><td>'+_html.escape(mr.get('SSID','?'))+'</td></tr>'
            '<tr><th>BSSID</th><td class="muted mono">'+_html.escape(mr.get('BSSID',''))+'</td></tr>'
            '<tr><th>Key</th><td style="color:#f5c542;font-family:monospace">'+_html.escape(mr.get('KEY',''))+'</td></tr></table>'
            '<form method=POST action=/mitmattack><button class="btn btn-r">&#9889; Launch MITM</button></form>'
            '<p class=muted style="font-size:11px;margin-top:8px">Pauses Kismet. Authorized networks only.</p>')
    else:
        mrac='<p class=muted>Run the WiFi test (Recon tab). Button appears here after cracking the password.</p>'

    bspam_state=(hp(True,'ACTIVE','')+'<span class=muted style="margin-left:8px">flooding airspace</span>' if bspam
        else hp(False,'','stopped'))
    bspam_btn=('<form method=POST action=/beacon_spam_stop><button class="btn btn-r">Stop Beacon Spam</button></form>'
        if bspam else '<form method=POST action=/beacon_spam><button class="btn btn-r">&#128246; Launch Beacon Spam</button></form>')

    p.append('<div id=tab-attack class=tab-page>')
    p.append('<div class=card><div class=card-h>MITM Attack Chain '
        '<span class=muted style="text-transform:none;font-weight:400;font-size:12px">'
        'test &rarr; crack &rarr; connect &rarr; ARP spoof &rarr; DNS/SNI</span></div>'
        '<div id=mitm-inner>'+mrac+'</div></div>')
    p.append('<div class=card><div class=card-h>MITM Target (manual)</div>'
        '<form method=POST action=/mitmattack><div class=form-row>'
        '<div><label>BSSID</label><input type=text name=bssid placeholder="AA:BB:CC:DD:EE:FF" size=18></div>'
        '<div><label>Key (WPA)</label><input type=text name=key placeholder="passphrase" size=20></div>'
        '</div><button class="btn btn-r">&#9889; Launch MITM</button>'
        '<span class=muted style="font-size:11px;margin-left:8px">SSID y canal se auto-detectan. Authorized networks only.</span></form></div>')
    p.append('<div class=card><div class=card-h>MITM Monitor &middot; Live HTTPS / SNI</div>'
        '<div id=mitm-feed>'+hfl(mf,'no HTTPS yet')+'</div></div>')
    p.append('<div class=card><div class=card-h>Deauth</div>'
        '<form method=POST action=/deauth><div class=form-row>'
        '<div><label>BSSID</label><input type=text name=bssid value="" size=18></div>'
        '<div><label>Channel</label><input type=text name=ch value="6" size=4></div>'
        '</div><button class="btn btn-r">Deauth &times;10</button>'
        '<span class=muted style="font-size:11px;margin-left:8px">Pauses Kismet ~7s. Your network only.</span></form></div>')
    p.append('<div class=card><div class=card-h>Beacon Spam '
        '<span class=muted style="text-transform:none;font-weight:400;font-size:12px">'
        'floods the air with fake SSIDs via mdk4</span></div>'
        '<div id=beacon-state style="margin-bottom:10px">'+bspam_state+'</div>'
        '<div id=beacon-btn>'+bspam_btn+'</div>'
        '<p class=muted style="font-size:11px;margin-top:8px">Pauses Kismet while active. Authorized environments only.</p>'
        '</div>')
    p.append('</div>')

    # ════════════ DEFENSA ════════════
    kc_str='<div id=k-state style="margin-bottom:10px">'+hp(k=='active','active',k)
    if k=='active': kc_str+=' &nbsp;devices: <b>'+_html.escape(str(kc_n))+'</b>'
    kc_str+='</div>'
    al_html=""
    if al is None:
        al_html='<p class=muted>(Kismet API unavailable &mdash; is it running?)</p>'
    elif not al:
        al_html='<p style="color:#3fb950">No active alerts &#10003;</p>'
    else:
        for h2,sev,t in reversed(al):
            cls="alert-h" if sev>=10 else "alert-m"
            al_html+='<div class='+cls+'><b>'+_html.escape(h2)+'</b> <span class=muted>'+_html.escape(t)+'</span></div>'

    p.append('<div id=tab-defense class=tab-page>')
    p.append('<div class=card><div class=card-h>Kismet &middot; Passive IDS</div>'
        +kc_str+al_html
        +'<div style="margin-top:12px"><a href="'+_html.escape(klink)+'" target=_blank>'
        '<button class="btn btn-b">Open Kismet UI &#8599;</button></a></div></div>')
    p.append('</div>')

    # ════════════ BLUETOOTH ════════════
    ble_pill=(hp(False,'','idle') if ble_st=='idle'
        else ('<span class="pill pwarn">&#x25cf; scanning... (12s)</span>' if ble_st=='running'
        else hp(True,'done','')))

    if ble_devs:
        skimmers=[d for d in ble_devs if 'SKIMMER' in d.get('flags',[])]
        airtags=[d for d in ble_devs if 'AIRTAG' in d.get('flags',[])]
        ble_summary=''
        if skimmers: ble_summary+='<span class="pill poff" style="margin-right:6px">&#9888; '+str(len(skimmers))+' SKIMMER'+('S' if len(skimmers)>1 else '')+'</span>'
        if airtags: ble_summary+='<span class="pill pon" style="margin-right:6px">'+str(len(airtags))+' AIRTAG'+('S' if len(airtags)>1 else '')+'</span>'
        if not skimmers and not airtags and ble_st=='done': ble_summary='<span class=muted style="font-size:12px">No threats detected</span>'
        ble_rows=''
        for d in ble_devs:
            flags=''.join('<span class="bflag '+('bf-skimmer' if f=='SKIMMER' else 'bf-airtag' if f=='AIRTAG' else 'bf-apple')+'">'+_html.escape(f)+'</span>'
                for f in d.get('flags',[]))
            rssi=str(d.get('rssi',''))+(' dBm' if d.get('rssi') else '')
            row_bg=' style="background:#2d141820"' if 'SKIMMER' in d.get('flags',[]) else ''
            ble_rows+=('<tr'+row_bg+'><td class=mono style="font-size:12px">'+_html.escape(d.get('mac',''))+'</td>'
                '<td>'+_html.escape(d.get('name',''))+'</td><td style="font-size:12px">'+rssi+'</td><td>'+flags+'</td></tr>')
        ble_table='<table><thead><tr><th>MAC</th><th>Name</th><th>RSSI</th><th>Flags</th></tr></thead><tbody>'+ble_rows+'</tbody></table>'
    else:
        ble_summary=''; ble_table='<p class=muted>No devices. Run a BLE scan (12s).</p>'

    p.append('<div id=tab-ble class=tab-page>')
    p.append('<div class=card><div class=card-h>BLE Scanner &middot; Skimmer &amp; Tracker Detector</div>'
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap">'
        '<div id=ble-state>'+ble_pill+'</div>'
        '<div id=ble-summary>'+ble_summary+'</div></div>'
        '<form method=POST action=/ble_scan style="margin-bottom:16px">'
        '<button class="btn btn-p">&#9654; Scan Bluetooth (12s)</button>'
        '<span class=muted style="font-size:12px;margin-left:10px">Uses Pi built-in BT 5.0. Does not pause Kismet.</span>'
        '</form>'
        '<div id=ble-table>'+ble_table+'</div>'
        '</div>')
    p.append('<div class=card style="border-color:#30363d">'
        '<div class=card-h>Detection Types</div>'
        '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">'
        '<div class=mod-card><div class=mod-label style="color:#f85149">&#9888; Skimmer</div>'
        '<p style="font-size:12px;color:#8b949e">Names HC-03/05/06/07/08, BlueSweep, SKM-LE. Serial Bluetooth devices used in fraudulent card readers.</p></div>'
        '<div class=mod-card><div class=mod-label style="color:#3fb950">AirTag / FindMy</div>'
        '<p style="font-size:12px;color:#8b949e">Apple manufacturer data 0x004C type 0x12. AirTags and Apple FindMy network devices.</p></div>'
        '<div class=mod-card><div class=mod-label style="color:#79c0ff">Apple</div>'
        '<p style="font-size:12px;color:#8b949e">Other Apple devices (AirPods, iPhone, Mac) with Apple manufacturer data identified in BLE advertisements.</p></div>'
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
            '<div class=tpl-name>'+_html.escape(name)+(
                ' <span class="pill pon" style="font-size:10px">active</span>' if is_active else '')+'</div>'
            '<div class=tpl-actions>'
            '<button class="btn btn-sm btn-g" onclick="portalLoadTpl(\''+_html.escape(name,quote=True)+'\')">Edit</button>'
            +('<button class="btn btn-sm btn-p" onclick="portalActivate(\''+_html.escape(name,quote=True)+'\')">Activate</button>' if not is_active else '')
            +'<button class="btn btn-sm btn-r" onclick="portalDelete(\''+_html.escape(name,quote=True)+'\')">&#x2715;</button>'
            '</div></div>')
    if not tpl_cards:
        tpl_cards='<p class=muted>No saved templates. Create one below.</p>'

    # Creds table
    if pcreds:
        cred_rows=''
        for c in reversed(pcreds[-30:]):
            fields=' &nbsp;'.join(_html.escape(k)+'=<b>'+_html.escape(str(v))+'</b>'
                for k,v in (c.get('data') or {}).items())
            cred_rows+=('<div class=cred-row>'
                '<span class=muted>'+_html.escape(c.get('ts',''))+'</span>'
                '<span class=muted>'+_html.escape(c.get('ip',''))+'</span>'
                '<span>'+fields+'</span></div>')
        creds_html=cred_rows
    else:
        creds_html='<p class=muted id=portal-creds>No captures yet.</p>'

    p.append('<div id=tab-portal class=tab-page>')
    p.append('<div class=grid-2>'
        '<div class=card><div class=card-h>Portal Status</div>'
        '<div id=portal-status style="margin-bottom:12px">'+(
            hp(True,'ACTIVE','')+'&nbsp;<span class=muted>template: <b>'+_html.escape(pan)+'</b></span>' if pst2
            else hp(False,'','off'))+'</div>'
        '<div id=portal-toggle-btn>'+(
            '<form method=POST action=/portal_off><button class="btn btn-r">Stop portal</button></form>' if pst2
            else '<form method=POST action=/portal_on><button class="btn btn-p">Activate active portal</button></form>')+'</div>'
        '<p class=muted style="font-size:11px;margin-top:12px">When active: redirects all AP DNS to this Pi and serves the portal on port 80.</p>'
        '</div>'
        '<div class=card><div class=card-h>Captured Credentials &nbsp;<b style="color:#e6edf3">'+str(len(pcreds))+'</b></div>'
        '<div id=portal-creds>'+creds_html+'</div>'
        '<form method=POST action=/portal_creds_clear style="margin-top:10px">'
        '<button class="btn btn-r btn-sm">Clear captures</button></form>'
        '</div></div>')
    p.append('<div class=card><div class=card-h>Saved Templates '
        '<button class="btn btn-sm btn-p" style="text-transform:none;letter-spacing:0;font-size:12px" onclick="portalNew()">+ New template</button></div>'
        '<div class=tpl-grid>'+tpl_cards+'</div>'
        '</div>')
    p.append('<div class=card><div class=card-h>Template Editor</div>'
        '<div class=form-row style="margin-bottom:12px">'
        '<div><label>Name</label><input type=text id=pe-name placeholder="mi-portal" size=24></div>'
        '<button class="btn btn-g" style="align-self:flex-end" onclick="portalSave(false)">Save</button>'
        '<button class="btn btn-p" style="align-self:flex-end" onclick="portalSave(true)">Save &amp; Activate</button>'
        '</div>'
        '<textarea class=code-ed id=pe-html placeholder="Enter portal HTML here..."></textarea>'
        '<p class=muted style="font-size:11px;margin-top:6px">The form must POST to <code>/login</code>. '
        'All form fields are captured automatically.</p>'
        '</div>')
    p.append('</div>')

    p.append('<script>'+JS+'</script>')
    p.append('</div></div></body></html>')
    return ''.join(p).encode('utf-8')

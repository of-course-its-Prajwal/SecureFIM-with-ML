"""
SecureFIM Pro — Monitoring Dashboard (Port 8443)
Full feature UI: file audit, watchlist, threat scoring, sensitivity labels,
MITRE ATT&CK tags, heatmap, working hours, reports, light/dark mode.
"""
from flask import Blueprint, Response
dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/")
def index():
    return Response(HTML, mimetype="text/html", headers={
        "Cache-Control":"no-cache,no-store,must-revalidate","Pragma":"no-cache","Expires":"0"})

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureFIM Pro — Dashboard</title>
<script src="https://cdn.socket.io/4.7.4/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--card2:#1c2333;--bdr:#30363d;--tx:#e6edf3;--dim:#8b949e;--acc:#58a6ff;--grn:#3fb950;--red:#f85149;--yel:#d29922;--cyn:#39d2c0;--pur:#bc8cff;--org:#db6d28;--sbw:220px}
[data-theme="light"]{--bg:#f0f2f5;--card:#fff;--card2:#f8f9fa;--bdr:#d0d7de;--tx:#1f2328;--dim:#656d76;--acc:#0969da;--grn:#1a7f37;--red:#cf222e;--yel:#9a6700;--cyn:#0969da;--pur:#8250df;--org:#bc4c00}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--tx);display:flex;min-height:100vh;font-size:14px}
a{color:var(--acc);text-decoration:none}
.sidebar{width:var(--sbw);background:var(--card);border-right:1px solid var(--bdr);position:fixed;top:0;left:0;bottom:0;overflow-y:auto;z-index:50;display:flex;flex-direction:column}
.sb-logo{padding:16px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;gap:8px}
.sb-logo h1{font-size:14px;font-weight:600;color:var(--acc)}
.sb-logo span{font-size:10px;color:var(--dim);display:block}
.nav-sec{padding:8px 0}.nav-sec-t{padding:3px 16px;font-size:10px;text-transform:uppercase;color:var(--dim);letter-spacing:1px;font-weight:700}
.nav-i{display:flex;align-items:center;gap:8px;padding:6px 16px;color:var(--dim);cursor:pointer;font-size:12px;border-left:3px solid transparent;transition:all .1s}
.nav-i:hover{background:var(--card2);color:var(--tx)}.nav-i.active{color:var(--acc);border-left-color:var(--acc);background:rgba(88,166,255,.06)}
.nav-i .ic{width:15px;text-align:center;font-size:13px}.nav-i .bdg{margin-left:auto;background:var(--acc);color:#fff;font-size:9px;padding:1px 6px;border-radius:8px;font-weight:700}
.nav-sub{padding-left:24px}.nav-sub .nav-i{font-size:11px;padding:4px 16px}
.sb-bottom{margin-top:auto;padding:10px 16px;border-top:1px solid var(--bdr)}
.theme-t{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--dim);cursor:pointer}.theme-t:hover{color:var(--tx)}
.main{margin-left:var(--sbw);flex:1;padding:18px;min-width:0}
.page{display:none}.page.active{display:block}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}.topbar h2{font-size:17px;font-weight:600}
.topbar-r{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--dim)}
.btn{padding:4px 12px;border-radius:5px;border:1px solid var(--bdr);background:var(--card);color:var(--tx);cursor:pointer;font-size:11px;transition:all .1s}.btn:hover{border-color:var(--acc)}.btn-p{background:var(--acc);border-color:var(--acc);color:#fff}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bdr);border-radius:8px;padding:14px}
.card .l{font-size:9px;text-transform:uppercase;color:var(--dim);letter-spacing:.5px;margin-bottom:4px}.card .v{font-size:22px;font-weight:700}.card .s{font-size:10px;color:var(--dim);margin-top:2px}
.sec{background:var(--card);border:1px solid var(--bdr);border-radius:8px;margin-bottom:12px;overflow:hidden}
.sec-h{padding:11px 16px;border-bottom:1px solid var(--bdr);font-size:12px;font-weight:600;display:flex;align-items:center;gap:6px;justify-content:space-between}
.sec-b{padding:12px 16px}.sec-b.np{padding:0}
.chart-c{position:relative;height:180px;padding:8px}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
@media(max-width:1000px){.row2{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:6px 12px;color:var(--dim);font-weight:600;font-size:9px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--bdr)}
td{padding:6px 12px;border-bottom:1px solid var(--bdr)}.mono{font-family:monospace;font-size:11px}
.badge{display:inline-block;padding:1px 8px;border-radius:8px;font-size:9px;font-weight:600}
.badge.critical,.badge.DELETED,.badge.HIGH{background:rgba(248,81,73,.12);color:var(--red)}
.badge.warning,.badge.MODIFIED,.badge.MEDIUM{background:rgba(210,153,34,.12);color:var(--yel)}
.badge.info,.badge.CREATED,.badge.LOW{background:rgba(88,166,255,.12);color:var(--acc)}
.badge.online{background:rgba(63,185,80,.12);color:var(--grn)}.badge.offline{background:rgba(248,81,73,.12);color:var(--red)}
.badge.ransomware{background:rgba(188,140,255,.12);color:var(--pur)}.badge.anomaly{background:rgba(219,109,40,.12);color:var(--org)}
.badge.MOVED{background:rgba(57,210,192,.12);color:var(--cyn)}.badge.high{background:rgba(219,109,40,.12);color:var(--org)}.badge.medium{background:rgba(210,153,34,.12);color:var(--yel)}.badge.low{background:rgba(63,185,80,.12);color:var(--grn)}
.empty{text-align:center;padding:24px;color:var(--dim);font-style:italic;font-size:12px}
.feed-i{padding:8px 12px;border-bottom:1px solid var(--bdr);display:flex;gap:8px;font-size:12px}.feed-i:hover{background:var(--card2)}
.dot{width:6px;height:6px;border-radius:50%;margin-top:5px;flex-shrink:0}.dot.c{background:var(--grn)}.dot.m{background:var(--yel)}.dot.d{background:var(--red)}.dot.v{background:var(--cyn)}
.feed-t{font-size:11px;font-weight:500}.feed-p{font-size:10px;color:var(--dim);font-family:monospace;word-break:break-all;margin-top:1px}.feed-tm{font-size:9px;color:var(--dim);margin-top:1px}
.inp{padding:5px 10px;border-radius:5px;border:1px solid var(--bdr);background:var(--bg);color:var(--tx);font-size:12px}.inp:focus{outline:none;border-color:var(--acc)}
/* Heatmap */
.hm-grid{display:grid;grid-template-columns:40px repeat(24,1fr);gap:2px;font-size:9px}
.hm-cell{aspect-ratio:1;border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:8px;color:var(--tx)}
.hm-label{display:flex;align-items:center;color:var(--dim);font-size:10px}
/* Threat bar */
.threat-bar{height:6px;border-radius:3px;background:var(--bdr);overflow:hidden;width:60px;display:inline-block;vertical-align:middle}
.threat-fill{height:100%;border-radius:3px}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:3px}
</style>
</head>
<body>
<aside class="sidebar">
  <div class="sb-logo"><div style="font-size:20px">🔒</div><div><h1>SecureFIM Pro</h1><span data-i18n="dsb.subtitle">v4.0 Monitoring</span></div></div>
  <div class="nav-sec"><div class="nav-sec-t" data-i18n="dsec.monitoring">Monitoring</div>
    <div class="nav-i active" data-p="overview"><span class="ic">📊</span><span data-i18n="dnav.overview">Overview</span></div></div>
  <div class="nav-sec"><div class="nav-sec-t" data-i18n="dsec.audit">File Audit</div>
    <div class="nav-i" data-p="all-changes"><span class="ic">📁</span><span data-i18n="dnav.allchanges">All Changes</span><span class="bdg" id="bAll">0</span></div>
    <div class="nav-sub">
      <div class="nav-i" data-p="f-created"><span class="ic"></span><span data-i18n="dnav.created">Created</span></div>
      <div class="nav-i" data-p="f-modified"><span class="ic"></span><span data-i18n="dnav.modified">Modified</span></div>
      <div class="nav-i" data-p="f-deleted"><span class="ic"></span><span data-i18n="dnav.deleted">Deleted</span></div>
      <div class="nav-i" data-p="f-moved"><span class="ic"></span><span data-i18n="dnav.moved">Moved</span></div>
      <div class="nav-i" data-p="f-renamed"><span class="ic"></span><span data-i18n="dnav.renamed">Renamed</span></div>
    </div></div>
  <div class="nav-sec"><div class="nav-sec-t" data-i18n="dsec.devices">Devices</div>
    <div class="nav-i" data-p="agents"><span class="ic"></span><span data-i18n="dnav.agents">Agents</span></div></div>
  <div class="nav-sec"><div class="nav-sec-t" data-i18n="dsec.security">Security</div>
    <div class="nav-i" data-p="anomalies"><span class="ic"></span><span data-i18n="dnav.anomalies">Anomaly Detection</span></div>
    <div class="nav-i" data-p="ransomware"><span class="ic"></span><span data-i18n="dnav.ransomware">Ransomware</span></div>
    <div class="nav-i" data-p="alerts"><span class="ic"></span><span data-i18n="dnav.alerts">Alerts</span><span class="bdg" id="bAlerts">0</span></div>
    <div class="nav-i" data-p="watchlist"><span class="ic"></span><span data-i18n="dnav.watchlist">Watchlist</span></div>
    <div class="nav-i" data-p="threats"><span class="ic"></span><span data-i18n="dnav.threats">Threat Intel</span></div></div>
  <div class="nav-sec"><div class="nav-sec-t" data-i18n="dsec.analytics">Analytics</div>
    <div class="nav-i" data-p="heatmap"><span class="ic"></span><span data-i18n="dnav.heatmap">Activity Heatmap</span></div>
    <div class="nav-i" data-p="report-server"><span class="ic"></span><span data-i18n="dnav.repserver">Server Report</span></div>
    <div class="nav-i" data-p="report-agent"><span class="ic"></span><span data-i18n="dnav.repagent">Agent Report</span></div></div>
  <div class="sb-bottom">
    <div class="theme-t" onclick="tglTh()"><span id="thIc">🌙</span><span id="thTx">Dark Mode</span></div>
    <div class="theme-t" onclick="tglLang()" style="margin-top:6px"><span>🌐</span><span id="lngTx">नेपाली</span></div>
  </div>
</aside>
<div class="main">

<!-- OVERVIEW -->
<div class="page active" id="p-overview">
  <div class="topbar"><h2 data-i18n="dpage.overview">Overview</h2><div class="topbar-r"><span id="clock"></span><button class="btn" onclick="R()">↻</button></div></div>
  <div class="grid">
    <div class="card"><div class="l">Events (1h)</div><div class="v" id="sT">0</div></div>
    <div class="card"><div class="l">Anomalies</div><div class="v" style="color:var(--red)" id="sA">0</div></div>
    <div class="card"><div class="l">Warnings</div><div class="v" style="color:var(--yel)" id="sW">0</div></div>
    <div class="card"><div class="l">Online</div><div class="v" style="color:var(--grn)" id="sOn">0</div></div>
    <div class="card"><div class="l">Offline</div><div class="v" id="sOff">0</div></div>
    <div class="card"><div class="l">Created</div><div class="v" style="color:var(--grn)" id="sCr">0</div></div>
    <div class="card"><div class="l">Modified</div><div class="v" style="color:var(--yel)" id="sMo">0</div></div>
    <div class="card"><div class="l">Deleted</div><div class="v" style="color:var(--red)" id="sDe">0</div></div>
  </div>
  <div class="row2">
    <div class="sec"><div class="sec-h">📈 Timeline</div><div class="chart-c"><canvas id="chTime"></canvas></div></div>
    <div class="sec"><div class="sec-h">📊 By Type</div><div class="chart-c"><canvas id="chType"></canvas></div></div>
  </div>
  <div class="row2">
    <div class="sec"><div class="sec-h"> Recent Activity</div><div class="sec-b np" id="feedAct" style="max-height:300px;overflow-y:auto"><div class="empty">Waiting...</div></div></div>
    <div class="sec"><div class="sec-h"> Recent Alerts</div><div class="sec-b np" id="feedAlt" style="max-height:300px;overflow-y:auto"><div class="empty">No alerts</div></div></div>
  </div>
</div>

<!-- ALL CHANGES — now with threat score, sensitivity, MITRE, outside hours -->
<div class="page" id="p-all-changes">
  <div class="topbar"><h2 data-i18n="dpage.allchanges">All File Changes</h2><div class="topbar-r"><select id="sevFilter" class="btn" onchange="R()"><option value="">All</option><option value="info">Info</option><option value="warning">Warning</option><option value="critical">Critical</option></select></div></div>
  <div class="sec"><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>User</th><th>Type</th><th>File Path</th><th>Sensitivity</th><th>Threat</th><th>MITRE</th><th>🕐</th><th>💾</th></tr></thead><tbody id="tAll"></tbody></table></div></div>
</div>

<!-- Sub-pages for each type -->
<div class="page" id="p-f-created"><div class="topbar"><h2 data-i18n="dpage.created">Files Created</h2></div><div class="sec"><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Path</th><th>Size</th><th>Hash</th><th>Sensitivity</th></tr></thead><tbody id="tCreated"></tbody></table></div></div></div>
<div class="page" id="p-f-modified"><div class="topbar"><h2 data-i18n="dpage.modified">Files Modified</h2></div><div class="sec"><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Path</th><th>Size</th><th>Old Hash</th><th>New Hash</th><th>Sensitivity</th></tr></thead><tbody id="tModified"></tbody></table></div></div></div>
<div class="page" id="p-f-deleted"><div class="topbar"><h2 data-i18n="dpage.deleted">Files Deleted</h2></div><div class="sec"><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Path</th><th>Severity</th><th>Threat Score</th></tr></thead><tbody id="tDeleted"></tbody></table></div></div></div>
<div class="page" id="p-f-moved"><div class="topbar"><h2 data-i18n="dpage.moved">Files Moved</h2></div><div class="sec"><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Source</th><th>Destination</th></tr></thead><tbody id="tMoved"></tbody></table></div></div></div>
<div class="page" id="p-f-renamed"><div class="topbar"><h2 data-i18n="dpage.renamed">Files Renamed</h2></div><div class="sec"><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Old Name</th><th>New Name</th></tr></thead><tbody id="tRenamed"></tbody></table></div></div></div>

<!-- AGENTS -->
<div class="page" id="p-agents">
  <div class="topbar"><h2 data-i18n="dpage.agents">Agents</h2></div>
  <div class="sec"><div class="sec-h">💻 Status</div><div class="sec-b np"><table><thead><tr><th>Agent</th><th>Hostname</th><th>OS</th><th>Status</th><th>Paths</th><th>Events</th><th>Heartbeat</th></tr></thead><tbody id="tAgents"></tbody></table></div></div>
  <div class="sec"><div class="sec-h">📂 Monitored Paths</div><div class="sec-b np"><table><thead><tr><th>Agent</th><th>Path</th></tr></thead><tbody id="tPaths"></tbody></table></div></div>
</div>

<!-- ANOMALIES -->
<div class="page" id="p-anomalies">
  <div class="topbar"><h2 data-i18n="dpage.anomalies">Anomaly Detection — One-Class SVM</h2></div>
  <div class="grid">
    <div class="card"><div class="l">Model</div><div class="v" id="mlSt">—</div><div class="s" id="mlSub"></div></div>
    <div class="card"><div class="l">Samples</div><div class="v" id="mlSamp">0</div><div class="s" id="mlSampSub"></div></div>
    <div class="card"><div class="l">Anomalies</div><div class="v" style="color:var(--red)" id="mlAnCt">0</div></div>
    <div class="card"><div class="l">Model File</div><div class="v" id="mlFile">—</div></div>
  </div>
  <div class="sec"><div class="sec-h">🤖 Features</div><div class="sec-b" id="mlFeat"></div></div>
  <div class="sec"><div class="sec-h">🚨 Anomalies</div><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Type</th><th>Score</th><th>Severity</th><th>Description</th></tr></thead><tbody id="tAnom"></tbody></table></div></div>
</div>

<!-- RANSOMWARE -->
<div class="page" id="p-ransomware">
  <div class="topbar"><h2 data-i18n="dpage.ransomware">Ransomware Detection</h2></div>
  <div class="grid">
    <div class="card"><div class="l">Status</div><div class="v" style="color:var(--grn)">Active</div></div>
    <div class="card"><div class="l">Window</div><div class="v" id="rwWin">—</div></div>
    <div class="card"><div class="l">Renames</div><div class="v" id="rwRen">0</div></div>
    <div class="card"><div class="l">Deletes</div><div class="v" style="color:var(--red)" id="rwDel">0</div></div>
    <div class="card"><div class="l">Creates</div><div class="v" id="rwCre">0</div></div>
    <div class="card"><div class="l">Modifies</div><div class="v" id="rwMod">0</div></div>
  </div>
  <div class="sec"><div class="sec-h">🛡️ Alerts</div><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Severity</th><th>Message</th><th>MITRE</th></tr></thead><tbody id="tRw"></tbody></table></div></div>
</div>

<!-- ALERTS -->
<div class="page" id="p-alerts">
  <div class="topbar"><h2 data-i18n="dpage.alerts">Alerts</h2></div>
  <div class="sec"><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Type</th><th>Severity</th><th>Title</th><th>Message</th></tr></thead><tbody id="tAlerts"></tbody></table></div></div>
</div>

<!-- WATCHLIST -->
<div class="page" id="p-watchlist">
  <div class="topbar"><h2 data-i18n="dpage.watchlist">File Watchlist</h2></div>
  <div class="sec"><div class="sec-h">👁️ Watched Files<span style="font-weight:normal;color:var(--dim);font-size:11px">Files trigger immediate critical alert when changed</span></div><div class="sec-b np"><table><thead><tr><th>File Path</th><th>Sensitivity</th><th>Description</th><th>Auto Alert</th><th>Added</th></tr></thead><tbody id="tWatch"></tbody></table></div></div>
</div>

<!-- THREAT INTEL -->
<div class="page" id="p-threats">
  <div class="topbar"><h2 data-i18n="dpage.threats">Threat Intelligence</h2></div>
  <div class="row2">
    <div class="sec"><div class="sec-h">📊 Threat Level Distribution</div><div class="chart-c"><canvas id="chThreat"></canvas></div></div>
    <div class="sec"><div class="sec-h">🏷️ Sensitivity Distribution</div><div class="chart-c"><canvas id="chSens"></canvas></div></div>
  </div>
  <div class="sec"><div class="sec-h"> MITRE ATT&CK Techniques Observed</div><div class="sec-b" id="mitreList"><div class="empty">No MITRE tags observed yet</div></div></div>
  <div class="sec"><div class="sec-h"> High Threat Events</div><div class="sec-b np"><table><thead><tr><th>Time</th><th>Agent</th><th>Path</th><th>Threat</th><th>Sensitivity</th><th>MITRE</th><th>🕐</th></tr></thead><tbody id="tHighThreat"></tbody></table></div></div>
</div>

<!-- HEATMAP -->
<div class="page" id="p-heatmap">
  <div class="topbar"><h2 data-i18n="dpage.heatmap">Activity Heatmap (7 days)</h2></div>
  <div class="sec"><div class="sec-h"> Events by Day & Hour</div><div class="sec-b">
    <div style="display:flex;gap:4px;margin-bottom:6px;padding-left:40px"><span style="font-size:9px;color:var(--dim);flex:1;text-align:center" id="hmHours"></span></div>
    <div id="hmGrid" class="hm-grid"></div>
    <div style="display:flex;gap:8px;margin-top:10px;justify-content:center;font-size:10px;color:var(--dim)">
      <span>Low</span>
      <span style="display:inline-block;width:12px;height:12px;background:rgba(88,166,255,.1);border-radius:2px"></span>
      <span style="display:inline-block;width:12px;height:12px;background:rgba(88,166,255,.4);border-radius:2px"></span>
      <span style="display:inline-block;width:12px;height:12px;background:rgba(88,166,255,.7);border-radius:2px"></span>
      <span style="display:inline-block;width:12px;height:12px;background:rgba(248,81,73,.8);border-radius:2px"></span>
      <span>High</span>
    </div>
  </div></div>
</div>

<!-- SERVER REPORT -->
<div class="page" id="p-report-server">
  <div class="topbar"><h2 data-i18n="dpage.repserver">Server Report</h2></div>
  <div class="grid">
    <div class="card"><div class="l">Total Events</div><div class="v" id="rsTotalE">0</div></div>
    <div class="card"><div class="l">Agents</div><div class="v" id="rsTotalA">0</div></div>
    <div class="card"><div class="l">Anomalies</div><div class="v" style="color:var(--red)" id="rsAnom">0</div></div>
    <div class="card"><div class="l">Ransomware</div><div class="v" style="color:var(--pur)" id="rsRw">0</div></div>
  </div>
  <div class="row2">
    <div class="sec"><div class="sec-h">📊 By Type</div><div class="chart-c"><canvas id="chSrvType"></canvas></div></div>
    <div class="sec"><div class="sec-h">📈 By Severity</div><div class="chart-c"><canvas id="chSrvSev"></canvas></div></div>
  </div>
  <div class="sec"><div class="sec-h"> Per-Agent Summary</div><div class="sec-b np"><table><thead><tr><th>Agent</th><th>Host</th><th>Status</th><th>Events</th><th>Last Active</th></tr></thead><tbody id="tServerReport"></tbody></table></div></div>
</div>

<!-- AGENT REPORT -->
<div class="page" id="p-report-agent">
  <div class="topbar"><h2 data-i18n="dpage.repagent">Agent Report</h2><div class="topbar-r"><select id="reportAgentSel" class="btn" onchange="loadAgentReport()"><option value="">Select Agent</option></select></div></div>
  <div class="grid">
    <div class="card"><div class="l">Agent</div><div class="v" id="raAgent">—</div></div>
    <div class="card"><div class="l">Host</div><div class="v" id="raHost">—</div></div>
    <div class="card"><div class="l">Status</div><div class="v" id="raStatus">—</div></div>
    <div class="card"><div class="l">Events</div><div class="v" id="raEvents">0</div></div>
  </div>
  <div class="sec"><div class="sec-h"> Events</div><div class="sec-b np"><table><thead><tr><th>Time</th><th>Type</th><th>Path</th><th>Severity</th><th>Threat</th></tr></thead><tbody id="tAgentReport"></tbody></table></div></div>
</div>

</div>
<script>
const API=location.origin+'/api',socket=io();let D={},allE=[];

// Charts
let chTime,chType,chSrvType,chSrvSev,chThreat,chSens;
function initCh(){
const o={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}}};
const oL={responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#8b949e',font:{size:10}}}}};
const sc={x:{ticks:{color:'#8b949e',maxTicksLimit:8,font:{size:9}},grid:{color:'rgba(128,128,128,.12)'}},y:{ticks:{color:'#8b949e',font:{size:9}},grid:{color:'rgba(128,128,128,.12)'},beginAtZero:true}};
chTime=new Chart($('chTime'),{type:'line',data:{labels:[],datasets:[{data:[],borderColor:'#58a6ff',backgroundColor:'rgba(88,166,255,.1)',fill:true,tension:.3,pointRadius:2}]},options:{...o,scales:sc}});
chType=new Chart($('chType'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#3fb950','#d29922','#f85149','#58a6ff','#bc8cff']}]},options:oL});
chSrvType=new Chart($('chSrvType'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:['#3fb950','#d29922','#f85149','#58a6ff','#bc8cff']}]},options:{...o,scales:sc}});
chSrvSev=new Chart($('chSrvSev'),{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#58a6ff','#d29922','#f85149']}]},options:oL});
chThreat=new Chart($('chThreat'),{type:'doughnut',data:{labels:['Low','Medium','High','Critical'],datasets:[{data:[0,0,0,0],backgroundColor:['#3fb950','#d29922','#db6d28','#f85149']}]},options:oL});
chSens=new Chart($('chSens'),{type:'doughnut',data:{labels:['LOW','MEDIUM','HIGH'],datasets:[{data:[0,0,0],backgroundColor:['#58a6ff','#d29922','#f85149']}]},options:oL});
}

// Nav
document.querySelectorAll('.nav-i[data-p]').forEach(i=>i.addEventListener('click',()=>{
document.querySelectorAll('.nav-i').forEach(n=>n.classList.remove('active'));document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
i.classList.add('active');$('p-'+i.dataset.p).classList.add('active');
if(i.dataset.p==='heatmap')loadHeatmap();
}));

// Theme
function tglTh(){const d=document.documentElement,isL=d.getAttribute('data-theme')==='light';d.setAttribute('data-theme',isL?'':'light');$('thIc').textContent=isL?'🌙':'☀️';$('thTx').textContent=isL?t('btn.dark.txt'):t('btn.light.txt');localStorage.setItem('theme',isL?'dark':'light')}
if(localStorage.getItem('theme')==='light'){document.documentElement.setAttribute('data-theme','light');$('thIc').textContent='☀️'}

// ── Internationalization (v7.7) ─────────────────────────────────────────
const I18N = {
  en: {
    "dsb.subtitle":   "v4.0 Monitoring",
    "dsec.monitoring":"Monitoring",
    "dsec.audit":     "File Audit",
    "dsec.devices":   "Devices",
    "dsec.security":  "Security",
    "dsec.analytics": "Analytics",
    "dnav.overview":  "Overview",
    "dnav.allchanges":"All Changes",
    "dnav.created":   "Created",
    "dnav.modified":  "Modified",
    "dnav.deleted":   "Deleted",
    "dnav.moved":     "Moved",
    "dnav.renamed":   "Renamed",
    "dnav.agents":    "Agents",
    "dnav.anomalies": "Anomaly Detection",
    "dnav.ransomware":"Ransomware",
    "dnav.alerts":    "Alerts",
    "dnav.watchlist": "Watchlist",
    "dnav.threats":   "Threat Intel",
    "dnav.heatmap":   "Activity Heatmap",
    "dnav.repserver": "Server Report",
    "dnav.repagent":  "Agent Report",
    "dpage.overview": "Overview",
    "dpage.allchanges":"All File Changes",
    "dpage.created":  "Files Created",
    "dpage.modified": "Files Modified",
    "dpage.deleted":  "Files Deleted",
    "dpage.moved":    "Files Moved",
    "dpage.renamed":  "Files Renamed",
    "dpage.agents":   "Agents",
    "dpage.anomalies":"Anomaly Detection",
    "dpage.ransomware":"Ransomware Alerts",
    "dpage.alerts":   "Security Alerts",
    "dpage.watchlist":"Watchlist",
    "dpage.threats":  "Threat Intelligence",
    "dpage.heatmap":  "Activity Heatmap",
    "dpage.repserver":"Server Report",
    "dpage.repagent": "Agent Report",
    "btn.dark.txt":   "Dark Mode",
    "btn.light.txt":  "Light Mode",
    "btn.lang.np":    "नेपाली",
    "btn.lang.en":    "English",
  },
  np: {
    "dsb.subtitle":   "v4.0 निगरानी",
    "dsec.monitoring":"निगरानी",
    "dsec.audit":     "फाइल अडिट",
    "dsec.devices":   "उपकरणहरू",
    "dsec.security":  "सुरक्षा",
    "dsec.analytics": "विश्लेषण",
    "dnav.overview":  "अवलोकन",
    "dnav.allchanges":"सबै परिवर्तनहरू",
    "dnav.created":   "सिर्जना गरिएको",
    "dnav.modified":  "परिमार्जित",
    "dnav.deleted":   "मेटाइएको",
    "dnav.moved":     "सारिएको",
    "dnav.renamed":   "नाम परिवर्तन",
    "dnav.agents":    "एजेन्टहरू",
    "dnav.anomalies": "विसंगति पहिचान",
    "dnav.ransomware":"र्यान्समवेयर",
    "dnav.alerts":    "सतर्कता",
    "dnav.watchlist": "निगरानी सूची",
    "dnav.threats":   "धम्की सूचना",
    "dnav.heatmap":   "गतिविधि हीटम्याप",
    "dnav.repserver": "सर्भर प्रतिवेदन",
    "dnav.repagent":  "एजेन्ट प्रतिवेदन",
    "dpage.overview": "अवलोकन",
    "dpage.allchanges":"सबै फाइल परिवर्तनहरू",
    "dpage.created":  "सिर्जना गरिएका फाइलहरू",
    "dpage.modified": "परिमार्जित फाइलहरू",
    "dpage.deleted":  "मेटाइएका फाइलहरू",
    "dpage.moved":    "सारिएका फाइलहरू",
    "dpage.renamed":  "नाम परिवर्तित फाइलहरू",
    "dpage.agents":   "एजेन्टहरू",
    "dpage.anomalies":"विसंगति पहिचान",
    "dpage.ransomware":"र्यान्समवेयर सतर्कता",
    "dpage.alerts":   "सुरक्षा सतर्कता",
    "dpage.watchlist":"निगरानी सूची",
    "dpage.threats":  "धम्की जानकारी",
    "dpage.heatmap":  "गतिविधि हीटम्याप",
    "dpage.repserver":"सर्भर प्रतिवेदन",
    "dpage.repagent": "एजेन्ट प्रतिवेदन",
    "btn.dark.txt":   "डार्क मोड",
    "btn.light.txt":  "लाइट मोड",
    "btn.lang.np":    "नेपाली",
    "btn.lang.en":    "English",
  },
};
let CUR_LANG = localStorage.getItem('dshLang') || 'en';
function t(key){return (I18N[CUR_LANG] && I18N[CUR_LANG][key]) || (I18N.en[key]) || key}
function applyI18n(){
  document.querySelectorAll('[data-i18n]').forEach(el=>{
    const k=el.getAttribute('data-i18n');
    const v=t(k);
    if(v) el.textContent=v;
  });
  // Sync theme button text with current language
  const isLight=document.documentElement.getAttribute('data-theme')==='light';
  $('thTx').textContent=isLight?t('btn.light.txt'):t('btn.dark.txt');
  // Language button shows the OTHER language (what clicking switches TO)
  $('lngTx').textContent=CUR_LANG==='en'?t('btn.lang.np'):t('btn.lang.en');
  // Set lang attribute on root for accessibility
  document.documentElement.setAttribute('lang',CUR_LANG==='np'?'ne':'en');
}
function tglLang(){
  CUR_LANG=(CUR_LANG==='en')?'np':'en';
  localStorage.setItem('dshLang',CUR_LANG);
  applyI18n();
}
applyI18n();


// Socket
socket.on('new_event',()=>R());socket.on('anomaly_detected',()=>R());socket.on('new_alert',()=>R());

// Fetch
async function R(){
try{const r=await fetch(API+'/dashboard/summary');D=await r.json();render(D)}catch(e){}
try{const r2=await fetch(API+'/events/recent?limit=200');allE=(await r2.json()).events||[];renderEvents()}catch(e){}
try{const r3=await fetch(API+'/watchlist');renderWatchlist((await r3.json()).items||[])}catch(e){}
}

function threatBar(score){const c=score>=70?'var(--red)':score>=40?'var(--org)':score>=20?'var(--yel)':'var(--grn)';return `<span class="threat-bar"><span class="threat-fill" style="width:${score}%;background:${c}"></span></span> ${score}`}
function sensB(s){return `<span class="badge ${s||'LOW'}">${s||'LOW'}</span>`}
function mitreB(tags){if(!tags||!tags.length)return'—';return tags.map(t=>`<span class="badge anomaly" style="font-size:8px">${t}</span>`).join(' ')}
function ohB(v){return v?'<span title="Outside business hours" style="color:var(--yel)">🌙</span>':''}

function render(d){
const s=d.event_stats||{},bt=s.by_type||{},bs=s.by_severity||{};
tx('sT',s.total||0);tx('sA',s.anomaly_count||0);tx('sW',bs.warning||0);tx('sOn',d.agents_online||0);tx('sOff',d.agents_offline||0);
tx('sCr',bt.CREATED||0);tx('sMo',bt.MODIFIED||0);tx('sDe',bt.DELETED||0);tx('bAll',s.total||0);tx('bAlerts',(d.recent_alerts||[]).length);
const ot=s.over_time||[];if(chTime&&ot.length){chTime.data.labels=ot.map(b=>{try{const d=new Date(b.time);return d.getHours()+':'+String(d.getMinutes()).padStart(2,'0')}catch(e){return''}});chTime.data.datasets[0].data=ot.map(b=>b.count);chTime.update('none')}
if(chType&&Object.keys(bt).length){chType.data.labels=Object.keys(bt);chType.data.datasets[0].data=Object.values(bt);chType.update('none')}
// Feeds
const evts=d.recent_events||[];$('feedAct').innerHTML=evts.length?evts.map(e=>`<div class="feed-i"><div class="dot ${e.event_type==='CREATED'?'c':e.event_type==='MODIFIED'?'m':e.event_type==='DELETED'?'d':'v'}"></div><div><div class="feed-t"><strong>${esc(e.event_type||'')}</strong> ${sensB(e.sensitivity)} ${ohB(e.outside_hours)}</div><div class="feed-p">${esc(e.file_path||'')}</div><div class="feed-tm">${ft(e.timestamp)}</div></div></div>`).join(''):'<div class="empty">Waiting...</div>';
const alts=d.recent_alerts||[];$('feedAlt').innerHTML=alts.length?alts.map(a=>`<div class="feed-i"><div class="dot d"></div><div><div class="feed-t"><strong>${esc(a.title||a.alert_type||'')}</strong> <span class="badge ${a.severity||'warning'}">${a.severity||''}</span></div><div class="feed-p">${esc(a.message||'')}</div><div class="feed-tm">${ft(a.timestamp)}</div></div></div>`).join(''):'<div class="empty">No alerts</div>';
// Tables
const ags=d.agents||[];$('tAgents').innerHTML=ags.length?ags.map(a=>`<tr><td class="mono">${esc(a.agent_id)}</td><td>${esc(a.hostname||'')}</td><td>${esc(a.os_type||'')}</td><td><span class="badge ${a.status==='online'?'online':'offline'}">${a.status||'?'}</span></td><td class="mono">${(a.monitored_paths||[]).join('<br>')||'—'}</td><td>${a.event_count||0}</td><td class="mono">${ft(a.last_heartbeat)}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">None</td></tr>';
$('tPaths').innerHTML=(d.monitored_paths||[]).length?(d.monitored_paths||[]).map(p=>`<tr><td class="mono">${esc(p.agent_id)}</td><td class="mono">${esc(p.path)}</td></tr>`).join(''):'<tr><td colspan="2" class="empty">None</td></tr>';
// Anomalies
const ml=d.ml_status||{};tx('mlSt',ml.is_trained?'✅ Trained':'❌ Not Trained');tx('mlSub',ml.is_trained?'One-Class SVM':'Rule-based');tx('mlSamp',ml.training_samples||0);tx('mlSampSub','Min: '+(ml.min_required||100));tx('mlAnCt',s.anomaly_count||0);tx('mlFile',ml.model_file_exists?'✅ Saved':'❌');
if(ml.feature_names)$('mlFeat').innerHTML=ml.feature_names.map(f=>`<span class="badge info" style="margin:2px;padding:3px 8px">${f}</span>`).join('');
const anoms=d.recent_anomalies||[];$('tAnom').innerHTML=anoms.length?anoms.map(a=>`<tr><td class="mono">${ft(a.timestamp)}</td><td class="mono">${esc(a.agent_id||'')}</td><td><span class="badge anomaly">${esc(a.anomaly_type||'')}</span></td><td>${(a.anomaly_score||0).toFixed(3)}</td><td><span class="badge ${a.severity||''}">${a.severity||''}</span></td><td>${esc(a.description||'')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">None</td></tr>';
// Ransomware
const rw=d.ransomware_status||{};tx('rwWin',(rw.detection_window_s||120)+'s');tx('rwRen',rw.recent_renames||0);tx('rwDel',rw.recent_deletes||0);tx('rwCre',rw.recent_creates||0);tx('rwMod',rw.recent_modifies||0);
const rwA=alts.filter(a=>a.alert_type==='ransomware');$('tRw').innerHTML=rwA.length?rwA.map(a=>`<tr><td class="mono">${ft(a.timestamp)}</td><td class="mono">${esc(a.agent_id||'')}</td><td><span class="badge critical">${a.severity||''}</span></td><td>${esc(a.message||'')}</td><td>${mitreB(['T1486'])}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">None</td></tr>';
// All alerts
$('tAlerts').innerHTML=alts.length?alts.map(a=>`<tr><td class="mono">${ft(a.timestamp)}</td><td class="mono">${esc(a.agent_id||'')}</td><td><span class="badge ${a.alert_type==='ransomware'?'ransomware':'anomaly'}">${esc(a.alert_type||'')}</span></td><td><span class="badge ${a.severity||'info'}">${a.severity||''}</span></td><td>${esc(a.title||'')}</td><td>${esc(a.message||'')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">None</td></tr>';
// Reports
tx('rsTotalE',s.total||0);tx('rsTotalA',d.agents_total||0);tx('rsAnom',s.anomaly_count||0);tx('rsRw',rwA.length);
if(chSrvType&&Object.keys(bt).length){chSrvType.data.labels=Object.keys(bt);chSrvType.data.datasets[0].data=Object.values(bt);chSrvType.update('none')}
if(chSrvSev&&Object.keys(bs).length){chSrvSev.data.labels=Object.keys(bs);chSrvSev.data.datasets[0].data=Object.values(bs);chSrvSev.update('none')}
$('tServerReport').innerHTML=ags.length?ags.map(a=>`<tr><td class="mono">${esc(a.agent_id)}</td><td>${esc(a.hostname||'')}</td><td><span class="badge ${a.status==='online'?'online':'offline'}">${a.status||''}</span></td><td>${a.event_count||0}</td><td class="mono">${ft(a.last_heartbeat)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">None</td></tr>';
const sel=$('reportAgentSel');const cv=sel.value;sel.innerHTML='<option value="">Select</option>'+ags.map(a=>`<option value="${esc(a.agent_id)}">${esc(a.agent_id)}</option>`).join('');if(cv)sel.value=cv;
$('clock').textContent=new Date().toLocaleString();
}

function renderEvents(){
const sev=$('sevFilter')?$('sevFilter').value:'';let evts=allE;if(sev)evts=evts.filter(e=>(e.severity||'')==sev);
// All changes with threat enrichment
$('tAll').innerHTML=evts.length?evts.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td class="mono">${esc(e.agent_id||'')}</td><td class="mono">${esc(e.username||'—')}</td><td><span class="badge ${e.event_type||''}">${esc(e.event_type||'')}</span></td><td class="mono" style="max-width:250px;overflow:hidden;text-overflow:ellipsis">${esc(e.file_path||'')}</td><td>${sensB(e.sensitivity)}</td><td>${threatBar(e.threat_score||0)}</td><td>${mitreB(e.mitre_tags)}</td><td>${ohB(e.outside_hours)}</td><td>${e.backed_up?'<span title="Backed up" style="color:var(--grn)">💾</span>':''}</td></tr>`).join(''):'<tr><td colspan="10" class="empty">None</td></tr>';
// Sub tables
const cr=allE.filter(e=>e.event_type==='CREATED');$('tCreated').innerHTML=cr.length?cr.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td class="mono">${esc(e.agent_id||'')}</td><td class="mono">${esc(e.file_path||'')}</td><td>${e.file_size?fmtSz(e.file_size):'—'}</td><td class="mono">${(e.file_hash||'—').substring(0,12)}</td><td>${sensB(e.sensitivity)}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">None</td></tr>';
const mo=allE.filter(e=>e.event_type==='MODIFIED');$('tModified').innerHTML=mo.length?mo.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td class="mono">${esc(e.agent_id||'')}</td><td class="mono">${esc(e.file_path||'')}</td><td>${e.file_size?fmtSz(e.file_size):'—'}</td><td class="mono">${(e.old_hash||'—').substring(0,10)}</td><td class="mono">${(e.file_hash||'—').substring(0,10)}</td><td>${sensB(e.sensitivity)}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">None</td></tr>';
const de=allE.filter(e=>e.event_type==='DELETED');$('tDeleted').innerHTML=de.length?de.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td class="mono">${esc(e.agent_id||'')}</td><td class="mono">${esc(e.file_path||'')}</td><td><span class="badge ${e.severity||''}">${e.severity||''}</span></td><td>${threatBar(e.threat_score||0)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">None</td></tr>';
const mv=allE.filter(e=>e.event_type==='MOVED');$('tMoved').innerHTML=mv.length?mv.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td class="mono">${esc(e.agent_id||'')}</td><td class="mono">${esc(e.file_path||'')}</td><td class="mono">${esc(e.dest_path||'—')}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">None</td></tr>';
$('tRenamed').innerHTML=mv.length?mv.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td class="mono">${esc(e.agent_id||'')}</td><td class="mono">${esc(e.file_path||'')}</td><td class="mono">${esc(e.dest_path||'—')}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">None</td></tr>';
// Threat intel
const tLevels={low:0,medium:0,high:0,critical:0};const sLevels={LOW:0,MEDIUM:0,HIGH:0};const mitreSet=new Set();
allE.forEach(e=>{tLevels[e.threat_level||'low']++;sLevels[e.sensitivity||'LOW']++;(e.mitre_tags||[]).forEach(t=>mitreSet.add(t))});
if(chThreat){chThreat.data.datasets[0].data=[tLevels.low,tLevels.medium,tLevels.high,tLevels.critical];chThreat.update('none')}
if(chSens){chSens.data.datasets[0].data=[sLevels.LOW,sLevels.MEDIUM,sLevels.HIGH];chSens.update('none')}
$('mitreList').innerHTML=mitreSet.size?[...mitreSet].map(t=>`<span class="badge anomaly" style="margin:3px;padding:4px 10px;font-size:11px">${t}</span>`).join(''):'<div class="empty">No MITRE tags yet</div>';
const highT=allE.filter(e=>(e.threat_score||0)>=20).sort((a,b)=>(b.threat_score||0)-(a.threat_score||0)).slice(0,20);
$('tHighThreat').innerHTML=highT.length?highT.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td class="mono">${esc(e.agent_id||'')}</td><td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(e.file_path||'')}</td><td>${threatBar(e.threat_score||0)}</td><td>${sensB(e.sensitivity)}</td><td>${mitreB(e.mitre_tags)}</td><td>${ohB(e.outside_hours)}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">No high-threat events</td></tr>';
}

function renderWatchlist(items){
$('tWatch').innerHTML=items.length?items.map(w=>`<tr><td class="mono">${esc(w.file_path||'')}</td><td>${sensB(w.sensitivity)}</td><td>${esc(w.description||'')}</td><td>${w.auto_alert?'<span class="badge online">Yes</span>':'No'}</td><td class="mono">${ft(w.timestamp)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">No watched files. Add from Admin Panel (port 8444).</td></tr>';
}

async function loadHeatmap(){
try{const r=await fetch(API+'/threat/heatmap');const d=await r.json();
const grid=d.grid||[];const days=d.days||[];const maxV=Math.max(...grid.flat(),1);
let html='';
for(let day=0;day<7;day++){
html+=`<div class="hm-label">${days[day]||''}</div>`;
for(let h=0;h<24;h++){
const v=grid[day]?grid[day][h]||0:0;const intensity=v/maxV;
const bg=v===0?'rgba(128,128,128,.08)':intensity>0.7?'rgba(248,81,73,.8)':intensity>0.4?'rgba(88,166,255,.7)':intensity>0.1?'rgba(88,166,255,.4)':'rgba(88,166,255,.15)';
html+=`<div class="hm-cell" style="background:${bg}" title="${days[day]} ${h}:00 — ${v} events">${v||''}</div>`;
}}
$('hmGrid').innerHTML=html;
}catch(e){$('hmGrid').innerHTML='<div class="empty">Could not load heatmap</div>'}
}

async function loadAgentReport(){
const aid=$('reportAgentSel').value;if(!aid)return;
const ag=(D.agents||[]).find(a=>a.agent_id===aid);
tx('raAgent',aid);tx('raHost',ag?ag.hostname:'—');tx('raStatus',ag?ag.status:'—');
const agE=allE.filter(e=>e.agent_id===aid);tx('raEvents',agE.length);
$('tAgentReport').innerHTML=agE.length?agE.map(e=>`<tr><td class="mono">${ft(e.timestamp)}</td><td><span class="badge ${e.event_type||''}">${esc(e.event_type||'')}</span></td><td class="mono">${esc(e.file_path||'')}</td><td><span class="badge ${e.severity||'info'}">${e.severity||''}</span></td><td>${threatBar(e.threat_score||0)}</td></tr>`).join(''):'<tr><td colspan="5" class="empty">None</td></tr>';
}

function $(id){return document.getElementById(id)}
function tx(id,v){const e=$(id);if(e)e.textContent=v}
function esc(s){const d=document.createElement('div');d.textContent=String(s||'');return d.innerHTML}
function ft(t){if(!t)return'—';try{return new Date(t).toLocaleString()}catch(e){return t}}
function fmtSz(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB'}

initCh();R();setInterval(R,3000);
</script>
</body>
</html>"""

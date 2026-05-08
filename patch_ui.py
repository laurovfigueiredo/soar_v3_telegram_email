#!/usr/bin/env python3
"""
Patch de UI: transforma o SOAR Wazuh v2 para o estilo visual do Wazuh Dashboard
Execução: sudo python3 patch_ui.py
"""

import re, sys

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

# ─── Novo CSS (estilo Wazuh Dashboard) ────────────────────────────────────────
NEW_CSS = '''<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Source+Code+Pro:wght@400;500&display=swap');

:root{
  --bg:#07101F;
  --panel:#0d1a2d;
  --panel2:#0a1520;
  --sidebar:#0f1d30;
  --border:#1a2e4a;
  --accent:#006BB4;
  --accent-light:#0090e0;
  --green:#00BFB3;
  --yellow:#FEC514;
  --red:#BD271E;
  --red-light:#F86B63;
  --orange:#F5A700;
  --purple:#9170B8;
  --teal:#00BFB3;
  --dim:#4a6888;
  --text:#DFE5EF;
  --text-dim:#8faac8;
  --mono:'Source Code Pro',monospace;
  --sans:'Inter',sans-serif;
  --radius:6px;
  --shadow:0 2px 8px rgba(0,0,0,.4);
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:13px;min-height:100vh;display:flex;flex-direction:column}

/* ── TOP HEADER ─────────────────────────────────────────────────────────── */
header{
  display:flex;align-items:center;justify-content:space-between;
  padding:0 24px;height:48px;
  background:var(--panel);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:300;
  box-shadow:var(--shadow);
}
.logo{
  display:flex;align-items:center;gap:10px;
  font-family:var(--sans);font-size:15px;font-weight:700;
  color:var(--text);letter-spacing:.02em;
}
.logo-icon{
  width:28px;height:28px;border-radius:6px;
  background:linear-gradient(135deg,var(--accent),var(--accent-light));
  display:flex;align-items:center;justify-content:center;
  font-size:14px;font-weight:800;color:#fff;
}
.logo-sub{
  font-size:10px;font-weight:400;color:var(--dim);
  margin-left:2px;letter-spacing:.06em;text-transform:uppercase;
}
#status-bar{display:flex;gap:16px;align-items:center;font-size:12px}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:5px}
.dot.ok{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.bad{background:var(--red-light);box-shadow:0 0 6px var(--red-light)}
.dot.warn{background:var(--yellow);box-shadow:0 0 6px var(--yellow)}
#wazuh-dot{color:var(--text-dim);font-size:12px}
#alert-count{color:var(--text-dim);font-size:12px}
#last-refresh{color:var(--dim);font-size:11px;font-family:var(--mono)}
.hdr-btn{
  padding:5px 14px;border-radius:var(--radius);
  border:1px solid var(--border);background:transparent;
  color:var(--text-dim);cursor:pointer;font-size:12px;font-family:var(--sans);
  font-weight:500;transition:.15s;display:flex;align-items:center;gap:5px;
}
.hdr-btn:hover{border-color:var(--accent-light);color:var(--accent-light);background:rgba(0,107,180,.08)}
.hdr-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(0,107,180,.12)}

/* ── MAIN LAYOUT ────────────────────────────────────────────────────────── */
.app-body{display:flex;flex:1;overflow:hidden}

/* ── SIDEBAR ────────────────────────────────────────────────────────────── */
.sidebar{
  width:220px;flex-shrink:0;
  background:var(--sidebar);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  overflow-y:auto;
  position:sticky;top:48px;height:calc(100vh - 48px);
}
.sidebar-section{
  padding:16px 12px 8px;
  font-size:10px;font-weight:600;letter-spacing:.12em;
  text-transform:uppercase;color:var(--dim);
}
.sidebar-item{
  display:flex;align-items:center;gap:10px;
  padding:9px 16px;margin:1px 8px;border-radius:var(--radius);
  cursor:pointer;font-size:13px;color:var(--text-dim);
  transition:.15s;font-weight:400;
}
.sidebar-item:hover{background:rgba(0,107,180,.12);color:var(--text)}
.sidebar-item.active{
  background:rgba(0,107,180,.18);color:var(--accent-light);
  font-weight:500;
}
.sidebar-item .si-icon{font-size:15px;width:20px;text-align:center}
.sidebar-badge{
  margin-left:auto;background:var(--accent);color:#fff;
  font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px;
  min-width:18px;text-align:center;
}
.sidebar-badge.red{background:var(--red-light)}
.sidebar-divider{height:1px;background:var(--border);margin:8px 16px}

/* ── CONTENT ────────────────────────────────────────────────────────────── */
.content-area{flex:1;overflow-y:auto;padding:20px 24px}
.page{display:none}.page.active{display:block}

/* ── BREADCRUMB ─────────────────────────────────────────────────────────── */
.breadcrumb{
  display:flex;align-items:center;gap:6px;margin-bottom:16px;
  font-size:12px;color:var(--dim);
}
.breadcrumb span{color:var(--text-dim)}
.breadcrumb .bc-sep{color:var(--border)}

/* ── STATS ──────────────────────────────────────────────────────────────── */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.stat-card{
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px 16px;
  position:relative;overflow:hidden;cursor:pointer;
  transition:.15s;box-shadow:var(--shadow);
}
.stat-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.stat-card::before{
  content:'';position:absolute;bottom:0;left:0;right:0;height:3px;
}
.stat-card.c-blue::before{background:linear-gradient(90deg,var(--accent),var(--accent-light))}
.stat-card.c-red::before{background:linear-gradient(90deg,var(--red),var(--red-light))}
.stat-card.c-yellow::before{background:linear-gradient(90deg,var(--orange),var(--yellow))}
.stat-card.c-green::before{background:linear-gradient(90deg,var(--teal),#00e5d8)}
.stat-card.c-purple::before{background:linear-gradient(90deg,var(--purple),#b08dd4)}
.stat-label{font-size:11px;font-weight:500;letter-spacing:.04em;color:var(--dim);text-transform:uppercase}
.stat-value{font-family:var(--mono);font-size:28px;margin-top:4px;font-weight:500}
.c-blue .stat-value{color:var(--accent-light)}
.c-red .stat-value{color:var(--red-light)}
.c-yellow .stat-value{color:var(--yellow)}
.c-green .stat-value{color:var(--teal)}
.c-purple .stat-value{color:var(--purple)}

/* ── PANEL ──────────────────────────────────────────────────────────────── */
.panel{
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;
}
.panel-head{
  display:flex;align-items:center;justify-content:space-between;
  padding:11px 16px;border-bottom:1px solid var(--border);
  font-size:11px;font-weight:600;text-transform:uppercase;
  letter-spacing:.08em;color:var(--text-dim);background:var(--panel2);
}
.panel-head span{
  font-family:var(--mono);font-size:13px;
  color:var(--accent-light);font-weight:500;text-transform:none;letter-spacing:0;
}

/* ── TABLE ──────────────────────────────────────────────────────────────── */
table{width:100%;border-collapse:collapse}
th{
  padding:9px 12px;text-align:left;font-size:11px;
  font-weight:600;text-transform:uppercase;letter-spacing:.06em;
  color:var(--dim);border-bottom:1px solid var(--border);
  background:var(--panel2);white-space:nowrap;
}
td{
  padding:8px 12px;border-bottom:1px solid rgba(26,46,74,.5);
  vertical-align:middle;font-size:12px;
}
tr:last-child td{border:none}
tr:hover td{background:rgba(0,107,180,.05)}

/* ── LEVEL BADGES ───────────────────────────────────────────────────────── */
.lvl{
  display:inline-flex;align-items:center;justify-content:center;
  width:26px;height:26px;border-radius:5px;
  font-family:var(--mono);font-size:11px;font-weight:700;
}
.lvl.low{background:rgba(0,191,179,.12);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.lvl.medium{background:rgba(254,197,20,.1);color:var(--yellow);border:1px solid rgba(254,197,20,.3)}
.lvl.high{background:rgba(245,167,0,.12);color:var(--orange);border:1px solid rgba(245,167,0,.3)}
.lvl.crit{background:rgba(189,39,30,.15);color:var(--red-light);border:1px solid rgba(189,39,30,.4)}

/* ── STATUS BADGE ───────────────────────────────────────────────────────── */
.badge{
  display:inline-block;padding:2px 8px;border-radius:12px;
  font-size:10px;font-weight:600;letter-spacing:.04em;
}
.badge.open{background:rgba(0,107,180,.15);color:var(--accent-light);border:1px solid rgba(0,107,180,.3)}
.badge.ignored{background:rgba(74,104,136,.1);color:var(--dim);border:1px solid rgba(74,104,136,.2)}
.badge.actioned{background:rgba(0,191,179,.12);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.badge.escalated{background:rgba(145,112,184,.12);color:var(--purple);border:1px solid rgba(145,112,184,.3)}
.badge.fp{background:rgba(254,197,20,.1);color:var(--yellow);border:1px solid rgba(254,197,20,.25)}
.badge.investigating{background:rgba(0,144,224,.1);color:#5bc8f5;border:1px solid rgba(0,144,224,.25)}

/* ── BUTTONS ────────────────────────────────────────────────────────────── */
.btn{
  padding:4px 9px;border-radius:4px;border:none;cursor:pointer;
  font-size:10px;font-family:var(--sans);font-weight:600;letter-spacing:.03em;
  transition:opacity .15s,transform .1s;white-space:nowrap;
}
.btn:active{transform:scale(.95)}
.btn:disabled{opacity:.25;cursor:not-allowed}
.btn:hover:not(:disabled){opacity:.8}
.btn-blue{background:rgba(0,107,180,.2);color:var(--accent-light);border:1px solid rgba(0,107,180,.4)}
.btn-green{background:rgba(0,191,179,.15);color:var(--teal);border:1px solid rgba(0,191,179,.35)}
.btn-red{background:rgba(189,39,30,.2);color:var(--red-light);border:1px solid rgba(189,39,30,.4)}
.btn-gray{background:rgba(74,104,136,.15);color:var(--dim);border:1px solid rgba(74,104,136,.25)}
.btn-purple{background:rgba(145,112,184,.15);color:var(--purple);border:1px solid rgba(145,112,184,.3)}
.btn-yellow{background:rgba(245,167,0,.12);color:var(--yellow);border:1px solid rgba(245,167,0,.3)}
.btn-teal{background:rgba(0,191,179,.12);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.btn-orange{background:rgba(245,167,0,.12);color:var(--orange);border:1px solid rgba(245,167,0,.3)}
.btn-pink{background:rgba(145,112,184,.12);color:#d49fea;border:1px solid rgba(145,112,184,.25)}
.btn-lg{padding:7px 18px;font-size:12px}
.btn-group{display:flex;gap:3px;flex-wrap:wrap}

/* ── FILTER BAR ─────────────────────────────────────────────────────────── */
.filter-bar{
  display:flex;gap:8px;align-items:center;
  padding:12px 0 14px;flex-wrap:wrap;
}
.filter-bar select,.filter-bar input{
  padding:6px 10px;border-radius:var(--radius);
  background:var(--panel);border:1px solid var(--border);
  color:var(--text);font-size:12px;font-family:var(--sans);
  transition:.15s;
}
.filter-bar select:focus,.filter-bar input:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 2px rgba(0,107,180,.15);
}
select.input-dark option{background:var(--panel)}

/* ── INPUT ──────────────────────────────────────────────────────────────── */
.input-dark{
  background:var(--panel2);border:1px solid var(--border);color:var(--text);
  padding:7px 11px;border-radius:var(--radius);font-size:12px;width:100%;
  font-family:var(--sans);transition:.15s;
}
.input-dark:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,107,180,.15)}
select.input-dark option{background:var(--panel)}

/* ── SIDEBAR AGENTS ─────────────────────────────────────────────────────── */
.agent-row{
  display:flex;align-items:center;gap:8px;
  padding:8px 0;border-bottom:1px solid rgba(26,46,74,.4);
}
.agent-row:last-child{border:none}
.agt-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.agt-dot.active{background:var(--teal);box-shadow:0 0 5px var(--teal)}
.agt-dot.disconnected{background:var(--dim)}
.agt-dot.never_connected{background:var(--yellow)}
.agt-name{font-size:12px;font-weight:500;flex:1}
.agt-id{font-family:var(--mono);font-size:10px;color:var(--dim)}

/* ── LOG ────────────────────────────────────────────────────────────────── */
.log-entry{
  padding:6px 0;border-bottom:1px solid rgba(26,46,74,.4);
  font-family:var(--mono);font-size:11px;color:var(--dim);
}
.log-entry:last-child{border:none}
.log-ts{color:rgba(74,104,136,.6);margin-right:6px}
.log-ok{color:var(--teal)}
.log-err{color:var(--red-light)}
.log-inf{color:var(--accent-light)}

/* ── INCIDENTS ──────────────────────────────────────────────────────────── */
.incident-card{
  background:var(--panel2);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px 16px;margin-bottom:10px;
  transition:.15s;
}
.incident-card:hover{border-color:var(--accent)}
.inc-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.inc-id{font-family:var(--mono);font-size:11px;color:var(--dim)}
.inc-title{font-size:13px;font-weight:600;color:var(--text)}
.inc-meta{font-size:11px;color:var(--dim);margin-top:4px}
.priority-high{border-left:3px solid var(--red-light)}
.priority-med{border-left:3px solid var(--yellow)}
.priority-low{border-left:3px solid var(--teal)}

/* ── MISC ───────────────────────────────────────────────────────────────── */
.empty{text-align:center;padding:40px 20px;color:var(--dim);font-size:12px}
.spinner{
  display:inline-block;width:14px;height:14px;
  border:2px solid var(--border);border-top-color:var(--accent);
  border-radius:50%;animation:spin .6s linear infinite;
  vertical-align:middle;margin-right:5px;
}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* ── MODAL ──────────────────────────────────────────────────────────────── */
.modal-overlay{
  display:none;position:fixed;inset:0;
  background:rgba(0,0,0,.7);backdrop-filter:blur(3px);
  z-index:999;align-items:center;justify-content:center;
}
.modal-overlay.show{display:flex}
.modal{
  background:var(--panel);border:1px solid var(--accent);
  border-radius:8px;padding:24px;width:90%;
  max-width:700px;max-height:88vh;overflow-y:auto;font-size:13px;
  box-shadow:0 8px 32px rgba(0,0,0,.6);
}
.modal h3{color:var(--accent-light);margin-bottom:16px;font-size:15px;font-weight:600}
.modal pre{
  background:var(--bg);padding:12px;border-radius:var(--radius);
  overflow:auto;max-height:280px;white-space:pre-wrap;
  color:#8ab4d4;font-size:10px;font-family:var(--mono);
  border:1px solid var(--border);
}
.modal label{display:block;margin-bottom:3px;color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.modal-footer{display:flex;gap:8px;margin-top:16px;justify-content:flex-end}
.modal-close{
  padding:6px 16px;background:transparent;border:1px solid var(--dim);
  color:var(--dim);border-radius:var(--radius);cursor:pointer;font-size:12px;
}
.modal-close:hover{border-color:var(--accent);color:var(--accent)}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}
.info-item label{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em}
.info-item .val{font-family:var(--mono);font-size:12px;color:var(--text);margin-top:2px}
hr.dim{border:none;border-top:1px solid var(--border);margin:14px 0}

/* ── SCROLLBAR ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:10px}
::-webkit-scrollbar-thumb:hover{background:var(--dim)}

/* ── GRID ───────────────────────────────────────────────────────────────── */
.grid2{display:grid;grid-template-columns:1fr 300px;gap:16px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}

/* ── NOTE ───────────────────────────────────────────────────────────────── */
.note-item{
  background:var(--panel2);padding:8px 12px;border-radius:var(--radius);
  margin-bottom:6px;font-size:11px;border-left:2px solid var(--accent);
}
.note-time{font-family:var(--mono);font-size:10px;color:var(--dim);margin-right:6px}

/* ── PROCESS TABLE ──────────────────────────────────────────────────────── */
.proc-table{font-size:11px;font-family:var(--mono)}
.proc-table td{padding:3px 8px;color:var(--dim)}
.proc-table tr:hover td{color:var(--text)}
.proc-kill{
  padding:2px 7px;border-radius:3px;background:rgba(189,39,30,.2);
  color:var(--red-light);border:1px solid rgba(189,39,30,.4);
  cursor:pointer;font-size:10px;font-family:var(--mono);
}

/* ── OSINT ──────────────────────────────────────────────────────────────── */
.osint-section{
  background:var(--panel2);border:1px solid var(--border);
  border-radius:var(--radius);padding:12px;margin-bottom:10px;
}
.osint-label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:6px;font-weight:600}
.osint-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px}
.osint-key{color:var(--dim);font-size:10px;min-width:110px;font-weight:500}
.osint-val{color:var(--text);font-size:11px;font-family:var(--mono)}
.risk-badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-family:var(--mono);font-weight:700}
.risk-ALTO{background:rgba(189,39,30,.2);color:var(--red-light);border:1px solid rgba(189,39,30,.4)}
.risk-MÉDIO{background:rgba(254,197,20,.1);color:var(--yellow);border:1px solid rgba(254,197,20,.3)}
.risk-BAIXO{background:rgba(0,191,179,.1);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.ticket-card{background:var(--panel2);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:8px}
.ticket-id{font-family:var(--mono);font-size:11px;color:var(--accent-light)}
.sandbox-result{font-family:var(--mono);font-size:11px;padding:10px;background:var(--bg);border-radius:var(--radius);line-height:1.8;border:1px solid var(--border)}
.evidence-chain{font-family:var(--mono);font-size:10px;color:var(--dim);padding:6px 0;border-bottom:1px solid var(--border)}
.tab-group{display:flex;gap:0;margin-bottom:12px;border-bottom:1px solid var(--border)}
.tab-mini{
  padding:6px 14px;cursor:pointer;font-size:11px;font-family:var(--sans);font-weight:500;
  color:var(--dim);border-bottom:2px solid transparent;text-transform:uppercase;letter-spacing:.06em;transition:.15s;
}
.tab-mini.active{color:var(--accent-light);border-bottom-color:var(--accent)}
.tab-pane{display:none}.tab-pane.active{display:block}

/* ── AGENTS GRID ────────────────────────────────────────────────────────── */
.agent-card{
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:16px;transition:.15s;
}
.agent-card:hover{border-color:var(--accent)}
.agent-card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.agent-card-name{font-weight:600;font-size:13px}
.agent-card-id{font-family:var(--mono);font-size:10px;color:var(--dim)}
.agent-card-meta{font-size:11px;color:var(--dim);line-height:1.8}
.agent-status-ok{color:var(--teal);font-weight:600}
.agent-status-off{color:var(--dim)}

/* ── RESPONSIVE ─────────────────────────────────────────────────────────── */
@media(max-width:900px){
  .sidebar{display:none}
  .stats{grid-template-columns:repeat(2,1fr)}
}
</style>'''

# ─── Novo HTML do HEADER + SIDEBAR + ESTRUTURA ──────────────────────────────
NEW_HEADER = '''</head>
<body>

<!-- TOP HEADER -->
<header>
  <div class="logo">
    <div class="logo-icon">W</div>
    SOAR · WAZUH
    <span class="logo-sub">v2</span>
  </div>
  <div id="status-bar">
    <span id="wazuh-dot"><span class="dot warn"></span>verificando...</span>
    <span id="alert-count" style="color:var(--dim)">─</span>
    <span id="last-refresh" style="color:var(--dim);font-size:10px">─</span>
    <button class="hdr-btn" onclick="downloadReport()">📄 Relatório PDF</button>
    <button class="hdr-btn" onclick="refresh()">↻ Refresh</button>
  </div>
</header>

<div class="app-body">

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sidebar-section">Menu Principal</div>

  <div class="sidebar-item active" id="nav-alerts" onclick="switchTab('alerts')">
    <span class="si-icon">🔔</span>
    Alertas
    <span class="sidebar-badge red" id="sb-alerts">0</span>
  </div>

  <div class="sidebar-item" id="nav-incidents" onclick="switchTab('incidents')">
    <span class="si-icon">📋</span>
    Incidentes
    <span class="sidebar-badge" id="sb-incidents">0</span>
  </div>

  <div class="sidebar-item" id="nav-agents" onclick="switchTab('agents')">
    <span class="si-icon">🖥</span>
    Agentes
    <span class="sidebar-badge" id="sb-agents">─</span>
  </div>

  <div class="sidebar-item" id="nav-log" onclick="switchTab('log')">
    <span class="si-icon">📜</span>
    Log de Ações
  </div>

  <div class="sidebar-divider"></div>
  <div class="sidebar-section">Notificações</div>

  <div class="sidebar-item" onclick="testNotify()">
    <span class="si-icon">✈️</span>
    Testar Telegram
  </div>

  <div class="sidebar-divider"></div>
  <div class="sidebar-section">Ambiente</div>

  <div class="sidebar-item" style="cursor:default;color:var(--dim)">
    <span class="si-icon">🌐</span>
    <span style="font-size:11px" id="sb-host">192.168.0.10</span>
  </div>
  <div class="sidebar-item" style="cursor:default;color:var(--dim)">
    <span class="si-icon">🔒</span>
    <span style="font-size:11px">Porta 8000</span>
  </div>
</nav>

<!-- CONTENT -->
<div class="content-area">'''

# ─── Closing tags no final do body ──────────────────────────────────────────
OLD_BODY_CLOSE = "</body>\n</html>"
NEW_BODY_CLOSE = "</div><!-- /content-area -->\n</div><!-- /app-body -->\n</body>\n</html>"

# ─── Sidebar JS hook ─────────────────────────────────────────────────────────
OLD_SWITCH_TAB = "function switchTab(t){"
NEW_SWITCH_TAB = """function testNotify(){
  fetch('/api/notify/test').then(r=>r.json()).then(d=>{
    const ok = d.result && d.result.telegram;
    alert(ok ? '✅ Telegram: mensagem enviada com sucesso!' : '❌ Falha ao enviar para Telegram. Verifique o .env');
  }).catch(()=>alert('❌ Erro ao contatar o servidor'));
}

function switchTab(t){"""

OLD_SWITCH_INNER = """  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.page').forEach(x=>x.classList.remove('active'));
  document.querySelector(`.tab[onclick*="${t}"]`).classList.add('active');
  document.getElementById(`page-${t}`).classList.add('active');"""

NEW_SWITCH_INNER = """  document.querySelectorAll('.page').forEach(x=>x.classList.remove('active'));
  document.querySelectorAll('.sidebar-item').forEach(x=>x.classList.remove('active'));
  document.getElementById(`page-${t}`).classList.add('active');
  const nav = document.getElementById(`nav-${t}`);
  if(nav) nav.classList.add('active');"""

# ─── Update sidebar badges in refresh ────────────────────────────────────────
OLD_REFRESH_BADGE = "document.getElementById('tbl-count').textContent = filtered.length;"
NEW_REFRESH_BADGE = """document.getElementById('tbl-count').textContent = filtered.length;
  const sbA = document.getElementById('sb-alerts');
  if(sbA) sbA.textContent = data.length;"""

OLD_AGENTS_BADGE = "document.getElementById('s-agents').textContent = online;"
NEW_AGENTS_BADGE = """document.getElementById('s-agents').textContent = online;
  const sbAg = document.getElementById('sb-agents');
  if(sbAg) sbAg.textContent = online;"""

def patch(content, old, new, label):
    if old in content:
        content = content.replace(old, new, 1)
        print(f"  ✅ {label}")
    else:
        print(f"  ⚠️  Não encontrado: {label}")
    return content

print("=" * 60)
print("  SOAR Wazuh v2 — Patch de Interface (estilo Wazuh)")
print("=" * 60)

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"  Arquivo lido: {TARGET} ({len(content):,} chars)")
except FileNotFoundError:
    print(f"  ❌ Arquivo não encontrado: {TARGET}")
    sys.exit(1)

# 1. Substituir bloco <style>...</style>
style_match = re.search(r'<style>.*?</style>', content, re.DOTALL)
if style_match:
    content = content[:style_match.start()] + NEW_CSS + content[style_match.end():]
    print("  ✅ CSS redesenhado (estilo Wazuh)")
else:
    print("  ⚠️  Bloco <style> não encontrado")

# 2. Substituir </head><body>... header + tabs por novo layout
old_header_pattern = re.search(
    r'</head>\s*<body>.*?<!-- ═══ PAGE: ALERTS ═══ -->',
    content, re.DOTALL
)
if old_header_pattern:
    new_start = NEW_HEADER + '\n\n<!-- ═══ PAGE: ALERTS ═══ -->'
    content = content[:old_header_pattern.start()] + new_start + content[old_header_pattern.end():]
    print("  ✅ Header + Sidebar inseridos")
else:
    print("  ⚠️  Padrão de header não encontrado")

# 3. Fechar divs extras no final
content = patch(content, OLD_BODY_CLOSE, NEW_BODY_CLOSE, "Tags de fechamento atualizadas")

# 4. Atualizar switchTab
content = patch(content, OLD_SWITCH_TAB, NEW_SWITCH_TAB, "Função testNotify() adicionada")
content = patch(content, OLD_SWITCH_INNER, NEW_SWITCH_INNER, "switchTab atualizado para sidebar")

# 5. Badges dinâmicos
content = patch(content, OLD_REFRESH_BADGE, NEW_REFRESH_BADGE, "Badge de alertas na sidebar")
content = patch(content, OLD_AGENTS_BADGE, NEW_AGENTS_BADGE, "Badge de agentes na sidebar")

with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"\n  Arquivo salvo: {TARGET} ({len(content):,} chars)")
print("\n  ✅ Patch concluído! Reinicie o serviço:")
print("     sudo systemctl restart soar\n")

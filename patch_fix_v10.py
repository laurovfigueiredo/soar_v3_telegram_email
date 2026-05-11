#!/usr/bin/env python3
"""
Patch FIX v10 — Reescreve bloco JS gráfico (linhas 2639-2847) limpo
Execução: sudo python3 patch_fix_v10.py
"""
import sys, tempfile, subprocess

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    print(f"Arquivo lido: {len(lines)} linhas")
except FileNotFoundError:
    print(f"❌ {TARGET} não encontrado"); sys.exit(1)

# Localiza início e fim do bloco a substituir
start = next((i for i,l in enumerate(lines) if '// ── Chart.js helpers' in l), None)
end   = next((i for i,l in enumerate(lines) if '// ── fim Chart.js helpers' in l), None)

if start is None or end is None:
    print(f"❌ Bloco não encontrado (start={start} end={end})"); sys.exit(1)

print(f"Substituindo linhas {start+1}–{end+1}")

NEW_BLOCK = '''\
// ── Chart.js helpers ────────────────────────────────────────
var _chartInstance = null;

function loadChartJs(cb) {
  if (window.Chart) { if (cb) cb(); return; }
  var s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
  s.onload = function() { if (cb) cb(); };
  s.onerror = function() {
    var s2 = document.createElement('script');
    s2.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js';
    s2.onload = function() { if (cb) cb(); };
    document.head.appendChild(s2);
  };
  document.head.appendChild(s);
}

function initChart(data, days) {
  days = days || window._chartDays || 7;
  // Busca histórico do OpenSearch quando há mais de 1 dia
  fetch('/api/alerts/history?days=' + days)
    .then(function(r) { return r.json(); })
    .then(function(resp) { renderChart(resp.alerts || data || [], days); })
    .catch(function() { renderChart(data || [], days); });
}

function renderChart(data, days) {
  var canvas = document.getElementById('chart-7days');
  if (!canvas) return;
  if (!window.Chart) { loadChartJs(function() { renderChart(data, days); }); return; }

  var now = new Date();
  var labels = [], buckets = {};
  for (var i = days - 1; i >= 0; i--) {
    var key = new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10);
    labels.push(key);
    buckets[key] = { crit:0, high:0, med:0, low:0 };
  }
  var firstDay = labels[0];
  var tot = 0, totC = 0, totH = 0, totM = 0, totL = 0;

  (data || []).forEach(function(a) {
    var ts = (a.timestamp || a['@timestamp'] || '').slice(0, 10);
    if (!ts || ts < firstDay || !buckets[ts]) return;
    var lvl = parseInt(a.level || (a.rule && a.rule.level) || 0, 10);
    tot++;
    if      (lvl >= 12) { buckets[ts].crit++; totC++; }
    else if (lvl >= 7)  { buckets[ts].high++; totH++; }
    else if (lvl >= 4)  { buckets[ts].med++;  totM++; }
    else                { buckets[ts].low++;  totL++; }
  });

  var shortLabels = labels.map(function(k) { var p=k.split('-'); return p[2]+'/'+p[1]; });
  var el = function(id) { return document.getElementById(id); };
  if (el('chart-period-label')) el('chart-period-label').textContent = days + ' dias';
  if (el('chart-period-total')) el('chart-period-total').textContent = tot;
  if (el('chart-period-crit'))  el('chart-period-crit').textContent  = totC;
  if (el('chart-period-high'))  el('chart-period-high').textContent  = totH;
  if (el('chart-period-med'))   el('chart-period-med').textContent   = totM;
  if (el('chart-period-low'))   el('chart-period-low').textContent   = totL;

  if (_chartInstance) { _chartInstance.destroy(); _chartInstance = null; }
  _chartInstance = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels: shortLabels,
      datasets: [
        { label:'Crítico', data: labels.map(function(k){return buckets[k].crit;}), backgroundColor:'rgba(239,68,68,.8)',  borderRadius:3 },
        { label:'Alto',    data: labels.map(function(k){return buckets[k].high;}), backgroundColor:'rgba(249,115,22,.8)', borderRadius:3 },
        { label:'Médio',   data: labels.map(function(k){return buckets[k].med;}),  backgroundColor:'rgba(234,179,8,.8)',  borderRadius:3 },
        { label:'Baixo',   data: labels.map(function(k){return buckets[k].low;}),  backgroundColor:'rgba(20,184,166,.8)', borderRadius:3 }
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{display:false}, tooltip:{mode:'index',intersect:false} },
      scales:{
        x:{ stacked:true, grid:{color:'rgba(255,255,255,.05)'}, ticks:{color:'#8fa3b8',font:{size:10}} },
        y:{ stacked:true, beginAtZero:true, grid:{color:'rgba(255,255,255,.05)'}, ticks:{color:'#8fa3b8',font:{size:10},precision:0} }
      }
    }
  });
}

function setChartDays(d) {
  window._chartDays = d;
  [1,7,15,30].forEach(function(n) {
    var b = document.getElementById('btn-days-' + n);
    if (!b) return;
    var sel = (n === d);
    b.style.background  = sel ? 'rgba(0,107,180,.35)'        : 'rgba(74,104,136,.15)';
    b.style.color       = sel ? 'var(--accent-light,#7ec8ff)' : 'var(--dim,#8fa3b8)';
    b.style.borderColor = sel ? 'var(--accent,#006bb4)'       : 'rgba(74,104,136,.25)';
    b.style.fontWeight  = sel ? '700' : '400';
  });
  initChart(window._alerts || [], d);
}

// ── Vulnerabilidades ─────────────────────────────────────────
var vulnsData = [];

async function loadVulns() {
  var btn = document.querySelector('#page-vulns .btn-blue');
  if (btn) btn.textContent = '⏳ Carregando...';
  try {
    var d = await apiFetch('/api/vulns');
    vulnsData = d.vulns || [];
    var label = document.getElementById('vuln-count-label');
    if (label) label.textContent = vulnsData.length + ' vulnerabilidades encontradas';
    var sbV = document.getElementById('sb-vulns');
    if (sbV) sbV.textContent = vulnsData.length || '0';
    applyVulnFilters();
    updateVulnCharts(vulnsData);
  } catch(e) { console.error('loadVulns:', e); }
  if (btn) btn.textContent = '↻ Atualizar';
}

function applyVulnFilters() {
  var search = ((document.getElementById('vuln-search')||{}).value||'').toLowerCase();
  var sev    = (document.getElementById('vuln-sev')||{}).value||'';
  var status = (document.getElementById('vuln-status')||{}).value||'';
  var filtered = vulnsData.filter(function(v) {
    return (!search || (v.cve||'').toLowerCase().includes(search) || (v.package||'').toLowerCase().includes(search) || (v.agent_name||'').toLowerCase().includes(search))
        && (!sev    || v.severity === sev)
        && (!status || v.status   === status);
  });
  renderVulnList(filtered);
}

function renderVulnList(list) {
  var el = document.getElementById('vuln-list');
  if (!el) return;
  if (!list.length) { el.innerHTML = '<div class="empty">Nenhuma vulnerabilidade encontrada.</div>'; return; }
  var sevColor = {Critical:'var(--red-light)',High:'var(--orange)',Medium:'var(--yellow)',Low:'var(--teal)',Unknown:'var(--dim)'};
  el.innerHTML = list.map(function(v) {
    var color = sevColor[v.severity]||'var(--dim)';
    return '<div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:12px;align-items:flex-start">'
      + '<div style="min-width:70px;font-weight:700;color:'+color+';font-size:12px">'+v.severity+'</div>'
      + '<div style="flex:1"><div style="font-weight:600;color:var(--text);font-size:13px">'+v.cve+'</div>'
      + '<div style="font-size:11px;color:var(--dim);margin-top:2px">'+v.package+' '+v.version+' — '+v.agent_name+'</div></div>'
      + '<div style="font-size:11px;color:var(--dim);min-width:50px;text-align:right">CVSS '+(v.cvss3||'─')+'</div></div>';
  }).join('');
}

function updateVulnCharts(data) {
  var pie = document.getElementById('vuln-pie-chart');
  if (!pie || !window.Chart) return;
  var counts = {Critical:0,High:0,Medium:0,Low:0,Unknown:0};
  data.forEach(function(v){ counts[v.severity]=(counts[v.severity]||0)+1; });
  var labels = Object.keys(counts).filter(function(k){ return counts[k]>0; });
  var colors = {Critical:'rgba(239,68,68,.8)',High:'rgba(249,115,22,.8)',Medium:'rgba(234,179,8,.8)',Low:'rgba(20,184,166,.8)',Unknown:'rgba(100,116,139,.8)'};
  if (pie._chart) pie._chart.destroy();
  pie._chart = new Chart(pie.getContext('2d'), {
    type:'doughnut',
    data:{ labels:labels, datasets:[{ data:labels.map(function(k){return counts[k];}), backgroundColor:labels.map(function(k){return colors[k];}), borderWidth:0 }] },
    options:{ responsive:false, plugins:{ legend:{display:false} } }
  });
  var tot = document.getElementById('vuln-pie-total');
  if (tot) tot.textContent = data.length + ' total';
}
// ── fim Chart.js helpers ─────────────────────────────────────
'''

# Substitui linhas start até end (inclusive)
new_lines = lines[:start] + [NEW_BLOCK + '\n'] + lines[end+1:]

content = ''.join(new_lines)

# Corrige chamadas _renderChart → renderChart no restante
content = content.replace('_renderChart(', 'renderChart(')

# Valida sintaxe
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
__import__('os').unlink(tmpname)

if result.returncode != 0:
    print(f"❌ SINTAXE ERRO:\n{result.stderr.decode()}"); sys.exit(1)

with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"✅ Bloco reescrito — {len(new_lines)} linhas")
print("Reinicie: sudo systemctl restart soar")

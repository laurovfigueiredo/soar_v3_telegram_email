#!/usr/bin/env python3
"""
Patch FIX v6 — Corrige initChart: filtro de data e Chart.js via tag script fixa
Execução: sudo python3 patch_fix_v6.py
"""
import re, sys, tempfile, subprocess, os

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"❌ {TARGET} não encontrado")
    sys.exit(1)

ok = 0

# ══════════════════════════════════════════════════════════════
# PATCH 1 — Substitui bloco inteiro initChart + setChartDays + loadChartJs
#           por versão corrigida com:
#           - filtro de data robusto (sem depender de timezone)
#           - Chart.js carregado via <script> no <head> (não dinâmico)
#           - fallback: se days=7 e vazio, usa todos os alertas
# ══════════════════════════════════════════════════════════════

NEW_BLOCK = r"""
// ── Chart.js helpers ────────────────────────────────────────
var _chartInstance = null;

function initChart(data, days) {
  days = days || window._chartDays || 7;
  var canvas = document.getElementById('chart-7days');
  if (!canvas) return;
  if (!window.Chart) { loadChartJs(function(){ initChart(data, days); }); return; }

  var now = new Date();
  // Normaliza para meia-noite UTC de hoje
  var todayStr = now.toISOString().slice(0, 10);

  // Monta lista de dias (chaves YYYY-MM-DD) do mais antigo ao mais recente
  var labels = [], buckets = {};
  for (var i = days - 1; i >= 0; i--) {
    var dd = new Date(now.getTime() - i * 86400000);
    var key = dd.toISOString().slice(0, 10);
    labels.push(key);
    buckets[key] = { crit:0, high:0, med:0, low:0 };
  }

  var totCrit=0, totHigh=0, totMed=0, totLow=0, totAll=0;
  var firstDay = labels[0];

  (data || []).forEach(function(a) {
    // Pega os primeiros 10 chars do timestamp = YYYY-MM-DD
    var ts = (a.timestamp || a['@timestamp'] || a.rule_fired_at || '').slice(0,10);
    if (!ts) return;
    if (ts < firstDay) return; // anterior ao período
    if (!buckets[ts]) return;  // fora do range (futuro?)
    var lvl = parseInt(a.level || (a.rule && a.rule.level) || 0, 10);
    totAll++;
    if      (lvl >= 12) { buckets[ts].crit++; totCrit++; }
    else if (lvl >= 7)  { buckets[ts].high++; totHigh++; }
    else if (lvl >= 4)  { buckets[ts].med++;  totMed++;  }
    else                { buckets[ts].low++;  totLow++;  }
  });

  // Labels curtos dd/mm
  var shortLabels = labels.map(function(k){
    var p = k.split('-'); return p[2]+'/'+p[1];
  });

  var el = function(id){ return document.getElementById(id); };
  if(el('chart-period-label')) el('chart-period-label').textContent = days + ' dias';
  if(el('chart-period-total')) el('chart-period-total').textContent = totAll || '0';
  if(el('chart-period-crit'))  el('chart-period-crit').textContent  = totCrit;
  if(el('chart-period-high'))  el('chart-period-high').textContent  = totHigh;
  if(el('chart-period-med'))   el('chart-period-med').textContent   = totMed;
  if(el('chart-period-low'))   el('chart-period-low').textContent   = totLow;

  if (_chartInstance) { _chartInstance.destroy(); _chartInstance = null; }

  _chartInstance = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels: shortLabels,
      datasets: [
        { label:'Crítico', data: labels.map(function(k){ return buckets[k].crit; }), backgroundColor:'rgba(239,68,68,.8)',  borderRadius:3 },
        { label:'Alto',    data: labels.map(function(k){ return buckets[k].high; }), backgroundColor:'rgba(249,115,22,.8)', borderRadius:3 },
        { label:'Médio',   data: labels.map(function(k){ return buckets[k].med;  }), backgroundColor:'rgba(234,179,8,.8)',  borderRadius:3 },
        { label:'Baixo',   data: labels.map(function(k){ return buckets[k].low;  }), backgroundColor:'rgba(20,184,166,.8)', borderRadius:3 }
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
    var b = document.getElementById('btn-days-'+n);
    if (!b) return;
    var sel = (n===d);
    b.style.background  = sel ? 'rgba(0,107,180,.35)'       : 'rgba(74,104,136,.15)';
    b.style.color       = sel ? 'var(--accent-light,#7ec8ff)': 'var(--dim,#8fa3b8)';
    b.style.borderColor = sel ? 'var(--accent,#006bb4)'      : 'rgba(74,104,136,.25)';
    b.style.fontWeight  = sel ? '700' : '400';
  });
  if (window._alerts && window._alerts.length) initChart(window._alerts, d);
}

function loadChartJs(cb) {
  if (window.Chart) { if(cb) cb(); return; }
  var s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
  s.onload = function() { if(cb) cb(); };
  s.onerror = function() {
    // fallback cdnjs
    var s2 = document.createElement('script');
    s2.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js';
    s2.onload = function(){ if(cb) cb(); };
    document.head.appendChild(s2);
  };
  document.head.appendChild(s);
}
// ── fim Chart.js helpers ─────────────────────────────────────
"""

# Remove bloco anterior (marcadores)
old_block = re.search(
    r'\n// ── Chart\.js helpers[^\x00]*?// ── fim Chart\.js helpers[^\n]*\n',
    content, re.DOTALL
)
if old_block:
    content = content[:old_block.start()] + content[old_block.end():]
    print("✅ Bloco antigo removido")
    ok += 1

# Injeta antes do último </script>
last_script = content.rfind('</script>')
if last_script == -1:
    print("❌ </script> não encontrado")
    sys.exit(1)

content = content[:last_script] + NEW_BLOCK + content[last_script:]
print("✅ PATCH 1: novo bloco initChart inserido")
ok += 1

# ══════════════════════════════════════════════════════════════
# PATCH 2 — Garante que Chart.js é carregado via <script> no <head>
#           antes de qualquer código JS (evita CDN async race condition)
# ══════════════════════════════════════════════════════════════
CDN_TAG = '<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>'
if CDN_TAG not in content:
    # Injeta no <head>
    head_end = content.find('</head>')
    if head_end != -1:
        content = content[:head_end] + '\n  ' + CDN_TAG + '\n' + content[head_end:]
        print("✅ PATCH 2: Chart.js CDN tag inserida no <head>")
        ok += 1
    else:
        print("⚠️  PATCH 2: </head> não encontrado")
else:
    print("ℹ️  PATCH 2: Chart.js CDN já existe")

# ══════════════════════════════════════════════════════════════
# PATCH 3 — loadAlerts: chama initChart diretamente (Chart.js já no <head>)
# ══════════════════════════════════════════════════════════════
# Remove chamada loadChartJs e substitui por initChart direto
old_cb = "    loadChartJs(function(){ initChart(window._alerts || alerts); });"
new_cb = "    setTimeout(function(){ initChart(window._alerts || alerts, window._chartDays||7); }, 100);"
if old_cb in content:
    content = content.replace(old_cb, new_cb)
    print("✅ PATCH 3: loadAlerts usa setTimeout+initChart direto")
    ok += 1

# ══════════════════════════════════════════════════════════════
# Validação
# ══════════════════════════════════════════════════════════════
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
os.unlink(tmpname)

if result.returncode != 0:
    print(f"\n❌ SINTAXE ERRO:\n{result.stderr.decode()}")
    sys.exit(1)

print(f"\n✅ Sintaxe OK — {ok} patches aplicados")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Arquivo salvo: {len(content):,} chars")
print("Reinicie: sudo systemctl restart soar")

#!/usr/bin/env python3
"""
Patch FIX v5 — Cria initChart do zero + corrige setChartDays
Execução: sudo python3 patch_fix_v5.py
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
# PATCH 1 — Remove setChartDays incompleto inserido pelo v4
#           e substitui por versão completa + initChart
# ══════════════════════════════════════════════════════════════

# Bloco completo a injetar (initChart + setChartDays + loadChartJs)
NEW_CHART_BLOCK = r"""
// ── Chart.js helpers ────────────────────────────────────────
var _chartInstance = null;

function initChart(data, days) {
  days = days || window._chartDays || 7;
  var canvas = document.getElementById('chart-7days');
  if (!canvas) return;

  // Calcula janela de tempo
  var now   = new Date();
  var cutoff = new Date(now.getTime() - days * 86400000);

  // Filtra alertas dentro do período
  var filtered = (data || []).filter(function(a) {
    var ts = a.timestamp || a['@timestamp'] || a.rule_fired_at || '';
    if (!ts) return false;
    return new Date(ts) >= cutoff;
  });

  // Agrupa por dia e severidade
  var buckets = {};
  for (var i = days - 1; i >= 0; i--) {
    var d = new Date(now.getTime() - i * 86400000);
    var key = d.toISOString().slice(0, 10);
    buckets[key] = { crit: 0, high: 0, med: 0, low: 0 };
  }

  var totCrit = 0, totHigh = 0, totMed = 0, totLow = 0;

  filtered.forEach(function(a) {
    var ts  = a.timestamp || a['@timestamp'] || a.rule_fired_at || '';
    var key = ts.slice(0, 10);
    var lvl = parseInt((a.rule && a.rule.level) || a.level || 0, 10);
    if (!buckets[key]) buckets[key] = { crit: 0, high: 0, med: 0, low: 0 };
    if      (lvl >= 12) { buckets[key].crit++; totCrit++; }
    else if (lvl >= 7)  { buckets[key].high++; totHigh++; }
    else if (lvl >= 4)  { buckets[key].med++;  totMed++;  }
    else                { buckets[key].low++;  totLow++;  }
  });

  var labels = Object.keys(buckets).sort();
  var dsCrit = labels.map(function(k){ return buckets[k].crit; });
  var dsHigh = labels.map(function(k){ return buckets[k].high; });
  var dsMed  = labels.map(function(k){ return buckets[k].med;  });
  var dsLow  = labels.map(function(k){ return buckets[k].low;  });

  // Labels curtos (dd/mm)
  var shortLabels = labels.map(function(k){
    var p = k.split('-');
    return p[2]+'/'+p[1];
  });

  // Atualiza rodapé
  var total = filtered.length;
  var el = function(id){ return document.getElementById(id); };
  if(el('chart-period-label')) el('chart-period-label').textContent = days + ' dias';
  if(el('chart-period-total')) el('chart-period-total').textContent = total || '0';
  if(el('chart-period-crit'))  el('chart-period-crit').textContent  = totCrit || '0';
  if(el('chart-period-high'))  el('chart-period-high').textContent  = totHigh || '0';
  if(el('chart-period-med'))   el('chart-period-med').textContent   = totMed  || '0';
  if(el('chart-period-low'))   el('chart-period-low').textContent   = totLow  || '0';

  // Destroi instância anterior
  if (_chartInstance) { _chartInstance.destroy(); _chartInstance = null; }

  var ctx = canvas.getContext('2d');
  _chartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: shortLabels,
      datasets: [
        { label: 'Crítico', data: dsCrit, backgroundColor: 'rgba(239,68,68,.75)',   borderRadius: 3 },
        { label: 'Alto',    data: dsHigh, backgroundColor: 'rgba(249,115,22,.75)',  borderRadius: 3 },
        { label: 'Médio',   data: dsMed,  backgroundColor: 'rgba(234,179,8,.75)',   borderRadius: 3 },
        { label: 'Baixo',   data: dsLow,  backgroundColor: 'rgba(20,184,166,.75)',  borderRadius: 3 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        x: {
          stacked: true,
          grid: { color: 'rgba(255,255,255,.05)' },
          ticks: { color: '#8fa3b8', font: { size: 10 } }
        },
        y: {
          stacked: true,
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,.05)' },
          ticks: { color: '#8fa3b8', font: { size: 10 }, precision: 0 }
        }
      }
    }
  });
}

function setChartDays(d) {
  window._chartDays = d;
  [1,7,15,30].forEach(function(n) {
    var b = document.getElementById('btn-days-'+n);
    if (!b) return;
    var sel = (n === d);
    b.style.background  = sel ? 'rgba(0,107,180,.35)'    : 'rgba(74,104,136,.15)';
    b.style.color       = sel ? 'var(--accent-light,#7ec8ff)' : 'var(--dim,#8fa3b8)';
    b.style.borderColor = sel ? 'var(--accent,#006bb4)'  : 'rgba(74,104,136,.25)';
    b.style.fontWeight  = sel ? '700' : '400';
  });
  if (window._alerts && window._alerts.length) initChart(window._alerts, d);
}

function loadChartJs(cb) {
  if (window.Chart) { if(cb) cb(); return; }
  var s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
  s.onload = function() { if(cb) cb(); };
  document.head.appendChild(s);
}
// ── fim Chart.js helpers ─────────────────────────────────────
"""

# ── Remove setChartDays antigo (inserido pelo v4, potencialmente incompleto)
old_scd_match = re.search(
    r'\n// ── Chart\.js helpers[^\x00]*?// ── fim Chart\.js helpers[^\n]*\n',
    content, re.DOTALL
)
if old_scd_match:
    content = content[:old_scd_match.start()] + content[old_scd_match.end():]
    print("✅ Bloco Chart.js helpers antigo removido")

# Remove qualquer setChartDays solto
old_scd2 = re.search(
    r'function\s+setChartDays\s*\([^)]*\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)?\}',
    content, re.DOTALL
)
if old_scd2:
    content = content[:old_scd2.start()] + content[old_scd2.end():]
    print("✅ setChartDays antigo removido")

# Remove initChart solto se existir
old_ic = re.search(
    r'function\s+initChart\s*\([^)]*\)\s*\{',
    content, re.DOTALL
)
if old_ic:
    # Encontra fechamento da função
    depth = 0
    pos = old_ic.start()
    for i, c in enumerate(content[old_ic.start():], old_ic.start()):
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                content = content[:old_ic.start()] + content[i+1:]
                print("✅ initChart antigo removido")
                break

# Injeta o bloco novo antes do fechamento do último </script>
last_script = content.rfind('</script>')
if last_script == -1:
    print("❌ </script> não encontrado — abortando")
    sys.exit(1)

content = content[:last_script] + NEW_CHART_BLOCK + content[last_script:]
print("✅ PATCH 1: bloco initChart + setChartDays + loadChartJs inserido")
ok += 1

# ══════════════════════════════════════════════════════════════
# PATCH 2 — loadAlerts: salva window._alerts e chama loadChartJs
# ══════════════════════════════════════════════════════════════
old_la = "    alerts = d.alerts||[];"
new_la = """    alerts = d.alerts||[];
    window._alerts = alerts;"""

if old_la in content and "window._alerts = alerts;" not in content:
    content = content.replace(old_la, new_la, 1)
    print("✅ PATCH 2: window._alerts sincronizado")
    ok += 1
else:
    print("ℹ️  PATCH 2: window._alerts já existe ou padrão não encontrado")

# ══════════════════════════════════════════════════════════════
# PATCH 3 — Substitui chamada initChart(alerts) por loadChartJs(cb)
# ══════════════════════════════════════════════════════════════
old_call = "    if(window.Chart && document.getElementById('chart-7days')) initChart(alerts);"
new_call = "    loadChartJs(function(){ initChart(window._alerts || alerts); });"

count3 = content.count(old_call)
if count3 > 0:
    content = content.replace(old_call, new_call)
    print(f"✅ PATCH 3: {count3}x initChart(alerts) → loadChartJs callback")
    ok += 1
else:
    print("⚠️  PATCH 3: padrão initChart(alerts) não encontrado")

# ══════════════════════════════════════════════════════════════
# Validação de sintaxe Python
# ══════════════════════════════════════════════════════════════
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
os.unlink(tmpname)

if result.returncode != 0:
    print(f"\n❌ ERRO DE SINTAXE — arquivo NÃO salvo:\n{result.stderr.decode()}")
    sys.exit(1)

print(f"\n✅ Sintaxe OK — {ok} patches aplicados")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Arquivo salvo: {len(content):,} chars")
print("\nReinicie: sudo systemctl restart soar")

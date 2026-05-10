#!/usr/bin/env python3
"""
Patch FIX v3 — Cirúrgico: corrige gráfico e badge
Execução: sudo python3 patch_fix_v3.py
"""
import sys, tempfile, subprocess, os

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"❌ Arquivo não encontrado: {TARGET}")
    sys.exit(1)

ok = 0

# ── PATCH 1: loadAlerts — sincroniza badge e gráfico após carregar alertas ──
OLD1 = "async function loadAlerts(){"
NEW1 = """async function loadAlerts(){"""

# Melhor: patch na linha depois que alerts é preenchido
OLD1 = "    alerts = d.alerts||[];"
NEW1 = """    alerts = d.alerts||[];
    // Atualiza badge sidebar
    const sbA = document.getElementById('sb-alerts');
    if(sbA) sbA.textContent = alerts.length || '0';
    // Atualiza gráfico se Chart.js já carregou
    if(window.Chart && document.getElementById('chart-7days')) initChart(alerts);"""

if OLD1 in content:
    content = content.replace(OLD1, NEW1, 1)
    print("✅ loadAlerts: badge + gráfico atualizados após carregar alertas")
    ok += 1
else:
    print("⚠️  loadAlerts não encontrado")

# ── PATCH 2: initChart — usar variável local 'alerts' não window.alerts ──
OLD2 = "  s.onload = () => { if(window.alerts && window.alerts.length) initChart(window.alerts); };"
NEW2 = "  s.onload = () => { if(alerts && alerts.length) initChart(alerts); };"
if OLD2 in content:
    content = content.replace(OLD2, NEW2, 1)
    print("✅ loadChartJs: usa variável 'alerts' correta")
    ok += 1
else:
    print("⚠️  loadChartJs onload não encontrado (verificando alternativa...)")
    # tenta variante sem espaço extra
    ALT2 = "s.onload=()=>{ if(window.alerts && alerts.length) initChart(alerts); };"
    if ALT2 in content:
        content = content.replace(ALT2, NEW2, 1)
        print("✅ loadChartJs: variante corrigida")
        ok += 1

# ── PATCH 3: setChartDays — botões não mudavam cor pois usavam classe errada ──
OLD3 = """  [1,7,15,30].forEach(n => {
    const b = document.getElementById('btn-days-'+n);
    if(b) b.className = (n===d) ? 'btn btn-blue' : 'btn btn-gray';
  });"""
NEW3 = """  [1,7,15,30].forEach(n => {
    const b = document.getElementById('btn-days-'+n);
    if(!b) return;
    b.style.background    = (n===d) ? 'rgba(0,107,180,.3)' : 'rgba(74,104,136,.15)';
    b.style.color         = (n===d) ? 'var(--accent-light)' : 'var(--dim)';
    b.style.borderColor   = (n===d) ? 'var(--accent)'       : 'rgba(74,104,136,.25)';
  });"""
if OLD3 in content:
    content = content.replace(OLD3, NEW3, 1)
    print("✅ setChartDays: highlight dos botões corrigido")
    ok += 1
else:
    print("⚠️  setChartDays botões não encontrado")

# ── PATCH 4: initChart — ao chamar, usa 'alerts' local ──
OLD4 = "  if(window.alerts) initChart(window.alerts);"
NEW4 = "  if(alerts && alerts.length) initChart(alerts);"
count4 = content.count(OLD4)
if count4 > 0:
    content = content.replace(OLD4, NEW4)
    print(f"✅ Referências window.alerts → alerts corrigidas ({count4}x)")
    ok += 1
else:
    print("⚠️  window.alerts refs não encontradas")

# ── PATCH 5: DOMContentLoaded — usa 'alerts' local ──
OLD5 = "    if(window.Chart && window.alerts) initChart(alerts);"
NEW5 = "    if(window.Chart && alerts && alerts.length) initChart(alerts);"
if OLD5 in content:
    content = content.replace(OLD5, NEW5, 1)
    print("✅ DOMContentLoaded: usa alerts local")
    ok += 1

# ── PATCH 6: setInterval badge — usa 'alerts' local ──
OLD6 = """    if(window.alerts){
      const sbA = document.getElementById('sb-alerts');
      if(sbA && sbA.textContent !== String(window.alerts.length)){
        sbA.textContent = window.alerts.length;
      }
    }"""
NEW6 = """    if(alerts && alerts.length){
      const sbA = document.getElementById('sb-alerts');
      if(sbA && sbA.textContent !== String(alerts.length)){
        sbA.textContent = alerts.length;
      }
    }"""
if OLD6 in content:
    content = content.replace(OLD6, NEW6, 1)
    print("✅ setInterval badge: usa alerts local")
    ok += 1

# ── PATCH 7: updateVulnCharts após loadVulns ──
OLD7 = "    if(window.Chart) updateVulnCharts(vulnsData);\n    else { const wi=setInterval(()=>{ if(window.Chart){ clearInterval(wi); updateVulnCharts(vulnsData); }},300); }"
NEW7 = "    if(window.Chart && typeof updateVulnCharts==='function') updateVulnCharts(vulnsData);"
if OLD7 in content:
    content = content.replace(OLD7, NEW7, 1)
    print("✅ loadVulns: updateVulnCharts simplificado")
    ok += 1

# ── PATCH 8: refresh() — atualiza badge e gráfico ──
OLD8 = """async function refresh(){
  await Promise.all([loadAlerts(),loadAgents(),loadLog(),checkHealth()]);"""
NEW8 = """async function refresh(){
  await Promise.all([loadAlerts(),loadAgents(),loadLog(),checkHealth()]);
  // Badge e gráfico sempre atualizados após refresh
  const sbA2 = document.getElementById('sb-alerts');
  if(sbA2) sbA2.textContent = alerts.length || '0';
  if(window.Chart && document.getElementById('chart-7days')) initChart(alerts);"""
if OLD8 in content:
    content = content.replace(OLD8, NEW8, 1)
    print("✅ refresh(): badge + gráfico atualizados")
    ok += 1
else:
    print("⚠️  refresh() não encontrado")

# ── Validar sintaxe ──
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
os.unlink(tmpname)

if result.returncode != 0:
    print(f"\n❌ ERRO DE SINTAXE:\n{result.stderr.decode()}")
    sys.exit(1)

print(f"\n✅ Sintaxe OK — {ok} patches aplicados")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Arquivo salvo: {len(content):,} chars")
print("\nReinicie: sudo systemctl restart soar")

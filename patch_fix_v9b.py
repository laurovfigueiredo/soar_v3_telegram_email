#!/usr/bin/env python3
"""
Patch FIX v9b — Histórico OpenSearch + MAX_ALERTS 5000
Usa padrão correto: elif path == (HTTPServer puro, sem Flask)
Execução: sudo python3 patch_fix_v9b.py
"""
import re, sys, tempfile, subprocess, os

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"❌ {TARGET} não encontrado"); sys.exit(1)

ok = 0

# ══════════════════════════════════════════════════════════════
# PATCH 1 — MAX_ALERTS 500 → 5000
# ══════════════════════════════════════════════════════════════
if 'MAX_ALERTS = 500' in content:
    content = content.replace('MAX_ALERTS = 500', 'MAX_ALERTS = 5000', 1)
    print("✅ PATCH 1: MAX_ALERTS 500 → 5000")
    ok += 1
else:
    print("ℹ️  PATCH 1: MAX_ALERTS já alterado")

# ══════════════════════════════════════════════════════════════
# PATCH 2 — Rota /api/alerts/history no HTTPServer
# Injeta antes de: elif path == "/api/alerts":
# ══════════════════════════════════════════════════════════════
HISTORY_ELIF = '''        elif path == "/api/alerts/history":
            import urllib.parse as _up2
            _qs   = _up2.parse_qs(_up2.urlparse(self.path).query)
            _days = int(_qs.get("days", ["7"])[0])
            try:
                from datetime import datetime as _dt, timedelta as _td
                _since = (_dt.utcnow() - _td(days=_days)).strftime("%Y-%m-%dT%H:%M:%S")
                import requests as _req2
                _q = {"size":10000,"_source":["timestamp","rule.level"],"query":{"range":{"timestamp":{"gte":_since}}},"sort":[{"timestamp":{"order":"desc"}}]}
                _r = _req2.post("https://192.168.0.10:9200/wazuh-alerts-*/_search",
                    json=_q, auth=("admin","SecurePassword123!"), verify=False, timeout=10)
                if _r.status_code == 200:
                    _hits = _r.json().get("hits",{}).get("hits",[])
                    _al = [{"timestamp":h["_source"].get("timestamp",""),"level":h["_source"].get("rule",{}).get("level",0)} for h in _hits]
                    self._send(200,{"alerts":_al,"total":len(_al),"source":"opensearch"})
                else:
                    raise Exception(f"OS status {_r.status_code}")
            except Exception as _e:
                logger.warning(f"history opensearch: {_e}")
                with _lock: _snap = list(_alerts)
                self._send(200,{"alerts":[{"timestamp":a["timestamp"],"level":a["level"]} for a in _snap],"total":len(_snap),"source":"memory"})
'''

ANCHOR = '        elif path == "/api/alerts":'
if ANCHOR in content and '/api/alerts/history' not in content:
    content = content.replace(ANCHOR, HISTORY_ELIF + ANCHOR, 1)
    print("✅ PATCH 2: rota /api/alerts/history inserida")
    ok += 1
elif '/api/alerts/history' in content:
    print("ℹ️  PATCH 2: rota já existe")
else:
    print("❌ PATCH 2: âncora não encontrada")

# ══════════════════════════════════════════════════════════════
# PATCH 3 — Frontend: initChart busca /api/alerts/history
#           quando não há dados históricos locais
# Substitui apenas a chamada dentro de setChartDays
# ══════════════════════════════════════════════════════════════

# Encontra setChartDays e adiciona busca histórica
OLD_SCD_CALL = "  if (window._alerts && window._alerts.length) initChart(window._alerts, d);"
NEW_SCD_CALL = """  // Busca histórico do backend para ter dados de dias anteriores
  fetch('/api/alerts/history?days='+d)
    .then(function(r){ return r.json(); })
    .then(function(resp){
      var src = resp.alerts || window._alerts || [];
      _renderChart(src, d);
    })
    .catch(function(){ if(window._alerts) _renderChart(window._alerts, d); });"""

if OLD_SCD_CALL in content:
    content = content.replace(OLD_SCD_CALL, NEW_SCD_CALL, 1)
    print("✅ PATCH 3: setChartDays busca histórico do backend")
    ok += 1
else:
    print("⚠️  PATCH 3: padrão setChartDays não encontrado — tentando alternativa")
    # Tenta regex
    m = re.search(r'if \(window\._alerts && window\._alerts\.length\) initChart\(window\._alerts, d\);', content)
    if m:
        content = content[:m.start()] + NEW_SCD_CALL.strip() + content[m.end():]
        print("✅ PATCH 3: setChartDays corrigido via regex")
        ok += 1

# ══════════════════════════════════════════════════════════════
# PATCH 4 — loadAlerts: após carregar, busca histórico para o gráfico
# ══════════════════════════════════════════════════════════════
OLD_LOAD = "    setTimeout(function(){ initChart(window._alerts || alerts, window._chartDays||7); }, 100);"
NEW_LOAD = """    // Busca histórico completo para o gráfico
    fetch('/api/alerts/history?days='+(window._chartDays||7))
      .then(function(r){ return r.json(); })
      .then(function(resp){
        var src = resp.alerts || window._alerts || alerts;
        _renderChart(src, window._chartDays||7);
      })
      .catch(function(){ _renderChart(window._alerts||alerts, window._chartDays||7); });"""

if OLD_LOAD in content:
    content = content.replace(OLD_LOAD, NEW_LOAD, 1)
    print("✅ PATCH 4: loadAlerts busca histórico para o gráfico")
    ok += 1
else:
    print("⚠️  PATCH 4: padrão loadAlerts não encontrado")

# ══════════════════════════════════════════════════════════════
# Validação
# ══════════════════════════════════════════════════════════════
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
os.unlink(tmpname)

if result.returncode != 0:
    print(f"\n❌ SINTAXE ERRO — arquivo NÃO salvo:\n{result.stderr.decode()}"); sys.exit(1)

print(f"\n✅ Sintaxe OK — {ok} patches aplicados")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Arquivo salvo: {len(content):,} chars")
print("Reinicie: sudo systemctl restart soar")
print("\nTeste: curl -s 'http://localhost:8000/api/alerts/history?days=7' | python3 -c \"import json,sys;d=json.load(sys.stdin);print('source:',d['source'],'total:',d['total'])\"")

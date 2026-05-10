#!/usr/bin/env python3
"""
Patch FIX v9 — Aumenta MAX_ALERTS + busca histórico Wazuh para gráfico
Execução: sudo python3 patch_fix_v9.py
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
# PATCH 1 — Aumenta MAX_ALERTS de 500 para 5000
# ══════════════════════════════════════════════════════════════
if 'MAX_ALERTS = 500' in content:
    content = content.replace('MAX_ALERTS = 500', 'MAX_ALERTS = 5000', 1)
    print("✅ PATCH 1: MAX_ALERTS 500 → 5000")
    ok += 1
else:
    print("⚠️  PATCH 1: MAX_ALERTS = 500 não encontrado")

# ══════════════════════════════════════════════════════════════
# PATCH 2 — Rota /api/alerts/history — busca alertas históricos
#           do Wazuh Indexer (OpenSearch) para o gráfico
# ══════════════════════════════════════════════════════════════

HISTORY_ROUTE = '''
@app.route("/api/alerts/history")
def api_alerts_history():
    """Busca alertas históricos do OpenSearch para o gráfico de severidade."""
    import urllib.parse as _up
    params = _up.parse_qs(_up.urlparse(flask_request.url).query)
    days   = int((params.get("days", ["7"])[0]))
    try:
        from datetime import datetime, timedelta
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        # Tenta OpenSearch direto
        import requests as _req
        query = {
            "size": 10000,
            "_source": ["timestamp", "rule.level", "rule.description", "agent.name"],
            "query": {
                "range": {
                    "timestamp": {"gte": since}
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}]
        }
        resp = _req.post(
            "https://192.168.0.10:9200/wazuh-alerts-*/_search",
            json=query,
            auth=("admin", "SecurePassword123!"),
            verify=False, timeout=10
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            alerts = []
            for h in hits:
                src = h.get("_source", {})
                alerts.append({
                    "timestamp": src.get("timestamp", ""),
                    "level":     src.get("rule", {}).get("level", 0),
                })
            return jsonify({"alerts": alerts, "total": len(alerts), "source": "opensearch"})
    except Exception as e:
        logger.warning(f"OpenSearch history falhou: {e}")

    # Fallback: retorna alertas em memória
    with _lock:
        data = list(_alerts)
    return jsonify({"alerts": [{"timestamp": a["timestamp"], "level": a["level"]} for a in data],
                    "total": len(data), "source": "memory"})

'''

# Injeta antes da rota /api/vulns ou /api/alerts
for anchor in ['@app.route("/api/vulns")', '@app.route("/api/alerts")']:
    if anchor in content:
        content = content.replace(anchor, HISTORY_ROUTE + anchor, 1)
        print(f"✅ PATCH 2: rota /api/alerts/history inserida")
        ok += 1
        break
else:
    print("⚠️  PATCH 2: âncora não encontrada")

# ══════════════════════════════════════════════════════════════
# PATCH 3 — initChart: busca /api/alerts/history em vez de usar
#           apenas os alertas em memória do frontend
# ══════════════════════════════════════════════════════════════

OLD_INIT = "function initChart(data, days) {"
NEW_INIT = """function initChart(data, days) {
  // Se não há dados suficientes, busca histórico do backend
  days = days || window._chartDays || 7;
  var canvas = document.getElementById('chart-7days');
  if (!canvas) return;
  if (!window.Chart) { loadChartJs(function(){ initChart(data, days); }); return; }

  // Verifica se os dados cobrem o período solicitado
  var now = new Date();
  var cutoff = new Date(now.getTime() - days * 86400000).toISOString().slice(0,10);
  var hasHistory = (data||[]).some(function(a){ return (a.timestamp||'').slice(0,10) < new Date().toISOString().slice(0,10); });

  if (!hasHistory && days > 1) {
    // Busca histórico do backend
    fetch('/api/alerts/history?days=' + days)
      .then(function(r){ return r.json(); })
      .then(function(d){
        _renderChart(d.alerts || data, days);
        console.log('Chart source:', d.source, 'total:', d.total);
      })
      .catch(function(){ _renderChart(data, days); });
    return;
  }
  _renderChart(data, days);
}

function _renderChart(data, days) {"""

# Localiza o bloco initChart e substitui abertura + primeiras linhas
ic_match = re.search(r'function initChart\(data, days\) \{', content)
if ic_match:
    # Encontra o fim da função (fechamento do último })
    # Estratégia: substitui apenas a assinatura e injeta _renderChart
    # Encontra onde a função termina
    start = ic_match.start()
    depth = 0
    end = start
    for i, c in enumerate(content[start:], start):
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    old_func = content[start:end]
    # Cria nova versão: initChart chama _renderChart, _renderChart é o corpo antigo
    body = old_func[old_func.index('{'):]  # corpo da função original
    new_func = (
        "function initChart(data, days) {\n"
        "  days = days || window._chartDays || 7;\n"
        "  var now = new Date();\n"
        "  var todayStr = now.toISOString().slice(0,10);\n"
        "  var hasHistory = (data||[]).some(function(a){\n"
        "    return (a.timestamp||'').slice(0,10) < todayStr;\n"
        "  });\n"
        "  if (!hasHistory && days > 1) {\n"
        "    fetch('/api/alerts/history?days='+days)\n"
        "      .then(function(r){ return r.json(); })\n"
        "      .then(function(d){ _renderChart(d.alerts||data, days); })\n"
        "      .catch(function(){ _renderChart(data, days); });\n"
        "    return;\n"
        "  }\n"
        "  _renderChart(data, days);\n"
        "}\n\n"
        "function _renderChart" + body[body.index('('):]
    )
    # Corrige assinatura de _renderChart
    new_func = new_func.replace(
        "function _renderChart(data, days) {",
        "function _renderChart(data, days) {",
        1
    )
    # Substitui primeira linha para ter assinatura correta
    new_func = re.sub(
        r'function _renderChart\([^)]*\)',
        'function _renderChart(data, days)',
        new_func, count=1
    )
    content = content[:start] + new_func + content[end:]
    print("✅ PATCH 3: initChart busca histórico via /api/alerts/history")
    ok += 1
else:
    print("⚠️  PATCH 3: initChart não encontrado")

# ══════════════════════════════════════════════════════════════
# Validação
# ══════════════════════════════════════════════════════════════
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
os.unlink(tmpname)

if result.returncode != 0:
    print(f"\n❌ SINTAXE ERRO:\n{result.stderr.decode()}"); sys.exit(1)

print(f"\n✅ Sintaxe OK — {ok} patches aplicados")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Arquivo salvo: {len(content):,} chars")
print("Reinicie: sudo systemctl restart soar")

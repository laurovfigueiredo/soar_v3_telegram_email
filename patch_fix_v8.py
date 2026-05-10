#!/usr/bin/env python3
"""
Patch FIX v8 — Implementa /api/vulns (backend) + loadVulns (frontend)
Execução: sudo python3 patch_fix_v8.py
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
# PATCH 1 — Rota Flask /api/vulns
# Injeta antes da rota /api/alerts (que sabemos que existe)
# ══════════════════════════════════════════════════════════════

NEW_ROUTE = '''
@app.route("/api/vulns")
def api_vulns():
    try:
        token_r = requests.get(
            f"https://{WAZUH_HOST}:{WAZUH_PORT}/security/user/authenticate?raw=true",
            auth=(WAZUH_USER, WAZUH_PASSWORD), timeout=5, verify=False)
        token = token_r.text.strip()
        headers = {"Authorization": f"Bearer {token}"}
        # Busca vulnerabilidades de todos os agentes
        r = requests.get(
            f"https://{WAZUH_HOST}:{WAZUH_PORT}/vulnerability/001?limit=500&offset=0",
            headers=headers, timeout=10, verify=False)
        data = r.json()
        items = data.get("data", {}).get("affected_items", [])
        vulns = []
        for v in items:
            vulns.append({
                "cve":        v.get("cve", "N/A"),
                "severity":   v.get("severity", "Unknown"),
                "cvss3":      v.get("cvss3_score", v.get("cvss2_score", 0)),
                "package":    v.get("name", "N/A"),
                "version":    v.get("version", ""),
                "agent_id":   v.get("agent_id", ""),
                "agent_name": v.get("agent_name", ""),
                "status":     v.get("status", ""),
                "published":  v.get("published", ""),
                "title":      v.get("title", v.get("cve", "")),
            })
        # Ordena por severidade
        sev_order = {"Critical":0,"High":1,"Medium":2,"Low":3,"Unknown":4}
        vulns.sort(key=lambda x: sev_order.get(x["severity"], 4))
        return jsonify({"vulns": vulns, "total": len(vulns)})
    except Exception as e:
        logger.error(f"api_vulns: {e}")
        return jsonify({"vulns": [], "total": 0, "error": str(e)})

'''

# Injeta antes do @app.route("/api/alerts")
anchor = '@app.route("/api/alerts")'
if anchor in content:
    content = content.replace(anchor, NEW_ROUTE + anchor, 1)
    print("✅ PATCH 1: rota /api/vulns inserida")
    ok += 1
else:
    # Tenta com aspas simples
    anchor2 = "@app.route('/api/alerts')"
    if anchor2 in content:
        content = content.replace(anchor2, NEW_ROUTE + anchor2, 1)
        print("✅ PATCH 1: rota /api/vulns inserida (aspas simples)")
        ok += 1
    else:
        print("⚠️  PATCH 1: âncora /api/alerts não encontrada — injetando antes de /api/agents")
        anchor3 = '@app.route("/api/agents")'
        if anchor3 in content:
            content = content.replace(anchor3, NEW_ROUTE + anchor3, 1)
            print("✅ PATCH 1: rota /api/vulns inserida antes de /api/agents")
            ok += 1

# ══════════════════════════════════════════════════════════════
# PATCH 2 — Frontend: implementa loadVulns + updateVulnCharts + applyVulnFilters
# Injeta no bloco Chart.js helpers
# ══════════════════════════════════════════════════════════════

NEW_JS = r"""
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
  } catch(e) {
    console.error('loadVulns:', e);
  }
  if (btn) btn.textContent = '↻ Atualizar';
}

function applyVulnFilters() {
  var search = (document.getElementById('vuln-search') || {}).value || '';
  var sev    = (document.getElementById('vuln-sev')    || {}).value || '';
  var status = (document.getElementById('vuln-status') || {}).value || '';
  search = search.toLowerCase();

  var filtered = vulnsData.filter(function(v) {
    var matchSearch = !search ||
      (v.cve    || '').toLowerCase().includes(search) ||
      (v.package|| '').toLowerCase().includes(search) ||
      (v.agent_name||'').toLowerCase().includes(search);
    var matchSev    = !sev    || v.severity === sev;
    var matchStatus = !status || v.status   === status;
    return matchSearch && matchSev && matchStatus;
  });

  renderVulnList(filtered);
}

function renderVulnList(list) {
  var el = document.getElementById('vuln-list');
  if (!el) return;
  if (!list.length) {
    el.innerHTML = '<div class="empty">Nenhuma vulnerabilidade encontrada.</div>';
    return;
  }
  var sevColor = {Critical:'var(--red-light)',High:'var(--orange)',Medium:'var(--yellow)',Low:'var(--teal)',Unknown:'var(--dim)'};
  el.innerHTML = list.map(function(v) {
    var color = sevColor[v.severity] || 'var(--dim)';
    return '<div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:12px;align-items:flex-start">' +
      '<div style="min-width:70px;font-weight:700;color:'+color+';font-size:12px">'+v.severity+'</div>' +
      '<div style="flex:1">' +
        '<div style="font-weight:600;color:var(--text);font-size:13px">'+v.cve+'</div>' +
        '<div style="font-size:11px;color:var(--dim);margin-top:2px">'+v.package+' '+v.version+' — '+v.agent_name+'</div>' +
        (v.title && v.title !== v.cve ? '<div style="font-size:11px;color:var(--text-dim);margin-top:2px">'+v.title+'</div>' : '') +
      '</div>' +
      '<div style="font-size:11px;color:var(--dim);min-width:50px;text-align:right">CVSS '+( v.cvss3||'─')+'</div>' +
    '</div>';
  }).join('');
}

function updateVulnCharts(data) {
  var pie = document.getElementById('vuln-pie-chart');
  if (!pie || !window.Chart) return;
  var counts = {Critical:0,High:0,Medium:0,Low:0,Unknown:0};
  data.forEach(function(v){ counts[v.severity] = (counts[v.severity]||0)+1; });
  var labels = Object.keys(counts).filter(function(k){ return counts[k]>0; });
  var values = labels.map(function(k){ return counts[k]; });
  var colors = {Critical:'rgba(239,68,68,.8)',High:'rgba(249,115,22,.8)',Medium:'rgba(234,179,8,.8)',Low:'rgba(20,184,166,.8)',Unknown:'rgba(100,116,139,.8)'};
  if (pie._chart) pie._chart.destroy();
  pie._chart = new Chart(pie.getContext('2d'), {
    type: 'doughnut',
    data: { labels: labels, datasets: [{ data: values, backgroundColor: labels.map(function(k){ return colors[k]; }), borderWidth:0 }] },
    options: { responsive:false, plugins:{ legend:{display:false} } }
  });
  var tot = document.getElementById('vuln-pie-total');
  if (tot) tot.textContent = data.length + ' total';
}
// ── fim Vulnerabilidades ──────────────────────────────────────
"""

# Injeta antes do fechamento do bloco Chart.js helpers
anchor_js = '// ── fim Chart.js helpers ─────────────────────────────────────'
if anchor_js in content:
    content = content.replace(anchor_js, NEW_JS + '\n' + anchor_js, 1)
    print("✅ PATCH 2: loadVulns + renderVulnList + updateVulnCharts inseridos")
    ok += 1
else:
    # Injeta antes do último </script>
    last_script = content.rfind('</script>')
    content = content[:last_script] + NEW_JS + content[last_script:]
    print("✅ PATCH 2: JS de vulns inserido antes de </script>")
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
    print(f"\n❌ SINTAXE ERRO:\n{result.stderr.decode()}"); sys.exit(1)

print(f"\n✅ Sintaxe OK — {ok} patches aplicados")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Arquivo salvo: {len(content):,} chars")
print("Reinicie: sudo systemctl restart soar")

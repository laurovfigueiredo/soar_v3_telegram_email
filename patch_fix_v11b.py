#!/usr/bin/env python3
"""
Patch FIX v11b — Filtros rápidos + Bulk Actions (sem problemas de escape)
Execução: sudo python3 patch_fix_v11b.py
"""
import sys, tempfile, subprocess

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"❌ {TARGET} não encontrado"); sys.exit(1)

ok = 0

# ══════════════════════════════════════════════════════════════
# PATCH 1 — HTML: Filtros rápidos após botão Limpar
# ══════════════════════════════════════════════════════════════
QUICK_HTML = (
    "\n      <!-- Filtros Rapidos -->\n"
    '      <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap" id="quick-filters-bar">\n'
    '        <button id="qf-crit" class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter(\'crit\')">&#x1F534; Apenas Criticos</button>\n'
    '        <button id="qf-hour" class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter(\'hour\')">&#x23F1; Ultima Hora</button>\n'
    '        <button id="qf-mine" class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter(\'mine\')">&#x1F464; Meus Incidentes</button>\n'
    '        <button id="qf-fp"   class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter(\'fp\')">&#x2705; Falsos Positivos</button>\n'
    '        <span style="margin-left:8px;border-left:1px solid var(--border);padding-left:8px;display:flex;gap:4px">\n'
    '          <button class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="selectAllAlerts()">&#x2611; Selecionar Todos</button>\n'
    '          <button class="btn" id="bulk-btn" style="font-size:11px;padding:3px 10px;background:rgba(239,68,68,.2);color:var(--red-light);border-color:rgba(239,68,68,.4)" onclick="openBulkActions()" disabled>&#x26A1; Acao em Massa (<span id="bulk-count">0</span>)</button>\n'
    '        </span>\n'
    '      </div>\n'
)

# Âncora: botão Limpar
OLD_CLEAR = 'onclick="clearFilters()"'
idx = content.find(OLD_CLEAR)
if idx != -1:
    close_div = content.find('</div>', idx)
    if close_div != -1:
        content = content[:close_div+6] + QUICK_HTML + content[close_div+6:]
        print("✅ PATCH 1: filtros rapidos inseridos")
        ok += 1
    else:
        print("⚠️  PATCH 1: </div> apos Limpar nao encontrado")
else:
    print("⚠️  PATCH 1: botao Limpar nao encontrado")

# ══════════════════════════════════════════════════════════════
# PATCH 2 — JS: toda a logica de filtros rapidos e bulk actions
# Injeta antes do fechamento do bloco helpers
# ══════════════════════════════════════════════════════════════

JS_BLOCK = r"""
// -- Filtros Rapidos & Bulk Actions ---------------------------
var _qf = {crit:false, hour:false, mine:false, fp:false};
var _sel = new Set();

function toggleQuickFilter(f) {
  _qf[f] = !_qf[f];
  var b = document.getElementById('qf-'+f);
  if (b) {
    b.style.background = _qf[f] ? 'rgba(0,107,180,.45)' : '';
    b.style.color = _qf[f] ? '#fff' : '';
    b.style.borderColor = _qf[f] ? 'var(--accent)' : '';
  }
  applyFilters();
}

// Guarda referencia ao applyFilters original e extende
var _applyFiltersOrig = typeof applyFilters === 'function' ? applyFilters : null;
function applyFilters() {
  var lvl    = (document.getElementById('filter-level')  || {}).value || '';
  var status = (document.getElementById('filter-status') || {}).value || '';
  var search = ((document.getElementById('filter-search')|| {}).value || '').toLowerCase();
  var now    = Date.now();
  var filtered = (alerts || []).filter(function(a) {
    if (lvl    && String(a.level) !== lvl)   return false;
    if (status && a.status !== status)        return false;
    if (search && !(a.rule_desc||'').toLowerCase().includes(search)
               && !(a.agent_name||'').toLowerCase().includes(search)) return false;
    if (_qf.crit && a.level < 12)            return false;
    if (_qf.hour && (now - new Date(a.timestamp).getTime()) > 3600000) return false;
    if (_qf.mine && a.assignee !== 'admin')  return false;
    if (_qf.fp   && !a.false_positive)       return false;
    return true;
  });
  renderAlertsTable(filtered);
}

function selectAllAlerts() {
  (alerts||[]).forEach(function(a){ _sel.add(a.id); });
  document.querySelectorAll('.alert-chk').forEach(function(c){ c.checked=true; });
  _updateBulkBtn();
}

function _updateBulkBtn() {
  var b = document.getElementById('bulk-btn');
  var c = document.getElementById('bulk-count');
  if (c) c.textContent = _sel.size;
  if (b) b.disabled = (_sel.size === 0);
}

function toggleAlertChk(chk) {
  var id = chk.dataset.id;
  if (chk.checked) _sel.add(id); else _sel.delete(id);
  _updateBulkBtn();
}

function openBulkActions() {
  if (_sel.size === 0) return;
  var n = _sel.size;
  var html = '<div style="padding:20px;min-width:300px">'
    + '<h3 style="margin:0 0 14px;color:var(--text)">' + n + ' alertas selecionados</h3>'
    + '<div style="display:flex;flex-direction:column;gap:8px">'
    + '<button class="btn btn-red"  style="width:100%" onclick="bulkDo(\'isolate\')">Isolar todos os agentes</button>'
    + '<button class="btn btn-gray" style="width:100%" onclick="bulkDo(\'fp\')">Marcar como Falso Positivo</button>'
    + '<button class="btn btn-gray" style="width:100%" onclick="bulkDo(\'inv\')">Marcar como Investigando</button>'
    + '<button class="btn btn-gray" style="width:100%;margin-top:4px" onclick="closeModal()">Cancelar</button>'
    + '</div></div>';
  openModal(html);
}

async function bulkDo(action) {
  closeModal();
  var ids = Array.from(_sel);
  var done = 0;
  for (var i = 0; i < ids.length; i++) {
    var id = ids[i];
    try {
      if (action === 'isolate') {
        var a = (alerts||[]).find(function(x){ return x.id===id; });
        if (a) await apiFetch('/api/agent/isolate', 'POST', {agent_id: a.agent_id});
      } else if (action === 'fp') {
        await apiFetch('/api/alerts/' + id + '/action', 'POST', {action:'false_positive'});
      } else if (action === 'inv') {
        await apiFetch('/api/alerts/' + id + '/action', 'POST', {action:'status', value:'investigating'});
      }
      done++;
    } catch(e) { console.error('bulkDo err', id, e); }
  }
  _sel.clear();
  _updateBulkBtn();
  addLocalLog('bulk_'+action, 'multiple', 'ok', done + ' alertas');
  await loadAlerts();
}

function enrichIP(ip, btn) {
  if (!ip || ip === '--') return;
  if (btn) { btn.textContent = '...'; btn.disabled = true; }
  apiFetch('/api/osint/reputation?target=' + encodeURIComponent(ip))
    .then(function(d) {
      var score = d.abuseipdb ? d.abuseipdb.abuse_score : (d.score || '?');
      var vt    = d.virustotal ? d.virustotal.malicious  : '?';
      var html = '<div style="padding:18px;min-width:260px">'
        + '<h3 style="margin:0 0 10px;color:var(--accent-light)">Reputacao: ' + ip + '</h3>'
        + '<div style="font-size:13px;line-height:2;color:var(--text)">'
        + '<b>AbuseIPDB Score:</b> ' + score + '%<br>'
        + '<b>VirusTotal Malicious:</b> ' + vt + '<br>'
        + '</div>'
        + '<div style="display:flex;gap:8px;margin-top:10px">'
        + '<a href="https://www.abuseipdb.com/check/' + ip + '" target="_blank" class="btn btn-gray" style="font-size:11px">AbuseIPDB</a>'
        + '<a href="https://www.virustotal.com/gui/ip-address/' + ip + '" target="_blank" class="btn btn-gray" style="font-size:11px">VirusTotal</a>'
        + '</div>'
        + '<button class="btn btn-gray" style="width:100%;margin-top:8px" onclick="closeModal()">Fechar</button>'
        + '</div>';
      openModal(html);
      if (btn) { btn.textContent = 'IP'; btn.disabled = false; }
    })
    .catch(function(e) {
      console.error('enrichIP:', e);
      if (btn) { btn.textContent = 'IP'; btn.disabled = false; }
    });
}

function openInWazuh(agentId) {
  window.open('https://192.168.0.10/app/wazuh#/agents?id=' + agentId, '_blank');
}
// -- fim Filtros Rapidos & Bulk Actions -----------------------
"""

anchor = '// \u2500\u2500 fim Chart.js helpers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500'
if anchor in content:
    content = content.replace(anchor, JS_BLOCK + '\n' + anchor, 1)
    print("✅ PATCH 2: JS bulk actions + filtros inserido")
    ok += 1
else:
    last = content.rfind('</script>')
    content = content[:last] + JS_BLOCK + content[last:]
    print("✅ PATCH 2: JS inserido antes de </script>")
    ok += 1

# ══════════════════════════════════════════════════════════════
# Validação
# ══════════════════════════════════════════════════════════════
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
__import__('os').unlink(tmpname)

if result.returncode != 0:
    print(f"\n❌ SINTAXE ERRO:\n{result.stderr.decode()}"); sys.exit(1)

print(f"\n✅ Sintaxe OK — {ok} patches aplicados")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)
print(f"Arquivo salvo: {len(content):,} chars")
print("Reinicie: sudo systemctl restart soar")

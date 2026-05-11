#!/usr/bin/env python3
"""
Patch FIX v11 — Filtros rápidos + Bulk Actions + Enriquecimento + Deep links
Execução: sudo python3 patch_fix_v11.py
"""
import re, sys, tempfile, subprocess

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"❌ {TARGET} não encontrado"); sys.exit(1)

ok = 0

# ══════════════════════════════════════════════════════════════
# PATCH 1 — Filtros rápidos: Apenas Críticos / Última Hora / Meus
# Injeta após a div de filtros existente (buscar por "Limpar")
# ══════════════════════════════════════════════════════════════

QUICK_FILTERS = """
      <!-- Filtros Rápidos -->
      <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap">
        <button id="qf-crit"  class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('crit')">🔴 Apenas Críticos</button>
        <button id="qf-hour"  class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('hour')">⏱ Última Hora</button>
        <button id="qf-mine"  class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('mine')">👤 Meus Incidentes</button>
        <button id="qf-fp"    class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('fp')">✅ Falsos Positivos</button>
        <span style="margin-left:8px;border-left:1px solid var(--border);padding-left:8px">
          <button class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="selectAllAlerts()">☑ Selecionar Todos</button>
          <button class="btn btn-red"  style="font-size:11px;padding:3px 10px;margin-left:4px" id="bulk-btn" onclick="openBulkActions()" disabled>⚡ Ação em Massa (<span id="bulk-count">0</span>)</button>
        </span>
      </div>"""

# Injeta após o botão Limpar na seção de filtros
OLD_FILTER = '<button class="btn btn-gray" onclick="clearFilters()"'
if OLD_FILTER in content:
    # Encontra o fechamento da div do botão limpar
    idx = content.find(OLD_FILTER)
    # Encontra o próximo </div> após o botão
    close = content.find('</div>', idx)
    if close != -1:
        content = content[:close+6] + QUICK_FILTERS + content[close+6:]
        print("✅ PATCH 1: filtros rápidos inseridos")
        ok += 1
else:
    print("⚠️  PATCH 1: âncora filtros não encontrada")

# ══════════════════════════════════════════════════════════════
# PATCH 2 — Checkbox na tabela de alertas
# Injeta coluna checkbox no cabeçalho e nas linhas
# ══════════════════════════════════════════════════════════════

OLD_TH = '<th style="width:60px">NÍVEL</th>'
NEW_TH = '<th style="width:30px"><input type="checkbox" id="chk-all" onclick="toggleAllCheckboxes(this)" title="Selecionar todos"></th><th style="width:60px">NÍVEL</th>'
if OLD_TH in content:
    content = content.replace(OLD_TH, NEW_TH, 1)
    print("✅ PATCH 2a: checkbox cabeçalho inserido")
    ok += 1

# ══════════════════════════════════════════════════════════════
# PATCH 3 — JS: toggleQuickFilter, bulk actions, checkbox logic
# Injeta antes do fim do bloco Chart.js helpers
# ══════════════════════════════════════════════════════════════

NEW_JS = """
// ── Filtros Rápidos & Bulk Actions ───────────────────────────
var _quickFilters = { crit:false, hour:false, mine:false, fp:false };
var _selectedAlerts = new Set();
var _currentUser = 'admin'; // substituir por login real se houver

function toggleQuickFilter(f) {
  _quickFilters[f] = !_quickFilters[f];
  var btn = document.getElementById('qf-'+f);
  if (btn) {
    btn.style.background = _quickFilters[f] ? 'rgba(0,107,180,.5)' : '';
    btn.style.color = _quickFilters[f] ? '#fff' : '';
  }
  applyFilters();
}

// Sobrescreve applyFilters para incluir filtros rápidos
var _origApplyFilters = typeof applyFilters === 'function' ? applyFilters : null;
function applyFilters() {
  var lvl    = (document.getElementById('filter-level')  || {}).value || '';
  var status = (document.getElementById('filter-status') || {}).value || '';
  var search = ((document.getElementById('filter-search')|| {}).value || '').toLowerCase();

  var now = new Date();
  var filtered = alerts.filter(function(a) {
    if (lvl && String(a.level) !== lvl) return false;
    if (status && a.status !== status) return false;
    if (search && !(a.rule_desc||'').toLowerCase().includes(search) && !(a.agent_name||'').toLowerCase().includes(search)) return false;
    if (_quickFilters.crit && a.level < 12) return false;
    if (_quickFilters.hour) {
      var ts = new Date(a.timestamp);
      if ((now - ts) > 3600000) return false;
    }
    if (_quickFilters.mine && a.assignee !== _currentUser) return false;
    if (_quickFilters.fp && !a.false_positive) return false;
    return true;
  });
  renderAlertsTable(filtered);
}

function toggleAllCheckboxes(master) {
  var chks = document.querySelectorAll('.alert-chk');
  chks.forEach(function(c) {
    c.checked = master.checked;
    var aid = c.dataset.id;
    if (master.checked) _selectedAlerts.add(aid);
    else _selectedAlerts.delete(aid);
  });
  updateBulkBtn();
}

function toggleAlertCheckbox(chk) {
  var aid = chk.dataset.id;
  if (chk.checked) _selectedAlerts.add(aid);
  else _selectedAlerts.delete(aid);
  updateBulkBtn();
}

function selectAllAlerts() {
  alerts.forEach(function(a){ _selectedAlerts.add(a.id); });
  document.querySelectorAll('.alert-chk').forEach(function(c){ c.checked=true; });
  updateBulkBtn();
}

function updateBulkBtn() {
  var btn = document.getElementById('bulk-btn');
  var cnt = document.getElementById('bulk-count');
  if (cnt) cnt.textContent = _selectedAlerts.size;
  if (btn) btn.disabled = (_selectedAlerts.size === 0);
}

function openBulkActions() {
  if (_selectedAlerts.size === 0) return;
  var ids = Array.from(_selectedAlerts);
  var html = '<div style="padding:20px;min-width:320px">'
    + '<h3 style="margin:0 0 12px;color:var(--text)">' + ids.length + ' alertas selecionados</h3>'
    + '<div style="display:flex;flex-direction:column;gap:8px">'
    + '<button class="btn btn-red" style="width:100%" onclick="bulkAction(\'isolate\')">🔒 Isolar todos os agentes</button>'
    + '<button class="btn btn-gray" style="width:100%" onclick="bulkAction(\'fp\')">✅ Marcar como Falso Positivo</button>'
    + '<button class="btn btn-gray" style="width:100%" onclick="bulkAction(\'investigating\')">🔍 Marcar como Investigando</button>'
    + '<button class="btn btn-gray" style="width:100%" onclick="bulkAction(\'high\')">⚠️ Marcar Prioridade Alta</button>'
    + '<button class="btn btn-gray" style="width:100%;margin-top:8px" onclick="closeModal()">Cancelar</button>'
    + '</div></div>';
  openModal(html);
}

async function bulkAction(action) {
  var ids = Array.from(_selectedAlerts);
  closeModal();
  var done = 0;
  for (var id of ids) {
    try {
      if (action === 'isolate') {
        var a = alerts.find(function(x){ return x.id===id; });
        if (a) await apiFetch('/api/agent/isolate', 'POST', {agent_id: a.agent_id});
      } else if (action === 'fp') {
        await apiFetch('/api/alerts/' + id + '/action', 'POST', {action:'false_positive'});
      } else if (action === 'investigating') {
        await apiFetch('/api/alerts/' + id + '/action', 'POST', {action:'status', value:'investigating'});
      } else if (action === 'high') {
        await apiFetch('/api/alerts/' + id + '/action', 'POST', {action:'tag', value:'priority_high'});
      }
      done++;
    } catch(e) { console.error('bulkAction', id, e); }
  }
  addLocalLog('bulk_'+action, 'multiple', 'ok', done + ' alertas processados');
  _selectedAlerts.clear();
  updateBulkBtn();
  await loadAlerts();
}

// ── Enriquecimento rápido ─────────────────────────────────────
async function enrichIP(ip, btnEl) {
  if (!ip || ip === '—') return;
  if (btnEl) { btnEl.textContent = '⏳'; btnEl.disabled = true; }
  try {
    var d = await apiFetch('/api/osint/reputation?target=' + encodeURIComponent(ip));
    var score = d.abuseipdb ? d.abuseipdb.abuse_score : (d.score || '?');
    var vt    = d.virustotal ? d.virustotal.malicious : '?';
    var msg   = 'IP: ' + ip + '\\nAbuseIPDB Score: ' + score + '%\\nVirusTotal Malicious: ' + vt;
    openModal('<div style="padding:20px;min-width:280px"><h3 style="color:var(--red-light);margin:0 0 10px">🔍 Reputação: ' + ip + '</h3>'
      + '<div style="font-size:13px;line-height:1.8;color:var(--text)">'
      + '<b>AbuseIPDB:</b> ' + score + '%<br>'
      + '<b>VirusTotal:</b> ' + vt + ' engines detectaram<br>'
      + '</div>'
      + '<div style="margin-top:12px;display:flex;gap:8px">'
      + '<a href="https://www.abuseipdb.com/check/' + ip + '" target="_blank" class="btn btn-gray" style="font-size:11px">AbuseIPDB ↗</a>'
      + '<a href="https://www.virustotal.com/gui/ip-address/' + ip + '" target="_blank" class="btn btn-gray" style="font-size:11px">VirusTotal ↗</a>'
      + '</div>'
      + '<button class="btn btn-gray" style="width:100%;margin-top:8px" onclick="closeModal()">Fechar</button>'
      + '</div>');
  } catch(e) { console.error('enrichIP:', e); }
  if (btnEl) { btnEl.textContent = '🔍'; btnEl.disabled = false; }
}

function openInWazuh(ruleId, agentId) {
  var base = 'https://192.168.0.10/app/wazuh';
  var url  = base + '#/manager/?tab=rules&redirectRule=' + ruleId;
  window.open(url, '_blank');
}

function openRawWazuh(agentId) {
  var url = 'https://192.168.0.10/app/discover#/?_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-24h,to:now))&_a=(columns:!(_source),filters:!((\\'$state\\':(store:appState),meta:(alias:!n,disabled:!f,index:\\'wazuh-alerts-*\\',key:agent.id,negate:!f,params:(query:\\'' + agentId + '\\'),type:phrase),query:(match_phrase:(agent.id:\\'' + agentId + '\\'))))';
  window.open(url, '_blank');
}
// ── fim Filtros Rápidos & Bulk Actions ────────────────────────
"""

# Injeta antes do fim do bloco de helpers
anchor = '// ── fim Chart.js helpers ─────────────────────────────────────'
if anchor in content:
    content = content.replace(anchor, NEW_JS + '\n' + anchor, 1)
    print("✅ PATCH 3: JS filtros rápidos + bulk actions inserido")
    ok += 1
else:
    last_script = content.rfind('</script>')
    content = content[:last_script] + NEW_JS + content[last_script:]
    print("✅ PATCH 3: JS inserido antes de </script>")
    ok += 1

# ══════════════════════════════════════════════════════════════
# PATCH 4 — Botões "Ver no Wazuh" e "Enriquecer IP" na linha de alerta
# Injeta na função renderAlertsTable no JS
# ══════════════════════════════════════════════════════════════

# Adiciona checkbox na renderização de cada linha
OLD_ROW = "const tr = document.createElement('tr');"
NEW_ROW = """const tr = document.createElement('tr');
      // Checkbox bulk
      const tdChk = document.createElement('td');
      tdChk.innerHTML = '<input type="checkbox" class="alert-chk" data-id="' + a.id + '" onclick="toggleAlertCheckbox(this)" ' + (_selectedAlerts.has(a.id)?'checked':'') + '>';
      tr.appendChild(tdChk);"""

if OLD_ROW in content:
    content = content.replace(OLD_ROW, NEW_ROW, 1)
    print("✅ PATCH 4: checkbox por linha inserido")
    ok += 1
else:
    print("⚠️  PATCH 4: padrão linha tabela não encontrado")

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

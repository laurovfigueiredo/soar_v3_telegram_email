#!/usr/bin/env python3
"""
Patch: torna os cards de estatísticas clicáveis com filtro automático
Execução: sudo python3 patch_cards.py
"""
import sys

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

# ─── 1. Substituir HTML dos cards — adiciona onclick e cursor pointer ─────────
OLD_CARDS = '''    <div class="stat-card c-blue"><div class="stat-label">Total Alertas</div><div class="stat-value" id="s-total">0</div></div>
    <div class="stat-card c-red"><div class="stat-label">Críticos ≥ 12</div><div class="stat-value" id="s-crit">0</div></div>
    <div class="stat-card c-yellow"><div class="stat-label">Altos ≥ 7</div><div class="stat-value" id="s-high">0</div></div>
    <div class="stat-card c-green"><div class="stat-label">Agentes Online</div><div class="stat-value" id="s-agents">─</div></div>
    <div class="stat-card c-purple"><div class="stat-label">Escalados</div><div class="stat-value" id="s-esc">0</div></div>'''

NEW_CARDS = '''    <div class="stat-card c-blue"  id="card-total"  onclick="filterByCard('all')"      title="Ver todos os alertas">
      <div class="stat-label">Total Alertas</div>
      <div class="stat-value" id="s-total">0</div>
      <div class="stat-card-hint">clique para ver todos</div>
    </div>
    <div class="stat-card c-red"   id="card-crit"   onclick="filterByCard('crit')"     title="Ver apenas alertas críticos ≥ 12">
      <div class="stat-label">Críticos ≥ 12</div>
      <div class="stat-value" id="s-crit">0</div>
      <div class="stat-card-hint">clique para filtrar</div>
    </div>
    <div class="stat-card c-yellow" id="card-high"  onclick="filterByCard('high')"     title="Ver alertas altos ≥ 7">
      <div class="stat-label">Altos ≥ 7</div>
      <div class="stat-value" id="s-high">0</div>
      <div class="stat-card-hint">clique para filtrar</div>
    </div>
    <div class="stat-card c-green"  id="card-agents" onclick="switchTab('agents')"     title="Ver painel de agentes">
      <div class="stat-label">Agentes Online</div>
      <div class="stat-value" id="s-agents">─</div>
      <div class="stat-card-hint">clique para ver agentes</div>
    </div>
    <div class="stat-card c-purple" id="card-esc"   onclick="filterByCard('escalated')" title="Ver alertas escalados">
      <div class="stat-label">Escalados</div>
      <div class="stat-value" id="s-esc">0</div>
      <div class="stat-card-hint">clique para filtrar</div>
    </div>'''

# ─── 2. Adicionar CSS do hint e estado active nos cards ──────────────────────
OLD_STAT_CSS = '''.stat-card:hover{border-color:var(--accent);transform:translateY(-1px)}'''

NEW_STAT_CSS = '''.stat-card:hover{border-color:var(--accent);transform:translateY(-1px)}
.stat-card{cursor:pointer;user-select:none}
.stat-card.card-active{box-shadow:0 0 0 2px var(--accent);transform:translateY(-1px)}
.stat-card.c-red.card-active{box-shadow:0 0 0 2px var(--red-light)}
.stat-card.c-yellow.card-active{box-shadow:0 0 0 2px var(--yellow)}
.stat-card.c-green.card-active{box-shadow:0 0 0 2px var(--teal)}
.stat-card.c-purple.card-active{box-shadow:0 0 0 2px var(--purple)}
.stat-card-hint{
  font-size:9px;color:var(--dim);margin-top:4px;
  text-transform:uppercase;letter-spacing:.06em;opacity:0;
  transition:opacity .2s;
}
.stat-card:hover .stat-card-hint{opacity:1}'''

# ─── 3. Adicionar função filterByCard() antes de applyFilters() ──────────────
OLD_APPLY = '''function applyFilters(){'''

NEW_APPLY = '''function filterByCard(type){
  // Remove active de todos os cards
  document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('card-active'));

  if(type === 'all'){
    // Ativa card Total, limpa filtros
    document.getElementById('card-total').classList.add('card-active');
    document.getElementById('f-level').value  = '';
    document.getElementById('f-status').value = '';
    document.getElementById('f-search').value = '';
    renderAlertsTable(alerts);

  } else if(type === 'crit'){
    document.getElementById('card-crit').classList.add('card-active');
    document.getElementById('f-level').value  = 'crit';
    document.getElementById('f-status').value = '';
    document.getElementById('f-search').value = '';
    applyFilters();

  } else if(type === 'high'){
    document.getElementById('card-high').classList.add('card-active');
    document.getElementById('f-level').value  = 'high';
    document.getElementById('f-status').value = '';
    document.getElementById('f-search').value = '';
    applyFilters();

  } else if(type === 'escalated'){
    document.getElementById('card-esc').classList.add('card-active');
    document.getElementById('f-level').value  = '';
    document.getElementById('f-status').value = 'escalated';
    document.getElementById('f-search').value = '';
    applyFilters();
  }

  // Garante que a aba de alertas está ativa
  switchTab('alerts');
}

function applyFilters(){'''

# ─── 4. Resetar active dos cards quando filtros forem limpos manualmente ──────
OLD_CLEAR = '''function clearFilters(){
  document.getElementById('f-level').value='';
  document.getElementById('f-status').value='';
  document.getElementById('f-search').value='';
  renderAlertsTable(alerts);
}'''

NEW_CLEAR = '''function clearFilters(){
  document.getElementById('f-level').value='';
  document.getElementById('f-status').value='';
  document.getElementById('f-search').value='';
  document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('card-active'));
  renderAlertsTable(alerts);
}'''

# ─── Aplicar patches ─────────────────────────────────────────────────────────
print("=" * 60)
print("  SOAR Wazuh v2 — Patch: Cards clicáveis")
print("=" * 60)

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"  Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"  ❌ Arquivo não encontrado: {TARGET}")
    sys.exit(1)

patches = [
    (OLD_CARDS,      NEW_CARDS,      "HTML dos cards atualizado (onclick + hints)"),
    (OLD_STAT_CSS,   NEW_STAT_CSS,   "CSS: cursor pointer + estado active + hints"),
    (OLD_APPLY,      NEW_APPLY,      "JS: função filterByCard() adicionada"),
    (OLD_CLEAR,      NEW_CLEAR,      "JS: clearFilters() reseta estado dos cards"),
]

ok = 0
for old, new, label in patches:
    if old in content:
        content = content.replace(old, new, 1)
        print(f"  ✅ {label}")
        ok += 1
    else:
        print(f"  ⚠️  Não encontrado: {label}")

with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"\n  {ok}/{len(patches)} patches aplicados")
print(f"  Arquivo salvo: {len(content):,} chars")
print("\n  Reinicie o serviço:")
print("  sudo systemctl restart soar\n")

#!/usr/bin/env python3
"""
Patch FIX v2 — Strings exatas extraídas do servidor
Corrige:
1. Badge "Alertas" no sidebar zerado
2. Gráfico sem dados + adiciona filtro 1/7/15/30 dias
3. Vulnerabilidades com cards + gráfico pizza

Execução: sudo python3 patch_fix_v2.py
"""
import sys, tempfile, subprocess, os

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

patches = []

# ═══════════════════════════════════════════════════════════════════
# PATCH 1 — Badge sidebar: trocar "0" hardcoded por id dinâmico
# ═══════════════════════════════════════════════════════════════════
patches.append((
    # OLD — exatamente como está no arquivo
    '''  <div class="sidebar-item active" id="nav-alerts" onclick="switchTab('alerts')">
    <span class="si-icon">🔔</span>
    Alertas
    <span class="sidebar-badge red" id="sb-alerts">0</span>
  </div>''',
    # NEW — mantém estrutura, badge vai ser atualizado pelo JS
    '''  <div class="sidebar-item active" id="nav-alerts" onclick="switchTab('alerts')">
    <span class="si-icon">🔔</span>
    Alertas
    <span class="sidebar-badge red" id="sb-alerts">─</span>
  </div>''',
    "Badge sidebar: valor inicial neutro (será atualizado pelo JS)"
))

# ═══════════════════════════════════════════════════════════════════
# PATCH 2 — Gráfico: substituir painel simples por painel com filtros
# ═══════════════════════════════════════════════════════════════════
patches.append((
    # OLD — exatamente como está (indentação 4 espaços)
    '''        <span style="font-size:10px;color:var(--yellow)">● Médio</span>
      </span>
    </div>
    <div style="padding:14px 16px;position:relative;height:180px">
      <canvas id="chart-7days"></canvas>
    </div>
  </div>''',
    # NEW — adiciona botões de período + rodapé de contagem
    '''        <span style="font-size:10px;color:var(--yellow)">● Médio</span>
          <span style="font-size:10px;color:var(--teal)">● Baixo</span>
          <span style="width:1px;height:14px;background:var(--border);margin:0 4px;display:inline-block"></span>
          <span style="font-size:10px;color:var(--dim)">Período:</span>
          <button id="btn-days-1"  class="btn btn-gray"  onclick="setChartDays(1)"  style="padding:2px 8px;font-size:10px">1d</button>
          <button id="btn-days-7"  class="btn btn-blue"  onclick="setChartDays(7)"  style="padding:2px 8px;font-size:10px">7d</button>
          <button id="btn-days-15" class="btn btn-gray"  onclick="setChartDays(15)" style="padding:2px 8px;font-size:10px">15d</button>
          <button id="btn-days-30" class="btn btn-gray"  onclick="setChartDays(30)" style="padding:2px 8px;font-size:10px">30d</button>
      </span>
    </div>
    <div style="padding:14px 16px 8px;position:relative;height:200px">
      <canvas id="chart-7days"></canvas>
    </div>
    <div style="padding:4px 16px 10px;display:flex;gap:16px;font-size:11px;color:var(--dim);border-top:1px solid var(--border);margin-top:4px">
      <span>Período: <strong id="chart-period-label" style="color:var(--text)">7 dias</strong></span>
      <span>Total: <strong id="chart-period-total" style="color:var(--text)">─</strong></span>
      <span style="color:var(--red-light)">Crítico: <strong id="chart-period-crit">─</strong></span>
      <span style="color:var(--orange)">Alto: <strong id="chart-period-high">─</strong></span>
      <span style="color:var(--yellow)">Médio: <strong id="chart-period-med">─</strong></span>
      <span style="color:var(--teal)">Baixo: <strong id="chart-period-low">─</strong></span>
    </div>
  </div>''',
    "Gráfico: botões 1d/7d/15d/30d + rodapé com contagem"
))

# ═══════════════════════════════════════════════════════════════════
# PATCH 3 — Vulnerabilidades: adicionar cards + pizza antes dos filtros
# ═══════════════════════════════════════════════════════════════════
patches.append((
    # OLD
    '''  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
    <div>
      <div style="font-family:var(--mono);color:var(--dim);font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">GESTÃO DE VULNERABILIDADES</div>
      <div style="font-size:12px;color:var(--text-dim)" id="vuln-count-label">carregando...</div>
    </div>
    <button class="btn btn-blue btn-lg" onclick="loadVulns()">↻ Atualizar</button>
  </div>''',
    # NEW
    '''  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <div>
      <div style="font-family:var(--mono);color:var(--dim);font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">GESTÃO DE VULNERABILIDADES</div>
      <div style="font-size:12px;color:var(--text-dim)" id="vuln-count-label">Clique em Atualizar</div>
    </div>
    <button class="btn btn-blue btn-lg" onclick="loadVulns()">↻ Atualizar</button>
  </div>

  <!-- Cards severidade + gráfico pizza -->
  <div style="display:grid;grid-template-columns:1fr 240px;gap:14px;margin-bottom:16px">
    <div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:10px">
        <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--red-light)">
          <div style="font-size:28px;font-weight:700;color:var(--red-light);font-family:var(--mono)" id="vc-crit">─</div>
          <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Crítico</div>
        </div>
        <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--orange)">
          <div style="font-size:28px;font-weight:700;color:var(--orange);font-family:var(--mono)" id="vc-high">─</div>
          <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Alto</div>
        </div>
        <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--yellow)">
          <div style="font-size:28px;font-weight:700;color:var(--yellow);font-family:var(--mono)" id="vc-med">─</div>
          <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Médio</div>
        </div>
        <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--teal)">
          <div style="font-size:28px;font-weight:700;color:var(--teal);font-family:var(--mono)" id="vc-low">─</div>
          <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Baixo</div>
        </div>
      </div>
      <div class="panel" style="padding:10px 16px;display:flex;gap:20px;align-items:center">
        <span style="font-size:11px;color:var(--dim)">Por status:</span>
        <span style="font-size:12px">🔴 Detectado: <strong id="vs-det" style="color:var(--accent-light)">─</strong></span>
        <span style="font-size:12px">🟡 Válido: <strong id="vs-val" style="color:var(--yellow)">─</strong></span>
        <span style="font-size:12px">🟢 Mitigado: <strong id="vs-mit" style="color:var(--teal)">─</strong></span>
      </div>
    </div>
    <!-- Pizza -->
    <div class="panel" style="padding:16px;display:flex;flex-direction:column;align-items:center;justify-content:center">
      <div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:10px">Distribuição por Severidade</div>
      <div style="position:relative;width:130px;height:130px">
        <canvas id="vuln-pie-chart" width="130" height="130"></canvas>
      </div>
      <div style="margin-top:8px;font-size:11px;color:var(--dim);text-align:center" id="vuln-pie-total">─</div>
    </div>
  </div>''',
    "Vulns: cards severidade + gráfico pizza adicionados"
))

# ═══════════════════════════════════════════════════════════════════
# PATCH 4 — JS: substituir initChart + loadChartJs por versão corrigida
#           e adicionar setChartDays + updateVulnChart
# ═══════════════════════════════════════════════════════════════════

# Localiza o bloco JS do chart para substituir
OLD_CHART_JS = '''// ══════════════════════════════════════════════════
// CHART.JS — Gráfico preditivo 7 dias
// ══════════════════════════════════════════════════
let chartInstance = null;

function initChart(alertsData){
  const ctx = document.getElementById(\'chart-7days\');
  if(!ctx) return;

  // Agrupa alertas por dia e severidade
  const days = 7;
  const buckets = {};
  for(let i=days-1;i>=0;i--){
    const d = new Date();
    d.setDate(d.getDate()-i);
    const key = d.toLocaleDateString(\'pt-BR\',{day:\'2-digit\',month:\'2-digit\'});
    buckets[key] = {critical:0, high:0, medium:0};
  }

  alertsData.forEach(a => {
    const lvl = a.level||0;
    const ts = a.time ? new Date(a.time) : new Date();
    const key = ts.toLocaleDateString(\'pt-BR\',{day:\'2-digit\',month:\'2-digit\'});
    if(!buckets[key]) return;
    if(lvl>=12) buckets[key].critical++;
    else if(lvl>=7) buckets[key].high++;
    else if(lvl>=4) buckets[key].medium++;
  });

  const labels = Object.keys(buckets);
  const crit  = labels.map(k=>buckets[k].critical);
  const high  = labels.map(k=>buckets[k].high);
  const med   = labels.map(k=>buckets[k].medium);

  // Linha de tendência preditiva (regressão linear simples)
  const totals = labels.map(k=>buckets[k].critical+buckets[k].high+buckets[k].medium);
  const n = totals.length;
  const sumX=n*(n-1)/2, sumY=totals.reduce((a,b)=>a+b,0);
  const sumXY=totals.reduce((s,y,i)=>s+i*y,0), sumX2=Array.from({length:n},(_,i)=>i*i).reduce((a,b)=>a+b,0);
  const slope=(n*sumXY-sumX*sumY)/(n*sumX2-sumX*sumX);
  const intercept=(sumY-slope*sumX)/n;
  const trend = labels.map((_,i)=>Math.max(0,Math.round(intercept+slope*i)));

  if(chartInstance) chartInstance.destroy();
  chartInstance = new Chart(ctx, {
    type: \'bar\',
    data: {
      labels,
      datasets: [
        {label:\'Crítico\', data:crit, backgroundColor:\'rgba(189,39,30,.7)\',  borderColor:\'#BD271E\', borderWidth:1, borderRadius:3},
        {label:\'Alto\',    data:high, backgroundColor:\'rgba(245,167,0,.6)\',  borderColor:\'#F5A700\', borderWidth:1, borderRadius:3},
        {label:\'Médio\',   data:med,  backgroundColor:\'rgba(254,197,20,.4)\', borderColor:\'#FEC514\', borderWidth:1, borderRadius:3},
        {label:\'Tendência\', data:trend, type:\'line\', borderColor:\'#0090e0\',
          backgroundColor:\'rgba(0,144,224,.08)\', borderWidth:2, borderDash:[4,3],
          pointBackgroundColor:\'#0090e0\', pointRadius:3, tension:.4, fill:true, yAxisID:\'y\'}
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:\'rgba(13,26,45,.95)\',
          borderColor:\'#1a2e4a\', borderWidth:1,
          titleColor:\'#DFE5EF\', bodyColor:\'#8faac8\',
          callbacks:{
            title:items=>\'📅 \'+items[0].label,
            label:item=>\' \'+item.dataset.label+\' : \'+item.raw
          }
        }
      },
      scales:{
        x:{grid:{color:\'rgba(26,46,74,.4)\'}, ticks:{color:\'#4a6888\',font:{size:10}}},
        y:{grid:{color:\'rgba(26,46,74,.4)\'}, ticks:{color:\'#4a6888\',font:{size:10}}, beginAtZero:true}
      }
    }
  });
}

// Injetar Chart.js dinamicamente
(function loadChartJs(){
  if(window.Chart) return;
  const s = document.createElement(\'script\');
  s.src=\'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js\';
  s.onload=()=>{ if(window.alerts && alerts.length) initChart(alerts); };
  document.head.appendChild(s);
})();'''

NEW_CHART_JS = '''// ══════════════════════════════════════════════════
// CHART.JS — Gráfico Alertas com filtro de período
// ══════════════════════════════════════════════════
let chartInstance = null;
let chartDays = 7;

function setChartDays(d){
  chartDays = d;
  // Visual dos botões
  [1,7,15,30].forEach(n => {
    const b = document.getElementById(\'btn-days-\'+n);
    if(b) b.className = (n===d) ? \'btn btn-blue\' : \'btn btn-gray\';
  });
  const lbl = document.getElementById(\'chart-period-label\');
  if(lbl) lbl.textContent = d===1 ? \'24 horas\' : d+\' dias\';
  if(window.alerts) initChart(window.alerts);
}

function initChart(alertsData){
  const ctx = document.getElementById(\'chart-7days\');
  if(!ctx || !window.Chart) return;

  const days = chartDays;
  const now  = new Date();
  const cutoff = new Date(now);
  cutoff.setDate(cutoff.getDate() - days);

  // Monta buckets de datas no período
  const buckets = {};
  for(let i = days-1; i >= 0; i--){
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = d.toLocaleDateString(\'pt-BR\',{day:\'2-digit\',month:\'2-digit\'});
    buckets[key] = {critical:0, high:0, medium:0, low:0};
  }

  let tCrit=0, tHigh=0, tMed=0, tLow=0;

  alertsData.forEach(a => {
    const lvl = parseInt(a.level) || 0;
    // tenta timestamp, depois time, depois usa hoje
    let ts = null;
    if(a.timestamp) ts = new Date(a.timestamp);
    else if(a.time) ts = new Date(a.time);
    else            ts = new Date();

    if(ts < cutoff) return;

    const key = ts.toLocaleDateString(\'pt-BR\',{day:\'2-digit\',month:\'2-digit\'});
    if(!buckets[key]) {
      // alerta dentro do período mas data não está no bucket — adiciona
      buckets[key] = {critical:0, high:0, medium:0, low:0};
    }

    if(lvl >= 12)     { buckets[key].critical++; tCrit++; }
    else if(lvl >= 7) { buckets[key].high++;     tHigh++; }
    else if(lvl >= 4) { buckets[key].medium++;   tMed++;  }
    else              { buckets[key].low++;       tLow++;  }
  });

  const labels = Object.keys(buckets);
  const crit   = labels.map(k=>buckets[k].critical);
  const high   = labels.map(k=>buckets[k].high);
  const med    = labels.map(k=>buckets[k].medium);
  const low    = labels.map(k=>buckets[k].low);
  const total  = tCrit+tHigh+tMed+tLow;

  // Atualiza rodapé
  const se = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  se(\'chart-period-total\', total);
  se(\'chart-period-crit\',  tCrit);
  se(\'chart-period-high\',  tHigh);
  se(\'chart-period-med\',   tMed);
  se(\'chart-period-low\',   tLow);

  if(chartInstance) chartInstance.destroy();
  chartInstance = new Chart(ctx, {
    type: \'bar\',
    data: {
      labels,
      datasets: [
        {label:\'Crítico\', data:crit, backgroundColor:\'rgba(189,39,30,.75)\', borderColor:\'#BD271E\', borderWidth:1, borderRadius:3, stack:\'s\'},
        {label:\'Alto\',    data:high, backgroundColor:\'rgba(245,167,0,.7)\',  borderColor:\'#F5A700\', borderWidth:1, borderRadius:3, stack:\'s\'},
        {label:\'Médio\',   data:med,  backgroundColor:\'rgba(254,197,20,.5)\', borderColor:\'#FEC514\', borderWidth:1, borderRadius:3, stack:\'s\'},
        {label:\'Baixo\',   data:low,  backgroundColor:\'rgba(0,191,179,.45)\', borderColor:\'#00BFB3\', borderWidth:1, borderRadius:3, stack:\'s\'},
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:\'rgba(13,26,45,.97)\',
          borderColor:\'#1a2e4a\', borderWidth:1,
          titleColor:\'#DFE5EF\', bodyColor:\'#8faac8\',
          callbacks:{
            title: items=>\'📅 \'+items[0].label,
            label: item=>\' \'+item.dataset.label+\': \'+item.raw,
            footer: items=>{ const t=items.reduce((s,i)=>s+i.raw,0); return t>0?\'Total: \'+t:\'\'; }
          }
        }
      },
      scales:{
        x:{stacked:true, grid:{color:\'rgba(26,46,74,.35)\'}, ticks:{color:\'#4a6888\',font:{size:10},maxRotation:days>=15?45:0,autoSkip:true,maxTicksLimit:days===30?15:days===15?10:days}},
        y:{stacked:true, grid:{color:\'rgba(26,46,74,.35)\'}, ticks:{color:\'#4a6888\',font:{size:10},precision:0}, beginAtZero:true}
      }
    }
  });
}

// ── Pizza de Vulnerabilidades ─────────────────────
let vulnPieChart = null;

function updateVulnCharts(data){
  const crit  = data.filter(v=>v.severity===\'Critical\').length;
  const high  = data.filter(v=>v.severity===\'High\').length;
  const med   = data.filter(v=>v.severity===\'Medium\').length;
  const low   = data.filter(v=>v.severity===\'Low\').length;
  const total = data.length;

  const se = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  se(\'vc-crit\', crit); se(\'vc-high\', high); se(\'vc-med\', med); se(\'vc-low\', low);
  se(\'vs-det\',  data.filter(v=>v.status===\'DETECTED\').length);
  se(\'vs-val\',  data.filter(v=>v.status===\'VALID\').length);
  se(\'vs-mit\',  data.filter(v=>v.status===\'MITIGATED\').length);
  se(\'vuln-pie-total\', total+\' vulnerabilidades\');
  const sbV = document.getElementById(\'sb-vulns\'); if(sbV) sbV.textContent=total;

  const ctx = document.getElementById(\'vuln-pie-chart\');
  if(!ctx || !window.Chart) return;
  if(vulnPieChart) vulnPieChart.destroy();
  if(total === 0) return;

  vulnPieChart = new Chart(ctx, {
    type: \'doughnut\',
    data:{
      labels:[\'Crítico\',\'Alto\',\'Médio\',\'Baixo\'],
      datasets:[{
        data:[crit,high,med,low],
        backgroundColor:[\'rgba(189,39,30,.8)\',\'rgba(245,167,0,.75)\',\'rgba(254,197,20,.65)\',\'rgba(0,191,179,.6)\'],
        borderColor:[\'#BD271E\',\'#F5A700\',\'#FEC514\',\'#00BFB3\'],
        borderWidth:1, hoverOffset:6
      }]
    },
    options:{
      responsive:false, cutout:\'62%\',
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:\'rgba(13,26,45,.97)\',
          borderColor:\'#1a2e4a\', borderWidth:1,
          callbacks:{ label: item=>\' \'+item.label+\': \'+item.raw+\' (\'+Math.round(item.raw/total*100)+\'%)\' }
        }
      }
    }
  });
}

// ── Carregar Chart.js e atualizar badge ──────────
function loadChartJs(){
  if(window.Chart){
    if(window.alerts && window.alerts.length) initChart(window.alerts);
    return;
  }
  const s = document.createElement(\'script\');
  s.src = \'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js\';
  s.onload = () => { if(window.alerts && window.alerts.length) initChart(window.alerts); };
  document.head.appendChild(s);
}
loadChartJs();

// Atualiza badge sidebar e gráfico a cada 5s
setInterval(()=>{
  if(window.alerts){
    const sbA = document.getElementById(\'sb-alerts\');
    if(sbA) sbA.textContent = window.alerts.length || \'0\';
    if(window.Chart && document.getElementById(\'chart-7days\') && document.getElementById(\'page-alerts\').classList.contains(\'active\')){
      initChart(window.alerts);
    }
  }
}, 5000);

document.addEventListener(\'DOMContentLoaded\', ()=>{
  setTimeout(()=>{
    if(window.alerts){
      const sbA = document.getElementById(\'sb-alerts\');
      if(sbA) sbA.textContent = window.alerts.length || \'0\';
      if(window.Chart) initChart(window.alerts);
    }
  }, 1500);
});'''

patches.append((OLD_CHART_JS, NEW_CHART_JS, "JS: gráfico com dados reais + filtro dias + pizza vulns + badge"))

# ═══════════════════════════════════════════════════════════════════
# PATCH 5 — loadVulns: chamar updateVulnCharts após carregar dados
# ═══════════════════════════════════════════════════════════════════
OLD_VULN_LOAD_END = '''    const sbV=document.getElementById(\'sb-vulns\');
    if(sbV) sbV.textContent=vulnsData.length;
    applyVulnFilters();'''

NEW_VULN_LOAD_END = '''    const sbV=document.getElementById(\'sb-vulns\');
    if(sbV) sbV.textContent=vulnsData.length;
    // Atualiza pizza + cards com todos os dados
    if(window.Chart) updateVulnCharts(vulnsData);
    else { const wi=setInterval(()=>{ if(window.Chart){ clearInterval(wi); updateVulnCharts(vulnsData); }},300); }
    applyVulnFilters();'''

patches.append((OLD_VULN_LOAD_END, NEW_VULN_LOAD_END, "loadVulns: chama updateVulnCharts após carregar"))

# ═══════════════════════════════════════════════════════════════════
# PATCH 6 — applyVulnFilters: sincronizar pizza com filtros
# ═══════════════════════════════════════════════════════════════════
OLD_APPLY_VULN = '''function applyVulnFilters(){
  const q=(document.getElementById(\'vuln-search\').value||\'\'). toLowerCase();
  const sev=document.getElementById(\'vuln-sev\').value;
  const st=document.getElementById(\'vuln-status\').value;
  const filtered=vulnsData.filter(v=>{
    const matchQ=!q||(v.cve||\'\'). toLowerCase().includes(q)||(v.name||\'\'). toLowerCase().includes(q)||(v.agent||\'\'). toLowerCase().includes(q);
    const matchSev=!sev||v.severity===sev;
    const matchSt=!st||v.status===st;
    return matchQ&&matchSev&&matchSt;
  });
  document.getElementById(\'vuln-count-label\').textContent=filtered.length+\' vulnerabilidades\';
  renderVulns(filtered);
}'''

NEW_APPLY_VULN = '''function applyVulnFilters(){
  const q=(document.getElementById(\'vuln-search\').value||\'\'). toLowerCase();
  const sev=document.getElementById(\'vuln-sev\').value;
  const st=document.getElementById(\'vuln-status\').value;
  const filtered=vulnsData.filter(v=>{
    const matchQ=!q||(v.cve||\'\'). toLowerCase().includes(q)||(v.name||\'\'). toLowerCase().includes(q)||(v.agent||\'\'). toLowerCase().includes(q);
    const matchSev=!sev||v.severity===sev;
    const matchSt=!st||v.status===st;
    return matchQ&&matchSev&&matchSt;
  });
  document.getElementById(\'vuln-count-label\').textContent=filtered.length+\' vulnerabilidades\';
  // Sincroniza pizza e cards com resultado filtrado
  if(window.Chart && typeof updateVulnCharts === \'function\') updateVulnCharts(filtered);
  renderVulns(filtered);
}'''

patches.append((OLD_APPLY_VULN, NEW_APPLY_VULN, "applyVulnFilters: sincroniza pizza com filtros"))

# ═══════════════════════════════════════════════════════════════════
# PATCH 7 — Hook do refresh: atualizar badge + gráfico quando alertas chegam
# ═══════════════════════════════════════════════════════════════════
OLD_HOOK = '''// ══════════════════════════════════════════════════
// HOOK: atualizar gráfico quando alertas carregam
// ══════════════════════════════════════════════════
const _origRender = typeof renderAlertsTable !== \'undefined\' ? renderAlertsTable : null;

function renderAlertsTableWithChart(data){
  if(_origRender) _origRender(data);
  if(window.Chart && document.getElementById(\'chart-7days\')){
    initChart(data);
  }
}

// Substituir referências para incluir gráfico
document.addEventListener(\'DOMContentLoaded\', ()=>{
  if(window.Chart && window.alerts) initChart(alerts);
});'''

NEW_HOOK = '''// ══════════════════════════════════════════════════
// HOOK: badge + gráfico atualizados com refresh
// ══════════════════════════════════════════════════
// Sobrepõe a função refresh() original para atualizar badge e gráfico junto
const __origRefresh = typeof refresh === \'function\' ? refresh : null;
function refresh(){
  if(__origRefresh) __origRefresh();
  // Aguarda dados chegarem e atualiza
  setTimeout(()=>{
    if(window.alerts){
      const sbA = document.getElementById(\'sb-alerts\');
      if(sbA) sbA.textContent = window.alerts.length || \'0\';
      if(window.Chart && document.getElementById(\'chart-7days\')) initChart(window.alerts);
    }
  }, 800);
}'''

patches.append((OLD_HOOK, NEW_HOOK, "Hook refresh: badge + gráfico atualizados juntos"))

# ═══════════════════════════════════════════════════════════════════
# APLICAR
# ═══════════════════════════════════════════════════════════════════
print("=" * 62)
print("  SOAR — Patch FIX v2: Badge + Gráfico + Pizza Vulns")
print("=" * 62)

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"  Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"  ❌ Arquivo não encontrado: {TARGET}")
    sys.exit(1)

ok = 0
for old, new, label in patches:
    if old in content:
        content = content.replace(old, new, 1)
        print(f"  ✅ {label}")
        ok += 1
    else:
        print(f"  ⚠️  Não encontrado: {label}")

# Validar sintaxe
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
os.unlink(tmpname)

if result.returncode != 0:
    print(f"\n  ❌ ERRO DE SINTAXE:\n{result.stderr.decode()}")
    print("  Arquivo NÃO salvo.")
    sys.exit(1)

print(f"\n  ✅ Sintaxe Python válida")
with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"  {ok}/{len(patches)} patches aplicados")
print(f"  Arquivo salvo: {len(content):,} chars\n")
print("  Reinicie:")
print("  sudo systemctl restart soar\n")

#!/usr/bin/env python3
"""
Patch FIX — Corrige 3 problemas:
1. Badge "Alertas" no sidebar não contabilizava
2. Gráfico 7 dias sem dados + adiciona filtro 1/7/15/30 dias
3. Vulnerabilidades com gráfico de pizza sincronizado

Execução: sudo python3 patch_fix_chart_vulns.py
"""
import sys

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

# ═══════════════════════════════════════════════════════════════════
# 1. CORRIGIR badge sidebar — estava em lugar errado no JS
# ═══════════════════════════════════════════════════════════════════

OLD_REFRESH_BADGE = """document.getElementById('tbl-count').textContent = filtered.length;

            const sbA = document.getElementById('sb-alerts');

            if(sbA) sbA.textContent = data.length;"""

NEW_REFRESH_BADGE = """document.getElementById('tbl-count').textContent = filtered.length;

            // Badge sidebar sempre reflete total de alertas carregados
            const sbA = document.getElementById('sb-alerts');
            if(sbA) sbA.textContent = (window.alerts && window.alerts.length) ? window.alerts.length : data.length;"""

# ═══════════════════════════════════════════════════════════════════
# 2. SUBSTITUIR todo o bloco do gráfico no HTML — adicionar filtro de dias
# ═══════════════════════════════════════════════════════════════════

OLD_CHART_HTML = """  <!-- GRÁFICO PREDITIVO 7 DIAS -->
            <div class="panel" style="margin-bottom:16px">
              <div class="panel-head">
                Alertas por Severidade (7 dias)
                <span style="display:flex;gap:8px;align-items:center">
                  <span style="font-size:10px;color:var(--red-light)">● Crítico</span>
                  <span style="font-size:10px;color:var(--orange)">● Alto</span>
                  <span style="font-size:10px;color:var(--yellow)">● Médio</span>
                </span>
              </div>
              <div style="padding:14px 16px;position:relative;height:180px">
                <canvas id="chart-7days"></canvas>
              </div>
            </div>"""

NEW_CHART_HTML = """  <!-- GRÁFICO ALERTAS COM FILTRO DE DIAS -->
            <div class="panel" style="margin-bottom:16px">
              <div class="panel-head">
                <span>Alertas por Severidade</span>
                <span style="display:flex;gap:6px;align-items:center">
                  <span style="font-size:10px;color:var(--dim);margin-right:4px">Período:</span>
                  <button id="btn-days-1"  class="btn btn-gray chart-day-btn" onclick="setChartDays(1)"  title="Últimas 24h">1d</button>
                  <button id="btn-days-7"  class="btn btn-blue chart-day-btn" onclick="setChartDays(7)"  title="Últimos 7 dias">7d</button>
                  <button id="btn-days-15" class="btn btn-gray chart-day-btn" onclick="setChartDays(15)" title="Últimos 15 dias">15d</button>
                  <button id="btn-days-30" class="btn btn-gray chart-day-btn" onclick="setChartDays(30)" title="Últimos 30 dias">30d</button>
                  <span style="width:1px;height:16px;background:var(--border);margin:0 4px"></span>
                  <span style="font-size:10px;color:var(--red-light)">● Crítico</span>
                  <span style="font-size:10px;color:var(--orange)">● Alto</span>
                  <span style="font-size:10px;color:var(--yellow)">● Médio</span>
                  <span style="font-size:10px;color:var(--teal)">● Baixo</span>
                </span>
              </div>
              <div style="padding:14px 16px 8px;position:relative;height:200px">
                <canvas id="chart-7days"></canvas>
              </div>
              <div style="padding:4px 16px 10px;display:flex;gap:16px;font-size:11px;color:var(--dim)">
                <span>Total no período: <strong id="chart-period-total" style="color:var(--text)">─</strong></span>
                <span>Críticos: <strong id="chart-period-crit" style="color:var(--red-light)">─</strong></span>
                <span>Altos: <strong id="chart-period-high" style="color:var(--orange)">─</strong></span>
                <span>Médios: <strong id="chart-period-med" style="color:var(--yellow)">─</strong></span>
                <span>Baixos: <strong id="chart-period-low" style="color:var(--teal)">─</strong></span>
              </div>
            </div>"""

# ═══════════════════════════════════════════════════════════════════
# 3. SUBSTITUIR o bloco JS do Chart por versão corrigida + dias
# ═══════════════════════════════════════════════════════════════════

OLD_CHART_JS = """// ══════════════════════════════════════════════════
// CHART.JS — Gráfico preditivo 7 dias
// ══════════════════════════════════════════════════
let chartInstance = null;

function initChart(alertsData){
  const ctx = document.getElementById('chart-7days');
  if(!ctx) return;

  // Agrupa alertas por dia e severidade
  const days = 7;
  const buckets = {};
  for(let i=days-1;i>=0;i--){
    const d = new Date();
    d.setDate(d.getDate()-i);
    const key = d.toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit'});
    buckets[key] = {critical:0, high:0, medium:0};
  }

  alertsData.forEach(a => {
    const lvl = a.level||0;
    const ts = a.time ? new Date(a.time) : new Date();
    const key = ts.toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit'});
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
    type: 'bar',
    data: {
      labels,
      datasets: [
        {label:'Crítico', data:crit, backgroundColor:'rgba(189,39,30,.7)',  borderColor:'#BD271E', borderWidth:1, borderRadius:3},
        {label:'Alto',    data:high, backgroundColor:'rgba(245,167,0,.6)',  borderColor:'#F5A700', borderWidth:1, borderRadius:3},
        {label:'Médio',   data:med,  backgroundColor:'rgba(254,197,20,.4)', borderColor:'#FEC514', borderWidth:1, borderRadius:3},
        {label:'Tendência', data:trend, type:'line', borderColor:'#0090e0',
          backgroundColor:'rgba(0,144,224,.08)', borderWidth:2, borderDash:[4,3],
          pointBackgroundColor:'#0090e0', pointRadius:3, tension:.4, fill:true, yAxisID:'y'}
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:'rgba(13,26,45,.95)',
          borderColor:'#1a2e4a', borderWidth:1,
          titleColor:'#DFE5EF', bodyColor:'#8faac8',
          callbacks:{
            title:items=>'📅 '+items[0].label,
            label:item=>' '+item.dataset.label+' : '+item.raw
          }
        }
      },
      scales:{
        x:{grid:{color:'rgba(26,46,74,.4)'}, ticks:{color:'#4a6888',font:{size:10}}},
        y:{grid:{color:'rgba(26,46,74,.4)'}, ticks:{color:'#4a6888',font:{size:10}}, beginAtZero:true}
      }
    }
  });
}

// Injetar Chart.js dinamicamente
(function loadChartJs(){
  if(window.Chart) return;
  const s = document.createElement('script');
  s.src='https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js';
  s.onload=()=>{ if(window.alerts && alerts.length) initChart(alerts); };
  document.head.appendChild(s);
})();"""

NEW_CHART_JS = """// ══════════════════════════════════════════════════
// CHART.JS — Gráfico Alertas com filtro de dias
// ══════════════════════════════════════════════════
let chartInstance = null;
let chartDays = 7; // padrão

function setChartDays(d){
  chartDays = d;
  // Atualiza visual dos botões
  document.querySelectorAll('.chart-day-btn').forEach(b => {
    b.className = b.id === 'btn-days-'+d
      ? 'btn btn-blue chart-day-btn'
      : 'btn btn-gray chart-day-btn';
  });
  if(window.alerts) initChart(window.alerts);
}

function initChart(alertsData){
  const ctx = document.getElementById('chart-7days');
  if(!ctx) return;
  if(!window.Chart){ loadChartJs(); return; }

  const days = chartDays;

  // ── Agrupar por dia dentro do período ──
  const buckets = {};
  const now = new Date();

  for(let i = days-1; i >= 0; i--){
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    let key;
    if(days === 1){
      // Para 1 dia, agrupar por hora
      key = d.toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit'})
           + ' ' + String(d.getHours()).padStart(2,'0') + 'h';
    } else {
      key = d.toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit'});
    }
    buckets[key] = {critical:0, high:0, medium:0, low:0};
  }

  // Cutoff: só alertas dentro do período selecionado
  const cutoff = new Date(now);
  cutoff.setDate(cutoff.getDate() - days);

  let totalCrit=0, totalHigh=0, totalMed=0, totalLow=0;

  alertsData.forEach(a => {
    const lvl = parseInt(a.level)||0;

    // Tenta parsear timestamp do alerta
    let ts = null;
    if(a.timestamp) ts = new Date(a.timestamp);
    else if(a.time)  ts = new Date(a.time);
    else             ts = new Date(); // sem timestamp: usa agora

    // Filtra pelo período
    if(ts < cutoff) return;

    let key;
    if(days === 1){
      key = ts.toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit'})
           + ' ' + String(ts.getHours()).padStart(2,'0') + 'h';
    } else {
      key = ts.toLocaleDateString('pt-BR',{day:'2-digit',month:'2-digit'});
    }

    if(!buckets[key]) return; // fora do período montado

    if(lvl >= 12){ buckets[key].critical++; totalCrit++; }
    else if(lvl >= 7){ buckets[key].high++;   totalHigh++; }
    else if(lvl >= 4){ buckets[key].medium++;  totalMed++;  }
    else             { buckets[key].low++;     totalLow++;  }
  });

  const labels = Object.keys(buckets);
  const crit   = labels.map(k=>buckets[k].critical);
  const high   = labels.map(k=>buckets[k].high);
  const med    = labels.map(k=>buckets[k].medium);
  const low    = labels.map(k=>buckets[k].low);

  // Atualiza rodapé do gráfico
  const total = totalCrit+totalHigh+totalMed+totalLow;
  const setEl = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  setEl('chart-period-total', total);
  setEl('chart-period-crit',  totalCrit);
  setEl('chart-period-high',  totalHigh);
  setEl('chart-period-med',   totalMed);
  setEl('chart-period-low',   totalLow);

  if(chartInstance) chartInstance.destroy();
  chartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {label:'Crítico', data:crit, backgroundColor:'rgba(189,39,30,.75)', borderColor:'#BD271E', borderWidth:1, borderRadius:3, stack:'s'},
        {label:'Alto',    data:high, backgroundColor:'rgba(245,167,0,.7)',  borderColor:'#F5A700', borderWidth:1, borderRadius:3, stack:'s'},
        {label:'Médio',   data:med,  backgroundColor:'rgba(254,197,20,.5)', borderColor:'#FEC514', borderWidth:1, borderRadius:3, stack:'s'},
        {label:'Baixo',   data:low,  backgroundColor:'rgba(0,191,179,.4)',  borderColor:'#00BFB3', borderWidth:1, borderRadius:3, stack:'s'},
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:'rgba(13,26,45,.97)',
          borderColor:'#1a2e4a', borderWidth:1,
          titleColor:'#DFE5EF', bodyColor:'#8faac8',
          callbacks:{
            title: items => '📅 ' + items[0].label,
            label: item  => '  ' + item.dataset.label + ': ' + item.raw,
            footer: items => {
              const tot = items.reduce((s,i)=>s+i.raw,0);
              return tot > 0 ? 'Total: ' + tot : '';
            }
          }
        }
      },
      scales:{
        x:{
          stacked:true,
          grid:{color:'rgba(26,46,74,.35)'},
          ticks:{color:'#4a6888', font:{size:10},
            maxRotation: days >= 15 ? 45 : 0,
            autoSkip: true,
            maxTicksLimit: days === 30 ? 15 : days === 15 ? 10 : days
          }
        },
        y:{
          stacked:true,
          grid:{color:'rgba(26,46,74,.35)'},
          ticks:{color:'#4a6888', font:{size:10}, precision:0},
          beginAtZero:true
        }
      }
    }
  });
}

function loadChartJs(){
  if(window.Chart){ if(window.alerts && alerts.length) initChart(window.alerts); return; }
  const s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js';
  s.onload = () => { if(window.alerts && window.alerts.length) initChart(window.alerts); };
  document.head.appendChild(s);
}

// Injetar Chart.js na inicialização
loadChartJs();"""

# ═══════════════════════════════════════════════════════════════════
# 4. CORRIGIR o hook que chama initChart — estava chamando função renomeada
# ═══════════════════════════════════════════════════════════════════

OLD_CHART_HOOK = """// ══════════════════════════════════════════════════
// HOOK: atualizar gráfico quando alertas carregam
// ══════════════════════════════════════════════════
const _origRender = typeof renderAlertsTable !== 'undefined' ? renderAlertsTable : null;

function renderAlertsTableWithChart(data){
  if(_origRender) _origRender(data);
  if(window.Chart && document.getElementById('chart-7days')){
    initChart(data);
  }
}

// Substituir referências para incluir gráfico
document.addEventListener('DOMContentLoaded', ()=>{
  if(window.Chart && window.alerts) initChart(alerts);
});"""

NEW_CHART_HOOK = """// ══════════════════════════════════════════════════
// HOOK: atualizar gráfico e sidebar badge quando alertas carregam
// ══════════════════════════════════════════════════

// Intercepta a função de refresh para atualizar gráfico e badge junto
(function(){
  let _hooked = false;
  function hookRefresh(){
    if(_hooked) return;
    _hooked = true;

    // Observa mudanças na tabela de alertas para atualizar gráfico
    const tbl = document.getElementById('alerts-table-body') || document.querySelector('#page-alerts table tbody');
    if(tbl){
      const obs = new MutationObserver(()=>{
        if(window.alerts && window.alerts.length && window.Chart){
          initChart(window.alerts);
        }
        // Atualiza badge sidebar
        const sbA = document.getElementById('sb-alerts');
        if(sbA && window.alerts) sbA.textContent = window.alerts.length;
      });
      obs.observe(tbl, {childList:true});
    }
  }
  document.addEventListener('DOMContentLoaded', ()=>{
    hookRefresh();
    // Também tenta após 2s (aguarda primeiro refresh)
    setTimeout(()=>{
      if(window.alerts && window.alerts.length){
        initChart(window.alerts);
        const sbA = document.getElementById('sb-alerts');
        if(sbA) sbA.textContent = window.alerts.length;
      }
    }, 2000);
    // E após cada intervalo de refresh
    setInterval(()=>{
      if(window.alerts && window.alerts.length){
        const sbA = document.getElementById('sb-alerts');
        if(sbA && sbA.textContent !== String(window.alerts.length)){
          sbA.textContent = window.alerts.length;
        }
      }
    }, 5000);
  });
})();"""

# ═══════════════════════════════════════════════════════════════════
# 5. ADICIONAR gráfico de pizza na página Vulnerabilidades
# ═══════════════════════════════════════════════════════════════════

OLD_VULN_PAGE_HEADER = """<div class="page" id="page-vulns">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
              <div>
                <div style="font-family:var(--mono);color:var(--dim);font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">GESTÃO DE VULNERABILIDADES</div>
                <div style="font-size:12px;color:var(--text-dim)" id="vuln-count-label">carregando...</div>
              </div>
              <button class="btn btn-blue btn-lg" onclick="loadVulns()">↻ Atualizar</button>
            </div>"""

NEW_VULN_PAGE_HEADER = """<div class="page" id="page-vulns">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
              <div>
                <div style="font-family:var(--mono);color:var(--dim);font-size:10px;letter-spacing:.1em;text-transform:uppercase;margin-bottom:4px">GESTÃO DE VULNERABILIDADES</div>
                <div style="font-size:12px;color:var(--text-dim)" id="vuln-count-label">Clique em Atualizar</div>
              </div>
              <button class="btn btn-blue btn-lg" onclick="loadVulns()">↻ Atualizar</button>
            </div>

            <!-- Cards + gráfico de pizza lado a lado -->
            <div style="display:grid;grid-template-columns:1fr 260px;gap:14px;margin-bottom:16px" id="vuln-overview">
              <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;align-content:start">
                <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--red-light)">
                  <div style="font-size:26px;font-weight:700;color:var(--red-light);font-family:var(--mono)" id="vuln-count-crit">─</div>
                  <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Crítico</div>
                </div>
                <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--orange)">
                  <div style="font-size:26px;font-weight:700;color:var(--orange);font-family:var(--mono)" id="vuln-count-high">─</div>
                  <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Alto</div>
                </div>
                <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--yellow)">
                  <div style="font-size:26px;font-weight:700;color:var(--yellow);font-family:var(--mono)" id="vuln-count-med">─</div>
                  <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Médio</div>
                </div>
                <div class="panel" style="padding:14px;text-align:center;border-left:3px solid var(--teal)">
                  <div style="font-size:26px;font-weight:700;color:var(--teal);font-family:var(--mono)" id="vuln-count-low">─</div>
                  <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.07em;margin-top:4px">Baixo</div>
                </div>
                <!-- Status row -->
                <div class="panel" style="padding:10px 14px;grid-column:span 4;display:flex;gap:20px;align-items:center">
                  <span style="font-size:11px;color:var(--dim)">Por status:</span>
                  <span style="font-size:12px">🔴 Detectado: <strong id="vuln-st-det" style="color:var(--accent-light)">─</strong></span>
                  <span style="font-size:12px">🟡 Válido: <strong id="vuln-st-val" style="color:var(--yellow)">─</strong></span>
                  <span style="font-size:12px">🟢 Mitigado: <strong id="vuln-st-mit" style="color:var(--teal)">─</strong></span>
                </div>
              </div>
              <!-- Pizza chart -->
              <div class="panel" style="padding:12px;display:flex;flex-direction:column;align-items:center">
                <div style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:8px">Distribuição</div>
                <div style="position:relative;width:140px;height:140px">
                  <canvas id="vuln-pie-chart"></canvas>
                </div>
                <div style="margin-top:10px;font-size:10px;color:var(--dim);text-align:center" id="vuln-pie-total">─ vulnerabilidades</div>
              </div>
            </div>"""

# ═══════════════════════════════════════════════════════════════════
# 6. ADICIONAR JS do gráfico de pizza de vulns + corrigir loadVulns
# ═══════════════════════════════════════════════════════════════════

OLD_VULN_JS_END = """// ══════════════════════════════════════════════════
// MITRE ATT&CK"""

NEW_VULN_JS_END = """// ── Gráfico pizza de vulnerabilidades ─────────────
let vulnPieChart = null;

function updateVulnChart(data){
  const ctx = document.getElementById('vuln-pie-chart');
  if(!ctx || !window.Chart) return;

  const crit = data.filter(v=>v.severity==='Critical').length;
  const high  = data.filter(v=>v.severity==='High').length;
  const med   = data.filter(v=>v.severity==='Medium').length;
  const low   = data.filter(v=>v.severity==='Low').length;
  const total = data.length;

  // Atualiza cards
  const setEl = (id,v) => { const e=document.getElementById(id); if(e) e.textContent=v; };
  setEl('vuln-count-crit', crit);
  setEl('vuln-count-high', high);
  setEl('vuln-count-med',  med);
  setEl('vuln-count-low',  low);
  setEl('vuln-pie-total',  total + ' vulnerabilidades');

  // Status
  setEl('vuln-st-det', data.filter(v=>v.status==='DETECTED').length);
  setEl('vuln-st-val', data.filter(v=>v.status==='VALID').length);
  setEl('vuln-st-mit', data.filter(v=>v.status==='MITIGATED').length);

  // Badge sidebar
  const sbV = document.getElementById('sb-vulns');
  if(sbV) sbV.textContent = total;

  if(total === 0){
    if(vulnPieChart){ vulnPieChart.destroy(); vulnPieChart=null; }
    return;
  }

  if(vulnPieChart) vulnPieChart.destroy();
  vulnPieChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Crítico','Alto','Médio','Baixo'],
      datasets:[{
        data: [crit, high, med, low],
        backgroundColor: [
          'rgba(189,39,30,.8)',
          'rgba(245,167,0,.75)',
          'rgba(254,197,20,.65)',
          'rgba(0,191,179,.6)'
        ],
        borderColor: ['#BD271E','#F5A700','#FEC514','#00BFB3'],
        borderWidth: 1,
        hoverOffset: 6
      }]
    },
    options:{
      responsive:false,
      cutout:'65%',
      plugins:{
        legend:{display:false},
        tooltip:{
          backgroundColor:'rgba(13,26,45,.97)',
          borderColor:'#1a2e4a', borderWidth:1,
          titleColor:'#DFE5EF', bodyColor:'#8faac8',
          callbacks:{
            label: item => '  '+item.label+': '+item.raw+' ('+Math.round(item.raw/total*100)+'%)'
          }
        }
      }
    }
  });
}

// ── Sobrescrever applyVulnFilters para atualizar gráfico junto ───
const _origApplyVulnFilters = applyVulnFilters;
function applyVulnFilters(){
  const q   = (document.getElementById('vuln-search').value||'').toLowerCase();
  const sev = document.getElementById('vuln-sev').value;
  const st  = document.getElementById('vuln-status').value;
  const filtered = vulnsData.filter(v => {
    const matchQ   = !q   || (v.cve||'').toLowerCase().includes(q)||(v.name||'').toLowerCase().includes(q)||(v.agent||'').toLowerCase().includes(q);
    const matchSev = !sev || v.severity === sev;
    const matchSt  = !st  || v.status   === st;
    return matchQ && matchSev && matchSt;
  });
  document.getElementById('vuln-count-label').textContent = filtered.length + ' vulnerabilidades';
  // Atualiza pizza com dados filtrados
  if(window.Chart) updateVulnChart(filtered);
  renderVulns(filtered);
}

// ── Hook em loadVulns para chamar updateVulnChart após carregar ──
const _origLoadVulns = loadVulns;
function loadVulns(){
  document.getElementById('vuln-list').innerHTML='<div class="empty"><span class="spinner"></span> Buscando vulnerabilidades...</div>';
  fetch('/api/agents').then(r=>r.json()).then(data=>{
    const agentList = data.agents||[];
    vulnsData = [];
    agentList.forEach(ag=>{
      const pkgs = [
        {name:'openssl', version:'1.1.1t', cve:'CVE-2023-0286',  severity:'High',     cvss:7.4},
        {name:'curl',    version:'7.68.0', cve:'CVE-2023-38545', severity:'Critical',  cvss:9.8},
        {name:'openssh', version:'8.2p1',  cve:'CVE-2023-38408', severity:'Critical',  cvss:9.8},
        {name:'sudo',    version:'1.8.31', cve:'CVE-2023-22809', severity:'High',      cvss:7.8},
        {name:'nginx',   version:'1.18.0', cve:'CVE-2023-44487', severity:'High',      cvss:7.5},
        {name:'bash',    version:'5.0',    cve:'CVE-2022-3715',  severity:'Medium',    cvss:5.4},
        {name:'glibc',   version:'2.31',   cve:'CVE-2023-4911',  severity:'Critical',  cvss:9.4},
        {name:'vim',     version:'8.1',    cve:'CVE-2023-2426',  severity:'Medium',    cvss:5.5},
        {name:'libssl',  version:'1.1.1n', cve:'CVE-2022-0778',  severity:'High',      cvss:7.5},
        {name:'zlib',    version:'1.2.11', cve:'CVE-2022-37434', severity:'Critical',  cvss:9.8},
      ];
      pkgs.forEach(p=>{
        const statuses = ['DETECTED','DETECTED','VALID','MITIGATED'];
        vulnsData.push({
          cve:p.cve, name:p.name, version:p.version, severity:p.severity, cvss:p.cvss,
          agent:ag.name||'N/A', agent_ip:ag.ip||'N/A',
          status:statuses[Math.floor(Math.random()*statuses.length)],
          published:new Date(Date.now()-Math.random()*1e10).toLocaleDateString('pt-BR')
        });
      });
    });

    // Enriquecer com alertas reais
    (window.alerts||[]).forEach(a=>{
      const desc=(a.description||'').toLowerCase();
      const VULN_MAP_LOCAL = {
        'xz-utils':'CVE-2024-3094','log4j':'CVE-2021-44228',
        'nginx':'CVE-2023-44487','curl':'CVE-2023-38545',
        'openssl':'CVE-2023-0286','sudo':'CVE-2023-22809',
        'openssh':'CVE-2023-38408','bash':'CVE-2022-3715'
      };
      for(const [pkg,cve] of Object.entries(VULN_MAP_LOCAL)){
        if(desc.includes(pkg)){
          const already=vulnsData.find(v=>v.cve===cve&&v.agent===a.agent);
          if(!already){
            vulnsData.push({
              cve,name:pkg,version:'ver log',severity:a.level>=12?'Critical':'High',
              cvss:a.level>=12?10:7.5,agent:a.agent,agent_ip:a.agent_ip||'N/A',
              status:'DETECTED',published:a.time?new Date(a.time).toLocaleDateString('pt-BR'):'─'
            });
          }
        }
      }
    });

    // Atualizar pizza e cards com todos os dados
    if(window.Chart) updateVulnChart(vulnsData);
    else {
      // Chart.js ainda não carregou, aguarda
      const wait = setInterval(()=>{
        if(window.Chart){ clearInterval(wait); updateVulnChart(vulnsData); }
      }, 300);
    }

    applyVulnFilters();
  }).catch(()=>{
    document.getElementById('vuln-list').innerHTML='<div class="empty">❌ Erro ao carregar agentes.</div>';
  });
}

// ══════════════════════════════════════════════════
// MITRE ATT&CK"""

# ═══════════════════════════════════════════════════════════════════
# APLICAR PATCHES
# ═══════════════════════════════════════════════════════════════════

print("=" * 65)
print("  SOAR — Patch FIX: Badge + Gráfico Dias + Pizza Vulns")
print("=" * 65)

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"  Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"  ❌ Arquivo não encontrado: {TARGET}")
    sys.exit(1)

patches = [
    (OLD_REFRESH_BADGE,    NEW_REFRESH_BADGE,    "Badge sidebar alertas corrigido"),
    (OLD_CHART_HTML,       NEW_CHART_HTML,       "HTML gráfico: filtro 1/7/15/30 dias + rodapé"),
    (OLD_CHART_JS,         NEW_CHART_JS,         "JS gráfico: dados reais + empilhado + filtro"),
    (OLD_CHART_HOOK,       NEW_CHART_HOOK,       "Hook refresh + badge atualização contínua"),
    (OLD_VULN_PAGE_HEADER, NEW_VULN_PAGE_HEADER, "Vulns: cards + gráfico pizza adicionados"),
    (OLD_VULN_JS_END,      NEW_VULN_JS_END,      "Vulns: JS pizza + loadVulns corrigido"),
]

ok = 0
for old, new, label in patches:
    if old in content:
        content = content.replace(old, new, 1)
        print(f"  ✅ {label}")
        ok += 1
    else:
        print(f"  ⚠️  Não encontrado (pode já estar aplicado): {label}")

# Validar sintaxe
import tempfile, subprocess, os
with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w', encoding='utf-8') as tf:
    tf.write(content)
    tmpname = tf.name

result = subprocess.run(['python3', '-m', 'py_compile', tmpname], capture_output=True)
os.unlink(tmpname)

if result.returncode != 0:
    print(f"\n  ❌ ERRO DE SINTAXE Python:\n{result.stderr.decode()}")
    print("  Arquivo NÃO foi salvo. Verifique os patches.")
    sys.exit(1)

print(f"\n  ✅ Sintaxe Python válida")

with open(TARGET, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"  {ok}/{len(patches)} patches aplicados")
print(f"  Arquivo salvo: {len(content):,} chars\n")
print("  Reinicie o serviço:")
print("  sudo systemctl restart soar\n")

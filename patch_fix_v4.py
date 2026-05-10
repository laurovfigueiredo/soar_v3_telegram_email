#!/usr/bin/env python3
"""
Patch FIX v4 — Diagnóstico + correção cirúrgica do gráfico e botões de período
Execução: sudo python3 patch_fix_v4.py
"""
import sys, re, tempfile, subprocess, os

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Arquivo lido: {len(content):,} chars")
except FileNotFoundError:
    print(f"❌ Arquivo não encontrado: {TARGET}")
    sys.exit(1)

ok = 0

# ══════════════════════════════════════════════════════════════
# DIAGNÓSTICO — mostra o que realmente está no arquivo
# ══════════════════════════════════════════════════════════════
print("\n── DIAGNÓSTICO ──────────────────────────────────────")

def show_ctx(label, pattern, flags=0):
    m = re.search(pattern, content, flags)
    if m:
        start = max(0, m.start() - 80)
        end   = min(len(content), m.end() + 200)
        snippet = content[start:end].replace('\n', '↵\n')
        print(f"\n[{label}] encontrado na pos {m.start()}:\n{snippet}\n{'─'*60}")
    else:
        print(f"\n[{label}] ⚠️  NÃO encontrado")

show_ctx("initChart chamada",   r'initChart\s*\(', re.IGNORECASE)
show_ctx("loadChartJs / s.onload", r's\.onload\s*=', re.IGNORECASE)
show_ctx("setChartDays",        r'setChartDays\b', re.IGNORECASE)
show_ctx("btn-days",            r'btn-days', re.IGNORECASE)
show_ctx("Chart.js script tag", r'chart\.js', re.IGNORECASE)
show_ctx("window.alerts ref",   r'window\.alerts', re.IGNORECASE)
show_ctx("DOMContentLoaded",    r'DOMContentLoaded', re.IGNORECASE)

print("\n── PATCHES ──────────────────────────────────────────")

# ══════════════════════════════════════════════════════════════
# PATCH A — Botões de período: tornar clicáveis via onclick inline
# Estratégia: encontrar os btn-days no HTML e garantir onclick=setChartDays(N)
# ══════════════════════════════════════════════════════════════

# Padrão flexível para botões de período — captura qualquer variante
btn_pattern = re.compile(
    r'(<button[^>]*id=["\']btn-days-(\d+)["\'][^>]*>)',
    re.IGNORECASE
)

def fix_btn(m):
    full_tag = m.group(1)
    n        = m.group(2)
    # Se já tem onclick, não mexe
    if 'onclick' in full_tag.lower():
        return full_tag
    # Injeta onclick antes do fechamento do >
    fixed = full_tag[:-1] + f' onclick="setChartDays({n})">'
    return fixed

new_content, n_btns = btn_pattern.subn(fix_btn, content)
if n_btns > 0:
    content = new_content
    print(f"✅ PATCH A: onclick injetado em {n_btns} botão(ões) btn-days")
    ok += 1
else:
    print("⚠️  PATCH A: botões btn-days não encontrados — tentando padrão alternativo")
    # Tenta padrão sem id explícito: botões "1d", "7d", "15d", "30d"
    alt_pattern = re.compile(
        r'(<button[^>]*>)\s*(1d|7d|15d|30d)\s*(</button>)',
        re.IGNORECASE
    )
    day_map = {'1d': 1, '7d': 7, '15d': 15, '30d': 30}
    def fix_alt_btn(m):
        tag   = m.group(1)
        label = m.group(2)
        close = m.group(3)
        n     = day_map[label.lower()]
        if 'onclick' in tag.lower():
            return m.group(0)
        fixed_tag = tag[:-1] + f' id="btn-days-{n}" onclick="setChartDays({n})">'
        return fixed_tag + label + close
    new_content2, n_alt = alt_pattern.subn(fix_alt_btn, content)
    if n_alt > 0:
        content = new_content2
        print(f"✅ PATCH A-alt: onclick+id injetados em {n_alt} botão(ões)")
        ok += 1
    else:
        print("❌ PATCH A: nenhum padrão de botão de período encontrado")

# ══════════════════════════════════════════════════════════════
# PATCH B — setChartDays: garantir que existe e funciona corretamente
# Substitui qualquer implementação existente por versão robusta
# ══════════════════════════════════════════════════════════════

new_scd = """function setChartDays(d){
  window._chartDays = d;
  [1,7,15,30].forEach(n => {
    const b = document.getElementById('btn-days-'+n);
    if(!b) return;
    const sel = (n===d);
    b.style.background  = sel ? 'rgba(0,107,180,.35)' : 'rgba(74,104,136,.15)';
    b.style.color       = sel ? 'var(--accent-light,#7ec8ff)' : 'var(--dim,#8fa3b8)';
    b.style.borderColor = sel ? 'var(--accent,#006bb4)'       : 'rgba(74,104,136,.25)';
    b.style.fontWeight  = sel ? '700' : '400';
  });
  if(typeof initChart === 'function' && window._alerts && window._alerts.length)
    initChart(window._alerts, d);
}"""

# Tenta substituir implementação existente
scd_match = re.search(
    r'function\s+setChartDays\s*\([^)]*\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)?\}',
    content, re.DOTALL
)
if scd_match:
    content = content[:scd_match.start()] + new_scd + content[scd_match.end():]
    print("✅ PATCH B: setChartDays substituído por versão robusta")
    ok += 1
else:
    # Injeta antes do fechamento do bloco <script> principal
    script_end = content.rfind('</script>')
    if script_end != -1:
        content = content[:script_end] + '\n' + new_scd + '\n' + content[script_end:]
        print("✅ PATCH B: setChartDays inserido (não existia)")
        ok += 1
    else:
        print("❌ PATCH B: não foi possível inserir setChartDays")

# ══════════════════════════════════════════════════════════════
# PATCH C — initChart: assinatura aceita parâmetro de dias opcional
# ══════════════════════════════════════════════════════════════
ic_match = re.search(
    r'function\s+initChart\s*\((\w+)\)\s*\{',
    content
)
if ic_match:
    param   = ic_match.group(1)
    old_sig = ic_match.group(0)
    new_sig = f'function initChart({param}, _days){{'
    if old_sig != new_sig:
        content = content.replace(old_sig, new_sig, 1)
        # Adiciona dias padrão no corpo
        insert_after = new_sig
        default_days = f"\n  const days = _days || window._chartDays || 7;"
        # Injeta logo após a abertura da função
        content = content.replace(
            insert_after,
            insert_after + default_days,
            1
        )
        print("✅ PATCH C: initChart aceita parâmetro de dias")
        ok += 1
    else:
        print("ℹ️  PATCH C: initChart já tem assinatura correta")
else:
    print("⚠️  PATCH C: initChart não encontrado")

# ══════════════════════════════════════════════════════════════
# PATCH D — Salvar alerts em window._alerts para acesso global
# ══════════════════════════════════════════════════════════════
old_alerts_assign = re.search(r'alerts\s*=\s*d\.alerts\s*\|\|\s*\[\]\s*;', content)
if old_alerts_assign:
    orig = old_alerts_assign.group(0)
    replacement = orig + "\n    window._alerts = alerts; // acesso global para gráfico"
    if "window._alerts" not in content:
        content = content.replace(orig, replacement, 1)
        print("✅ PATCH D: window._alerts sincronizado com alerts")
        ok += 1
    else:
        print("ℹ️  PATCH D: window._alerts já existe")
else:
    print("⚠️  PATCH D: atribuição alerts = d.alerts não encontrada")

# ══════════════════════════════════════════════════════════════
# PATCH E — s.onload / Chart.js callback: usa window._alerts
# ══════════════════════════════════════════════════════════════
onload_match = re.search(r's\.onload\s*=\s*[^;]+;', content, re.DOTALL)
if onload_match:
    old_onload = onload_match.group(0)
    new_onload = "s.onload = () => { if(window._alerts && window._alerts.length) initChart(window._alerts); };"
    if old_onload != new_onload:
        content = content.replace(old_onload, new_onload, 1)
        print("✅ PATCH E: s.onload usa window._alerts")
        ok += 1
    else:
        print("ℹ️  PATCH E: s.onload já correto")
else:
    print("⚠️  PATCH E: s.onload não encontrado")

# ══════════════════════════════════════════════════════════════
# PATCH F — DOMContentLoaded: chama initChart após Chart.js
# ══════════════════════════════════════════════════════════════
dcl_pattern = re.compile(
    r"(document\.addEventListener\s*\(\s*['\"]DOMContentLoaded['\"][^{]*\{)",
    re.DOTALL
)
dcl_match = dcl_pattern.search(content)
if dcl_match:
    insert_pos = dcl_match.end()
    inject = "\n  if(window.Chart && window._alerts && window._alerts.length) initChart(window._alerts);"
    if "window._alerts" not in content[insert_pos:insert_pos+200]:
        content = content[:insert_pos] + inject + content[insert_pos:]
        print("✅ PATCH F: DOMContentLoaded inicializa gráfico")
        ok += 1
    else:
        print("ℹ️  PATCH F: DOMContentLoaded já inicializa gráfico")
else:
    print("⚠️  PATCH F: DOMContentLoaded não encontrado")

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

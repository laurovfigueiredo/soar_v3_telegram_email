#!/usr/bin/env python3
"""
Patch FIX v7 — Remove fragmento orphan do setChartDays v4 que causa SyntaxError
Execução: sudo python3 patch_fix_v7.py
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

# ── Remove o fragmento orphan exato identificado no HTML gerado ──
# Trecho: ");↵  if(typeof initChart..." que sobrou do setChartDays v4 incompleto
ORPHAN = re.compile(
    r'\);\s*\n\s*if\s*\(typeof\s+initChart\s*===\s*\'function\'\s*&&\s*window\._alerts[^\n]*\n\s*initChart\(window\._alerts,\s*d\);\s*\n\s*\}',
    re.DOTALL
)

m = ORPHAN.search(content)
if m:
    content = content[:m.start()] + content[m.end():]
    print("✅ Fragmento orphan setChartDays removido")
    ok += 1
else:
    # Tenta variante mais ampla
    ORPHAN2 = re.compile(
        r'\s*\);\s*\n(\s*if\s*\(typeof\s+initChart[^\n]*\n[^\n]*\n\s*\})',
        re.DOTALL
    )
    m2 = ORPHAN2.search(content)
    if m2:
        content = content[:m2.start()] + content[m2.end():]
        print("✅ Fragmento orphan (variante) removido")
        ok += 1
    else:
        # Busca cirúrgica pela string exata vista no curl
        EXACT = ");  \n  if(typeof initChart === 'function' && window._alerts && window._alerts.length)\n    initChart(window._alerts, d);\n}"
        # Tenta encontrar o padrão pelo contexto: linha com só ); seguida do bloco
        lines = content.split('\n')
        new_lines = []
        i = 0
        removed = False
        while i < len(lines):
            line = lines[i]
            # Detecta linha que é só ");" precedida de contexto de setInterval/refresh
            if line.strip() == ');' and i+1 < len(lines) and "typeof initChart" in lines[i+1]:
                # Pula esta linha e as 3 seguintes (o bloco orphan)
                i += 4  # ); + if + initChart + }
                removed = True
                print(f"✅ Linha orphan ')' removida na linha {i}")
                continue
            new_lines.append(line)
            i += 1
        if removed:
            content = '\n'.join(new_lines)
            ok += 1
        else:
            print("⚠️  Fragmento orphan não encontrado pelo padrão — tentando busca direta")
            # Último recurso: remove qualquer ); isolado antes do bloco Chart.js helpers
            chart_block_start = content.find('// ── Chart.js helpers')
            if chart_block_start > 0:
                # Pega 200 chars antes do bloco
                before = content[:chart_block_start]
                # Remove padrão: );\n + if(typeof initChart...\n + initChart...\n + }
                cleaned = re.sub(
                    r'\);\s*\nif\s*\(typeof initChart[^\n]*\n[^\n]*\n\}',
                    '',
                    before
                )
                if cleaned != before:
                    content = cleaned + content[chart_block_start:]
                    print("✅ Fragmento orphan removido (busca direta)")
                    ok += 1
                else:
                    print("❌ Não foi possível remover o fragmento — inspecione manualmente")

# ── Validação ──
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

# ── Verifica se o HTML gerado ainda tem o token inválido ──
check = subprocess.run(
    ['python3', '-c', f'import subprocess; r=subprocess.run(["curl","-s","http://localhost:8000/"],capture_output=True,text=True); print("Token orphan no HTML:", ");" in r.stdout[40000:50000])'],
    capture_output=True, text=True
)
print(check.stdout.strip() if check.stdout else "")
print("Reinicie: sudo systemctl restart soar")

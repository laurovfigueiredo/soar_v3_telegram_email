#!/usr/bin/env python3
"""
Diagnóstico profundo v1 — extrai trechos reais para análise
Execução: sudo python3 diag_v1.py
"""
import re, sys

TARGET = "/home/soar/soar_v3_telegram_email/soar_v3_telegram_email.py"

try:
    with open(TARGET, 'r', encoding='utf-8') as f:
        content = f.read()
    print(f"Arquivo lido: {len(content):,} chars\n")
except FileNotFoundError:
    print(f"❌ {TARGET} não encontrado")
    sys.exit(1)

def show(label, pattern, flags=re.DOTALL, ctx_before=100, ctx_after=400):
    m = re.search(pattern, content, flags)
    if m:
        s = max(0, m.start() - ctx_before)
        e = min(len(content), m.end() + ctx_after)
        print(f"\n{'='*60}")
        print(f"[{label}]  pos={m.start()}")
        print('='*60)
        print(content[s:e])
    else:
        print(f"\n{'='*60}")
        print(f"[{label}]  ⚠️  NÃO ENCONTRADO")
        print('='*60)

# 1. Todas as funções JS definidas no arquivo
print("\n" + "="*60)
print("TODAS AS FUNÇÕES JS (function <nome>)")
print("="*60)
for m in re.finditer(r'function\s+(\w+)\s*\(', content):
    print(f"  pos {m.start():>7}  {m.group(1)}")

# 2. Todas as referências a Chart (maiúsculo)
print("\n" + "="*60)
print("TODAS AS REFS A 'Chart' ou 'chart'")
print("="*60)
for m in re.finditer(r'.{0,60}[Cc]hart.{0,60}', content):
    line = content[:m.start()].count('\n') + 1
    print(f"  linha {line:>5}: {m.group(0).strip()}")

# 3. Como o Chart.js é carregado (script tag ou import)
show("CARREGAMENTO Chart.js", r'chart\.js|cdn\.jsdelivr|chartjs', re.IGNORECASE)

# 4. Função que renderiza o gráfico (qualquer nome)
show("FUNÇÃO GRÁFICO (new Chart)", r'new\s+Chart\s*\(', re.IGNORECASE, 50, 600)

# 5. canvas chart-7days
show("CANVAS chart-7days", r'chart-7days', re.IGNORECASE, 50, 200)

# 6. setChartDays completo
show("setChartDays COMPLETO", r'function\s+setChartDays\s*\([^)]*\)\s*\{[^}]*(?:\{[^}]*\}[^}]*)?\}', re.DOTALL, 0, 0)

# 7. Como alertas chegam ao gráfico (filter por data)
show("FILTRO DE DATA nos alertas", r'timestamp|rule_fired_at|@timestamp|filter.*date|getTime\(\)', re.IGNORECASE, 50, 300)

# 8. O que acontece após alerts = d.alerts
show("APÓS alerts = d.alerts", r'alerts\s*=\s*d\.alerts[^;]*;', re.IGNORECASE, 0, 500)

print("\n\n✅ Diagnóstico concluído — cole a saída completa para análise")

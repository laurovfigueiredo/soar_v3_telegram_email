#!/usr/bin/env python3
"""
SOAR Platform v2 - Wazuh Integration
Servidor HTTP puro. Dependências: requests (+ fpdf2 opcional para PDF).
"""

import json, os, time, logging, threading, urllib.parse, html, io, base64
import smtplib, ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("/tmp/soar.log")],
)
logger = logging.getLogger("soar")

# ─── .env ─────────────────────────────────────────────────────────────────────
def load_env(path=".env"):
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())
load_env()

WAZUH_HOST     = os.getenv("WAZUH_HOST", "192.168.0.10")
WAZUH_PORT     = int(os.getenv("WAZUH_PORT", "55000"))
WAZUH_USER     = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "SoarSenha2024!")
SOAR_PORT      = int(os.getenv("SOAR_PORT", "8000"))

# ─── Deps opcionais ───────────────────────────────────────────────────────────
try:
    import requests, urllib3
    urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from fpdf import FPDF
    HAS_PDF = True
except ImportError:
    HAS_PDF = False

# ─── Wazuh Client ─────────────────────────────────────────────────────────────
class WazuhClient:
    def __init__(self):
        self.base   = f"https://{WAZUH_HOST}:{WAZUH_PORT}"
        self.token  = None
        self.expiry = 0

    def _auth(self):
        if not HAS_REQUESTS: return False
        try:
            r = requests.post(f"{self.base}/security/user/authenticate",
                              auth=(WAZUH_USER, WAZUH_PASSWORD), timeout=3, verify=False)
            if r.status_code == 200:
                self.token  = r.json()["data"]["token"]
                self.expiry = time.time() + 3300
                logger.info("✓ Autenticado no Wazuh")
                return True
            logger.error(f"✗ Auth Wazuh falhou: HTTP {r.status_code}")
        except Exception as e:
            logger.error(f"✗ Conexão Wazuh: {e}")
        return False

    def _headers(self):
        if not self.token or time.time() > self.expiry - 60:
            self._auth()
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def _get(self, path, params=None):
        if not HAS_REQUESTS: return {}
        try:
            r = requests.get(f"{self.base}{path}", headers=self._headers(),
                             params=params, timeout=3, verify=False)
            r.raise_for_status(); return r.json()
        except Exception as e:
            logger.error(f"✗ GET {path}: {e}"); return {}

    def _post(self, path, body=None, params=None):
        if not HAS_REQUESTS: return {}
        try:
            r = requests.post(f"{self.base}{path}", headers=self._headers(),
                              json=body or {}, params=params, timeout=3, verify=False)
            r.raise_for_status(); return r.json()
        except Exception as e:
            logger.error(f"✗ POST {path}: {e}"); return {}

    def _delete(self, path, params=None):
        if not HAS_REQUESTS: return {}
        try:
            r = requests.delete(f"{self.base}{path}", headers=self._headers(),
                                params=params, timeout=3, verify=False)
            r.raise_for_status(); return r.json()
        except Exception as e:
            logger.error(f"✗ DELETE {path}: {e}"); return {}

    def health(self):
        try: return bool(self._get("/cluster/status").get("data"))
        except: return False

    def get_agents(self):
        r = self._get("/agents", {"limit": 100})
        return r.get("data", {}).get("affected_items", [])

    def get_agent_detail(self, agent_id):
        r = self._get(f"/agents", {"agents_list": agent_id})
        items = r.get("data", {}).get("affected_items", [])
        return items[0] if items else {}

    def get_agent_processes(self, agent_id):
        r = self._get(f"/syscollector/{agent_id}/processes", {"limit": 50})
        return r.get("data", {}).get("affected_items", [])

    def get_agent_ports(self, agent_id):
        r = self._get(f"/syscollector/{agent_id}/ports", {"limit": 50})
        return r.get("data", {}).get("affected_items", [])

    def get_agent_packages(self, agent_id):
        r = self._get(f"/syscollector/{agent_id}/packages", {"limit": 50})
        return r.get("data", {}).get("affected_items", [])

    def get_sysinfo(self, agent_id):
        r = self._get(f"/syscollector/{agent_id}/hardware")
        return r.get("data", {}).get("affected_items", [{}])[0]

    def isolate_agent(self, agent_id):
        return self._post("/active-response",
                          {"command": "firewall-drop", "arguments": []},
                          {"agents_list": agent_id})

    def restore_agent(self, agent_id):
        return self._post("/active-response",
                          {"command": "firewall-allow", "arguments": []},
                          {"agents_list": agent_id})

    def run_command(self, agent_id, command, args=None):
        return self._post("/active-response",
                          {"command": command, "arguments": args or []},
                          {"agents_list": agent_id})

    def ban_ip(self, agent_id, ip):
        return self._post("/active-response",
                          {"command": "firewall-drop", "arguments": [ip]},
                          {"agents_list": agent_id})

    def kill_process(self, agent_id, pid):
        return self._post("/active-response",
                          {"command": "kill-process", "arguments": [str(pid)]},
                          {"agents_list": agent_id})

    def disable_agent(self, agent_id):
        return self._post("/agents/group", {"group_id": "disabled"},
                          {"agents_list": agent_id})

    def revoke_active_response(self, agent_id):
        return self._post("/active-response",
                          {"command": "restart-ossec", "arguments": []},
                          {"agents_list": agent_id})

wazuh = WazuhClient()

# ─── Notificações: Telegram + Email SMTP ──────────────────────────────────────
TELEGRAM_ENABLED = os.getenv("TELEGRAM_ENABLED", "true").lower() == "true"
TELEGRAM_TOKEN   = os.getenv("TELEGRAM_TOKEN",   "8283314443:AAHkWlm2C8Kc6RE1xHYlLb0OPJojbAKA000")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "1228283183")
TELEGRAM_LEVEL   = int(os.getenv("TELEGRAM_LEVEL", "8"))

EMAIL_ENABLED    = os.getenv("EMAIL_ENABLED",  "false").lower() == "true"
EMAIL_HOST       = os.getenv("EMAIL_HOST",     "smtp.gmail.com")
EMAIL_PORT       = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USER       = os.getenv("EMAIL_USER",     "seuemail@gmail.com")
EMAIL_PASS       = os.getenv("EMAIL_PASS",     "sua_senha_app")
EMAIL_FROM       = os.getenv("EMAIL_FROM",     "SOAR Wazuh <seuemail@gmail.com>")
EMAIL_TO         = os.getenv("EMAIL_TO",       "destino@empresa.com")
EMAIL_LEVEL      = int(os.getenv("EMAIL_LEVEL","12"))   # só críticos por email

class Notifier:
    """Envia alertas via Telegram e/ou Email SMTP de forma assíncrona com retry."""

    MAX_RETRIES = 3
    RETRY_DELAY = 3   # segundos entre tentativas

    # ── helpers internos ──────────────────────────────────────────────────────
    @staticmethod
    def _level_emoji(level: int) -> str:
        if level >= 12: return "🔴 CRÍTICO"
        if level >= 8:  return "🟠 ALTO"
        if level >= 5:  return "🟡 MÉDIO"
        return "🟢 BAIXO"

    @staticmethod
    def _fmt_alert(alert: dict) -> str:
        """Formata um alerta Wazuh em texto para Telegram/Email."""
        rule    = alert.get("rule", {})
        agent   = alert.get("agent", {})
        level   = int(rule.get("level", 0))
        emoji   = Notifier._level_emoji(level)
        ts      = alert.get("timestamp", datetime.now().isoformat())[:19].replace("T"," ")
        return (
            f"{emoji}\n\n"
            f"*Descrição:* {rule.get('description','N/A')}\n"
            f"*Rule ID:* {rule.get('id','N/A')}  |  *Nível:* {level}\n"
            f"*Agente:* {agent.get('name','N/A')}  |  *IP:* {agent.get('ip','N/A')}\n"
            f"*Timestamp:* {ts}"
        )

    @staticmethod
    def _fmt_vuln(vuln: dict) -> str:
        """Formata uma vulnerabilidade para Telegram/Email."""
        sev   = vuln.get("severity","N/A").upper()
        emoji = "🔴" if sev=="CRITICAL" else "🟠" if sev=="HIGH" else "🟡"
        return (
            f"{emoji} *VULNERABILIDADE {sev}*\n\n"
            f"*CVE:* {vuln.get('cve','N/A')}\n"
            f"*Pacote:* {vuln.get('name','N/A')} {vuln.get('version','')}\n"
            f"*Agente:* {vuln.get('agent_name','N/A')}  |  *IP:* {vuln.get('agent_ip','N/A')}\n"
            f"*Score CVSS:* {vuln.get('cvss3_score', vuln.get('cvss2_score','N/A'))}"
        )

    # ── Telegram ──────────────────────────────────────────────────────────────
    @classmethod
    def _send_telegram_now(cls, text: str) -> bool:
        """Envia mensagem ao Telegram. Retorna True se OK."""
        if not HAS_REQUESTS:
            logger.warning("[Telegram] requests não disponível")
            return False
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id":    TELEGRAM_CHAT_ID,
            "text":       text,
            "parse_mode": "Markdown"
        }
        for attempt in range(1, cls.MAX_RETRIES + 1):
            try:
                resp = requests.post(url, json=payload, timeout=10)
                if resp.status_code == 200:
                    logger.info("[Telegram] Mensagem enviada com sucesso")
                    return True
                # 429 = rate limit → espera e tenta de novo
                if resp.status_code == 429:
                    wait = resp.json().get("parameters", {}).get("retry_after", 5)
                    logger.warning(f"[Telegram] Rate limit, aguardando {wait}s...")
                    time.sleep(wait)
                    continue
                logger.error(f"[Telegram] Erro {resp.status_code}: {resp.text[:200]}")
            except requests.exceptions.Timeout:
                logger.warning(f"[Telegram] Timeout (tentativa {attempt}/{cls.MAX_RETRIES})")
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"[Telegram] Erro de conexão (tentativa {attempt}): {e}")
            except Exception as e:
                logger.error(f"[Telegram] Erro inesperado: {e}")
                break
            if attempt < cls.MAX_RETRIES:
                time.sleep(cls.RETRY_DELAY)
        logger.error("[Telegram] Falha em todas as tentativas")
        return False

    @classmethod
    def telegram(cls, text: str):
        """Dispara envio Telegram em thread separada (não bloqueia o servidor)."""
        if not TELEGRAM_ENABLED:
            return
        threading.Thread(target=cls._send_telegram_now, args=(text,), daemon=True).start()

    # ── Email SMTP ────────────────────────────────────────────────────────────
    @classmethod
    def _send_email_now(cls, subject: str, body_text: str, body_html: str = "") -> bool:
        """Envia email via SMTP com TLS. Retorna True se OK."""
        for attempt in range(1, cls.MAX_RETRIES + 1):
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"]    = EMAIL_FROM
                msg["To"]      = EMAIL_TO

                msg.attach(MIMEText(body_text, "plain", "utf-8"))
                if body_html:
                    msg.attach(MIMEText(body_html, "html", "utf-8"))

                ctx = ssl.create_default_context()
                with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=15) as server:
                    server.ehlo()
                    server.starttls(context=ctx)
                    server.login(EMAIL_USER, EMAIL_PASS)
                    server.sendmail(EMAIL_USER, EMAIL_TO.split(","), msg.as_string())
                logger.info(f"[Email] Mensagem enviada para {EMAIL_TO}")
                return True
            except smtplib.SMTPAuthenticationError:
                logger.error("[Email] Falha de autenticação SMTP — verifique EMAIL_USER/EMAIL_PASS")
                break   # não adianta tentar de novo
            except smtplib.SMTPException as e:
                logger.warning(f"[Email] Erro SMTP (tentativa {attempt}): {e}")
            except OSError as e:
                logger.warning(f"[Email] Erro de rede (tentativa {attempt}): {e}")
            except Exception as e:
                logger.error(f"[Email] Erro inesperado: {e}")
                break
            if attempt < cls.MAX_RETRIES:
                time.sleep(cls.RETRY_DELAY)
        logger.error("[Email] Falha em todas as tentativas de envio")
        return False

    @classmethod
    def email(cls, subject: str, body_text: str, body_html: str = ""):
        """Dispara envio de email em thread separada."""
        if not EMAIL_ENABLED:
            return
        threading.Thread(
            target=cls._send_email_now,
            args=(subject, body_text, body_html),
            daemon=True
        ).start()

    # ── Helpers de alto nível ─────────────────────────────────────────────────
    @classmethod
    def notify_alert(cls, alert: dict):
        """Envia alerta Wazuh para Telegram e/ou Email conforme nível configurado."""
        level = int(alert.get("rule", {}).get("level", 0))
        text  = cls._fmt_alert(alert)

        if TELEGRAM_ENABLED and level >= TELEGRAM_LEVEL:
            cls.telegram(text)

        if EMAIL_ENABLED and level >= EMAIL_LEVEL:
            rule  = alert.get("rule", {})
            subj  = f"[WAZUH] Nível {level} — {rule.get('description','Alerta')[:60]}"
            html_body = f"<pre style='font-family:monospace'>{text.replace('*','<b>').replace('\\n','<br>')}</b></pre>"
            cls.email(subj, text.replace("*",""), html_body)

    @classmethod
    def notify_vuln(cls, vuln: dict):
        """Envia vulnerabilidade crítica/alta para Telegram e/ou Email."""
        sev   = vuln.get("severity","").upper()
        if sev not in ("CRITICAL","HIGH"):
            return
        text  = cls._fmt_vuln(vuln)

        if TELEGRAM_ENABLED:
            cls.telegram(text)

        if EMAIL_ENABLED:
            subj = f"[WAZUH] Vulnerabilidade {sev} — {vuln.get('cve','N/A')}"
            cls.email(subj, text.replace("*",""))

    @classmethod
    def test(cls) -> dict:
        """Envia mensagem de teste para Telegram e Email. Retorna status."""
        now  = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        text = f"✅ *SOAR Wazuh v2 — Teste de Notificação*\n\n*Servidor:* {WAZUH_HOST}\n*Hora:* {now}\n\nTelegram e Email configurados com sucesso!"
        result = {}
        if TELEGRAM_ENABLED:
            result["telegram"] = cls._send_telegram_now(text)
        if EMAIL_ENABLED:
            result["email"] = cls._send_email_now("[SOAR] Teste de notificação", text.replace("*",""))
        return result


# ─── OSINT / Enrichment helpers ───────────────────────────────────────────────
def osint_reputation(ip_or_domain):
    """Consulta AbuseIPDB e ip-api para reputação e geolocalização."""
    result = {"target": ip_or_domain, "timestamp": datetime.now().isoformat(timespec="seconds")}
    if not HAS_REQUESTS:
        result["error"] = "requests não instalado"
        return result
    # GeoIP via ip-api (gratuito, sem chave)
    try:
        r = requests.get(f"http://ip-api.com/json/{ip_or_domain}?fields=status,country,regionName,city,isp,org,as,query,reverse,mobile,proxy,hosting",
                         timeout=5)
        if r.status_code == 200:
            d = r.json()
            result["geoip"] = d
    except Exception as e:
        result["geoip_error"] = str(e)
    # Whois simplificado via rdap
    try:
        target = ip_or_domain.strip()
        r2 = requests.get(f"https://rdap.arin.net/registry/ip/{target}", timeout=5)
        if r2.status_code == 200:
            d2 = r2.json()
            result["whois"] = {
                "name": d2.get("name",""),
                "handle": d2.get("handle",""),
                "type": d2.get("type",""),
                "country": d2.get("country",""),
                "remarks": [r.get("description","") for r in d2.get("remarks",[])[:2]] if d2.get("remarks") else []
            }
    except Exception as e:
        result["whois_error"] = str(e)
    # Score de risco básico baseado em GeoIP
    risk = 0
    geoip = result.get("geoip", {})
    if geoip.get("proxy"): risk += 40
    if geoip.get("hosting"): risk += 30
    if geoip.get("mobile"): risk += 5
    result["risk_score"] = min(risk, 100)
    result["risk_label"] = "ALTO" if risk >= 60 else "MÉDIO" if risk >= 30 else "BAIXO"
    return result

def collect_evidence(alert):
    """Coleta evidências forenses de um alerta."""
    ts = datetime.now().isoformat(timespec="seconds")
    evidence = {
        "evidence_id": f"EVD-{int(time.time())}",
        "collected_at": ts,
        "alert_id": alert["id"],
        "alert_summary": {
            "agent_id":   alert["agent_id"],
            "agent_name": alert["agent_name"],
            "rule_id":    alert["rule_id"],
            "rule_desc":  alert["rule_desc"],
            "level":      alert["level"],
            "timestamp":  alert["timestamp"],
            "status":     alert["status"],
            "assignee":   alert.get("assignee",""),
            "notes":      alert.get("notes",[]),
        },
        "raw_alert":   alert.get("raw", {}),
        "syscheck":    alert.get("raw",{}).get("syscheck", {}),
        "network":     alert.get("raw",{}).get("data", {}).get("srcip",""),
        "chain_of_custody": [{"time": ts, "action": "Evidence collected", "analyst": "SOAR-AUTO"}],
    }
    # Processos e portas via Wazuh
    try:
        procs = wazuh.get_agent_processes(alert["agent_id"])
        evidence["processes"] = procs[:30]
    except: evidence["processes"] = []
    try:
        ports = wazuh.get_agent_ports(alert["agent_id"])
        evidence["open_ports"] = ports[:30]
    except: evidence["open_ports"] = []
    return evidence

# ─── Persistência em disco (JSON) ─────────────────────────────────────────────
PERSIST_DIR  = os.getenv("SOAR_DATA_DIR", "/var/lib/soar")
os.makedirs(PERSIST_DIR, exist_ok=True)

_DB_FILES = {
    "alerts":    os.path.join(PERSIST_DIR, "alerts.json"),
    "log":       os.path.join(PERSIST_DIR, "log.json"),
    "incidents": os.path.join(PERSIST_DIR, "incidents.json"),
    "evidences": os.path.join(PERSIST_DIR, "evidences.json"),
    "tickets":   os.path.join(PERSIST_DIR, "tickets.json"),
}

def _load_json(key):
    path = _DB_FILES[key]
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
    except Exception as e:
        logger.error(f"[persist] Erro ao carregar {path}: {e}")
    return []

def _save_json(key, data):
    path  = _DB_FILES[key]
    tmp   = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, default=str)
        os.replace(tmp, path)
    except Exception as e:
        logger.error(f"[persist] Erro ao salvar {path}: {e}")

_lock      = threading.Lock()
_alerts    = _load_json("alerts")
_log       = _load_json("log")
_incidents = _load_json("incidents")
_evidences = _load_json("evidences")
_tickets   = _load_json("tickets")
MAX_ALERTS = 50000

logger.info(f"[persist] Dados carregados — alertas: {len(_alerts)} | logs: {len(_log)} | incidentes: {len(_incidents)} | evidências: {len(_evidences)} | tickets: {len(_tickets)}")

def store_alert(data: dict):
    ts = datetime.now().isoformat(timespec="seconds")
    alert = {
        "id":          f"alert-{int(time.time()*1000)}",
        "timestamp":   ts,
        "agent_id":    data.get("agent", {}).get("id", "000"),
        "agent_name":  data.get("agent", {}).get("name", "unknown"),
        "rule_id":     str(data.get("rule", {}).get("id", "0")),
        "rule_desc":   data.get("rule", {}).get("description", "Sem descrição"),
        "level":       int(data.get("rule", {}).get("level", data.get("level", 0))),
        "status":      "open",
        "assignee":    "",
        "notes":       [],
        "escalated":   False,
        "false_positive": False,
        "raw":         data,
    }
    # ── Disparar notificações Telegram / Email ────────────────────────────────
    threading.Thread(target=Notifier.notify_alert, args=(data,), daemon=True).start()

    with _lock:
        _alerts.insert(0, alert)
        if len(_alerts) > MAX_ALERTS:
            _alerts.pop()
        _save_json("alerts", _alerts)
    return alert

def add_log(action, agent_id, status, msg):
    with _lock:
        _log.insert(0, {
            "time":     datetime.now().strftime("%H:%M:%S"),
            "action":   action,
            "agent_id": agent_id,
            "status":   status,
            "msg":      msg,
        })
        if len(_log) > 200:
            _log.pop()
        _save_json("log", _log)

# ─── PDF Report ───────────────────────────────────────────────────────────────
def generate_pdf_report():
    if HAS_PDF:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "SOAR - Wazuh Security Report", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True, align="C")
        pdf.ln(6)

        with _lock:
            alerts_snap = list(_alerts)

        # Resumo
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Resumo", ln=True)
        pdf.set_font("Helvetica", "", 10)
        total  = len(alerts_snap)
        crits  = sum(1 for a in alerts_snap if a["level"] >= 12)
        highs  = sum(1 for a in alerts_snap if 7 <= a["level"] < 12)
        fps    = sum(1 for a in alerts_snap if a.get("false_positive"))
        esc    = sum(1 for a in alerts_snap if a.get("escalated"))
        pdf.cell(0, 6, f"Total de alertas: {total}  |  Criticos: {crits}  |  Altos: {highs}  |  Falsos Positivos: {fps}  |  Escalados: {esc}", ln=True)
        pdf.ln(4)

        # Tabela
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(30, 50, 80)
        pdf.set_text_color(200, 230, 255)
        for h, w in [("Nível",14),("Agente",30),("Regra",18),("Descrição",80),("Status",22),("Hora",26)]:
            pdf.cell(w, 7, h, border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(0,0,0)
        pdf.set_font("Helvetica", "", 8)
        for a in alerts_snap[:100]:
            pdf.set_fill_color(250,250,250) if alerts_snap.index(a)%2==0 else pdf.set_fill_color(240,240,240)
            desc = a["rule_desc"][:55] + ("…" if len(a["rule_desc"])>55 else "")
            for val, w in [(str(a["level"]),14),(a["agent_name"][:14],30),(a["rule_id"],18),(desc,80),(a["status"],22),(a["timestamp"][11:19],26)]:
                pdf.cell(w, 6, val, border=1, fill=True)
            pdf.ln()

        # Log de ações
        pdf.ln(6)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Log de Acoes Recentes", ln=True)
        pdf.set_font("Helvetica", "", 9)
        with _lock:
            log_snap = list(_log[:50])
        for l in log_snap:
            pdf.cell(0, 5, f"[{l['time']}] {l['action'].upper()} | ag:{l['agent_id']} | {l['msg']}", ln=True)

        return pdf.output()
    else:
        # Fallback texto
        with _lock:
            alerts_snap = list(_alerts)
        lines = [
            "SOAR - Wazuh Security Report",
            f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            "=" * 60,
            f"Total alertas: {len(alerts_snap)}",
            f"Criticos (>=12): {sum(1 for a in alerts_snap if a['level']>=12)}",
            f"Altos (>=7): {sum(1 for a in alerts_snap if 7<=a['level']<12)}",
            "=" * 60,
        ]
        for a in alerts_snap[:50]:
            lines.append(f"[{a['timestamp'][11:19]}] LV{a['level']:2} | {a['agent_name']:15} | {a['rule_desc'][:50]} | {a['status']}")
        return "\n".join(lines).encode("utf-8")

# ─── HTML Dashboard v2 ────────────────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOAR · Wazuh v2</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;500;700&display=swap" rel="stylesheet">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Source+Code+Pro:wght@400;500&display=swap');

:root{
  --bg:#07101F;
  --panel:#0d1a2d;
  --panel2:#0a1520;
  --sidebar:#0f1d30;
  --border:#1a2e4a;
  --accent:#006BB4;
  --accent-light:#0090e0;
  --green:#00BFB3;
  --yellow:#FEC514;
  --red:#BD271E;
  --red-light:#F86B63;
  --orange:#F5A700;
  --purple:#9170B8;
  --teal:#00BFB3;
  --dim:#4a6888;
  --text:#DFE5EF;
  --text-dim:#8faac8;
  --mono:'Source Code Pro',monospace;
  --sans:'Inter',sans-serif;
  --radius:6px;
  --shadow:0 2px 8px rgba(0,0,0,.4);
}

*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--sans);
  font-size:13px;min-height:100vh;display:flex;flex-direction:column}

/* ── TOP HEADER ─────────────────────────────────────────────────────────── */
header{
  display:flex;align-items:center;justify-content:space-between;
  padding:0 24px;height:48px;
  background:var(--panel);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:300;
  box-shadow:var(--shadow);
}
.logo{
  display:flex;align-items:center;gap:10px;
  font-family:var(--sans);font-size:15px;font-weight:700;
  color:var(--text);letter-spacing:.02em;
}
.logo-icon{
  width:28px;height:28px;border-radius:6px;
  background:linear-gradient(135deg,var(--accent),var(--accent-light));
  display:flex;align-items:center;justify-content:center;
  font-size:14px;font-weight:800;color:#fff;
}
.logo-sub{
  font-size:10px;font-weight:400;color:var(--dim);
  margin-left:2px;letter-spacing:.06em;text-transform:uppercase;
}
#status-bar{display:flex;gap:16px;align-items:center;font-size:12px}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:5px}
.dot.ok{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.bad{background:var(--red-light);box-shadow:0 0 6px var(--red-light)}
.dot.warn{background:var(--yellow);box-shadow:0 0 6px var(--yellow)}
#wazuh-dot{color:var(--text-dim);font-size:12px}
#alert-count{color:var(--text-dim);font-size:12px}
#last-refresh{color:var(--dim);font-size:11px;font-family:var(--mono)}
.hdr-btn{
  padding:5px 14px;border-radius:var(--radius);
  border:1px solid var(--border);background:transparent;
  color:var(--text-dim);cursor:pointer;font-size:12px;font-family:var(--sans);
  font-weight:500;transition:.15s;display:flex;align-items:center;gap:5px;
}
.hdr-btn:hover{border-color:var(--accent-light);color:var(--accent-light);background:rgba(0,107,180,.08)}
.hdr-btn.active{border-color:var(--accent);color:var(--accent);background:rgba(0,107,180,.12)}

/* ── MAIN LAYOUT ────────────────────────────────────────────────────────── */
.app-body{display:flex;flex:1;overflow:hidden}

/* ── SIDEBAR ────────────────────────────────────────────────────────────── */
.sidebar{
  width:220px;flex-shrink:0;
  background:var(--sidebar);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  overflow-y:auto;
  position:sticky;top:48px;height:calc(100vh - 48px);
}
.sidebar-section{
  padding:16px 12px 8px;
  font-size:10px;font-weight:600;letter-spacing:.12em;
  text-transform:uppercase;color:var(--dim);
}
.sidebar-item{
  display:flex;align-items:center;gap:10px;
  padding:9px 16px;margin:1px 8px;border-radius:var(--radius);
  cursor:pointer;font-size:13px;color:var(--text-dim);
  transition:.15s;font-weight:400;
}
.sidebar-item:hover{background:rgba(0,107,180,.12);color:var(--text)}
.sidebar-item.active{
  background:rgba(0,107,180,.18);color:var(--accent-light);
  font-weight:500;
}
.sidebar-item .si-icon{font-size:15px;width:20px;text-align:center}
.sidebar-badge{
  margin-left:auto;background:var(--accent);color:#fff;
  font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px;
  min-width:18px;text-align:center;
}
.sidebar-badge.red{background:var(--red-light)}
.sidebar-divider{height:1px;background:var(--border);margin:8px 16px}

/* ── CONTENT ────────────────────────────────────────────────────────────── */
.content-area{flex:1;overflow-y:auto;padding:20px 24px}
.page{display:none}.page.active{display:block}

/* ── BREADCRUMB ─────────────────────────────────────────────────────────── */
.breadcrumb{
  display:flex;align-items:center;gap:6px;margin-bottom:16px;
  font-size:12px;color:var(--dim);
}
.breadcrumb span{color:var(--text-dim)}
.breadcrumb .bc-sep{color:var(--border)}

/* ── STATS ──────────────────────────────────────────────────────────────── */
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:20px}
.stat-card{
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px 16px;
  position:relative;overflow:hidden;cursor:pointer;
  transition:.15s;box-shadow:var(--shadow);
}
.stat-card:hover{border-color:var(--accent);transform:translateY(-1px)}
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
.stat-card:hover .stat-card-hint{opacity:1}
.stat-card::before{
  content:'';position:absolute;bottom:0;left:0;right:0;height:3px;
}
.stat-card.c-blue::before{background:linear-gradient(90deg,var(--accent),var(--accent-light))}
.stat-card.c-red::before{background:linear-gradient(90deg,var(--red),var(--red-light))}
.stat-card.c-yellow::before{background:linear-gradient(90deg,var(--orange),var(--yellow))}
.stat-card.c-green::before{background:linear-gradient(90deg,var(--teal),#00e5d8)}
.stat-card.c-purple::before{background:linear-gradient(90deg,var(--purple),#b08dd4)}
.stat-label{font-size:11px;font-weight:500;letter-spacing:.04em;color:var(--dim);text-transform:uppercase}
.stat-value{font-family:var(--mono);font-size:28px;margin-top:4px;font-weight:500}
.c-blue .stat-value{color:var(--accent-light)}
.c-red .stat-value{color:var(--red-light)}
.c-yellow .stat-value{color:var(--yellow)}
.c-green .stat-value{color:var(--teal)}
.c-purple .stat-value{color:var(--purple)}

/* ── PANEL ──────────────────────────────────────────────────────────────── */
.panel{
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;
}
.panel-head{
  display:flex;align-items:center;justify-content:space-between;
  padding:11px 16px;border-bottom:1px solid var(--border);
  font-size:11px;font-weight:600;text-transform:uppercase;
  letter-spacing:.08em;color:var(--text-dim);background:var(--panel2);
}
.panel-head span{
  font-family:var(--mono);font-size:13px;
  color:var(--accent-light);font-weight:500;text-transform:none;letter-spacing:0;
}

/* ── TABLE ──────────────────────────────────────────────────────────────── */
table{width:100%;border-collapse:collapse}
th{
  padding:9px 12px;text-align:left;font-size:11px;
  font-weight:600;text-transform:uppercase;letter-spacing:.06em;
  color:var(--dim);border-bottom:1px solid var(--border);
  background:var(--panel2);white-space:nowrap;
}
td{
  padding:8px 12px;border-bottom:1px solid rgba(26,46,74,.5);
  vertical-align:middle;font-size:12px;
}
tr:last-child td{border:none}
tr:hover td{background:rgba(0,107,180,.05)}

/* ── LEVEL BADGES ───────────────────────────────────────────────────────── */
.lvl{
  display:inline-flex;align-items:center;justify-content:center;
  width:26px;height:26px;border-radius:5px;
  font-family:var(--mono);font-size:11px;font-weight:700;
}
.lvl.low{background:rgba(0,191,179,.12);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.lvl.medium{background:rgba(254,197,20,.1);color:var(--yellow);border:1px solid rgba(254,197,20,.3)}
.lvl.high{background:rgba(245,167,0,.12);color:var(--orange);border:1px solid rgba(245,167,0,.3)}
.lvl.crit{background:rgba(189,39,30,.15);color:var(--red-light);border:1px solid rgba(189,39,30,.4)}

/* ── STATUS BADGE ───────────────────────────────────────────────────────── */
.badge{
  display:inline-block;padding:2px 8px;border-radius:12px;
  font-size:10px;font-weight:600;letter-spacing:.04em;
}
.badge.open{background:rgba(0,107,180,.15);color:var(--accent-light);border:1px solid rgba(0,107,180,.3)}
.badge.ignored{background:rgba(74,104,136,.1);color:var(--dim);border:1px solid rgba(74,104,136,.2)}
.badge.actioned{background:rgba(0,191,179,.12);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.badge.escalated{background:rgba(145,112,184,.12);color:var(--purple);border:1px solid rgba(145,112,184,.3)}
.badge.fp{background:rgba(254,197,20,.1);color:var(--yellow);border:1px solid rgba(254,197,20,.25)}
.badge.investigating{background:rgba(0,144,224,.1);color:#5bc8f5;border:1px solid rgba(0,144,224,.25)}

/* ── BUTTONS ────────────────────────────────────────────────────────────── */
.btn{
  padding:4px 9px;border-radius:4px;border:none;cursor:pointer;
  font-size:10px;font-family:var(--sans);font-weight:600;letter-spacing:.03em;
  transition:opacity .15s,transform .1s;white-space:nowrap;
}
.btn:active{transform:scale(.95)}
.btn:disabled{opacity:.25;cursor:not-allowed}
.btn:hover:not(:disabled){opacity:.8}
.btn-blue{background:rgba(0,107,180,.2);color:var(--accent-light);border:1px solid rgba(0,107,180,.4)}
.btn-green{background:rgba(0,191,179,.15);color:var(--teal);border:1px solid rgba(0,191,179,.35)}
.btn-red{background:rgba(189,39,30,.2);color:var(--red-light);border:1px solid rgba(189,39,30,.4)}
.btn-gray{background:rgba(74,104,136,.15);color:var(--dim);border:1px solid rgba(74,104,136,.25)}
.btn-purple{background:rgba(145,112,184,.15);color:var(--purple);border:1px solid rgba(145,112,184,.3)}
.btn-yellow{background:rgba(245,167,0,.12);color:var(--yellow);border:1px solid rgba(245,167,0,.3)}
.btn-teal{background:rgba(0,191,179,.12);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.btn-orange{background:rgba(245,167,0,.12);color:var(--orange);border:1px solid rgba(245,167,0,.3)}
.btn-pink{background:rgba(145,112,184,.12);color:#d49fea;border:1px solid rgba(145,112,184,.25)}
.btn-lg{padding:7px 18px;font-size:12px}
.btn-group{display:flex;gap:3px;flex-wrap:wrap}

/* ── FILTER BAR ─────────────────────────────────────────────────────────── */
.filter-bar{
  display:flex;gap:8px;align-items:center;
  padding:12px 0 14px;flex-wrap:wrap;
}
.filter-bar select,.filter-bar input{
  padding:6px 10px;border-radius:var(--radius);
  background:var(--panel);border:1px solid var(--border);
  color:var(--text);font-size:12px;font-family:var(--sans);
  transition:.15s;
}
.filter-bar select:focus,.filter-bar input:focus{
  outline:none;border-color:var(--accent);
  box-shadow:0 0 0 2px rgba(0,107,180,.15);
}
select.input-dark option{background:var(--panel)}

/* ── INPUT ──────────────────────────────────────────────────────────────── */
.input-dark{
  background:var(--panel2);border:1px solid var(--border);color:var(--text);
  padding:7px 11px;border-radius:var(--radius);font-size:12px;width:100%;
  font-family:var(--sans);transition:.15s;
}
.input-dark:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,107,180,.15)}
select.input-dark option{background:var(--panel)}

/* ── SIDEBAR AGENTS ─────────────────────────────────────────────────────── */
.agent-row{
  display:flex;align-items:center;gap:8px;
  padding:8px 0;border-bottom:1px solid rgba(26,46,74,.4);
}
.agent-row:last-child{border:none}
.agt-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.agt-dot.active{background:var(--teal);box-shadow:0 0 5px var(--teal)}
.agt-dot.disconnected{background:var(--dim)}
.agt-dot.never_connected{background:var(--yellow)}
.agt-name{font-size:12px;font-weight:500;flex:1}
.agt-id{font-family:var(--mono);font-size:10px;color:var(--dim)}

/* ── LOG ────────────────────────────────────────────────────────────────── */
.log-entry{
  padding:6px 0;border-bottom:1px solid rgba(26,46,74,.4);
  font-family:var(--mono);font-size:11px;color:var(--dim);
}
.log-entry:last-child{border:none}
.log-ts{color:rgba(74,104,136,.6);margin-right:6px}
.log-ok{color:var(--teal)}
.log-err{color:var(--red-light)}
.log-inf{color:var(--accent-light)}

/* ── INCIDENTS ──────────────────────────────────────────────────────────── */
.incident-card{
  background:var(--panel2);border:1px solid var(--border);
  border-radius:var(--radius);padding:14px 16px;margin-bottom:10px;
  transition:.15s;
}
.incident-card:hover{border-color:var(--accent)}
.inc-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.inc-id{font-family:var(--mono);font-size:11px;color:var(--dim)}
.inc-title{font-size:13px;font-weight:600;color:var(--text)}
.inc-meta{font-size:11px;color:var(--dim);margin-top:4px}
.priority-high{border-left:3px solid var(--red-light)}
.priority-med{border-left:3px solid var(--yellow)}
.priority-low{border-left:3px solid var(--teal)}

/* ── MISC ───────────────────────────────────────────────────────────────── */
.empty{text-align:center;padding:40px 20px;color:var(--dim);font-size:12px}
.spinner{
  display:inline-block;width:14px;height:14px;
  border:2px solid var(--border);border-top-color:var(--accent);
  border-radius:50%;animation:spin .6s linear infinite;
  vertical-align:middle;margin-right:5px;
}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

/* ── MODAL ──────────────────────────────────────────────────────────────── */
.modal-overlay{
  display:none;position:fixed;inset:0;
  background:rgba(0,0,0,.7);backdrop-filter:blur(3px);
  z-index:999;align-items:center;justify-content:center;
}
.modal-overlay.show{display:flex}
.modal{
  background:var(--panel);border:1px solid var(--accent);
  border-radius:8px;padding:24px;width:90%;
  max-width:700px;max-height:88vh;overflow-y:auto;font-size:13px;
  box-shadow:0 8px 32px rgba(0,0,0,.6);
}
.modal h3{color:var(--accent-light);margin-bottom:16px;font-size:15px;font-weight:600}
.modal pre{
  background:var(--bg);padding:12px;border-radius:var(--radius);
  overflow:auto;max-height:280px;white-space:pre-wrap;
  color:#8ab4d4;font-size:10px;font-family:var(--mono);
  border:1px solid var(--border);
}
.modal label{display:block;margin-bottom:3px;color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.modal-footer{display:flex;gap:8px;margin-top:16px;justify-content:flex-end}
.modal-close{
  padding:6px 16px;background:transparent;border:1px solid var(--dim);
  color:var(--dim);border-radius:var(--radius);cursor:pointer;font-size:12px;
}
.modal-close:hover{border-color:var(--accent);color:var(--accent)}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px}
.info-item label{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em}
.info-item .val{font-family:var(--mono);font-size:12px;color:var(--text);margin-top:2px}
hr.dim{border:none;border-top:1px solid var(--border);margin:14px 0}

/* ── SCROLLBAR ──────────────────────────────────────────────────────────── */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:10px}
::-webkit-scrollbar-thumb:hover{background:var(--dim)}

/* ── GRID ───────────────────────────────────────────────────────────────── */
.grid2{display:grid;grid-template-columns:1fr 300px;gap:16px}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}

/* ── NOTE ───────────────────────────────────────────────────────────────── */
.note-item{
  background:var(--panel2);padding:8px 12px;border-radius:var(--radius);
  margin-bottom:6px;font-size:11px;border-left:2px solid var(--accent);
}
.note-time{font-family:var(--mono);font-size:10px;color:var(--dim);margin-right:6px}

/* ── PROCESS TABLE ──────────────────────────────────────────────────────── */
.proc-table{font-size:11px;font-family:var(--mono)}
.proc-table td{padding:3px 8px;color:var(--dim)}
.proc-table tr:hover td{color:var(--text)}
.proc-kill{
  padding:2px 7px;border-radius:3px;background:rgba(189,39,30,.2);
  color:var(--red-light);border:1px solid rgba(189,39,30,.4);
  cursor:pointer;font-size:10px;font-family:var(--mono);
}

/* ── OSINT ──────────────────────────────────────────────────────────────── */
.osint-section{
  background:var(--panel2);border:1px solid var(--border);
  border-radius:var(--radius);padding:12px;margin-bottom:10px;
}
.osint-label{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);margin-bottom:6px;font-weight:600}
.osint-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:4px}
.osint-key{color:var(--dim);font-size:10px;min-width:110px;font-weight:500}
.osint-val{color:var(--text);font-size:11px;font-family:var(--mono)}
.risk-badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:11px;font-family:var(--mono);font-weight:700}
.risk-ALTO{background:rgba(189,39,30,.2);color:var(--red-light);border:1px solid rgba(189,39,30,.4)}
.risk-MÉDIO{background:rgba(254,197,20,.1);color:var(--yellow);border:1px solid rgba(254,197,20,.3)}
.risk-BAIXO{background:rgba(0,191,179,.1);color:var(--teal);border:1px solid rgba(0,191,179,.3)}
.ticket-card{background:var(--panel2);border:1px solid var(--border);border-radius:var(--radius);padding:12px;margin-bottom:8px}
.ticket-id{font-family:var(--mono);font-size:11px;color:var(--accent-light)}
.sandbox-result{font-family:var(--mono);font-size:11px;padding:10px;background:var(--bg);border-radius:var(--radius);line-height:1.8;border:1px solid var(--border)}
.evidence-chain{font-family:var(--mono);font-size:10px;color:var(--dim);padding:6px 0;border-bottom:1px solid var(--border)}
.tab-group{display:flex;gap:0;margin-bottom:12px;border-bottom:1px solid var(--border)}
.tab-mini{
  padding:6px 14px;cursor:pointer;font-size:11px;font-family:var(--sans);font-weight:500;
  color:var(--dim);border-bottom:2px solid transparent;text-transform:uppercase;letter-spacing:.06em;transition:.15s;
}
.tab-mini.active{color:var(--accent-light);border-bottom-color:var(--accent)}
.tab-pane{display:none}.tab-pane.active{display:block}

/* ── AGENTS GRID ────────────────────────────────────────────────────────── */
.agent-card{
  background:var(--panel);border:1px solid var(--border);
  border-radius:var(--radius);padding:16px;transition:.15s;
}
.agent-card:hover{border-color:var(--accent)}
.agent-card-header{display:flex;align-items:center;gap:10px;margin-bottom:10px}
.agent-card-name{font-weight:600;font-size:13px}
.agent-card-id{font-family:var(--mono);font-size:10px;color:var(--dim)}
.agent-card-meta{font-size:11px;color:var(--dim);line-height:1.8}
.agent-status-ok{color:var(--teal);font-weight:600}
.agent-status-off{color:var(--dim)}

/* ── RESPONSIVE ─────────────────────────────────────────────────────────── */
@media(max-width:900px){
  .sidebar{display:none}
  .stats{grid-template-columns:repeat(2,1fr)}
}
</style>

  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>

<!-- TOP HEADER -->
<header>
  <div class="logo">
    <div class="logo-icon">W</div>
    SOAR · WAZUH
    <span class="logo-sub">v2</span>
  </div>
  <div id="status-bar">
    <span id="wazuh-dot"><span class="dot warn"></span>verificando...</span>
    <span id="alert-count" style="color:var(--dim)">─</span>
    <span id="last-refresh" style="color:var(--dim);font-size:10px">─</span>
    <button class="hdr-btn" onclick="downloadReport()">📄 Relatório PDF</button>
    <button class="hdr-btn" onclick="refresh()">↻ Refresh</button>
  </div>
</header>

<div class="app-body">

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sidebar-section">Menu Principal</div>

  <div class="sidebar-item active" id="nav-alerts" onclick="switchTab('alerts')">
    <span class="si-icon">🔔</span>
    Alertas
    <span class="sidebar-badge red" id="sb-alerts">─</span>
  </div>

  <div class="sidebar-item" id="nav-incidents" onclick="switchTab('incidents')">
    <span class="si-icon">📋</span>
    Incidentes
    <span class="sidebar-badge" id="sb-incidents">0</span>
  </div>

  <div class="sidebar-item" id="nav-agents" onclick="switchTab('agents')">
    <span class="si-icon">🖥</span>
    Agentes
    <span class="sidebar-badge" id="sb-agents">─</span>
  </div>

  <div class="sidebar-item" id="nav-log" onclick="switchTab('log')">
    <span class="si-icon">📜</span>
    Log de Ações
  </div>

  <div class="sidebar-item" id="nav-vulns" onclick="switchTab('vulns')">
    <span class="si-icon">🛡</span>
    Vulnerabilidades
    <span class="sidebar-badge" id="sb-vulns">─</span>
  </div>

  <div class="sidebar-item" id="nav-mitre" onclick="switchTab('mitre')">
    <span class="si-icon">⚔️</span>
    MITRE ATT&CK
    <span class="sidebar-badge" id="sb-mitre">─</span>
  </div>

  <div class="sidebar-divider"></div>
  <div class="sidebar-section">Notificações</div>

  <div class="sidebar-item" onclick="testNotify()">
    <span class="si-icon">✈️</span>
    Testar Telegram
  </div>

  <div class="sidebar-divider"></div>
  <div class="sidebar-section">Ambiente</div>

  <div class="sidebar-item" style="cursor:default;color:var(--dim)">
    <span class="si-icon">🌐</span>
    <span style="font-size:11px" id="sb-host">192.168.0.10</span>
  </div>
  <div class="sidebar-item" style="cursor:default;color:var(--dim)">
    <span class="si-icon">🔒</span>
    <span style="font-size:11px">Porta 8000</span>
  </div>
</nav>

<!-- CONTENT -->
<div class="content-area">

<!-- ═══ PAGE: ALERTS ═══ -->
<div class="page active" id="page-alerts">
  <div class="stats">
    <div class="stat-card c-blue"  id="card-total"  onclick="filterByCard('all')"      title="Ver todos os alertas">
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
    </div>
  </div>

  <!-- GRÁFICO PREDITIVO 7 DIAS -->
  <div class="panel" style="margin-bottom:16px">
    <div class="panel-head">
      Alertas por Severidade (7 dias)
      <span style="display:flex;gap:8px;align-items:center">
        <span style="font-size:10px;color:var(--red-light)">● Crítico</span>
        <span style="font-size:10px;color:var(--orange)">● Alto</span>
        <span style="font-size:10px;color:var(--yellow)">● Médio</span>
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
  </div>

  <div class="filter-bar">
    <select id="f-level" onchange="applyFilters()">
      <option value="">Todos os níveis</option>
      <option value="crit">Críticos (≥12)</option>
      <option value="high">Altos (7–11)</option>
      <option value="med">Médios (4–6)</option>
      <option value="low">Baixos (&lt;4)</option>
    </select>
    <select id="f-status" onchange="applyFilters()">
      <option value="">Todos os status</option>
      <option value="open">Aberto</option>
      <option value="actioned">Acionado</option>
      <option value="escalated">Escalado</option>
      <option value="ignored">Ignorado</option>
      <option value="fp">Falso Positivo</option>
    </select>
    <input id="f-search" placeholder="Buscar descrição / agente…" oninput="applyFilters()" style="width:220px">
    <button class="btn btn-gray" onclick="clearFilters()">✕ Limpar</button>
  </div>
      <!-- Filtros Rapidos -->
      <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap" id="quick-filters-bar">
        <button id="qf-crit" class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('crit')">&#x1F534; Apenas Criticos</button>
        <button id="qf-hour" class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('hour')">&#x23F1; Ultima Hora</button>
        <button id="qf-mine" class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('mine')">&#x1F464; Meus Incidentes</button>
        <button id="qf-fp"   class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="toggleQuickFilter('fp')">&#x2705; Falsos Positivos</button>
        <span style="margin-left:8px;border-left:1px solid var(--border);padding-left:8px;display:flex;gap:4px">
          <button class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="selectAllAlerts()">&#x2611; Selecionar Todos</button>
          <button class="btn btn-gray" style="font-size:11px;padding:3px 10px" onclick="deleteSelected()">&#x1F5D1; Deletar Selecionados</button><button class="btn btn-gray" style="font-size:11px;padding:3px 10px;color:var(--red-light)" onclick="deleteAllAlerts()">&#x1F5D1; Deletar Todos</button><button class="btn" id="bulk-btn" style="font-size:11px;padding:3px 10px;background:rgba(239,68,68,.2);color:var(--red-light);border-color:rgba(239,68,68,.4)" onclick="openBulkActions()" disabled>&#x26A1; Acao em Massa (<span id="bulk-count">0</span>)</button>
        </span>
      </div>


  <div class="panel">
    <div class="panel-head">Alertas Recentes <span id="tbl-count">─</span></div>
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>Nível</th><th>Agente</th><th>Regra</th><th>Descrição</th>
            <th>Hora</th><th>Responsável</th><th>Status</th><th>Ações</th>
          </tr>
        </thead>
        <tbody id="alert-tbody"><tr><td colspan="8" class="empty">Carregando…</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ═══ PAGE: INCIDENTS ═══ -->
<div class="page" id="page-incidents">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
    <span style="font-family:var(--mono);color:var(--dim);font-size:11px">GESTÃO DE INCIDENTES</span>
    <button class="btn btn-blue btn-lg" onclick="openNewIncident()">+ Novo Incidente</button>
  </div>
  <div id="incident-list"><div class="empty">Nenhum incidente criado ainda.</div></div>
</div>

<!-- ═══ PAGE: AGENTS ═══ -->
<div class="page" id="page-agents">
  <div id="agents-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px">
    <div class="empty">Carregando agentes…</div>
  </div>
</div>

<!-- ═══ PAGE: LOG ═══ -->
<div class="page" id="page-log">
  <div class="panel">
    <div class="panel-head">Log de Ações <span id="log-count-pg">─</span></div>
    <div style="padding:10px 14px" id="log-full"></div>
  </div>
</div>

<!-- ═══ PAGE: VULNERABILITIES ═══ -->
<div class="page" id="page-vulns">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
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
  </div>

  <div style="display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap">
    <input id="vuln-search" class="input-dark" placeholder="🔍 Buscar por CVE, pacote ou agente..."
      oninput="applyVulnFilters()" style="flex:1;min-width:240px">
    <select id="vuln-sev" class="input-dark" onchange="applyVulnFilters()" style="width:140px">
      <option value="">Todos</option>
      <option value="Critical">Crítico</option>
      <option value="High">Alto</option>
      <option value="Medium">Médio</option>
      <option value="Low">Baixo</option>
    </select>
    <select id="vuln-status" class="input-dark" onchange="applyVulnFilters()" style="width:140px">
      <option value="">Todas</option>
      <option value="DETECTED">Detectado</option>
      <option value="VALID">Validado</option>
      <option value="MITIGATED">Mitigado</option>
    </select>
  </div>

  <div id="vuln-list">
    <div class="empty">Clique em Atualizar para carregar vulnerabilidades.</div>
  </div>
</div>

<!-- ═══ PAGE: MITRE ATT&CK ═══ -->
<div class="page" id="page-mitre">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
    <div>
      <div style="font-size:16px;font-weight:700;color:var(--text);margin-bottom:2px">⚔️ Painel MITRE ATT&CK</div>
      <div style="font-size:11px;color:var(--dim)">Mapeamento de técnicas baseado em alertas Wazuh em tempo real</div>
    </div>
    <button class="btn btn-blue" onclick="loadMitre()">↻</button>
  </div>

  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0">
    <div class="panel" style="padding:14px;text-align:center">
      <div style="font-size:26px;font-weight:700;color:var(--accent-light);font-family:var(--mono)" id="mitre-total">─</div>
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Técnicas Mapeadas</div>
    </div>
    <div class="panel" style="padding:14px;text-align:center">
      <div style="font-size:26px;font-weight:700;color:var(--yellow);font-family:var(--mono)" id="mitre-active">─</div>
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Com Alertas Ativos</div>
    </div>
    <div class="panel" style="padding:14px;text-align:center">
      <div style="font-size:26px;font-weight:700;color:var(--red-light);font-family:var(--mono)" id="mitre-crit">─</div>
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Nível Crítico</div>
    </div>
    <div class="panel" style="padding:14px;text-align:center">
      <div style="font-size:26px;font-weight:700;color:var(--teal);font-family:var(--mono)" id="mitre-tactics">─</div>
      <div style="font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-top:4px">Táticas Cobertas</div>
    </div>
  </div>

  <div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center">
    <input id="mitre-search" class="input-dark" placeholder="🔍 Buscar técnica, ID ou tática..."
      oninput="applyMitreFilters()" style="flex:1;min-width:240px">
    <select id="mitre-tactic" class="input-dark" onchange="applyMitreFilters()" style="width:180px">
      <option value="">Todas Táticas</option>
      <option value="initial-access">Initial Access</option>
      <option value="execution">Execution</option>
      <option value="persistence">Persistence</option>
      <option value="privilege-escalation">Privilege Escalation</option>
      <option value="defense-evasion">Defense Evasion</option>
      <option value="credential-access">Credential Access</option>
      <option value="discovery">Discovery</option>
      <option value="lateral-movement">Lateral Movement</option>
      <option value="collection">Collection</option>
      <option value="exfiltration">Exfiltration</option>
      <option value="impact">Impact</option>
      <option value="command-and-control">Command & Control</option>
    </select>
    <select id="mitre-cat" class="input-dark" onchange="applyMitreFilters()" style="width:160px">
      <option value="">Todas Categorias</option>
      <option value="critical">Crítico</option>
      <option value="high">Alto</option>
      <option value="medium">Médio</option>
      <option value="active">Com Alerta Ativo</option>
    </select>
    <select id="mitre-view" class="input-dark" onchange="renderMitre()" style="width:100px">
      <option value="grid">Grid</option>
      <option value="matrix">Matriz</option>
    </select>
    <span style="font-size:11px;color:var(--dim)" id="mitre-shown">─ técnicas exibidas</span>
  </div>

  <div id="mitre-container">
    <div class="empty">Clique em ↻ para carregar dados MITRE.</div>
  </div>
</div>

<!-- ════════════════ MODALS ════════════════ -->

<!-- Modal: Investigar -->
<div class="modal-overlay" id="modal-investigate">
  <div class="modal">
    <h3>🔍 Investigar Alerta</h3>
    <div class="info-grid" id="inv-info"></div>
    <hr class="dim">
    <div style="margin-bottom:8px;font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em">Processos do Agente</div>
    <div id="inv-processes"><div class="empty" style="padding:10px">Carregando…</div></div>
    <hr class="dim">
    <div style="margin-bottom:8px;font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em">Portas Abertas</div>
    <div id="inv-ports"><div class="empty" style="padding:10px">Carregando…</div></div>
    <hr class="dim">
    <div style="margin-bottom:8px;font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.06em">Raw Alert</div>
    <pre id="inv-raw"></pre>
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-investigate')">Fechar</button>
    </div>
  </div>
</div>

<!-- Modal: Kill Process -->
<div class="modal-overlay" id="modal-kill">
  <div class="modal">
    <h3>⚔️ Kill Process</h3>
    <p style="color:var(--dim);font-size:12px;margin-bottom:14px">Encerrar processo malicioso no agente <b id="kill-agent-label" style="color:var(--accent)"></b></p>
    <label>PID do Processo</label>
    <input id="kill-pid" class="input-dark" placeholder="ex: 1337" style="margin-bottom:12px">
    <label>Motivo (opcional)</label>
    <input id="kill-reason" class="input-dark" placeholder="ex: Processo suspeito detectado">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-kill')">Cancelar</button>
      <button class="btn btn-red btn-lg" onclick="submitKill()">⚔️ Encerrar Processo</button>
    </div>
  </div>
</div>

<!-- Modal: Ban IP -->
<div class="modal-overlay" id="modal-ban">
  <div class="modal">
    <h3>🚫 Ban IP</h3>
    <p style="color:var(--dim);font-size:12px;margin-bottom:14px">Bloquear IP via firewall no agente <b id="ban-agent-label" style="color:var(--accent)"></b></p>
    <label>Endereço IP</label>
    <input id="ban-ip" class="input-dark" placeholder="ex: 45.33.32.156" style="margin-bottom:12px">
    <label>Motivo (opcional)</label>
    <input id="ban-reason" class="input-dark" placeholder="ex: Fonte de ataque">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-ban')">Cancelar</button>
      <button class="btn btn-orange btn-lg" onclick="submitBan()">🚫 Banir IP</button>
    </div>
  </div>
</div>

<!-- Modal: Assign -->
<div class="modal-overlay" id="modal-assign">
  <div class="modal">
    <h3>👤 Atribuir Responsável</h3>
    <label>Analista Responsável</label>
    <input id="assign-name" class="input-dark" placeholder="ex: João Silva" style="margin-bottom:12px">
    <label>Prioridade</label>
    <select id="assign-priority" class="input-dark" style="margin-bottom:12px">
      <option value="high">Alta</option>
      <option value="medium">Média</option>
      <option value="low">Baixa</option>
    </select>
    <label>Nota</label>
    <input id="assign-note" class="input-dark" placeholder="Observação sobre a atribuição…">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-assign')">Cancelar</button>
      <button class="btn btn-teal btn-lg" onclick="submitAssign()">✓ Atribuir</button>
    </div>
  </div>
</div>

<!-- Modal: Escalar -->
<div class="modal-overlay" id="modal-escalate">
  <div class="modal">
    <h3>⬆️ Escalar Alerta</h3>
    <label>Para (equipe / pessoa)</label>
    <input id="esc-to" class="input-dark" placeholder="ex: SOC Tier 2 / CSIRT" style="margin-bottom:12px">
    <label>Justificativa</label>
    <input id="esc-reason" class="input-dark" placeholder="ex: Possível comprometimento crítico">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-escalate')">Cancelar</button>
      <button class="btn btn-purple btn-lg" onclick="submitEscalate()">⬆️ Escalar</button>
    </div>
  </div>
</div>

<!-- Modal: Snapshot -->
<div class="modal-overlay" id="modal-snapshot">
  <div class="modal">
    <h3>📸 Snapshot do Agente</h3>
    <div id="snap-content"><div class="empty">Carregando…</div></div>
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-snapshot')">Fechar</button>
      <button class="btn btn-green btn-lg" onclick="downloadSnap()">⬇ Exportar JSON</button>
    </div>
  </div>
</div>

<!-- Modal: Novo Incidente -->
<div class="modal-overlay" id="modal-new-incident">
  <div class="modal">
    <h3>📋 Criar Novo Incidente</h3>
    <label>Título</label>
    <input id="inc-title" class="input-dark" placeholder="ex: Possível ransomware em servidor" style="margin-bottom:10px">
    <label>Prioridade</label>
    <select id="inc-priority" class="input-dark" style="margin-bottom:10px">
      <option value="high">Alta</option><option value="medium">Média</option><option value="low">Baixa</option>
    </select>
    <label>Responsável</label>
    <input id="inc-assignee" class="input-dark" placeholder="ex: João Silva" style="margin-bottom:10px">
    <label>Descrição</label>
    <input id="inc-desc" class="input-dark" placeholder="Descreva o incidente…">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-new-incident')">Cancelar</button>
      <button class="btn btn-blue btn-lg" onclick="submitNewIncident()">✓ Criar Incidente</button>
    </div>
  </div>
</div>

<!-- Modal: Notas -->
<div class="modal-overlay" id="modal-notes">
  <div class="modal">
    <h3 id="notes-title">📝 Notas do Alerta</h3>
    <div id="notes-list" style="margin-bottom:12px;max-height:200px;overflow-y:auto"></div>
    <label>Adicionar Nota</label>
    <input id="notes-input" class="input-dark" placeholder="Escreva uma observação…">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-notes')">Fechar</button>
      <button class="btn btn-blue btn-lg" onclick="submitNote()">➕ Adicionar</button>
    </div>
  </div>
</div>

<!-- Modal: OSINT / Reputação / Whois / GeoIP -->
<div class="modal-overlay" id="modal-osint">
  <div class="modal" style="max-width:760px">
    <h3>🌐 OSINT · Investigação e Enriquecimento</h3>
    <div class="tab-group">
      <div class="tab-mini active" onclick="switchOsintTab('reputation')">🔍 Reputação</div>
      <div class="tab-mini" onclick="switchOsintTab('whois')">📋 Whois / GeoIP</div>
      <div class="tab-mini" onclick="switchOsintTab('userinfo')">👤 User Info (AD/LDAP)</div>
    </div>
    <!-- Tab: Reputação -->
    <div class="tab-pane active" id="osint-tab-reputation">
      <div style="display:flex;gap:8px;margin-bottom:12px;align-items:flex-end">
        <div style="flex:1">
          <label>IP ou Domínio para consulta</label>
          <input id="osint-target" class="input-dark" placeholder="ex: 45.33.32.156 ou malicious.example.com">
        </div>
        <button class="btn btn-pink btn-lg" onclick="runOsint()"><span id="osint-spin"></span>🌐 Consultar</button>
      </div>
      <div id="osint-result"><div class="empty" style="padding:20px">Informe um IP ou domínio e clique em Consultar.</div></div>
    </div>
    <!-- Tab: Whois / GeoIP -->
    <div class="tab-pane" id="osint-tab-whois">
      <div style="display:flex;gap:8px;margin-bottom:12px;align-items:flex-end">
        <div style="flex:1">
          <label>IP ou Domínio</label>
          <input id="whois-target" class="input-dark" placeholder="ex: 8.8.8.8">
        </div>
        <button class="btn btn-teal btn-lg" onclick="runWhois()">📋 Consultar Whois</button>
      </div>
      <div id="whois-result"><div class="empty" style="padding:20px">Aguardando consulta…</div></div>
    </div>
    <!-- Tab: User Info -->
    <div class="tab-pane" id="osint-tab-userinfo">
      <p style="color:var(--dim);font-size:11px;margin-bottom:12px">Consulta simulada de usuário em AD/LDAP. Em produção, configure endpoint /api/ldap/user.</p>
      <label>Nome de usuário ou e-mail</label>
      <input id="userinfo-input" class="input-dark" placeholder="ex: jsilva ou joao.silva@empresa.com" style="margin-bottom:10px">
      <button class="btn btn-purple btn-lg" onclick="runUserInfo()">👤 Buscar Usuário</button>
      <div id="userinfo-result" style="margin-top:12px"></div>
    </div>
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-osint')">Fechar</button>
      <button class="btn btn-gray btn-lg" onclick="exportOsint()">⬇ Exportar JSON</button>
    </div>
  </div>
</div>

<!-- Modal: Sandbox Analysis -->
<div class="modal-overlay" id="modal-sandbox">
  <div class="modal" style="max-width:720px">
    <h3>🧪 Sandbox Analysis</h3>
    <p style="color:var(--dim);font-size:11px;margin-bottom:12px">Análise de hash, arquivo ou URL suspeita. Integração com VirusTotal/Any.run (simulada).</p>
    <label>Hash MD5/SHA256, URL ou nome de arquivo</label>
    <input id="sandbox-target" class="input-dark" placeholder="ex: d41d8cd98f00b204e9800998ecf8427e" style="margin-bottom:10px">
    <label>Tipo de análise</label>
    <select id="sandbox-type" class="input-dark" style="margin-bottom:12px">
      <option value="hash">Hash (MD5/SHA256)</option>
      <option value="url">URL</option>
      <option value="file">Nome de Arquivo</option>
    </select>
    <button class="btn btn-purple btn-lg" onclick="runSandbox()" style="margin-bottom:14px"><span id="sandbox-spin"></span>🧪 Analisar</button>
    <div id="sandbox-result"><div class="empty" style="padding:16px">Aguardando análise…</div></div>
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-sandbox')">Fechar</button>
    </div>
  </div>
</div>

<!-- Modal: Revogar Tokens / Reset Sessão -->
<div class="modal-overlay" id="modal-revoke">
  <div class="modal">
    <h3>🔑 Revogar Tokens / Reset de Sessão</h3>
    <p style="color:var(--dim);font-size:12px;margin-bottom:14px">Alerta: <b id="revoke-alert-label" style="color:var(--accent)"></b></p>
    <label>Usuário / Conta</label>
    <input id="revoke-user" class="input-dark" placeholder="ex: jsilva ou DOMAIN\\jsilva" style="margin-bottom:10px">
    <label>Tipo de ação</label>
    <select id="revoke-type" class="input-dark" style="margin-bottom:10px">
      <option value="revoke_tokens">Revogar todos os tokens OAuth/JWT</option>
      <option value="reset_session">Reset de Sessão Ativa</option>
      <option value="force_mfa">Forçar Re-autenticação MFA</option>
      <option value="all">Todas as ações acima</option>
    </select>
    <label>Justificativa</label>
    <input id="revoke-reason" class="input-dark" placeholder="ex: Suspeita de comprometimento de credencial">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-revoke')">Cancelar</button>
      <button class="btn btn-red btn-lg" onclick="submitRevoke()">🔑 Executar</button>
    </div>
  </div>
</div>

<!-- Modal: Desabilitar Conta -->
<div class="modal-overlay" id="modal-disable-account">
  <div class="modal">
    <h3>🚷 Desabilitar Conta (AD/LDAP)</h3>
    <p style="color:var(--dim);font-size:12px;margin-bottom:14px">Alerta: <b id="disable-alert-label" style="color:var(--accent)"></b></p>
    <label>Usuário / Conta AD</label>
    <input id="disable-user" class="input-dark" placeholder="ex: jsilva" style="margin-bottom:10px">
    <label>Escopo</label>
    <select id="disable-scope" class="input-dark" style="margin-bottom:10px">
      <option value="disable_ad">Desabilitar conta no AD</option>
      <option value="lock_ldap">Bloquear conta no LDAP</option>
      <option value="remove_groups">Remover de grupos privilegiados</option>
      <option value="full">Desabilitar + Revogar tokens + Remover grupos</option>
    </select>
    <label>Motivo</label>
    <input id="disable-reason" class="input-dark" placeholder="ex: Atividade maliciosa detectada">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-disable-account')">Cancelar</button>
      <button class="btn btn-orange btn-lg" onclick="submitDisableAccount()">🚷 Desabilitar</button>
    </div>
  </div>
</div>

<!-- Modal: Criar Ticket Jira/ITSM -->
<div class="modal-overlay" id="modal-ticket">
  <div class="modal" style="max-width:700px">
    <h3>🎫 Criar Ticket Jira / ITSM</h3>
    <label>Projeto / Fila</label>
    <select id="ticket-project" class="input-dark" style="margin-bottom:10px">
      <option value="SOC">SOC - Security Operations</option>
      <option value="IR">IR - Incident Response</option>
      <option value="VULN">VULN - Vulnerability Management</option>
      <option value="CSIRT">CSIRT - Critical Incidents</option>
    </select>
    <label>Título do Ticket</label>
    <input id="ticket-title" class="input-dark" placeholder="ex: Alerta crítico — Possível ransomware" style="margin-bottom:10px">
    <label>Prioridade</label>
    <select id="ticket-priority" class="input-dark" style="margin-bottom:10px">
      <option value="Critical">Critical</option>
      <option value="High">High</option>
      <option value="Medium">Medium</option>
      <option value="Low">Low</option>
    </select>
    <label>Responsável (assignee)</label>
    <input id="ticket-assignee" class="input-dark" placeholder="ex: analista@empresa.com" style="margin-bottom:10px">
    <label>Descrição / Detalhes</label>
    <textarea id="ticket-desc" class="input-dark" rows="3" placeholder="Descreva o contexto do incidente…" style="resize:vertical;margin-bottom:10px"></textarea>
    <label>Labels / Tags</label>
    <input id="ticket-labels" class="input-dark" placeholder="ex: malware, endpoint, tier2">
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-ticket')">Cancelar</button>
      <button class="btn btn-teal btn-lg" onclick="submitTicket()">🎫 Criar Ticket</button>
    </div>
  </div>
</div>

<!-- Modal: Ticket criado (confirmação) -->
<div class="modal-overlay" id="modal-ticket-confirm">
  <div class="modal" style="max-width:480px;text-align:center">
    <h3 style="color:var(--green)">✅ Ticket Criado com Sucesso</h3>
    <div id="ticket-confirm-content" style="margin:16px 0"></div>
    <div class="modal-footer" style="justify-content:center">
      <button class="modal-close" onclick="closeModal('modal-ticket-confirm')">Fechar</button>
    </div>
  </div>
</div>

<!-- Modal: Coleta de Evidências Forenses -->
<div class="modal-overlay" id="modal-forensics">
  <div class="modal" style="max-width:760px">
    <h3>🔬 Resposta Avançada — Coleta de Evidências (Forensics)</h3>
    <div id="forensics-status" style="margin-bottom:12px"></div>
    <div class="tab-group">
      <div class="tab-mini active" onclick="switchForensicTab('summary')">📄 Resumo</div>
      <div class="tab-mini" onclick="switchForensicTab('processes')">⚙️ Processos</div>
      <div class="tab-mini" onclick="switchForensicTab('network')">🌐 Rede</div>
      <div class="tab-mini" onclick="switchForensicTab('chain')">🔗 Cadeia de Custódia</div>
      <div class="tab-mini" onclick="switchForensicTab('raw')">📦 Raw</div>
    </div>
    <div class="tab-pane active" id="ftab-summary"><div id="fev-summary"></div></div>
    <div class="tab-pane" id="ftab-processes"><div id="fev-processes"></div></div>
    <div class="tab-pane" id="ftab-network"><div id="fev-network"></div></div>
    <div class="tab-pane" id="ftab-chain"><div id="fev-chain"></div></div>
    <div class="tab-pane" id="ftab-raw"><pre id="fev-raw" style="max-height:340px;overflow:auto"></pre></div>
    <div class="modal-footer">
      <button class="modal-close" onclick="closeModal('modal-forensics')">Fechar</button>
      <button class="btn btn-green btn-lg" onclick="exportEvidence()">⬇ Exportar Evidência</button>
    </div>
  </div>
</div>

<script>
const API = '';
let alerts = [], agents = [], actionLog = [], incidents = [];
let snapData = null;
let currentAlertId = null;

// ── Helpers ──────────────────────────────────────────────────────────────────
function lvlClass(n){ return n>=12?'crit':n>=7?'high':n>=4?'medium':'low'; }
function timeShort(iso){ try{return new Date(iso).toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}catch{return iso} }
function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;') }
function closeModal(id){ document.getElementById(id).classList.remove('show') }
function openModal(id){ document.getElementById(id).classList.add('show') }
document.querySelectorAll('.modal-overlay').forEach(m=>{
  m.addEventListener('click',e=>{ if(e.target===m) m.classList.remove('show') })
})

// ── Tabs ─────────────────────────────────────────────────────────────────────
function switchTab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>{
    const pages=['alerts','incidents','agents','log'];
    t.classList.toggle('active', pages[i]===name);
  });
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  if(name==='agents') renderAgentCards();
  if(name==='log') renderLogFull();
  if(name==='incidents') renderIncidents();
}

// ── API ───────────────────────────────────────────────────────────────────────
async function apiFetch(path, opts){
  const r = await fetch(API+path, opts);
  if(!r.ok) throw new Error('HTTP '+r.status);
  return r.json();
}
async function execAction(alertId, action, extra={}){
  return apiFetch('/api/actions',{
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({alert_id:alertId, action, ...extra})
  });
}

// ── Filters ───────────────────────────────────────────────────────────────────
function filterByCard(type){
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

function applyFilters(){
  const lv = document.getElementById('f-level').value;
  const st = document.getElementById('f-status').value;
  const q  = document.getElementById('f-search').value.toLowerCase();
  let filtered = alerts.filter(a=>{
    if(lv==='crit' && a.level<12) return false;
    if(lv==='high' && (a.level<7||a.level>=12)) return false;
    if(lv==='med'  && (a.level<4||a.level>=7))  return false;
    if(lv==='low'  && a.level>=4) return false;
    if(st && a.status!==st && !(st==='fp'&&a.false_positive)) return false;
    if(q && !a.rule_desc.toLowerCase().includes(q) && !a.agent_name.toLowerCase().includes(q)) return false;
    return true;
  });
  renderAlertsTable(filtered);
}
function clearFilters(){
  document.getElementById('f-level').value='';
  document.getElementById('f-status').value='';
  document.getElementById('f-search').value='';
  document.querySelectorAll('.stat-card').forEach(c => c.classList.remove('card-active'));
  renderAlertsTable(alerts);
}

// ── Render Alerts ─────────────────────────────────────────────────────────────
function renderAlerts(){
  const lv = document.getElementById('f-level') ? document.getElementById('f-level').value : '';
  const st = document.getElementById('f-status') ? document.getElementById('f-status').value : '';
  const q  = document.getElementById('f-search') ? document.getElementById('f-search').value : '';
  if(!lv && !st && !q){
    renderAlertsTable(alerts);
  } else {
    applyFilters();
  }
  updateStats();
}

function renderAlertsTable(list){
  const tbody = document.getElementById('alert-tbody');
  document.getElementById('tbl-count').textContent = list.length;
  if(!list.length){
    tbody.innerHTML='<tr><td colspan="8" class="empty">Nenhum alerta encontrado.<br>Configure o webhook no Wazuh Manager.</td></tr>';
    return;
  }
  tbody.innerHTML = list.map(a=>{
    const lc = lvlClass(a.level);
    const dis = a.status==='open'?'':'disabled';
    const st = a.false_positive?'fp':a.escalated?'escalated':a.status;
    const stLabel = a.false_positive?'falso+':a.escalated?'escalado':a.status;
    return `<tr>
      <td style="width:30px;text-align:center"><input type="checkbox" class="alert-chk" data-id="${a.id}" onchange="toggleAlertChk(this)"></td>
      <td><span class="lvl ${lc}">${a.level}</span></td>
      <td style="font-family:var(--mono);font-size:11px">${esc(a.agent_name)}<br><span style="color:var(--dim);font-size:10px">#${esc(a.agent_id)}</span></td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--dim)">${esc(a.rule_id)}</td>
      <td style="max-width:220px;font-size:11px" title="${esc(a.rule_desc)}">${esc(a.rule_desc.substring(0,55))}${a.rule_desc.length>55?'…':''}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--dim);white-space:nowrap">${timeShort(a.timestamp)}</td>
      <td style="font-size:11px;color:var(--accent)">${a.assignee?'👤 '+esc(a.assignee):'─'}</td>
      <td><span class="badge ${st}">${stLabel}</span></td>
      <td>
        <div class="btn-group">
          <button class="btn btn-blue"    ${dis} onclick="doAction('${a.id}','quarantine',this)" title="Isolar agente">🔒 Isolar</button>
          <button class="btn btn-green"   ${dis} onclick="doAction('${a.id}','patch',this)"      title="Patch">🔧 Patch</button>
          <button class="btn btn-red"     ${dis} onclick="doAction('${a.id}','delete',this)"     title="Deletar ameaça">🗑 Delete</button>
          <button class="btn btn-orange"  ${dis} onclick="openKill('${a.id}')"                  title="Kill process">⚔️ Kill</button>
          <button class="btn btn-yellow"  onclick="openBan('${a.id}')"                          title="Banir IP/Domínio">🚫 Ban</button>
          <button class="btn btn-teal"    onclick="openInvestigate('${a.id}')"                  title="Investigar + Enriquecimento">🔍 Inv.</button>
          <button class="btn btn-pink"    onclick="openOsint('${a.id}')"                        title="OSINT / Reputação / Whois / GeoIP">🌐 OSINT</button>
          <button class="btn btn-purple"  onclick="openSandbox('${a.id}')"                      title="Sandbox Analysis">🧪 Sandbox</button>
          <button class="btn btn-purple"  onclick="openSnapshot('${a.id}')"                     title="Snapshot Forense">📸 Snap</button>
          <button class="btn btn-gray"    onclick="openAssign('${a.id}')"                       title="Atribuir / User Info AD">👤 Assign</button>
          <button class="btn btn-purple"  onclick="openEscalate('${a.id}')"                     title="Escalar SOC Tier 2/3">⬆️ Esc.</button>
          <button class="btn btn-red"     onclick="openRevokeTokens('${a.id}')"                 title="Revogar Tokens / Reset Sessão">🔑 Revoke</button>
          <button class="btn btn-orange"  onclick="openDisableAccount('${a.id}')"               title="Desabilitar Conta AD/LDAP">🚷 Disable</button>
          <button class="btn btn-teal"    onclick="openCreateTicket('${a.id}')"                 title="Criar Ticket Jira/ITSM">🎫 Ticket</button>
          <button class="btn btn-yellow"  ${dis} onclick="doAction('${a.id}','fp',this)"        title="Falso Positivo">⚠️ FP</button>
          <button class="btn btn-green"   onclick="openForensics('${a.id}')"                    title="Coletar Evidências Forenses">🔬 Forense</button>
          <button class="btn btn-gray"    onclick="openNotes('${a.id}')"                        title="Notas">📝 ${a.notes?a.notes.length:0}</button>
          <button class="btn btn-gray"    ${dis} onclick="doAction('${a.id}','restore',this)"   title="Rollback/Restaurar">↩ Rollback</button>
          <button class="btn btn-gray"    ${dis} onclick="doAction('${a.id}','ignore',this)"    title="Ignorar">✓ Ignorar</button>
        </div>
      </td>
    </tr>`;
  }).join('');
}

function updateStats(){
  let crit=0,high=0,esc_count=0;
  alerts.forEach(a=>{
    if(a.level>=12) crit++;
    else if(a.level>=7) high++;
    if(a.escalated) esc_count++;
  });
  document.getElementById('s-total').textContent = alerts.length;
  document.getElementById('s-crit').textContent  = crit;
  document.getElementById('s-high').textContent  = high;
  document.getElementById('s-esc').textContent   = esc_count;
}

// ── Generic Action ─────────────────────────────────────────────────────────────
async function doAction(alertId, action, btn){
  if(btn){ btn.disabled=true; const o=btn.textContent; btn.innerHTML='<span class="spinner"></span>'; setTimeout(()=>{btn.textContent=o;btn.disabled=false},3000); }
  try{
    const r = await execAction(alertId, action);
    addLocalLog(action, r.agent_id||'?', 'ok', r.message||'OK');
    await loadAlerts();
  }catch(e){ addLocalLog(action,'?','err',e.message); }
}

// ── Kill Process ──────────────────────────────────────────────────────────────
function openKill(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  document.getElementById('kill-agent-label').textContent = a?a.agent_name:'?';
  document.getElementById('kill-pid').value='';
  document.getElementById('kill-reason').value='';
  openModal('modal-kill');
}
async function submitKill(){
  const pid = document.getElementById('kill-pid').value.trim();
  if(!pid){ alert('Informe o PID'); return; }
  closeModal('modal-kill');
  await doAction(currentAlertId,'kill',null);
  await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({alert_id:currentAlertId,action:'kill',pid})});
  addLocalLog('kill','?','ok',`PID ${pid} encerrado`);
  await loadAlerts();
}

// ── Ban IP ────────────────────────────────────────────────────────────────────
function openBan(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  document.getElementById('ban-agent-label').textContent = a?a.agent_name:'?';
  document.getElementById('ban-ip').value='';
  document.getElementById('ban-reason').value='';
  openModal('modal-ban');
}
async function submitBan(){
  const ip = document.getElementById('ban-ip').value.trim();
  if(!ip){ alert('Informe o IP'); return; }
  closeModal('modal-ban');
  try{
    const r = await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:currentAlertId,action:'ban_ip',ip})});
    addLocalLog('ban_ip', r.agent_id||'?', 'ok', `IP ${ip} banido`);
    await loadAlerts();
  }catch(e){ addLocalLog('ban_ip','?','err',e.message); }
}

// ── Investigate ───────────────────────────────────────────────────────────────
async function openInvestigate(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  if(!a) return;
  document.getElementById('inv-info').innerHTML = `
    <div class="info-item"><label>Agente</label><div class="val">${esc(a.agent_name)} #${esc(a.agent_id)}</div></div>
    <div class="info-item"><label>Regra</label><div class="val">${esc(a.rule_id)}</div></div>
    <div class="info-item"><label>Nível</label><div class="val" style="color:var(--red)">${a.level}</div></div>
    <div class="info-item"><label>Timestamp</label><div class="val">${esc(a.timestamp)}</div></div>
    <div class="info-item" style="grid-column:1/-1"><label>Descrição</label><div class="val">${esc(a.rule_desc)}</div></div>`;
  document.getElementById('inv-raw').textContent = JSON.stringify(a.raw||a, null, 2);
  document.getElementById('inv-processes').innerHTML = '<div class="empty" style="padding:8px">Carregando processos…</div>';
  document.getElementById('inv-ports').innerHTML     = '<div class="empty" style="padding:8px">Carregando portas…</div>';
  openModal('modal-investigate');
  // Marcar como investigando
  try{
    await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:alertId,action:'investigating'})});
    await loadAlerts();
  }catch{}
  // Carregar processos e portas
  try{
    const pd = await apiFetch(`/api/agent/${a.agent_id}/processes`);
    const procs = pd.processes||[];
    if(!procs.length){ document.getElementById('inv-processes').innerHTML='<div class="empty" style="padding:8px">Sem dados (agente offline?)</div>'; }
    else{
      document.getElementById('inv-processes').innerHTML=`<table class="proc-table" style="width:100%">
        <tr><th style="text-align:left;color:var(--dim);padding:3px 8px">PID</th><th style="text-align:left;color:var(--dim);padding:3px 8px">Nome</th><th style="text-align:left;color:var(--dim);padding:3px 8px">CPU%</th><th></th></tr>
        ${procs.slice(0,15).map(p=>`<tr><td>${p.pid||'─'}</td><td>${esc(p.name||'─')}</td><td>${p.cpu||'─'}</td><td><button class="proc-kill" onclick="quickKill('${a.agent_id}','${p.pid}')">kill</button></td></tr>`).join('')}
      </table>`;
    }
  }catch{ document.getElementById('inv-processes').innerHTML='<div class="empty" style="padding:8px">Sem dados de processos</div>'; }
  try{
    const portd = await apiFetch(`/api/agent/${a.agent_id}/ports`);
    const ports = portd.ports||[];
    if(!ports.length){ document.getElementById('inv-ports').innerHTML='<div class="empty" style="padding:8px">Sem portas abertas</div>'; }
    else{
      document.getElementById('inv-ports').innerHTML=`<table class="proc-table" style="width:100%">
        <tr><th style="text-align:left;color:var(--dim);padding:3px 8px">Porta</th><th style="text-align:left;color:var(--dim);padding:3px 8px">Protocolo</th><th style="text-align:left;color:var(--dim);padding:3px 8px">Estado</th><th style="text-align:left;color:var(--dim);padding:3px 8px">Processo</th></tr>
        ${ports.slice(0,15).map(p=>`<tr><td>${p.local&&p.local.port||'─'}</td><td>${esc(p.protocol||'─')}</td><td>${esc(p.state||'─')}</td><td>${esc(p.process&&p.process.name||'─')}</td></tr>`).join('')}
      </table>`;
    }
  }catch{ document.getElementById('inv-ports').innerHTML='<div class="empty" style="padding:8px">Sem dados de portas</div>'; }
}

async function quickKill(agentId, pid){
  if(!confirm(`Encerrar processo PID ${pid}?`)) return;
  try{
    await apiFetch('/api/agent/kill',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({agent_id:agentId,pid:String(pid)})});
    addLocalLog('kill',agentId,'ok',`PID ${pid} encerrado via investigação`);
  }catch(e){ addLocalLog('kill',agentId,'err',e.message); }
}

// ── Snapshot ──────────────────────────────────────────────────────────────────
async function openSnapshot(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  if(!a) return;
  snapData = null;
  document.getElementById('snap-content').innerHTML = '<div class="empty">Coletando dados do agente…</div>';
  openModal('modal-snapshot');
  try{
    const [ag, pd, portd] = await Promise.all([
      apiFetch(`/api/agent/${a.agent_id}/info`).catch(()=>({})),
      apiFetch(`/api/agent/${a.agent_id}/processes`).catch(()=>({processes:[]})),
      apiFetch(`/api/agent/${a.agent_id}/ports`).catch(()=>({ports:[]})),
    ]);
    snapData = { alert:a, agent_info:ag, processes:pd.processes||[], ports:portd.ports||[], snapshot_time: new Date().toISOString() };
    document.getElementById('snap-content').innerHTML = `
      <div class="info-grid">
        <div class="info-item"><label>Agente</label><div class="val">${esc(a.agent_name)}</div></div>
        <div class="info-item"><label>ID</label><div class="val">#${esc(a.agent_id)}</div></div>
        <div class="info-item"><label>Alerta</label><div class="val">${esc(a.rule_desc.substring(0,40))}</div></div>
        <div class="info-item"><label>Processos capturados</label><div class="val">${(pd.processes||[]).length}</div></div>
        <div class="info-item"><label>Portas capturadas</label><div class="val">${(portd.ports||[]).length}</div></div>
        <div class="info-item"><label>Hora do snapshot</label><div class="val">${new Date().toLocaleTimeString('pt-BR')}</div></div>
      </div>
      <pre style="max-height:200px">${esc(JSON.stringify(snapData,null,2).substring(0,2000))}…</pre>`;
  }catch(e){
    document.getElementById('snap-content').innerHTML = `<div class="empty">Erro ao coletar dados: ${esc(e.message)}</div>`;
  }
}
function downloadSnap(){
  if(!snapData) return;
  const blob = new Blob([JSON.stringify(snapData,null,2)],{type:'application/json'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href=url; a.download=`snapshot-${currentAlertId}-${Date.now()}.json`; a.click();
  URL.revokeObjectURL(url);
}

// ── Assign ────────────────────────────────────────────────────────────────────
function openAssign(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  document.getElementById('assign-name').value = a?a.assignee||'':'';
  openModal('modal-assign');
}
async function submitAssign(){
  const name = document.getElementById('assign-name').value.trim();
  const note = document.getElementById('assign-note').value.trim();
  if(!name){ alert('Informe o responsável'); return; }
  closeModal('modal-assign');
  try{
    await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:currentAlertId,action:'assign',assignee:name,note})});
    addLocalLog('assign','─','ok',`Atribuído a ${name}`);
    await loadAlerts();
  }catch(e){ addLocalLog('assign','─','err',e.message); }
}

// ── Escalate ──────────────────────────────────────────────────────────────────
function openEscalate(alertId){
  currentAlertId = alertId;
  document.getElementById('esc-to').value='';
  document.getElementById('esc-reason').value='';
  openModal('modal-escalate');
}
async function submitEscalate(){
  const to     = document.getElementById('esc-to').value.trim();
  const reason = document.getElementById('esc-reason').value.trim();
  if(!to){ alert('Informe para quem escalar'); return; }
  closeModal('modal-escalate');
  try{
    await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:currentAlertId,action:'escalate',to,reason})});
    addLocalLog('escalate','─','ok',`Escalado para ${to}`);
    await loadAlerts();
  }catch(e){ addLocalLog('escalate','─','err',e.message); }
}

// ── Notes ─────────────────────────────────────────────────────────────────────
function openNotes(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  document.getElementById('notes-title').textContent = `📝 Notas — ${a?a.rule_desc.substring(0,40):'Alerta'}`;
  document.getElementById('notes-input').value='';
  renderNotesList(a?(a.notes||[]):[]);
  openModal('modal-notes');
}
function renderNotesList(notes){
  const el = document.getElementById('notes-list');
  if(!notes.length){ el.innerHTML='<div style="color:var(--dim);font-size:11px;padding:6px">Nenhuma nota ainda.</div>'; return; }
  el.innerHTML = notes.map(n=>`<div class="note-item"><span class="note-time">${esc(n.time)}</span>${esc(n.text)}</div>`).join('');
}
async function submitNote(){
  const text = document.getElementById('notes-input').value.trim();
  if(!text) return;
  try{
    await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:currentAlertId,action:'note',text})});
    document.getElementById('notes-input').value='';
    await loadAlerts();
    const a = alerts.find(x=>x.id===currentAlertId);
    renderNotesList(a?(a.notes||[]):[]);
  }catch(e){ alert('Erro: '+e.message); }
}

// ── OSINT / Reputação / Whois / GeoIP ─────────────────────────────────────────
let osintData = null;
function switchOsintTab(tab){
  document.querySelectorAll('#modal-osint .tab-mini').forEach((t,i)=>{
    const tabs=['reputation','whois','userinfo'];
    t.classList.toggle('active', tabs[i]===tab);
  });
  document.querySelectorAll('#modal-osint .tab-pane').forEach(p=>p.classList.remove('active'));
  document.getElementById('osint-tab-'+tab).classList.add('active');
}
function openOsint(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  osintData = null;
  // Pré-preenche IP do alerta se existir
  const srcip = a?.raw?.data?.srcip || a?.raw?.agent?.ip || '';
  document.getElementById('osint-target').value = srcip;
  document.getElementById('whois-target').value = srcip;
  document.getElementById('osint-result').innerHTML = '<div class="empty" style="padding:16px">Clique em Consultar para iniciar o enriquecimento.</div>';
  document.getElementById('whois-result').innerHTML = '<div class="empty" style="padding:16px">Aguardando consulta…</div>';
  document.getElementById('userinfo-result').innerHTML = '';
  switchOsintTab('reputation');
  openModal('modal-osint');
}
async function runOsint(){
  const target = document.getElementById('osint-target').value.trim();
  if(!target){ alert('Informe IP ou domínio'); return; }
  const btn = document.querySelector('#osint-tab-reputation button');
  const spin = document.getElementById('osint-spin');
  spin.innerHTML = '<span class="spinner"></span>';
  document.getElementById('osint-result').innerHTML = '<div class="empty" style="padding:16px"><span class="spinner"></span> Consultando fontes OSINT…</div>';
  try{
    const r = await apiFetch(`/api/osint/reputation?target=${encodeURIComponent(target)}`);
    osintData = r;
    const geo = r.geoip||{};
    const risk = r.risk_label||'─';
    document.getElementById('osint-result').innerHTML = `
      <div class="osint-section">
        <div class="osint-label">📍 Identificação</div>
        <div class="osint-row"><span class="osint-key">Target</span><span class="osint-val">${esc(r.target||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Risk Score</span>
          <span class="risk-badge risk-${esc(risk)}">${esc(risk)} (${r.risk_score||0}/100)</span>
        </div>
        <div class="osint-row"><span class="osint-key">Timestamp</span><span class="osint-val">${esc(r.timestamp||'─')}</span></div>
      </div>
      <div class="osint-section">
        <div class="osint-label">🌍 GeoIP</div>
        <div class="osint-row"><span class="osint-key">País</span><span class="osint-val">${esc(geo.country||'─')} / ${esc(geo.regionName||'─')} / ${esc(geo.city||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">ISP / Org</span><span class="osint-val">${esc(geo.isp||'─')} — ${esc(geo.org||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">ASN</span><span class="osint-val">${esc(geo.as||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Proxy/VPN</span><span class="osint-val" style="color:${geo.proxy?'var(--red)':'var(--green)'}">${geo.proxy?'⚠️ SIM':'✓ NÃO'}</span></div>
        <div class="osint-row"><span class="osint-key">Hosting</span><span class="osint-val" style="color:${geo.hosting?'var(--yellow)':'var(--green)'}">${geo.hosting?'⚠️ SIM':'✓ NÃO'}</span></div>
        <div class="osint-row"><span class="osint-key">Reverse DNS</span><span class="osint-val">${esc(geo.reverse||'─')}</span></div>
      </div>
      ${r.geoip_error?`<div class="osint-section" style="border-color:var(--red)"><div class="osint-label" style="color:var(--red)">⚠ Erro GeoIP</div><div class="osint-val">${esc(r.geoip_error)}</div></div>`:''}
    `;
    addLocalLog('osint', currentAlertId, 'ok', `OSINT concluído para ${target} — Risco: ${risk}`);
  }catch(e){
    document.getElementById('osint-result').innerHTML=`<div class="empty" style="color:var(--red)">Erro: ${esc(e.message)}</div>`;
    addLocalLog('osint','─','err',e.message);
  }
  spin.innerHTML='';
}
async function runWhois(){
  const target = document.getElementById('whois-target').value.trim();
  if(!target){ alert('Informe IP ou domínio'); return; }
  document.getElementById('whois-result').innerHTML = '<div class="empty"><span class="spinner"></span> Consultando Whois/RDAP…</div>';
  try{
    const r = await apiFetch(`/api/osint/whois?target=${encodeURIComponent(target)}`);
    const w = r.whois||{};
    const geo = r.geoip||{};
    document.getElementById('whois-result').innerHTML = `
      <div class="osint-section">
        <div class="osint-label">📋 Whois / RDAP</div>
        <div class="osint-row"><span class="osint-key">Name</span><span class="osint-val">${esc(w.name||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Handle</span><span class="osint-val">${esc(w.handle||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Type</span><span class="osint-val">${esc(w.type||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">País</span><span class="osint-val">${esc(w.country||geo.country||'─')}</span></div>
        ${(w.remarks||[]).length?`<div class="osint-row"><span class="osint-key">Remarks</span><span class="osint-val">${w.remarks.map(esc).join(' | ')}</span></div>`:''}
        ${r.whois_error?`<div class="osint-row" style="color:var(--yellow)"><span class="osint-key">Aviso</span><span class="osint-val">${esc(r.whois_error)}</span></div>`:''}
      </div>
      <div class="osint-section">
        <div class="osint-label">🗺 GeoLocalização</div>
        <div class="osint-row"><span class="osint-key">IP</span><span class="osint-val">${esc(geo.query||target)}</span></div>
        <div class="osint-row"><span class="osint-key">Localização</span><span class="osint-val">${esc(geo.city||'─')}, ${esc(geo.regionName||'─')}, ${esc(geo.country||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">ISP</span><span class="osint-val">${esc(geo.isp||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Org</span><span class="osint-val">${esc(geo.org||'─')}</span></div>
      </div>`;
    addLocalLog('whois','─','ok',`Whois concluído para ${target}`);
  }catch(e){
    document.getElementById('whois-result').innerHTML=`<div class="empty" style="color:var(--red)">Erro: ${esc(e.message)}</div>`;
  }
}
async function runUserInfo(){
  const user = document.getElementById('userinfo-input').value.trim();
  if(!user){ alert('Informe o usuário'); return; }
  document.getElementById('userinfo-result').innerHTML = '<div class="empty"><span class="spinner"></span> Consultando AD/LDAP…</div>';
  try{
    const r = await apiFetch(`/api/osint/userinfo?user=${encodeURIComponent(user)}`);
    const u = r.user||{};
    document.getElementById('userinfo-result').innerHTML = `
      <div class="osint-section">
        <div class="osint-label">👤 Informações do Usuário</div>
        <div class="osint-row"><span class="osint-key">Nome</span><span class="osint-val">${esc(u.name||user)}</span></div>
        <div class="osint-row"><span class="osint-key">E-mail</span><span class="osint-val">${esc(u.email||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Dept.</span><span class="osint-val">${esc(u.department||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Grupos</span><span class="osint-val">${esc((u.groups||[]).join(', ')||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Status</span>
          <span class="osint-val" style="color:${u.enabled===false?'var(--red)':'var(--green)'}">
            ${u.enabled===false?'🔴 DESABILITADO':'🟢 ATIVO'}
          </span>
        </div>
        <div class="osint-row"><span class="osint-key">Último Login</span><span class="osint-val">${esc(u.last_login||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Fonte</span><span class="osint-val">${esc(r.source||'AD/LDAP simulado')}</span></div>
      </div>`;
    addLocalLog('userinfo','─','ok',`User info consultado para ${user}`);
  }catch(e){
    document.getElementById('userinfo-result').innerHTML=`<div class="empty" style="color:var(--red)">Erro: ${esc(e.message)}</div>`;
  }
}
function exportOsint(){
  if(!osintData){ alert('Nenhum dado OSINT coletado ainda.'); return; }
  const blob = new Blob([JSON.stringify(osintData,null,2)],{type:'application/json'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href=url; a.download=`osint-${currentAlertId}-${Date.now()}.json`; a.click();
  URL.revokeObjectURL(url);
}

// ── Sandbox Analysis ──────────────────────────────────────────────────────────
function openSandbox(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  const hash = a?.raw?.syscheck?.md5||a?.raw?.data?.md5||'';
  document.getElementById('sandbox-target').value = hash;
  document.getElementById('sandbox-type').value = hash?'hash':'url';
  document.getElementById('sandbox-result').innerHTML = '<div class="empty" style="padding:16px">Aguardando análise…</div>';
  openModal('modal-sandbox');
}
async function runSandbox(){
  const target = document.getElementById('sandbox-target').value.trim();
  const type   = document.getElementById('sandbox-type').value;
  if(!target){ alert('Informe o alvo para análise'); return; }
  document.getElementById('sandbox-spin').innerHTML = '<span class="spinner"></span>';
  document.getElementById('sandbox-result').innerHTML = '<div class="empty"><span class="spinner"></span> Enviando para sandbox…</div>';
  try{
    const r = await apiFetch(`/api/sandbox/analyze?target=${encodeURIComponent(target)}&type=${type}`);
    const verdict = r.verdict||'unknown';
    const vColor = verdict==='malicious'?'var(--red)':verdict==='suspicious'?'var(--yellow)':'var(--green)';
    document.getElementById('sandbox-result').innerHTML = `
      <div class="sandbox-result">
        <div style="margin-bottom:10px;font-size:13px">
          Veredicto: <span style="color:${vColor};font-weight:700;font-size:15px">${esc(verdict.toUpperCase())}</span>
          &nbsp; Score: <span style="color:${vColor}">${r.score||0}/100</span>
        </div>
        <div class="osint-section">
          <div class="osint-label">📊 Detalhes da Análise</div>
          <div class="osint-row"><span class="osint-key">Tipo</span><span class="osint-val">${esc(type)}</span></div>
          <div class="osint-row"><span class="osint-key">Alvo</span><span class="osint-val">${esc(target)}</span></div>
          <div class="osint-row"><span class="osint-key">Engines</span><span class="osint-val">${esc(r.engines_detected||'─')} / ${esc(r.engines_total||'─')} detectaram</span></div>
          <div class="osint-row"><span class="osint-key">Família</span><span class="osint-val">${esc(r.malware_family||'─')}</span></div>
          <div class="osint-row"><span class="osint-key">Categorias</span><span class="osint-val">${esc((r.categories||[]).join(', ')||'─')}</span></div>
          <div class="osint-row"><span class="osint-key">Fonte</span><span class="osint-val">${esc(r.source||'VirusTotal/Any.run simulado')}</span></div>
        </div>
        ${(r.behaviors||[]).length?`
        <div class="osint-section">
          <div class="osint-label">⚠ Comportamentos Detectados</div>
          ${r.behaviors.map(b=>`<div class="osint-row" style="color:var(--yellow)">• ${esc(b)}</div>`).join('')}
        </div>`:''}
      </div>`;
    addLocalLog('sandbox','─','ok',`Sandbox: ${target} → ${verdict}`);
  }catch(e){
    document.getElementById('sandbox-result').innerHTML=`<div class="empty" style="color:var(--red)">Erro: ${esc(e.message)}</div>`;
    addLocalLog('sandbox','─','err',e.message);
  }
  document.getElementById('sandbox-spin').innerHTML='';
}

// ── Revoke Tokens / Reset Sessions ───────────────────────────────────────────
function openRevokeTokens(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  document.getElementById('revoke-alert-label').textContent = a?a.rule_desc.substring(0,50):'─';
  document.getElementById('revoke-user').value = a?.assignee||'';
  document.getElementById('revoke-reason').value = '';
  openModal('modal-revoke');
}
async function submitRevoke(){
  const user   = document.getElementById('revoke-user').value.trim();
  const type   = document.getElementById('revoke-type').value;
  const reason = document.getElementById('revoke-reason').value.trim();
  if(!user){ alert('Informe o usuário'); return; }
  closeModal('modal-revoke');
  try{
    const r = await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:currentAlertId, action:'revoke_tokens', user, type, reason})});
    addLocalLog('revoke_tokens','─','ok',`${type} executado para ${user}`);
    await loadAlerts();
  }catch(e){ addLocalLog('revoke_tokens','─','err',e.message); }
}

// ── Disable Account ───────────────────────────────────────────────────────────
function openDisableAccount(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  document.getElementById('disable-alert-label').textContent = a?a.rule_desc.substring(0,50):'─';
  document.getElementById('disable-user').value = a?.assignee||'';
  document.getElementById('disable-reason').value = '';
  openModal('modal-disable-account');
}
async function submitDisableAccount(){
  const user   = document.getElementById('disable-user').value.trim();
  const scope  = document.getElementById('disable-scope').value;
  const reason = document.getElementById('disable-reason').value.trim();
  if(!user){ alert('Informe o usuário'); return; }
  closeModal('modal-disable-account');
  try{
    await apiFetch('/api/actions',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:currentAlertId, action:'disable_account', user, scope, reason})});
    addLocalLog('disable_account','─','ok',`Conta ${user} desabilitada (${scope})`);
    await loadAlerts();
  }catch(e){ addLocalLog('disable_account','─','err',e.message); }
}

// ── Create Jira / Ticket ──────────────────────────────────────────────────────
let ticketsList = [];
function openCreateTicket(alertId){
  currentAlertId = alertId;
  const a = alerts.find(x=>x.id===alertId);
  document.getElementById('ticket-title').value = a?`[${a.rule_id}] ${a.rule_desc.substring(0,60)}`:'';
  document.getElementById('ticket-assignee').value = a?.assignee||'';
  document.getElementById('ticket-priority').value = a&&a.level>=12?'Critical':a&&a.level>=7?'High':'Medium';
  document.getElementById('ticket-desc').value = a?
    `Alerta: ${a.rule_desc}\nAgente: ${a.agent_name} (#${a.agent_id})\nNível: ${a.level}\nTimestamp: ${a.timestamp}\nStatus: ${a.status}`:'';
  document.getElementById('ticket-labels').value = 'soar,wazuh';
  openModal('modal-ticket');
}
async function submitTicket(){
  const title    = document.getElementById('ticket-title').value.trim();
  const project  = document.getElementById('ticket-project').value;
  const priority = document.getElementById('ticket-priority').value;
  const assignee = document.getElementById('ticket-assignee').value.trim();
  const desc     = document.getElementById('ticket-desc').value.trim();
  const labels   = document.getElementById('ticket-labels').value.trim();
  if(!title){ alert('Informe o título do ticket'); return; }
  closeModal('modal-ticket');
  try{
    const r = await apiFetch('/api/ticket/create',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:currentAlertId, project, title, priority, assignee, description:desc, labels:labels.split(',').map(l=>l.trim())})});
    ticketsList.unshift(r.ticket||{});
    document.getElementById('ticket-confirm-content').innerHTML = `
      <div class="osint-section" style="text-align:left">
        <div class="osint-row"><span class="osint-key">Ticket ID</span><span class="ticket-id">${esc(r.ticket?.id||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Projeto</span><span class="osint-val">${esc(project)}</span></div>
        <div class="osint-row"><span class="osint-key">Prioridade</span><span class="osint-val">${esc(priority)}</span></div>
        <div class="osint-row"><span class="osint-key">Assignee</span><span class="osint-val">${esc(assignee||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Status</span><span class="osint-val" style="color:var(--green)">OPEN</span></div>
      </div>`;
    openModal('modal-ticket-confirm');
    addLocalLog('ticket','─','ok',`Ticket ${r.ticket?.id||'criado'} — ${project}/${priority}`);
    await loadAlerts();
  }catch(e){ addLocalLog('ticket','─','err',e.message); }
}

// ── Forensics / Collect Evidence ──────────────────────────────────────────────
let evidenceData = null;
function switchForensicTab(tab){
  document.querySelectorAll('#modal-forensics .tab-mini').forEach((t,i)=>{
    const tabs=['summary','processes','network','chain','raw'];
    t.classList.toggle('active', tabs[i]===tab);
  });
  document.querySelectorAll('#modal-forensics .tab-pane').forEach(p=>p.classList.remove('active'));
  document.getElementById('ftab-'+tab).classList.add('active');
}
async function openForensics(alertId){
  currentAlertId = alertId;
  evidenceData = null;
  const a = alerts.find(x=>x.id===alertId);
  if(!a) return;
  document.getElementById('forensics-status').innerHTML = '<div class="empty"><span class="spinner"></span> Coletando evidências forenses…</div>';
  document.getElementById('fev-summary').innerHTML = '';
  document.getElementById('fev-processes').innerHTML = '';
  document.getElementById('fev-network').innerHTML = '';
  document.getElementById('fev-chain').innerHTML = '';
  document.getElementById('fev-raw').textContent = '';
  switchForensicTab('summary');
  openModal('modal-forensics');
  try{
    const r = await apiFetch('/api/forensics/collect',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({alert_id:alertId})});
    evidenceData = r.evidence||{};
    const ev = evidenceData;
    document.getElementById('forensics-status').innerHTML =
      `<div style="color:var(--green);font-family:var(--mono);font-size:11px">✅ Evidência coletada — ID: <b>${esc(ev.evidence_id||'─')}</b></div>`;
    // Summary tab
    const s = ev.alert_summary||{};
    document.getElementById('fev-summary').innerHTML = `
      <div class="osint-section">
        <div class="osint-label">🔎 Alerta</div>
        <div class="osint-row"><span class="osint-key">ID Evidência</span><span class="osint-val">${esc(ev.evidence_id||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Coletado em</span><span class="osint-val">${esc(ev.collected_at||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Agente</span><span class="osint-val">${esc(s.agent_name||'─')} #${esc(s.agent_id||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Regra</span><span class="osint-val">${esc(s.rule_id||'─')} — ${esc(s.rule_desc||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Nível</span><span class="osint-val" style="color:var(--red)">${s.level||0}</span></div>
        <div class="osint-row"><span class="osint-key">Timestamp</span><span class="osint-val">${esc(s.timestamp||'─')}</span></div>
        <div class="osint-row"><span class="osint-key">Responsável</span><span class="osint-val">${esc(s.assignee||'─')}</span></div>
      </div>
      ${ev.syscheck&&Object.keys(ev.syscheck).length?`
      <div class="osint-section">
        <div class="osint-label">📁 Syscheck (Integridade)</div>
        ${Object.entries(ev.syscheck).map(([k,v])=>`<div class="osint-row"><span class="osint-key">${esc(k)}</span><span class="osint-val">${esc(String(v))}</span></div>`).join('')}
      </div>`:''}`;
    // Processes tab
    const procs = ev.processes||[];
    document.getElementById('fev-processes').innerHTML = procs.length
      ? `<table class="proc-table" style="width:100%">
          <tr><th style="text-align:left;color:var(--dim);padding:4px 8px">PID</th><th style="text-align:left;color:var(--dim);padding:4px 8px">Nome</th><th style="text-align:left;color:var(--dim);padding:4px 8px">CPU%</th><th style="text-align:left;color:var(--dim);padding:4px 8px">Usuário</th></tr>
          ${procs.slice(0,30).map(p=>`<tr><td>${esc(p.pid||'─')}</td><td>${esc(p.name||'─')}</td><td>${esc(p.cpu||'─')}</td><td>${esc(p.euser||p.uname||'─')}</td></tr>`).join('')}
        </table>`
      : '<div class="empty">Sem dados de processos</div>';
    // Network tab
    const ports = ev.open_ports||[];
    document.getElementById('fev-network').innerHTML = `
      <div class="osint-section">
        <div class="osint-label">🌐 IP de Origem</div>
        <div class="osint-row"><span class="osint-key">srcip</span><span class="osint-val">${esc(ev.network||'─')}</span></div>
      </div>
      ${ports.length?`
      <div class="osint-section">
        <div class="osint-label">🔌 Portas Abertas (${ports.length})</div>
        <table class="proc-table" style="width:100%">
          <tr><th style="text-align:left;color:var(--dim);padding:4px 8px">Porta</th><th style="text-align:left;color:var(--dim);padding:4px 8px">Proto</th><th style="text-align:left;color:var(--dim);padding:4px 8px">Estado</th><th style="text-align:left;color:var(--dim);padding:4px 8px">Processo</th></tr>
          ${ports.slice(0,20).map(p=>`<tr><td>${esc(p.local&&p.local.port||'─')}</td><td>${esc(p.protocol||'─')}</td><td>${esc(p.state||'─')}</td><td>${esc(p.process&&p.process.name||'─')}</td></tr>`).join('')}
        </table>
      </div>`:'<div class="empty" style="padding:8px">Sem dados de portas</div>'}`;
    // Chain of custody tab
    const chain = ev.chain_of_custody||[];
    document.getElementById('fev-chain').innerHTML = `
      <div class="osint-section">
        <div class="osint-label">🔗 Cadeia de Custódia</div>
        ${chain.map(c=>`<div class="evidence-chain">[${esc(c.time||'─')}] ${esc(c.action||'─')} — ${esc(c.analyst||'─')}</div>`).join('')}
      </div>`;
    // Raw tab
    document.getElementById('fev-raw').textContent = JSON.stringify(ev, null, 2);
    addLocalLog('forensics', s.agent_id||'─', 'ok', `Evidência ${ev.evidence_id} coletada`);
  }catch(e){
    document.getElementById('forensics-status').innerHTML=`<div class="empty" style="color:var(--red)">Erro ao coletar evidências: ${esc(e.message)}</div>`;
    addLocalLog('forensics','─','err',e.message);
  }
}
function exportEvidence(){
  if(!evidenceData){ alert('Nenhuma evidência coletada ainda.'); return; }
  const blob = new Blob([JSON.stringify(evidenceData,null,2)],{type:'application/json'});
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href=url; a.download=`evidence-${evidenceData.evidence_id||currentAlertId}-${Date.now()}.json`; a.click();
  URL.revokeObjectURL(url);
}

// ── Agents Page ───────────────────────────────────────────────────────────────
function renderAgents(){
  let online=0;
  agents.forEach(a=>{ if(a.status==='active') online++; });
  document.getElementById('s-agents').textContent = online;
  const sbAg = document.getElementById('sb-agents');
  if(sbAg) sbAg.textContent = online;
}
function renderAgentCards(){
  const el = document.getElementById('agents-grid');
  if(!agents.length){ el.innerHTML='<div class="empty">Sem agentes — verifique conexão Wazuh</div>'; return; }
  el.innerHTML = agents.map(a=>{
    const st = a.status||'never_connected';
    const stColor = st==='active'?'var(--green)':st==='disconnected'?'var(--dim)':'var(--yellow)';
    const lastKeepAlive = a.lastKeepAlive||a.last_keep_alive||'─';
    return `<div class="panel" style="padding:0">
      <div class="panel-head">${esc(a.name||'unknown')} <span>#${esc(a.id||'?')}</span></div>
      <div style="padding:12px;font-size:12px">
        <div style="display:flex;align-items:center;gap:6px;margin-bottom:8px">
          <span class="agt-dot ${st}"></span>
          <span style="color:${stColor}">${st}</span>
        </div>
        <div style="color:var(--dim);margin-bottom:4px">IP: <span style="color:var(--text)">${esc(a.ip||'─')}</span></div>
        <div style="color:var(--dim);margin-bottom:4px">OS: <span style="color:var(--text)">${esc((a.os&&a.os.name)||'─')}</span></div>
        <div style="color:var(--dim);margin-bottom:10px">Versão: <span style="color:var(--text)">${esc(a.version||'─')}</span></div>
        <div class="btn-group">
          <button class="btn btn-blue"   onclick="agentIsolate('${a.id}','${a.name}')">🔒 Isolar</button>
          <button class="btn btn-green"  onclick="agentRestore('${a.id}','${a.name}')">🔓 Restaurar</button>
          <button class="btn btn-teal"   onclick="agentSnapshot('${a.id}','${a.name}')">📸 Snap</button>
        </div>
      </div>
    </div>`;
  }).join('');
}
async function agentIsolate(id, name){
  if(!confirm(`Isolar agente ${name}?`)) return;
  try{
    await apiFetch('/api/agent/isolate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:id})});
    addLocalLog('isolate',id,'ok',`Agente ${name} isolado`);
  }catch(e){ addLocalLog('isolate',id,'err',e.message); }
}
async function agentRestore(id, name){
  if(!confirm(`Restaurar agente ${name}?`)) return;
  try{
    await apiFetch('/api/agent/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:id})});
    addLocalLog('restore',id,'ok',`Agente ${name} restaurado`);
  }catch(e){ addLocalLog('restore',id,'err',e.message); }
}
async function agentSnapshot(id, name){
  addLocalLog('snapshot',id,'inf',`Snapshot iniciado para ${name}`);
  try{
    const [pd,portd] = await Promise.all([
      apiFetch(`/api/agent/${id}/processes`).catch(()=>({processes:[]})),
      apiFetch(`/api/agent/${id}/ports`).catch(()=>({ports:[]})),
    ]);
    const snap = {agent_id:id,agent_name:name,processes:pd.processes||[],ports:portd.ports||[],time:new Date().toISOString()};
    const blob = new Blob([JSON.stringify(snap,null,2)],{type:'application/json'});
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href=url; a.download=`snapshot-agent-${id}-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
    addLocalLog('snapshot',id,'ok',`Snapshot de ${name} exportado`);
  }catch(e){ addLocalLog('snapshot',id,'err',e.message); }
}

// ── Incidents ─────────────────────────────────────────────────────────────────
function openNewIncident(){
  document.getElementById('inc-title').value='';
  document.getElementById('inc-assignee').value='';
  document.getElementById('inc-desc').value='';
  openModal('modal-new-incident');
}
function submitNewIncident(){
  const title    = document.getElementById('inc-title').value.trim();
  const priority = document.getElementById('inc-priority').value;
  const assignee = document.getElementById('inc-assignee').value.trim();
  const desc     = document.getElementById('inc-desc').value.trim();
  if(!title){ alert('Informe o título'); return; }
  const inc = {
    id: `INC-${Date.now()}`, title, priority, assignee, desc,
    status:'open', created: new Date().toLocaleString('pt-BR'), updates:[]
  };
  incidents.unshift(inc);
  closeModal('modal-new-incident');
  renderIncidents();
  switchTab('incidents');
}
function renderIncidents(){
  const el = document.getElementById('incident-list');
  if(!incidents.length){ el.innerHTML='<div class="empty">Nenhum incidente criado ainda.</div>'; return; }
  el.innerHTML = incidents.map(inc=>`
    <div class="incident-card priority-${inc.priority}">
      <div class="inc-header">
        <div>
          <div class="inc-id">${esc(inc.id)} · ${inc.priority.toUpperCase()}</div>
          <div class="inc-title">${esc(inc.title)}</div>
        </div>
        <div class="btn-group">
          <span class="badge ${inc.status==='open'?'open':'actioned'}">${inc.status}</span>
          <button class="btn btn-green" onclick="closeIncident('${inc.id}')">✓ Fechar</button>
        </div>
      </div>
      <div class="inc-meta">
        👤 ${esc(inc.assignee||'Não atribuído')} &nbsp;·&nbsp; 🕐 ${esc(inc.created)}
        ${inc.desc?`<br><span style="color:var(--text)">${esc(inc.desc)}</span>`:''}
      </div>
    </div>`).join('');
}
function closeIncident(id){
  const inc = incidents.find(x=>x.id===id);
  if(inc){ inc.status='closed'; renderIncidents(); }
}

// ── Log ───────────────────────────────────────────────────────────────────────
function addLocalLog(action, agentId, status, msg){
  const now = new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  actionLog.unshift({time:now, action, agent_id:agentId, status, msg});
  if(actionLog.length>200) actionLog.pop();
}
function renderLog(){
  document.getElementById('log-count').textContent = actionLog.length;
}
function renderLogFull(){
  const el = document.getElementById('log-full');
  document.getElementById('log-count-pg').textContent = actionLog.length;
  if(!actionLog.length){ el.innerHTML='<div class="empty">Nenhuma ação ainda</div>'; return; }
  el.innerHTML = actionLog.map(l=>`
    <div class="log-entry">
      <span class="log-ts">${l.time}</span>
      <span class="log-${l.status}">[${l.action.toUpperCase()}]</span>
      <span> ag:${esc(l.agent_id)} — ${esc(l.msg)}</span>
    </div>`).join('');
}

// ── Report ────────────────────────────────────────────────────────────────────
async function downloadReport(){
  try{
    const r = await fetch(API+'/api/report');
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href=url;
    const ext = r.headers.get('Content-Type')||'';
    a.download = `soar-report-${Date.now()}.${ext.includes('pdf')?'pdf':'txt'}`;
    a.click(); URL.revokeObjectURL(url);
  }catch(e){ alert('Erro ao gerar relatório: '+e.message); }
}

// ── Load Data ─────────────────────────────────────────────────────────────────
async function loadAlerts(){
  try{
    const d = await apiFetch('/api/alerts');
    alerts = d.alerts||[];
    window._alerts = alerts;
    // Atualiza badge sidebar
    const sbA = document.getElementById('sb-alerts');
    if(sbA) sbA.textContent = alerts.length || '0';
    // Atualiza gráfico se Chart.js já carregou
    // Busca histórico completo para o gráfico
    fetch('/api/alerts/history?days='+(window._chartDays||7))
      .then(function(r){ return r.json(); })
      .then(function(resp){
        var src = resp.alerts || window._alerts || alerts;
        renderChart(src, window._chartDays||7);
      })
      .catch(function(){ renderChart(window._alerts||alerts, window._chartDays||7); });
    renderAlerts();
  }catch(e){ console.error('alerts:',e); }
}
async function loadAgents(){
  try{
    const d = await apiFetch('/api/agents');
    agents = d.agents||[];
    renderAgents();
    if(document.getElementById('page-agents').classList.contains('active')) renderAgentCards();
  }catch(e){ console.error('agents:',e); }
}
async function loadLog(){
  try{
    const d = await apiFetch('/api/log');
    actionLog = d.log||[];
    renderLog();
    if(document.getElementById('page-log').classList.contains('active')) renderLogFull();
  }catch{}
}
async function checkHealth(){
  try{
    const d = await apiFetch('/health');
    const el = document.getElementById('wazuh-dot');
    el.innerHTML = d.wazuh==='connected'
      ? '<span class="dot ok"></span>Wazuh conectado'
      : '<span class="dot bad"></span>Wazuh offline';
    document.getElementById('alert-count').textContent = `${d.alerts} alertas`;
  }catch{
    document.getElementById('wazuh-dot').innerHTML='<span class="dot bad"></span>SOAR offline';
  }
}
async function refresh(){
  await Promise.all([loadAlerts(),loadAgents(),loadLog(),checkHealth()]);
  // Badge e gráfico sempre atualizados após refresh
  const sbA2 = document.getElementById('sb-alerts');
  if(sbA2) sbA2.textContent = alerts.length || '0';
  if(window.Chart && document.getElementById('chart-7days')) initChart(alerts);
  document.getElementById('last-refresh').textContent =
    new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

refresh();
setInterval(refresh, 10000);



// ── Chart.js helpers ────────────────────────────────────────
var _chartInstance = null;

function loadChartJs(cb) {
  if (window.Chart) { if (cb) cb(); return; }
  var s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
  s.onload = function() { if (cb) cb(); };
  s.onerror = function() {
    var s2 = document.createElement('script');
    s2.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js';
    s2.onload = function() { if (cb) cb(); };
    document.head.appendChild(s2);
  };
  document.head.appendChild(s);
}

function initChart(data, days) {
  days = days || window._chartDays || 7;
  // Busca histórico do OpenSearch quando há mais de 1 dia
  fetch('/api/alerts/history?days=' + days)
    .then(function(r) { return r.json(); })
    .then(function(resp) { renderChart(resp.alerts || data || [], days); })
    .catch(function() { renderChart(data || [], days); });
}

function renderChart(data, days) {
  var canvas = document.getElementById('chart-7days');
  if (!canvas) return;
  if (!window.Chart) { loadChartJs(function() { renderChart(data, days); }); return; }

  var now = new Date();
  var labels = [], buckets = {};
  for (var i = days - 1; i >= 0; i--) {
    var key = new Date(now.getTime() - i * 86400000).toISOString().slice(0, 10);
    labels.push(key);
    buckets[key] = { crit:0, high:0, med:0, low:0 };
  }
  var firstDay = labels[0];
  var tot = 0, totC = 0, totH = 0, totM = 0, totL = 0;

  (data || []).forEach(function(a) {
    var ts = (a.timestamp || a['@timestamp'] || '').slice(0, 10);
    if (!ts || ts < firstDay || !buckets[ts]) return;
    var lvl = parseInt(a.level || (a.rule && a.rule.level) || 0, 10);
    tot++;
    if      (lvl >= 12) { buckets[ts].crit++; totC++; }
    else if (lvl >= 7)  { buckets[ts].high++; totH++; }
    else if (lvl >= 4)  { buckets[ts].med++;  totM++; }
    else                { buckets[ts].low++;  totL++; }
  });

  var shortLabels = labels.map(function(k) { var p=k.split('-'); return p[2]+'/'+p[1]; });
  var el = function(id) { return document.getElementById(id); };
  if (el('chart-period-label')) el('chart-period-label').textContent = days + ' dias';
  if (el('chart-period-total')) el('chart-period-total').textContent = tot;
  if (el('chart-period-crit'))  el('chart-period-crit').textContent  = totC;
  if (el('chart-period-high'))  el('chart-period-high').textContent  = totH;
  if (el('chart-period-med'))   el('chart-period-med').textContent   = totM;
  if (el('chart-period-low'))   el('chart-period-low').textContent   = totL;

  if (_chartInstance) { _chartInstance.destroy(); _chartInstance = null; }
  _chartInstance = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels: shortLabels,
      datasets: [
        { label:'Crítico', data: labels.map(function(k){return buckets[k].crit;}), backgroundColor:'rgba(239,68,68,.8)',  borderRadius:3 },
        { label:'Alto',    data: labels.map(function(k){return buckets[k].high;}), backgroundColor:'rgba(249,115,22,.8)', borderRadius:3 },
        { label:'Médio',   data: labels.map(function(k){return buckets[k].med;}),  backgroundColor:'rgba(234,179,8,.8)',  borderRadius:3 },
        { label:'Baixo',   data: labels.map(function(k){return buckets[k].low;}),  backgroundColor:'rgba(20,184,166,.8)', borderRadius:3 }
      ]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{ legend:{display:false}, tooltip:{mode:'index',intersect:false} },
      scales:{
        x:{ stacked:true, grid:{color:'rgba(255,255,255,.05)'}, ticks:{color:'#8fa3b8',font:{size:10}} },
        y:{ stacked:true, beginAtZero:true, grid:{color:'rgba(255,255,255,.05)'}, ticks:{color:'#8fa3b8',font:{size:10},precision:0} }
      }
    }
  });
}

function setChartDays(d) {
  window._chartDays = d;
  [1,7,15,30].forEach(function(n) {
    var b = document.getElementById('btn-days-' + n);
    if (!b) return;
    var sel = (n === d);
    b.style.background  = sel ? 'rgba(0,107,180,.35)'        : 'rgba(74,104,136,.15)';
    b.style.color       = sel ? 'var(--accent-light,#7ec8ff)' : 'var(--dim,#8fa3b8)';
    b.style.borderColor = sel ? 'var(--accent,#006bb4)'       : 'rgba(74,104,136,.25)';
    b.style.fontWeight  = sel ? '700' : '400';
  });
  initChart(window._alerts || [], d);
}

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
  } catch(e) { console.error('loadVulns:', e); }
  if (btn) btn.textContent = '↻ Atualizar';
}

function applyVulnFilters() {
  var search = ((document.getElementById('vuln-search')||{}).value||'').toLowerCase();
  var sev    = (document.getElementById('vuln-sev')||{}).value||'';
  var status = (document.getElementById('vuln-status')||{}).value||'';
  var filtered = vulnsData.filter(function(v) {
    return (!search || (v.cve||'').toLowerCase().includes(search) || (v.package||'').toLowerCase().includes(search) || (v.agent_name||'').toLowerCase().includes(search))
        && (!sev    || v.severity === sev)
        && (!status || v.status   === status);
  });
  renderVulnList(filtered);
}

function renderVulnList(list) {
  var el = document.getElementById('vuln-list');
  if (!el) return;
  if (!list.length) { el.innerHTML = '<div class="empty">Nenhuma vulnerabilidade encontrada.</div>'; return; }
  var sevColor = {Critical:'var(--red-light)',High:'var(--orange)',Medium:'var(--yellow)',Low:'var(--teal)',Unknown:'var(--dim)'};
  el.innerHTML = list.map(function(v) {
    var color = sevColor[v.severity]||'var(--dim)';
    return '<div style="padding:10px 14px;border-bottom:1px solid var(--border);display:flex;gap:12px;align-items:flex-start">'
      + '<div style="min-width:70px;font-weight:700;color:'+color+';font-size:12px">'+v.severity+'</div>'
      + '<div style="flex:1"><div style="font-weight:600;color:var(--text);font-size:13px">'+v.cve+'</div>'
      + '<div style="font-size:11px;color:var(--dim);margin-top:2px">'+v.package+' '+v.version+' — '+v.agent_name+'</div></div>'
      + '<div style="font-size:11px;color:var(--dim);min-width:50px;text-align:right">CVSS '+(v.cvss3||'─')+'</div></div>';
  }).join('');
}

function updateVulnCharts(data) {
  var pie = document.getElementById('vuln-pie-chart');
  if (!pie || !window.Chart) return;
  var counts = {Critical:0,High:0,Medium:0,Low:0,Unknown:0};
  data.forEach(function(v){ counts[v.severity]=(counts[v.severity]||0)+1; });
  var labels = Object.keys(counts).filter(function(k){ return counts[k]>0; });
  var colors = {Critical:'rgba(239,68,68,.8)',High:'rgba(249,115,22,.8)',Medium:'rgba(234,179,8,.8)',Low:'rgba(20,184,166,.8)',Unknown:'rgba(100,116,139,.8)'};
  if (pie._chart) pie._chart.destroy();
  pie._chart = new Chart(pie.getContext('2d'), {
    type:'doughnut',
    data:{ labels:labels, datasets:[{ data:labels.map(function(k){return counts[k];}), backgroundColor:labels.map(function(k){return colors[k];}), borderWidth:0 }] },
    options:{ responsive:false, plugins:{ legend:{display:false} } }
  });
  var tot = document.getElementById('vuln-pie-total');
  if (tot) tot.textContent = data.length + ' total';
}
// ── fim Chart.js helpers ─────────────────────────────────────


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

function deleteSelected() {
  if (_sel.size === 0) return;
  if (!confirm(_sel.size + ' alertas serao removidos. Confirma?')) return;
  apiFetch('/api/alerts/delete', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids:Array.from(_sel)})})
    .then(function(d){ _sel.clear(); _updateBulkBtn(); loadAlerts(); })
    .catch(function(e){ console.error('deleteSelected:', e); });
}
function deleteAllAlerts() {
  if (!confirm('Remover TODOS os ' + alerts.length + ' alertas? Esta acao nao pode ser desfeita.')) return;
  var ids = alerts.map(function(a){ return a.id; });
  apiFetch('/api/alerts/delete', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids:ids})})
    .then(function(d){ loadAlerts(); })
    .catch(function(e){ console.error('deleteAll:', e); });
}

// -- fim Filtros Rapidos & Bulk Actions -----------------------
</script>
</div><!-- /content-area -->
</div><!-- /app-body -->
</body>
</html>
"""

# ─── HTTP Handler ─────────────────────────────────────────────────────────────
class SOARHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        logger.info(f"{self.address_string()} {fmt % args}")

    def _send(self, code, body, ct="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_OPTIONS(self):
        self._send(204, b"")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/")

        if path in ("", "/"):
            self._send(200, DASHBOARD_HTML, "text/html; charset=utf-8")

        elif path == "/health":
            ok = wazuh.health()
            self._send(200, {"status": "healthy" if ok else "degraded",
                             "wazuh":  "connected" if ok else "disconnected",
                             "alerts": len(_alerts)})

        elif path == "/api/alerts/delete":
            import json as _j
            body = _j.loads(self.rfile.read(int(self.headers.get("Content-Length",0))) or b"{}")
            ids  = set(body.get("ids", []))
            with _lock:
                before = len(_alerts)
                _alerts[:] = [a for a in _alerts if a["id"] not in ids]
                removed = before - len(_alerts)
                _save_json("alerts", _alerts)
            self._send(200, {"removed": removed})
        elif path == "/api/alerts/history":
            import urllib.parse as _up2
            _qs   = _up2.parse_qs(_up2.urlparse(self.path).query)
            _days = int(_qs.get("days", ["7"])[0])
            try:
                from datetime import datetime as _dt, timedelta as _td
                _since = (_dt.utcnow() - _td(days=_days)).strftime("%Y-%m-%dT%H:%M:%S")
                import requests as _req2
                _q = {"size":10000,"_source":["timestamp","rule.level"],"query":{"range":{"timestamp":{"gte":_since}}}}
                _r = _req2.post("https://127.0.0.1:9200/wazuh-alerts-*/_search",json=_q,auth=("admin","NewAdmin2024!"),verify=False,timeout=10)
                if _r.status_code == 200:
                    _hits = _r.json().get("hits",{}).get("hits",[])
                    _al = [{"timestamp":h["_source"].get("timestamp",""),"level":h["_source"].get("rule",{}).get("level",0)} for h in _hits]
                    self._send(200,{"alerts":_al,"total":len(_al),"source":"opensearch"})
                else: raise Exception(f"status {_r.status_code}")
            except Exception as _e:
                with _lock: _snap = list(_alerts)
                self._send(200,{"alerts":[{"timestamp":a["timestamp"],"level":a["level"]} for a in _snap],"total":len(_snap),"source":"memory"})
        elif path == "/api/alerts":
            with _lock: data = list(_alerts)
            self._send(200, {"total": len(data), "alerts": data})

        elif path.startswith("/api/alerts/"):
            aid = path.split("/")[-1]
            with _lock: found = next((a for a in _alerts if a["id"] == aid), None)
            self._send(200, found) if found else self._send(404, {"error": "not found"})

        elif path == "/api/agents":
            ag = wazuh.get_agents()
            self._send(200, {"total": len(ag), "agents": ag})

        elif path.startswith("/api/agent/") and path.endswith("/processes"):
            agent_id = path.split("/")[3]
            procs = wazuh.get_agent_processes(agent_id)
            self._send(200, {"processes": procs})

        elif path.startswith("/api/agent/") and path.endswith("/ports"):
            agent_id = path.split("/")[3]
            ports = wazuh.get_agent_ports(agent_id)
            self._send(200, {"ports": ports})

        elif path.startswith("/api/agent/") and path.endswith("/info"):
            agent_id = path.split("/")[3]
            info = wazuh.get_agent_detail(agent_id)
            self._send(200, info)

        elif path == "/api/log":
            with _lock: data = list(_log)
            self._send(200, {"log": data})

        elif path == "/api/tickets":
            with _lock: data = list(_tickets)
            self._send(200, {"tickets": data})

        elif path == "/api/osint/reputation":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            target = params.get("target", [""])[0]
            if not target:
                self._send(400, {"error": "target required"}); return
            result = osint_reputation(target)
            self._send(200, result)

        elif path == "/api/osint/whois":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            target = params.get("target", [""])[0]
            if not target:
                self._send(400, {"error": "target required"}); return
            result = osint_reputation(target)
            self._send(200, result)

        elif path == "/api/osint/userinfo":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            user = params.get("user", [""])[0]
            # Simulated AD/LDAP response — replace with real LDAP integration
            simulated = {
                "source": "AD/LDAP simulado (configure endpoint real)",
                "user": {
                    "name": user.replace(".", " ").title(),
                    "email": f"{user}@empresa.com",
                    "department": "TI / Operações",
                    "groups": ["Domain Users", "VPN_Users", "IT_Staff"],
                    "enabled": True,
                    "last_login": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "account_locked": False,
                    "password_last_set": "2024-12-01",
                }
            }
            self._send(200, simulated)

        elif path == "/api/sandbox/analyze":
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            target = params.get("target", [""])[0]
            atype  = params.get("type", ["hash"])[0]
            # Simulated sandbox result — integrate real VirusTotal / Any.run API
            import hashlib, random
            seed = int(hashlib.md5(target.encode()).hexdigest(), 16) % 100
            verdict = "malicious" if seed > 70 else "suspicious" if seed > 40 else "clean"
            det = max(0, seed - 30) if verdict != "clean" else 0
            result = {
                "target": target,
                "type": atype,
                "verdict": verdict,
                "score": seed,
                "engines_detected": det,
                "engines_total": 72,
                "malware_family": "Trojan.GenericKD" if verdict == "malicious" else "",
                "categories": (["trojan", "ransomware"] if verdict == "malicious"
                               else ["adware"] if verdict == "suspicious" else []),
                "behaviors": (["Modifica chaves de registro", "Tenta elevar privilégios",
                                "Conexão com C2 externo"] if verdict == "malicious"
                               else ["Modifica arquivos do sistema"] if verdict == "suspicious" else []),
                "source": "VirusTotal/Any.run (simulado — configure API key real)",
                "analyzed_at": datetime.now().isoformat(timespec="seconds"),
            }
            self._send(200, result)

        elif path == "/api/report":
            try:
                report = generate_pdf_report()
                ct = "application/pdf" if HAS_PDF else "text/plain; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", ct)
                self.send_header("Content-Length", len(report))
                self.send_header("Content-Disposition", f'attachment; filename="soar-report-{int(time.time())}.{"pdf" if HAS_PDF else "txt"}"')
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(report)
            except Exception as e:
                self._send(500, {"error": str(e)})

        elif path == "/api/notify/test":
            try:
                result = Notifier.test()
                self._send(200, {"ok": True, "result": result})
            except Exception as e:
                self._send(500, {"error": str(e)})

        elif path == "/api/notify/config":
            self._send(200, {
                "telegram": {
                    "enabled":  TELEGRAM_ENABLED,
                    "chat_id":  TELEGRAM_CHAT_ID,
                    "min_level": TELEGRAM_LEVEL,
                },
                "email": {
                    "enabled":  EMAIL_ENABLED,
                    "host":     EMAIL_HOST,
                    "port":     EMAIL_PORT,
                    "to":       EMAIL_TO,
                    "min_level": EMAIL_LEVEL,
                }
            })

        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/")

        # ── Webhook ──
        if path == "/webhooks/alert":
            try:
                payload   = self._body()
                alert_raw = payload.get("alert", payload)
                alert     = store_alert(alert_raw)
                logger.info(f"📥 Webhook: {alert['rule_desc']} (lv {alert['level']})")
                self._send(200, {"status": "received", "id": alert["id"]})
            except Exception as e:
                self._send(400, {"error": str(e)})

        # ── Actions ──
        elif path == "/api/alerts/delete":
            try:
                body = self._body()
                ids  = set(body.get("ids", []))
                with _lock:
                    before = len(_alerts)
                    _alerts[:] = [a for a in _alerts if a["id"] not in ids]
                    removed = before - len(_alerts)
                    _save_json("alerts", _alerts)
                self._send(200, {"removed": removed})
            except Exception as e:
                self._send(400, {"error": str(e)})
        elif path == "/api/actions":
            try:
                body   = self._body()
                aid    = body.get("alert_id", "")
                action = body.get("action", "").lower()

                with _lock:
                    alert = next((a for a in _alerts if a["id"] == aid), None)
                if not alert:
                    self._send(404, {"error": "alert not found"}); return

                agent_id = alert["agent_id"]
                msg      = ""

                if action == "quarantine":
                    threading.Thread(target=wazuh.isolate_agent, args=(agent_id,), daemon=True).start()
                    msg = f"Isolando agente {agent_id}…"
                    alert["status"] = "actioned"

                elif action == "patch":
                    threading.Thread(target=wazuh.run_command,
                                     args=(agent_id, "custom_command", ["apt-get", "upgrade", "-y"]),
                                     daemon=True).start()
                    msg = f"Patch iniciado em {agent_id}…"
                    alert["status"] = "actioned"

                elif action == "delete":
                    fp = alert.get("raw", {}).get("syscheck", {}).get("path", "")
                    if fp:
                        threading.Thread(target=wazuh.run_command, args=(agent_id, "delete_file", [fp]), daemon=True).start()
                        msg = f"Removendo {fp}…"
                    else:
                        msg = "Caminho do arquivo não encontrado"
                    alert["status"] = "actioned"

                elif action == "ignore":
                    alert["status"] = "ignored"
                    msg = "Alerta ignorado"

                elif action == "restore":
                    threading.Thread(target=wazuh.restore_agent, args=(agent_id,), daemon=True).start()
                    msg = f"Restaurando agente {agent_id}…"
                    alert["status"] = "actioned"

                elif action == "kill":
                    pid = body.get("pid", "")
                    if pid:
                        threading.Thread(target=wazuh.kill_process, args=(agent_id, str(pid)), daemon=True).start()
                        msg = f"Kill PID {pid} no agente {agent_id}…"
                    else:
                        msg = "PID não informado"
                    alert["status"] = "actioned"

                elif action == "ban_ip":
                    ip = body.get("ip", "")
                    if ip:
                        threading.Thread(target=wazuh.ban_ip, args=(agent_id, ip), daemon=True).start()
                        msg = f"Banindo IP {ip} via firewall…"
                    else:
                        msg = "IP não informado"
                    alert["status"] = "actioned"

                elif action == "assign":
                    assignee = body.get("assignee", "")
                    note_txt = body.get("note", "")
                    alert["assignee"] = assignee
                    if note_txt:
                        alert.setdefault("notes", []).append({
                            "time": datetime.now().strftime("%H:%M:%S"), "text": note_txt
                        })
                    msg = f"Atribuído a {assignee}"

                elif action == "escalate":
                    to     = body.get("to", "")
                    reason = body.get("reason", "")
                    alert["escalated"] = True
                    alert["status"]    = "escalated"
                    alert.setdefault("notes", []).append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "text": f"Escalado para {to}: {reason}"
                    })
                    msg = f"Escalado para {to}"

                elif action == "fp":
                    alert["false_positive"] = True
                    alert["status"]         = "fp"
                    msg = "Marcado como Falso Positivo"

                elif action == "investigating":
                    alert["status"] = "investigating"
                    msg = "Em investigação"

                elif action == "note":
                    text = body.get("text", "")
                    alert.setdefault("notes", []).append({
                        "time": datetime.now().strftime("%H:%M:%S"), "text": text
                    })
                    msg = "Nota adicionada"

                elif action == "revoke_tokens":
                    user   = body.get("user", "")
                    rtype  = body.get("type", "revoke_tokens")
                    reason = body.get("reason", "")
                    alert.setdefault("notes", []).append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "text": f"Tokens/Sessão revogados — usuário: {user} | tipo: {rtype} | motivo: {reason}"
                    })
                    alert["status"] = "actioned"
                    msg = f"Tokens/sessão revogados para {user} ({rtype})"

                elif action == "disable_account":
                    user   = body.get("user", "")
                    scope  = body.get("scope", "disable_ad")
                    reason = body.get("reason", "")
                    alert.setdefault("notes", []).append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "text": f"Conta desabilitada — usuário: {user} | escopo: {scope} | motivo: {reason}"
                    })
                    alert["status"] = "actioned"
                    msg = f"Conta {user} desabilitada ({scope})"

                else:
                    self._send(400, {"error": "ação desconhecida"}); return

                with _lock:
                    _save_json("alerts", _alerts)
                add_log(action, agent_id, "ok", msg)
                self._send(200, {"status": "ok", "action": action, "agent_id": agent_id, "message": msg})

            except Exception as e:
                logger.error(f"action error: {e}")
                self._send(500, {"error": str(e)})

        # ── Agent direct actions ──
        elif path == "/api/agent/isolate":
            try:
                body     = self._body()
                agent_id = body.get("agent_id", "")
                threading.Thread(target=wazuh.isolate_agent, args=(agent_id,), daemon=True).start()
                add_log("isolate", agent_id, "ok", f"Agente {agent_id} isolado via painel")
                self._send(200, {"status": "ok", "message": f"Isolando {agent_id}…"})
            except Exception as e:
                self._send(500, {"error": str(e)})

        elif path == "/api/agent/restore":
            try:
                body     = self._body()
                agent_id = body.get("agent_id", "")
                threading.Thread(target=wazuh.restore_agent, args=(agent_id,), daemon=True).start()
                add_log("restore", agent_id, "ok", f"Agente {agent_id} restaurado via painel")
                self._send(200, {"status": "ok", "message": f"Restaurando {agent_id}…"})
            except Exception as e:
                self._send(500, {"error": str(e)})

        elif path == "/api/agent/kill":
            try:
                body     = self._body()
                agent_id = body.get("agent_id", "")
                pid      = body.get("pid", "")
                threading.Thread(target=wazuh.kill_process, args=(agent_id, str(pid)), daemon=True).start()
                add_log("kill", agent_id, "ok", f"Kill PID {pid}")
                self._send(200, {"status": "ok", "message": f"Kill PID {pid}…"})
            except Exception as e:
                self._send(500, {"error": str(e)})

        elif path == "/api/ticket/create":
            try:
                body    = self._body()
                aid     = body.get("alert_id", "")
                project = body.get("project", "SOC")
                title   = body.get("title", "")
                priority= body.get("priority", "High")
                assignee= body.get("assignee", "")
                desc    = body.get("description", "")
                labels  = body.get("labels", [])
                ticket = {
                    "id": f"{project}-{int(time.time()) % 100000}",
                    "alert_id": aid,
                    "project": project,
                    "title": title,
                    "priority": priority,
                    "assignee": assignee,
                    "description": desc,
                    "labels": labels,
                    "status": "OPEN",
                    "created_at": datetime.now().isoformat(timespec="seconds"),
                    "url": f"https://jira.empresa.com/browse/{project}-{int(time.time()) % 100000}",
                }
                with _lock:
                    _tickets.insert(0, ticket)
                    if len(_tickets) > 200: _tickets.pop()
                    _save_json("tickets", _tickets)
                # Add note to alert
                with _lock:
                    alert = next((a for a in _alerts if a["id"] == aid), None)
                if alert:
                    alert.setdefault("notes", []).append({
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "text": f"Ticket criado: {ticket['id']} ({project}/{priority})"
                    })
                    with _lock:
                        _save_json("alerts", _alerts)
                add_log("ticket", aid, "ok", f"Ticket {ticket['id']} criado")
                self._send(200, {"status": "ok", "ticket": ticket})
            except Exception as e:
                self._send(500, {"error": str(e)})

        elif path == "/api/forensics/collect":
            try:
                body  = self._body()
                aid   = body.get("alert_id", "")
                with _lock:
                    alert = next((a for a in _alerts if a["id"] == aid), None)
                if not alert:
                    self._send(404, {"error": "alert not found"}); return
                evidence = collect_evidence(alert)
                with _lock:
                    _evidences.insert(0, evidence)
                    if len(_evidences) > 100: _evidences.pop()
                    _save_json("evidences", _evidences)
                alert.setdefault("notes", []).append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "text": f"Evidências coletadas: {evidence['evidence_id']}"
                })
                with _lock:
                    _save_json("alerts", _alerts)
                add_log("forensics", alert["agent_id"], "ok", f"Evidência {evidence['evidence_id']} coletada")
                self._send(200, {"status": "ok", "evidence": evidence})
            except Exception as e:
                logger.error(f"forensics error: {e}")
                self._send(500, {"error": str(e)})

        else:
            self._send(404, {"error": "not found"})


# ─── Main ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if HAS_PDF:
        logger.info("✓ fpdf2 disponível — relatórios PDF habilitados")
    else:
        logger.info("ℹ fpdf2 não instalado — relatórios em .txt (instale com: pip3 install fpdf2)")

    server = HTTPServer(("0.0.0.0", SOAR_PORT), SOARHandler)
    logger.info("=" * 60)
    logger.info("  SOAR Platform v2 iniciado")
    logger.info(f"  Dashboard: http://{WAZUH_HOST}:{SOAR_PORT}")
    logger.info(f"  Wazuh:     https://{WAZUH_HOST}:{WAZUH_PORT}")
    logger.info("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Servidor encerrado.")

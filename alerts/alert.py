import smtplib
import time
from collections import deque
from datetime import datetime, timezone
from email.message import EmailMessage

import requests

import os
import rules

# ---------- Configuration ----------
ES = os.getenv("ES_URL", "http://localhost:9200")
ES_AUTH = (os.getenv("ES_USER", "elastic"), os.getenv("ES_PASSWORD", ""))
TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
BRUTE_THRESHOLD = int(os.getenv("BRUTE_THRESHOLD", "50"))
COOLDOWN = int(os.getenv("COOLDOWN", "600"))
SPIKE_FACTOR = float(os.getenv("SPIKE_FACTOR", "3"))
SPIKE_MIN_EVENTS = int(os.getenv("SPIKE_MIN_EVENTS", "200"))
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY")
ABUSE_THRESHOLD = int(os.getenv("ABUSE_THRESHOLD", "80"))
ABUSE_DAILY_QUOTA = 900  # la clé gratuite autorise 1000 requêtes/jour
REPUTATION_TTL = 7 * 86400
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_FROM = os.getenv("SMTP_FROM") or SMTP_USER
EMAIL_TO = os.getenv("ALERT_EMAIL_TO")
BLOCKLIST_URL = "https://lists.blocklist.de/lists/ssh.txt"
LOOP_SECONDS = 30

# ---------- État interne (borné) ----------
last_sent = {}
seen_events = deque(maxlen=5000)
seen_set = set()
blocklist = set()
blocklist_loaded = 0
abuse_calls = {"day": None, "n": 0}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def mark_seen(event_id):
    if len(seen_events) == seen_events.maxlen:
        seen_set.discard(seen_events[0])
    seen_events.append(event_id)
    seen_set.add(event_id)


# ---------- Accès Elasticsearch ----------
def es_request(method, path, body=None):
    try:
        r = requests.request(method, f"{ES}/{path}", json=body, auth=ES_AUTH, timeout=15)
        return r.json()
    except Exception as e:
        print("Erreur Elasticsearch :", e)
        return {}


def search(body, index="cowrie-*"):
    return es_request("POST", f"{index}/_search", body)


# ---------- Canaux de notification ----------
def send_telegram(msg):
    if not TOKEN or not CHAT_ID:
        return False
    try:
        r = requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage",
                          data={"chat_id": CHAT_ID, "text": msg}, timeout=10)
        print("Telegram :", r.status_code)
        return r.ok
    except Exception as e:
        print("Erreur Telegram :", e)
        return False


def send_email(subject, body):
    if not (SMTP_HOST and EMAIL_TO and SMTP_FROM):
        return False
    try:
        m = EmailMessage()
        m["Subject"], m["From"], m["To"] = subject, SMTP_FROM, EMAIL_TO
        m.set_content(body)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(m)
        print("Email envoyé :", subject)
        return True
    except Exception as e:
        print("Erreur email :", e)
        return False


def raise_alert(rule, src_ip, text, count=None, event_id=None, cooldown_key=None):
    """Route l'alerte selon le niveau, applique l'anti-doublon et l'archive dans ES."""
    key = cooldown_key or f"{rule}:{src_ip}"
    now = time.time()
    if now - last_sent.get(key, 0) < COOLDOWN:
        return
    last_sent[key] = now
    severity, channels = rules.ROUTING[rule]
    msg = rules.format_alert(rule, text)
    delivered = []
    if "telegram" in channels and send_telegram(msg):
        delivered.append("telegram")
    if "email" in channels and send_email(f"[Honeypot {severity.upper()}] {rule}", msg):
        delivered.append("email")
    doc = {"@timestamp": now_iso(), "rule": rule, "severity": severity, "message": text,
           "channels": delivered or channels, "delivered": bool(delivered)}
    if src_ip:
        doc["src_ip"] = src_ip
    if count is not None:
        doc["count"] = count
    if event_id:
        doc["event_id"] = event_id
    es_request("POST", "honeypot-alerts/_doc", doc)


# ---------- Réputation des IP ----------
def refresh_blocklist():
    global blocklist, blocklist_loaded
    if time.time() - blocklist_loaded < 3600:
        return
    blocklist_loaded = time.time()
    try:
        r = requests.get(BLOCKLIST_URL, timeout=20)
        r.raise_for_status()
        blocklist = {l.strip() for l in r.text.splitlines() if l.strip() and not l.startswith("#")}
        print(f"Blocklist chargée : {len(blocklist)} IP")
    except Exception as e:
        print("Erreur blocklist :", e)


def abuse_score(ip):
    """Score AbuseIPDB (0-100) avec cache Elasticsearch ; None si indisponible."""
    if not ABUSE_KEY or not rules.is_public_ip(ip):
        return None
    cached = es_request("GET", f"ip-reputation/_doc/{ip}")
    if cached.get("found"):
        src = cached["_source"]
        age = time.time() - datetime.fromisoformat(src["@timestamp"].replace("Z", "+00:00")).timestamp()
        if age < REPUTATION_TTL:
            return src.get("abuse_score")
    today = datetime.now(timezone.utc).date()
    if abuse_calls["day"] != today:
        abuse_calls.update(day=today, n=0)
    if abuse_calls["n"] >= ABUSE_DAILY_QUOTA:
        return None
    abuse_calls["n"] += 1
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         headers={"Key": ABUSE_KEY, "Accept": "application/json"},
                         params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10)
        r.raise_for_status()
        d = r.json()["data"]
    except Exception as e:
        print("Erreur AbuseIPDB :", e)
        return None
    es_request("PUT", f"ip-reputation/_doc/{ip}", {
        "@timestamp": now_iso(), "src_ip": ip, "abuse_score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"), "isp": d.get("isp"),
        "total_reports": d.get("totalReports")})
    return d.get("abuseConfidenceScore")


# ---------- Règles de détection ----------
def recent_ips(window="now-1m", size=50):
    body = {"size": 0, "query": {"range": {"@timestamp": {"gte": window}}},
            "aggs": {"ips": {"terms": {"field": "src_ip", "size": size}}}}
    return [b["key"] for b in search(body).get("aggregations", {}).get("ips", {}).get("buckets", [])]


def check_bruteforce():
    body = {"size": 0, "query": {"bool": {"filter": [
        {"terms": {"eventid": ["cowrie.login.failed", "cowrie.login.success"]}},
        {"range": {"@timestamp": {"gte": "now-1m"}}}]}},
        "aggs": {"ips": {"terms": {"field": "src_ip", "min_doc_count": BRUTE_THRESHOLD}}}}
    for b in search(body).get("aggregations", {}).get("ips", {}).get("buckets", []):
        ip = b["key"]
        score = abuse_score(ip)
        extra = f" | AbuseIPDB {score}%" if score is not None else ""
        extra += " | listée blocklist.de" if ip in blocklist else ""
        raise_alert("brute_force", ip,
                    f"Brute force SSH/Telnet : {ip} ({b['doc_count']} tentatives en 1 min){extra}",
                    count=b["doc_count"])


def new_hits(event_filter, window="now-5m"):
    body = {"size": 100, "sort": [{"@timestamp": "asc"}],
            "query": {"bool": {"filter": [event_filter, {"range": {"@timestamp": {"gte": window}}}]}}}
    for hit in search(body).get("hits", {}).get("hits", []):
        if hit["_id"] in seen_set:
            continue
        mark_seen(hit["_id"])
        yield hit["_id"], hit["_source"]


def check_commands():
    for eid, src in new_hits({"term": {"eventid": "cowrie.command.input"}}):
        cmd = src.get("command_input") or ""
        if rules.is_dangerous(cmd):
            ip = src.get("src_ip")
            raise_alert("dangerous_command", ip, f"Commande dangereuse de {ip} : {cmd}",
                        event_id=eid, cooldown_key=f"cmd:{eid}")


def check_downloads():
    flt = {"terms": {"eventid": ["cowrie.session.file_download", "cowrie.session.file_upload"]}}
    for eid, src in new_hits(flt):
        ip = src.get("src_ip")
        what = src.get("url") or src.get("filename") or src.get("outfile") or "fichier inconnu"
        sha = f" (sha256 {src['shasum'][:16]}…)" if src.get("shasum") else ""
        raise_alert("file_download", ip, f"Dépôt de fichier par {ip} : {what}{sha}",
                    event_id=eid, cooldown_key=f"dl:{eid}")


def check_reputation():
    for ip in recent_ips():
        score = abuse_score(ip)
        if rules.is_malicious(score, ABUSE_THRESHOLD, ip in blocklist):
            detail = f"score AbuseIPDB {score}%" if score is not None else "listée sur blocklist.de"
            raise_alert("malicious_ip", ip, f"IP malveillante connue : {ip} ({detail})")


def check_spike():
    def hourly(window_from, window_to):
        return search({"size": 0, "track_total_hits": True, "query": {"range": {
            "@timestamp": {"gte": window_from, "lt": window_to}}}}
        ).get("hits", {}).get("total", {}).get("value", 0)
    current = hourly("now-1h", "now")
    baseline = hourly("now-25h", "now-1h") / 24
    if rules.is_spike(current, baseline, SPIKE_FACTOR, SPIKE_MIN_EVENTS):
        raise_alert("activity_spike", None,
                    f"Pic d'activité : {current} événements sur 1 h (moyenne habituelle {baseline:.0f}/h)",
                    count=current, cooldown_key="spike")


def preload_seen():
    """Après un redémarrage, ne pas ré-alerter sur les événements déjà traités."""
    body = {"size": 500, "query": {"bool": {"filter": [
        {"exists": {"field": "event_id"}}, {"range": {"@timestamp": {"gte": "now-15m"}}}]}}}
    for hit in search(body, index="honeypot-alerts*").get("hits", {}).get("hits", []):
        mark_seen(hit["_source"]["event_id"])


CHECKS = [check_bruteforce, check_commands, check_downloads, check_reputation, check_spike]

if __name__ == "__main__":
    if not (TOKEN and CHAT_ID) and not (SMTP_HOST and EMAIL_TO):
        raise SystemExit("Configurez Telegram et/ou SMTP dans .env")
    print("Surveillance démarrée...")
    preload_seen()
    while True:
        refresh_blocklist()
        for check in CHECKS:
            try:
                check()
            except Exception as e:  # une règle en erreur ne doit pas arrêter les autres
                print(f"Erreur dans {check.__name__} :", e)
        time.sleep(LOOP_SECONDS)

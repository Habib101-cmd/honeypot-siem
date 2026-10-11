import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()

# ---------- Configuration ----------
ES = os.getenv("ES_URL", "http://localhost:9200")
TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
BRUTE_THRESHOLD = int(os.getenv("BRUTE_THRESHOLD", "50"))
COOLDOWN = 600  # secondes entre deux alertes identiques
DANGEROUS = ["wget", "curl", "chmod +x", "rm -rf", "nc ", "bash -i"]
BLOCKLIST_URL = "https://lists.blocklist.de/lists/ssh.txt"

# ---------- État interne ----------
last_sent = {}
seen_hits = set()
blocklist = set()
blocklist_loaded = 0


# ---------- Fonctions utilitaires ----------
def send(msg):
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": msg},
            timeout=10,
        )
        print("Telegram :", r.status_code, msg)
    except Exception as e:
        print("Erreur Telegram :", e)


def should_alert(key):
    """Évite d'envoyer la même alerte plusieurs fois de suite."""
    now = time.time()
    if now - last_sent.get(key, 0) < COOLDOWN:
        return False
    last_sent[key] = now
    return True


def search(body):
    try:
        r = requests.post(f"{ES}/cowrie-*/_search", json=body, timeout=10)
        return r.json()
    except Exception as e:
        print("Erreur Elasticsearch :", e)
        return {}


def refresh_blocklist():
    """Télécharge la liste d'IP malveillantes une fois par heure."""
    global blocklist, blocklist_loaded
    if time.time() - blocklist_loaded < 3600:
        return
    blocklist_loaded = time.time()
    try:
        r = requests.get(BLOCKLIST_URL, timeout=20)
        r.raise_for_status()
        blocklist = {
            line.strip()
            for line in r.text.splitlines()
            if line.strip() and not line.startswith("#")
        }
        print(f"Blocklist chargée : {len(blocklist)} IP")
    except Exception as e:
        print("Erreur blocklist :", e)


# ---------- Règles de détection ----------
def check_bruteforce():
    body = {
        "size": 0,
        "query": {"bool": {"filter": [
            {"terms": {"eventid": ["cowrie.login.failed", "cowrie.login.success"]}},
            {"range": {"@timestamp": {"gte": "now-1m"}}},
        ]}},
        "aggs": {"ips": {"terms": {"field": "src_ip", "min_doc_count": BRUTE_THRESHOLD}}},
    }
    buckets = search(body).get("aggregations", {}).get("ips", {}).get("buckets", [])
    for b in buckets:
        ip = b["key"]
        if should_alert("brute:" + ip):
            extra = " | IP déjà signalée (blocklist.de)" if ip in blocklist else ""
            send(f"🚨 Brute force : {ip} ({b['doc_count']} tentatives en 1 min){extra}")


def check_commands():
    body = {
        "size": 50,
        "query": {"bool": {"filter": [
            {"term": {"eventid": "cowrie.command.input"}},
            {"range": {"@timestamp": {"gte": "now-2m"}}},
        ]}},
    }
    for hit in search(body).get("hits", {}).get("hits", []):
        if hit["_id"] in seen_hits:
            continue
        seen_hits.add(hit["_id"])
        src = hit["_source"]
        cmd = src.get("command_input") or ""
        if not isinstance(cmd, str):
            cmd = ""
        if any(d in cmd for d in DANGEROUS):
            send(f"⚠️ Commande dangereuse de {src.get('src_ip')} : {cmd}")


def check_reputation():
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-1m"}}},
        "aggs": {"ips": {"terms": {"field": "src_ip", "size": 50}}},
    }
    buckets = search(body).get("aggregations", {}).get("ips", {}).get("buckets", [])
    for b in buckets:
        ip = b["key"]
        if ip in blocklist and should_alert("rep:" + ip):
            send(f"🔴 IP malveillante connue : {ip} (listée sur blocklist.de)")


# ---------- Boucle principale ----------
if __name__ == "__main__":
    if not TOKEN or not CHAT_ID:
        raise SystemExit("TELEGRAM_TOKEN ou TELEGRAM_CHAT_ID manquant dans .env")
    print("Surveillance démarrée...")
    while True:
        refresh_blocklist()
        check_bruteforce()
        check_commands()
        check_reputation()
        time.sleep(60)

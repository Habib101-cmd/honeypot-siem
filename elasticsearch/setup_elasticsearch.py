"""Initialisation idempotente d'Elasticsearch (exécutée par le service `setup`)."""
import os
import sys
import time

import requests

ES = os.getenv("ES_URL", "http://localhost:9200")
AUTH = (os.getenv("ES_USER", "elastic"), os.getenv("ES_PASSWORD", ""))
KIBANA_PASSWORD = os.getenv("KIBANA_PASSWORD")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))

PIPELINE = {
    "description": "Géolocalisation de l'IP source",
    "processors": [
        {"geoip": {"field": "src_ip", "target_field": "geoip",
                   "ignore_missing": True, "ignore_failure": True}}
    ],
}

# Les index sont des index quotidiens classiques (cowrie-YYYY.MM.DD).
COWRIE_TEMPLATE = {
    "index_patterns": ["cowrie-*"],
    "priority": 500,
    "template": {
        "settings": {"index.lifecycle.name": "honeypot-retention"},
        "mappings": {
            "dynamic_templates": [
                {"strings_as_keyword": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "keyword", "ignore_above": 1024}}}
            ],
            "properties": {
                "@timestamp": {"type": "date"},
                "geoip": {"properties": {"location": {"type": "geo_point"}}},
            },
        },
    },
}

ALERTS_TEMPLATE = {
    "index_patterns": ["honeypot-alerts*"],
    "priority": 500,
    "template": {"mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "rule": {"type": "keyword"},
        "severity": {"type": "keyword"},
        "src_ip": {"type": "ip"},
        "message": {"type": "text"},
        "channels": {"type": "keyword"},
        "count": {"type": "long"},
    }}},
}

REPUTATION_TEMPLATE = {
    "index_patterns": ["ip-reputation*"],
    "priority": 500,
    "template": {"mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "src_ip": {"type": "ip"},
        "abuse_score": {"type": "integer"},
        "country": {"type": "keyword"},
        "isp": {"type": "keyword"},
        "total_reports": {"type": "integer"},
    }}},
}

ILM = {"policy": {"phases": {
    "hot": {"actions": {}},
    "delete": {"min_age": f"{RETENTION_DAYS}d", "actions": {"delete": {}}},
}}}


def call(method, path, body=None):
    r = requests.request(method, f"{ES}/{path}", json=body, auth=AUTH, timeout=30)
    print(method, path, "->", r.status_code, r.text[:120].replace("\n", " "))
    if r.status_code >= 400:
        sys.exit(1)


def wait_for_es(retries=60):
    for _ in range(retries):
        try:
            if requests.get(ES, auth=AUTH, timeout=5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(5)
    sys.exit("Elasticsearch injoignable")


if __name__ == "__main__":
    wait_for_es()
    if KIBANA_PASSWORD:
        call("POST", "_security/user/kibana_system/_password", {"password": KIBANA_PASSWORD})
    call("PUT", "_ilm/policy/honeypot-retention", ILM)
    call("PUT", "_ingest/pipeline/cowrie-geoip", PIPELINE)
    call("PUT", "_index_template/cowrie-template", COWRIE_TEMPLATE)
    call("PUT", "_index_template/honeypot-alerts-template", ALERTS_TEMPLATE)
    call("PUT", "_index_template/ip-reputation-template", REPUTATION_TEMPLATE)
    print("Configuration Elasticsearch terminée.")

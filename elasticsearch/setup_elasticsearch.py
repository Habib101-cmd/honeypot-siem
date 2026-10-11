import sys
import requests

ES = "http://localhost:9200"

PIPELINE = {
    "processors": [
        {"geoip": {"field": "src_ip", "target_field": "geoip",
                   "ignore_missing": True, "ignore_failure": True}}
    ]
}

TEMPLATE = {
    "index_patterns": ["cowrie-*"],
    "priority": 500,
    "data_stream": {},
    "template": {
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
        }
    },
}


def put(path, body):
    r = requests.put(f"{ES}/{path}", json=body, timeout=30)
    print(path, "->", r.status_code, r.text[:120])
    if r.status_code >= 400:
        sys.exit(1)


put("_ingest/pipeline/cowrie-geoip", PIPELINE)
put("_index_template/cowrie-template", TEMPLATE)
print("Configuration Elasticsearch terminée.")

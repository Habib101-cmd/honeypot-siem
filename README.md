# Honeypot SIEM

Mini-SOC : honeypot Cowrie, stack Elastic (Elasticsearch, Kibana, Filebeat) et alertes Telegram.

## Architecture

Attaquant → Cowrie → Filebeat → Elasticsearch → Kibana
↓
Script alerts → Telegram

## Prérequis

Docker Desktop, Python 3, un bot Telegram (BotFather).

## Installation

1. Copier `.env.example` vers `.env` et le remplir.
2. `docker compose up -d elasticsearch kibana`
3. Attendre 1 à 2 minutes, puis : `python elasticsearch/setup_elasticsearch.py`
4. `docker compose up -d --build`
5. Kibana (http://localhost:5601) → Stack Management → Saved Objects → Import → `kibana/dashboard.ndjson`

## Tests

- Connexion au honeypot : `ssh -p 2222 root@localhost`
- Simulation d'attaques : `python scripts/simulate_attacks.py`

## Avertissement

Projet éducatif. Ne jamais exposer Elasticsearch ou Kibana sur Internet. Déployer le honeypot sur une machine isolée.

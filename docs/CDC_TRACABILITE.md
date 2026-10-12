# Traçabilité cahier des charges → implémentation

| Réf. | Exigence | Statut | Où |
| ---- | -------- | ------ | -- |
| F1 | Honeypot SSH/Telnet | ✅ | Cowrie, ports 2222/2223 (`docker-compose.yml`) |
| F2 | Journalisation | ✅ | `cowrie.json` |
| F3 | Collecte centralisée | ✅ | `filebeat.yml` (Logstash non utilisé : Filebeat → ES direct) |
| F4 | Parsing + enrichissement | ✅ | GeoIP (pipeline ES) ; AbuseIPDB (`alerts/alert.py`, index `ip-reputation`, clé requise) |
| F5 | Stockage/recherche | ✅ | Elasticsearch, rétention `RETENTION_DAYS` |
| F6 | Dashboard | 🟡 | Panneaux d'origine conservés ; totaux jour/semaine/mois, top pays et dernières alertes restent à ajouter dans Kibana (Data Views `honeypot-alerts*`, `ip-reputation*` prêtes) |
| F7 | Règles de détection | ✅ | 5 règles, `alerts/rules.py` |
| F8 | Alertes Telegram/email | ✅ | `alerts/alert.py` (email : renseigner SMTP) |
| F9 | Auth dashboard | ✅ | Sécurité Elastic activée |
| F10 | Export de rapports | ✅ | service `reports` (PDF + CSV) |
| F11 | Blocage auto d'IP | ⏳ évolution (hors périmètre) | — |
| NFR | Isolation, redémarrage, Docker, doc | ✅ | `scripts/isolate_honeypot.sh`, restart policy, README |

Non vérifié par exécution : la stack Docker complète (images non lancées dans l'environnement de développement). Vérifié : tests unitaires des règles, génération PDF/CSV, syntaxe des scripts.

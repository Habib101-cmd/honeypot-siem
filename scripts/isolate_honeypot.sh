#!/usr/bin/env bash
# Isolation du honeypot : bloque les connexions SORTANTES des conteneurs cowrie
# (empêche le rebond / l'utilisation du honeypot comme relais d'attaque).
# À exécuter en root sur l'hôte Docker (Linux). Test : voir README, section Isolation.
set -euo pipefail

CONTAINER=cowrie
IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER")
[ -n "$IP" ] || { echo "Conteneur $CONTAINER introuvable"; exit 1; }

# DOCKER-USER est évaluée avant les règles de Docker et survit aux redémarrages de conteneurs.
iptables -N HONEYPOT_EGRESS 2>/dev/null || iptables -F HONEYPOT_EGRESS
# Autoriser uniquement les réponses aux connexions entrantes (SSH/Telnet des attaquants)
iptables -A HONEYPOT_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# Journaliser puis refuser toute connexion initiée par le honeypot
iptables -A HONEYPOT_EGRESS -m limit --limit 5/min -j LOG --log-prefix "HONEYPOT-EGRESS-DROP: "
iptables -A HONEYPOT_EGRESS -j DROP

iptables -D DOCKER-USER -s "$IP" -j HONEYPOT_EGRESS 2>/dev/null || true
iptables -I DOCKER-USER -s "$IP" -j HONEYPOT_EGRESS
echo "Egress bloqué pour $CONTAINER ($IP). Vérification :"
echo "  docker exec cowrie sh -c 'wget -T 3 -qO- http://example.com || echo BLOQUE'"
echo "Note : l'IP du conteneur peut changer après recréation ; relancer ce script."

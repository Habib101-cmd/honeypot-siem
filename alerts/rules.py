"""Logique de détection pure (sans I/O), facile à tester."""
import ipaddress
import re

DANGEROUS_RE = re.compile(
    r"\b(wget|curl|tftp|ftpget)\b|chmod\s+\+x|rm\s+-rf|\bnc\b|bash\s+-i|/dev/tcp/",
    re.IGNORECASE,
)

# Règle -> (niveau, canaux) : conforme au tableau du cahier des charges (section 7)
ROUTING = {
    "brute_force":       ("high",     ["telegram"]),
    "dangerous_command": ("critical", ["telegram", "email"]),
    "malicious_ip":      ("medium",   ["email"]),
    "file_download":     ("high",     ["telegram"]),
    "activity_spike":    ("medium",   ["email"]),
}

SEVERITY_ICON = {"critical": "🛑", "high": "🚨", "medium": "⚠️"}


def is_dangerous(command):
    return isinstance(command, str) and bool(DANGEROUS_RE.search(command))


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def is_spike(current, baseline_avg, factor, min_events):
    """Pic : volume horaire élevé en absolu ET supérieur à `factor` x la moyenne."""
    if current < min_events:
        return False
    return current > factor * max(baseline_avg, 1)


def is_malicious(score, threshold, in_blocklist=False):
    """Score AbuseIPDB >= seuil, ou présence dans la liste de blocage."""
    return (score is not None and score >= threshold) or in_blocklist


def format_alert(rule, text):
    severity, _ = ROUTING[rule]
    return f"{SEVERITY_ICON[severity]} [{severity.upper()}] {text}"

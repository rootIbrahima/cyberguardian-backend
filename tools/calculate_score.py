"""
Outil #10 du CDC — calculate_score()
Score global /100 pondéré selon le CDC §4.3 :
    DNS 25 pts · SSL/TLS 25 pts · Headers HTTP 20 pts · Ports 15 pts · Réputation 15 pts

Les critères dont l'outil n'est pas encore implémenté (ports, réputation) ou
non applicables (DNS pour une IP) sont exclus du calcul : le score est
normalisé sur les critères réellement évalués, pour ne pas pénaliser la cible
sur des contrôles qui n'ont pas eu lieu.
"""

WEIGHTS = {
    "dns":        25,
    "ssl":        25,
    "headers":    20,
    "ports":      15,   # scan_ports() — à venir
    "reputation": 15,   # scan_virustotal() + scan_abuseipdb() — à venir
}

LABELS = {
    "dns":        "DNS (SPF, DMARC, DKIM, DNSSEC)",
    "ssl":        "SSL/TLS",
    "headers":    "En-têtes HTTP",
    "ports":      "Ports réseau",
    "reputation": "Réputation",
}


def calculate_score(parts: dict[str, int]) -> dict:
    """
    parts : critère -> points obtenus (uniquement les critères évalués).
    Retourne le score global /100 normalisé + le détail par critère.
    """
    evaluated = {k: v for k, v in parts.items() if k in WEIGHTS and v is not None}
    max_raw = sum(WEIGHTS[k] for k in evaluated)
    raw = sum(min(v, WEIGHTS[k]) for k, v in evaluated.items())
    score = round(raw / max_raw * 100) if max_raw else 0

    return {
        "score":     score,
        "raw":       raw,
        "max_raw":   max_raw,
        "breakdown": [
            {
                "criterion": k,
                "label":     LABELS[k],
                "points":    evaluated[k],
                "max":       WEIGHTS[k],
            }
            for k in WEIGHTS if k in evaluated
        ],
        "not_evaluated": [
            {"criterion": k, "label": LABELS[k], "max": WEIGHTS[k]}
            for k in WEIGHTS if k not in evaluated
        ],
    }

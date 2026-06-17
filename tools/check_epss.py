"""
Outil EPSS — Exploit Prediction Scoring System (FIRST.org).
Enrichit les CVE détectées (EASM et dépendances GitHub) avec la probabilité
d'exploitation à 30 jours, puis croise CVSS (gravité) et EPSS (probabilité)
pour produire une priorité de traitement.

CVSS répond à « à quel point c'est grave » ; EPSS à « quelle probabilité que
ce soit exploité ». Les deux combinés permettent une priorisation fondée sur
le risque réel plutôt que sur la seule gravité théorique.

API publique et gratuite : https://api.first.org/data/v1/epss (sans clé).
"""

import httpx

_EPSS_URL = "https://api.first.org/data/v1/epss"
_TIMEOUT = 10
_CHUNK = 80   # nombre de CVE par requête

# Sévérité textuelle -> CVSS approximatif (pour les findings sans score numérique)
_SEV_TO_CVSS = {
    "CRITICAL": 9.0, "CRITIQUE": 9.0,
    "HIGH": 7.5, "HAUT": 7.5,
    "MEDIUM": 5.0, "MOYEN": 5.0, "MODERATE": 5.0,
    "LOW": 2.0, "BAS": 2.0,
}

# Seuils de priorisation (documentés pour le mémoire)
_EPSS_PROBABLE = 0.10   # 10 % de probabilité d'exploitation à 30 jours
_CVSS_GRAVE    = 7.0    # seuil de gravité "élevée" au sens CVSS


def fetch_epss(cve_ids: list[str]) -> dict:
    """Retourne {cve_id: {"epss": float, "percentile": float}} pour les CVE
    connues de l'EPSS. Les CVE absentes ne figurent pas dans le résultat.
    En cas d'échec réseau, retourne un dictionnaire vide (dégradation propre)."""
    ids = sorted({c for c in cve_ids if c and c.upper().startswith("CVE-")})
    if not ids:
        return {}

    out: dict = {}
    for i in range(0, len(ids), _CHUNK):
        chunk = ids[i:i + _CHUNK]
        try:
            resp = httpx.get(_EPSS_URL, params={"cve": ",".join(chunk)}, timeout=_TIMEOUT)
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                cve = row.get("cve")
                if cve:
                    out[cve] = {
                        "epss":       round(float(row.get("epss", 0)), 4),
                        "percentile": round(float(row.get("percentile", 0)), 4),
                    }
        except Exception:
            continue   # un échec de lot ne bloque pas les autres
    return out


def _cvss_of(item: dict) -> float:
    c = item.get("cvss")
    if isinstance(c, (int, float)):
        return float(c)
    return _SEV_TO_CVSS.get((item.get("severity") or "").upper(), 0.0)


def combined_priority(cvss: float, epss: float | None) -> str:
    """Priorité croisée CVSS × EPSS : URGENTE | ÉLEVÉE | À SURVEILLER | FAIBLE."""
    grave    = (cvss or 0) >= _CVSS_GRAVE
    probable = epss is not None and epss >= _EPSS_PROBABLE
    if grave and probable:
        return "URGENTE"        # grave ET activement exploitée
    if grave:
        return "ÉLEVÉE"         # grave mais peu exploitée pour l'instant
    if probable:
        return "À SURVEILLER"   # exploitée même si moins grave
    return "FAIBLE"


def enrich_cves(cves: list[dict], id_key: str = "id") -> list[dict]:
    """Ajoute à chaque CVE les champs epss, epss_percentile et priority.
    id_key vaut 'id' pour les CVE EASM, 'cve' pour les findings Safety GitHub."""
    if not cves:
        return cves
    epss_map = fetch_epss([c.get(id_key, "") for c in cves])
    for c in cves:
        info = epss_map.get(c.get(id_key, ""))
        epss = info["epss"] if info else None
        c["epss"]            = epss
        c["epss_percentile"] = info["percentile"] if info else None
        c["priority"]        = combined_priority(_cvss_of(c), epss)
    return cves

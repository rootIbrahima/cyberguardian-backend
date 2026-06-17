"""
Outil #5 du CDC — scan_headers()
Analyse les en-têtes de sécurité HTTP d'un site : CSP, HSTS, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
Pèse 20 pts dans le score global (protection XSS, clickjacking, sniffing).
"""

import warnings
from dataclasses import dataclass, field
from typing import Optional

import httpx

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# (en-tête, points, sévérité si absent, titre, recommandation)
HEADER_CHECKS = [
    ("strict-transport-security", 5, "HAUT",
     "HSTS absent (Strict-Transport-Security)",
     "Sans HSTS, un attaquant peut forcer une connexion HTTP non chiffrée (attaque SSL stripping). "
     "Ajoutez : Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", 5, "HAUT",
     "CSP absente (Content-Security-Policy)",
     "Sans CSP, le navigateur exécute n'importe quel script injecté (XSS). "
     "Définissez une politique restreignant les sources de scripts."),
    ("x-frame-options", 4, "MOYEN",
     "X-Frame-Options absent",
     "Le site peut être chargé dans une iframe malveillante (clickjacking). "
     "Ajoutez : X-Frame-Options: DENY (ou frame-ancestors dans la CSP)."),
    ("x-content-type-options", 3, "MOYEN",
     "X-Content-Type-Options absent",
     "Le navigateur peut interpréter un fichier avec un mauvais type MIME (MIME sniffing). "
     "Ajoutez : X-Content-Type-Options: nosniff"),
    ("referrer-policy", 2, "BAS",
     "Referrer-Policy absent",
     "Les URLs visitées (avec leurs paramètres) fuitent vers les sites tiers. "
     "Ajoutez : Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", 1, "BAS",
     "Permissions-Policy absent",
     "Les API sensibles du navigateur (caméra, micro, géolocalisation) ne sont pas restreintes. "
     "Ajoutez : Permissions-Policy: camera=(), microphone=(), geolocation=()"),
]

_SEVERITY_COLOR = {"HAUT": "orange", "MOYEN": "yellow", "BAS": "blue"}


@dataclass
class HeadersResult:
    target: str
    reachable: bool = False
    final_url: Optional[str] = None
    headers_present: dict = field(default_factory=dict)    # en-tête → valeur (tronquée)
    headers_missing: list[str] = field(default_factory=list)
    server_banner: Optional[str] = None
    score: int = 0                                          # 0-20 pts (poids Headers dans le score global)
    issues: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def _extract_host(target: str) -> str:
    target = target.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0]


def scan_headers(target: str, timeout: int = 10) -> HeadersResult:
    host = _extract_host(target)
    result = HeadersResult(target=host)

    resp = None
    for scheme in ("https", "http"):
        try:
            resp = httpx.get(
                f"{scheme}://{host}",
                timeout=timeout,
                follow_redirects=True,
                verify=False,  # nosec B501 — intentionnel : scanner des sites au certificat invalide
            )
            break
        except Exception as e:
            result.error = str(e)

    if resp is None:
        result.issues.append({
            "severity": "CRITIQUE",
            "color":    "red",
            "title":    "Site web inaccessible",
            "desc":     "Impossible de récupérer les en-têtes HTTP (ni en HTTPS ni en HTTP).",
            "tool":     "scan_headers()",
        })
        return result

    result.reachable = True
    result.error = None
    result.final_url = str(resp.url)
    result.server_banner = resp.headers.get("server")

    score = 0
    for header, points, severity, title, reco in HEADER_CHECKS:
        value = resp.headers.get(header)
        if value:
            score += points
            result.headers_present[header] = value[:120]
        else:
            result.headers_missing.append(header)
            result.issues.append({
                "severity": severity,
                "color":    _SEVERITY_COLOR[severity],
                "title":    title,
                "desc":     reco,
                "tool":     "scan_headers()",
            })

    # Site servi en HTTP uniquement — les en-têtes ne protègent rien sans TLS
    if result.final_url and result.final_url.startswith("http://"):
        result.issues.append({
            "severity": "CRITIQUE",
            "color":    "red",
            "title":    "Site accessible uniquement en HTTP",
            "desc":     "Tout le trafic circule en clair. Activez HTTPS avant toute autre mesure.",
            "tool":     "scan_headers()",
        })
        score = max(0, score - 5)

    result.score = score
    return result

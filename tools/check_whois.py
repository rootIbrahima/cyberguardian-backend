"""
Outil #2 du CDC — check_whois()
Interroge la base WHOIS d'un domaine : registrar, propriétaire, dates de
création et d'expiration. Signale une expiration proche ou dépassée, qui
expose le domaine à un détournement (un domaine expiré peut être racheté
par un tiers).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import whois


@dataclass
class WhoisResult:
    target: str
    found: bool = False
    registrar: Optional[str] = None
    owner: Optional[str] = None
    country: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None
    days_until_expiry: Optional[int] = None
    name_servers: list[str] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def _extract_domain(target: str) -> str:
    target = target.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0].split(":")[0]


def _first(value):
    """python-whois renvoie parfois une liste — on prend la première valeur."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _fmt_date(value) -> Optional[str]:
    dt = _first(value)
    if isinstance(dt, datetime):
        return dt.strftime("%d/%m/%Y")
    return str(dt) if dt else None


def check_whois(target: str) -> WhoisResult:
    domain = _extract_domain(target)
    result = WhoisResult(target=domain)

    try:
        data = whois.whois(domain)
    except Exception as e:
        result.error = f"Requête WHOIS impossible : {e.__class__.__name__}"
        return result

    # Un domaine inexistant renvoie des champs vides
    if not data or not data.get("domain_name"):
        result.error = "Aucune information WHOIS disponible pour ce domaine."
        return result

    result.found     = True
    result.registrar = _first(data.get("registrar"))
    result.owner     = _first(data.get("org")) or _first(data.get("name"))
    result.country   = _first(data.get("country"))
    result.created   = _fmt_date(data.get("creation_date"))
    result.expires   = _fmt_date(data.get("expiration_date"))

    ns = data.get("name_servers") or []
    if isinstance(ns, str):
        ns = [ns]
    result.name_servers = sorted({str(n).lower().rstrip(".") for n in ns if n})

    exp = _first(data.get("expiration_date"))
    if isinstance(exp, datetime):
        # Certains registrars renvoient une date avec fuseau — on normalise en naïf
        if exp.tzinfo is not None:
            exp = exp.replace(tzinfo=None)
        result.days_until_expiry = (exp - datetime.now()).days

    result.issues = _detect_issues(result)
    return result


def _detect_issues(r: WhoisResult) -> list[dict]:
    issues = []
    d = r.days_until_expiry

    if d is not None:
        if d < 0:
            issues.append({
                "severity": "CRITIQUE",
                "color":    "red",
                "title":    "Domaine expiré",
                "desc":     f"Le domaine a expiré il y a {abs(d)} jours. Il peut être racheté par un "
                            "tiers, qui prendrait le contrôle du site et des emails. Renouvelez-le "
                            "immédiatement.",
                "tool":     "check_whois()",
            })
        elif d <= 30:
            issues.append({
                "severity": "HAUT",
                "color":    "orange",
                "title":    f"Domaine expire dans {d} jours",
                "desc":     "Renouvelez le domaine sans tarder pour éviter une interruption de service "
                            "et un risque de détournement.",
                "tool":     "check_whois()",
            })

    return issues

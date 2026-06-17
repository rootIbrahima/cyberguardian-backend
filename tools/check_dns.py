"""
Outil #1 du CDC — check_dns()
Vérifie la posture DNS d'un domaine : SPF, DMARC, DKIM, MX et DNSSEC.
Pèse 25 pts dans le score global (critère le plus lourd : SPF + DMARC
protègent directement contre l'usurpation d'email, DNSSEC contre
l'empoisonnement de cache DNS).
"""

from dataclasses import dataclass, field
from typing import Optional

import dns.resolver

# Sélecteurs DKIM les plus répandus (Google Workspace, Microsoft 365, défauts)
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]

_TIMEOUT = 5


@dataclass
class DNSResult:
    target: str
    resolvable: bool = False
    mx_records: list[str] = field(default_factory=list)
    spf_present: bool = False
    spf_record: Optional[str] = None
    dmarc_present: bool = False
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None      # none | quarantine | reject
    dkim_present: bool = False
    dkim_selector: Optional[str] = None
    dnssec_enabled: bool = False
    score: int = 0                          # 0-25 pts (poids DNS dans le score global)
    issues: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def _extract_domain(target: str) -> str:
    target = target.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0].split(":")[0]


def _query_txt(name: str, resolver: dns.resolver.Resolver) -> list[str]:
    try:
        answers = resolver.resolve(name, "TXT")
        return ["".join(s.decode() for s in r.strings) for r in answers]
    except Exception:
        return []


def check_dns(target: str) -> DNSResult:
    domain = _extract_domain(target)
    result = DNSResult(target=domain)

    resolver = dns.resolver.Resolver()
    resolver.timeout = _TIMEOUT
    resolver.lifetime = _TIMEOUT

    # Le domaine existe-t-il ?
    try:
        try:
            resolver.resolve(domain, "A")
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            resolver.resolve(domain, "AAAA")
        result.resolvable = True
    except Exception as e:
        result.error = f"Domaine non résolvable : {e.__class__.__name__}"
        result.issues.append({
            "severity": "CRITIQUE",
            "color":    "red",
            "title":    "Domaine non résolvable",
            "desc":     "Aucun enregistrement A/AAAA trouvé. Le domaine n'existe pas ou le DNS est mal configuré.",
            "tool":     "check_dns()",
        })
        return result

    # MX
    try:
        answers = resolver.resolve(domain, "MX")
        result.mx_records = sorted(str(r.exchange).rstrip(".") for r in answers)
    except Exception:
        pass

    # SPF — enregistrement TXT commençant par v=spf1
    for txt in _query_txt(domain, resolver):
        if txt.lower().startswith("v=spf1"):
            result.spf_present = True
            result.spf_record = txt
            break

    # DMARC — TXT sur _dmarc.<domaine>
    for txt in _query_txt(f"_dmarc.{domain}", resolver):
        if txt.lower().startswith("v=dmarc1"):
            result.dmarc_present = True
            result.dmarc_record = txt
            for part in txt.replace(" ", "").split(";"):
                if part.lower().startswith("p="):
                    result.dmarc_policy = part[2:].lower()
            break

    # DKIM — TXT sur <selecteur>._domainkey.<domaine>, sélecteurs courants
    for selector in DKIM_SELECTORS:
        for txt in _query_txt(f"{selector}._domainkey.{domain}", resolver):
            if "v=dkim1" in txt.lower() or "k=rsa" in txt.lower():
                result.dkim_present = True
                result.dkim_selector = selector
                break
        if result.dkim_present:
            break

    # DNSSEC — présence d'enregistrements DNSKEY (zone signée)
    try:
        answers = resolver.resolve(domain, "DNSKEY")
        result.dnssec_enabled = len(answers) > 0
    except Exception:
        result.dnssec_enabled = False

    result.issues.extend(_detect_issues(result))
    result.score = _calculate_score(result)
    return result


def _detect_issues(r: DNSResult) -> list[dict]:
    issues = []

    if not r.spf_present:
        issues.append({
            "severity": "HAUT",
            "color":    "orange",
            "title":    "Enregistrement SPF absent",
            "desc":     f"N'importe quel serveur peut envoyer des emails au nom de @{r.target}. "
                        "Ajoutez un enregistrement TXT « v=spf1 ... » dans votre zone DNS.",
            "tool":     "check_dns()",
        })

    if not r.dmarc_present:
        issues.append({
            "severity": "HAUT",
            "color":    "orange",
            "title":    "Enregistrement DMARC absent",
            "desc":     f"Sans DMARC, rien n'indique aux destinataires comment traiter un email usurpant @{r.target}. "
                        "Ajoutez un TXT « v=DMARC1; p=quarantine; » sur _dmarc." + r.target + ".",
            "tool":     "check_dns()",
        })
    elif r.dmarc_policy == "none":
        issues.append({
            "severity": "MOYEN",
            "color":    "yellow",
            "title":    "Politique DMARC permissive (p=none)",
            "desc":     "DMARC est présent mais en mode surveillance uniquement : les emails usurpés sont quand même livrés. "
                        "Passez à p=quarantine puis p=reject.",
            "tool":     "check_dns()",
        })

    if not r.dkim_present:
        issues.append({
            "severity": "MOYEN",
            "color":    "yellow",
            "title":    "DKIM non détecté (sélecteurs courants)",
            "desc":     "Aucune clé DKIM trouvée sur les sélecteurs usuels (default, google, selector1...). "
                        "Si DKIM est configuré avec un sélecteur personnalisé, ce résultat peut être un faux négatif.",
            "tool":     "check_dns()",
        })

    if not r.dnssec_enabled:
        issues.append({
            "severity": "BAS",
            "color":    "blue",
            "title":    "DNSSEC non activé",
            "desc":     "Sans DNSSEC, les réponses DNS ne sont pas signées et restent exposées à "
                        "l'empoisonnement de cache (redirection furtive des visiteurs). Activez la "
                        "signature DNSSEC chez votre hébergeur DNS.",
            "tool":     "check_dns()",
        })

    if not r.mx_records and (r.spf_present or r.dmarc_present):
        issues.append({
            "severity": "INFO",
            "color":    "blue",
            "title":    "Aucun enregistrement MX",
            "desc":     "Ce domaine ne reçoit pas d'emails. SPF/DMARC restent utiles pour empêcher l'usurpation en émission.",
            "tool":     "check_dns()",
        })

    return issues


def _calculate_score(r: DNSResult) -> int:
    """Score /25 pts : SPF 9, DMARC 9 (5 si p=none), DKIM 4, DNSSEC 3."""
    if not r.resolvable:
        return 0

    score = 0
    if r.spf_present:
        score += 9
    if r.dmarc_present:
        score += 9 if r.dmarc_policy in ("quarantine", "reject") else 5
    if r.dkim_present:
        score += 4
    if r.dnssec_enabled:
        score += 3

    return min(score, 25)

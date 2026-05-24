import ssl
import socket
import datetime
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SSLResult:
    target: str
    reachable: bool
    valid: bool
    expired: bool
    self_signed: bool
    days_until_expiry: Optional[int]
    expiry_date: Optional[str]
    issued_to: Optional[str]
    issued_by: Optional[str]
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    sans: list[str] = field(default_factory=list)
    grade: str = "F"
    score: int = 0          # 0-25 pts (poids SSL dans le score global)
    issues: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def check_ssl(target: str, port: int = 443, timeout: int = 10) -> SSLResult:
    """
    Vérifie le certificat SSL/TLS d'un domaine.
    Retourne un SSLResult avec tous les détails + score /25 pts.
    """
    hostname = _extract_hostname(target)

    result = SSLResult(
        target=hostname,
        reachable=False,
        valid=False,
        expired=False,
        self_signed=False,
        days_until_expiry=None,
        expiry_date=None,
        issued_to=None,
        issued_by=None,
        tls_version=None,
        cipher_suite=None,
    )

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result.reachable = True
                result.tls_version = ssock.version()
                cipher = ssock.cipher()
                result.cipher_suite = cipher[0] if cipher else None

                cert = ssock.getpeercert()
                result.valid = True
                result.issued_to = _get_cn(cert.get("subject", ()))
                result.issued_by = _get_cn(cert.get("issuer", ()))
                result.self_signed = result.issued_to == result.issued_by
                result.sans = _get_sans(cert)

                not_after = cert.get("notAfter")
                if not_after:
                    expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    result.expiry_date = expiry_dt.strftime("%d/%m/%Y")
                    result.days_until_expiry = (expiry_dt - datetime.datetime.utcnow()).days
                    result.expired = result.days_until_expiry < 0

    except ssl.SSLCertVerificationError as e:
        result.reachable = True
        result.valid = False
        result.error = f"Certificat invalide : {e.reason}"
    except ssl.SSLError as e:
        result.reachable = True
        result.error = f"Erreur SSL : {str(e)}"
    except (socket.timeout, ConnectionRefusedError):
        result.error = f"Port {port} inaccessible ou timeout"
    except Exception as e:
        result.error = str(e)

    result.issues = _detect_issues(result)
    result.score, result.grade = _calculate_score(result)
    return result


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _extract_hostname(target: str) -> str:
    target = target.strip()
    for prefix in ("https://", "http://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    return target.split("/")[0].split(":")[0]


def _get_cn(rdns_tuples) -> Optional[str]:
    for rdn in rdns_tuples:
        for key, val in rdn:
            if key == "commonName":
                return val
    return None


def _get_sans(cert: dict) -> list[str]:
    sans = []
    for type_, value in cert.get("subjectAltName", ()):
        if type_ == "DNS":
            sans.append(value)
    return sans


def _detect_issues(r: SSLResult) -> list[dict]:
    issues = []

    if not r.reachable:
        issues.append({
            "severity": "CRITIQUE",
            "color": "red",
            "title": "Port 443 inaccessible",
            "desc": "Aucune connexion SSL/TLS possible. HTTPS non activé ou port filtré.",
            "tool": "check_ssl()",
        })
        return issues

    if not r.valid:
        issues.append({
            "severity": "CRITIQUE",
            "color": "red",
            "title": "Certificat SSL invalide",
            "desc": r.error or "Le certificat ne peut pas être vérifié.",
            "tool": "check_ssl()",
        })

    if r.expired:
        issues.append({
            "severity": "CRITIQUE",
            "color": "red",
            "title": "Certificat SSL expiré",
            "desc": f"Le certificat a expiré il y a {abs(r.days_until_expiry)} jours. Les navigateurs bloquent l'accès.",
            "tool": "check_ssl()",
        })
    elif r.days_until_expiry is not None and r.days_until_expiry <= 30:
        issues.append({
            "severity": "HAUT",
            "color": "orange",
            "title": f"Certificat expire dans {r.days_until_expiry} jours",
            "desc": "Renouvelez le certificat avant expiration pour éviter une interruption de service.",
            "tool": "check_ssl()",
        })

    if r.self_signed:
        issues.append({
            "severity": "HAUT",
            "color": "orange",
            "title": "Certificat auto-signé",
            "desc": "Un certificat auto-signé n'est pas approuvé par les navigateurs. Utilisez Let's Encrypt ou une CA reconnue.",
            "tool": "check_ssl()",
        })

    if r.tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
        issues.append({
            "severity": "HAUT",
            "color": "orange",
            "title": f"Version TLS obsolète ({r.tls_version})",
            "desc": "TLS 1.0 et 1.1 sont dépréciés et vulnérables. Activez uniquement TLS 1.2 et TLS 1.3.",
            "tool": "check_ssl()",
        })

    return issues


def _calculate_score(r: SSLResult) -> tuple[int, str]:
    """Score /25 pts selon les critères SSL."""
    if not r.reachable:
        return 0, "F"

    score = 25

    if not r.valid:
        score -= 15
    if r.expired:
        score -= 10
    elif r.days_until_expiry is not None and r.days_until_expiry <= 30:
        score -= 5
    if r.self_signed:
        score -= 8
    if r.tls_version in ("TLSv1", "TLSv1.1"):
        score -= 7
    elif r.tls_version in ("SSLv2", "SSLv3"):
        score -= 10

    score = max(0, score)

    if score >= 23:   grade = "A+"
    elif score >= 20: grade = "A"
    elif score >= 16: grade = "B"
    elif score >= 10: grade = "C"
    else:             grade = "F"

    return score, grade

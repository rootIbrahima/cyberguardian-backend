"""
CyberGuardian — Serveur MCP (FastMCP)

Expose les outils de scan EASM + GitHub au protocole MCP pour qu'un LLM
(Ollama, Claude Desktop, MCP Inspector...) puisse les orchestrer lui-même.

Lancement (transport STDIO, depuis le dossier backend/) :
    python mcp_server.py

Test interactif avec MCP Inspector :
    npx @modelcontextprotocol/inspector python mcp_server.py

Outils du cahier des charges restant à ajouter ici au fur et à mesure :
check_whois, scan_ports, scan_virustotal, scan_abuseipdb, generate_report.
"""

from dataclasses import asdict

from fastmcp import FastMCP

from tools.check_dns import check_dns as _check_dns
from tools.check_whois import check_whois as _check_whois
from tools.check_ssl import check_ssl as _check_ssl
from tools.check_cve import check_tls_cves as _check_tls_cves
from tools.check_cve import check_service_cves as _check_service_cves
from tools.scan_headers import scan_headers as _scan_headers
from tools.calculate_score import calculate_score as _calculate_score
from tools.check_epss import fetch_epss as _fetch_epss
from tools.check_epss import combined_priority as _combined_priority
from tools.check_epss import enrich_cves as _enrich_cves
from tools.github_tools import github_info as _github_info
from tools.github_tools import scan_github as _scan_github

mcp = FastMCP(
    "CyberGuardian",
    instructions=(
        "Outils d'évaluation de la surface d'attaque externe (EASM) et de scan "
        "de repositories GitHub publics. Strictement non intrusifs et read-only. "
        "Pour une analyse complète d'un domaine/IP/URL, utiliser analyze_security. "
        "Pour un repository GitHub public, utiliser scan_github_repo."
    ),
)


# ── Outil 1 (CDC) — DNS anti-phishing ─────────────────────────────────────────

@mcp.tool
def check_dns_records(domain: str) -> dict:
    """Vérifie la posture DNS d'un domaine : enregistrement SPF, politique DMARC
    (none/quarantine/reject), clés DKIM (sélecteurs courants), serveurs MX et
    activation de DNSSEC. Sans SPF ni DMARC, n'importe qui peut envoyer des
    emails en usurpant le domaine ; sans DNSSEC, les réponses DNS ne sont pas
    signées. Score sur 25 points."""
    return asdict(_check_dns(domain))


# ── Outil 2 (CDC) — WHOIS ─────────────────────────────────────────────────────

@mcp.tool
def check_domain_whois(domain: str) -> dict:
    """Interroge la base WHOIS d'un domaine : registrar, propriétaire, pays,
    dates de création et d'expiration, serveurs de noms. Signale un domaine
    expiré ou proche de l'expiration, ce qui expose à un détournement. Note :
    certaines extensions nationales (.sn par exemple) ne sont pas couvertes
    par les serveurs WHOIS publics."""
    return asdict(_check_whois(domain))


# ── Outil 5 (CDC) — En-têtes de sécurité HTTP ─────────────────────────────────

@mcp.tool
def scan_http_headers(target: str) -> dict:
    """Analyse les en-têtes de sécurité HTTP d'un site web : HSTS, CSP,
    X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
    Permissions-Policy. Ces en-têtes protègent contre le XSS, le clickjacking
    et le SSL stripping. Score sur 20 points avec recommandations pour chaque
    en-tête manquant."""
    return asdict(_scan_headers(target))


# ── Outil 10 (CDC) — Score global pondéré ─────────────────────────────────────

@mcp.tool
def calculate_global_score(dns_score: int | None = None,
                           ssl_score: int | None = None,
                           headers_score: int | None = None) -> dict:
    """Calcule le score de sécurité global /100 pondéré selon la méthodologie
    CyberGuardian : DNS 25 pts, SSL/TLS 25 pts, En-têtes HTTP 20 pts (ports et
    réputation à venir). Passer les scores obtenus par les outils check_dns_records,
    check_ssl_certificate et scan_http_headers ; les critères non évalués sont
    exclus et le score est normalisé sur le reste."""
    return _calculate_score({"dns": dns_score, "ssl": ssl_score, "headers": headers_score})


# ── Outil 3 (CDC) — SSL/TLS ───────────────────────────────────────────────────

@mcp.tool
def check_ssl_certificate(target: str) -> dict:
    """Vérifie le certificat SSL/TLS d'un domaine, d'une IP ou d'une URL :
    validité, expiration, auto-signature, version TLS, suite de chiffrement,
    SANs. Retourne aussi une note (A+ à F), un score sur 25 points et la liste
    des problèmes détectés avec leur sévérité."""
    return asdict(_check_ssl(target))


# ── CVE — configuration TLS et service exposé ────────────────────────────────

@mcp.tool
def check_tls_cves(tls_version: str, cipher_suite: str) -> list:
    """Liste les CVE connues associées à une version TLS obsolète (TLSv1,
    TLSv1.1) ou à une suite de chiffrement faible (RC4, DES, NULL) : POODLE,
    BEAST, FREAK, SWEET32... Utiliser les valeurs tls_version et cipher_suite
    retournées par check_ssl_certificate."""
    return _check_tls_cves(tls_version, cipher_suite)


@mcp.tool
def check_service_cves(target: str) -> dict:
    """Identifie le serveur web exposé via sa bannière HTTP (en-tête Server)
    puis recherche les CVE connues pour ce logiciel et cette version dans la
    base NVD (NIST). Retourne la bannière détectée et la liste des CVE."""
    banner, cves = _check_service_cves(target)
    return {"server_banner": banner, "cves": cves}


# ── EPSS — corrélation gravité (CVSS) × probabilité d'exploitation ────────────

@mcp.tool
def correlate_cvss_epss(cve_ids: list[str], cvss_scores: list[float] | None = None) -> dict:
    """Croise la gravité (CVSS) et la probabilité d'exploitation à 30 jours
    (EPSS, source FIRST.org) pour prioriser les vulnérabilités selon le risque
    réel. Pour chaque CVE : score EPSS, percentile, et priorité combinée
    (URGENTE = grave ET probable ; ÉLEVÉE = grave ; À SURVEILLER = exploitée
    même si moins grave ; FAIBLE). Passer la liste des identifiants CVE et,
    optionnellement, leurs scores CVSS dans le même ordre."""
    epss_map = _fetch_epss(cve_ids)
    cvss_scores = cvss_scores or []
    results = []
    for i, cve in enumerate(cve_ids):
        info = epss_map.get(cve)
        epss = info["epss"] if info else None
        cvss = cvss_scores[i] if i < len(cvss_scores) else 0.0
        results.append({
            "cve":             cve,
            "cvss":            cvss,
            "epss":            epss,
            "epss_percentile": info["percentile"] if info else None,
            "priority":        _combined_priority(cvss, epss),
        })
    return {"results": results}


# ── Outil 4 (CDC) — Orchestration EASM complète ──────────────────────────────

@mcp.tool
def analyze_security(target: str) -> dict:
    """Analyse de sécurité EASM complète d'un domaine, d'une IP ou d'une URL :
    DNS anti-phishing (SPF/DMARC/DKIM), certificat SSL/TLS, en-têtes de
    sécurité HTTP, CVE liées à la configuration TLS et au serveur exposé.
    Retourne tous les résultats agrégés, le score global /100 pondéré et la
    liste consolidée des problèmes. À privilégier quand l'utilisateur demande
    une analyse ou un audit complet d'une cible."""
    import ipaddress

    ssl_result = _check_ssl(target)
    headers_result = _scan_headers(target)
    tls_cves = _check_tls_cves(ssl_result.tls_version or "", ssl_result.cipher_suite or "")
    banner, svc_cves = _check_service_cves(target)
    cves = _enrich_cves(tls_cves + svc_cves, id_key="id")   # gravité + probabilité EPSS

    issues = list(ssl_result.issues) + list(headers_result.issues)
    parts = {"ssl": ssl_result.score, "headers": headers_result.score}
    dns_dict = None
    whois_dict = None

    # DNS et WHOIS n'ont de sens que pour un domaine, pas une IP brute
    host = ssl_result.target
    try:
        ipaddress.ip_address(host)
    except ValueError:
        dns_result = _check_dns(host)
        dns_dict = asdict(dns_result)
        issues += dns_result.issues
        parts["dns"] = dns_result.score

        whois_result = _check_whois(host)
        whois_dict = asdict(whois_result)
        issues += whois_result.issues

    score_detail = _calculate_score(parts)
    return {
        "target":        target,
        "dns":           dns_dict,
        "whois":         whois_dict,
        "ssl":           asdict(ssl_result),
        "headers":       asdict(headers_result),
        "cves":          cves,
        "server_banner": banner,
        "score":         score_detail["score"],
        "score_detail":  score_detail,
        "issues":        issues,
    }


# ── Outil 12 (CDC) — Scan GitHub ──────────────────────────────────────────────

@mcp.tool
def get_github_info(repo_url: str) -> dict:
    """Récupère les métadonnées publiques d'un repository GitHub : description,
    langage principal, stars, forks, dernière mise à jour. Ne clone pas le
    repository — utile pour un aperçu rapide avant un scan complet."""
    return _github_info(repo_url)


@mcp.tool
def scan_github_repo(repo_url: str) -> dict:
    """Analyse de sécurité complète d'un repository GitHub PUBLIC : clone
    temporaire puis analyse statique du code (Bandit pour Python, npm audit
    pour JavaScript/TypeScript), vérification des dépendances contre les CVE
    connues (Safety) et détection de secrets exposés — clés API, tokens, mots
    de passe en dur (TruffleHog). Retourne les résultats détaillés par outil
    et un score bonus sur 30 points. Durée : 20 à 30 secondes."""
    return _scan_github(repo_url)


if __name__ == "__main__":
    mcp.run()

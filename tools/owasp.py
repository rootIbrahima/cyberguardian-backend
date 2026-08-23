"""
Rattachement des constats au Top 10 de l'OWASP.

Un intitulé technique — « en-tête HSTS absent » — parle à un ingénieur. La
catégorie OWASP parle à un auditeur, à un responsable conformité et à un jury :
elle rattache le constat à un référentiel public, ce qui permet de comparer
deux rapports produits par deux outils différents.

La table est centrale plutôt que dispersée dans chaque outil. Vingt-quatre
constats étaient à rattacher ; les annoter un par un aurait multiplié les
occasions de se tromper, et rendu la cohérence de l'ensemble invérifiable. Ici
elle se lit d'un seul regard.

Un constat sans correspondance ne reçoit pas de catégorie : mieux vaut un
champ absent qu'un rattachement approximatif, qu'un auditeur relèverait.
"""

A01 = "A01:2021 - Broken Access Control"
A02 = "A02:2021 - Cryptographic Failures"
A03 = "A03:2021 - Injection"
A05 = "A05:2021 - Security Misconfiguration"
A06 = "A06:2021 - Vulnerable and Outdated Components"
A07 = "A07:2021 - Identification and Authentication Failures"
A08 = "A08:2021 - Software and Data Integrity Failures"

# Catégorie par défaut de chaque outil, quand le titre ne précise rien de plus.
_PAR_OUTIL = {
    "check_ssl()":         A02,   # certificats, protocoles, chiffrement
    "scan_headers()":      A05,   # en-têtes de sécurité absents
    "check_ports()":       A05,   # services exposés sans nécessité
    "scan_ports()":        A05,
    "check_dns()":         A05,   # SPF, DMARC, DKIM, DNSSEC
    "check_whois()":       A05,
    "check_reputation()":  A08,   # actif signalé, intégrité compromise
    "scan_virustotal()":   A08,   # noms réellement émis par check_reputation
    "scan_abuseipdb()":    A08,
    "check_subdomains()":  A05,
    "scan_bandit()":       A03,   # analyse statique, majoritairement injection
    "scan_safety()":       A06,   # dépendances vulnérables
    "scan_trufflehog()":   A02,   # secrets en clair, cf. A02 « hard-coded passwords »
    "npm_audit()":         A06,
}

# Affinages par mot-clé du titre, prioritaires sur la table par outil. Ils ne
# servent que là où un même outil produit des constats de nature différente.
_PAR_MOTCLE = (
    ("dmarc",       A07),   # usurpation d'expéditeur
    ("spf",         A07),
    ("dkim",        A07),
    ("secret",      A02),
    ("mot de passe", A07),
    ("injection",   A03),
    ("cve",         A06),
    ("expir",       A02),
)


def categoriser(issue: dict) -> str | None:
    """Catégorie OWASP d'un constat, ou None si aucune ne s'impose."""
    titre = (issue.get("title") or "").lower()
    for motcle, categorie in _PAR_MOTCLE:
        if motcle in titre:
            return categorie
    return _PAR_OUTIL.get(issue.get("tool") or "")


def annoter(issues: list[dict]) -> list[dict]:
    """Ajoute la catégorie aux constats qui n'en portent pas déjà une.

    Les outils qui la renseignent eux-mêmes gardent la main : ils connaissent
    leur constat mieux que cette table ne peut le deviner."""
    for issue in issues:
        if not issue.get("owasp"):
            categorie = categoriser(issue)
            if categorie:
                issue["owasp"] = categorie
    return issues

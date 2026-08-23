"""
Découverte de sous-domaines par les journaux de transparence des certificats.

C'est ce qui distingue la gestion d'une surface d'attaque de la simple analyse
d'une adresse. Une organisation connaît son site principal ; ce qu'elle ignore,
ce sont les environnements de recette laissés en ligne, les outils internes
exposés par commodité, les hôtes créés pour une démonstration et jamais
retirés. N'analyser que le domaine qu'on nous donne revient à vérifier une
porte en ignorant le reste du bâtiment.

Aucun paquet n'est envoyé vers ces hôtes : la source est publique et
déclarative, tout certificat émis étant inscrit dans des journaux consultables.
La méthode est donc entièrement passive et ne révèle que ce que l'organisation
a elle-même rendu public en demandant un certificat.
"""

from dataclasses import dataclass, field
from typing import Optional

import httpx

_ENTETES = {"User-Agent": "CyberGuardian-EASM/1.0"}

# Préfixes qui trahissent un environnement hors production. Leur exposition
# n'est pas une faille en soi, mais ces hôtes portent souvent des données
# réelles avec des protections moindres : mot de passe par défaut, absence de
# limitation de débit, versions non corrigées.
_PREFIXES_SENSIBLES = {
    "dev":           "environnement de développement",
    "developpement": "environnement de développement",
    "test":          "environnement de test",
    "recette":       "environnement de recette",
    "staging":       "environnement de pré-production",
    "preprod":       "environnement de pré-production",
    "uat":           "environnement de validation",
    "demo":          "environnement de démonstration",
    "admin":         "interface d'administration",
    "adminer":       "administration de base de données",
    "phpmyadmin":    "administration de base de données",
    "backup":        "sauvegardes",
    "old":           "version obsolète conservée en ligne",
    "legacy":        "version obsolète conservée en ligne",
    "intern":        "service à usage interne",
    "interne":       "service à usage interne",
    "internal":      "service à usage interne",
    "vpn":           "accès distant",
    "git":           "gestion de code source",
    "gitlab":        "gestion de code source",
    "jenkins":       "intégration continue",
    "ci":            "intégration continue",
    "jira":          "gestion de projet",
    "grafana":       "supervision",
    "kibana":        "consultation de journaux",
    "monitoring":    "supervision",
    "db":            "base de données",
    "sql":           "base de données",
    "ftp":           "transfert de fichiers",
}


@dataclass
class SubdomainResult:
    target: str
    found: bool
    subdomains: list[str] = field(default_factory=list)
    sensibles: list[dict] = field(default_factory=list)
    total: int = 0
    source: str = ""
    issues: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def _domaine_racine(target: str) -> str:
    """Extrait le domaine d'une URL ou d'un nom d'hôte."""
    nom = target.strip().lower()
    for prefixe in ("https://", "http://"):
        if nom.startswith(prefixe):
            nom = nom[len(prefixe):]
    nom = nom.split("/")[0].split(":")[0].split("?")[0]
    return nom[4:] if nom.startswith("www.") else nom


def _certspotter(domaine: str, timeout: int) -> set[str]:
    r = httpx.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domaine, "include_subdomains": "true", "expand": "dns_names"},
        headers=_ENTETES, timeout=timeout,
    )
    r.raise_for_status()
    return {n for entree in r.json() for n in entree.get("dns_names", [])}


def _crtsh(domaine: str, timeout: int) -> set[str]:
    """Repli. Ce service tombe régulièrement, d'où sa place en second."""
    r = httpx.get("https://crt.sh/", params={"q": f"%.{domaine}", "output": "json"},
                  headers=_ENTETES, timeout=timeout)
    r.raise_for_status()
    noms = set()
    for entree in r.json():
        for nom in (entree.get("name_value") or "").split("\n"):
            noms.add(nom.strip())
    return noms


def _nettoyer(noms: set[str], domaine: str) -> list[str]:
    """Ne conserve que les hôtes réels du domaine analysé.

    Les journaux contiennent des noms génériques en *.exemple.sn, et parfois
    des suffixes répétés issus d'une saisie fautive lors de la demande de
    certificat : auth.exemple.sn.exemple.sn en est un cas rencontré."""
    retenus = set()
    for nom in noms:
        nom = nom.strip().lower().rstrip(".")
        if not nom or nom.startswith("*."):
            continue
        if nom != domaine and not nom.endswith("." + domaine):
            continue
        if nom.count("." + domaine) > 1:
            continue
        retenus.add(nom)
    return sorted(retenus)


def _reperer_sensibles(sousdomaines: list[str], domaine: str) -> list[dict]:
    sensibles = []
    for nom in sousdomaines:
        if nom == domaine:
            continue
        etiquettes = nom[: -(len(domaine) + 1)].split(".")
        for etiquette in etiquettes:
            motif = _PREFIXES_SENSIBLES.get(etiquette)
            if motif:
                sensibles.append({"hote": nom, "motif": motif})
                break
    return sensibles


def _construire_issues(r: "SubdomainResult") -> list[dict]:
    """L'étendue d'une surface n'est pas un défaut : seuls les hôtes qui
    trahissent un environnement hors production justifient un signalement."""
    if not r.sensibles:
        return []
    details = ", ".join(s["hote"] + " (" + s["motif"] + ")" for s in r.sensibles[:4])
    if len(r.sensibles) > 4:
        details += ", et " + str(len(r.sensibles) - 4) + " autre(s)"
    return [{
        "severity": "MOYEN",
        "color": "orange",
        "title": str(len(r.sensibles)) + " sous-domaine(s) hors production exposé(s)",
        "desc": details + ". Ces hôtes portent souvent des données réelles avec des "
                "protections moindres. Restreignez-y l'accès ou retirez-les.",
        "tool": "check_subdomains()",
        "owasp": "A05:2021 - Security Misconfiguration",
    }]


def check_subdomains(target: str, timeout: int = 20) -> SubdomainResult:
    """Recense les sous-domaines exposés d'un domaine, sans le solliciter."""
    domaine = _domaine_racine(target)
    resultat = SubdomainResult(target=domaine, found=False)

    noms, source = set(), ""
    for nom_source, fonction in (("certSpotter", _certspotter), ("crt.sh", _crtsh)):
        try:
            noms = fonction(domaine, timeout)
            source = nom_source
            break
        except Exception as e:
            resultat.error = nom_source + " : " + type(e).__name__

    if not noms:
        resultat.error = resultat.error or "Aucune source de transparence n'a répondu"
        return resultat

    resultat.subdomains = _nettoyer(noms, domaine)
    resultat.total      = len(resultat.subdomains)
    resultat.source     = source
    resultat.found      = resultat.total > 0
    resultat.error      = None
    resultat.sensibles  = _reperer_sensibles(resultat.subdomains, domaine)
    resultat.issues     = _construire_issues(resultat)
    return resultat

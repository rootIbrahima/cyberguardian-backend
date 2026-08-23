"""
Comparaison de deux scans d'une même cible.

Une plateforme de surveillance ne vaut pas par le scan qu'elle produit mais par
l'écart qu'elle détecte entre deux scans : un port qui s'ouvre, un certificat
qui approche de son terme, un secret qui apparaît dans un dépôt. Ce module
isole cette logique ; il n'a besoin ni de la base ni du réseau, deux
dictionnaires de résultats lui suffisent.

Règle qui gouverne tout le fichier : on alerte sur un changement, jamais sur un
état. Sans cela un certificat expirant dans trente jours produirait trente
alertes identiques et le destinataire finirait par couper ses notifications.
Un premier scan est traité comme un changement depuis rien : l'état observé y
est signalé intégralement, faute de point de comparaison.
"""

from dataclasses import dataclass

from tools.check_ssl import DUREE_COURTE

# En deçà de dix points sur cent, l'écart relève autant de la variation de
# mesure (délai réseau sur un port, moteur de réputation indisponible) que
# d'une dégradation réelle : alerter dessus reviendrait à alerter sur du bruit.
SEUIL_CHUTE_SCORE = 10

# Paliers d'expiration du certificat, du plus urgent au plus lointain. L'ordre
# compte : c'est le premier palier franchi qui donne sa gravité à l'alerte.
#
# Deux jeux, selon que le certificat est renouvelé à la main ou par un automate.
# Un certificat de quatre-vingt-dix jours passe sous les trente jours restants à
# chaque cycle sans que rien n'aille mal : lui appliquer le préavis long
# reviendrait à alerter tous les quatre-vingts jours sur la majorité du web.
PALIERS_SSL       = ((7, "critique"), (14, "haute"), (30, "moyenne"))
PALIERS_SSL_COURT = ((3, "critique"),)

# Les sévérités n'ont pas la même langue selon leur origine : check_ports les
# produit en français pour l'affichage, les CVE arrivent en anglais du NVD. Les
# deux formes sont acceptées, une correspondance manquante retombant sur
# « moyenne » plutôt que de faire disparaître l'alerte.
_GRAVITE_PORT = {"CRITIQUE": "critique", "CRITICAL": "critique",
                 "HAUT":     "haute",    "HIGH":     "haute",
                 "MOYEN":    "moyenne",  "MEDIUM":   "moyenne",
                 "BAS":      "moyenne",  "LOW":      "moyenne"}

_GRAVITE_CVE = {"CRITIQUE": "critique", "CRITICAL": "critique",
                "HAUT":     "haute",    "HIGH":     "haute"}

_RANG = {"critique": 0, "haute": 1, "moyenne": 2}


@dataclass
class Alerte:
    """Un écart digne d'être signalé au propriétaire de l'actif."""
    type:    str   # secret | score | port | cve | ssl | reputation
    gravite: str   # critique | haute | moyenne
    titre:   str
    detail:  str


# ── Lecture des résultats ─────────────────────────────────────────────────────

def _resultats(scan: dict | None) -> dict:
    return (scan or {}).get("results") or {}


def _ports_ouverts(scan: dict | None) -> dict[int, dict]:
    """Ports ouverts indexés par numéro. Les ports d'information (80, 443) sont
    écartés : leur ouverture est le fonctionnement normal d'un site web."""
    ports = (_resultats(scan).get("ports") or {}).get("open_ports") or []
    return {
        p["port"]: p for p in ports
        if p.get("port") is not None and (p.get("severity") or "").upper() != "INFO"
    }


def _secrets(scan: dict | None) -> dict[str, dict]:
    """Secrets exposés, indexés par emplacement : un même type de clé peut
    apparaître dans plusieurs fichiers, chacun est une fuite distincte."""
    trouves = (_resultats(scan).get("trufflehog") or {}).get("findings") or []
    return {f"{f.get('type')}|{f.get('file')}|{f.get('line')}": f for f in trouves}


def _cves_graves(scan: dict | None) -> dict[str, dict]:
    """CVE critiques et hautes, indexées par identifiant. Les moyennes et
    basses sont visibles dans le rapport mais ne justifient pas de réveiller
    quelqu'un."""
    return {
        c["id"]: c for c in (_resultats(scan).get("cves") or [])
        if c.get("id") and (c.get("severity") or "").upper() in _GRAVITE_CVE
    }


def _jours_ssl(scan: dict | None) -> int | None:
    return (_resultats(scan).get("ssl") or {}).get("days_until_expiry")


def _paliers_ssl(scan: dict) -> tuple:
    """Paliers applicables, selon la durée de vie du certificat observé.

    Les scans antérieurs à l'enregistrement de cette durée conservent le préavis
    long : mieux vaut une alerte de trop qu'un certificat expiré en silence."""
    duree = (_resultats(scan).get("ssl") or {}).get("duree_validite")
    return PALIERS_SSL_COURT if duree and duree <= DUREE_COURTE else PALIERS_SSL


def _reputation_signalee(scan: dict | None) -> str:
    """Motif de signalement de l'actif, chaîne vide s'il est vu comme sain."""
    rep = _resultats(scan).get("reputation") or {}
    if rep.get("vt_disponible") and (rep.get("vt_malveillant") or 0) > 0:
        return (f"{rep['vt_malveillant']} moteur(s) VirusTotal sur "
                f"{rep.get('vt_total_moteurs', '?')} le classent malveillant")
    if rep.get("abuse_disponible") and (rep.get("abuse_score") or 0) >= 25:
        return (f"AbuseIPDB attribue un indice d'abus de {rep['abuse_score']}/100 "
                f"({rep.get('abuse_signalements', 0)} signalements)")
    return ""


def _bareme(scan: dict) -> int:
    """Note maximale du scan : 100 pour un actif réseau, 30 pour un dépôt
    GitHub. Sans cette normalisation, une chute de dix points n'aurait pas le
    même sens d'un type d'actif à l'autre."""
    return _resultats(scan).get("score_max") or 100


# ── Détections ────────────────────────────────────────────────────────────────

def _alerte_score(precedent: dict | None, courant: dict) -> list[Alerte]:
    """Chute du score global. Demande deux scans : la note d'un premier scan
    n'est pas une dégradation, c'est un point de départ."""
    if not precedent:
        return []
    avant, apres = precedent.get("score"), courant.get("score")
    if avant is None or apres is None or apres >= avant:
        return []

    bareme = _bareme(courant)
    chute  = (avant - apres) * 100 / bareme
    if chute < SEUIL_CHUTE_SCORE:
        return []

    gravite = "critique" if chute >= 25 else "haute" if chute >= 15 else "moyenne"
    return [Alerte(
        type    = "score",
        gravite = gravite,
        titre   = f"Score en baisse : {avant} → {apres} sur {bareme}",
        detail  = "La posture de sécurité de cet actif s'est dégradée depuis "
                  "le scan précédent.",
    )]


def _alertes_secrets(precedent: dict | None, courant: dict) -> list[Alerte]:
    """Secrets nouvellement exposés dans le dépôt. Priorité absolue : une clé
    publiée reste compromise même après suppression du fichier, l'historique
    Git la conserve. La seule réponse est la révocation."""
    avant    = _secrets(precedent)
    nouveaux = [f for cle, f in _secrets(courant).items() if cle not in avant]
    if not nouveaux:
        return []

    emplacements = ", ".join(
        f"{f.get('type')} dans {f.get('file')}:{f.get('line')}" for f in nouveaux[:3]
    )
    if len(nouveaux) > 3:
        emplacements += f", et {len(nouveaux) - 3} autre(s)"

    return [Alerte(
        type    = "secret",
        gravite = "critique",
        titre   = f"{len(nouveaux)} secret(s) exposé(s) dans le dépôt",
        detail  = f"{emplacements}. Révoquez ces identifiants immédiatement : "
                  "les retirer du code ne suffit pas, l'historique les conserve.",
    )]


def _alertes_ports(precedent: dict | None, courant: dict) -> list[Alerte]:
    """Ports sensibles nouvellement ouverts, regroupés en une seule alerte."""
    avant    = _ports_ouverts(precedent)
    nouveaux = [p for num, p in _ports_ouverts(courant).items() if num not in avant]
    if not nouveaux:
        return []

    pire = min(
        (_GRAVITE_PORT.get((p.get("severity") or "").upper(), "moyenne") for p in nouveaux),
        key=lambda g: _RANG[g],
    )
    liste = ", ".join(f"{p['port']} ({p.get('service') or 'inconnu'})" for p in nouveaux)
    return [Alerte(
        type    = "port",
        gravite = pire,
        titre   = f"{len(nouveaux)} port(s) sensible(s) ouvert(s) : {liste}",
        detail  = "Un service exposé à internet est une porte d'entrée directe. "
                  "Vérifiez qu'il doit l'être et restreignez l'accès par pare-feu "
                  "si ce n'est pas le cas.",
    )]


def _alertes_cves(precedent: dict | None, courant: dict) -> list[Alerte]:
    """CVE critiques ou hautes apparues depuis le scan précédent, soit parce
    qu'un service a changé de version, soit parce que la vulnérabilité vient
    d'être publiée."""
    avant    = _cves_graves(precedent)
    nouvelles = [c for cle, c in _cves_graves(courant).items() if cle not in avant]
    if not nouvelles:
        return []

    pire = min(
        (_GRAVITE_CVE[(c.get("severity") or "").upper()] for c in nouvelles),
        key=lambda g: _RANG[g],
    )
    liste = ", ".join(
        f"{c['id']} (CVSS {c.get('cvss', '?')})" for c in nouvelles[:4]
    )
    if len(nouvelles) > 4:
        liste += f", et {len(nouvelles) - 4} autre(s)"

    return [Alerte(
        type    = "cve",
        gravite = pire,
        titre   = f"{len(nouvelles)} vulnérabilité(s) grave(s) détectée(s)",
        detail  = f"{liste}. Consultez le rapport pour les correctifs applicables.",
    )]


def _alertes_ssl(precedent: dict | None, courant: dict) -> list[Alerte]:
    """Expiration du certificat. Le franchissement d'un palier déclenche une
    alerte et une seule : c'est ce qui distingue un rappel utile d'un rappel
    quotidien que l'on finit par ignorer."""
    jours = _jours_ssl(courant)
    if jours is None:
        return []
    avant = _jours_ssl(precedent) if precedent else None

    if jours < 0:
        # Déjà signalé au scan précédent si le certificat était expiré alors
        if avant is not None and avant < 0:
            return []
        return [Alerte(
            type    = "ssl",
            gravite = "critique",
            titre   = f"Certificat expiré depuis {abs(jours)} jour(s)",
            detail  = "Les navigateurs affichent un avertissement de sécurité à "
                      "vos visiteurs. Renouvelez le certificat sans attendre.",
        )]

    for palier, gravite in _paliers_ssl(courant):
        if jours <= palier and (avant is None or avant > palier):
            return [Alerte(
                type    = "ssl",
                gravite = gravite,
                titre   = f"Certificat expirant dans {jours} jour(s)",
                detail  = "Programmez le renouvellement. Avec Let's Encrypt, "
                          "vérifiez que le renouvellement automatique fonctionne.",
            )]
    return []


def _alertes_reputation(precedent: dict | None, courant: dict) -> list[Alerte]:
    """Signalement de l'actif par un service de réputation. Ne se déclenche
    qu'à la bascule : un actif signalé le reste souvent plusieurs semaines."""
    motif = _reputation_signalee(courant)
    if not motif or (precedent and _reputation_signalee(precedent)):
        return []
    return [Alerte(
        type    = "reputation",
        gravite = "haute",
        titre   = "Actif signalé par un service de réputation",
        detail  = f"{motif}. Un signalement traduit un historique de "
                  "compromission ou d'envoi abusif, pas un défaut de "
                  "configuration : la correction passe par une demande de "
                  "retrait après nettoyage.",
    )]


# ── Interface publique ────────────────────────────────────────────────────────

def comparer(precedent: dict | None, courant: dict) -> list[Alerte]:
    """Écarts significatifs entre deux scans d'une même cible, du plus grave au
    moins grave. « precedent » vaut None au premier scan de la cible : l'état
    observé est alors signalé tel quel."""
    alertes = (
        _alertes_secrets(precedent, courant)
        + _alertes_ssl(precedent, courant)
        + _alertes_cves(precedent, courant)
        + _alertes_ports(precedent, courant)
        + _alertes_reputation(precedent, courant)
        + _alerte_score(precedent, courant)
    )
    return sorted(alertes, key=lambda a: _RANG[a.gravite])


def resumer(cible: str, alertes: list[Alerte]) -> tuple[str, str]:
    """Compose le titre et le corps d'une notification unique.

    Un message par écart transformerait un scan en rafale de six notifications,
    ce qui pousse à toutes les ignorer. Le titre porte la gravité maximale, le
    corps énumère le reste."""
    if not alertes:
        return "", ""

    entete = {
        "critique": f"Alerte critique : {cible}",
        "haute":    f"Alerte sécurité : {cible}",
        "moyenne":  f"Évolution détectée : {cible}",
    }[alertes[0].gravite]

    corps = "\n".join(f"• {a.titre}\n  {a.detail}" for a in alertes)
    return entete, corps

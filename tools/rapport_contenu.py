"""
Contenu métier du rapport : traduction des constats techniques en langage
compréhensible par un dirigeant, estimation de l'effort de correction et
classement par horizon de traitement.

Séparé de la mise en page (generate_pdf.py) parce que ce sont deux métiers
distincts : ici on décide *quoi* dire et avec quelle priorité, là-bas *comment*
l'afficher. Tout est déterministe et dérivé des résultats du scan — aucune
donnée inventée, aucun appel réseau.
"""

# Sévérités normalisées : les outils EASM renvoient du français, les outils
# GitHub de l'anglais.
_NORMALISATION = {
    "CRITICAL": "CRITIQUE", "CRITIQUE": "CRITIQUE",
    "HIGH": "HAUT",         "HAUT": "HAUT",
    "MEDIUM": "MOYEN",      "MOYEN": "MOYEN",  "MODERATE": "MOYEN",
    "LOW": "BAS",           "BAS": "BAS",
    "INFO": "INFO",
}

ORDRE_SEVERITE = ["CRITIQUE", "HAUT", "MOYEN", "BAS", "INFO"]


def normaliser_severite(valeur: str | None) -> str:
    return _NORMALISATION.get((valeur or "").upper(), "BAS")


# Traduction d'un constat technique en conséquence concrète pour l'entreprise.
# Chaque entrée : (mots-clés du titre, impact métier, effort estimé, horizon).
_REGLES = [
    (("dmarc",),
     "N'importe qui peut envoyer un email en se faisant passer pour votre entreprise. "
     "C'est le vecteur principal des arnaques au faux virement visant vos clients.",
     "15 minutes", "immediat"),
    (("spf",),
     "Vos emails peuvent être usurpés et vos messages légitimes finir en indésirables, "
     "ce qui dégrade votre communication commerciale.",
     "15 minutes", "immediat"),
    (("dkim",),
     "Vos emails ne sont pas signés : les destinataires ne peuvent pas vérifier qu'ils "
     "viennent réellement de vous.",
     "30 minutes", "court_terme"),
    (("dnssec",),
     "Vos visiteurs peuvent être redirigés à leur insu vers un site frauduleux imitant "
     "le vôtre, sans qu'aucun signe ne les alerte.",
     "1 heure", "court_terme"),
    (("certificat", "ssl", "tls"),
     "Les navigateurs affichent un avertissement de sécurité, voire bloquent l'accès. "
     "Perte immédiate de trafic et de confiance.",
     "1 heure", "immediat"),
    (("hsts", "strict-transport"),
     "Sur un réseau non maîtrisé (wifi public), un attaquant peut forcer une connexion "
     "non chiffrée et intercepter les données échangées.",
     "30 minutes", "court_terme"),
    (("csp", "content-security"),
     "Un script malveillant injecté dans une page s'exécute sans obstacle, ce qui permet "
     "le vol de sessions utilisateur.",
     "1 journée", "fond"),
    (("x-frame", "clickjacking"),
     "Votre site peut être encadré dans une page pirate pour piéger vos utilisateurs "
     "en leur faisant cliquer à leur insu.",
     "15 minutes", "court_terme"),
    (("x-content-type", "referrer", "permissions-policy"),
     "Renforcement du navigateur incomplet : durcissement recommandé, sans exploitation "
     "directe connue.",
     "15 minutes", "fond"),
    (("http uniquement", "accessible uniquement en http"),
     "Tout le trafic circule en clair : identifiants et données de vos clients sont "
     "lisibles par un intermédiaire réseau.",
     "2 heures", "immediat"),
    (("secret", "mot de passe", "token", "clé"),
     "Une clé d'accès est publiquement lisible dans votre code. Un tiers peut s'en servir "
     "pour accéder directement à vos systèmes.",
     "Immédiat", "immediat"),
    # « ouvert » est déterminant : un port fermé ou filtré n'est pas une exposition.
    (("ouvert",),
     "Un service est joignable depuis internet. S'il s'agit d'une base de données ou d'un "
     "accès d'administration, c'est une porte d'entrée directe vers vos systèmes.",
     "1 heure", "immediat"),
    (("443 inaccessible", "https non", "port 443"),
     "Le site n'est pas joignable en HTTPS. Les échanges avec vos visiteurs ne sont pas "
     "chiffrés et les navigateurs signalent le site comme non sécurisé.",
     "2 heures", "immediat"),
    (("domaine non résolvable", "expiré"),
     "Le nom de domaine peut être racheté par un tiers, qui prendrait alors le contrôle "
     "de votre site et de vos emails.",
     "Immédiat", "immediat"),
]

_DEFAUT = ("Écart de configuration relevé par rapport aux bonnes pratiques de sécurité.",
           "À évaluer", "fond")

# Horizon imposé par la gravité, quel que soit le type de constat
_HORIZON_PAR_SEVERITE = {"CRITIQUE": "immediat", "HAUT": "court_terme"}

LIBELLES_HORIZON = {
    "immediat":    "Immédiat — sous 24 à 48 heures",
    "court_terme": "Court terme — sous un mois",
    "fond":        "Travail de fond — prochain trimestre",
}


def analyser_constat(titre: str, severite: str) -> tuple[str, str, str]:
    """Renvoie (impact métier, effort estimé, horizon) pour un constat."""
    t = (titre or "").lower()
    impact, effort, horizon = _DEFAUT
    for cles, imp, eff, hor in _REGLES:
        if any(c in t for c in cles):
            impact, effort, horizon = imp, eff, hor
            break
    # Un constat critique ou élevé remonte d'office dans le plan de traitement
    sev = normaliser_severite(severite)
    if sev in _HORIZON_PAR_SEVERITE:
        priorite = _HORIZON_PAR_SEVERITE[sev]
        if ORDRE_HORIZON[priorite] < ORDRE_HORIZON[horizon]:
            horizon = priorite
    return impact, effort, horizon


ORDRE_HORIZON = {"immediat": 0, "court_terme": 1, "fond": 2}


def compter_par_severite(constats: list[dict]) -> dict[str, int]:
    compte = {s: 0 for s in ORDRE_SEVERITE}
    for c in constats:
        compte[normaliser_severite(c.get("severity"))] += 1
    return compte


def constats_tries(constats: list[dict]) -> list[dict]:
    """Du plus grave au moins grave."""
    return sorted(constats, key=lambda c: ORDRE_SEVERITE.index(normaliser_severite(c.get("severity"))))


def plan_remediation(constats: list[dict]) -> dict[str, list[dict]]:
    """Regroupe les constats par horizon de traitement, sans doublon de titre."""
    plan = {"immediat": [], "court_terme": [], "fond": []}
    vus  = set()
    for c in constats_tries(constats):
        titre = c.get("title", "")
        if titre in vus:
            continue
        vus.add(titre)
        impact, effort, horizon = analyser_constat(titre, c.get("severity"))
        plan[horizon].append({
            "titre":    titre,
            "severite": normaliser_severite(c.get("severity")),
            "impact":   impact,
            "effort":   effort,
            "action":   c.get("desc", ""),
        })
    return plan


def niveau_posture(score: int, maximum: int = 100) -> tuple[str, str]:
    """Libellé et interprétation du score global."""
    pct = (score / maximum * 100) if maximum else 0
    if pct >= 80:
        return "Satisfaisante", (
            "La configuration analysée respecte l'essentiel des bonnes pratiques. "
            "L'enjeu est désormais de maintenir ce niveau dans la durée."
        )
    if pct >= 50:
        return "Perfectible", (
            "Les fondamentaux sont partiellement en place, mais plusieurs écarts exposent "
            "l'organisation à des attaques courantes et évitables."
        )
    return "Critique", (
        "Plusieurs protections élémentaires sont absentes. En l'état, l'organisation est "
        "exposée à des attaques ne demandant ni compétence avancée ni moyens particuliers."
    )


GLOSSAIRE = [
    ("SPF",    "Enregistrement DNS listant les serveurs autorisés à envoyer des emails "
               "au nom de votre domaine."),
    ("DKIM",   "Signature cryptographique apposée à vos emails, prouvant qu'ils viennent "
               "bien de vous et n'ont pas été modifiés."),
    ("DMARC",  "Politique indiquant aux messageries destinataires quoi faire d'un email "
               "qui échoue aux contrôles SPF et DKIM."),
    ("DNSSEC", "Signature des réponses DNS, empêchant qu'on redirige vos visiteurs vers "
               "un faux site à votre insu."),
    ("TLS",    "Protocole de chiffrement du trafic web, à l'origine du cadenas affiché "
               "par les navigateurs. Anciennement appelé SSL."),
    ("HSTS",   "En-tête imposant au navigateur de n'utiliser que des connexions chiffrées "
               "avec votre site."),
    ("CSP",    "En-tête restreignant les scripts qu'une page a le droit d'exécuter, "
               "principale défense contre l'injection de code."),
    ("CVE",    "Identifiant mondial unique attribué à une vulnérabilité publiquement "
               "connue dans un logiciel."),
    ("CVSS",   "Note de gravité d'une vulnérabilité, de 0 à 10. Mesure le dommage "
               "potentiel, pas la probabilité qu'elle soit exploitée."),
    ("EPSS",   "Probabilité qu'une vulnérabilité soit réellement exploitée dans les "
               "30 jours. Complète le CVSS pour prioriser selon le risque réel."),
    ("EASM",   "Évaluation de la surface d'attaque externe : tout ce qu'un attaquant peut "
               "voir de votre organisation depuis internet, sans accès privilégié."),
]

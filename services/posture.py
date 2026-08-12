"""
Posture de sécurité des comptes, vue du prestataire.

La console d'administration savait dire combien de scans avaient été lancés,
jamais ce qu'ils avaient révélé. Un client dont le score s'effondre, un actif
qui n'a pas été analysé depuis un mois, un compte qui cumule les vulnérabilités
graves : rien de tout cela n'apparaissait, alors que le moteur de comparaison
produit déjà l'information à chaque scan. Elle n'était simplement agrégée nulle
part.

Deux précautions gouvernent le calcul.

Les scores sont ramenés sur cent avant toute moyenne. Un dépôt GitHub est noté
sur trente ; mêler les deux barèmes ferait passer un dépôt parfait pour un
actif en perdition.

Un actif compte une fois, par son dernier scan. Sans cela, un client qui relance
dix fois la même analyse pèserait dix fois plus qu'un autre dans sa propre
moyenne, et la posture mesurerait l'assiduité plutôt que la sécurité.
"""

from collections import defaultdict

from sqlalchemy.orm import Session

from horodatage import ecoule_depuis
from models import Scan, User

# Sévérités jugées dignes d'attention immédiate. Les deux langues coexistent :
# les outils français étiquettent en français, les CVE arrivent du NVD.
GRAVES = {"CRITIQUE", "CRITICAL", "HAUT", "HIGH"}


def _sur_cent(scan: Scan) -> int:
    """Score du scan ramené sur cent, quel que soit son barème d'origine."""
    bareme = (scan.results or {}).get("score_max") or 100
    return round((scan.score or 0) * 100 / bareme)


def _graves(scan: Scan) -> int:
    return sum(1 for i in (scan.issues or [])
               if (i.get("severity") or "").upper() in GRAVES)


def posture_comptes(db: Session) -> list[dict]:
    """Une ligne par compte ayant scanné au moins un actif, du plus préoccupant
    au plus sain.

    Tous les scans sont chargés en une requête puis regroupés en mémoire : une
    requête par compte puis par actif produirait la cascade que nous avons déjà
    éliminée sur les conversations. Le volume s'y prête, l'historique complet
    tenant très largement en mémoire."""
    # Seuls les clients figurent ici : la vue répond à une question de
    # prestataire, et un expert qui analyse ses propres actifs pour s'entraîner
    # n'est pas un compte à suivre commercialement. Son historique reste
    # consultable dans la liste des scans.
    clients = {u.id for u in db.query(User).filter(User.role == "client").all()}
    if not clients:
        return []

    scans = (db.query(Scan)
             .filter(Scan.status == "completed", Scan.user_id.in_(clients))
             .order_by(Scan.id)
             .all())
    if not scans:
        return []

    par_compte: dict[int, dict[str, list[Scan]]] = defaultdict(lambda: defaultdict(list))
    for scan in scans:
        par_compte[scan.user_id][scan.target].append(scan)

    comptes = {u.id: u for u in db.query(User)
               .filter(User.id.in_(par_compte.keys())).all()}

    lignes = []
    for user_id, cibles in par_compte.items():
        utilisateur = comptes.get(user_id)
        if not utilisateur:
            continue          # compte supprimé, scans orphelins

        derniers = [historique[-1] for historique in cibles.values()]
        scores   = [_sur_cent(s) for s in derniers]

        # La tendance ne porte que sur les actifs réanalysés : un actif scanné
        # une seule fois n'a pas de passé, et le compter comme stable diluerait
        # la dégradation des autres.
        ecarts = [_sur_cent(h[-1]) - _sur_cent(h[-2])
                  for h in cibles.values() if len(h) > 1]

        recent = max(derniers, key=lambda s: s.id)
        age    = ecoule_depuis(recent.created_at)

        lignes.append({
            "user_id":       user_id,
            "nom":           utilisateur.name,
            "email":         utilisateur.email,
            "role":          utilisateur.role,
            "actif":         utilisateur.is_active,
            "actifs":        len(cibles),
            "score":         round(sum(scores) / len(scores)),
            "pire_score":    min(scores),
            "tendance":      round(sum(ecarts) / len(ecarts)) if ecarts else None,
            "degrades":      sum(1 for e in ecarts if e < 0),
            "graves":        sum(_graves(s) for s in derniers),
            "dernier_scan":  recent.date,
            "jours_depuis":  age.days if age else None,
        })

    # Deux motifs d'attention, dans cet ordre : ce qui bouge dans le mauvais
    # sens, puis ce qui va mal sans bouger. Les comptes ayant au moins un actif
    # dégradé passent devant, du plus dégradé au moins ; les autres suivent par
    # score croissant.
    #
    # Trier sur la seule tendance enterrerait un compte durablement mauvais
    # derrière un compte sain qui vient de perdre deux points — c'est le
    # travers qu'a montré le premier essai, où la pire posture arrivait
    # cinquième parce qu'elle s'améliorait.
    def priorite(ligne: dict) -> tuple:
        if ligne["degrades"]:
            return (0, ligne["tendance"], ligne["score"])
        # Hors dégradation, la tendance n'a plus rien à départager : seul le
        # score dit lesquels vont mal.
        return (1, 0, ligne["score"])

    lignes.sort(key=priorite)
    return lignes

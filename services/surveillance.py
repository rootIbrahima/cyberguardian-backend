"""
Surveillance continue de la surface d'attaque.

Un scanner répond à la question « comment va cet actif maintenant ». Une
plateforme EASM répond à « qu'est-ce qui a changé depuis la dernière fois »,
ce qui suppose qu'il y ait une dernière fois, et donc des passages réguliers.
Sans eux, un port qui s'ouvre en août n'est découvert qu'au prochain scan
manuel, c'est-à-dire souvent jamais.

Le module ne réinvente rien : un passage planifié crée un scan ordinaire et
emprunte exactement le chemin d'un scan manuel. Le moteur de comparaison et
l'envoi d'alertes déjà en place font le reste. Ce fichier ne décide que de deux
choses : ce qui doit être réanalysé, et quand.
"""

from datetime import timedelta

from sqlalchemy.orm import Session

from horodatage import lire, maintenant, maintenant_iso
from models import Scan, SurveillanceCible

FREQUENCES = {"quotidienne": timedelta(days=1), "hebdomadaire": timedelta(days=7)}

# Marge de sécurité entre deux passages d'un même actif. Un redémarrage du
# planificateur ou une exécution manuelle ne doit pas relancer une analyse qui
# vient d'avoir lieu : les outils sollicitent des serveurs tiers, et une cible
# scannée deux fois dans l'heure ressemble à une reconnaissance agressive.
DELAI_MINIMAL = timedelta(hours=12)


def prochaine_echeance(frequence: str, depuis=None):
    """Date du prochain passage, en ISO."""
    base = depuis or maintenant()
    return (base + FREQUENCES.get(frequence, FREQUENCES["hebdomadaire"])).isoformat(timespec="seconds")


def activer(db: Session, user_id: int, target: str, asset_type: str,
            frequence: str = "hebdomadaire") -> SurveillanceCible:
    """Met un actif sous surveillance, ou réactive une surveillance retirée.

    Le premier passage n'est pas immédiat : l'actif vient d'être scanné, c'est
    d'ailleurs ce scan qui donne le point de comparaison. Relancer tout de suite
    produirait deux analyses identiques et aucune alerte."""
    existante = (db.query(SurveillanceCible)
                 .filter(SurveillanceCible.user_id == user_id,
                         SurveillanceCible.target == target)
                 .first())
    if existante:
        existante.actif            = True
        existante.frequence        = frequence
        existante.prochain_passage = prochaine_echeance(frequence)
        return existante

    surveillance = SurveillanceCible(
        user_id          = user_id,
        target           = target,
        asset_type       = asset_type,
        frequence        = frequence,
        actif            = True,
        cree_le          = maintenant_iso(),
        prochain_passage = prochaine_echeance(frequence),
    )
    db.add(surveillance)
    return surveillance


def desactiver(db: Session, user_id: int, surveillance_id: int) -> bool:
    """Retire un actif de la surveillance sans effacer son historique."""
    surveillance = (db.query(SurveillanceCible)
                    .filter(SurveillanceCible.id == surveillance_id,
                            SurveillanceCible.user_id == user_id)
                    .first())
    if not surveillance:
        return False
    surveillance.actif = False
    return True


def echues(db: Session, limite: int | None = None) -> list[SurveillanceCible]:
    """Surveillances dont l'échéance est passée, la plus ancienne d'abord.

    Le filtrage sur la date se fait en base, la garde des douze heures en
    mémoire : elle porte sur le dernier passage réel, dont l'absence est
    fréquente et rendrait la requête moins lisible qu'utile."""
    maintenant_iso_ = maintenant_iso()
    candidates = (db.query(SurveillanceCible)
                  .filter(SurveillanceCible.actif.is_(True),
                          SurveillanceCible.prochain_passage <= maintenant_iso_)
                  .order_by(SurveillanceCible.prochain_passage)
                  .all())

    seuil = maintenant() - DELAI_MINIMAL
    retenues = [s for s in candidates
                if not s.dernier_passage or (lire(s.dernier_passage) or seuil) <= seuil]
    return retenues[:limite] if limite else retenues


def enregistrer_passage(db: Session, surveillance: SurveillanceCible,
                        scan: Scan | None) -> None:
    """Note qu'un passage a eu lieu et programme le suivant.

    L'échéance suivante part de l'instant présent et non de l'échéance ratée :
    après une interruption du planificateur, compter à partir du passé ferait
    rejouer d'un coup toutes les analyses manquées."""
    surveillance.dernier_passage  = maintenant_iso()
    surveillance.prochain_passage = prochaine_echeance(surveillance.frequence)
    if scan:
        surveillance.dernier_scan_id = scan.id
    db.commit()

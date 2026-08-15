"""
Surveillance continue : le client choisit les actifs qu'il fait réanalyser
périodiquement. L'exécution, elle, est menée hors de l'application par
taches_planifiees.py.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import SurveillanceCible, User
from services.surveillance import FREQUENCES, activer, desactiver
from tools.target_guard import CibleInterdite, resoudre_et_valider

router = APIRouter(prefix="/surveillance", tags=["surveillance"])


class SurveillanceRequest(BaseModel):
    target:     str
    asset_type: str
    frequence:  str = "hebdomadaire"


@router.get("")
def lister(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    surveillances = (db.query(SurveillanceCible)
                     .filter(SurveillanceCible.user_id == current_user.id,
                             SurveillanceCible.actif.is_(True))
                     .order_by(SurveillanceCible.prochain_passage)
                     .all())
    return [s.to_dict() for s in surveillances]


@router.post("")
def mettre_sous_surveillance(
    body:         SurveillanceRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """Place un actif sous surveillance périodique."""
    if body.asset_type not in ("domain", "ip", "url", "github"):
        raise HTTPException(status_code=400, detail="Type d'actif invalide")
    if body.frequence not in FREQUENCES:
        raise HTTPException(
            status_code=400,
            detail=f"Fréquence invalide : {', '.join(FREQUENCES)}",
        )
    # Même garde qu'au lancement d'un scan : une cible interne ferait de la
    # plateforme un relais de reconnaissance, et le passage étant automatique,
    # elle le ferait indéfiniment.
    if body.asset_type in ("domain", "url", "ip"):
        try:
            resoudre_et_valider(body.target)
        except CibleInterdite as e:
            raise HTTPException(status_code=400, detail=str(e))

    surveillance = activer(db, current_user.id, body.target, body.asset_type, body.frequence)
    db.commit()
    db.refresh(surveillance)
    return surveillance.to_dict()


@router.delete("/{surveillance_id}")
def retirer(
    surveillance_id: int,
    db:              Session = Depends(get_db),
    current_user:    User    = Depends(get_current_user),
):
    if not desactiver(db, current_user.id, surveillance_id):
        raise HTTPException(status_code=404, detail="Surveillance introuvable")
    db.commit()
    return {"retiree": surveillance_id}

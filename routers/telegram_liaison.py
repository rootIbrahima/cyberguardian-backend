"""
Routes de liaison Telegram.
- Routes client (auth JWT) : générer un code, consulter le statut, délier.
- Routes bot (header X-Bot-Secret) : vérifier un code, résoudre un chat_id
  vers les données du client. Jamais accessibles sans le secret.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Scan, TelegramLink, User
from auth import get_current_user
from config import TELEGRAM_WEBHOOK_SECRET
from services.telegram_liaison import (
    generer_code_liaison,
    verifier_code_et_lier,
    get_user_par_chat_id,
    delier_compte,
)

router = APIRouter(prefix="/telegram", tags=["telegram"])


def _require_bot_secret(request: Request):
    """Protège les routes appelées par le bot / Hermes Agent."""
    if not TELEGRAM_WEBHOOK_SECRET or \
       request.headers.get("X-Bot-Secret") != TELEGRAM_WEBHOOK_SECRET:
        raise HTTPException(status_code=403, detail="Interdit")


def _mask_chat_id(chat_id: str) -> str:
    """123456789 -> 123***789"""
    if not chat_id or len(chat_id) <= 6:
        return "***"
    return f"{chat_id[:3]}***{chat_id[-3:]}"


class VerifierCodeBody(BaseModel):
    code:    str
    chat_id: str


# ── Routes client (auth JWT) ──────────────────────────────────────────────────

@router.get("/generer-code")
def route_generer_code(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    return generer_code_liaison(current_user.id, db)


@router.get("/statut")
def route_statut(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    lien = db.query(TelegramLink).filter(
        TelegramLink.user_id == current_user.id,
        TelegramLink.actif.is_(True),
    ).first()
    if not lien:
        return {"lie": False, "chat_id": None, "lie_depuis": None}
    return {
        "lie":        True,
        "chat_id":    _mask_chat_id(lien.chat_id),
        "lie_depuis": lien.linked_at.strftime("%d/%m/%Y") if lien.linked_at else None,
    }


@router.delete("/delier")
def route_delier(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    ok = delier_compte(current_user.id, db)
    if not ok:
        raise HTTPException(status_code=404, detail="Aucun compte Telegram lié.")
    return {
        "succes":  True,
        "message": "Compte Telegram délié. Vous ne recevrez plus d'alertes sur Telegram.",
    }


# ── Routes bot (header X-Bot-Secret) ──────────────────────────────────────────

@router.post("/verifier-code")
def route_verifier_code(
    body:    VerifierCodeBody,
    request: Request,
    db:      Session = Depends(get_db),
):
    _require_bot_secret(request)
    return verifier_code_et_lier(body.code, body.chat_id, db)


@router.get("/client/{chat_id}")
def route_client_par_chat_id(
    chat_id: str,
    request: Request,
    db:      Session = Depends(get_db),
):
    """Métadonnées du client lié à ce chat_id — pour que l'agent réponde.
    Ne renvoie jamais les résultats complets de scan, seulement des métadonnées."""
    _require_bot_secret(request)

    user = get_user_par_chat_id(chat_id, db)
    if not user:
        raise HTTPException(status_code=404, detail="chat_id non lié")

    scans = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).all()

    # Actifs = cibles distinctes scannées par le client
    seen, assets = set(), []
    for s in scans:
        if s.target not in seen:
            seen.add(s.target)
            assets.append({"id": s.id, "type": s.type, "valeur": s.target})

    dernier = scans[0] if scans else None
    dernier_scan = None
    if dernier:
        d = dernier.to_dict()
        niveau = ("bon" if (d["score"] or 0) >= 80
                  else "moyen" if (d["score"] or 0) >= 50 else "critique")
        dernier_scan = {
            "score":        d["score"],
            "niveau":       niveau,
            "date":         d["date"],
            "issues_count": d["vulns"],
        }

    return {
        "user_id":     user.id,
        "nom":         user.name,
        "email":       user.email,
        "assets":      assets,
        "dernier_scan": dernier_scan,
        "abonnement":  None,   # table Abonnement à venir
    }

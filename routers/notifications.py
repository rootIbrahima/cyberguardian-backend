"""
Notifications persistantes : contrairement à un compteur dérivé d'une requête
live (candidatures en attente, messages non lus), chaque événement devient une
ligne en base qui reste visible, marquée lue, jamais supprimée silencieusement.
"""

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from horodatage import maintenant_iso
from database import get_db
from models import Notification, User
from auth import get_current_user
from services.notifications import notifier_apres_commit

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _now_iso() -> str:
    return maintenant_iso()


def creer_notification(db: Session, user_id: int, type: str, title: str,
                       body: str | None = None, link: str | None = None,
                       externe: str | None = None) -> Notification:
    """Appelée par les autres routeurs au moment de l'événement (nouveau message,
    mission acceptée, contrat signé, candidature...). Ne fait pas le commit :
    l'appelant commit avec le reste de sa transaction."""
    notif = Notification(
        user_id    = user_id,
        type       = type,
        title      = title,
        body       = body,
        link       = link,
        created_at = _now_iso(),
    )
    db.add(notif)

    # Le même événement part sur les canaux externes du destinataire : Telegram
    # s'il a lié son compte, plus tout canal déclaré dans APPRISE_URLS. Le
    # paramètre « externe » permet un texte plus complet là-bas qu'à l'écran,
    # où la place est comptée.
    notifier_apres_commit(db, user_id, title, externe or body or title)
    return notif


@router.get("")
def list_notifications(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    notifs = (
        db.query(Notification)
        .filter(Notification.user_id == current_user.id)
        .order_by(Notification.id.desc())
        .limit(30)
        .all()
    )
    return [n.to_dict() for n in notifs]


@router.put("/read-all")
def mark_all_read(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    now = _now_iso()
    (db.query(Notification)
     .filter(Notification.user_id == current_user.id, Notification.read_at.is_(None))
     .update({"read_at": now}))
    db.commit()
    return {"marked": True}


@router.put("/{notif_id}/read")
def mark_read(
    notif_id:     int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    notif = (db.query(Notification)
             .filter(Notification.id == notif_id, Notification.user_id == current_user.id)
             .first())
    if not notif:
        raise HTTPException(status_code=404, detail="Notification introuvable")
    if notif.read_at is None:
        notif.read_at = _now_iso()
        db.commit()
    return notif.to_dict()

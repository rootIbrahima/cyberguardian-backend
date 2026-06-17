"""
Annuaire des experts validés + dépôt de candidature (CDC §4.2).
La validation des candidatures se fait côté admin (routers/admin.py).
"""

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from database import get_db
from models import ExpertProfile, User
from auth import get_current_user

router = APIRouter(prefix="/experts", tags=["experts"])

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads" / "experts"

MOIS = ["jan", "fev", "mar", "avr", "mai", "jun",
        "jul", "aou", "sep", "oct", "nov", "dec"]

# Couleurs d'avatar attribuées cycliquement aux nouveaux experts
AVATAR_COLORS = ["#1F5C99", "#10B981", "#F59E0B", "#8B5CF6", "#EF4444", "#0891B2"]

MAX_FILE_SIZE = 5 * 1024 * 1024   # 5 MB (limite affichée dans le formulaire)


def _date_label() -> str:
    now = datetime.now()
    return f"{now.day:02d} {MOIS[now.month - 1]}. {now.year}"


def _save_upload(upload: UploadFile, dest_stem: str) -> str:
    content = upload.file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (max 5 MB)")
    suffix = Path(upload.filename or "document").suffix or ".bin"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{dest_stem}{suffix}"
    dest.write_bytes(content)
    return str(dest)


@router.get("")
def list_experts(db: Session = Depends(get_db)):
    """Annuaire public (authentifié) des experts validés."""
    from models import Conversation

    profiles = (
        db.query(ExpertProfile)
        .filter(ExpertProfile.status == "approved")
        .order_by(ExpertProfile.id)
        .all()
    )

    cards = []
    for p in profiles:
        # Missions et note calculées sur les données réelles, pas sur le seed
        missions = (
            db.query(Conversation)
            .filter(Conversation.expert_id == p.user_id, Conversation.level >= 3)
            .count()
        )
        ratings = [
            r for (r,) in db.query(Conversation.rating)
            .filter(Conversation.expert_id == p.user_id, Conversation.rating.isnot(None))
            .all()
        ]
        rating = round(sum(ratings) / len(ratings), 1) if ratings else None

        card = p.to_card()
        card["missions"] = missions
        card["rating"]   = rating
        cards.append(card)

    # Les mieux notés d'abord, puis les nouveaux (sans note) après
    cards.sort(key=lambda c: (c["rating"] is None, -(c["rating"] or 0), -c["missions"]))
    return cards


@router.post("/apply")
def apply(
    cni:          str               = Form(...),
    level:        str               = Form(""),
    specialty:    str               = Form(""),
    cni_file:     UploadFile | None = File(None),
    diploma_file: UploadFile | None = File(None),
    db:           Session           = Depends(get_db),
    current_user: User              = Depends(get_current_user),
):
    """Dépôt de candidature expert : 5 champs (CDC §4.2), validation manuelle par l'admin."""
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Seul un compte client peut candidater comme expert")
    existing = db.query(ExpertProfile).filter(ExpertProfile.user_id == current_user.id).first()
    if existing and existing.status == "pending":
        raise HTTPException(status_code=409, detail="Candidature déjà en attente de validation")
    if existing and existing.status == "approved":
        raise HTTPException(status_code=409, detail="Vous êtes déjà expert validé")

    cni_path     = _save_upload(cni_file,     f"{current_user.id}_cni")     if cni_file     else None
    diploma_path = _save_upload(diploma_file, f"{current_user.id}_diplome") if diploma_file else None

    if existing:   # candidature rejetée précédemment — on la met à jour
        profile = existing
        profile.status = "pending"
    else:
        profile = ExpertProfile(user_id=current_user.id)
        db.add(profile)

    profile.cni          = cni
    profile.level        = level
    profile.specialty    = specialty
    profile.applied_at   = _date_label()
    profile.color        = AVATAR_COLORS[current_user.id % len(AVATAR_COLORS)]
    if cni_path:
        profile.cni_file = cni_path
    if diploma_path:
        profile.diploma_file = diploma_path

    db.commit()
    db.refresh(profile)
    return {"id": profile.id, "status": profile.status}

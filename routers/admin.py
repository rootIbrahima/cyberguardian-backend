"""
Administration : validation des candidatures experts (CNI + diplôme — CDC §4.2),
statistiques de la plateforme et consultation des pièces justificatives.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Conversation, ExpertProfile, Scan, User
from auth import get_current_user

router = APIRouter(prefix="/admin", tags=["admin"])


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Réservé à l'administrateur")
    return current_user


def _get_profile_or_404(profile_id: int, db: Session) -> ExpertProfile:
    profile = db.query(ExpertProfile).filter(ExpertProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Candidature introuvable")
    return profile


@router.get("/experts/pending")
def pending_experts(
    db: Session = Depends(get_db),
    _:  User    = Depends(require_admin),
):
    profiles = (
        db.query(ExpertProfile)
        .filter(ExpertProfile.status == "pending")
        .order_by(ExpertProfile.id.desc())
        .all()
    )
    return [p.to_pending() for p in profiles]


@router.put("/experts/{profile_id}/approve")
def approve_expert(
    profile_id: int,
    db:         Session = Depends(get_db),
    _:          User    = Depends(require_admin),
):
    profile = _get_profile_or_404(profile_id, db)
    profile.status = "approved"
    profile.user.role = "expert"
    db.commit()
    return {"id": profile.id, "status": profile.status}


@router.put("/experts/{profile_id}/reject")
def reject_expert(
    profile_id: int,
    db:         Session = Depends(get_db),
    _:          User    = Depends(require_admin),
):
    profile = _get_profile_or_404(profile_id, db)
    profile.status = "rejected"
    db.commit()
    return {"id": profile.id, "status": profile.status}


@router.get("/experts/approved")
def approved_experts(
    db: Session = Depends(get_db),
    _:  User    = Depends(require_admin),
):
    profiles = (
        db.query(ExpertProfile)
        .filter(ExpertProfile.status == "approved")
        .order_by(ExpertProfile.id.desc())
        .all()
    )
    return [
        {**p.to_card(), "email": p.user.email if p.user else "", "cni": p.cni, "level": p.level}
        for p in profiles
    ]


@router.put("/experts/{profile_id}/revoke")
def revoke_expert(
    profile_id: int,
    db:         Session = Depends(get_db),
    _:          User    = Depends(require_admin),
):
    """Retire un expert validé de l'annuaire : statut révoqué + retour au rôle client."""
    profile = _get_profile_or_404(profile_id, db)
    if profile.status != "approved":
        raise HTTPException(status_code=409, detail="Cet expert n'est pas validé")
    profile.status = "revoked"
    profile.user.role = "client"
    db.commit()
    return {"id": profile.id, "status": profile.status}


@router.get("/experts/{profile_id}/document/{kind}")
def expert_document(
    profile_id: int,
    kind:       str,
    db:         Session = Depends(get_db),
    _:          User    = Depends(require_admin),
):
    """Pièce justificative d'une candidature : kind = cni | diploma."""
    profile = _get_profile_or_404(profile_id, db)
    path = profile.cni_file if kind == "cni" else profile.diploma_file if kind == "diploma" else None
    if path is None:
        raise HTTPException(status_code=404, detail="Document non fourni")
    file = Path(path)
    if not file.exists():
        raise HTTPException(status_code=404, detail="Fichier introuvable sur le serveur")
    return FileResponse(file, filename=file.name)


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    _:  User    = Depends(require_admin),
):
    users = db.query(User).order_by(User.id).all()
    return [
        {
            "id":        u.id,
            "name":      u.name,
            "email":     u.email,
            "role":      u.role,
            "is_active": bool(u.is_active),
            "scans":     u.scans.count(),
        }
        for u in users
    ]


@router.put("/users/{user_id}/toggle")
def toggle_user(
    user_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(require_admin),
):
    """Active / désactive un compte. Un compte désactivé perd l'accès immédiatement."""
    if user_id == current_user.id:
        raise HTTPException(status_code=409, detail="Impossible de désactiver votre propre compte")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    user.is_active = not user.is_active
    db.commit()
    return {"id": user.id, "is_active": bool(user.is_active)}


@router.get("/stats")
def stats(
    db: Session = Depends(get_db),
    _:  User    = Depends(require_admin),
):
    return {
        "pending":       db.query(ExpertProfile).filter(ExpertProfile.status == "pending").count(),
        "approved":      db.query(ExpertProfile).filter(ExpertProfile.status == "approved").count(),
        "rejected":      db.query(ExpertProfile).filter(ExpertProfile.status == "rejected").count(),
        "users":         db.query(User).count(),
        "clients":       db.query(User).filter(User.role == "client").count(),
        "experts":       db.query(User).filter(User.role == "expert").count(),
        "scans":         db.query(Scan).count(),
        "conversations": db.query(Conversation).count(),
    }

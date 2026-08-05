"""
Administration : validation des candidatures experts (CNI + diplôme, CDC §4.2),
statistiques de la plateforme et consultation des pièces justificatives.
"""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from database import get_db
from models import Conversation, ExpertProfile, RepoAutorisation, Scan, User
from auth import get_current_user
from services.remediation import proposer_correction
from routers.github_oauth import _repo_slug
from routers.notifications import creer_notification

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
    creer_notification(
        db, profile.user_id, "expert_decision",
        title = "Candidature acceptée",
        body  = "Vous êtes désormais expert validé : votre profil apparaît dans l'annuaire.",
        link  = "/dashboard",
    )
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
    creer_notification(
        db, profile.user_id, "expert_decision",
        title = "Candidature non retenue",
        body  = "Votre candidature d'expert n'a pas été validée cette fois-ci.",
        link  = "/settings",
    )
    db.commit()
    return {"id": profile.id, "status": profile.status}


@router.post("/scans/{scan_id}/remediation")
def proposer_remediation(
    scan_id: int,
    db:      Session = Depends(get_db),
    _:       User    = Depends(require_admin),
):
    """Déclenche la remédiation assistée d'un scan GitHub : ouvre une Pull
    Request corrective sur le dépôt du client (si celui-ci l'a autorisée)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    if scan.type != "github":
        raise HTTPException(status_code=400,
                            detail="La correction automatique ne concerne que les scans GitHub.")

    res = proposer_correction(scan.user_id, scan.target, scan.to_dict(), db)
    if not res["ok"]:
        raise HTTPException(status_code=400, detail=res["message"])
    return res


@router.get("/remediation/candidats")
def remediation_candidats(
    db: Session = Depends(get_db),
    _:  User    = Depends(require_admin),
):
    """Scans GitHub des clients ayant autorisé la correction de leur dépôt :
    ce que l'admin peut proposer de corriger."""
    autos = db.query(RepoAutorisation).filter(RepoAutorisation.actif.is_(True)).all()
    items = []
    for a in autos:
        scans = (db.query(Scan)
                 .filter(Scan.user_id == a.user_id, Scan.type == "github")
                 .order_by(Scan.id.desc()).all())
        scan = next((s for s in scans if _repo_slug(s.target) == a.repo_slug), None)
        # Sans scan, on ne connaît pas les vulnérabilités : rien à proposer
        if not scan:
            continue
        d   = scan.to_dict()
        r   = d.get("results", {}) or {}
        deps    = len((r.get("safety", {})    or {}).get("findings", []))
        secrets = len((r.get("trufflehog", {}) or {}).get("findings", []))
        code    = len((r.get("bandit", {})     or {}).get("findings", []))
        npm     = len((r.get("npm_audit") or {}).get("findings", [])) if r.get("npm_audit") else 0
        client  = db.query(User).filter(User.id == a.user_id).first()
        items.append({
            "scan_id":      scan.id,
            "client":       client.name if client else "",
            "email":        client.email if client else "",
            "slug":         a.repo_slug,
            "problemes":    deps + secrets + code + npm,   # total détecté
            "corrigeables": deps,                          # dépendances : traitées automatiquement
            "secrets":      secrets,                       # secrets : nécessitent un expert / l'agent
            "date":         d.get("date"),
        })
    return items


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

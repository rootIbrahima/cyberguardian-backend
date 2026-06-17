"""
Messagerie interne client-expert (CDC §4.7) avec accès progressif en 3 niveaux :
    Niveau 1 — demande reçue (score global + nombre de failles)
    Niveau 2 — mission acceptée (l'expert répond → score détaillé par catégorie)
    Niveau 3 — contrat signé (rapport complet, accès 48h)
Polling côté frontend toutes les 5 secondes — pas de WebSocket.
"""

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db
from models import Conversation, ExpertProfile, Message, Scan, User
from auth import get_current_user

router = APIRouter(prefix="/conversations", tags=["messages"])

MOIS = ["jan", "fev", "mar", "avr", "mai", "jun",
        "jul", "aou", "sep", "oct", "nov", "dec"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _humanize(iso: str | None) -> str:
    """'Il y a 5 min' / 'Il y a 3h' / 'Hier' / '15 avr.'"""
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    delta = datetime.now() - dt
    minutes = int(delta.total_seconds() // 60)
    if minutes < 1:
        return "À l'instant"
    if minutes < 60:
        return f"Il y a {minutes} min"
    if minutes < 24 * 60:
        return f"Il y a {minutes // 60}h"
    if minutes < 48 * 60:
        return "Hier"
    return f"{dt.day} {MOIS[dt.month - 1]}."


def _conv_to_dict(conv: Conversation, viewer: User) -> dict:
    """Format attendu par MessagesPage.jsx — l'interlocuteur affiché dépend du rôle.
    La clé s'appelle "expert" côté frontend mais contient l'interlocuteur :
    l'expert pour un client, le client pour un expert."""
    is_client = viewer.id == conv.client_id
    other     = conv.expert if is_client else conv.client
    profile   = getattr(conv.expert, "_profile_cache", None)

    last_read = conv.client_last_read if is_client else conv.expert_last_read
    last_msg  = conv.messages[-1] if conv.messages else None
    if viewer.id not in (conv.client_id, conv.expert_id):
        unread = 0   # superviseur (admin) : pas de notion de non-lu
    else:
        unread = sum(
            1 for m in conv.messages
            if m.sender_id not in (viewer.id, None)
            and (not last_read or (m.created_at or "") > last_read)
        )

    return {
        "id":      conv.id,
        "expert": {
            "id":        other.id,
            "name":      other.name,
            "specialty": (profile.specialty if profile and is_client else None) or
                         ("Expert cybersécurité" if is_client else "Client"),
            "color":     (profile.color if profile and is_client else None) or "#1F5C99",
        },
        "subject":      conv.subject,
        "level":        conv.level,
        "missionStart": conv.mission_start,
        "rating":       conv.rating,
        "unread":       unread,
        "last":         _humanize(last_msg.created_at if last_msg else conv.created_at),
        "preview":      (last_msg.text[:60] if last_msg else "Nouvelle conversation"),
    }


def _msg_to_dict(msg: Message, conv: Conversation) -> dict:
    """Format attendu par MessageThread.jsx."""
    if msg.sender_id is None:
        sender = "system"
    elif msg.sender_id == conv.client_id:
        sender = "client"
    else:
        sender = "expert"
    try:
        time_label = datetime.fromisoformat(msg.created_at).strftime("%H:%M")
    except (ValueError, TypeError):
        time_label = ""
    return {"id": msg.id, "from": sender, "time": time_label, "text": msg.text,
            "created_at": msg.created_at}


def _get_conv_or_404(conv_id: int, db: Session, user: User) -> Conversation:
    conv = db.query(Conversation).filter(Conversation.id == conv_id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation introuvable")
    if user.role != "admin" and user.id not in (conv.client_id, conv.expert_id):
        raise HTTPException(status_code=403, detail="Accès refusé")
    return conv


def mission_active(conv: Conversation) -> bool:
    """Niveau 3 actif : contrat signé il y a moins de 48h (CDC §4.2)."""
    if conv.level < 3 or not conv.mission_start:
        return False
    try:
        start = datetime.fromisoformat(conv.mission_start)
    except ValueError:
        return False
    return datetime.now() - start < timedelta(hours=48)


def _attach_expert_profile(conv: Conversation, db: Session):
    profile = db.query(ExpertProfile).filter(ExpertProfile.user_id == conv.expert_id).first()
    conv.expert._profile_cache = profile


# ── Modèles ───────────────────────────────────────────────────────────────────

class ConversationCreate(BaseModel):
    expert_id: int                  # id utilisateur de l'expert
    subject:   str | None = None    # défaut : cible du dernier scan du client


class MessageCreate(BaseModel):
    text: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_conversations(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    q = db.query(Conversation)
    if current_user.role != "admin":
        q = q.filter(
            (Conversation.client_id == current_user.id)
            | (Conversation.expert_id == current_user.id)
        )
    convs = q.order_by(Conversation.id.desc()).all()
    for c in convs:
        _attach_expert_profile(c, db)
    return [_conv_to_dict(c, current_user) for c in convs]


@router.post("")
def create_conversation(
    body:         ConversationCreate,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="Seul un client peut initier une conversation")
    expert = db.query(User).filter(User.id == body.expert_id, User.role == "expert").first()
    if not expert:
        raise HTTPException(status_code=404, detail="Expert introuvable")

    subject = (body.subject or "").strip()
    if not subject:
        last_scan = (
            db.query(Scan)
            .filter(Scan.user_id == current_user.id)
            .order_by(Scan.id.desc())
            .first()
        )
        subject = last_scan.target if last_scan else "Conseil sécurité"

    existing = (
        db.query(Conversation)
        .filter(
            Conversation.client_id == current_user.id,
            Conversation.expert_id == expert.id,
            Conversation.subject   == subject,
        )
        .first()
    )
    if existing:
        _attach_expert_profile(existing, db)
        return _conv_to_dict(existing, current_user)

    conv = Conversation(
        client_id  = current_user.id,
        expert_id  = expert.id,
        subject    = subject,
        level      = 1,
        created_at = _now_iso(),
    )
    db.add(conv)
    db.commit()
    db.refresh(conv)
    _attach_expert_profile(conv, db)
    return _conv_to_dict(conv, current_user)


@router.get("/{conv_id}/scan")
def conversation_scan(
    conv_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """Vue du scan lié au sujet de la conversation, filtrée par le niveau d'accès :
    Niveau 1 : score global + nombre de failles.
    Niveau 2 : + score détaillé par catégorie.
    Niveau 3 : + accès au rapport complet (scan_id), expire 48h après signature.
    Le client (propriétaire) et l'admin voient toujours tout."""
    conv = _get_conv_or_404(conv_id, db, current_user)
    scan = (
        db.query(Scan)
        .filter(Scan.user_id == conv.client_id, Scan.target == conv.subject)
        .order_by(Scan.id.desc())
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Aucun scan pour ce sujet")

    full    = scan.to_dict()
    minimal = {k: full.get(k) for k in ("target", "typeLabel", "score", "vulns", "cve")}
    breakdown = (full.get("results", {}).get("score_detail", {}) or {}).get("breakdown", [])

    # Client propriétaire et admin : vue complète sans restriction
    if current_user.id != conv.expert_id:
        return {"access": "full", "scan_id": scan.id, "scan": minimal, "breakdown": breakdown}

    # Expert : selon le niveau de la conversation
    if conv.level == 1:
        return {"access": "level1", "scan": minimal}
    if conv.level == 2:
        return {"access": "level2", "scan": minimal, "breakdown": breakdown}
    if not mission_active(conv):
        return {"access": "expired", "scan": minimal}
    return {"access": "full", "scan_id": scan.id, "scan": minimal, "breakdown": breakdown}


@router.get("/{conv_id}/messages")
def list_messages(
    conv_id:      int,
    since:        str | None = None,
    db:           Session    = Depends(get_db),
    current_user: User       = Depends(get_current_user),
):
    conv = _get_conv_or_404(conv_id, db, current_user)
    msgs = conv.messages
    if since:
        msgs = [m for m in msgs if (m.created_at or "") > since]

    # Marque comme lu pour le compteur de non-lus
    now = _now_iso()
    if current_user.id == conv.client_id:
        conv.client_last_read = now
    elif current_user.id == conv.expert_id:
        conv.expert_last_read = now
    db.commit()

    return [_msg_to_dict(m, conv) for m in msgs]


@router.post("/{conv_id}/messages")
def send_message(
    conv_id:      int,
    body:         MessageCreate,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    conv = _get_conv_or_404(conv_id, db, current_user)
    # L'admin supervise en lecture seule — seuls les participants écrivent
    if current_user.id not in (conv.client_id, conv.expert_id):
        raise HTTPException(status_code=403, detail="Seuls les participants peuvent écrire")
    text = body.text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Message vide")

    msg = Message(
        conversation_id = conv.id,
        sender_id       = current_user.id,
        text            = text,
        created_at      = _now_iso(),
    )
    db.add(msg)

    # Niveau 1 → 2 : la première réponse de l'expert vaut acceptation de mission
    if conv.level == 1 and current_user.id == conv.expert_id:
        conv.level = 2
        db.add(Message(
            conversation_id = conv.id,
            sender_id       = None,
            text            = "Mission acceptée — l'expert a maintenant accès au score détaillé par catégorie (Niveau 2).",
            created_at      = _now_iso(),
        ))

    db.commit()
    db.refresh(msg)
    return _msg_to_dict(msg, conv)


@router.post("/{conv_id}/contract/sign")
def sign_contract(
    conv_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """Signature du contrat numérique par le client → Niveau 3, accès expert 48h."""
    conv = _get_conv_or_404(conv_id, db, current_user)
    if current_user.id != conv.client_id:
        raise HTTPException(status_code=403, detail="Seul le client peut signer le contrat")
    if conv.level >= 3:
        raise HTTPException(status_code=409, detail="Contrat déjà signé")

    conv.level         = 3
    conv.mission_start = _now_iso()
    db.add(Message(
        conversation_id = conv.id,
        sender_id       = None,
        text            = "Contrat numérique signé — l'expert a accès au rapport complet (Niveau 3) pendant 48h.",
        created_at      = _now_iso(),
    ))
    # Une mission de plus au compteur de l'expert
    profile = db.query(ExpertProfile).filter(ExpertProfile.user_id == conv.expert_id).first()
    if profile:
        profile.missions = (profile.missions or 0) + 1
    db.commit()
    return {"id": conv.id, "level": conv.level, "missionStart": conv.mission_start}


class RateRequest(BaseModel):
    stars: int


@router.post("/{conv_id}/rate")
def rate_expert(
    conv_id:      int,
    body:         RateRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """Le client note l'expert (1-5) après une mission contractualisée.
    La réputation de l'expert devient la moyenne de ses notes réelles."""
    conv = _get_conv_or_404(conv_id, db, current_user)
    if current_user.id != conv.client_id:
        raise HTTPException(status_code=403, detail="Seul le client peut noter l'expert")
    if conv.level < 3:
        raise HTTPException(status_code=409, detail="La notation est possible après signature du contrat")
    if conv.rating is not None:
        raise HTTPException(status_code=409, detail="Mission déjà notée")
    if not 1 <= body.stars <= 5:
        raise HTTPException(status_code=422, detail="Note entre 1 et 5")

    conv.rating = body.stars

    profile = db.query(ExpertProfile).filter(ExpertProfile.user_id == conv.expert_id).first()
    expert_rating = None
    if profile:
        ratings = [
            r for (r,) in db.query(Conversation.rating)
            .filter(
                Conversation.expert_id == conv.expert_id,
                Conversation.rating.isnot(None),
                Conversation.id != conv.id,
            )
            .all()
        ]
        ratings.append(body.stars)
        profile.rating = round(sum(ratings) / len(ratings), 1)
        expert_rating  = profile.rating

    db.add(Message(
        conversation_id = conv.id,
        sender_id       = None,
        text            = f"Le client a évalué la mission : {body.stars}/5.",
        created_at      = _now_iso(),
    ))
    db.commit()
    return {"id": conv.id, "rating": conv.rating, "expert_rating": expert_rating}

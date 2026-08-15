"""
Messagerie interne client-expert (CDC §4.7) avec accès progressif en 3 niveaux :
    Niveau 1 : demande reçue (score global + nombre de failles)
    Niveau 2 : mission acceptée (l'expert répond → score détaillé par catégorie)
    Niveau 3 : contrat signé (rapport complet, accès 48h)
Polling côté frontend toutes les 5 secondes, pas de WebSocket.
"""

from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, joinedload, selectinload

from database import get_db
from horodatage import anterieur_ou_egal, ecoule_depuis, lire, maintenant_iso
from models import Conversation, ExpertProfile, Message, MessageAttachment, Scan, User
from auth import get_current_user
from routers.notifications import creer_notification

router = APIRouter(prefix="/conversations", tags=["messages"])

MOIS = ["jan", "fev", "mar", "avr", "mai", "jun",
        "jul", "aou", "sep", "oct", "nov", "dec"]


# ── Helpers ───────────────────────────────────────────────────────────────────

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads" / "messages"

# Types acceptés en pièce jointe : ce qu'un expert et un client s'échangent
# réellement pour instruire une faille. SVG volontairement exclu, il peut
# embarquer du script. Le type servi au téléchargement vient de cette table et
# jamais de ce que déclare le client.
TYPES_ACCEPTES = {
    "image/png":       (".png",  bytes.fromhex("89504e47")),
    "image/jpeg":      (".jpg",  bytes.fromhex("ffd8ff")),
    "image/webp":      (".webp", b"RIFF"),
    "image/gif":       (".gif",  b"GIF8"),
    "application/pdf": (".pdf",  b"%PDF"),
    "text/plain":      (".txt",  None),   # pas de signature binaire
}
TAILLE_MAX = 5 * 1024 * 1024   # 5 Mo, comme les pièces de candidature


def _now_iso() -> str:
    return maintenant_iso()


def _humanize(iso: str | None) -> str:
    """'Il y a 5 min' / 'Il y a 3h' / 'Hier' / '15 avr.'"""
    dt = lire(iso)
    if dt is None:
        return iso or ""
    delta = ecoule_depuis(iso)
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
    """Format attendu par MessagesPage.jsx, l'interlocuteur affiché dépend du rôle.
    La clé s'appelle "expert" côté frontend mais contient l'interlocuteur :
    l'expert pour un client, le client pour un expert."""
    is_client = viewer.id == conv.client_id
    other     = conv.expert if is_client else conv.client
    profile   = getattr(conv.expert, "_profile_cache", None)

    last_read = conv.client_last_read if is_client else conv.expert_last_read
    last_msg  = conv.messages[-1] if conv.messages else None
    participant = viewer.id in (conv.client_id, conv.expert_id)
    if not participant:
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
        # L'aperçu est du contenu : soixante caractères du dernier message
        # suffisent à révéler un port ouvert ou un nom de fichier compromis.
        # Un superviseur reçoit à la place le volume de l'échange, qui est ce
        # dont il a besoin pour juger de son activité.
        "preview":      ((last_msg.text[:60] if last_msg else "Nouvelle conversation")
                         if participant
                         else f"{len(conv.messages)} message(s) échangé(s)"),
        "supervision":  not participant,
        # Le format d'origine n'affiche qu'un interlocuteur, celui d'en face,
        # puisqu'un participant se connaît lui-même. Superviser suppose au
        # contraire de voir les deux parties, et le volume de l'échange.
        "parties": None if participant else {
            "client":   {"id": conv.client.id, "nom": conv.client.name,
                         "email": conv.client.email},
            "expert":   {"id": conv.expert.id, "nom": conv.expert.name,
                         "email": conv.expert.email},
            "messages": len(conv.messages),
            "ouverte":  conv.created_at,
        },
    }


def _msg_to_dict(msg: Message, conv: Conversation, viewer: User | None = None) -> dict:
    """Format attendu par MessageThread.jsx."""
    if msg.sender_id is None:
        sender = "system"
    elif msg.sender_id == conv.client_id:
        sender = "client"
    else:
        sender = "expert"
    dt = lire(msg.created_at)
    time_label = dt.strftime("%H:%M") if dt else ""

    # Accusé de lecture, sur ses propres messages seulement : l'information
    # existait déjà en base sans jamais être remontée à l'expéditeur.
    lu = None
    if viewer is not None and msg.sender_id == viewer.id:
        lecture_autre = (conv.expert_last_read if viewer.id == conv.client_id
                         else conv.client_last_read)
        lu = anterieur_ou_egal(msg.created_at, lecture_autre)

    piece = msg.piece_jointe
    return {
        "id":         msg.id,
        "from":       sender,
        "time":       time_label,
        "text":       msg.text,
        "created_at": msg.created_at,
        "lu":         lu,
        "piece":      ({"id": piece.id, "nom": piece.nom, "type": piece.type_mime,
                        "taille": piece.taille} if piece else None),
    }


def _enregistrer_piece(upload: UploadFile) -> tuple[bytes, str, str]:
    """Valide puis nomme une pièce jointe. Renvoie (contenu, type retenu, suffixe).

    Le type est repris de notre table, jamais de la déclaration du client, et la
    signature du fichier est confrontée à ce type : un exécutable renommé en
    .png est refusé ici plutôt que servi plus tard."""
    type_mime = (upload.content_type or "").split(";")[0].strip().lower()
    if type_mime not in TYPES_ACCEPTES:
        raise HTTPException(
            status_code=415,
            detail="Format refusé. Images, PDF et fichiers texte uniquement.",
        )
    contenu = upload.file.read()
    if not contenu:
        raise HTTPException(status_code=422, detail="Fichier vide")
    if len(contenu) > TAILLE_MAX:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux (max 5 Mo)")

    suffixe, signature = TYPES_ACCEPTES[type_mime]
    if signature and not contenu.startswith(signature):
        raise HTTPException(
            status_code=415,
            detail="Le contenu du fichier ne correspond pas à son format annoncé.",
        )
    return contenu, type_mime, suffixe


def _get_conv_or_404(conv_id: int, db: Session, user: User) -> Conversation:
    conv = db.query(Conversation).filter(Conversation.id == conv_id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation introuvable")
    if user.role != "admin" and user.id not in (conv.client_id, conv.expert_id):
        raise HTTPException(status_code=403, detail="Accès refusé")
    return conv


def _exiger_participant(conv: Conversation, user: User, quoi: str) -> None:
    """Réserve aux deux interlocuteurs tout ce qui touche au contenu échangé.

    L'administration voit la conversation — qui parle à qui, sur quel actif, à
    quel niveau de mission, depuis quand, combien de messages — mais pas ce qui
    s'y dit. Les échanges portent les rapports de vulnérabilités des actifs du
    client : ports ouverts, secrets exposés, chemins de fichiers. Un compte
    capable de tout lire sans laisser de trace concentre précisément ce qu'un
    attaquant cherche, pour un besoin d'exploitation que les métadonnées
    couvrent déjà."""
    if user.id not in (conv.client_id, conv.expert_id):
        raise HTTPException(status_code=403, detail=quoi)


def mission_active(conv: Conversation) -> bool:
    """Niveau 3 actif : contrat signé il y a moins de 48h (CDC §4.2)."""
    if conv.level < 3:
        return False
    depuis = ecoule_depuis(conv.mission_start)
    return depuis is not None and depuis < timedelta(hours=48)


def _suites_envoi(conv: Conversation, auteur: User, apercu: str, db: Session):
    """Notification du destinataire et passage éventuel au niveau 2. Partagé par
    l'envoi de texte et l'envoi de pièce jointe, qui valent tous deux réponse."""
    dest_id = conv.expert_id if auteur.id == conv.client_id else conv.client_id
    creer_notification(
        db, dest_id, "message",
        title = f"Nouveau message : {conv.subject}",
        body  = apercu[:120],
        link  = "/messages",
    )

    # Niveau 1 → 2 : la première réponse de l'expert vaut acceptation de mission
    if conv.level == 1 and auteur.id == conv.expert_id:
        conv.level = 2
        db.add(Message(
            conversation_id = conv.id,
            sender_id       = None,
            text            = "Mission acceptée : l'expert a maintenant accès au score détaillé par catégorie (Niveau 2).",
            created_at      = _now_iso(),
        ))
        creer_notification(
            db, conv.client_id, "mission_level",
            title = f"Mission acceptée : {conv.subject}",
            body  = "L'expert a accepté votre demande et accède au score détaillé.",
            link  = "/messages",
        )


def _attach_expert_profile(conv: Conversation, db: Session):
    profile = db.query(ExpertProfile).filter(ExpertProfile.user_id == conv.expert_id).first()
    conv.expert._profile_cache = profile


def _attach_expert_profiles(convs: list[Conversation], db: Session):
    """Même chose pour une liste, en une seule requête. Charger les profils un
    par un coûtait trois requêtes par conversation à chaque sondage."""
    if not convs:
        return
    ids      = {c.expert_id for c in convs}
    profils  = db.query(ExpertProfile).filter(ExpertProfile.user_id.in_(ids)).all()
    par_user = {p.user_id: p for p in profils}
    for c in convs:
        c.expert._profile_cache = par_user.get(c.expert_id)


# ── Modèles ───────────────────────────────────────────────────────────────────

class ConversationCreate(BaseModel):
    expert_id: int                  # id utilisateur de l'expert
    subject:   str | None = None    # défaut : cible du dernier scan du client


class MessageCreate(BaseModel):
    # Borne haute : rien ne limitait la taille d'un message côté serveur.
    text: str = Field(max_length=4000)


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
    convs = (
        q.options(
            selectinload(Conversation.messages),
            joinedload(Conversation.client),
            joinedload(Conversation.expert),
        )
        .order_by(Conversation.id.desc())
        .all()
    )
    _attach_expert_profiles(convs, db)
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

    subject   = (body.subject or "").strip()
    last_scan = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id,
                *([Scan.target == subject] if subject else []))
        .order_by(Scan.id.desc())
        .first()
    )
    if not subject:
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
        # Le scan est figé à la création : la conversation porte sur celui qui a
        # motivé la demande, pas sur le dernier en date de la même cible.
        scan_id    = last_scan.id if last_scan else None,
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
    # Lien direct quand il existe. Le repli par comparaison de sujet ne sert que
    # pour les conversations créées avant l'ajout de la colonne et qu'aucun scan
    # ne permettait de rattacher.
    scan = conv.scan if conv.scan_id else (
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
    apres:        int | None = None,
    db:           Session    = Depends(get_db),
    current_user: User       = Depends(get_current_user),
):
    """Fil complet, ou seulement les messages postérieurs à « apres » (id du
    dernier message déjà affiché) pour les rafraîchissements périodiques."""
    conv = _get_conv_or_404(conv_id, db, current_user)
    _exiger_participant(conv, current_user,
                        "Le contenu des échanges est réservé aux deux interlocuteurs.")
    msgs = conv.messages
    if apres is not None:
        msgs = [m for m in msgs if m.id > apres]

    # Marque comme lu pour le compteur de non-lus
    now = _now_iso()
    if current_user.id == conv.client_id:
        conv.client_last_read = now
    elif current_user.id == conv.expert_id:
        conv.expert_last_read = now
    db.commit()

    return [_msg_to_dict(m, conv, current_user) for m in msgs]


@router.post("/{conv_id}/messages")
def send_message(
    conv_id:      int,
    body:         MessageCreate,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    conv = _get_conv_or_404(conv_id, db, current_user)
    _exiger_participant(conv, current_user, "Seuls les interlocuteurs peuvent écrire.")
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
    _suites_envoi(conv, current_user, text, db)
    db.commit()
    db.refresh(msg)
    return _msg_to_dict(msg, conv, current_user)


@router.post("/{conv_id}/messages/piece-jointe")
def send_attachment(
    conv_id:      int,
    fichier:      UploadFile = File(...),
    text:         str        = Form(""),
    db:           Session    = Depends(get_db),
    current_user: User       = Depends(get_current_user),
):
    """Envoi d'une pièce jointe, avec un commentaire facultatif. Une capture ou
    un extrait de journal valent souvent mieux qu'une description."""
    conv = _get_conv_or_404(conv_id, db, current_user)
    _exiger_participant(conv, current_user, "Seuls les interlocuteurs peuvent écrire.")

    contenu, type_mime, suffixe = _enregistrer_piece(fichier)
    legende = (text or "").strip()[:4000]

    msg = Message(
        conversation_id = conv.id,
        sender_id       = current_user.id,
        text            = legende,
        created_at      = _now_iso(),
    )
    db.add(msg)
    db.flush()   # besoin de l'id du message pour nommer le fichier

    # Le nom sur disque est le nôtre : celui fourni par le client ne sert qu'à
    # l'affichage et ne doit jamais décider d'un chemin.
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    chemin = UPLOAD_DIR / f"conv{conv.id}-msg{msg.id}{suffixe}"
    chemin.write_bytes(contenu)

    db.add(MessageAttachment(
        message_id = msg.id,
        nom        = Path(fichier.filename or f"piece{suffixe}").name[:120],
        type_mime  = type_mime,
        taille     = len(contenu),
        chemin     = str(chemin),
    ))
    _suites_envoi(conv, current_user, legende or "Pièce jointe", db)
    db.commit()
    db.refresh(msg)
    return _msg_to_dict(msg, conv, current_user)


@router.get("/{conv_id}/pieces-jointes/{piece_id}")
def download_attachment(
    conv_id:      int,
    piece_id:     int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """Téléchargement d'une pièce jointe, réservé aux deux interlocuteurs."""
    conv  = _get_conv_or_404(conv_id, db, current_user)
    _exiger_participant(conv, current_user,
                        "Les pièces jointes sont réservées aux deux interlocuteurs.")
    piece = (
        db.query(MessageAttachment)
        .join(Message, Message.id == MessageAttachment.message_id)
        .filter(MessageAttachment.id == piece_id, Message.conversation_id == conv.id)
        .first()
    )
    if not piece:
        raise HTTPException(status_code=404, detail="Pièce jointe introuvable")

    fichier = Path(piece.chemin)
    if not fichier.is_file():
        raise HTTPException(status_code=410, detail="Pièce jointe absente du serveur")

    # Le type servi vient de notre table, jamais de ce qui a été déclaré à
    # l'envoi. Les images s'affichent dans le fil, le reste se télécharge.
    en_ligne = piece.type_mime.startswith("image/")
    disposition = "inline" if en_ligne else "attachment"
    return Response(
        content=fichier.read_bytes(),
        media_type=piece.type_mime,
        headers={
            "Content-Disposition": f'{disposition}; filename="{piece.nom}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


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
        text            = "Contrat numérique signé : l'expert a accès au rapport complet (Niveau 3) pendant 48h.",
        created_at      = _now_iso(),
    ))
    # Une mission de plus au compteur de l'expert
    profile = db.query(ExpertProfile).filter(ExpertProfile.user_id == conv.expert_id).first()
    if profile:
        profile.missions = (profile.missions or 0) + 1
    creer_notification(
        db, conv.expert_id, "contract",
        title = f"Contrat signé : {conv.subject}",
        body  = "Vous avez accès au rapport complet pendant 48h.",
        link  = "/messages",
    )
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
    creer_notification(
        db, conv.expert_id, "rating",
        title = f"Nouvelle évaluation : {body.stars}/5",
        body  = f"Mission « {conv.subject} » notée par le client.",
        link  = "/messages",
    )
    db.commit()
    return {"id": conv.id, "rating": conv.rating, "expert_rating": expert_rating}

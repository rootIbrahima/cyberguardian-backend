"""
Service de liaison Telegram.
Telegram identifie un utilisateur par son chat_id (jamais par numéro). La
liaison se fait par un code à usage unique généré depuis l'interface web,
puis envoyé au bot — ce qui prouve que la même personne contrôle le compte
CyberGuardian et le compte Telegram. Le backend reste maître des données :
Hermes Agent / le bot interrogent l'API, ils ne stockent rien.
"""

import os
import random
import string
from datetime import datetime, timedelta

import httpx
from sqlalchemy.orm import Session

from models import TelegramCode, TelegramLink, User

CODE_TTL_MINUTES = 5


# ── Génération du code de liaison ─────────────────────────────────────────────

def generer_code_liaison(user_id: int, db: Session) -> dict:
    """Génère un code à usage unique pour lier un compte Telegram."""
    # Invalide les codes précédents non utilisés de cet utilisateur
    db.query(TelegramCode).filter(
        TelegramCode.user_id == user_id,
        TelegramCode.utilise.is_(False),
    ).update({"utilise": True})

    # Code unique CG-XXXXXX (6 caractères alphanumériques majuscules)
    chars = string.ascii_uppercase + string.digits
    while True:
        code = "CG-" + "".join(random.choices(chars, k=6))
        if not db.query(TelegramCode).filter(TelegramCode.code == code).first():
            break

    db.add(TelegramCode(
        user_id   = user_id,
        code      = code,
        expire_at = datetime.utcnow() + timedelta(minutes=CODE_TTL_MINUTES),
        utilise   = False,
    ))
    db.commit()

    bot_username = os.getenv("TELEGRAM_BOT_USERNAME", "CyberGuardianBot")
    lien = f"https://t.me/{bot_username}?start={code}"

    return {
        "code":        code,
        "lien":        lien,
        "expire_dans": f"{CODE_TTL_MINUTES} minutes",
        "instructions": [
            "1. Cliquez sur le lien ci-dessous, ou ouvrez votre bot Telegram",
            f"2. Envoyez ce message au bot : /start {code}",
            "3. Votre compte sera lié automatiquement",
        ],
    }


# ── Vérification du code et liaison ───────────────────────────────────────────

def verifier_code_et_lier(code: str, chat_id: str, db: Session) -> dict:
    """Appelée par le bot quand il reçoit /start <code>."""
    record = db.query(TelegramCode).filter(
        TelegramCode.code == code,
        TelegramCode.utilise.is_(False),
    ).first()

    if not record:
        return {"succes": False, "erreur": "Code invalide."}

    if datetime.utcnow() > record.expire_at:
        return {"succes": False,
                "erreur": "Code expiré. Générez un nouveau code depuis CyberGuardian."}

    # Ce chat_id est-il déjà lié à un AUTRE compte ?
    existant = db.query(TelegramLink).filter(
        TelegramLink.chat_id == chat_id,
        TelegramLink.user_id != record.user_id,
        TelegramLink.actif.is_(True),
    ).first()
    if existant:
        return {"succes": False,
                "erreur": "Ce compte Telegram est déjà lié à un autre compte CyberGuardian."}

    # Crée ou met à jour le lien
    lien = db.query(TelegramLink).filter(TelegramLink.user_id == record.user_id).first()
    if lien:
        lien.chat_id   = chat_id
        lien.linked_at = datetime.utcnow()
        lien.actif     = True
    else:
        db.add(TelegramLink(user_id=record.user_id, chat_id=chat_id))

    record.utilise = True
    db.commit()

    return {
        "succes":  True,
        "user_id": record.user_id,
        "message": "Compte lié avec succès. Vous recevrez désormais vos alertes "
                   "de sécurité sur Telegram.",
    }


# ── Résolution chat_id → utilisateur ──────────────────────────────────────────

def get_user_par_chat_id(chat_id: str, db: Session) -> User | None:
    """Utilisée par le bot à chaque message pour savoir à qui il parle."""
    lien = db.query(TelegramLink).filter(
        TelegramLink.chat_id == chat_id,
        TelegramLink.actif.is_(True),
    ).first()
    if not lien:
        return None
    return db.query(User).filter(User.id == lien.user_id).first()


# ── Déliaison ─────────────────────────────────────────────────────────────────

def delier_compte(user_id: int, db: Session) -> bool:
    """Désactive le lien sans supprimer l'historique."""
    lien = db.query(TelegramLink).filter(
        TelegramLink.user_id == user_id,
        TelegramLink.actif.is_(True),
    ).first()
    if not lien:
        return False
    lien.actif = False
    db.commit()
    return True


# ── Envoi d'un message Telegram ───────────────────────────────────────────────

def envoyer_message_telegram(chat_id: str, text: str, html: bool = True) -> bool:
    """Envoie un message via l'API Bot Telegram. html=False pour du texte brut
    (utile pour les réponses IA qui peuvent contenir des caractères < > &)."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return False
    payload = {"chat_id": chat_id, "text": text}
    if html:
        payload["parse_mode"] = "HTML"
    try:
        resp = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload, timeout=10,
        )
        return resp.status_code == 200
    except Exception:
        return False


def envoyer_action_typing(chat_id: str) -> None:
    """Affiche « en train d'écrire… » côté Telegram pendant la génération."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/sendChatAction",
            json={"chat_id": chat_id, "action": "typing"}, timeout=5,
        )
    except Exception:
        pass


def envoyer_clavier(chat_id: str, text: str, clavier: list, html: bool = True) -> bool:
    """Envoie un message avec un clavier de boutons inline.
    clavier : liste de lignes, chaque ligne = liste de {'text':..., 'data':...}."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return False
    inline = [[{"text": b["text"], "callback_data": b["data"]} for b in ligne] for ligne in clavier]
    payload = {"chat_id": chat_id, "text": text, "reply_markup": {"inline_keyboard": inline}}
    if html:
        payload["parse_mode"] = "HTML"
    try:
        resp = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload, timeout=10,
        )
        return resp.status_code == 200
    except Exception:
        return False


def repondre_callback(callback_id: str) -> None:
    """Acquitte l'appui sur un bouton (retire l'animation de chargement)."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return
    try:
        httpx.post(
            f"https://api.telegram.org/bot{token}/answerCallbackQuery",
            json={"callback_query_id": callback_id}, timeout=5,
        )
    except Exception:
        pass

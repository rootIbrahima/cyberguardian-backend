"""
Webhook Telegram — reçoit messages et appuis sur boutons (callbacks).
- /start <code> : liaison du compte
- scans / statut / problèmes / aide : commandes directes (sans IA, instantanées)
- boutons inline : Mes scans · Dernier score · Derniers problèmes · Contacter un expert
- un client ayant plusieurs scans peut choisir lequel consulter via « Mes scans »
- question libre : réponse IA (Ollama) en tâche de fond, avec mémoire de conversation
Renvoie toujours 200 à Telegram, sinon Telegram réessaie.
"""

import httpx
from fastapi import APIRouter, Request, Depends, BackgroundTasks
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from models import Scan, TelegramMessage
from config import OLLAMA_URL, OLLAMA_KEY, OLLAMA_MODEL
from services.telegram_liaison import (
    verifier_code_et_lier,
    get_user_par_chat_id,
    envoyer_message_telegram,
    envoyer_action_typing,
    envoyer_clavier,
    repondre_callback,
)

router = APIRouter(prefix="/telegram", tags=["telegram"])

# Clavier de boutons proposé après la liaison et avec l'aide
CLAVIER = [
    [{"text": "🗂 Mes scans",           "data": "scans"}],
    [{"text": "📊 Dernier score",       "data": "score"}],
    [{"text": "📋 Derniers problèmes",  "data": "problemes"}],
    [{"text": "👤 Contacter un expert", "data": "expert"}],
]

ACCUEIL = (
    "👋 <b>Bienvenue sur CyberGuardian</b>\n\n"
    "Pour lier votre compte :\n"
    "1. Connectez-vous sur CyberGuardian\n"
    "2. Allez dans Paramètres\n"
    "3. Cliquez sur « Lier Telegram »\n"
    "4. Utilisez le code généré"
)

LIAISON_OK = (
    "✅ <b>Compte lié avec succès</b>\n\n"
    "Vous recevrez désormais vos alertes de sécurité ici.\n"
    "Utilisez les boutons ci-dessous, ou posez vos questions en langage naturel."
)

AIDE = (
    "<b>Que puis-je faire pour vous ?</b>\n\n"
    "• <b>scans</b> — choisir parmi vos scans\n"
    "• <b>statut</b> — score de votre dernier scan\n"
    "• <b>problèmes</b> — problèmes de votre dernier scan\n"
    "• <b>aide</b> — affiche ce message\n\n"
    "Posez aussi vos questions en langage naturel (ex. « comment corriger le HSTS ? »)."
)


@router.post("/webhook")
async def telegram_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    try:
        body = await request.json()
    except Exception:
        return {"ok": True}

    # ── Appui sur un bouton inline ────────────────────────────────────────────
    callback = body.get("callback_query")
    if callback:
        repondre_callback(callback.get("id", ""))
        data    = callback.get("data", "")
        chat_id = str(callback.get("from", {}).get("id", ""))
        user    = get_user_par_chat_id(chat_id, db)
        if not user:
            envoyer_message_telegram(chat_id, "🔒 Compte non lié. Tapez /start.")
        elif data == "scans":
            _lister_scans(chat_id, user.id, db)
        elif data == "score":
            _envoyer_statut(chat_id, user.id, db)
        elif data == "problemes":
            _lister_problemes(chat_id, user.id, db)
        elif data == "expert":
            _contacter_expert(chat_id)
        elif data.startswith("scan:"):
            _envoyer_statut(chat_id, user.id, db, scan_id=_int(data[5:]))
        elif data.startswith("probscan:"):
            _lister_problemes(chat_id, user.id, db, scan_id=_int(data[9:]))
        return {"ok": True}

    # ── Message texte ─────────────────────────────────────────────────────────
    message = body.get("message", {})
    text    = (message.get("text") or "").strip()
    chat_id = str(message.get("from", {}).get("id", ""))
    if not chat_id:
        return {"ok": True}

    if text.startswith("/start"):
        parties = text.split()
        if len(parties) == 1:
            envoyer_message_telegram(chat_id, ACCUEIL)
        else:
            resultat = verifier_code_et_lier(parties[1], chat_id, db)
            if resultat["succes"]:
                envoyer_clavier(chat_id, LIAISON_OK, CLAVIER)
            else:
                envoyer_message_telegram(
                    chat_id,
                    f"❌ {resultat['erreur']}\n\n"
                    "Retournez sur CyberGuardian pour générer un nouveau code.",
                )
        return {"ok": True}

    _handle_message(chat_id, text, db, background_tasks)
    return {"ok": True}


def _handle_message(chat_id: str, text: str, db: Session, background_tasks: BackgroundTasks):
    user = get_user_par_chat_id(chat_id, db)
    if not user:
        envoyer_message_telegram(
            chat_id,
            "🔒 Votre compte n'est pas encore lié. Tapez /start ou liez-le "
            "depuis CyberGuardian (Paramètres).",
        )
        return

    cmd = text.lower()
    if cmd in ("aide", "/aide", "help", "menu", "/menu"):
        envoyer_clavier(chat_id, AIDE, CLAVIER)
        return

    if cmd in ("scans", "/scans", "mes scans", "liste"):
        _lister_scans(chat_id, user.id, db)
        return

    if cmd in ("statut", "/statut", "score", "/score"):
        _envoyer_statut(chat_id, user.id, db)
        return

    # Demande de liste des problèmes → réponse déterministe (instantanée, complète)
    if cmd in ("problemes", "/problemes", "problèmes", "/problèmes") or \
       any(k in cmd for k in ("probleme", "problème", "faille", "vulnérab", "vulnerab")):
        _lister_problemes(chat_id, user.id, db)
        return

    # Question libre → réponse IA (Ollama) en tâche de fond, avec mémoire
    envoyer_action_typing(chat_id)
    background_tasks.add_task(_repondre_ia, chat_id, user.id, text)


# ── Commandes déterministes (sans IA) ─────────────────────────────────────────

_ORDRE_SEV = {"CRITIQUE": 0, "CRITICAL": 0, "HAUT": 1, "HIGH": 1,
              "MOYEN": 2, "MEDIUM": 2, "MODERATE": 2, "BAS": 3, "LOW": 3, "INFO": 4}


def _int(s: str):
    """Convertit en entier ou renvoie None (callback_data manipulé)."""
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


def _scan_du_client(user_id: int, db: Session, scan_id=None):
    """Renvoie le scan demandé s'il appartient au client, sinon le plus récent."""
    q = db.query(Scan).filter(Scan.user_id == user_id)
    if scan_id is not None:
        return q.filter(Scan.id == scan_id).first()
    return q.order_by(Scan.id.desc()).first()


def _lister_scans(chat_id: str, user_id: int, db: Session):
    """Liste les scans du client sous forme de boutons : il choisit lequel consulter."""
    scans = (db.query(Scan).filter(Scan.user_id == user_id)
             .order_by(Scan.id.desc()).limit(8).all())
    if not scans:
        envoyer_message_telegram(
            chat_id, "Aucun scan disponible. Lancez un scan depuis CyberGuardian.")
        return
    boutons = [[{"text": f"{d['target'][:32]} · {d['score']}/100", "data": f"scan:{d['id']}"}]
               for d in (s.to_dict() for s in scans)]
    envoyer_clavier(chat_id, f"🗂 <b>Vos scans récents</b> ({len(scans)}) — choisissez-en un :", boutons)


def _envoyer_statut(chat_id: str, user_id: int, db: Session, scan_id=None):
    scan = _scan_du_client(user_id, db, scan_id)
    if not scan:
        envoyer_message_telegram(chat_id, "Scan introuvable pour votre compte.")
        return
    d = scan.to_dict()
    suffixe = "" if scan_id else "  (dernier scan — tapez « scans » pour en choisir un autre)"
    envoyer_clavier(
        chat_id,
        f"📊 <b>{d['target']}</b>\nScore : <b>{d['score']}/100</b>\n"
        f"Problèmes détectés : {d['vulns']}\nScan du {d['date']}{suffixe}",
        [[{"text": "📋 Voir les problèmes", "data": f"probscan:{d['id']}"}]],
    )


def _lister_problemes(chat_id: str, user_id: int, db: Session, scan_id=None):
    """Liste exhaustive des problèmes d'un scan, triés par sévérité —
    sans IA : instantané et toujours complet."""
    scan = _scan_du_client(user_id, db, scan_id)
    if not scan:
        envoyer_message_telegram(chat_id, "Scan introuvable pour votre compte.")
        return
    d = scan.to_dict()
    issues = d.get("issues", [])
    if not issues:
        envoyer_message_telegram(
            chat_id, f"✅ Aucun problème détecté sur {d['target']} — bonne posture de sécurité.")
        return

    issues = sorted(issues, key=lambda i: _ORDRE_SEV.get((i.get("severity") or "").upper(), 5))
    lignes = [f"📋 <b>{d['target']}</b> — {len(issues)} problème(s) détecté(s) :\n"]
    for n, iss in enumerate(issues, 1):
        sev = (iss.get("severity") or "").upper()
        lignes.append(f"{n}. [{sev}] {iss.get('title', '')}")
    lignes.append("\nPosez une question (ex. « comment corriger le HSTS ? ») pour des conseils détaillés.")
    envoyer_message_telegram(chat_id, "\n".join(lignes))


def _contacter_expert(chat_id: str):
    envoyer_message_telegram(
        chat_id,
        "👤 <b>Contacter un expert</b>\n\n"
        "Nos experts validés (identité et diplôme vérifiés) peuvent vous accompagner "
        "pour corriger les problèmes détectés.\n\n"
        "Connectez-vous sur CyberGuardian, ouvrez le menu <b>Experts</b>, choisissez "
        "un expert et démarrez une mission sécurisée.",
    )


# ── Réponse IA avec mémoire de conversation ───────────────────────────────────

def _contexte_scan(scan_dict: dict) -> str:
    r       = scan_dict.get("results", {}) or {}
    target  = scan_dict.get("target", "—")
    score   = scan_dict.get("score", 0)
    lines   = [f"Cible : {target}", f"Score global : {score}/100"]

    breakdown = (r.get("score_detail") or {}).get("breakdown", [])
    if breakdown:
        lines.append("Détail du score : " + ", ".join(
            f"{b['label'].split(' ')[0]} {b['points']}/{b['max']}" for b in breakdown))

    issues = scan_dict.get("issues", [])
    if issues:
        lines.append(f"Problèmes détectés ({len(issues)}) :")
        for i in issues[:12]:
            lines.append(f"  - [{i.get('severity', '')}] {i.get('title', '')}")

    cves = r.get("cves", [])
    if cves:
        urgentes = sum(1 for c in cves if c.get("priority") == "URGENTE")
        lines.append(f"CVE identifiées : {len(cves)}" +
                     (f" dont {urgentes} URGENTE(s)" if urgentes else ""))

    return "\n".join(lines)


def _historique(user_id: int, db: Session) -> str:
    """Les 6 derniers messages de la conversation (mémoire)."""
    msgs = (db.query(TelegramMessage)
            .filter(TelegramMessage.user_id == user_id)
            .order_by(TelegramMessage.id.desc()).limit(6).all())
    if not msgs:
        return ""
    msgs = list(reversed(msgs))
    lignes = [("Client" if m.role == "user" else "Assistant") + " : " + (m.content or "")[:300]
              for m in msgs]
    return "Historique récent de la conversation :\n" + "\n".join(lignes) + "\n\n"


def _repondre_ia(chat_id: str, user_id: int, question: str):
    """Tâche de fond : contexte du scan + historique → Ollama → réponse + mémorisation."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.user_id == user_id).order_by(Scan.id.desc()).first()
        contexte   = _contexte_scan(scan.to_dict()) if scan else "Aucun scan disponible."
        historique = _historique(user_id, db)
        prompt = (
            "Tu es un expert en cybersécurité qui conseille des PME sénégalaises. "
            "Voici les résultats du dernier scan de sécurité du client :\n"
            f"{contexte}\n\n"
            f"{historique}"
            "Réponds à la nouvelle question en français simple, sans jargon, en t'appuyant "
            "sur ces résultats réels et sur l'historique. Sois concis (3 à 5 phrases) pour "
            "une question générale ; énumère clairement si on te demande la liste des "
            "problèmes. Donne un conseil concret quand c'est pertinent. "
            "Écris en texte simple, sans formatage Markdown ni astérisques.\n"
            f"Nouvelle question : {question}"
        )
        try:
            resp = httpx.post(
                f"{OLLAMA_URL}/api/generate",
                headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
                      "think": False,
                      "options": {"num_predict": 500, "temperature": 0.6}},
                timeout=httpx.Timeout(connect=15.0, read=180.0, write=15.0, pool=5.0),
            )
            resp.raise_for_status()
            answer = (resp.json().get("response") or "").strip()
        except Exception:
            answer = ""

        if not answer:
            answer = ("Le service d'analyse est momentanément indisponible. "
                      "Réessayez dans un instant, ou tapez « statut » pour votre score.")
        answer = answer.replace("**", "")

        # Mémorise l'échange (question + réponse)
        db.add(TelegramMessage(user_id=user_id, role="user", content=question[:2000]))
        db.add(TelegramMessage(user_id=user_id, role="assistant", content=answer[:2000]))
        db.commit()

        envoyer_message_telegram(chat_id, answer, html=False)
    finally:
        db.close()

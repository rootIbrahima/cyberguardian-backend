"""
Service de notification : couche d'abstraction au-dessus d'Apprise.
Découple le code métier (remédiation, missions, candidatures...) du canal de
notification réellement utilisé. Aujourd'hui, seul Telegram est configuré (le
chat_id de l'utilisateur est résolu dynamiquement) ; ajouter un canal
supplémentaire (e-mail, Slack...) ne demande qu'une URL dans APPRISE_URLS,
sans toucher aux appelants. Même logique que le fallback multi-LLM du CDC,
appliquée aux notifications sortantes.
"""

import threading

import apprise
from sqlalchemy import event
from sqlalchemy.orm import Session

from config import APPRISE_URLS, TELEGRAM_BOT_TOKEN
from database import SessionLocal
from services.telegram_liaison import get_chat_id_par_user


def _canaux_statiques() -> list[str]:
    """URLs Apprise fixes issues de la configuration (.env), en plus de Telegram."""
    return [u.strip() for u in APPRISE_URLS.split(",") if u.strip()]


def notifier_utilisateur(user_id: int, titre: str, message: str, db: Session) -> bool:
    """Pousse une notification à un utilisateur sur tous ses canaux disponibles :
    Telegram s'il a lié son compte, plus les canaux statiques de APPRISE_URLS.
    Renvoie False si aucun canal n'est joignable, l'appelant ne doit jamais
    bloquer sur ce retour (la notification est un à-côté, pas le résultat métier)."""
    apobj = apprise.Apprise()

    chat_id = get_chat_id_par_user(user_id, db)
    if chat_id and TELEGRAM_BOT_TOKEN:
        apobj.add(f"tgram://{TELEGRAM_BOT_TOKEN}/{chat_id}")

    for url in _canaux_statiques():
        apobj.add(url)

    if len(apobj) == 0:
        return False

    return apobj.notify(body=message, title=titre)


def _pousser(user_id: int, titre: str, message: str) -> None:
    """Envoi effectif, hors du fil de la requête, avec sa propre session : celle
    de la requête est refermée avant que ce fil ne s'exécute."""
    db = SessionLocal()
    try:
        notifier_utilisateur(user_id, titre, message, db)
    except Exception as e:
        print(f"  [!] notification externe non remise à l'utilisateur {user_id} : {e}")
    finally:
        db.close()


def notifier_apres_commit(db: Session, user_id: int, titre: str, message: str) -> None:
    """Programme l'envoi externe pour l'instant où la transaction sera validée.

    Envoyer immédiatement préviendrait d'un événement encore susceptible d'être
    annulé. Envoyer dans le fil de la requête ferait attendre l'appelant le
    temps d'un aller-retour Telegram ou SMTP, alors qu'une notification est un
    à-côté : elle ne doit jamais peser sur la réponse rendue à l'utilisateur."""
    def au_commit(_session):
        threading.Thread(target=_pousser, args=(user_id, titre, message), daemon=True).start()

    event.listen(db, "after_commit", au_commit, once=True)

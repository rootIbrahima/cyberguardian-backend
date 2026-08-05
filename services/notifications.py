"""
Service de notification — couche d'abstraction au-dessus d'Apprise.
Découple le code métier (remédiation, missions, candidatures...) du canal de
notification réellement utilisé. Aujourd'hui, seul Telegram est configuré (le
chat_id de l'utilisateur est résolu dynamiquement) ; ajouter un canal
supplémentaire (e-mail, Slack...) ne demande qu'une URL dans APPRISE_URLS,
sans toucher aux appelants. Même logique que le fallback multi-LLM du CDC,
appliquée aux notifications sortantes.
"""

import apprise
from sqlalchemy.orm import Session

from config import APPRISE_URLS, TELEGRAM_BOT_TOKEN
from services.telegram_liaison import get_chat_id_par_user


def _canaux_statiques() -> list[str]:
    """URLs Apprise fixes issues de la configuration (.env), en plus de Telegram."""
    return [u.strip() for u in APPRISE_URLS.split(",") if u.strip()]


def notifier_utilisateur(user_id: int, titre: str, message: str, db: Session) -> bool:
    """Pousse une notification à un utilisateur sur tous ses canaux disponibles :
    Telegram s'il a lié son compte, plus les canaux statiques de APPRISE_URLS.
    Renvoie False si aucun canal n'est joignable — l'appelant ne doit jamais
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

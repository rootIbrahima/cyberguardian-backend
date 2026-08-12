"""
Service de notification : couche d'abstraction au-dessus d'Apprise.
Découple le code métier (remédiation, missions, candidatures...) du canal de
notification réellement utilisé. Deux canaux personnels sont résolus à l'envoi
pour chaque destinataire, Telegram s'il a lié son compte et l'e-mail de son
compte s'il l'a laissé actif ; s'y ajoutent les canaux d'exploitation fixes de
APPRISE_URLS. Un canal supplémentaire se branche ici sans toucher aux
appelants. Même logique que le fallback multi-LLM du CDC, appliquée aux
notifications sortantes.
"""

import threading
from html import escape
from urllib.parse import quote

import apprise
from apprise.common import NotifyFormat
from sqlalchemy import event
from sqlalchemy.orm import Session

from config import (APPRISE_URLS, SMTP_FROM, SMTP_HOST, SMTP_PASSWORD,
                    SMTP_PORT, SMTP_USER, TELEGRAM_BOT_TOKEN)
from database import SessionLocal
from models import User
from services.telegram_liaison import get_chat_id_par_user


def _canaux_statiques() -> list[str]:
    """URLs Apprise fixes issues de la configuration (.env), en plus de Telegram."""
    return [u.strip() for u in APPRISE_URLS.split(",") if u.strip()]


def _url_email(destinataire: str) -> str | None:
    """URL Apprise du canal e-mail pour une adresse donnée, None si la
    plateforme n'a pas de compte d'envoi configuré.

    Les identifiants sont ceux de la plateforme et sont encodés : un caractère
    réservé dans le mot de passe couperait l'URL en deux et Apprise se
    connecterait au mauvais serveur, ou à aucun."""
    if not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD):
        return None
    identifiants = f"{quote(SMTP_USER, safe='')}:{quote(SMTP_PASSWORD, safe='')}"
    return (
        f"mailtos://{identifiants}@{SMTP_HOST}:{SMTP_PORT}"
        f"?to={quote(destinataire)}"
        f"&from={quote(SMTP_FROM or SMTP_USER)}"
        f"&name=CyberGuardian"
    )


def _en_html(texte: str) -> str:
    """Texte brut vers HTML, le format qu'attendent Telegram comme l'e-mail.

    La conversion est faite ici plutôt que laissée à Apprise, qui remplace
    chaque espace par une entité insécable : le texte ne se replie alors plus
    dans un client de messagerie et déborde de l'écran sur téléphone. Celle-ci
    ne touche qu'aux retours à la ligne, et échappe le reste — un nom de
    fichier ou un titre de CVE contenant « < » casserait sinon le message."""
    return escape(texte).replace("\n", "<br/>\n")


def notifier_utilisateur(user_id: int, titre: str, message: str, db: Session) -> bool:
    """Pousse une notification à un utilisateur sur tous ses canaux disponibles.
    Renvoie False si aucun canal n'est joignable, l'appelant ne doit jamais
    bloquer sur ce retour (la notification est un à-côté, pas le résultat métier)."""
    apobj = apprise.Apprise()

    chat_id = get_chat_id_par_user(user_id, db)
    if chat_id and TELEGRAM_BOT_TOKEN:
        apobj.add(f"tgram://{TELEGRAM_BOT_TOKEN}/{chat_id}")

    utilisateur = db.query(User).filter(User.id == user_id).first()
    if utilisateur and utilisateur.alertes_email:
        url = _url_email(utilisateur.email)
        if url:
            apobj.add(url)

    for url in _canaux_statiques():
        apobj.add(url)

    if len(apobj) == 0:
        return False

    return apobj.notify(body=_en_html(message), title=titre,
                        body_format=NotifyFormat.HTML)


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

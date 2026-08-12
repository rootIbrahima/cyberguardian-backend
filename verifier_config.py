"""
Contrôle des URL publiques après un déploiement.

Une valeur d'URL peut être syntaxiquement correcte et pointer nulle part. Trois
pannes l'ont montré le même jour : le webhook Telegram déclaré sans le préfixe
/api, le lien de liaison construit vers un bot inexistant, le retour OAuth
GitHub refusé pour la même raison. Aucune ne se voyait au démarrage, toutes se
sont manifestées par un silence — un bot muet, une page d'avertissement — des
heures après la mise en ligne.

Ce script ne lit pas la configuration : il l'emprunte. Chaque URL est appelée
pour de bon, et on regarde qui répond.

Usage, depuis le dossier backend/ :
    python verifier_config.py

À jouer après chaque déploiement, et chaque fois qu'une URL publique change.
Aucun effet de bord : uniquement des requêtes de lecture.
"""

import sys

import httpx

from config import (FRONTEND_URL, GITHUB_CLIENT_ID, PUBLIC_BASE_URL,
                    SMTP_HOST, SMTP_PASSWORD, SMTP_USER,
                    TELEGRAM_BOT_TOKEN, TELEGRAM_BOT_USERNAME,
                    incoherences)

OK, ECHEC, PASSE = "  [ok] ", "  [!!] ", "  [--] "


def _titre(texte: str) -> None:
    print(f"\n{texte}")


def verifier_backend_public() -> bool:
    """PUBLIC_BASE_URL atteint-elle vraiment cette API ?

    C'est le contrôle décisif. Une URL qui renvoie du HTML désigne le serveur
    de fichiers statiques et non FastAPI : le préfixe du reverse proxy manque,
    et tout ce qui repose sur un retour externe échouera."""
    _titre("URL publique du backend")
    if not PUBLIC_BASE_URL:
        print(PASSE + "PUBLIC_BASE_URL vide, l'autorisation GitHub est désactivée")
        return True

    cible = f"{PUBLIC_BASE_URL}/openapi.json"
    try:
        reponse = httpx.get(cible, timeout=25)
    except Exception as e:
        print(ECHEC + f"{cible} injoignable ({type(e).__name__})")
        return False

    type_contenu = reponse.headers.get("content-type", "")
    if reponse.status_code == 200 and "json" in type_contenu:
        titre = reponse.json().get("info", {}).get("title", "?")
        print(OK + f"{PUBLIC_BASE_URL} atteint bien l'API ({titre})")
        return True

    print(ECHEC + f"{cible} renvoie {reponse.status_code} en {type_contenu or 'type inconnu'}")
    # La cause se lit dans le code de réponse, et s'y tromper enverrait chercher
    # au mauvais endroit : un 502 ne dit rien de l'URL, seulement que rien
    # n'écoute derrière le proxy.
    if reponse.status_code in (502, 503, 504):
        print("       Le proxy répond mais rien n'écoute derrière : le backend")
        print("       est-il démarré, et sur le port que le proxy interroge ?")
    elif "html" in type_contenu:
        print("       Cette URL mène au serveur de fichiers, pas à FastAPI.")
        print("       Il y manque le préfixe du reverse proxy, /api en production.")
    elif reponse.status_code == 404:
        print("       Le backend répond mais ignore cette route : le préfixe")
        print("       de l'URL ne correspond pas à celui qu'attend le proxy.")
    return False


def verifier_frontend() -> bool:
    """FRONTEND_URL doit servir le site, donc du HTML, et non l'API."""
    _titre("URL du frontend")
    try:
        reponse = httpx.get(FRONTEND_URL, timeout=25)
    except Exception as e:
        print(ECHEC + f"{FRONTEND_URL} injoignable ({type(e).__name__})")
        return False

    if reponse.status_code == 200 and "html" in reponse.headers.get("content-type", ""):
        print(OK + f"{FRONTEND_URL} sert bien le site")
        return True
    print(ECHEC + f"{FRONTEND_URL} renvoie {reponse.status_code}, "
                  f"{reponse.headers.get('content-type', 'type inconnu')}")
    print("       C'est là que le client atterrit après avoir autorisé GitHub.")
    return False


def verifier_webhook_telegram() -> bool:
    """Le webhook déclaré chez Telegram doit correspondre à cette installation."""
    _titre("Webhook Telegram")
    if not TELEGRAM_BOT_TOKEN:
        print(PASSE + "TELEGRAM_BOT_TOKEN vide, canal désactivé")
        return True

    try:
        api = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
        bot = httpx.get(f"{api}/getMe", timeout=25).json().get("result", {})
        info = httpx.get(f"{api}/getWebhookInfo", timeout=25).json().get("result", {})
    except Exception as e:
        print(ECHEC + f"API Telegram injoignable ({type(e).__name__})")
        return False

    reel = bot.get("username", "")
    if reel and TELEGRAM_BOT_USERNAME != reel:
        print(ECHEC + f"TELEGRAM_BOT_USERNAME vaut « {TELEGRAM_BOT_USERNAME} » "
                      f"alors que le bot est @{reel}")
        print("       Les liens de liaison mèneront vers un bot qui n'est pas le vôtre.")
        return False
    print(OK + f"bot @{reel}, nom d'utilisateur conforme")

    declare = info.get("url") or ""
    erreur  = info.get("last_error_message")
    attendu = f"{PUBLIC_BASE_URL}/telegram/webhook" if PUBLIC_BASE_URL else None

    if not declare:
        print(ECHEC + "aucun webhook déclaré, le bot ne recevra rien")
        return False
    if attendu and declare != attendu:
        print(ECHEC + f"webhook déclaré sur {declare}")
        print(f"       alors que cette installation répond sur {attendu}")
        print("       Rejouez : python enregistrer_webhook.py " + PUBLIC_BASE_URL)
        return False
    print(OK + f"webhook déclaré sur {declare}")

    if erreur:
        print(ECHEC + f"dernière livraison en erreur : {erreur}")
        if "405" in erreur:
            print("       Le POST atteint le serveur web et non FastAPI.")
        return False
    print(OK + f"aucune erreur de livraison, {info.get('pending_update_count', 0)} en attente")
    return True


def verifier_github() -> bool:
    """L'URL de retour attendue par GitHub se règle sur son site : on ne peut
    que l'afficher pour comparaison, l'API OAuth ne l'expose pas."""
    _titre("Retour OAuth GitHub")
    if not GITHUB_CLIENT_ID:
        print(PASSE + "GITHUB_CLIENT_ID vide, canal désactivé")
        return True
    if not PUBLIC_BASE_URL:
        print(ECHEC + "GITHUB_CLIENT_ID renseigné sans PUBLIC_BASE_URL, l'autorisation renverra 503")
        return False
    print(OK + "cette installation enverra l'URL de retour suivante :")
    print(f"         {PUBLIC_BASE_URL}/github/callback")
    print("       Elle doit figurer au caractère près dans « Authorization callback URL »")
    print("       sur https://github.com/settings/developers")
    return True


def verifier_email() -> bool:
    _titre("Canal e-mail")
    if not SMTP_HOST:
        print(PASSE + "SMTP_HOST vide, les alertes ne partiront que sur Telegram")
        return True
    if not (SMTP_USER and SMTP_PASSWORD):
        print(ECHEC + "SMTP_HOST renseigné mais SMTP_USER ou SMTP_PASSWORD manque")
        return False
    print(OK + f"compte d'envoi {SMTP_USER} sur {SMTP_HOST}")
    return True


if __name__ == "__main__":
    print("=== Vérification de la configuration CyberGuardian ===")

    ecarts = incoherences()
    if ecarts:
        _titre("Cohérence du fichier .env")
        for ecart in ecarts:
            print(ECHEC + ecart)

    resultats = [
        verifier_backend_public(),
        verifier_frontend(),
        verifier_webhook_telegram(),
        verifier_github(),
        verifier_email(),
    ]

    echecs = resultats.count(False) + (1 if ecarts else 0)
    print()
    if echecs:
        print(f"{echecs} point(s) à corriger.")
        sys.exit(1)
    print("Configuration cohérente, toutes les URL publiques répondent.")

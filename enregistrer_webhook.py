"""
Enregistre le webhook Telegram avec son secret d'authentification.

À rejouer à chaque fois que l'URL publique change : sur l'offre gratuite ngrok,
c'est-à-dire à chaque redémarrage du tunnel. L'URL est détectée automatiquement
via l'API locale de ngrok, ou passée en argument.

Usage (depuis le dossier backend/) :
    python enregistrer_webhook.py                      # détection auto via ngrok
    python enregistrer_webhook.py https://mon-domaine  # URL explicite

L'URL doit être celle qui atteint réellement FastAPI depuis l'extérieur, préfixe
de reverse proxy compris. En production, nginx expose l'API sous /api :

    https://cyberguardian.207-180-196-65.nip.io/api

Le webhook y a été déclaré sans ce préfixe pendant un temps ; les messages
tombaient alors sur le gestionnaire de fichiers statiques, qui refuse le POST,
et plus personne ne pouvait lier son compte. Rien ne le signalait côté
plateforme, l'erreur n'étant visible que dans getWebhookInfo.

Le secret n'est jamais affiché ni saisi au clavier : il est lu depuis .env.
"""

import sys

import httpx
from dotenv import dotenv_values

NGROK_API = "http://127.0.0.1:4040/api/tunnels"


def url_publique_ngrok() -> str | None:
    """Interroge l'agent ngrok local pour récupérer l'URL HTTPS du tunnel."""
    try:
        tunnels = httpx.get(NGROK_API, timeout=5).json().get("tunnels", [])
    except Exception:
        return None
    for t in tunnels:
        if t.get("public_url", "").startswith("https://"):
            return t["public_url"]
    return None


def main() -> int:
    config = dotenv_values(".env")
    token  = config.get("TELEGRAM_BOT_TOKEN", "")
    secret = config.get("TELEGRAM_WEBHOOK_SECRET", "")

    if not token:
        print("TELEGRAM_BOT_TOKEN absent de .env : impossible de continuer.")
        return 1
    if not secret:
        print("TELEGRAM_WEBHOOK_SECRET absent de .env : le webhook accepterait "
              "n'importe quelle requête. Renseignez-le avant d'enregistrer.")
        return 1

    base = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else url_publique_ngrok()
    if not base:
        print("Aucune URL publique trouvée.")
        print("Démarrez le tunnel (ngrok http 8001) ou passez l'URL en argument :")
        print("    python enregistrer_webhook.py https://votre-domaine")
        return 1

    url = f"{base}/telegram/webhook"
    print(f"Enregistrement du webhook : {url}")

    r = httpx.post(
        f"https://api.telegram.org/bot{token}/setWebhook",
        # Les mises à jour en attente sont des tentatives de liaison bien
        # réelles, accumulées pendant que le webhook était injoignable : les
        # jeter les ferait disparaître sans trace. Un code périmé qui se rejoue
        # est simplement refusé, ce qui est moins grave qu'une demande perdue.
        data={"url": url, "secret_token": secret,
              "drop_pending_updates": "false"},
        timeout=20,
    )
    reponse = r.json()
    if not reponse.get("ok"):
        print("Échec :", reponse.get("description", reponse))
        return 1

    infos = httpx.get(f"https://api.telegram.org/bot{token}/getWebhookInfo",
                      timeout=15).json().get("result", {})
    print("Webhook enregistré.")
    print("  url               :", infos.get("url"))
    print("  maj en attente    :", infos.get("pending_update_count", 0))
    erreur = infos.get("last_error_message")
    print("  dernière erreur   :", erreur or "aucune")
    if erreur and "405" in erreur:
        print("                      le POST atteint le serveur web et non FastAPI :")
        print("                      le préfixe du reverse proxy manque dans l'URL")

    if base != config.get("PUBLIC_BASE_URL", "").rstrip("/"):
        print()
        print("Pensez à aligner PUBLIC_BASE_URL dans .env sur cette même URL :")
        print(f"    PUBLIC_BASE_URL={base}")
        print("Sans cela, le retour d'autorisation OAuth GitHub échouera.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

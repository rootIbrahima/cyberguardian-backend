"""
Configuration centralisée : toutes les valeurs sensibles viennent du fichier
.env (jamais dans le code, conformément au CDC §6.2).
"""

import os

from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_KEY   = os.getenv("OLLAMA_KEY", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:latest")

# Durée pendant laquelle Ollama garde le modèle chargé en mémoire GPU après une
# requête. Par défaut il le décharge au bout de 5 minutes, si bien que le
# premier client de la journée attend le rechargement complet (≈ 15 s pour un
# modèle de 14 Go). « -1 » le maintient en permanence : la mémoire est occupée
# en continu, mais aucune requête ne paie le démarrage.
# Ollama attend soit un entier de secondes (-1 pour « indéfiniment »), soit une
# durée avec unité (« 30m », « 24h »). Une chaîne « -1 » est refusée : le
# serveur répond « missing unit in duration ». La valeur est donc convertie.
_keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "-1").strip()
try:
    OLLAMA_KEEP_ALIVE = int(_keep_alive)
except ValueError:
    OLLAMA_KEEP_ALIVE = _keep_alive

# Modèle de secours, sollicité uniquement lorsque le serveur d'inférence de
# l'UN-CHK ne répond pas. Il parle le dialecte OpenAI, que presque tous les
# fournisseurs exposent, si bien qu'on change de fournisseur sans toucher au
# code. Exemples d'URL :
#     Mistral   https://api.mistral.ai/v1          mistral-small-latest
#     Groq      https://api.groq.com/openai/v1     llama-3.3-70b-versatile
#     Gemini    https://generativelanguage.googleapis.com/v1beta/openai
#     OpenAI    https://api.openai.com/v1          gpt-4o-mini
#
# Laissé vide, le comportement est inchangé : source première seule. Les invites
# portent les ports ouverts et les secrets exposés de nos clients ; ces données
# ne quittent le pays qu'en cas de panne, jamais par défaut.
LLM_SECOURS_URL   = os.getenv("LLM_SECOURS_URL", "").rstrip("/")
LLM_SECOURS_KEY   = os.getenv("LLM_SECOURS_KEY", "")
LLM_SECOURS_MODEL = os.getenv("LLM_SECOURS_MODEL", "")

# Plafond de scans par cible et par 24 h (CDC §7.1). 0 désactive la limite.
QUOTA_SCANS_PAR_CIBLE = int(os.getenv("QUOTA_SCANS_PAR_CIBLE", "0"))

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cg-dev-only-secret")

# Comptes de démonstration créés par seed.py. Aucune valeur par défaut ici :
# le dépôt est public, un mot de passe écrit dans le code serait lisible par
# n'importe qui. Vide, seed.py en tire un au sort et l'affiche une fois.
SEED_ADMIN_PASSWORD  = os.getenv("SEED_ADMIN_PASSWORD", "")
SEED_EXPERT_PASSWORD = os.getenv("SEED_EXPERT_PASSWORD", "")
SEED_CLIENT_PASSWORD = os.getenv("SEED_CLIENT_PASSWORD", "")

# Chiffrement au repos des secrets stockés en base (jeton OAuth GitHub).
# Générer avec : python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")

# Bot Telegram (notifications et support multi-canal)
TELEGRAM_BOT_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_BOT_USERNAME   = os.getenv("TELEGRAM_BOT_USERNAME", "CyberGuardianBot")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")

# OAuth GitHub : « Connecter GitHub » : le client autorise la correction assistée
# de ses dépôts (l'agent ouvre une Pull Request, jamais de push direct).
GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
# URL publique du backend, cible du callback OAuth. Elle doit désigner ce qui
# atteint réellement FastAPI depuis l'extérieur, préfixe du reverse proxy
# compris : en production nginx expose l'API sous /api, et l'oublier envoie le
# callback sur les fichiers statiques. La barre finale est retirée, sans quoi
# l'URL construite comporterait un double séparateur.
PUBLIC_BASE_URL      = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")
# URL du frontend, pour rediriger le client après l'autorisation. Celle-ci
# désigne le site, servi à la racine : elle ne porte pas le préfixe /api.
FRONTEND_URL         = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")

# Réputation (cinquième critère du score) : clés gratuites après inscription.
#   https://www.virustotal.com/gui/my-apikey
#   https://www.abuseipdb.com/account/api
# Sans clé, le critère est exclu du score au lieu d'être compté à zéro.
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

# Canaux de notification additionnels (Apprise), voir services/notifications.py.
# Liste d'URLs séparées par des virgules (ex. mailto://user:motdepasse@gmail.com,
# slack://TokenA/TokenB/TokenC/#canal). Ces canaux reçoivent les notifications de
# tous les utilisateurs : ils conviennent à une adresse d'exploitation, pas au
# canal personnel d'un client, qui est résolu à l'envoi.
APPRISE_URLS = os.getenv("APPRISE_URLS", "")

# Compte d'envoi des alertes par e-mail. Il appartient à la plateforme : le
# client ne fournit jamais d'identifiants de messagerie, ses alertes partent
# vers l'adresse de son compte. Sans SMTP_HOST, le canal est simplement absent
# et les notifications continuent de partir sur Telegram.
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = os.getenv("SMTP_PORT", "587")
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "")   # à défaut, SMTP_USER fait l'expéditeur


# ── Cohérence de la configuration ─────────────────────────────────────────────

BOT_PAR_DEFAUT = "CyberGuardianBot"


def _developpement(url: str) -> bool:
    """URL d'un poste de développement : boucle locale ou tunnel temporaire."""
    # Ces chaînes sont des motifs recherchés dans une URL de configuration, non
    # une adresse d'écoute : le code signale une URL de développement, il n'ouvre
    # aucun service. D'où l'exemption du contrôle B104.
    return any(marque in url for marque in
               ("localhost", "127.0.0.1", "0.0.0.0", "ngrok", ".local"))  # nosec B104


def incoherences() -> list[str]:
    """Écarts de configuration qui ne peuvent pas relever d'une intention.

    Trois pannes ont eu la même origine : une valeur de développement laissée
    dans le .env du serveur, ou l'inverse. Aucune ne se voyait au démarrage,
    seulement à l'usage et parfois des heures plus tard. Elles se voient ici.

    La liste n'interrompt pas le démarrage : chacun de ces défauts ne casse
    qu'une fonction — l'autorisation GitHub, la liaison Telegram — alors qu'un
    refus de démarrer priverait les clients de toute la plateforme, scans
    compris. Le remède serait pire que le mal."""
    problemes = []

    if PUBLIC_BASE_URL and FRONTEND_URL and _developpement(PUBLIC_BASE_URL) != _developpement(FRONTEND_URL):
        problemes.append(
            "PUBLIC_BASE_URL et FRONTEND_URL mélangent développement et production.\n"
            f"    PUBLIC_BASE_URL = {PUBLIC_BASE_URL}\n"
            f"    FRONTEND_URL    = {FRONTEND_URL}\n"
            "    L'autorisation GitHub renverra le client sur le mauvais site."
        )

    if TELEGRAM_BOT_TOKEN and TELEGRAM_BOT_USERNAME == BOT_PAR_DEFAUT:
        problemes.append(
            f"TELEGRAM_BOT_USERNAME absent, repli sur @{BOT_PAR_DEFAUT} qui n'est\n"
            "    pas votre bot. Les liens de liaison mèneront ailleurs, personne ne\n"
            "    pourra lier son compte, et rien d'autre ne le signalera."
        )

    if SMTP_HOST and not (SMTP_USER and SMTP_PASSWORD):
        problemes.append(
            "SMTP_HOST est renseigné mais SMTP_USER ou SMTP_PASSWORD manque :\n"
            "    le canal e-mail est inactif et les alertes ne partiront que sur Telegram."
        )

    return problemes


def signaler_incoherences() -> None:
    """Affiche les écarts au démarrage, dans un cadre repérable au milieu des
    lignes d'accès d'uvicorn — c'est là que l'exploitant les cherchera."""
    problemes = incoherences()
    if not problemes:
        return
    print("\n" + "=" * 72)
    print("  CONFIGURATION INCOHÉRENTE".center(72))
    print("=" * 72)
    for probleme in problemes:
        print(f"  [!] {probleme}")
    print("=" * 72 + "\n")

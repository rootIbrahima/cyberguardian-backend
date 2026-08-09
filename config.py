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
# URL publique du backend (tunnel ngrok en dev), cible du callback OAuth
PUBLIC_BASE_URL      = os.getenv("PUBLIC_BASE_URL", "")
# URL du frontend, pour rediriger le client après l'autorisation
FRONTEND_URL         = os.getenv("FRONTEND_URL", "http://localhost:5173")

# Réputation (cinquième critère du score) : clés gratuites après inscription.
#   https://www.virustotal.com/gui/my-apikey
#   https://www.abuseipdb.com/account/api
# Sans clé, le critère est exclu du score au lieu d'être compté à zéro.
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")

# Canaux de notification additionnels (Apprise), voir services/notifications.py.
# Liste d'URLs séparées par des virgules (ex. mailto://user:motdepasse@gmail.com,
# slack://TokenA/TokenB/TokenC/#canal). Vide par défaut : seul Telegram est utilisé.
APPRISE_URLS = os.getenv("APPRISE_URLS", "")

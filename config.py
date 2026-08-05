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

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cg-dev-only-secret")

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

# Canaux de notification additionnels (Apprise), voir services/notifications.py.
# Liste d'URLs séparées par des virgules (ex. mailto://user:motdepasse@gmail.com,
# slack://TokenA/TokenB/TokenC/#canal). Vide par défaut : seul Telegram est utilisé.
APPRISE_URLS = os.getenv("APPRISE_URLS", "")

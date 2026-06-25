"""
Configuration centralisée — toutes les valeurs sensibles viennent du fichier
.env (jamais dans le code, conformément au CDC §6.2).
"""

import os

from dotenv import load_dotenv

load_dotenv()

OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_KEY   = os.getenv("OLLAMA_KEY", "")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:latest")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "cg-dev-only-secret")

# Bot Telegram (notifications et support multi-canal)
TELEGRAM_BOT_TOKEN      = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_BOT_USERNAME   = os.getenv("TELEGRAM_BOT_USERNAME", "CyberGuardianBot")
TELEGRAM_WEBHOOK_SECRET = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")

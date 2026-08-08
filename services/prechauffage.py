"""
Préchargement du modèle de langage au démarrage du serveur.

Ollama décharge un modèle de la mémoire GPU après quelques minutes d'inactivité.
Le client suivant paie alors le rechargement complet, soit une quinzaine de
secondes pour un modèle de 14 Go : inacceptable pour quelqu'un qui vient de
poser une question sur son rapport.

Deux mesures complémentaires :
  - chaque appel transmet keep_alive (voir config.OLLAMA_KEEP_ALIVE), qui
    demande à Ollama de conserver le modèle en mémoire ;
  - une requête minimale est émise au démarrage, pour que le tout premier
    utilisateur n'attende pas non plus.

Le préchargement s'exécute dans un fil séparé et n'échoue jamais bruyamment :
un serveur d'inférence indisponible ne doit pas empêcher la plateforme de
démarrer, les scans et les rapports fonctionnant sans lui.
"""

import threading

import httpx

from config import OLLAMA_URL, OLLAMA_KEY, OLLAMA_MODEL, OLLAMA_KEEP_ALIVE


def _charger() -> None:
    try:
        httpx.post(
            f"{OLLAMA_URL}/api/generate",
            headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
            json={
                "model":      OLLAMA_MODEL,
                "prompt":     "ok",
                "stream":     False,
                "keep_alive": OLLAMA_KEEP_ALIVE,
                "options":    {"num_predict": 1},
            },
            timeout=httpx.Timeout(connect=10.0, read=180.0, write=10.0, pool=5.0),
        )
    except Exception:
        pass   # l'indisponibilité du service d'inférence n'est pas bloquante


def prechauffer_modele() -> None:
    """Lance le préchargement sans retarder le démarrage du serveur."""
    threading.Thread(target=_charger, daemon=True, name="prechauffage-llm").start()

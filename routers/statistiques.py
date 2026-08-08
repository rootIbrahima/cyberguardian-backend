"""
Statistiques publiques affichées sur les pages de connexion et d'inscription.

Volontairement limitées à des agrégats : un total de scans, un nombre d'outils
et un nombre d'experts validés ne révèlent ni identité, ni cible analysée, ni
résultat. C'est la seule route de la plateforme accessible sans authentification
en dehors de la connexion et de l'inscription.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import ExpertProfile, Scan

router = APIRouter(prefix="/stats", tags=["statistiques"])

# Nombre d'outils exposés par le serveur MCP (voir mcp_server.py). Compté à
# l'import plutôt que codé en dur, pour ne pas dériver à chaque outil ajouté.
def _compter_outils_mcp() -> int:
    from pathlib import Path
    fichier = Path(__file__).resolve().parent.parent / "mcp_server.py"
    try:
        return fichier.read_text(encoding="utf-8").count("@mcp.tool")
    except OSError:
        return 0


NB_OUTILS_MCP = _compter_outils_mcp()


@router.get("/publiques")
def statistiques_publiques(db: Session = Depends(get_db)):
    """Agrégats affichés avant connexion. Aucune donnée nominative."""
    return {
        "scans":   db.query(Scan).count(),
        "outils":  NB_OUTILS_MCP,
        "experts": db.query(ExpertProfile)
                     .filter(ExpertProfile.status == "approved").count(),
    }

"""
OAuth GitHub : « Connecter GitHub » et consentement de correction assistée.
Le client autorise CyberGuardian une fois (portée public_repo, moindre
privilège), puis autorise explicitement la correction d'un dépôt précis.
L'agent s'appuiera sur ce jeton pour ouvrir une Pull Request, jamais de push
direct. Le consentement est explicite, par dépôt, et révocable.
"""

import re
import time
from urllib.parse import urlencode

import httpx
from jose import jwt, JWTError
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from database import get_db
from auth import get_current_user
from config import (JWT_SECRET_KEY, GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET,
                    PUBLIC_BASE_URL, FRONTEND_URL)
from models import User, GitHubConnection, RepoAutorisation
from services.chiffrement import chiffrer, dechiffrer

router = APIRouter(prefix="/github", tags=["github"])

GH_AUTHORIZE = "https://github.com/login/oauth/authorize"
GH_TOKEN     = "https://github.com/login/oauth/access_token"
GH_API       = "https://api.github.com"
SCOPE        = "public_repo"   # moindre privilège : dépôts publics du client
STATE_TTL    = 600             # 10 min


class RepoRequest(BaseModel):
    repo_url: str


def _repo_slug(url: str) -> str:
    """Extrait « owner/repo » (minuscules) d'une URL GitHub, quelle que soit la forme."""
    if not url:
        return ""
    m = re.search(r"github\.com[:/]+([^/]+)/([^/]+?)(?:\.git)?/?$", url.strip(), re.I)
    if m:
        return f"{m.group(1)}/{m.group(2)}".lower()
    parts = [p for p in re.split(r"[/:]", url.strip().rstrip("/")) if p]
    return "/".join(parts[-2:]).lower().removesuffix(".git") if len(parts) >= 2 else url.lower()


def _make_state(user_id: int) -> str:
    return jwt.encode({"uid": user_id, "exp": time.time() + STATE_TTL, "typ": "gh_state"},
                      JWT_SECRET_KEY, algorithm="HS256")


def _read_state(token: str) -> int | None:
    try:
        p = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return p.get("uid") if p.get("typ") == "gh_state" else None
    except JWTError:
        return None


def _gh_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


# ── 1. Démarrage de l'autorisation ────────────────────────────────────────────

@router.get("/connect")
def connect(current_user: User = Depends(get_current_user)):
    """Renvoie l'URL d'autorisation GitHub ; le frontend y redirige le navigateur."""
    if not GITHUB_CLIENT_ID or not PUBLIC_BASE_URL:
        raise HTTPException(status_code=503,
                            detail="OAuth GitHub non configuré (GITHUB_CLIENT_ID / PUBLIC_BASE_URL).")
    params = {
        "client_id":    GITHUB_CLIENT_ID,
        "redirect_uri": f"{PUBLIC_BASE_URL}/github/callback",
        "scope":        SCOPE,
        "state":        _make_state(current_user.id),
    }
    return {"url": f"{GH_AUTHORIZE}?{urlencode(params)}"}


# ── 2. Retour de GitHub : échange du code contre un jeton ─────────────────────

@router.get("/callback")
def callback(code: str = "", state: str = "", db: Session = Depends(get_db)):
    uid = _read_state(state)
    if not uid or not code:
        return RedirectResponse(f"{FRONTEND_URL}/settings?github=erreur")

    try:
        r = httpx.post(GH_TOKEN, headers={"Accept": "application/json"},
                       data={"client_id":     GITHUB_CLIENT_ID,
                             "client_secret": GITHUB_CLIENT_SECRET,
                             "code":          code,
                             "redirect_uri":  f"{PUBLIC_BASE_URL}/github/callback"},
                       timeout=15)
        token = r.json().get("access_token", "")
    except Exception:
        token = ""
    if not token:
        return RedirectResponse(f"{FRONTEND_URL}/settings?github=erreur")

    login = ""
    try:
        u = httpx.get(f"{GH_API}/user", headers=_gh_headers(token), timeout=15)
        login = u.json().get("login", "")
    except Exception:
        pass

    # Le jeton porte la portée public_repo (écriture) : jamais en clair en base
    jeton_chiffre = chiffrer(token)
    conn = db.query(GitHubConnection).filter(GitHubConnection.user_id == uid).first()
    if conn:
        conn.access_token = jeton_chiffre
        conn.github_login = login
    else:
        db.add(GitHubConnection(user_id=uid, access_token=jeton_chiffre, github_login=login))
    db.commit()
    return RedirectResponse(f"{FRONTEND_URL}/settings?github=connecte")


# ── 3. État de la connexion et dépôts autorisés ───────────────────────────────

@router.get("/statut")
def statut(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    conn = db.query(GitHubConnection).filter(GitHubConnection.user_id == current_user.id).first()
    autos = (db.query(RepoAutorisation)
             .filter(RepoAutorisation.user_id == current_user.id, RepoAutorisation.actif.is_(True))
             .all())
    return {
        "connecte": bool(conn),
        "login":    conn.github_login if conn else None,
        "depots":   [{"id": a.id, "slug": a.repo_slug} for a in autos],
    }

# ── 4. Autoriser la correction d'un dépôt précis ──────────────────────────────

@router.post("/autoriser-correction")
def autoriser_correction(body: RepoRequest,
                         current_user: User = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    conn = db.query(GitHubConnection).filter(GitHubConnection.user_id == current_user.id).first()
    if not conn:
        raise HTTPException(status_code=400, detail="Connectez d'abord votre compte GitHub.")

    slug = _repo_slug(body.repo_url)
    if not slug or "/" not in slug:
        raise HTTPException(status_code=400, detail="URL de dépôt GitHub invalide.")

    # Vérifie que le client contrôle réellement ce dépôt (droit de push)
    try:
        r = httpx.get(f"{GH_API}/repos/{slug}",
                      headers=_gh_headers(dechiffrer(conn.access_token)), timeout=15)
    except Exception:
        raise HTTPException(status_code=502, detail="Impossible de contacter GitHub.")
    if r.status_code == 404:
        raise HTTPException(status_code=404, detail="Dépôt introuvable ou inaccessible avec votre compte.")
    if r.status_code != 200:
        raise HTTPException(status_code=400, detail="GitHub a refusé l'accès à ce dépôt.")
    if not (r.json().get("permissions", {}) or {}).get("push"):
        raise HTTPException(status_code=403,
                            detail="Vous devez avoir les droits d'écriture sur ce dépôt pour autoriser sa correction.")

    existante = (db.query(RepoAutorisation)
                 .filter(RepoAutorisation.user_id == current_user.id,
                         RepoAutorisation.repo_slug == slug).first())
    if existante:
        existante.actif = True
        db.commit()
        return {"id": existante.id, "slug": slug, "deja": True}

    auto = RepoAutorisation(user_id=current_user.id, repo_slug=slug, actif=True)
    db.add(auto)
    db.commit()
    db.refresh(auto)
    return {"id": auto.id, "slug": slug}


# ── 5. Révoquer une autorisation / se déconnecter ─────────────────────────────

@router.delete("/autoriser-correction/{auto_id}")
def retirer_autorisation(auto_id: int,
                         current_user: User = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    auto = (db.query(RepoAutorisation)
            .filter(RepoAutorisation.id == auto_id, RepoAutorisation.user_id == current_user.id)
            .first())
    if not auto:
        raise HTTPException(status_code=404, detail="Autorisation introuvable.")
    db.delete(auto)
    db.commit()
    return {"deleted": auto_id}


@router.delete("/deconnecter")
def deconnecter(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(RepoAutorisation).filter(RepoAutorisation.user_id == current_user.id).delete()
    conn = db.query(GitHubConnection).filter(GitHubConnection.user_id == current_user.id).first()
    if conn:
        db.delete(conn)
    db.commit()
    return {"deconnecte": True}

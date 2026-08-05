"""
Remédiation assistée : correcteur déterministe + ouverture de Pull Request.
Pour un scan GitHub d'un client ayant autorisé son dépôt, on monte les
dépendances vulnérables détectées vers leur dernière version stable et on ouvre
une Pull Request. L'agent propose ; le client relit et fusionne, jamais de
push direct. C'est le même patron que Dependabot, intégré à la chaîne EASM.
"""

import re
import time
import base64

import httpx

from sqlalchemy.orm import Session

from models import GitHubConnection, RepoAutorisation
from routers.github_oauth import _repo_slug
from routers.notifications import creer_notification
from services.chiffrement import dechiffrer
from services.notifications import notifier_utilisateur

GH_API = "https://api.github.com"


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def _normaliser(nom: str) -> str:
    """Normalisation PyPI : minuscules, underscores → tirets."""
    return nom.strip().lower().replace("_", "-")


def _pypi_derniere_version(nom: str) -> str | None:
    """Dernière version stable d'un paquet sur PyPI."""
    try:
        r = httpx.get(f"https://pypi.org/pypi/{nom}/json", timeout=10)
        if r.status_code != 200:
            return None
        return (r.json().get("info") or {}).get("version") or None
    except Exception:
        return None


def _version_superieure(a: str, b: str) -> bool:
    """Vrai si a > b. Utilise packaging si disponible, sinon comparaison naïve."""
    try:
        from packaging.version import Version
        return Version(a) > Version(b)
    except Exception:
        return a != b


def corriger_requirements(contenu: str, vulnerables: set[str]) -> tuple[str, list[dict]]:
    """Monte les paquets vulnérables vers leur dernière version stable.
    Renvoie (nouveau_contenu, changements)."""
    lignes      = contenu.splitlines()
    changements = []
    ligne_re    = re.compile(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([0-9][^\s;#]*)\s*$")

    for i, ligne in enumerate(lignes):
        m = ligne_re.match(ligne.strip())
        if not m:
            continue
        nom, extras, version = m.group(1), (m.group(2) or ""), m.group(3)
        if _normaliser(nom) not in vulnerables:
            continue
        derniere = _pypi_derniere_version(nom)
        if not derniere or not _version_superieure(derniere, version):
            continue
        lignes[i] = f"{nom}{extras}=={derniere}"
        changements.append({"paquet": nom, "avant": version, "apres": derniere})

    return "\n".join(lignes) + ("\n" if contenu.endswith("\n") else ""), changements


def _ouvrir_pr(token: str, slug: str, chemin: str, nouveau: str, file_sha: str,
               base_branch: str, base_sha: str, changements: list[dict]) -> str | None:
    """Crée une branche, met à jour le fichier et ouvre la PR. Renvoie l'URL de la PR."""
    branche = f"cyberguardian/correctif-deps-{int(time.time())}"
    h       = _headers(token)
    try:
        r = httpx.post(f"{GH_API}/repos/{slug}/git/refs", headers=h, timeout=15,
                       json={"ref": f"refs/heads/{branche}", "sha": base_sha})
        if r.status_code not in (200, 201):
            return None

        resume = ", ".join(f"{c['paquet']} {c['avant']}→{c['apres']}" for c in changements)
        r = httpx.put(f"{GH_API}/repos/{slug}/contents/{chemin}", headers=h, timeout=15,
                      json={"message": f"Correctif sécurité : {resume}",
                            "content": base64.b64encode(nouveau.encode()).decode(),
                            "sha":     file_sha,
                            "branch":  branche})
        if r.status_code not in (200, 201):
            return None

        corps = ("Correctif de sécurité proposé par CyberGuardian.\n\n"
                 "Dépendances mises à jour :\n"
                 + "\n".join(f"- **{c['paquet']}** : {c['avant']} → {c['apres']}" for c in changements)
                 + "\n\nRelisez puis fusionnez si tout vous convient.")
        r = httpx.post(f"{GH_API}/repos/{slug}/pulls", headers=h, timeout=15,
                       json={"title": "Correctif de sécurité : dépendances vulnérables",
                             "head": branche, "base": base_branch, "body": corps})
        if r.status_code not in (200, 201):
            return None
        return r.json().get("html_url")
    except Exception:
        return None


def proposer_correction(user_id: int, repo_target: str, scan_dict: dict, db: Session) -> dict:
    """Orchestration : vérifie le consentement, calcule le correctif, ouvre la PR,
    notifie le client. Renvoie un dict de résultat lisible par l'API."""
    slug = _repo_slug(repo_target)

    conn = db.query(GitHubConnection).filter(GitHubConnection.user_id == user_id).first()
    if not conn:
        return {"ok": False, "message": "Le client n'a pas connecté son compte GitHub."}

    auto = (db.query(RepoAutorisation)
            .filter(RepoAutorisation.user_id == user_id,
                    RepoAutorisation.repo_slug == slug,
                    RepoAutorisation.actif.is_(True)).first())
    if not auto:
        return {"ok": False, "message": "Le client n'a pas autorisé la correction de ce dépôt."}

    safety      = (scan_dict.get("results", {}) or {}).get("safety", {}) or {}
    findings    = safety.get("findings", [])
    vulnerables = {_normaliser(f.get("package", "")) for f in findings if f.get("package")}
    if not vulnerables:
        return {"ok": False, "message": "Aucune dépendance vulnérable à corriger sur ce scan."}

    chemin = safety.get("requirements_file") or "requirements.txt"
    jeton  = dechiffrer(conn.access_token)   # déchiffré uniquement pour l'appel API
    h      = _headers(jeton)

    # Branche par défaut + SHA de tête
    try:
        repo = httpx.get(f"{GH_API}/repos/{slug}", headers=h, timeout=15).json()
        base_branch = repo.get("default_branch", "main")
        ref = httpx.get(f"{GH_API}/repos/{slug}/git/ref/heads/{base_branch}", headers=h, timeout=15).json()
        base_sha = (ref.get("object") or {}).get("sha")
        contents = httpx.get(f"{GH_API}/repos/{slug}/contents/{chemin}?ref={base_branch}",
                             headers=h, timeout=15).json()
        file_sha = contents.get("sha")
        contenu  = base64.b64decode(contents.get("content", "")).decode("utf-8", errors="ignore")
    except Exception:
        return {"ok": False, "message": "Impossible de lire le dépôt sur GitHub."}
    if not base_sha or not file_sha:
        return {"ok": False, "message": f"Fichier {chemin} introuvable sur le dépôt."}

    nouveau, changements = corriger_requirements(contenu, vulnerables)
    if not changements:
        return {"ok": False, "message": "Les dépendances vulnérables sont déjà à jour."}

    pr_url = _ouvrir_pr(jeton, slug, chemin, nouveau, file_sha,
                        base_branch, base_sha, changements)
    if not pr_url:
        return {"ok": False, "message": "GitHub a refusé l'ouverture de la Pull Request."}

    # Notifie le client sur tous ses canaux externes disponibles (Telegram +
    # canaux additionnels éventuels, voir services/notifications.py) et dans
    # la plateforme elle-même, pour ceux qui n'ont lié aucun canal externe.
    resume = "\n".join(f"• {c['paquet']} : {c['avant']} → {c['apres']}" for c in changements)
    notifier_utilisateur(
        user_id,
        f"Correctif proposé : {slug}",
        f"{resume}\n\nRelisez et fusionnez la Pull Request :\n{pr_url}",
        db,
    )
    creer_notification(
        db, user_id, "remediation",
        title = f"Correctif proposé : {slug}",
        body  = resume,
        link  = pr_url,
    )
    db.commit()

    return {"ok": True, "pr_url": pr_url, "changements": changements}

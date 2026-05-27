import json
import httpx
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from models import Scan, User
from auth import get_current_user, get_current_user_optional
from tools.check_ssl import check_ssl
from tools.check_cve import check_tls_cves, check_service_cves
from tools.generate_pdf import generate_scan_pdf
from tools.github_tools import scan_github

OLLAMA_URL   = "https://fromager.unchk.sn:11435"
OLLAMA_KEY   = "partner-2c58610f55694bcaa6b83a15635bf348"
OLLAMA_MODEL = "llama3:latest"

router = APIRouter(prefix="/scans", tags=["scans"])

MOIS = ["jan", "fev", "mar", "avr", "mai", "jun",
        "jul", "aou", "sep", "oct", "nov", "dec"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    now = datetime.now()
    return f"{now.day:02d} {MOIS[now.month - 1]}. {now.year}, {now.strftime('%H:%M')}"


def _detect_asset_type(target: str) -> str:
    import ipaddress
    try:
        ip = ipaddress.ip_address(target.strip())
        if ip.is_private:
            if str(ip).startswith("192.168."):
                return "IP privée — probablement un routeur ou équipement réseau domestique"
            if str(ip).startswith("10."):
                return "IP privée — réseau d'entreprise interne"
            return "IP privée — équipement réseau interne"
        return "IP publique — serveur accessible sur internet"
    except ValueError:
        return "Nom de domaine public"


# ── Modèles ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:     str
    asset_type: str   # domain | ip | url | github


class AskRequest(BaseModel):
    question: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("")
def launch_scan(
    body:         ScanRequest,
    db:           Session      = Depends(get_db),
    current_user: User | None  = Depends(get_current_user_optional),
):
    results = {}
    issues  = []
    all_cves      = []
    server_banner = ""

    if body.asset_type in ("domain", "url", "ip"):
        ssl = check_ssl(body.target)
        results["ssl"] = {
            "valid":             ssl.valid,
            "expired":           ssl.expired,
            "self_signed":       ssl.self_signed,
            "days_until_expiry": ssl.days_until_expiry,
            "expiry_date":       ssl.expiry_date,
            "issued_to":         ssl.issued_to,
            "issued_by":         ssl.issued_by,
            "tls_version":       ssl.tls_version,
            "cipher_suite":      ssl.cipher_suite,
            "sans":              ssl.sans,
            "grade":             ssl.grade,
            "score":             ssl.score,
            "issues":            ssl.issues,
            "error":             ssl.error,
        }
        issues = ssl.issues

        tls_cves                 = check_tls_cves(ssl.tls_version or "", ssl.cipher_suite or "")
        server_banner, svc_cves  = check_service_cves(body.target)
        all_cves                 = tls_cves + svc_cves
        results["cves"]          = all_cves
        results["server_banner"] = server_banner
        total_score = results["ssl"].get("score", 0)

    elif body.asset_type == "github":
        gh = scan_github(body.target)
        results["github_info"] = gh["github_info"]
        results["bandit"]      = gh["bandit"]
        results["safety"]      = gh["safety"]
        results["trufflehog"]  = gh["trufflehog"]
        results["npm_audit"]   = gh.get("npm_audit")
        results["langage"]     = gh.get("langage", "N/A")
        results["score_max"]   = gh.get("max", 30)
        total_score            = gh["score"]
        all_cves               = gh["safety"].get("findings", [])
        issues = [
            {
                "severity": f["severity"],
                "title":    f["issue"],
                "desc":     f"Fichier : {f['file']} — ligne {f['line']}",
                "color":    "red" if f["severity"] == "HIGH" else "orange" if f["severity"] == "MEDIUM" else "yellow",
                "tool":     "scan_bandit()",
            }
            for f in gh["bandit"].get("findings", [])
        ] + [
            {
                "severity": "HAUT",
                "title":    f"Secret exposé : {f['type']}",
                "desc":     f"Fichier : {f['file']} — ligne {f['line']}",
                "color":    "red",
                "tool":     "scan_trufflehog()",
            }
            for f in gh["trufflehog"].get("findings", [])
        ]
    else:
        raise HTTPException(status_code=400, detail="Type d'actif invalide")

    type_labels = {"domain": "Domaine", "ip": "IP", "url": "URL", "github": "GitHub"}

    scan = Scan(
        user_id    = current_user.id if current_user else None,
        target     = body.target,
        type       = body.asset_type,
        type_label = type_labels.get(body.asset_type, "Domaine"),
        score      = total_score,
        status     = "completed",
        vulns      = len(issues),
        cve        = len(all_cves),
        date       = _now(),
        results    = results,
        issues     = issues,
        conversations = [],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan.to_dict()


@router.get("")
def list_scans(
    db:           Session     = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    q = db.query(Scan)
    # Admin voit tous les scans ; client ne voit que les siens
    if current_user and current_user.role != "admin":
        q = q.filter(Scan.user_id == current_user.id)
    scans = q.order_by(Scan.id.desc()).all()
    return [s.to_dict() for s in scans]


@router.get("/quota")
def get_quota(
    db:           Session     = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    if current_user:
        used = db.query(Scan).filter(Scan.user_id == current_user.id).count()
    else:
        used = db.query(Scan).count()
    return {"used": used, "limit": 9999}


@router.get("/{scan_id}/status")
def get_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return {"id": scan_id, "status": scan.status}


@router.get("/{scan_id}/pdf")
def download_pdf(
    scan_id:      int,
    db:           Session     = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    scan = _get_scan_or_404(scan_id, db, current_user)
    scan_dict      = scan.to_dict()
    ai_explanation = _generate_simple_explanation(scan_dict)
    pdf_bytes      = generate_scan_pdf(scan_dict, ai_explanation=ai_explanation)
    filename       = f"cyberguardian-{scan.target}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}")
def get_scan(
    scan_id:      int,
    db:           Session     = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    return _get_scan_or_404(scan_id, db, current_user).to_dict()


@router.delete("/{scan_id}")
def delete_scan(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    scan = _get_scan_or_404(scan_id, db, current_user)
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}


@router.post("/{scan_id}/rerun")
def rerun_scan(
    scan_id:      int,
    db:           Session     = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    scan = _get_scan_or_404(scan_id, db, current_user)
    body = ScanRequest(target=scan.target, asset_type=scan.type)
    return launch_scan(body, db, current_user)


@router.post("/{scan_id}/ask")
def ask_ai(
    scan_id:      int,
    body:         AskRequest,
    db:           Session     = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    scan      = _get_scan_or_404(scan_id, db, current_user)
    scan_dict = scan.to_dict()

    results = scan_dict.get("results", {})
    issues  = scan_dict.get("issues", [])
    is_gh   = scan_dict.get("type") == "github"

    if is_gh:
        info      = results.get("github_info", {})
        bandit    = results.get("bandit", {})
        safety    = results.get("safety", {})
        truffle   = results.get("trufflehog", {})
        npm_audit = results.get("npm_audit") or {}
        score_max = results.get("score_max", 30)
        gh_lang   = results.get("langage") or info.get("language") or "N/A"
        bandit_h  = sum(1 for f in bandit.get("findings", []) if f.get("severity") == "HIGH")
        bandit_m  = sum(1 for f in bandit.get("findings", []) if f.get("severity") == "MEDIUM")
        cve_list  = "; ".join(
            f"{f['package']} {f['version']} ({f['cve']})"
            for f in safety.get("findings", [])[:5]
        ) or "aucune"
        npm_list  = "; ".join(
            f"{f['package']} ({f['severity']})"
            for f in npm_audit.get("findings", [])[:5]
        ) or "aucune"
        secrets   = len(truffle.get("findings", []))
        score_val = scan_dict["score"]
        score_label = (
            f"{score_val}/{score_max} — excellent, aucune faille détectée"
            if score_val == score_max else f"{score_val}/{score_max}"
        )
        context = (
            f"Tu es un expert en cybersécurité senior qui conseille des entreprises sénégalaises.\n\n"
            f"Dépôt GitHub analysé : {scan_dict['target']}\n"
            f"Langage principal : {gh_lang}\n"
            f"Score GitHub : {score_label}\n"
            f"Visibilité : {info.get('visibility', 'N/A')} | Licence : {info.get('license', 'N/A')}\n"
            f"Bandit (Python statique) : {len(bandit.get('findings', []))} findings ({bandit_h} HIGH, {bandit_m} MEDIUM)\n"
            f"Safety (CVE dépendances Python) : {len(safety.get('findings', []))} CVE — {cve_list}\n"
            f"npm audit (CVE Node.js) : {len(npm_audit.get('findings', []))} vulnérabilités — {npm_list}\n"
            f"Secrets exposés : {secrets} secret(s) détecté(s)\n\n"
            f"RÈGLES :\n"
            f"- Priorise les secrets exposés et les CVE CRITICAL/HIGH.\n"
            f"- Pour chaque CVE Python, recommande pip install --upgrade.\n"
            f"- Pour chaque CVE npm, recommande npm audit fix.\n"
            f"- Réponds en français simple, concis.\n\n"
            f"Question de l'utilisateur : {body.question}"
        )
    else:
        ssl        = results.get("ssl", {})
        asset_type = _detect_asset_type(scan_dict["target"])
        problems   = "; ".join("[" + i["severity"] + "] " + i["title"] for i in issues) or "aucun"
        context = (
            "Tu es un expert en cybersécurité senior qui conseille des entreprises sénégalaises.\n\n"
            f"Actif analysé : {scan_dict['target']}\n"
            f"Type d'actif détecté : {asset_type}\n"
            f"Score de sécurité : {scan_dict['score']}/100\n"
            f"SSL/TLS : valide={ssl.get('valid')}, expiré={ssl.get('expired')}, "
            f"auto-signé={ssl.get('self_signed')}, version={ssl.get('tls_version')}, "
            f"grade={ssl.get('grade')}, score={ssl.get('score', 0)}/25, "
            f"expiration={ssl.get('expiry_date')} ({ssl.get('days_until_expiry')} jours restants), "
            f"émis par={ssl.get('issued_by')}\n"
            f"Problèmes ({len(issues)}) : {problems}\n\n"
            "RÈGLES IMPORTANTES :\n"
            "- Si IP privée, explique que CyberGuardian analyse des actifs publics.\n"
            "- Pour un domaine public, recommande Let's Encrypt.\n"
            "- Adapte tes recommandations au contexte sénégalais.\n"
            "- Réponds en français simple, concis.\n\n"
            f"Question de l'utilisateur : {body.question}"
        )

    def stream():
        tokens = []
        try:
            with httpx.stream(
                "POST",
                f"{OLLAMA_URL}/api/generate",
                headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
                json={"model": OLLAMA_MODEL, "prompt": context, "stream": True},
                timeout=httpx.Timeout(connect=15.0, read=180.0, write=15.0, pool=5.0),
            ) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines():
                    if not line:
                        continue
                    data  = json.loads(line)
                    token = data.get("response", "")
                    if token:
                        tokens.append(token)
                        yield f"data: {json.dumps({'token': token})}\n\n"
                    if data.get("done"):
                        answer = "".join(tokens)
                        _save_conversation(scan_id, body.question, answer)
                        yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Helpers internes ──────────────────────────────────────────────────────────

def _get_scan_or_404(scan_id: int, db: Session, current_user: User | None) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    # Admin voit tout ; client ne voit que ses propres scans
    if current_user and current_user.role != "admin":
        if scan.user_id and scan.user_id != current_user.id:
            raise HTTPException(status_code=403, detail="Accès refusé")
    return scan


def _save_conversation(scan_id: int, question: str, answer: str):
    """Ouvre une session dédiée pour sauvegarder la conversation (contexte streaming)."""
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            convs = list(scan.conversations or [])
            convs.append({"question": question, "answer": answer, "date": _now()})
            scan.conversations = convs
            db.commit()
    finally:
        db.close()


def _generate_simple_explanation(scan: dict) -> str:
    results   = scan.get("results", {})
    is_github = scan.get("type") == "github"

    if is_github:
        score_max = results.get("score_max", 30)
        gh_lang   = results.get("langage") or results.get("github_info", {}).get("language") or "N/A"
        bandit    = results.get("bandit", {})
        safety    = results.get("safety", {})
        truffle   = results.get("trufflehog", {})
        npm_audit = results.get("npm_audit") or {}
        secrets   = len(truffle.get("findings", []))
        score_val = scan["score"]
        score_label = (
            f"{score_val}/{score_max} — score parfait, aucune faille détectée"
            if score_val == score_max else f"{score_val}/{score_max}"
        )
        prompt = (
            f"Tu es un expert en cybersécurité. Explique les résultats de ce scan GitHub "
            f"à une personne non-informaticienne.\n\n"
            f"Dépôt : {scan['target']}\nLangage : {gh_lang}\nScore GitHub : {score_label}\n"
            f"Bandit : {len(bandit.get('findings', []))} problème(s) de code détecté(s)\n"
            f"Safety / npm audit : {len(safety.get('findings', [])) + len(npm_audit.get('findings', []))} CVE détectée(s)\n"
            f"Secrets exposés : {secrets} secret(s) détecté(s)\n\n"
            f"RÈGLES :\n"
            f"- Si score parfait ({score_max}/{score_max}), rassure mais recommande une surveillance.\n"
            f"- Si des secrets sont exposés, c'est la priorité absolue.\n"
            f"- Français simple, 5 à 7 phrases max, tutoie le lecteur."
        )
    else:
        ssl        = results.get("ssl", {})
        issues     = scan.get("issues", [])
        asset_type = _detect_asset_type(scan["target"])
        issues_str = "\n".join("- " + i["title"] for i in issues) if issues else "Aucun"
        prompt = (
            "Tu es un expert en cybersécurité. Explique les résultats d'un scan à une personne non-informaticienne.\n\n"
            f"Actif analysé : {scan['target']}\nType d'actif : {asset_type}\n"
            f"Score : {scan['score']}/100\nCertificat SSL valide : {ssl.get('valid', '?')}\n"
            f"Certificat expiré : {ssl.get('expired', '?')}\nAuto-signé : {ssl.get('self_signed', '?')}\n"
            f"Version TLS : {ssl.get('tls_version', '?')}\nGrade : {ssl.get('grade', '?')}\n"
            f"Expiration : {ssl.get('expiry_date', '?')} ({ssl.get('days_until_expiry', '?')} jours restants)\n"
            f"Problèmes : {issues_str}\n\n"
            "RÈGLES :\n"
            "- Si IP privée, explique que cet outil analyse des actifs publics.\n"
            "- Français simple, 5 à 8 phrases max, sans jargon. Tutoie le lecteur."
        )

    try:
        resp = httpx.post(
            f"{OLLAMA_URL}/api/generate",
            headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    except Exception:
        return ""

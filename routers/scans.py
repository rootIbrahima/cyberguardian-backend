import json
import httpx
from pathlib import Path
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from tools.check_ssl import check_ssl
from tools.check_cve import check_tls_cves, check_service_cves
from tools.generate_pdf import generate_scan_pdf
from tools.github_tools import scan_github

OLLAMA_URL   = "https://fromager.unchk.sn:11435"
OLLAMA_KEY   = "partner-2c58610f55694bcaa6b83a15635bf348"
#OLLAMA_MODEL = "llama3:latest"
OLLAMA_MODEL = "llama3:latest"



router = APIRouter(prefix="/scans", tags=["scans"])

DB_FILE = Path(__file__).parent.parent / "data" / "scans.json"


# ── Persistance fichier JSON ──────────────────────────────────────────────────

def _load() -> dict:
    if DB_FILE.exists():
        try:
            return json.loads(DB_FILE.read_text(encoding="utf-8"))
        except Exception:  # nosec B110 — return empty store on any JSON/IO error
            pass
    return {"counter": 0, "scans": {}}


def _save(db: dict):
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    DB_FILE.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")


# ── Modèles ───────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    asset_type: str  # domain | ip | url | github


class AskRequest(BaseModel):
    question: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("")
def launch_scan(body: ScanRequest):
    db = _load()
    db["counter"] += 1
    scan_id = db["counter"]

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

        tls_cves                  = check_tls_cves(ssl.tls_version or "", ssl.cipher_suite or "")
        server_banner, svc_cves   = check_service_cves(body.target)
        all_cves                  = tls_cves + svc_cves
        results["cves"]           = all_cves
        results["server_banner"]  = server_banner

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

    total_score = total_score if body.asset_type == "github" else results.get("ssl", {}).get("score", 0)

    type_labels = {"domain": "Domaine", "ip": "IP", "url": "URL", "github": "GitHub"}

    scan = {
        "id":        scan_id,
        "target":    body.target,
        "type":      body.asset_type,
        "typeLabel": type_labels.get(body.asset_type, "Domaine"),
        "score":     total_score,
        "status":    "completed",
        "vulns":     len(issues),
        "cve":       len(all_cves),
        "date":      _now(),
        "results":   results,
        "issues":    issues,
    }

    db["scans"][str(scan_id)] = scan
    _save(db)
    return scan


@router.get("")
def list_scans():
    db = _load()
    scans = list(db["scans"].values())
    scans.sort(key=lambda s: s["id"], reverse=True)
    return scans


@router.get("/quota")
def get_quota():
    return {"used": 0, "limit": 9999}


@router.get("/{scan_id}/status")
def get_status(scan_id: int):
    db   = _load()
    scan = db["scans"].get(str(scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return {"id": scan_id, "status": scan["status"]}


@router.get("/{scan_id}/pdf")
def download_pdf(scan_id: int):
    db   = _load()
    scan = db["scans"].get(str(scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    ai_explanation = _generate_simple_explanation(scan)
    pdf_bytes = generate_scan_pdf(scan, ai_explanation=ai_explanation)
    filename  = f"cyberguardian-{scan['target']}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@router.get("/{scan_id}")
def get_scan(scan_id: int):
    db   = _load()
    scan = db["scans"].get(str(scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan


@router.post("/{scan_id}/ask")
def ask_ai(scan_id: int, body: AskRequest):
    db   = _load()
    scan = db["scans"].get(str(scan_id))
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    results = scan.get("results", {})
    issues  = scan.get("issues", [])
    is_gh   = scan.get("type") == "github"

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
        cve_list  = "; ".join(f"{f['package']} {f['version']} ({f['cve']})" for f in safety.get("findings", [])[:5]) or "aucune"
        npm_list  = "; ".join(f"{f['package']} ({f['severity']})" for f in npm_audit.get("findings", [])[:5]) or "aucune"
        secrets   = len(truffle.get("findings", []))
        score_label = (f"{scan['score']}/{score_max} — excellent, aucune faille détectée"
                       if scan['score'] == score_max
                       else f"{scan['score']}/{score_max}")
        context = f"""Tu es un expert en cybersécurité senior qui conseille des entreprises sénégalaises.

Dépôt GitHub analysé : {scan['target']}
Langage principal : {gh_lang}
Score GitHub : {score_label}
Visibilité : {info.get('visibility', 'N/A')} | Licence : {info.get('license', 'N/A')}
Bandit (Python statique) : {len(bandit.get('findings', []))} findings ({bandit_h} HIGH, {bandit_m} MEDIUM)
Safety (CVE dépendances Python) : {len(safety.get('findings', []))} CVE — {cve_list}
npm audit (CVE Node.js) : {len(npm_audit.get('findings', []))} vulnérabilités — {npm_list}
Secrets exposés : {secrets} secret(s) détecté(s)

RÈGLES :
- Priorise les secrets exposés (révoquer immédiatement) et les CVE CRITICAL/HIGH.
- Pour chaque CVE Python, recommande la commande pip install --upgrade.
- Pour chaque CVE npm, recommande npm audit fix ou la version corrigée.
- Pour Bandit HIGH, explique le risque avec un exemple de code corrigé.
- Réponds en français simple, concis, sans jargon inutile.

Question de l'utilisateur : {body.question}"""
    else:
        ssl        = results.get("ssl", {})
        asset_type = _detect_asset_type(scan['target'])
        context = f"""Tu es un expert en cybersécurité senior qui conseille des entreprises sénégalaises.

Actif analysé : {scan['target']}
Type d'actif détecté : {asset_type}
Score de sécurité : {scan['score']}/100
SSL/TLS : valide={ssl.get('valid')}, expiré={ssl.get('expired')}, auto-signé={ssl.get('self_signed')}, version={ssl.get('tls_version')}, grade={ssl.get('grade')}, score={ssl.get('score', 0)}/25, expiration={ssl.get('expiry_date')} ({ssl.get('days_until_expiry')} jours restants), émis par={ssl.get('issued_by')}
Problèmes ({len(issues)}) : {'; '.join(f"[{i['severity']}] {i['title']}" for i in issues) or 'aucun'}

RÈGLES IMPORTANTES :
- Si l'actif est une IP privée (192.168.x.x, 10.x.x.x, 172.16-31.x.x), explique clairement que CyberGuardian est conçu pour analyser des actifs publics accessibles sur internet, pas des équipements réseau internes (routeurs, NAS, caméras). Donne quand même des conseils adaptés à l'équipement détecté.
- Ne recommande JAMAIS "redémarrez le serveur" ou "Let's Encrypt" pour une IP privée ou un équipement réseau interne.
- Pour un domaine public, recommande Let's Encrypt ou les hébergeurs locaux (OVH, Sonatel, Arc Informatique).
- Adapte tes recommandations au contexte sénégalais quand c'est pertinent.
- Réponds en français simple, concis, sans jargon inutile.

Question de l'utilisateur : {body.question}"""

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
                    data = json.loads(line)
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
            print(f"[AI ERROR] {type(e).__name__}: {e}")
            traceback.print_exc()
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    from datetime import datetime
    MOIS = ["jan", "fev", "mar", "avr", "mai", "jun",
            "jul", "aou", "sep", "oct", "nov", "dec"]
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


def _save_conversation(scan_id: int, question: str, answer: str):
    db   = _load()
    scan = db["scans"].get(str(scan_id), {})
    if "conversations" not in scan:
        scan["conversations"] = []
    scan["conversations"].append({"question": question, "answer": answer, "date": _now()})
    db["scans"][str(scan_id)] = scan
    _save(db)


def _generate_simple_explanation(scan: dict) -> str:
    results   = scan.get("results", {})
    is_github = scan.get("type") == "github"

    if is_github:
        score_max  = results.get("score_max", 30)
        gh_lang    = results.get("langage") or results.get("github_info", {}).get("language") or "N/A"
        bandit     = results.get("bandit", {})
        safety     = results.get("safety", {})
        truffle    = results.get("trufflehog", {})
        npm_audit  = results.get("npm_audit") or {}
        secrets    = len(truffle.get("findings", []))
        score_label = (f"{scan['score']}/{score_max} — score parfait, aucune faille détectée"
                       if scan['score'] == score_max
                       else f"{scan['score']}/{score_max}")
        prompt = f"""Tu es un expert en cybersécurité. Explique les résultats de ce scan GitHub à une personne non-informaticienne.

Dépôt : {scan['target']}
Langage : {gh_lang}
Score GitHub : {score_label}
Bandit : {len(bandit.get('findings', []))} problème(s) de code détecté(s)
Safety / npm audit : {len(safety.get('findings', [])) + len(npm_audit.get('findings', []))} CVE détectée(s)
Secrets exposés : {secrets} secret(s) détecté(s)

RÈGLES :
- Si score parfait ({score_max}/{score_max}), rassure mais recommande une surveillance régulière.
- Si des secrets sont exposés, c'est la priorité absolue — explique le risque en termes simples.
- Français simple, 5 à 7 phrases max, tutoie le lecteur."""
    else:
        ssl        = results.get("ssl", {})
        issues     = scan.get("issues", [])
        asset_type = _detect_asset_type(scan['target'])
        prompt = f"""Tu es un expert en cybersécurité. Tu dois expliquer les résultats d'un scan à une personne non-informaticienne.

Actif analysé : {scan['target']}
Type d'actif : {asset_type}
Score : {scan['score']}/100
Certificat SSL valide : {ssl.get('valid', '?')}
Certificat expiré : {ssl.get('expired', '?')}
Auto-signé : {ssl.get('self_signed', '?')}
Version TLS : {ssl.get('tls_version', '?')}
Grade : {ssl.get('grade', '?')}
Expiration : {ssl.get('expiry_date', '?')} ({ssl.get('days_until_expiry', '?')} jours restants)
Problèmes : {chr(10).join(f'- {i["title"]}' for i in issues) if issues else 'Aucun'}

RÈGLES :
- Si c'est une IP privée (192.168.x.x, 10.x.x.x), explique que cet outil analyse des actifs publics sur internet, pas des équipements internes. Adapte tes conseils à l'équipement (routeur, NAS, etc.).
- Si c'est un domaine ou une IP publique, explique le score et les actions concrètes à faire.
- Français simple, 5 à 8 phrases max, sans jargon. Tutoie le lecteur."""

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

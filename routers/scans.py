import re
import json
from dataclasses import asdict

import httpx
from datetime import datetime, timedelta
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from horodatage import maintenant, maintenant_iso
from database import get_db, SessionLocal
from models import Conversation, Scan, User
from auth import get_current_user
from routers.notifications import creer_notification
from services.comparaison import comparer, resumer
from tools.check_dns import check_dns
from tools.check_whois import check_whois
from tools.check_epss import enrich_cves
from tools.check_ssl import check_ssl
from tools.check_cve import check_tls_cves, check_service_cves
from tools.scan_headers import scan_headers
from tools.check_ports import check_ports
from tools.check_reputation import check_reputation
from tools.target_guard import resoudre_et_valider, CibleInterdite
from tools.calculate_score import calculate_score
from tools.generate_pdf import generate_scan_pdf
from tools.github_tools import scan_github

from config import (OLLAMA_URL, OLLAMA_KEY, OLLAMA_MODEL, OLLAMA_KEEP_ALIVE,
                    QUOTA_SCANS_PAR_CIBLE)

router = APIRouter(prefix="/scans", tags=["scans"])

MOIS = ["jan", "fev", "mar", "avr", "mai", "jun",
        "jul", "aou", "sep", "oct", "nov", "dec"]

# CDC §7.1 : limite le rythme des scans pour qu'un compte ne puisse pas
# transformer la plateforme en relais de reconnaissance à haute fréquence.
# Réglable par QUOTA_SCANS_PAR_CIBLE dans .env, 0 désactivant la limite.
QUOTA_PAR_CIBLE_24H = QUOTA_SCANS_PAR_CIBLE


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    now = datetime.now()
    return f"{now.day:02d} {MOIS[now.month - 1]}. {now.year}, {now.strftime('%H:%M')}"


def _depuis_24h() -> str:
    return (maintenant() - timedelta(hours=24)).isoformat(timespec="seconds")


def _verifier_quota(db: Session, user_id: int, target: str) -> None:
    """Refuse au-delà de QUOTA_PAR_CIBLE_24H scans d'une même cible sur 24h.
    Les scans antérieurs à l'ajout du champ created_at ne sont pas décomptés."""
    if QUOTA_PAR_CIBLE_24H <= 0:      # limite désactivée par configuration
        return
    recents = (
        db.query(Scan)
        .filter(
            Scan.user_id    == user_id,
            Scan.target     == target,
            Scan.created_at.isnot(None),
            Scan.created_at >= _depuis_24h(),
        )
        .count()
    )
    if recents >= QUOTA_PAR_CIBLE_24H:
        raise HTTPException(
            status_code=429,
            detail=f"Limite atteinte : {QUOTA_PAR_CIBLE_24H} scans par jour et par cible. "
                   "Relancez l'analyse demain ou soumettez un autre actif.",
        )


def _detect_asset_type(target: str) -> str:
    import ipaddress
    try:
        ip = ipaddress.ip_address(target.strip())
        if ip.is_private:
            if str(ip).startswith("192.168."):
                return "IP privée : probablement un routeur ou équipement réseau domestique"
            if str(ip).startswith("10."):
                return "IP privée : réseau d'entreprise interne"
            return "IP privée : équipement réseau interne"
        return "IP publique : serveur accessible sur internet"
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
    taches:       BackgroundTasks,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    # Périmètre externe uniquement : une cible interne (boucle locale, réseau
    # privé, métadonnées cloud) ferait de la plateforme un relais de scan.
    if body.asset_type not in ("domain", "ip", "url", "github"):
        raise HTTPException(status_code=400, detail="Type d'actif invalide")

    if body.asset_type in ("domain", "url", "ip"):
        try:
            resoudre_et_valider(body.target)
        except CibleInterdite as e:
            raise HTTPException(status_code=400, detail=str(e))

    _verifier_quota(db, current_user.id, body.target)

    # Le scan est enregistré tout de suite, à l'état « en cours », et les outils
    # tournent ensuite. Menée dans la requête, l'analyse laissait le client
    # devant un bouton figé : 68 s mesurées sur un domaine avec scan de ports,
    # pendant que la page de progression n'avait plus rien à montrer une fois
    # atteinte. Elle suit désormais l'avancement réel.
    type_labels = {"domain": "Domaine", "ip": "IP", "url": "URL", "github": "GitHub"}

    scan = Scan(
        user_id    = current_user.id,
        target     = body.target,
        type       = body.asset_type,
        type_label = type_labels.get(body.asset_type, "Domaine"),
        score      = None,
        status     = "running",
        vulns      = 0,
        cve        = 0,
        date       = _now(),
        created_at = maintenant_iso(),
        results    = {},
        issues     = [],
        conversations = [],
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    taches.add_task(_executer_scan, scan.id, body.target, body.asset_type)
    return scan.to_dict()


def _executer_scan(scan_id: int, target: str, asset_type: str) -> None:
    """Exécute les outils et complète le scan déjà créé.

    Tourne après l'envoi de la réponse : la session de la requête est fermée,
    il en faut une dédiée. Toute erreur laisse le scan en « failed » plutôt
    qu'indéfiniment « running », sans quoi la page de progression tournerait
    sans fin."""
    try:
        results = {}
        issues  = []
        all_cves      = []
        server_banner = ""

        if asset_type in ("domain", "url", "ip"):
            ssl = check_ssl(target)
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
            server_banner, svc_cves  = check_service_cves(target)
            all_cves                 = enrich_cves(tls_cves + svc_cves, id_key="id")
            results["cves"]          = all_cves
            results["server_banner"] = server_banner

            headers = scan_headers(target)
            results["headers"] = asdict(headers)
            issues = issues + headers.issues

            ports = check_ports(target)
            results["ports"] = asdict(ports)
            issues = issues + ports.issues

            reputation = check_reputation(target)
            results["reputation"] = asdict(reputation)
            issues = issues + reputation.issues

            score_parts = {"ssl": ssl.score, "headers": headers.score,
                           "ports": ports.score, "reputation": reputation.score}

            # DNS et WHOIS n'ont de sens que pour un domaine, pas une IP brute
            if asset_type in ("domain", "url"):
                dns = check_dns(target)
                results["dns"] = asdict(dns)
                issues = issues + dns.issues
                score_parts["dns"] = dns.score

                whois = check_whois(target)
                results["whois"] = asdict(whois)
                issues = issues + whois.issues

            score_detail            = calculate_score(score_parts)
            results["score_detail"] = score_detail
            total_score             = score_detail["score"]

        elif asset_type == "github":
            gh = scan_github(target)
            # Enrichit les CVE de dépendances (Safety) avec l'EPSS avant stockage
            enrich_cves(gh["safety"].get("findings", []), id_key="cve")
            results["github_info"] = gh["github_info"]
            results["bandit"]      = gh["bandit"]
            results["safety"]      = gh["safety"]
            results["trufflehog"]  = gh["trufflehog"]
            results["npm_audit"]   = gh.get("npm_audit")
            results["langage"]     = gh.get("langage", "N/A")
            results["score_max"]   = gh.get("max", 30)
            total_score            = gh["score"]
            all_cves               = gh["safety"].get("findings", [])
            _sev_fr = {"LOW": "BAS", "MEDIUM": "MOYEN", "HIGH": "HAUT"}
            issues = [
                {
                    "severity": _sev_fr.get(f["severity"], f["severity"]),
                    "title":    f["issue"],
                    "desc":     f"Fichier : {f['file']}, ligne {f['line']}",
                    "color":    "red" if f["severity"] == "HIGH" else "orange" if f["severity"] == "MEDIUM" else "yellow",
                    "tool":     "scan_bandit()",
                }
                for f in gh["bandit"].get("findings", [])
            ] + [
                {
                    "severity": "HAUT",
                    "title":    f"Secret exposé : {f['type']}",
                    "desc":     f"Fichier : {f['file']}, ligne {f['line']}",
                    "color":    "red",
                    "tool":     "scan_trufflehog()",
                }
                for f in gh["trufflehog"].get("findings", [])
            ]
        else:
            raise ValueError("Type d'actif invalide")
    except Exception as e:
        print(f"  [!] scan {scan_id} en échec sur {target} : {e}")
        db = SessionLocal()
        try:
            rate = db.query(Scan).filter(Scan.id == scan_id).first()
            if rate:
                rate.status = "failed"
                db.commit()
        finally:
            db.close()
        return

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return   # supprimé pendant l'analyse
        scan.score   = total_score
        scan.status  = "completed"
        scan.vulns   = len(issues)
        scan.cve     = len(all_cves)
        scan.results = results
        scan.issues  = issues
        db.commit()

        # Ce que ce scan change par rapport au précédent part immédiatement sur
        # les canaux du propriétaire. C'est la raison d'être d'une surveillance :
        # le rapport n'informe que celui qui vient déjà le consulter, l'alerte
        # va chercher celui qui ne sait pas encore qu'il doit le faire.
        _alerter_sur_evolution(db, scan)

        # Le rapport rédigé est produit dans la foulée, le scan étant déjà
        # marqué terminé : le client consulte ses résultats pendant ce temps et
        # ne subit plus les 30 à 140 s du modèle au moment où il demande le PDF.
        # L'échec est sans conséquence, le téléchargement le régénérera.
        redaction = _generate_simple_explanation(scan.to_dict())
        if redaction:
            scan.results = {**(scan.results or {}), "rapport_ia": redaction}
            db.commit()
    finally:
        db.close()


def _alerter_sur_evolution(db: Session, scan: Scan) -> None:
    """Compare le scan au précédent de la même cible et prévient son
    propriétaire de ce qui a changé.

    L'échec reste sans conséquence sur le scan : celui-ci est déjà enregistré et
    consultable, une alerte manquée ne doit pas le remettre en cause. Elle est
    donc journalisée, pas propagée."""
    if not scan.user_id:
        return
    try:
        precedent = (
            db.query(Scan)
            .filter(
                Scan.user_id == scan.user_id,
                Scan.target  == scan.target,
                Scan.status  == "completed",
                Scan.id      != scan.id,
            )
            .order_by(Scan.id.desc())
            .first()
        )
        alertes = comparer(precedent.to_dict() if precedent else None, scan.to_dict())
        if not alertes:
            return

        titre, corps = resumer(scan.target, alertes)
        creer_notification(
            db, scan.user_id,
            type    = "alerte_securite",
            title   = titre,
            # Le panneau de notifications ne montre que les intitulés : le détail
            # de chaque écart y serait illisible, il est réservé au canal externe.
            body    = " · ".join(a.titre for a in alertes),
            link    = f"/scan-results/{scan.id}",
            externe = corps,
        )
        db.commit()
    except Exception as e:
        print(f"  [!] alerte d'évolution non émise pour {scan.target} : {e}")
        db.rollback()


@router.get("")
def list_scans(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    q = db.query(Scan)
    # Admin voit tous les scans ; client ne voit que les siens ;
    # un expert voit aussi les scans partagés via une mission niveau 3 active
    if current_user.role == "expert":
        from routers.messages import mission_active
        convs = (
            db.query(Conversation)
            .filter(Conversation.expert_id == current_user.id, Conversation.level >= 3)
            .all()
        )
        shared_ids = []
        for c in convs:
            if mission_active(c):
                shared = (
                    db.query(Scan)
                    .filter(Scan.user_id == c.client_id, Scan.target == c.subject)
                    .order_by(Scan.id.desc())
                    .first()
                )
                if shared:
                    shared_ids.append(shared.id)
        q = q.filter((Scan.user_id == current_user.id) | Scan.id.in_(shared_ids))
    elif current_user.role != "admin":
        q = q.filter(Scan.user_id == current_user.id)
    scans = q.order_by(Scan.id.desc()).all()
    return [s.to_dict() for s in scans]


@router.get("/quota")
def get_quota(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    """Consommation des dernières 24h et plafond appliqué par cible (CDC §7.1).
    limit vaut null quand la limitation est désactivée."""
    used = (
        db.query(Scan)
        .filter(
            Scan.user_id    == current_user.id,
            Scan.created_at.isnot(None),
            Scan.created_at >= _depuis_24h(),
        )
        .count()
    )
    return {
        "used":   used,
        "limit":  QUOTA_PAR_CIBLE_24H if QUOTA_PAR_CIBLE_24H > 0 else None,
        "window": "24h",
        "scope":  "cible",
    }


@router.get("/{scan_id}/status")
def get_status(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    scan = _get_scan_or_404(scan_id, db, current_user)
    return {"id": scan.id, "status": scan.status}


@router.get("/{scan_id}/pdf")
def download_pdf(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    scan      = _get_scan_or_404(scan_id, db, current_user)
    scan_dict = scan.to_dict()

    # Le texte rédigé est conservé avec le scan. Sans cela chaque téléchargement
    # relançait le modèle, soit 30 à 140 s d'attente selon la charge du serveur,
    # pour reproduire une analyse de résultats qui, eux, ne changent plus.
    ai_explanation = (scan.results or {}).get("rapport_ia") or ""
    if not ai_explanation:
        ai_explanation = _generate_simple_explanation(scan_dict)
        if ai_explanation:
            # Réaffectation complète : SQLAlchemy ne détecte pas la modification
            # d'une clé à l'intérieur d'une colonne JSON.
            scan.results = {**(scan.results or {}), "rapport_ia": ai_explanation}
            db.commit()

    pdf_bytes = generate_scan_pdf(scan_dict, ai_explanation=ai_explanation)
    filename  = f"cyberguardian-{scan.target}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}")
def get_scan(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
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
    taches:       BackgroundTasks,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    scan = _get_scan_or_404(scan_id, db, current_user)
    body = ScanRequest(target=scan.target, asset_type=scan.type)
    return launch_scan(body, taches, db, current_user)


@router.post("/{scan_id}/ask")
def ask_ai(
    scan_id:      int,
    body:         AskRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
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
            f"{score_val}/{score_max}, excellent, aucune faille détectée"
            if score_val == score_max else f"{score_val}/{score_max}"
        )
        context = (
            f"Tu es un expert en cybersécurité senior qui conseille des entreprises sénégalaises.\n\n"
            f"Dépôt GitHub analysé : {scan_dict['target']}\n"
            f"Langage principal : {gh_lang}\n"
            f"Score GitHub : {score_label}\n"
            f"Visibilité : {info.get('visibility', 'N/A')} | Licence : {info.get('license', 'N/A')}\n"
            f"Bandit (Python statique) : {len(bandit.get('findings', []))} findings ({bandit_h} HIGH, {bandit_m} MEDIUM)\n"
            f"Safety (CVE dépendances Python) : {len(safety.get('findings', []))} CVE : {cve_list}\n"
            f"npm audit (CVE Node.js) : {len(npm_audit.get('findings', []))} vulnérabilités, {npm_list}\n"
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
        cves       = results.get("cves", [])
        server     = results.get("server_banner", "")
        asset_type = _detect_asset_type(scan_dict["target"])
        problems   = "; ".join("[" + i["severity"] + "] " + i["title"] for i in issues) or "aucun"
        dns_line   = _dns_summary(results)
        whois_line = _whois_summary(results)
        headers_line = _headers_summary(results)
        ports_line = _ports_summary(results)
        reputation_line = _reputation_summary(results)
        cve_critical = [c for c in cves if c.get("severity", "").upper() in ("CRITICAL", "CRITIQUE")]
        cve_high     = [c for c in cves if c.get("severity", "").upper() in ("HIGH", "HAUT")]
        cve_details  = "\n".join(
            "  - " + c.get("id", "?") + " CVSS=" + str(c.get("cvss", "?")) +
            (" EPSS=" + str(round((c.get("epss") or 0) * 100, 1)) + "%" if c.get("epss") is not None else "") +
            (" priorité=" + c["priority"] if c.get("priority") else "") +
            " (" + c.get("severity", "?") + ") : " + (c.get("title") or "")[:120]
            for c in cves[:10]
        ) or "  Aucune CVE détectée"
        context = (
            "Tu es un expert en cybersécurité senior qui conseille des entreprises sénégalaises.\n\n"
            f"Actif analysé : {scan_dict['target']}\n"
            f"Type d'actif détecté : {asset_type}\n"
            f"Score de sécurité : {scan_dict['score']}/100\n"
            f"Serveur détecté : {server or 'N/A'}\n"
            f"SSL/TLS : valide={ssl.get('valid')}, expiré={ssl.get('expired')}, "
            f"auto-signé={ssl.get('self_signed')}, version={ssl.get('tls_version')}, "
            f"grade={ssl.get('grade')}, score={ssl.get('score', 0)}/25, "
            f"expiration={ssl.get('expiry_date')} ({ssl.get('days_until_expiry')} jours restants), "
            f"émis par={ssl.get('issued_by')}\n"
            f"{dns_line}"
            f"{whois_line}"
            f"{headers_line}"
            f"{ports_line}"
            f"{reputation_line}"
            f"CVE détectées ({len(cves)}) dont {len(cve_critical)} CRITIQUE et {len(cve_high)} HAUT :\n"
            f"{cve_details}\n"
            f"Problèmes détectés ({len(issues)}) : {problems}\n\n"
            "RÈGLES IMPORTANTES :\n"
            "- Le score couvre cinq critères : DNS, SSL/TLS, en-têtes HTTP, ports\n"
            "  réseau et réputation. Appuie-toi sur celui que la question concerne.\n"
            "- Analyse les CVE détectées en priorité, pas seulement le SSL.\n"
            "- Si CVE CRITICAL ou HIGH, explique le risque concret et la correction.\n"
            "- Un port de base de données ou d'administration ouvert est une porte\n"
            "  d'entrée directe : traite-le avec le même sérieux qu'une CVE.\n"
            "- Un signalement de réputation indique un historique de compromission,\n"
            "  pas un défaut de configuration : la correction est différente.\n"
            "- Si IP privée, explique que CyberGuardian analyse des actifs publics.\n"
            "- Pour un domaine public, recommande Let's Encrypt si besoin.\n"
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
                json={"model": OLLAMA_MODEL, "prompt": context, "stream": True, "keep_alive": OLLAMA_KEEP_ALIVE,
                      "think": False,   # qwen3.6 : pas de raisonnement parasite dans le flux
                      "options": {"num_predict": 500, "temperature": 0.6}},
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

def _dns_summary(results: dict) -> str:
    dns = results.get("dns")
    if not dns:
        return ""
    policy = dns.get("dmarc_policy") or "absent"
    return (
        f"DNS : SPF={'présent' if dns.get('spf_present') else 'ABSENT'}, "
        f"DMARC={'présent (p=' + policy + ')' if dns.get('dmarc_present') else 'ABSENT'}, "
        f"DKIM={'présent' if dns.get('dkim_present') else 'non détecté'}, "
        f"DNSSEC={'activé' if dns.get('dnssec_enabled') else 'absent'}, "
        f"score={dns.get('score', 0)}/25\n"
    )


def _whois_summary(results: dict) -> str:
    whois = results.get("whois")
    if not whois or not whois.get("found"):
        return ""
    days = whois.get("days_until_expiry")
    expiry = ""
    if days is not None:
        expiry = f", expire dans {days} jours" if days >= 0 else f", EXPIRÉ depuis {abs(days)} jours"
    return (
        f"WHOIS : registrar={whois.get('registrar') or 'N/A'}, "
        f"créé le {whois.get('created') or 'N/A'}{expiry}\n"
    )


def _headers_summary(results: dict) -> str:
    headers = results.get("headers")
    if not headers:
        return ""
    missing = ", ".join(headers.get("headers_missing", [])) or "aucun"
    return (
        f"En-têtes de sécurité HTTP : score={headers.get('score', 0)}/20, "
        f"manquants : {missing}\n"
    )


def _ports_summary(results: dict) -> str:
    ports = results.get("ports")
    if not ports or ports.get("score") is None:
        return ""
    ouverts = ", ".join(f"{p['port']} ({p['service']})" for p in ports.get("open_ports", [])) or "aucun port sensible ouvert"
    return (
        f"Ports réseau : score={ports.get('score', 0)}/15, "
        f"ouverts : {ouverts}\n"
    )


_FIN_DE_PHRASE = re.compile(r"[.!?](?=\s|$)")


def _couper_a_la_phrase(texte: str) -> str:
    """Tronque au dernier point terminant réellement une phrase. Le modèle
    s'arrête net quand il atteint sa limite de jetons ; une phrase interrompue
    en plein milieu dans un rapport remis à un client fait plus mauvais effet
    qu'une phrase en moins."""
    texte = (texte or "").strip()
    if not texte or texte[-1] in ".!?":
        return texte

    # Les points de numérotation (« 1. », « 2. ») ne terminent pas une phrase
    fins = [m.end() for m in _FIN_DE_PHRASE.finditer(texte)
            if not (m.start() > 0 and texte[m.start() - 1].isdigit())]
    if not fins:
        return texte

    # Ne pas amputer plus du quart du texte : au-delà, la coupure ferait perdre
    # plus d'information que la phrase incomplète n'en gêne la lecture.
    return texte[:fins[-1]].strip() if fins[-1] >= len(texte) * 0.75 else texte


def _reputation_summary(results: dict) -> str:
    rep = results.get("reputation")
    if not rep or rep.get("score") is None:
        return ""
    details = []
    if rep.get("vt_disponible"):
        details.append(f"VirusTotal : {rep.get('vt_malveillant', 0)} moteur(s) malveillant "
                       f"sur {rep.get('vt_total_moteurs', 0)}")
    if rep.get("abuse_disponible"):
        details.append(f"AbuseIPDB : indice {rep.get('abuse_score', 0)}/100 "
                       f"({rep.get('abuse_signalements', 0)} signalements)")
    return f"Réputation : score={rep.get('score')}/15, " + ", ".join(details) + "\n"


def _expert_share_active(scan: Scan, user: User, db: Session) -> bool:
    """Un expert accède au scan d'un client si une conversation sur cette cible
    est au niveau 3 (contrat signé) depuis moins de 48h (CDC §4.2)."""
    from routers.messages import mission_active
    conv = (
        db.query(Conversation)
        .filter(
            Conversation.expert_id == user.id,
            Conversation.client_id == scan.user_id,
            Conversation.subject   == scan.target,
            Conversation.level     >= 3,
        )
        .order_by(Conversation.id.desc())
        .first()
    )
    return bool(conv and mission_active(conv))


def _get_scan_or_404(scan_id: int, db: Session, current_user: User) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    # Admin voit tout ; client ne voit que ses propres scans ;
    # un expert voit le scan d'un client si contrat signé < 48h (niveau 3).
    # L'authentification est obligatoire : un rapport contient les failles et
    # les ports ouverts d'un actif, il ne doit jamais être lisible anonymement.
    if current_user.role != "admin":
        if scan.user_id and scan.user_id != current_user.id:
            if not (current_user.role == "expert"
                    and _expert_share_active(scan, current_user, db)):
                raise HTTPException(status_code=403, detail="Accès refusé ou expiré")
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
            f"{score_val}/{score_max}, score parfait, aucune faille détectée"
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
        cves       = results.get("cves", [])
        server     = results.get("server_banner", "")
        issues     = scan.get("issues", [])
        asset_type = _detect_asset_type(scan["target"])
        issues_str = "\n".join("- " + i["title"] for i in issues) if issues else "Aucun"
        cve_critical = [c for c in cves if c.get("severity", "").upper() in ("CRITICAL", "CRITIQUE")]
        cve_high     = [c for c in cves if c.get("severity", "").upper() in ("HIGH", "HAUT")]
        cve_str = "\n".join(
            "  - " + c.get("id", "?") + " CVSS=" + str(c.get("cvss", "?")) +
            " (" + c.get("severity", "?") + ") : " + (c.get("title") or "")[:120]
            for c in cves[:6]
        ) or "  Aucune CVE détectée"
        prompt = (
            "Tu es un expert en cybersécurité. Explique les résultats d'un scan à une personne non-informaticienne.\n\n"
            f"Actif analysé : {scan['target']}\nType d'actif : {asset_type}\n"
            f"Score global : {scan['score']}/100\nServeur détecté : {server or 'N/A'}\n"
            f"Certificat SSL valide : {ssl.get('valid', '?')} | "
            f"Version TLS : {ssl.get('tls_version', '?')} | Grade : {ssl.get('grade', '?')}\n"
            f"Expiration SSL : {ssl.get('expiry_date', '?')} ({ssl.get('days_until_expiry', '?')} jours restants)\n"
            f"{_dns_summary(results)}"
            f"{_whois_summary(results)}"
            f"{_headers_summary(results)}"
            f"{_ports_summary(results)}"
            f"{_reputation_summary(results)}"
            f"CVE détectées ({len(cves)}) dont {len(cve_critical)} CRITIQUE et {len(cve_high)} HAUT :\n{cve_str}\n"
            f"Problèmes détectés :\n{issues_str}\n\n"
            "RÈGLES :\n"
            "- Commence par les CVE critiques si présentes, c'est la priorité.\n"
            "- Explique ce que chaque CVE critique/haute signifie concrètement.\n"
            "- Le score porte sur cinq critères : DNS, SSL/TLS, en-têtes HTTP, ports\n"
            "  réseau et réputation. Cite ceux qui l'ont réellement fait baisser.\n"
            "- Un port de base de données ou d'administration ouvert, et un\n"
            "  signalement de réputation, sont aussi graves qu'une CVE : ne les omets pas.\n"
            "- Si IP privée, explique que cet outil analyse des actifs publics.\n"
            "- Français simple, 6 à 9 phrases max, sans jargon. Tutoie le lecteur."
        )

    try:
        resp = httpx.post(
            f"{OLLAMA_URL}/api/generate",
            headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "keep_alive": OLLAMA_KEEP_ALIVE,
                  "think": False,   # qwen3.6 : réponse directe sans raisonnement
                  # La consigne demande 6 à 9 phrases, mesurées entre 255 et 370
                  # jetons. Le plafond de 600 n'ajoutait aucun texte, seulement
                  # du temps d'attente dans le pire cas.
                  "options": {"num_predict": 400, "temperature": 0.6}},
            # Le serveur d'inférence est mutualisé : le même prompt a été
            # chronométré à 28 s puis à 139 s. Un délai de 60 s coupait la
            # génération et le rapport arrivait vide, sans trace.
            timeout=httpx.Timeout(connect=15.0, read=180.0, write=15.0, pool=5.0),
        )
        resp.raise_for_status()
        return _couper_a_la_phrase(resp.json().get("response", ""))
    except Exception as e:
        print(f"  [!] rapport rédigé indisponible pour {scan.get('target')} : {e}")
        return ""

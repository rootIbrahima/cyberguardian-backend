from fpdf import FPDF
from datetime import datetime
import unicodedata


def _ascii(text: str) -> str:
    if not text:
        return ""
    text = str(text)
    text = text.replace("—", "-").replace("–", "-").replace("·", "|")
    text = text.replace("‘", "'").replace("’", "'")
    text = text.replace("“", '"').replace("”", '"')
    text = text.replace("«", '"').replace("»", '"')
    text = text.replace("…", "...").replace("•", "-").replace("‣", "-")
    text = text.replace("**", "").replace("*", "")
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


# Palette
BLUE_DARK  = (15,  41,  77)
BLUE_MED   = (31,  92, 153)
GREEN      = (26, 122,  74)
ORANGE     = (133,  79,  11)
RED        = (153,  27,  27)
GRAY_DARK  = (17,  24,  39)
GRAY_MID   = (107, 114, 128)
GRAY_LIGHT = (229, 231, 235)
WHITE      = (255, 255, 255)
PURPLE     = (109,  40, 217)
GH_DARK    = (17,  24,  39)


def _score_color(pct: int) -> tuple:
    if pct >= 80: return GREEN
    if pct >= 50: return ORANGE
    return RED


def _sev_color(sev: str) -> tuple:
    sev = (sev or "").upper()
    if sev in ("CRITICAL", "CRITIQUE"):     return RED
    if sev in ("HIGH", "HAUT"):             return (220, 80, 20)
    if sev in ("MEDIUM", "MOYEN", "MODERATE"): return ORANGE
    return GRAY_MID


class CyberGuardianPDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*WHITE)
        self.set_xy(10, 4)
        self.cell(0, 10, "CyberGuardian  |  Rapport de securite", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(180, 200, 220)
        self.set_xy(0, 6)
        self.cell(200, 6, datetime.now().strftime("%d/%m/%Y %H:%M"), align="R")
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.cell(0, 8, f"CyberGuardian EASM Platform  -  Page {self.page_no()}  -  Confidentiel", align="C")

    def section_title(self, title: str):
        self.ln(4)
        self.set_fill_color(*BLUE_MED)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 7, _ascii(f"  {title}"), ln=True, fill=True)
        self.ln(2)

    def kv_row(self, key: str, value: str, value_color=None):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*GRAY_MID)
        self.set_x(12)
        self.cell(52, 6, _ascii(key))
        self.set_text_color(*(value_color or GRAY_DARK))
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 6, _ascii(value), ln=True)

    def score_bar(self, pts: int, max_pts: int, label: str):
        bar_x, bar_y = 12, self.get_y()
        bar_w, bar_h = 130, 5
        pct     = int((pts / max_pts) * 100) if max_pts else 0
        fill_w  = int((pts / max_pts) * bar_w) if max_pts else 0
        color   = _score_color(pct)

        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_MID)
        self.set_xy(bar_x, bar_y)
        self.cell(52, 5, _ascii(label))

        self.set_fill_color(*GRAY_LIGHT)
        self.rect(bar_x + 52, bar_y + 0.5, bar_w, bar_h, "F")
        if fill_w > 0:
            self.set_fill_color(*color)
            self.rect(bar_x + 52, bar_y + 0.5, fill_w, bar_h, "F")

        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*color)
        self.set_xy(bar_x + 52 + bar_w + 4, bar_y)
        self.cell(20, 5, f"{pts}/{max_pts}")
        self.ln(8)

    def finding_box(self, sev: str, title: str, desc: str, tool: str = "", extra: str = ""):
        color   = _sev_color(sev)
        box_x   = 12
        box_w   = 186
        y_start = self.get_y()

        self.set_fill_color(*color)
        self.rect(box_x, y_start, 3, 18, "F")

        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*color)
        self.set_xy(box_x + 6, y_start + 1)
        self.cell(22, 5, _ascii(sev.upper()))

        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*GRAY_DARK)
        self.set_xy(box_x + 30, y_start + 1)
        self.cell(0, 5, _ascii(title), ln=True)

        self.set_font("Helvetica", "", 8)
        self.set_text_color(*GRAY_MID)
        self.set_x(box_x + 6)
        self.multi_cell(box_w - 6, 4.5, _ascii(desc))

        if extra:
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(*GRAY_MID)
            self.set_x(box_x + 6)
            self.multi_cell(box_w - 6, 4.5, _ascii(extra))

        if tool:
            self.set_font("Helvetica", "I", 7.5)
            self.set_text_color(150, 160, 170)
            self.set_x(box_x + 6)
            self.cell(0, 4, _ascii(tool), ln=True)

        y_end = self.get_y()
        self.set_draw_color(*GRAY_LIGHT)
        self.line(box_x, y_end, box_x + box_w, y_end)
        self.ln(3)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _empty_ok(pdf: CyberGuardianPDF, msg: str = "Aucune vulnerabilite detectee."):
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*GREEN)
    pdf.set_x(12)
    pdf.cell(0, 7, msg, ln=True)


# ── Section EASM (SSL/TLS) ───────────────────────────────────────────────────

def _section_ssl(pdf: CyberGuardianPDF, scan: dict):
    ssl    = scan.get("results", {}).get("ssl", {})
    issues = scan.get("issues", [])

    pdf.section_title("Details SSL / TLS")
    pdf.score_bar(ssl.get("score", 0), 25, "Score SSL")
    pdf.kv_row("Version TLS",  ssl.get("tls_version") or "-")
    pdf.kv_row("Cipher suite", ssl.get("cipher_suite") or "-")
    pdf.kv_row("Certificat",   "Valide" if ssl.get("valid") else "Invalide",
               GREEN if ssl.get("valid") else RED)
    pdf.kv_row("Auto-signe",   "Oui" if ssl.get("self_signed") else "Non",
               RED if ssl.get("self_signed") else GREEN)
    pdf.kv_row("Emis pour",    ssl.get("issued_to") or "-")
    pdf.kv_row("Emis par",     ssl.get("issued_by") or "-")
    pdf.kv_row("Expiration",   ssl.get("expiry_date") or "-")
    days = ssl.get("days_until_expiry")
    if days is not None:
        c   = RED if days < 0 else ORANGE if days <= 30 else GREEN
        txt = "Expire !" if days < 0 else f"{days} jours restants"
        pdf.kv_row("Jours restants", txt, c)
    sans = ssl.get("sans", [])
    if sans:
        pdf.kv_row("SAN (domaines)", _ascii(", ".join(sans[:5]) + ("..." if len(sans) > 5 else "")))

    pdf.section_title(f"Problemes detectes  ({len(issues)})")
    if not issues:
        _empty_ok(pdf, "Aucun probleme SSL detecte.")
    else:
        for iss in issues:
            pdf.finding_box(
                sev   = iss.get("severity", ""),
                title = iss.get("title", ""),
                desc  = iss.get("desc", ""),
                tool  = iss.get("tool", ""),
            )

    # CVE
    cves = scan.get("results", {}).get("cves", [])
    if cves:
        pdf.section_title(f"CVE identifiees  ({len(cves)})")
        banner = scan.get("results", {}).get("server_banner", "")
        if banner:
            pdf.set_font("Helvetica", "I", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 6, f"Serveur detecte : {_ascii(banner)}", ln=True)
        for cve in cves:
            pdf.finding_box(
                sev   = cve.get("severity", "LOW"),
                title = cve.get("title", ""),
                desc  = f"{cve.get('id', '')}  |  CVSS {cve.get('cvss', '-')}",
                tool  = "check_tls_cves() / check_service_cves()",
            )

    pdf.section_title("Recommandations")
    for i, rec in enumerate(_build_ssl_recommendations(ssl, issues), 1):
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _ascii(f"{i}. {rec}"))
        pdf.ln(1)


# ── Section GitHub ────────────────────────────────────────────────────────────

def _section_github(pdf: CyberGuardianPDF, scan: dict):
    r         = scan.get("results", {})
    info      = r.get("github_info", {})
    bandit    = r.get("bandit", {})
    safety    = r.get("safety", {})
    truffle   = r.get("trufflehog", {})
    npm       = r.get("npm_audit", {})
    language  = r.get("langage") or info.get("language") or "N/A"
    score_max = r.get("score_max", 30)
    score     = scan.get("score", 0)

    # ── Infos depot ──────────────────────────────────────────────────────────
    pdf.section_title("Informations du depot GitHub")
    pdf.score_bar(score, score_max, "Score securite")
    pdf.kv_row("Depot",           scan.get("target", "-"))
    pdf.kv_row("Langage principal", language)
    pdf.kv_row("Visibilite",       info.get("visibility") or "-")
    pdf.kv_row("Licence",          info.get("license") or "Aucune")
    pdf.kv_row("Branche par defaut", info.get("default_branch") or "-")
    pdf.kv_row("Branches",         str(info.get("branches") or "-"))
    pdf.kv_row("Contributeurs",    str(info.get("contributors") or "-"))
    pdf.kv_row("Stars",            str(info.get("stars") or "0"))
    pdf.kv_row("Forks",            str(info.get("forks") or "0"))
    pdf.kv_row("Issues ouvertes",  str(info.get("open_issues") or "0"))
    if info.get("size_kb"):
        pdf.kv_row("Taille",       f"{info['size_kb']} KB")
    if info.get("created_at"):
        pdf.kv_row("Cree le",      _ascii(str(info["created_at"])))
    if info.get("updated_at"):
        pdf.kv_row("Mis a jour",   _ascii(str(info["updated_at"])))
    if info.get("description"):
        pdf.ln(1)
        pdf.set_font("Helvetica", "I", 8.5)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _ascii(f'"{info["description"]}"'))

    # ── Bandit ───────────────────────────────────────────────────────────────
    b_findings = bandit.get("findings", [])
    b_loc      = bandit.get("loc", 0)
    b_note     = bandit.get("note", "")
    b_err      = bandit.get("error", "")

    pdf.section_title(f"Bandit — Analyse statique Python  ({len(b_findings)} finding(s))")
    if b_err or b_note:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _ascii(b_note or b_err))
    elif not b_findings:
        if b_loc:
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 5, f"{b_loc} lignes analysees", ln=True)
        _empty_ok(pdf)
    else:
        if b_loc:
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 5, f"{b_loc} lignes de code analysees", ln=True)
            pdf.ln(1)
        for f in b_findings:
            pdf.finding_box(
                sev   = f.get("severity", "LOW"),
                title = f.get("issue", "-"),
                desc  = f"{f.get('file', '-')} | ligne {f.get('line', '-')}",
                extra = f.get("code", ""),
                tool  = "scan_bandit()",
            )

    # ── Safety ───────────────────────────────────────────────────────────────
    s_findings = safety.get("findings", [])
    s_pkg      = safety.get("packages_checked", 0)
    s_file     = safety.get("requirements_file", "")
    s_note     = safety.get("note", "")
    s_err      = safety.get("error", "")

    pdf.section_title(f"Safety — Dependances Python vulnérables  ({len(s_findings)})")
    if s_err or s_note:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _ascii(s_note or s_err))
    elif not s_findings:
        msg = f"{s_pkg} dependances verifiees — aucune CVE connue" if s_pkg else "Aucun fichier requirements.txt trouve"
        if s_file:
            msg += f" ({s_file})"
        _empty_ok(pdf, msg)
    else:
        if s_file:
            pdf.set_font("Helvetica", "", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 5, f"{s_file} | {s_pkg} dependances", ln=True)
            pdf.ln(1)
        for f in s_findings:
            pdf.finding_box(
                sev   = f.get("severity", "MEDIUM"),
                title = f"{f.get('package', '-')} v{f.get('version', '-')}",
                desc  = f.get("desc", "-"),
                extra = f"CVE : {f.get('cve', '-')} | pip install {f.get('package', '')} --upgrade",
                tool  = "scan_safety()",
            )

    # ── npm audit ─────────────────────────────────────────────────────────────
    npm_findings = (npm or {}).get("findings", [])
    npm_err      = (npm or {}).get("error", "")
    npm_summary  = (npm or {}).get("summary")
    if npm_findings or (npm and not npm_err):
        pdf.section_title(f"npm audit — Dependances JavaScript  ({len(npm_findings)})")
        if npm_err:
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.multi_cell(186, 5, _ascii(npm_err))
        elif not npm_findings:
            _empty_ok(pdf, "Aucune vulnerabilite npm detectee.")
        else:
            if npm_summary:
                parts = [f"{v} {k}" for k, v in npm_summary.items() if v > 0]
                if parts:
                    pdf.set_font("Helvetica", "", 8.5)
                    pdf.set_text_color(*GRAY_MID)
                    pdf.set_x(12)
                    pdf.cell(0, 5, "Resume : " + ", ".join(parts), ln=True)
                    pdf.ln(1)
            for f in npm_findings:
                sev = f.get("severity", "low")
                pdf.finding_box(
                    sev   = "MEDIUM" if sev == "moderate" else sev.upper(),
                    title = f.get("package", "-"),
                    desc  = f.get("issue", "-"),
                    extra = f"Versions affectees : {f.get('range', '-')}" if f.get("range") else "",
                    tool  = "scan_npm_audit()",
                )

    # ── TruffleHog ────────────────────────────────────────────────────────────
    t_findings = truffle.get("findings", [])
    t_err      = truffle.get("error", "")

    pdf.section_title(f"TruffleHog — Secrets exposes  ({len(t_findings)})")
    if t_err:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _ascii(t_err))
    elif not t_findings:
        _empty_ok(pdf, "Aucun secret expose detecte.")
    else:
        for f in t_findings:
            extra = ""
            if f.get("verified"):
                extra = "ACTIF : Ce secret est valide. Revoquez-le immediatement sur la plateforme concernee."
            pdf.finding_box(
                sev   = "CRITICAL" if f.get("verified") else "HIGH",
                title = f.get("type", "Secret inconnu"),
                desc  = f"{f.get('file', '-')} | ligne {f.get('line', '-')} | {f.get('value', '')[:60]}",
                extra = extra,
                tool  = "scan_trufflehog()",
            )

    # ── Recommandations ───────────────────────────────────────────────────────
    pdf.section_title("Recommandations")
    recs = _build_github_recommendations(b_findings, s_findings, t_findings, npm_findings)
    for i, rec in enumerate(recs, 1):
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _ascii(f"{i}. {rec}"))
        pdf.ln(1)


# ── Point d'entree ────────────────────────────────────────────────────────────

def generate_scan_pdf(scan: dict, ai_explanation: str = "") -> bytes:
    is_github = scan.get("type") == "github"
    score     = scan.get("score", 0)
    score_max = scan.get("results", {}).get("score_max", 30) if is_github else 100
    score_pct = int((score / score_max) * 100) if score_max else 0
    target    = scan.get("target", "-")
    sc        = _score_color(score_pct)

    pdf = CyberGuardianPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Hero ──────────────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*sc)
    pdf.set_x(12)
    pdf.cell(30, 12, str(score), ln=False)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(14, 12, f"/ {score_max}", ln=False)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(*GRAY_DARK)
    pdf.cell(0, 12, _ascii(target), ln=True)

    label = "Bon" if score_pct >= 80 else "Niveau moyen" if score_pct >= 50 else "Critique"
    if is_github:
        subtitle = f"Analyse GitHub  |  {label}  |  Scan du {_ascii(scan.get('date', '-'))}"
    else:
        grade    = scan.get("results", {}).get("ssl", {}).get("grade", "-")
        subtitle = f"Grade SSL : {grade}  |  {label}  |  Scan du {_ascii(scan.get('date', '-'))}"

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*GRAY_MID)
    pdf.set_x(12)
    pdf.cell(0, 5, subtitle, ln=True)
    pdf.ln(4)

    # ── Corps selon le type ───────────────────────────────────────────────────
    if is_github:
        _section_github(pdf, scan)
    else:
        _section_ssl(pdf, scan)

    # ── Explication IA ────────────────────────────────────────────────────────
    if ai_explanation:
        pdf.section_title("Ce que ca signifie pour vous")
        pdf.set_x(12)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.multi_cell(186, 6, _ascii(ai_explanation))
        pdf.ln(2)

    return bytes(pdf.output())


# ── Recommandations ───────────────────────────────────────────────────────────

def _build_ssl_recommendations(ssl: dict, issues: list) -> list[str]:
    recs = []
    if not ssl.get("valid"):
        recs.append("Installez un certificat SSL valide signe par une autorite reconnue (Let's Encrypt, DigiCert).")
    if ssl.get("expired"):
        recs.append("Renouvelez immediatement votre certificat SSL expire.")
    days = ssl.get("days_until_expiry")
    if days is not None and 0 < days <= 30:
        recs.append(f"Renouvelez votre certificat dans les {days} jours.")
    if ssl.get("self_signed"):
        recs.append("Remplacez le certificat auto-signe par un certificat d'une CA publique reconnue.")
    if ssl.get("tls_version") in ("TLSv1", "TLSv1.1"):
        recs.append("Desactivez TLS 1.0 et 1.1. Activez uniquement TLS 1.2 et TLS 1.3.")
    if not recs:
        recs.append("La configuration SSL/TLS est correcte. Maintenez le renouvellement automatique.")
    return recs


def _build_github_recommendations(bandit, safety, truffle, npm) -> list[str]:
    recs = []
    if truffle:
        recs.append(
            f"{len(truffle)} secret(s) expose(s) detecte(s). Revoquez immediatement les tokens concernes "
            "sur GitHub, AWS ou la plateforme correspondante, puis ajoutez ces fichiers au .gitignore."
        )
    verified = [f for f in truffle if f.get("verified")]
    if verified:
        recs.append("Des secrets ACTIFS ont ete confirmes. Invalidez les cles API / tokens sans delai.")
    if safety:
        pkgs = list({f.get("package", "") for f in safety if f.get("package")})
        recs.append(
            f"Mettez a jour les dependances Python vulnerables : {', '.join(pkgs[:5])}. "
            "Utilisez : pip install <package> --upgrade"
        )
    if npm:
        recs.append(
            f"{len(npm)} vulnerabilite(s) npm detectee(s). Executez : npm audit fix "
            "pour corriger les vulnerabilites corrigeables automatiquement."
        )
    high_bandit = [f for f in bandit if f.get("severity") in ("HIGH", "CRITICAL")]
    if high_bandit:
        recs.append(
            f"{len(high_bandit)} probleme(s) critique(s) Bandit detecte(s) dans le code Python. "
            "Consultez les details ci-dessus et corrigez les injections, eval() sur entrees utilisateur "
            "et mots de passe codes en dur."
        )
    if not recs:
        recs.append("Aucune vulnerabilite critique detectee. Activez Dependabot sur GitHub pour "
                    "surveiller automatiquement les nouvelles CVE sur vos dependances.")
        recs.append("Maintenez les dependances a jour et activez la protection des branches sur GitHub.")
    return recs

import os
from fpdf import FPDF
from datetime import datetime

# Police Unicode du document (accents français rendus correctement).
# Segoe UI est présente sur Windows ; repli sur Helvetica si introuvable.
FONT = "CG"
_FONT_DIR = r"C:\Windows\Fonts"
_FONT_FILES = {
    "":  os.path.join(_FONT_DIR, "segoeui.ttf"),
    "B": os.path.join(_FONT_DIR, "segoeuib.ttf"),
    "I": os.path.join(_FONT_DIR, "segoeuii.ttf"),
}


def _register_fonts(pdf: "FPDF") -> str:
    """Enregistre la police Unicode ; retourne le nom de famille utilisable."""
    if all(os.path.exists(p) for p in _FONT_FILES.values()):
        for style, path in _FONT_FILES.items():
            pdf.add_font(FONT, style, path)
        return FONT
    return "Helvetica"   # repli : accents non garantis, mais pas de plantage


def _clean(text: str) -> str:
    """Nettoie le texte tout en conservant les accents (police Unicode).
    Retire seulement le balisage Markdown que le LLM peut produire."""
    if not text:
        return ""
    return str(text).replace("**", "").replace("*", "")


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


# Ordre de tri des CVE par priorité combinée CVSS x EPSS
_PRIORITY_ORDER = {"URGENTE": 0, "ÉLEVÉE": 1, "À SURVEILLER": 2, "FAIBLE": 3}


def _priority_rank(priority: str | None) -> int:
    return _PRIORITY_ORDER.get(priority or "", 4)


class CyberGuardianPDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font(FONT, "B", 11)
        self.set_text_color(*WHITE)
        self.set_xy(10, 4)
        self.cell(0, 10, "CyberGuardian  ·  Rapport de sécurité", ln=False)
        self.set_font(FONT, "", 8)
        self.set_text_color(180, 200, 220)
        self.set_xy(0, 6)
        self.cell(200, 6, datetime.now().strftime("%d/%m/%Y  %H:%M"), align="R")
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font(FONT, "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.cell(0, 8, f"CyberGuardian  ·  Page {self.page_no()}  ·  Document confidentiel", align="C")

    def section_title(self, title: str):
        # Style sobre : filet bleu à gauche + titre foncé + fin trait de séparation
        self.ln(5)
        y = self.get_y()
        self.set_fill_color(*BLUE_MED)
        self.rect(10, y + 0.5, 2.5, 5, "F")
        self.set_font(FONT, "B", 10.5)
        self.set_text_color(*BLUE_DARK)
        self.set_xy(15, y)
        self.cell(0, 6, _clean(title), ln=True)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y() + 0.5, 200, self.get_y() + 0.5)
        self.ln(3)

    def kv_row(self, key: str, value: str, value_color=None):
        self.set_font(FONT, "", 9)
        self.set_text_color(*GRAY_MID)
        self.set_x(12)
        self.cell(52, 6, _clean(key))
        self.set_text_color(*(value_color or GRAY_DARK))
        self.set_font(FONT, "B", 9)
        self.cell(0, 6, _clean(value), ln=True)

    def score_bar(self, pts: int, max_pts: int, label: str):
        bar_x, bar_y = 12, self.get_y()
        bar_w, bar_h = 130, 5
        pct     = int((pts / max_pts) * 100) if max_pts else 0
        fill_w  = int((pts / max_pts) * bar_w) if max_pts else 0
        color   = _score_color(pct)

        self.set_font(FONT, "", 8.5)
        self.set_text_color(*GRAY_MID)
        self.set_xy(bar_x, bar_y)
        self.cell(52, 5, _clean(label))

        self.set_fill_color(*GRAY_LIGHT)
        self.rect(bar_x + 52, bar_y + 0.5, bar_w, bar_h, "F")
        if fill_w > 0:
            self.set_fill_color(*color)
            self.rect(bar_x + 52, bar_y + 0.5, fill_w, bar_h, "F")

        self.set_font(FONT, "B", 8.5)
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

        self.set_font(FONT, "B", 7.5)
        self.set_text_color(*color)
        self.set_xy(box_x + 6, y_start + 1)
        self.cell(22, 5, _clean(sev.upper()))

        self.set_font(FONT, "B", 9)
        self.set_text_color(*GRAY_DARK)
        self.set_xy(box_x + 30, y_start + 1)
        self.cell(0, 5, _clean(title), ln=True)

        self.set_font(FONT, "", 8)
        self.set_text_color(*GRAY_MID)
        self.set_x(box_x + 6)
        self.multi_cell(box_w - 6, 4.5, _clean(desc))

        if extra:
            self.set_font(FONT, "I", 8)
            self.set_text_color(*GRAY_MID)
            self.set_x(box_x + 6)
            self.multi_cell(box_w - 6, 4.5, _clean(extra))

        if tool:
            self.set_font(FONT, "I", 7.5)
            self.set_text_color(150, 160, 170)
            self.set_x(box_x + 6)
            self.cell(0, 4, _clean(tool), ln=True)

        y_end = self.get_y()
        self.set_draw_color(*GRAY_LIGHT)
        self.line(box_x, y_end, box_x + box_w, y_end)
        self.ln(3)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _empty_ok(pdf: CyberGuardianPDF, msg: str = "Aucune vulnérabilité détectée."):
    pdf.set_font(FONT, "I", 9)
    pdf.set_text_color(*GREEN)
    pdf.set_x(12)
    pdf.cell(0, 7, msg, ln=True)


# ── Section EASM (DNS + SSL/TLS + Headers) ───────────────────────────────────

def _section_ssl(pdf: CyberGuardianPDF, scan: dict):
    results = scan.get("results", {})
    ssl     = results.get("ssl", {})
    dns     = results.get("dns")
    whois   = results.get("whois")
    headers = results.get("headers")
    issues  = scan.get("issues", [])

    # Détail du score pondéré par critère
    breakdown = results.get("score_detail", {}).get("breakdown", [])
    if breakdown:
        pdf.section_title("Détail du score pondéré")
        for b in breakdown:
            pdf.score_bar(b.get("points", 0), b.get("max", 25), b.get("label", ""))

    # DNS anti-phishing
    if dns:
        pdf.section_title("DNS (SPF, DMARC, DKIM, DNSSEC)")
        pdf.kv_row("SPF",   "Présent" if dns.get("spf_present") else "ABSENT",
                   GREEN if dns.get("spf_present") else RED)
        policy = dns.get("dmarc_policy")
        pdf.kv_row("DMARC", f"Présent (p={policy})" if dns.get("dmarc_present") else "ABSENT",
                   GREEN if dns.get("dmarc_present") and policy in ("quarantine", "reject")
                   else ORANGE if dns.get("dmarc_present") else RED)
        pdf.kv_row("DKIM",  f"Présent (sélecteur {dns.get('dkim_selector')})" if dns.get("dkim_present")
                   else "Non détecté (sélecteurs courants)",
                   GREEN if dns.get("dkim_present") else ORANGE)
        pdf.kv_row("DNSSEC", "Activé" if dns.get("dnssec_enabled") else "Absent",
                   GREEN if dns.get("dnssec_enabled") else ORANGE)
        mx = dns.get("mx_records", [])
        pdf.kv_row("Serveurs MX", ", ".join(mx[:3]) + ("..." if len(mx) > 3 else "") if mx else "Aucun")

    # WHOIS — identite et expiration du domaine
    if whois and whois.get("found"):
        pdf.section_title("WHOIS (propriétaire et expiration du domaine)")
        pdf.kv_row("Registrar", whois.get("registrar") or "-")
        if whois.get("owner"):
            pdf.kv_row("Propriétaire", whois.get("owner"))
        pdf.kv_row("Créé le",    whois.get("created") or "-")
        pdf.kv_row("Expiré le",  whois.get("expires") or "-")
        d = whois.get("days_until_expiry")
        if d is not None:
            c   = RED if d < 0 else ORANGE if d <= 30 else GREEN
            txt = f"Expiré depuis {abs(d)} jours !" if d < 0 else f"{d} jours restants"
            pdf.kv_row("Échéance", txt, c)

    pdf.section_title("Détails SSL / TLS")
    pdf.score_bar(ssl.get("score", 0), 25, "Score SSL")
    pdf.kv_row("Version TLS",  ssl.get("tls_version") or "-")
    pdf.kv_row("Cipher suite", ssl.get("cipher_suite") or "-")
    pdf.kv_row("Certificat",   "Valide" if ssl.get("valid") else "Invalide",
               GREEN if ssl.get("valid") else RED)
    pdf.kv_row("Auto-signé",   "Oui" if ssl.get("self_signed") else "Non",
               RED if ssl.get("self_signed") else GREEN)
    pdf.kv_row("Émis pour",    ssl.get("issued_to") or "-")
    pdf.kv_row("Émis par",     ssl.get("issued_by") or "-")
    pdf.kv_row("Expiration",   ssl.get("expiry_date") or "-")
    days = ssl.get("days_until_expiry")
    if days is not None:
        c   = RED if days < 0 else ORANGE if days <= 30 else GREEN
        txt = "Expiré !" if days < 0 else f"{days} jours restants"
        pdf.kv_row("Jours restants", txt, c)
    sans = ssl.get("sans", [])
    if sans:
        pdf.kv_row("SAN (domaines)", _clean(", ".join(sans[:5]) + ("..." if len(sans) > 5 else "")))

    # En-têtes de sécurité HTTP
    if headers:
        present = headers.get("headers_present", {})
        missing = headers.get("headers_missing", [])
        pdf.section_title(f"En-têtes de sécurité HTTP  ({len(present)} présents, {len(missing)} manquants)")
        for name in present:
            pdf.kv_row(name, "Présent", GREEN)
        for name in missing:
            pdf.kv_row(name, "Manquant", RED)

    pdf.section_title(f"Problèmes détectés  ({len(issues)})")
    if not issues:
        _empty_ok(pdf, "Aucun probleme SSL détecté.")
    else:
        for iss in issues:
            pdf.finding_box(
                sev   = iss.get("severity", ""),
                title = iss.get("title", ""),
                desc  = iss.get("desc", ""),
                tool  = iss.get("tool", ""),
            )

    # CVE — gravité (CVSS) croisée avec probabilité d'exploitation (EPSS)
    cves = scan.get("results", {}).get("cves", [])
    if cves:
        pdf.section_title(f"CVE identifiées  ({len(cves)})")
        banner = scan.get("results", {}).get("server_banner", "")
        if banner:
            pdf.set_font(FONT, "I", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 6, f"Serveur détecté : {_clean(banner)}", ln=True)
        # CVE triées par priorité combinée (URGENTE d'abord)
        for cve in sorted(cves, key=lambda c: _priority_rank(c.get("priority"))):
            desc = f"{cve.get('id', '')}  |  CVSS {cve.get('cvss', '-')}"
            epss = cve.get("epss")
            if epss is not None:
                desc += f"  |  EPSS {round(epss * 100, 1)}%  (probabilité d'exploitation a 30 j)"
            extra = ""
            prio = cve.get("priority")
            if prio:
                extra = f"Priorité (CVSS x EPSS) : {prio}"
            pdf.finding_box(
                sev   = cve.get("severity", "LOW"),
                title = cve.get("title", ""),
                desc  = desc,
                extra = extra,
                tool  = "check_service_cves() / check_epss()",
            )

    pdf.section_title("Recommandations")
    for i, rec in enumerate(_build_easm_recommendations(ssl, dns, whois, headers, issues), 1):
        pdf.set_font(FONT, "", 9)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _clean(f"{i}. {rec}"))
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
    pdf.score_bar(score, score_max, "Score sécurité")
    pdf.kv_row("Dépôt",           scan.get("target", "-"))
    pdf.kv_row("Langage principal", language)
    pdf.kv_row("Visibilité",       info.get("visibility") or "-")
    pdf.kv_row("Licence",          info.get("license") or "Aucune")
    pdf.kv_row("Branche par défaut", info.get("default_branch") or "-")
    pdf.kv_row("Branches",         str(info.get("branches") or "-"))
    pdf.kv_row("Contributeurs",    str(info.get("contributors") or "-"))
    pdf.kv_row("Stars",            str(info.get("stars") or "0"))
    pdf.kv_row("Forks",            str(info.get("forks") or "0"))
    pdf.kv_row("Issues ouvertes",  str(info.get("open_issues") or "0"))
    if info.get("size_kb"):
        pdf.kv_row("Taille",       f"{info['size_kb']} KB")
    if info.get("created_at"):
        pdf.kv_row("Créé le",      _clean(str(info["created_at"])))
    if info.get("updated_at"):
        pdf.kv_row("Mis à jour",   _clean(str(info["updated_at"])))
    if info.get("description"):
        pdf.ln(1)
        pdf.set_font(FONT, "I", 8.5)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _clean(f'"{info["description"]}"'))

    # ── Bandit ───────────────────────────────────────────────────────────────
    b_findings = bandit.get("findings", [])
    b_loc      = bandit.get("loc", 0)
    b_note     = bandit.get("note", "")
    b_err      = bandit.get("error", "")

    pdf.section_title(f"Bandit — Analyse statique Python  ({len(b_findings)} finding(s))")
    if b_err or b_note:
        pdf.set_font(FONT, "I", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _clean(b_note or b_err))
    elif not b_findings:
        if b_loc:
            pdf.set_font(FONT, "", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 5, f"{b_loc} lignes analysées", ln=True)
        _empty_ok(pdf)
    else:
        if b_loc:
            pdf.set_font(FONT, "", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 5, f"{b_loc} lignes de code analysées", ln=True)
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

    pdf.section_title(f"Safety — Dépendances Python vulnérables  ({len(s_findings)})")
    if s_err or s_note:
        pdf.set_font(FONT, "I", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _clean(s_note or s_err))
    elif not s_findings:
        msg = f"{s_pkg} dépendances vérifiées — aucune CVE connue" if s_pkg else "Aucun fichier requirements.txt trouvé"
        if s_file:
            msg += f" ({s_file})"
        _empty_ok(pdf, msg)
    else:
        if s_file:
            pdf.set_font(FONT, "", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.cell(0, 5, f"{s_file} | {s_pkg} dépendances", ln=True)
            pdf.ln(1)
        for f in sorted(s_findings, key=lambda c: _priority_rank(c.get("priority"))):
            epss = f.get("epss")
            epss_txt = f"  |  EPSS {round(epss * 100, 1)}%" if epss is not None else ""
            prio = f.get("priority")
            prio_txt = f"  |  Priorité : {prio}" if prio else ""
            pdf.finding_box(
                sev   = f.get("severity", "MEDIUM"),
                title = f"{f.get('package', '-')} v{f.get('version', '-')}",
                desc  = f"{f.get('desc', '-')}",
                extra = f"CVE : {f.get('cve', '-')}{epss_txt}{prio_txt}  |  pip install {f.get('package', '')} --upgrade",
                tool  = "scan_safety() / check_epss()",
            )

    # ── npm audit ─────────────────────────────────────────────────────────────
    npm_findings = (npm or {}).get("findings", [])
    npm_err      = (npm or {}).get("error", "")
    npm_summary  = (npm or {}).get("summary")
    if npm_findings or (npm and not npm_err):
        pdf.section_title(f"npm audit — Dépendances JavaScript  ({len(npm_findings)})")
        if npm_err:
            pdf.set_font(FONT, "I", 9)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(12)
            pdf.multi_cell(186, 5, _clean(npm_err))
        elif not npm_findings:
            _empty_ok(pdf, "Aucune vulnérabilité npm détectée.")
        else:
            if npm_summary:
                parts = [f"{v} {k}" for k, v in npm_summary.items() if v > 0]
                if parts:
                    pdf.set_font(FONT, "", 8.5)
                    pdf.set_text_color(*GRAY_MID)
                    pdf.set_x(12)
                    pdf.cell(0, 5, "Résumé : " + ", ".join(parts), ln=True)
                    pdf.ln(1)
            for f in npm_findings:
                sev = f.get("severity", "low")
                pdf.finding_box(
                    sev   = "MEDIUM" if sev == "moderate" else sev.upper(),
                    title = f.get("package", "-"),
                    desc  = f.get("issue", "-"),
                    extra = f"Versions affectées : {f.get('range', '-')}" if f.get("range") else "",
                    tool  = "scan_npm_audit()",
                )

    # ── TruffleHog ────────────────────────────────────────────────────────────
    t_findings = truffle.get("findings", [])
    t_err      = truffle.get("error", "")

    pdf.section_title(f"TruffleHog — Secrets exposés  ({len(t_findings)})")
    if t_err:
        pdf.set_font(FONT, "I", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _clean(t_err))
    elif not t_findings:
        _empty_ok(pdf, "Aucun secret exposé détecté.")
    else:
        for f in t_findings:
            extra = ""
            if f.get("verified"):
                extra = "ACTIF : Ce secret est valide. Révoquez-le immédiatement sur la plateforme concernée."
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
        pdf.set_font(FONT, "", 9)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _clean(f"{i}. {rec}"))
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
    _register_fonts(pdf)            # police Unicode avant add_page (l'en-tête l'utilise)
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Hero ──────────────────────────────────────────────────────────────────
    pdf.set_font(FONT, "B", 22)
    pdf.set_text_color(*sc)
    pdf.set_x(12)
    pdf.cell(30, 12, str(score), ln=False)
    pdf.set_font(FONT, "", 10)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(14, 12, f"/ {score_max}", ln=False)
    pdf.set_font(FONT, "B", 13)
    pdf.set_text_color(*GRAY_DARK)
    pdf.cell(0, 12, _clean(target), ln=True)

    label = "Bon" if score_pct >= 80 else "Niveau moyen" if score_pct >= 50 else "Critique"
    if is_github:
        subtitle = f"Analyse GitHub  ·  {label}  ·  Scan du {_clean(scan.get('date', '-'))}"
    else:
        grade    = scan.get("results", {}).get("ssl", {}).get("grade", "-")
        subtitle = f"Grade SSL : {grade}  ·  {label}  ·  Scan du {_clean(scan.get('date', '-'))}"

    pdf.set_font(FONT, "", 9)
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
        pdf.section_title("Synthèse")
        pdf.set_x(12)
        pdf.set_font(FONT, "", 9.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.multi_cell(186, 6, _clean(ai_explanation))
        pdf.ln(2)

    return bytes(pdf.output())


# ── Recommandations ───────────────────────────────────────────────────────────

def _build_easm_recommendations(ssl: dict, dns: dict | None, whois: dict | None,
                                headers: dict | None, issues: list) -> list[str]:
    recs = []

    # WHOIS — priorité absolue si le domaine est expiré ou proche de l'expiration
    if whois and whois.get("found"):
        d = whois.get("days_until_expiry")
        if d is not None and d < 0:
            recs.append("Renouvelez IMMEDIATEMENT votre nom de domaine expire : il peut etre rachete "
                        "par un tiers qui prendrait le contrôle du site et des emails.")
        elif d is not None and d <= 30:
            recs.append(f"Renouvelez votre nom de domaine sous {d} jours pour eviter une interruption "
                        "de service et un risque de detournement.")

    # DNS — priorité anti-phishing (critère le plus lourd du score)
    if dns:
        if not dns.get("spf_present"):
            recs.append("Ajoutez un enregistrement SPF (TXT 'v=spf1 ...') : sans lui, n'importe quel "
                        "serveur peut envoyer des emails au nom de votre domaine.")
        if not dns.get("dmarc_present"):
            recs.append("Configurez DMARC (TXT 'v=DMARC1; p=quarantine;' sur _dmarc.votredomaine) pour "
                        "bloquer l'usurpation d'emails. C'est la mesure anti-phishing la plus efficace.")
        elif dns.get("dmarc_policy") == "none":
            recs.append("Durcissez votre politique DMARC : passez de p=none (surveillance seule) a "
                        "p=quarantine puis p=reject.")
        if not dns.get("dkim_present"):
            recs.append("Activez la signature DKIM auprès de votre fournisseur email (Google Workspace, "
                        "Microsoft 365...) pour authentifier vos emails sortants.")
        if not dns.get("dnssec_enabled"):
            recs.append("Activez DNSSEC chez votre hébergeur DNS pour signer vos réponses DNS et empêcher "
                        "l'empoisonnement de cache (redirection furtive de vos visiteurs).")

    # SSL/TLS
    if not ssl.get("valid"):
        recs.append("Installez un certificat SSL valide signé par une autorité reconnue (Let's Encrypt, DigiCert).")
    if ssl.get("expired"):
        recs.append("Renouvelez immédiatement votre certificat SSL expire.")
    days = ssl.get("days_until_expiry")
    if days is not None and 0 < days <= 30:
        recs.append(f"Renouvelez votre certificat dans les {days} jours.")
    if ssl.get("self_signed"):
        recs.append("Remplacez le certificat auto-signé par un certificat d'une CA publique reconnue.")
    if ssl.get("tls_version") in ("TLSv1", "TLSv1.1"):
        recs.append("Désactivez TLS 1.0 et 1.1. Activez uniquement TLS 1.2 et TLS 1.3.")

    # En-têtes HTTP
    if headers:
        missing = headers.get("headers_missing", [])
        if "strict-transport-security" in missing:
            recs.append("Activez HSTS (Strict-Transport-Security: max-age=31536000) pour empêcher les "
                        "attaques de rétrogradation vers HTTP.")
        if "content-security-policy" in missing:
            recs.append("Définissez une Content-Security-Policy pour bloquer l'exécution de scripts "
                        "injectés (protection XSS).")
        others = [h for h in missing if h not in ("strict-transport-security", "content-security-policy")]
        if others:
            recs.append("Ajoutez les en-têtes de sécurité restants : " + ", ".join(others) + ".")

    if not recs:
        recs.append("La configuration est correcte sur tous les criteres evalues. Maintenez le "
                    "renouvellement automatique du certificat et surveillez votre posture regulierement.")
    return recs


def _build_github_recommendations(bandit, safety, truffle, npm) -> list[str]:
    recs = []
    if truffle:
        recs.append(
            f"{len(truffle)} secret(s) expose(s) détecté(s). Révoquez immédiatement les tokens concernes "
            "sur GitHub, AWS ou la plateforme correspondante, puis ajoutez ces fichiers au .gitignore."
        )
    verified = [f for f in truffle if f.get("verified")]
    if verified:
        recs.append("Des secrets ACTIFS ont ete confirmes. Invalidez les cles API / tokens sans delai.")
    if safety:
        pkgs = list({f.get("package", "") for f in safety if f.get("package")})
        recs.append(
            f"Mettez a jour les dépendances Python vulnerables : {', '.join(pkgs[:5])}. "
            "Utilisez : pip install <package> --upgrade"
        )
    if npm:
        recs.append(
            f"{len(npm)} vulnérabilité(s) npm détectée(s). Executez : npm audit fix "
            "pour corriger les vulnérabilités corrigeables automatiquement."
        )
    high_bandit = [f for f in bandit if f.get("severity") in ("HIGH", "CRITICAL")]
    if high_bandit:
        recs.append(
            f"{len(high_bandit)} probleme(s) critique(s) Bandit détecté(s) dans le code Python. "
            "Consultez les details ci-dessus et corrigez les injections, eval() sur entrees utilisateur "
            "et mots de passe codes en dur."
        )
    if not recs:
        recs.append("Aucune vulnérabilité critique détectée. Activez Dependabot sur GitHub pour "
                    "surveiller automatiquement les nouvelles CVE sur vos dépendances.")
        recs.append("Maintenez les dépendances a jour et activez la protection des branches sur GitHub.")
    return recs

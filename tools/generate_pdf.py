import os
from fpdf import FPDF
from datetime import datetime

from tools.rapport_contenu import (
    GLOSSAIRE,
    LIBELLES_HORIZON,
    ORDRE_SEVERITE,
    analyser_constat,
    compter_par_severite,
    constats_tries,
    niveau_posture,
    normaliser_severite,
    plan_remediation,
)

# Police Unicode du document, pour que les accents français soient rendus.
# Les jeux sont essayés dans l'ordre : Segoe UI sur Windows, DejaVu sur les
# distributions Linux (paquet fonts-dejavu-core, présent par défaut sur Ubuntu).
_JEUX_POLICES = [
    {
        "":  r"C:\Windows\Fonts\segoeui.ttf",
        "B": r"C:\Windows\Fonts\segoeuib.ttf",
        "I": r"C:\Windows\Fonts\segoeuii.ttf",
    },
    {
        "":  "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "B": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "I": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
    },
]


def _choisir_jeu_polices() -> dict | None:
    for jeu in _JEUX_POLICES:
        if all(os.path.exists(chemin) for chemin in jeu.values()):
            return jeu
    return None


# Choix arrêté à l'import : la famille utilisée dans tout le document doit être
# connue avant le premier tracé. Sans police Unicode disponible on retombe sur
# Helvetica, intégrée à fpdf, qui couvre le latin-1 donc les accents français.
_JEU_POLICES = _choisir_jeu_polices()
FONT = "CG" if _JEU_POLICES else "Helvetica"


def _register_fonts(pdf: "FPDF") -> None:
    """Déclare la police Unicode auprès du document, si un jeu est disponible.
    Avec Helvetica il n'y a rien à enregistrer, fpdf l'intègre."""
    if not _JEU_POLICES:
        return
    for style, chemin in _JEU_POLICES.items():
        pdf.add_font(FONT, style, chemin)


# Transpositions appliquées uniquement en repli Helvetica, dont le jeu latin-1
# ne couvre ni la ligature « œ » ni les signes typographiques. Sans elles, la
# génération échoue sur un simple « mise en œuvre ».
_HORS_LATIN1 = {
    "œ": "oe", "Œ": "OE", "æ": "ae", "Æ": "AE",
    "…": "...", "—": "-", "–": "-", "‑": "-",
    "’": "'", "‘": "'", "“": '"', "”": '"',
    "≥": ">=", "≤": "<=", "×": "x", "·": "-",
}


def _clean(text: str) -> str:
    """Nettoie le texte tout en conservant les accents (police Unicode).
    Retire le balisage Markdown que le LLM peut produire, et n'applique la
    transposition latin-1 que si aucune police Unicode n'est disponible."""
    if not text:
        return ""
    texte = str(text).replace("**", "").replace("*", "")
    if FONT == "Helvetica":
        for origine, remplacement in _HORS_LATIN1.items():
            texte = texte.replace(origine, remplacement)
        # Filet de sécurité : tout caractère restant hors latin-1 ferait échouer
        # la génération, mieux vaut un point d'interrogation qu'un rapport absent
        texte = texte.encode("latin-1", "replace").decode("latin-1")
    return texte


# Palette : alignée sur le design system du frontend (BLUE_MED = --cg-primary).
# Contrastes vérifiés selon WCAG AA sur fond blanc et sur trame : toutes les
# couleurs de texte dépassent 4,5:1, sauf GRAY_MUTED (3,5:1) réservé aux
# valeurs nulles et GRAY_LIGHT qui ne sert qu'aux filets et aux aplats.
BLUE_DARK  = (15,  41,  77)
BLUE_MED   = (31,  92, 153)     # #1F5C99
GREEN      = (26, 122,  74)
ORANGE     = (133,  79,  11)
RED        = (153,  27,  27)
GRAY_DARK  = (17,  24,  39)
GRAY_MID   = (107, 114, 128)
GRAY_MUTED = (130, 137, 148)    # valeurs à zéro : lisibles mais secondaires
GRAY_LIGHT = (229, 231, 235)    # filets et aplats uniquement
TRAME      = (247, 249, 251)    # fond d'une ligne sur deux dans les tableaux
WHITE      = (255, 255, 255)


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

    # Renseignés avant le rendu : repris dans l'en-tête et le pied de chaque page
    reference = ""
    actif     = ""

    def header(self):
        # La couverture (page 1) n'affiche ni bandeau ni pied de page. Le test
        # porte sur le numéro de page : fpdf dessine le pied à la fermeture de
        # la page, bien après le rendu de son contenu.
        if self.page_no() == 1:
            return
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font(FONT, "B", 10)
        self.set_text_color(*WHITE)
        self.set_xy(10, 4)
        self.cell(0, 10, "Rapport d'évaluation de la posture de sécurité", ln=False)
        self.set_font(FONT, "", 8)
        self.set_text_color(170, 195, 220)
        self.set_xy(0, 6)
        self.cell(200, 6, _clean(self.actif), align="R")
        self.ln(14)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-13)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_y(-11)
        self.set_font(FONT, "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.cell(63, 8, _clean(self.reference))
        self.cell(64, 8, "Document confidentiel", align="C")
        self.cell(63, 8, f"Page {self.page_no()} sur {{nb}}", align="R")

    def chapitre(self, titre: str, forcer_page: bool = False, reserve: float = 110):
        """Titre de premier niveau, repris automatiquement dans le sommaire.

        Le chapitre s'enchaîne sur la page en cours s'il y reste assez de place :
        systématiquement ouvrir une page produit des pages remplies au quart, ce
        qui donne un document creux. Il bascule à la page suivante dès que
        l'espace restant descend sous `reserve`, pour ne pas amorcer un chapitre
        en bas de page."""
        if forcer_page or self.espace_restant() < reserve:
            self.add_page()
        else:
            self.ln(8)
        self.start_section(_clean(titre))
        self.set_font(FONT, "B", 15)
        self.set_text_color(*BLUE_DARK)
        self.set_x(10)
        self.cell(0, 9, _clean(titre), ln=True)
        self.set_draw_color(*BLUE_MED)
        self.set_line_width(0.6)
        self.line(10, self.get_y() + 1, 200, self.get_y() + 1)
        self.set_line_width(0.2)
        self.ln(5)

    def paragraphe(self, texte: str, taille: float = 9.5, couleur=None):
        self.set_font(FONT, "", taille)
        self.set_text_color(*(couleur or GRAY_DARK))
        self.set_x(12)
        self.multi_cell(186, 5.2, _clean(texte))
        self.ln(2)

    def espace_restant(self) -> float:
        return self.h - self.b_margin - self.get_y()

    def section_title(self, title: str, reserve: float = 30):
        """Style sobre : filet bleu à gauche + titre foncé + trait de séparation.
        `reserve` est la place minimale exigée sous le titre : un intertitre seul
        en bas de page, avec son contenu à la page suivante, est un défaut de
        composition (ligne orpheline)."""
        if self.espace_restant() < reserve:
            self.add_page()
        # Filet bleu à gauche + titre foncé + fin trait de séparation
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
        # Le libellé, la barre et la valeur forment un tout : sans cette réserve,
        # le saut de page automatique les dissocie sur deux ou trois pages.
        if self.espace_restant() < 12:
            self.add_page()
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

        # Un constat ne doit jamais être coupé en deux : sans cette réserve, le
        # saut de page automatique survient après l'étiquette de sévérité et
        # laisse celle-ci seule en bas de page. La hauteur est mesurée par un
        # rendu à blanc, une estimation au nombre de caractères étant trop
        # imprécise pour les textes longs.
        self.set_font(FONT, "", 8)
        besoin = 14 + self.multi_cell(box_w - 6, 4.5, _clean(desc),
                                      dry_run=True, output="HEIGHT")
        if extra:
            besoin += self.multi_cell(box_w - 6, 4.5, _clean(extra),
                                      dry_run=True, output="HEIGHT")
        if tool:
            besoin += 4
        if self.espace_restant() < besoin:
            self.add_page()

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

    # Le score par critère figure au chapitre « Synthèse des constats »

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

    # WHOIS : identite et expiration du domaine
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

    # Réputation : historique de la cible auprès des listes publiques
    reputation = results.get("reputation")
    if reputation and reputation.get("score") is not None:
        pdf.section_title(f"Réputation  ({', '.join(reputation.get('sources', []))})")
        if reputation.get("vt_disponible"):
            malveillant = reputation.get("vt_malveillant", 0)
            pdf.kv_row("Moteurs signalant un risque",
                       f"{malveillant} sur {reputation.get('vt_total_moteurs', 0)}",
                       RED if malveillant else GREEN)
            if reputation.get("vt_suspect"):
                pdf.kv_row("Moteurs jugeant suspect", str(reputation["vt_suspect"]), ORANGE)
        if reputation.get("abuse_disponible"):
            indice = reputation.get("abuse_score", 0)
            pdf.kv_row("Indice de signalement d'abus", f"{indice} sur 100",
                       RED if indice >= 50 else ORANGE if indice else GREEN)
            pdf.kv_row("Signalements sur 90 jours", str(reputation.get("abuse_signalements", 0)))
            if reputation.get("abuse_fournisseur"):
                pdf.kv_row("Hébergeur", reputation["abuse_fournisseur"])
            if reputation.get("abuse_pays"):
                pdf.kv_row("Pays de l'adresse", reputation["abuse_pays"])

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

    # CVE : gravité (CVSS) croisée avec probabilité d'exploitation (EPSS)
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

    # Les recommandations sont regroupées au chapitre « Plan de remédiation »


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

    pdf.section_title(f"Bandit : analyse statique Python  ({len(b_findings)} finding(s))")
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

    pdf.section_title(f"Safety : dépendances Python vulnérables  ({len(s_findings)})")
    if s_err or s_note:
        pdf.set_font(FONT, "I", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _clean(s_note or s_err))
    elif not s_findings:
        msg = f"{s_pkg} dépendances vérifiées, aucune CVE connue" if s_pkg else "Aucun fichier requirements.txt trouvé"
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
        pdf.section_title(f"npm audit : dépendances JavaScript  ({len(npm_findings)})")
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

    pdf.section_title(f"TruffleHog : secrets exposés  ({len(t_findings)})")
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

    # Les recommandations sont regroupées au chapitre « Plan de remédiation »


# ── Couverture, sommaire et sections transverses ─────────────────────────────

def _page_couverture(pdf: CyberGuardianPDF, scan: dict, score_max: int):
    pdf.add_page()

    pdf.set_fill_color(*BLUE_DARK)
    pdf.rect(0, 0, 210, 88, "F")

    pdf.set_font(FONT, "B", 26)
    pdf.set_text_color(*WHITE)
    pdf.set_xy(18, 26)
    pdf.cell(0, 12, "Rapport d'évaluation", ln=True)
    pdf.set_xy(18, 39)
    pdf.cell(0, 12, "de la posture de sécurité", ln=True)

    pdf.set_font(FONT, "", 11)
    pdf.set_text_color(150, 180, 215)
    pdf.set_xy(18, 58)
    pdf.cell(0, 6, "CyberGuardian  ·  Surface d'attaque externe", ln=True)

    # Bloc d'identification du document
    pdf.set_xy(18, 106)
    pdf.set_font(FONT, "", 9)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(40, 7, "Actif analysé")
    pdf.set_font(FONT, "B", 11)
    pdf.set_text_color(*GRAY_DARK)
    pdf.multi_cell(130, 7, _clean(scan.get("target", "-")))

    lignes = [
        ("Type d'analyse", "Dépôt GitHub public" if scan.get("type") == "github"
                           else "Surface d'attaque externe (EASM)"),
        ("Date du scan",   scan.get("date", "-")),
        ("Édité le",       datetime.now().strftime("%d/%m/%Y à %H:%M")),
        ("Score obtenu",   f"{scan.get('score', 0)} sur {score_max}"),
        ("Référence",      f"CG-{scan.get('id', 0):05d}"),
    ]
    y = pdf.get_y() + 3
    for cle, valeur in lignes:
        pdf.set_xy(18, y)
        pdf.set_font(FONT, "", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.cell(40, 7, _clean(cle))
        pdf.set_font(FONT, "B", 9.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(0, 7, _clean(str(valeur)))
        y += 7

    # Mention de confidentialité
    pdf.set_xy(18, 246)
    pdf.set_draw_color(*GRAY_LIGHT)
    pdf.line(18, 244, 192, 244)
    pdf.set_font(FONT, "", 8)
    pdf.set_text_color(*GRAY_MID)
    pdf.multi_cell(174, 4.5,
        "Document confidentiel. Il contient la description de vulnérabilités affectant "
        "l'actif analysé et ne doit être communiqué qu'aux personnes habilitées de "
        "l'organisation concernée. Analyse réalisée sans intrusion ni exploitation, "
        "à partir d'informations publiquement accessibles.")


def _rendre_sommaire(pdf: CyberGuardianPDF, entrees):
    pdf.set_font(FONT, "B", 15)
    pdf.set_text_color(*BLUE_DARK)
    pdf.set_x(10)
    pdf.cell(0, 9, "Sommaire", ln=True)
    pdf.set_draw_color(*BLUE_MED)
    pdf.set_line_width(0.6)
    pdf.line(10, pdf.get_y() + 1, 200, pdf.get_y() + 1)
    pdf.set_line_width(0.2)
    pdf.ln(7)

    for e in entrees:
        pdf.set_font(FONT, "", 10)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(14)
        titre = _clean(e.name)
        largeur = pdf.get_string_width(titre)
        pdf.cell(largeur + 2, 7, titre)
        # Points de conduite calculés sur la largeur réelle du point
        pdf.set_text_color(*GRAY_MID)
        restant = 182 - largeur - 12
        largeur_point = pdf.get_string_width(".") or 1
        pdf.cell(restant, 7, "." * max(0, int(restant / largeur_point)))
        pdf.set_font(FONT, "B", 10)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(10, 7, str(e.page_number), align="R", ln=True)


def _section_resume_executif(pdf: CyberGuardianPDF, scan: dict, score_max: int,
                             ai_explanation: str = ""):
    # Pas de saut : insert_toc_placeholder a déjà ouvert la page suivante
    pdf.chapitre("1.  Résumé exécutif")

    score   = scan.get("score", 0)
    issues  = scan.get("issues", [])
    compte  = compter_par_severite(issues)
    libelle, interpretation = niveau_posture(score, score_max)

    # Bandeau de score
    couleur = _score_color(int(score / score_max * 100) if score_max else 0)
    y = pdf.get_y()
    pdf.set_fill_color(248, 250, 252)
    pdf.rect(10, y, 190, 26, "F")
    pdf.set_fill_color(*couleur)
    pdf.rect(10, y, 3, 26, "F")

    pdf.set_xy(18, y + 4)
    pdf.set_font(FONT, "B", 24)
    pdf.set_text_color(*couleur)
    pdf.cell(28, 12, str(score))
    pdf.set_font(FONT, "", 10)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(18, 12, f"/ {score_max}")
    pdf.set_font(FONT, "B", 13)
    pdf.set_text_color(*GRAY_DARK)
    pdf.cell(0, 12, f"Posture {libelle.lower()}")
    # Répartition complète : n'afficher que les niveaux présents évite un
    # « 0 critique, 0 élevé, 0 moyen » qui laisse le lecteur chercher le reste.
    presents = [f"{compte[s]} {s.lower()}" for s in ORDRE_SEVERITE if compte[s]]
    repartition = ", ".join(presents) if presents else "aucun constat"
    pdf.set_xy(18, y + 16)
    pdf.set_font(FONT, "", 8.5)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(0, 6, _clean(f"{len(issues)} constat(s) : {repartition}"))
    pdf.set_y(y + 32)

    pdf.paragraphe(interpretation)

    # Les trois risques majeurs, traduits en conséquences concrètes
    majeurs = [i for i in constats_tries(issues)
               if normaliser_severite(i.get("severity")) in ("CRITIQUE", "HAUT")][:3]
    if majeurs:
        pdf.section_title("Risques principaux")
        for n, iss in enumerate(majeurs, 1):
            impact, effort, _ = analyser_constat(iss.get("title", ""), iss.get("severity"))
            pdf.set_font(FONT, "B", 9.5)
            pdf.set_text_color(*_sev_color(iss.get("severity", "")))
            pdf.set_x(12)
            pdf.cell(0, 6, _clean(f"{n}. {iss.get('title', '')}"), ln=True)
            pdf.set_font(FONT, "", 9)
            pdf.set_text_color(*GRAY_DARK)
            pdf.set_x(16)
            pdf.multi_cell(182, 5, _clean(impact))
            pdf.set_font(FONT, "I", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(16)
            pdf.cell(0, 5, _clean(f"Effort de correction estimé : {effort}"), ln=True)
            pdf.ln(2)
    else:
        pdf.section_title("Risques principaux")
        _empty_ok(pdf, "Aucun risque critique ou élevé sur les critères évalués.")

    # Effort global
    plan = plan_remediation(issues)
    pdf.section_title("Charge de traitement")
    pdf.paragraphe(
        f"{len(plan['immediat'])} action(s) à engager sous 48 heures, "
        f"{len(plan['court_terme'])} sous un mois et {len(plan['fond'])} à planifier "
        "sur le trimestre. Le détail figure au chapitre « Plan de remédiation »."
    )

    if ai_explanation:
        pdf.section_title("Lecture d'ensemble")
        pdf.paragraphe(ai_explanation)


def _section_methodologie(pdf: CyberGuardianPDF, scan: dict):
    pdf.chapitre("2.  Méthodologie et périmètre")

    est_github = scan.get("type") == "github"
    pdf.paragraphe(
        "L'analyse repose exclusivement sur des informations publiquement accessibles. "
        "Aucune tentative d'intrusion, d'exploitation de vulnérabilité ou de "
        "contournement d'authentification n'a été effectuée. Les contrôles sont "
        "passifs et sans effet sur la disponibilité des services analysés."
    )

    pdf.section_title("Contrôles effectués")
    if est_github:
        controles = [
            ("Analyse statique du code", "Bandit, recherche de motifs dangereux dans le code Python"),
            ("Dépendances vulnérables",  "Safety et npm audit, comparaison des versions aux CVE connues"),
            ("Secrets exposés",          "Recherche par motifs de clés d'API, jetons et mots de passe"),
        ]
    else:
        controles = [
            ("Authentification email", "SPF, DKIM, DMARC et DNSSEC dans les enregistrements DNS publics"),
            ("Chiffrement du trafic",  "Certificat TLS, suite de chiffrement, et versions du "
                                       "protocole acceptées, éprouvées une par une"),
            ("En-têtes HTTP",          "Six en-têtes recommandés par l'OWASP, relevés sur la "
                                       "page demandée lorsqu'une URL complète a été soumise"),
            ("Ports réseau",           "Connexion TCP simple sur une sélection de ports courants"),
            ("Vulnérabilités connues", "CVE liées au serveur exposé, croisées CVSS et EPSS"),
            ("Réputation",             "VirusTotal et AbuseIPDB, listes noires et signalements"),
            ("Identité du domaine",    "Registre WHOIS : propriétaire et échéance"),
            ("Sous-domaines exposés",  "Journaux publics de transparence des certificats, "
                                       "sans aucune sollicitation des hôtes découverts"),
        ]
    for nom, detail in controles:
        pdf.kv_row(nom, detail)

    # Transparence : ce qui n'a pas été évalué pèse sur la lecture du score
    non_evalues = (scan.get("results", {}).get("score_detail", {}) or {}).get("not_evaluated", [])
    pdf.section_title("Limites du périmètre")
    if non_evalues:
        points = sum(c.get("max", 0) for c in non_evalues)
        pdf.paragraphe(
            f"Les critères suivants n'ont pas été évalués, soit {points} points sur 100. "
            "Le score est calculé sur les seuls critères réellement mesurés et ne préjuge "
            "donc pas de la posture sur ces aspects :"
        )
        for c in non_evalues:
            pdf.kv_row(c.get("label", "-"), f"non évalué ({c.get('max', 0)} points)", ORANGE)
    else:
        pdf.paragraphe("L'ensemble des critères prévus a été évalué.")

    pdf.ln(1)
    pdf.paragraphe(
        "Cette évaluation porte sur la surface exposée à la date du scan. Elle ne "
        "remplace ni un test d'intrusion, ni un audit de l'infrastructure interne, ni "
        "une revue applicative approfondie.", taille=9, couleur=GRAY_MID
    )


def _section_synthese(pdf: CyberGuardianPDF, scan: dict):
    # Ce chapitre tient en deux blocs indissociables, le tableau des sévérités
    # et celui des scores. Démarrer sans la place pour les deux revient à
    # renvoyer le second seul sur la page suivante.
    pdf.chapitre("3.  Synthèse des constats", reserve=145)

    issues = scan.get("issues", [])
    compte = compter_par_severite(issues)

    # En-tête du tableau
    pdf.set_fill_color(*BLUE_DARK)
    pdf.set_text_color(*WHITE)
    pdf.set_font(FONT, "B", 9)
    pdf.set_x(12)
    pdf.cell(50, 8, "  Sévérité", fill=True)
    pdf.cell(28, 8, "Nombre", align="C", fill=True)
    pdf.cell(108, 8, "  Interprétation", fill=True, ln=True)

    interpretations = {
        "CRITIQUE": "Exploitable sans compétence particulière, à traiter sans délai",
        "HAUT":     "Risque avéré, exploitation documentée et accessible",
        "MOYEN":    "Renforcement attendu, exploitation moins directe",
        "BAS":      "Bonne pratique non appliquée, sans risque immédiat",
        "INFO":     "Élément de contexte, sans incidence de sécurité",
    }
    for rang, sev in enumerate(ORDRE_SEVERITE):
        n = compte[sev]
        # Tramage une ligne sur deux : lecture facilitée sur un tableau dense
        if rang % 2 == 0:
            pdf.set_fill_color(*TRAME)
            pdf.rect(12, pdf.get_y(), 186, 7.5, "F")
        pdf.set_x(12)
        pdf.set_font(FONT, "B", 9)
        pdf.set_text_color(*(_sev_color(sev) if n else GRAY_MID))
        pdf.cell(50, 7.5, f"  {sev.capitalize()}")
        pdf.set_font(FONT, "B", 10)
        pdf.set_text_color(*(GRAY_DARK if n else GRAY_MUTED))
        pdf.cell(28, 7.5, str(n), align="C")
        pdf.set_font(FONT, "", 8.5)
        pdf.set_text_color(*(GRAY_MID if n else GRAY_MUTED))
        pdf.cell(108, 7.5, f"  {interpretations[sev]}", ln=True)

    pdf.ln(4)
    r = scan.get("results", {}) or {}
    breakdown = (r.get("score_detail", {}) or {}).get("breakdown", [])
    if breakdown:
        # Réserve la hauteur de l'ensemble des barres : un tableau de scores
        # éclaté sur deux pages perd sa lisibilité comparative.
        pdf.section_title("Score par critère", reserve=20 + 8 * len(breakdown))
        for b in breakdown:
            pdf.score_bar(b.get("points", 0), b.get("max", 25), b.get("label", ""))

    elif scan.get("type") == "github":
        # Le score GitHub n'est pas pondéré par critère : on restitue plutôt le
        # volume de constats par contrôle, qui indique où porter l'effort.
        pdf.section_title("Répartition par contrôle")
        controles = [
            ("Analyse statique du code (Bandit)", (r.get("bandit") or {}).get("findings", []),
             "Motifs dangereux relevés dans le code source"),
            ("Dépendances Python (Safety)", (r.get("safety") or {}).get("findings", []),
             "Bibliothèques dont la version présente une CVE connue"),
            ("Dépendances JavaScript (npm audit)", (r.get("npm_audit") or {}).get("findings", []),
             "Paquets npm vulnérables signalés par l'écosystème"),
            ("Secrets exposés (TruffleHog)", (r.get("trufflehog") or {}).get("findings", []),
             "Clés d'API, jetons ou mots de passe lisibles dans le dépôt"),
        ]
        for rang, (nom, findings, detail) in enumerate(controles):
            n = len(findings)
            if rang % 2 == 0:
                pdf.set_fill_color(*TRAME)
                pdf.rect(12, pdf.get_y(), 186, 12, "F")
            y = pdf.get_y()
            pdf.set_xy(14, y + 1)
            pdf.set_font(FONT, "B", 9)
            pdf.set_text_color(*(GRAY_DARK if n else GRAY_MID))
            pdf.cell(150, 5, _clean(nom))
            pdf.set_font(FONT, "B", 11)
            pdf.set_text_color(*(RED if n else GREEN))
            pdf.cell(30, 5, str(n), align="R", ln=True)
            pdf.set_xy(14, y + 6)
            pdf.set_font(FONT, "", 8)
            pdf.set_text_color(*GRAY_MID)
            pdf.cell(0, 5, _clean(detail), ln=True)
            pdf.set_y(y + 12)

        pdf.ln(3)
        info = r.get("github_info", {}) or {}
        pdf.section_title("Contexte du dépôt")
        pdf.kv_row("Langage principal", r.get("langage") or info.get("language") or "-")
        pdf.kv_row("Visibilité",        info.get("visibility") or "-")
        pdf.kv_row("Licence",           info.get("license") or "Aucune")
        pdf.kv_row("Contributeurs",     str(info.get("contributors") or "-"))
        pdf.kv_row("Dernière mise à jour", str(info.get("updated_at") or "-"))


def _section_surface(pdf: CyberGuardianPDF, scan: dict):
    """Surface exposée : sous-domaines découverts et protocoles TLS tolérés.

    Ces deux relevés répondent à des questions que le reste du rapport ne pose
    pas. Le premier nomme des actifs que l'organisation a souvent oubliés ; le
    second dit ce que le serveur accepte d'un client peu exigeant, là où la
    section TLS ne rapporte que la version négociée avec un navigateur récent."""
    results = scan.get("results", {})
    sd      = results.get("subdomains") or {}
    ssl_res = results.get("ssl") or {}
    protocoles = ssl_res.get("protocoles") or []

    if not sd.get("total") and not protocoles:
        return

    pdf.section_title("Surface exposée")

    if protocoles:
        obsoletes = ssl_res.get("protocoles_obsoletes") or []
        pdf.kv_row("Protocoles TLS acceptés", ", ".join(protocoles),
                   RED if obsoletes else GREEN)
        if obsoletes:
            pdf.kv_row("Dont dépréciés", ", ".join(obsoletes), RED)
            pdf.paragraphe(
                "Dépréciés depuis 2021 par la RFC 8996 et refusés par PCI-DSS. Le "
                "serveur propose aussi des versions récentes, mais un client peut "
                "choisir l'ancienne : le risque pèse alors sur lui. La correction "
                "consiste à les désactiver côté serveur.",
                taille=8.5, couleur=GRAY_MID)

    if sd.get("total"):
        sensibles = sd.get("sensibles") or []
        pdf.kv_row("Sous-domaines découverts", str(sd["total"]))
        pdf.kv_row("Source", sd.get("source") or "-", GRAY_MID)
        pdf.paragraphe(
            "Relevés dans les journaux publics de transparence des certificats. "
            "Aucun paquet n'a été émis vers ces hôtes : la source est déclarative, "
            "tout certificat émis y étant inscrit.",
            taille=8.5, couleur=GRAY_MID)

        if sensibles:
            pdf.kv_row("Hors production", str(len(sensibles)), ORANGE)
            for entree in sensibles[:12]:
                pdf.kv_row("   " + str(entree.get("hote", "")),
                           str(entree.get("motif", "")), ORANGE)
            if len(sensibles) > 12:
                pdf.paragraphe("... et " + str(len(sensibles) - 12) + " autre(s).",
                               taille=8.5, couleur=GRAY_MID)
            pdf.paragraphe(
                "Ces hôtes portent souvent des données réelles avec des protections "
                "moindres : mot de passe par défaut, absence de limitation de débit, "
                "versions non corrigées. Restreignez-y l'accès ou retirez-les.",
                taille=8.5, couleur=GRAY_MID)
        else:
            pdf.paragraphe(
                "Aucun nom ne trahit un environnement hors production.",
                taille=8.5, couleur=GRAY_MID)


def _section_plan(pdf: CyberGuardianPDF, scan: dict):
    pdf.chapitre("5.  Plan de remédiation")
    pdf.paragraphe(
        "Les actions sont classées par urgence de traitement. Les délais indiqués sont "
        "des ordres de grandeur pour une configuration standard ; ils supposent l'accès "
        "à la zone DNS et à la configuration du serveur web."
    )

    plan = plan_remediation(scan.get("issues", []))
    vide = True
    for horizon in ("immediat", "court_terme", "fond"):
        actions = plan[horizon]
        if not actions:
            continue
        vide = False
        pdf.section_title(f"{LIBELLES_HORIZON[horizon]}  ({len(actions)})")
        for n, a in enumerate(actions, 1):
            pdf.set_font(FONT, "B", 9.5)
            pdf.set_text_color(*_sev_color(a["severite"]))
            pdf.set_x(12)
            pdf.multi_cell(186, 5.5, _clean(f"{n}. {a['titre']}"))
            if a["action"]:
                pdf.set_font(FONT, "", 9)
                pdf.set_text_color(*GRAY_DARK)
                pdf.set_x(16)
                pdf.multi_cell(182, 5, _clean(a["action"]))
            pdf.set_font(FONT, "I", 8.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.set_x(16)
            pdf.cell(0, 5, _clean(f"Effort estimé : {a['effort']}  ·  Sévérité : {a['severite'].capitalize()}"), ln=True)
            pdf.ln(2)

    if vide:
        _empty_ok(pdf, "Aucune action corrective requise sur les critères évalués.")

    # Consignes détaillées, propres au type d'analyse
    r = scan.get("results", {}) or {}
    if scan.get("type") == "github":
        recs = _build_github_recommendations(
            (r.get("bandit") or {}).get("findings", []),
            (r.get("safety") or {}).get("findings", []),
            (r.get("trufflehog") or {}).get("findings", []),
            (r.get("npm_audit") or {}).get("findings", []),
        )
    else:
        recs = _build_easm_recommendations(
            r.get("ssl", {}), r.get("dns"), r.get("whois"),
            r.get("headers"), scan.get("issues", []),
        )
    if recs:
        pdf.section_title("Consignes de mise en œuvre")
        for i, rec in enumerate(recs, 1):
            pdf.set_font(FONT, "", 9)
            pdf.set_text_color(*GRAY_DARK)
            pdf.set_x(12)
            pdf.multi_cell(186, 5, _clean(f"{i}. {rec}"))
            pdf.ln(1)


def _section_annexes(pdf: CyberGuardianPDF):
    pdf.chapitre("6.  Annexe : glossaire")
    pdf.paragraphe(
        "Définitions des termes techniques employés dans ce rapport, à l'usage des "
        "lecteurs non spécialistes."
    )
    for terme, definition in GLOSSAIRE:
        pdf.set_font(FONT, "B", 9.5)
        pdf.set_text_color(*BLUE_DARK)
        pdf.set_x(12)
        pdf.cell(28, 6, _clean(terme))
        pdf.set_font(FONT, "", 9)
        pdf.set_text_color(*GRAY_DARK)
        pdf.multi_cell(158, 6, _clean(definition))
        pdf.ln(1)

    pdf.ln(3)
    # Bloc court et indissociable : réserver sa hauteur évite qu'une référence
    # isolée ne parte seule sur une page supplémentaire.
    pdf.section_title("Sources et référentiels", reserve=48)
    for source in [
        "NIST NVD, base publique des vulnérabilités (CVE)",
        "FIRST.org, scores CVSS et probabilités d'exploitation EPSS",
        "OWASP Secure Headers Project, en-têtes HTTP recommandés",
        "RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), RFC 4033 (DNSSEC)",
    ]:
        pdf.set_font(FONT, "", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.set_x(12)
        pdf.multi_cell(186, 5.5, _clean(f"·  {source}"))


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
    pdf.reference = f"CG-{scan.get('id', 0):05d}"
    pdf.actif     = target
    pdf.alias_nb_pages()            # résout « page X sur Y » en fin de rendu
    pdf.set_auto_page_break(auto=True, margin=18)

    # Couverture, puis sommaire dont la pagination est résolue en fin de rendu
    _page_couverture(pdf, scan, score_max)
    pdf.add_page()
    pdf.insert_toc_placeholder(_rendre_sommaire, pages=1)

    # Lecture décroissante : d'abord la décision, ensuite la preuve technique
    _section_resume_executif(pdf, scan, score_max, ai_explanation)
    _section_methodologie(pdf, scan)
    _section_synthese(pdf, scan)

    pdf.chapitre("4.  Détail technique des constats", forcer_page=True)
    pdf.paragraphe(
        "Résultat brut de chaque contrôle, avec l'outil qui l'a produit. Cette partie "
        "s'adresse aux personnes chargées de la mise en œuvre.",
        taille=9, couleur=GRAY_MID,
    )
    if is_github:
        _section_github(pdf, scan)
    else:
        _section_ssl(pdf, scan)
        _section_surface(pdf, scan)

    _section_plan(pdf, scan)
    _section_annexes(pdf)

    return bytes(pdf.output())


# ── Recommandations ───────────────────────────────────────────────────────────

def _build_easm_recommendations(ssl: dict, dns: dict | None, whois: dict | None,
                                headers: dict | None, issues: list) -> list[str]:
    recs = []

    # WHOIS : priorité absolue si le domaine est expiré ou proche de l'expiration
    if whois and whois.get("found"):
        d = whois.get("days_until_expiry")
        if d is not None and d < 0:
            recs.append("Renouvelez IMMEDIATEMENT votre nom de domaine expire : il peut etre rachete "
                        "par un tiers qui prendrait le contrôle du site et des emails.")
        elif d is not None and d <= 30:
            recs.append(f"Renouvelez votre nom de domaine sous {d} jours pour eviter une interruption "
                        "de service et un risque de detournement.")

    # DNS : priorité anti-phishing (critère le plus lourd du score)
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

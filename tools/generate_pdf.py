from fpdf import FPDF
from datetime import datetime
import unicodedata


def _ascii(text: str) -> str:
    if not text:
        return ""
    text = str(text)
    text = text.replace("—", "-")   # em dash
    text = text.replace("–", "-")   # en dash
    text = text.replace("·", "|")   # middle dot
    text = text.replace("‘", "'")   # left single quote
    text = text.replace("’", "'")   # right single quote
    text = text.replace("“", '"')   # left double quote
    text = text.replace("”", '"')   # right double quote
    text = text.replace("«", '"')   # guillemet gauche
    text = text.replace("»", '"')   # guillemet droit
    text = text.replace("…", "...")  # ellipsis
    text = text.replace("•", "-")   # bullet
    text = text.replace("‣", "-")   # triangular bullet
    text = text.replace("**", "").replace("*", "")
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


# Couleurs
BLUE_DARK  = (15,  41,  77)
BLUE_MED   = (31,  92, 153)
GREEN      = (16, 185, 129)
ORANGE     = (245, 158, 11)
RED        = (239,  68,  68)
GRAY_DARK  = (17,  24,  39)
GRAY_MID   = (107, 114, 128)
GRAY_LIGHT = (229, 231, 235)
WHITE      = (255, 255, 255)


def _score_color(score: int) -> tuple:
    if score >= 80: return GREEN
    if score >= 50: return ORANGE
    return RED


def _severity_color(color: str) -> tuple:
    return {"red": RED, "orange": ORANGE, "yellow": (245, 158, 11)}.get(color, GRAY_MID)


class CyberGuardianPDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*WHITE)
        self.set_xy(10, 4)
        self.cell(0, 10, "CyberGuardian  |  Rapport de securite EASM", ln=False)
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
        if value_color:
            self.set_text_color(*value_color)
        else:
            self.set_text_color(*GRAY_DARK)
        self.set_font("Helvetica", "B", 9)
        self.cell(0, 6, _ascii(value), ln=True)

    def score_bar(self, pts: int, max_pts: int, label: str):
        bar_x, bar_y = 12, self.get_y()
        bar_w, bar_h = 130, 5
        fill_w = int((pts / max_pts) * bar_w) if max_pts else 0
        color = _score_color(int((pts / max_pts) * 100) if max_pts else 0)

        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_MID)
        self.set_xy(bar_x, bar_y)
        self.cell(52, 5, label)

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

    def issue_box(self, issue: dict):
        color    = _severity_color(issue.get("color", "gray"))
        severity = _ascii(issue.get("severity", ""))
        title    = _ascii(issue.get("title", ""))
        desc     = _ascii(issue.get("desc", ""))
        tool     = _ascii(issue.get("tool", ""))

        box_x = 12
        box_w = 186
        y_start = self.get_y()

        self.set_fill_color(*color)
        self.rect(box_x, y_start, 3, 18, "F")

        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*color)
        self.set_xy(box_x + 6, y_start + 1)
        self.cell(22, 5, severity)

        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*GRAY_DARK)
        self.set_xy(box_x + 30, y_start + 1)
        self.cell(0, 5, title, ln=True)

        self.set_font("Helvetica", "", 8)
        self.set_text_color(*GRAY_MID)
        self.set_x(box_x + 6)
        self.multi_cell(box_w - 6, 4.5, desc)

        self.set_font("Helvetica", "I", 7.5)
        self.set_text_color(150, 160, 170)
        self.set_x(box_x + 6)
        self.cell(0, 4, tool, ln=True)

        y_end = self.get_y()
        self.set_draw_color(*GRAY_LIGHT)
        self.line(box_x, y_end, box_x + box_w, y_end)
        self.ln(3)


# ── Point d'entree ──────────────────────────────────────────────────────────

def generate_scan_pdf(scan: dict, ai_explanation: str = "") -> bytes:
    ssl    = scan.get("results", {}).get("ssl", {})
    issues = scan.get("issues", [])
    score  = scan.get("score", 0)
    target = scan.get("target", "-")

    pdf = CyberGuardianPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Hero
    sc = _score_color(score)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*sc)
    pdf.set_x(12)
    pdf.cell(30, 12, str(score), ln=False)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(12, 12, "/ 100", ln=False)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(*GRAY_DARK)
    pdf.cell(0, 12, _ascii(target), ln=True)

    grade = ssl.get("grade", "-")
    label = "Bon" if score >= 80 else "Niveau moyen" if score >= 50 else "Critique"
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*GRAY_MID)
    pdf.set_x(12)
    pdf.cell(0, 5, f"Grade SSL : {grade}  |  {label}  |  Scan du {_ascii(scan.get('date', '-'))}", ln=True)
    pdf.ln(4)

    # Details SSL
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
        color = RED if days < 0 else ORANGE if days <= 30 else GREEN
        txt = "Expire !" if days < 0 else f"{days} jours restants"
        pdf.kv_row("Jours restants", txt, color)
    sans = ssl.get("sans", [])
    if sans:
        pdf.kv_row("SAN (domaines)", _ascii(", ".join(sans[:5]) + ("..." if len(sans) > 5 else "")))

    # Problemes
    pdf.section_title(f"Problemes detectes  ({len(issues)})")
    if not issues:
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*GREEN)
        pdf.set_x(12)
        pdf.cell(0, 7, "Aucun probleme SSL detecte.", ln=True)
    else:
        for iss in issues:
            pdf.issue_box(iss)

    # Recommandations
    pdf.section_title("Recommandations")
    recs = _build_recommendations(ssl, issues)
    for i, rec in enumerate(recs, 1):
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(12)
        pdf.multi_cell(186, 5, _ascii(f"{i}. {rec}"))
        pdf.ln(1)

    # Explication IA en langage simple
    if ai_explanation:
        pdf.section_title("Ce que ca signifie pour vous")
        pdf.set_x(12)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.multi_cell(186, 6, _ascii(ai_explanation))
        pdf.ln(2)

    return bytes(pdf.output())


def _build_recommendations(ssl: dict, issues: list) -> list[str]:
    recs = []
    if not ssl.get("valid"):
        recs.append("Installez un certificat SSL valide signe par une autorite reconnue (Let's Encrypt, DigiCert).")
    if ssl.get("expired"):
        recs.append("Renouvelez immediatement votre certificat SSL expire pour retablir la confiance des navigateurs.")
    days = ssl.get("days_until_expiry")
    if days is not None and 0 < days <= 30:
        recs.append(f"Renouvelez votre certificat dans les {days} jours pour eviter une interruption de service.")
    if ssl.get("self_signed"):
        recs.append("Remplacez le certificat auto-signe par un certificat emis par une CA publique reconnue.")
    if ssl.get("tls_version") in ("TLSv1", "TLSv1.1"):
        recs.append("Desactivez TLS 1.0 et TLS 1.1 sur votre serveur. Activez uniquement TLS 1.2 et TLS 1.3.")
    if not recs:
        recs.append("La configuration SSL/TLS est correcte. Maintenez le renouvellement automatique du certificat actif.")
    return recs

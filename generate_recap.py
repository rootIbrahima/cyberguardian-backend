from fpdf import FPDF
from datetime import datetime

BLUE_DARK  = (15,  41,  77)
BLUE_MED   = (31,  92, 153)
BLUE_LIGHT = (232, 241, 250)
GREEN      = (16, 185, 129)
ORANGE     = (245, 158, 11)
RED        = (239,  68,  68)
PURPLE     = (139,  92, 246)
GRAY_DARK  = (17,  24,  39)
GRAY_MID   = (107, 114, 128)
GRAY_LIGHT = (229, 231, 235)
GRAY_BG    = (249, 250, 251)
WHITE      = (255, 255, 255)


class RecapPDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*WHITE)
        self.set_xy(10, 5)
        self.cell(130, 10, "CyberGuardian - Recapitulatif technique du backend", ln=False)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(180, 200, 220)
        self.set_xy(0, 7)
        self.cell(200, 6, datetime.now().strftime("%d/%m/%Y"), align="R")
        self.ln(16)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.cell(0, 8, f"CyberGuardian EASM Platform  -  Page {self.page_no()}  -  Confidentiel", align="C")

    def h1(self, title):
        self.ln(3)
        self.set_fill_color(*BLUE_MED)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, f"  {title}", ln=True, fill=True)
        self.ln(3)

    def h2(self, title, color=None):
        c = color or BLUE_MED
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*c)
        self.set_x(10)
        self.cell(0, 6, title, ln=True)
        self.ln(1)

    def body(self, text, indent=12):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_DARK)
        self.set_x(indent)
        self.multi_cell(190 - indent + 10, 5, text)
        self.ln(1)

    def bullet(self, text, indent=16, color=None):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*(color or GRAY_DARK))
        self.set_x(indent)
        self.multi_cell(190 - indent + 10, 5, f"- {text}")

    def code_block(self, lines, indent=14):
        self.set_fill_color(30, 30, 46)
        h = len(lines) * 5 + 6
        x = indent
        w = 190 - indent + 10
        y = self.get_y()
        self.rect(x, y, w, h, "F")
        self.set_font("Courier", "", 8)
        self.set_text_color(189, 147, 249)
        for i, line in enumerate(lines):
            self.set_xy(x + 4, y + 3 + i * 5)
            self.cell(w - 8, 5, line)
        self.set_y(y + h + 3)
        self.set_text_color(*GRAY_DARK)

    def tag(self, text, color, bg=None):
        bg = bg or tuple(c + 40 for c in color)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*color)
        self.set_fill_color(*bg)
        self.cell(0, 5, f" {text} ", fill=True, ln=True)

    def file_row(self, path, desc, status="NOUVEAU", status_color=None):
        sc = status_color or GREEN
        y = self.get_y()
        self.set_fill_color(*GRAY_BG)
        self.rect(12, y, 186, 10, "F")
        self.set_draw_color(*GRAY_LIGHT)
        self.rect(12, y, 186, 10)
        # status badge
        self.set_fill_color(*sc)
        self.set_font("Helvetica", "B", 6.5)
        self.set_text_color(*WHITE)
        self.set_xy(14, y + 2.5)
        self.cell(22, 5, f"  {status}  ", fill=True)
        # path
        self.set_font("Courier", "B", 8)
        self.set_text_color(*BLUE_MED)
        self.set_xy(40, y + 1.5)
        self.cell(80, 4, path)
        # desc
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.set_xy(40, y + 5.5)
        self.cell(155, 4, desc)
        self.ln(12)

    def endpoint_row(self, method, path, desc):
        colors = {"GET": (16, 185, 129), "POST": (31, 92, 153), "DELETE": (239, 68, 68)}
        c = colors.get(method, GRAY_MID)
        y = self.get_y()
        self.set_fill_color(*c)
        self.set_font("Helvetica", "B", 7.5)
        self.set_text_color(*WHITE)
        self.set_xy(14, y)
        self.cell(18, 6, f"  {method}", fill=True)
        self.set_font("Courier", "", 8.5)
        self.set_text_color(*BLUE_MED)
        self.set_xy(35, y)
        self.cell(60, 6, path)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*GRAY_MID)
        self.set_xy(100, y)
        self.cell(0, 6, desc)
        self.ln(8)

    def arrow_flow(self, items):
        x = 12
        for i, (label, color) in enumerate(items):
            w = int(186 / len(items)) - 2
            self.set_fill_color(*color)
            self.set_font("Helvetica", "B", 7.5)
            self.set_text_color(*WHITE)
            self.set_xy(x, self.get_y())
            self.cell(w, 8, label, align="C", fill=True)
            if i < len(items) - 1:
                self.set_xy(x + w, self.get_y())
                self.set_font("Helvetica", "B", 10)
                self.set_text_color(*GRAY_MID)
                self.cell(4, 8, ">", align="C")
            x += w + 4
        self.ln(12)


def generate():
    pdf = RecapPDF()
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    # ── TITRE ─────────────────────────────────────────────────────────────────
    pdf.set_fill_color(*BLUE_LIGHT)
    pdf.rect(10, pdf.get_y(), 190, 22, "F")
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*BLUE_DARK)
    pdf.set_xy(16, pdf.get_y() + 4)
    pdf.cell(0, 8, "Recapitulatif technique - Backend CyberGuardian", ln=True)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*GRAY_MID)
    pdf.set_x(16)
    pdf.cell(0, 6, "Integration backend FastAPI avec le frontend React - Phase tests", ln=True)
    pdf.ln(8)

    # ── 1. CONTEXTE ───────────────────────────────────────────────────────────
    pdf.h1("1. Contexte et objectif")
    pdf.body(
        "Le projet CyberGuardian est une plateforme EASM (External Attack Surface Management) "
        "permettant de scanner la securite d'actifs publics (domaines, IPs, URLs, depots GitHub). "
        "L'objectif de cette phase etait d'implementer le backend Python (FastAPI) pour la partie "
        "scan SSL, et de le connecter au frontend React existant."
    )
    pdf.ln(2)

    # ── 2. ARCHITECTURE ───────────────────────────────────────────────────────
    pdf.h1("2. Architecture generale")
    pdf.body("Flux de donnees de bout en bout :")
    pdf.ln(2)
    pdf.arrow_flow([
        ("Utilisateur",     BLUE_DARK),
        ("React (port 3000)", BLUE_MED),
        ("FastAPI (port 8001)", GREEN),
        ("check_ssl.py",    PURPLE),
        ("scans.json",      ORANGE),
    ])
    pdf.body(
        "1. L'utilisateur saisit un domaine dans le formulaire de scan du dashboard.\n"
        "2. Le frontend envoie POST /scans au backend FastAPI sur le port 8001.\n"
        "3. Le backend execute check_ssl() qui se connecte en TLS au domaine cible.\n"
        "4. Les resultats sont persistes dans backend/data/scans.json.\n"
        "5. Le frontend affiche les resultats en temps reel sur la page de resultats."
    )

    # ── 3. FICHIERS CREES ─────────────────────────────────────────────────────
    pdf.h1("3. Fichiers crees et modifies")

    pdf.h2("Backend - Nouveaux fichiers", GREEN)
    pdf.file_row("backend/main.py",               "Point d'entree FastAPI - CORS, routeurs")
    pdf.file_row("backend/requirements.txt",       "Dependances : fastapi, uvicorn, fpdf2")
    pdf.file_row("backend/routers/scans.py",       "Endpoints REST du module scan")
    pdf.file_row("backend/tools/check_ssl.py",     "Outil de scan SSL/TLS (bibliotheque standard Python)")
    pdf.file_row("backend/tools/generate_pdf.py",  "Generateur de rapport PDF (fpdf2)")
    pdf.file_row("backend/data/scans.json",        "Base de donnees JSON - persistance des scans")

    pdf.h2("Frontend - Fichiers modifies", ORANGE)
    pdf.file_row("frontend/src/lib/constants.js",        "MCP_TOOLS reduit aux 2 outils implementes",      "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/components/ScanForm.jsx", "Quota supprime (9999), badge mis a jour",         "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/pages/DashboardPage.jsx", "Metriques et liste de scans dynamiques via API",  "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/pages/ScanResultsPage.jsx","Resultats SSL reels, suppression des mocks",     "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/pages/ScanProgressPage.jsx","Textes mis a jour (2 outils au lieu de 11)",    "MODIFIE", ORANGE)

    # ── 4. ENDPOINTS API ──────────────────────────────────────────────────────
    pdf.h1("4. Endpoints API (port 8001)")
    pdf.endpoint_row("POST", "/scans",             "Lance un scan SSL sur la cible, sauvegarde et retourne les resultats")
    pdf.endpoint_row("GET",  "/scans",             "Retourne la liste de tous les scans (tri par date decroissante)")
    pdf.endpoint_row("GET",  "/scans/{id}",        "Retourne les details complets d'un scan par son ID")
    pdf.endpoint_row("GET",  "/scans/{id}/status", "Retourne uniquement le statut d'un scan (completed/running)")
    pdf.endpoint_row("GET",  "/scans/{id}/pdf",    "Genere et telecharge le rapport PDF du scan")
    pdf.endpoint_row("GET",  "/scans/quota",       "Retourne le quota journalier (desactive en phase test)")

    # ── 5. OUTIL check_ssl ────────────────────────────────────────────────────
    pdf.h1("5. Outil check_ssl.py - Fonctionnement")
    pdf.body("Aucune dependance externe - utilise uniquement la bibliotheque standard Python (ssl, socket).")
    pdf.ln(2)

    pdf.h2("Ce qui est verifie :")
    checks = [
        ("Validite du certificat",     "Connexion TLS reelle sur le port 443"),
        ("Date d'expiration",          "Calcul des jours restants avant expiration"),
        ("Certificat auto-signe",      "Comparaison issuer/subject"),
        ("Version TLS",                "Detection TLS 1.0/1.1/1.2/1.3"),
        ("Cipher suite",               "Algorithme de chiffrement utilise"),
        ("Subject Alt Names (SANs)",   "Liste des domaines couverts"),
        ("Grade (A+/A/B/C/F)",         "Calcul selon les criteres SSL Labs"),
        ("Score /25 pts",              "Poids SSL dans le score global /100"),
    ]
    for label, detail in checks:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*BLUE_MED)
        pdf.set_x(16)
        pdf.cell(55, 5, label)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*GRAY_MID)
        pdf.cell(0, 5, detail, ln=True)

    pdf.ln(3)
    pdf.h2("Barème du score SSL /25 pts :")
    scoring = [
        ("-15 pts", "Certificat invalide",            RED),
        ("-10 pts", "Certificat expire",              RED),
        ("-5 pts",  "Expiration dans moins de 30j",   ORANGE),
        ("-8 pts",  "Certificat auto-signe",          ORANGE),
        ("-7 pts",  "TLS 1.0 ou 1.1 detecte",        ORANGE),
        ("-10 pts", "SSLv2 ou SSLv3 detecte",         RED),
        ("25/25",   "Aucun probleme detecte -> A+",   GREEN),
    ]
    for pts, label, color in scoring:
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*color)
        pdf.cell(22, 5, pts)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(0, 5, label, ln=True)

    # ── 6. PERSISTANCE ────────────────────────────────────────────────────────
    pdf.h1("6. Persistance des donnees")
    pdf.body(
        "Les scans sont stockes dans backend/data/scans.json. Le fichier est cree "
        "automatiquement au premier scan. Les donnees survivent aux redemarrages du serveur."
    )
    pdf.ln(2)
    pdf.code_block([
        '{',
        '  "counter": 3,',
        '  "scans": {',
        '    "1": { "id": 1, "target": "ec2lt.sn", "score": 22, "status": "completed", ... },',
        '    "2": { "id": 2, "target": "google.com", "score": 25, "status": "completed", ... }',
        '  }',
        '}',
    ])

    # ── 7. INTERCONNEXION FRONTEND ────────────────────────────────────────────
    pdf.h1("7. Interconnexion Frontend <-> Backend")

    pdf.h2("Fichier frontend/src/lib/api.js (inchange)")
    pdf.body("Toutes les requetes passent par axios avec BASE_URL = 'http://localhost:8001'")
    pdf.code_block([
        "scanAPI.launch(target, assetType)  ->  POST  /scans",
        "scanAPI.list()                     ->  GET   /scans",
        "scanAPI.get(id)                    ->  GET   /scans/{id}",
        "scanAPI.status(id)                 ->  GET   /scans/{id}/status",
        "scanAPI.downloadPDF(id)            ->  GET   /scans/{id}/pdf",
        "scanAPI.quota()                    ->  GET   /scans/quota",
    ])

    pdf.h2("Dashboard (DashboardPage.jsx)")
    pdf.bullet("Au chargement : GET /scans -> affiche la liste reelle des scans")
    pdf.bullet("Metriques calculees dynamiquement : score moyen, total failles, total CVE")
    pdf.bullet("ScoreCard = moyenne des scores reels")
    pdf.bullet("Fallback sur MOCK_SCANS si backend hors ligne")

    pdf.h2("Formulaire de scan (ScanForm.jsx)")
    pdf.bullet("Quota journalier desactive (9999) pour la phase de tests")
    pdf.bullet("POST /scans au clic sur 'Lancer le scan'")
    pdf.bullet("Redirection vers /scan-progress/{id} apres lancement")

    pdf.h2("Page progression (ScanProgressPage.jsx)")
    pdf.bullet("Animation terminale avec 2 outils : check_ssl() + calculate_score()")
    pdf.bullet("Polling GET /scans/{id}/status toutes les 5 secondes")
    pdf.bullet("Redirection automatique vers /scan-results/{id} quand done")

    pdf.h2("Page resultats (ScanResultsPage.jsx)")
    pdf.bullet("GET /scans/{id} au chargement -> donnees SSL reelles")
    pdf.bullet("Breakdown SSL : score/25, grade, TLS version, expiration, issuer")
    pdf.bullet("Issues : liste des problemes reels detectes par check_ssl()")
    pdf.bullet("Rapport auto-genere depuis les donnees SSL reelles (sans LLM)")
    pdf.bullet("Suggestions de questions basees sur les vraies issues trouvees")
    pdf.bullet("Telechargement PDF : GET /scans/{id}/pdf (genere par fpdf2)")
    pdf.bullet("Si scan introuvable : page d'erreur propre (plus de fallback mock)")

    # ── 8. LANCEMENT ─────────────────────────────────────────────────────────
    pdf.h1("8. Comment lancer le projet")

    pdf.h2("Backend")
    pdf.code_block([
        "cd backend",
        "pip install -r requirements.txt",
        "python -m uvicorn main:app --port 8001 --reload",
    ])
    pdf.body("Documentation interactive disponible sur : http://localhost:8001/docs")

    pdf.h2("Frontend")
    pdf.code_block([
        "cd frontend",
        "npm install",
        "npm run dev",
    ])
    pdf.body("Application disponible sur : http://localhost:3000")

    # ── 9. PROCHAINES ETAPES ─────────────────────────────────────────────────
    pdf.h1("9. Prochaines etapes recommandees")
    next_steps = [
        ("check_dns()",      "Verification DNS : SPF, DMARC, DKIM, MX, WHOIS",      BLUE_MED),
        ("scan_headers()",   "Analyse des headers HTTP : CSP, HSTS, X-Frame-Options", BLUE_MED),
        ("scan_ports()",     "Scan de ports reseau avec python-nmap",                  BLUE_MED),
        ("scan_virustotal()", "Verification reputation via API VirusTotal",             ORANGE),
        ("generate_report()", "Rapport IA avec Ollama mistral:7b en local",             PURPLE),
        ("Base de donnees",  "Remplacer scans.json par SQLite ou PostgreSQL",           GREEN),
    ]
    for tool, desc, color in next_steps:
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*color)
        pdf.cell(45, 6, tool)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(0, 6, desc, ln=True)

    # ── SAVE ──────────────────────────────────────────────────────────────────
    output_path = "recap_backend_cyberguardian.pdf"
    pdf.output(output_path)
    print(f"PDF genere : {output_path}")


if __name__ == "__main__":
    generate()

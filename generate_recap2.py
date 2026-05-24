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
        self.cell(130, 10, "CyberGuardian - Recapitulatif technique - Session 2", ln=False)
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

    def check(self, text, color=None):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*(color or GREEN))
        self.set_x(16)
        self.multi_cell(182, 5, f"[OK] {text}")

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

    def file_row(self, path, desc, status="NOUVEAU", status_color=None):
        sc = status_color or GREEN
        y = self.get_y()
        self.set_fill_color(*GRAY_BG)
        self.rect(12, y, 186, 10, "F")
        self.set_draw_color(*GRAY_LIGHT)
        self.rect(12, y, 186, 10)
        self.set_fill_color(*sc)
        self.set_font("Helvetica", "B", 6.5)
        self.set_text_color(*WHITE)
        self.set_xy(14, y + 2.5)
        self.cell(22, 5, f"  {status}  ", fill=True)
        self.set_font("Courier", "B", 8)
        self.set_text_color(*BLUE_MED)
        self.set_xy(40, y + 1.5)
        self.cell(80, 4, path)
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.set_xy(40, y + 5.5)
        self.cell(155, 4, desc)
        self.ln(12)

    def endpoint_row(self, method, path, desc):
        colors = {"GET": GREEN, "POST": BLUE_MED, "DELETE": RED}
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

    def two_col(self, left_items, right_items):
        y_start = self.get_y()
        x_left  = 12
        x_right = 110
        col_w   = 88

        self.set_font("Helvetica", "", 8.5)
        y_l = y_start
        for label, val, color in left_items:
            self.set_xy(x_left, y_l)
            self.set_text_color(*(color or GRAY_DARK))
            self.cell(col_w, 5, f"- {label}: {val}", ln=False)
            y_l += 5

        y_r = y_start
        for label, val, color in right_items:
            self.set_xy(x_right, y_r)
            self.set_text_color(*(color or GRAY_DARK))
            self.cell(col_w, 5, f"- {label}: {val}", ln=False)
            y_r += 5

        self.set_y(max(y_l, y_r) + 2)
        self.set_text_color(*GRAY_DARK)


def generate():
    pdf = RecapPDF()
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()

    # ── TITRE ─────────────────────────────────────────────────────────────────
    pdf.set_fill_color(*BLUE_LIGHT)
    pdf.rect(10, pdf.get_y(), 190, 28, "F")
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(*BLUE_DARK)
    pdf.set_xy(16, pdf.get_y() + 4)
    pdf.cell(0, 8, "Recapitulatif technique - Session 2", ln=True)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*BLUE_MED)
    pdf.set_x(16)
    pdf.cell(0, 6, "UX/UI, IA streaming, CVE, icones Lucide, navigation avancee", ln=True)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*GRAY_MID)
    pdf.set_x(16)
    pdf.cell(0, 6, f"Genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')}  |  CyberGuardian EASM Platform", ln=True)
    pdf.ln(8)

    # ── 1. RESUME ─────────────────────────────────────────────────────────────
    pdf.h1("1. Resume de la session")
    pdf.body(
        "Cette session a porte sur 5 axes majeurs : (1) integration d'un serveur Ollama distant "
        "avec chat IA en streaming, (2) implementation du module check_cve avec detection TLS et "
        "interrogation de l'API NVD, (3) migration complete du systeme d'icones vers Lucide React, "
        "(4) refonte de la navigation avec page liste des scans, et (5) nettoyage complet de "
        "l'interface pour la presentation au jury (suppression des elements revelant la stack technique)."
    )
    pdf.ln(2)

    # ── 2. FICHIERS ───────────────────────────────────────────────────────────
    pdf.h1("2. Fichiers crees et modifies")

    pdf.h2("Nouveaux fichiers backend", GREEN)
    pdf.file_row("backend/tools/check_cve.py",    "Detection CVE : mapping TLS + API NVD (NIST)")
    pdf.file_row("backend/generate_recap2.py",     "Script de generation du present document PDF")

    pdf.h2("Nouveaux fichiers frontend", GREEN)
    pdf.file_row("frontend/src/pages/ScanListPage.jsx", "Page liste de tous les scans avec recherche")

    pdf.h2("Fichiers backend modifies", ORANGE)
    pdf.file_row("backend/routers/scans.py",      "CVE integre, streaming SSE, timeout 180s, modele llama3", "MODIFIE", ORANGE)
    pdf.file_row("backend/tools/generate_pdf.py", "Section IA en francais simple, _ascii() robuste",         "MODIFIE", ORANGE)

    pdf.h2("Fichiers frontend modifies", ORANGE)
    pdf.file_row("frontend/src/components/Icons.jsx",        "Migration vers Lucide React (suppression SVG inline)",        "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/components/ui.jsx",           "Bell et Settings en Lucide, suppression SVG inline",          "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/components/Sidebar.jsx",      "Badge role supprime, navigation intelligente last-scan",      "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/components/ScanForm.jsx",     "Quota supprime, formulaire simplifie",                        "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/components/ScoreCard.jsx",    "Uniquement SSL/25, suppression mocks DNS/Headers/Ports",      "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/pages/LoginPage.jsx",         "Comptes demo supprimes, badge TLS fictif supprime",           "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/pages/DashboardPage.jsx",     "MOCK_SCANS supprime, etat vide propre, CVE reel",             "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/pages/ScanResultsPage.jsx",   "Streaming chat, section CVE, redirection last-scan",          "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/pages/ScanProgressPage.jsx",  "LLM_CHAIN supprime, textes neutres, icones Lucide",           "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/lib/constants.js",            "MCP_TOOLS complets : 12 outils avec groupes et types",        "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/App.jsx",                     "Route /scan-results -> ScanListPage, /:id -> detail",         "MODIFIE", ORANGE)
    pdf.file_row("frontend/src/index.css",                   "@import Google Fonts deplace en ligne 1 (fix PostCSS)",        "MODIFIE", ORANGE)
    pdf.file_row("frontend/package.json",                    "Ajout dependance lucide-react",                               "MODIFIE", ORANGE)

    # ── 3. IA STREAMING ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("3. Integration IA - Serveur Ollama distant avec streaming")

    pdf.h2("Configuration du serveur")
    pdf.code_block([
        "OLLAMA_URL   = 'https://fromager.unchk.sn:11435'",
        "OLLAMA_KEY   = 'partner-2c58610f55694bcaa6b83a15635bf348'",
        "OLLAMA_MODEL = 'llama3:latest'   # modele retenu apres test",
    ])

    pdf.h2("Modeles disponibles sur le serveur")
    models = [
        ("llama3:latest",  "RETENU", "Bon equilibre vitesse/qualite cybersecurite", GREEN),
        ("gemma3:12b",     "TROP LENT", "Qualite correcte mais 12B = lent", ORANGE),
        ("hermes3:latest", "ERREUR",  "Tag incorrect au premier essai -> corrige", RED),
        ("qwen3.6:latest", "RESERVE", "Tres rapide (6B) - option si llama3 lent", BLUE_MED),
        ("gemma4:latest",  "RESERVE", "Plus puissant mais potentiellement lent", GRAY_MID),
    ]
    for name, status, desc, color in models:
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*color)
        pdf.cell(30, 5, name)
        pdf.set_fill_color(*color)
        pdf.set_text_color(*WHITE)
        pdf.cell(22, 5, f" {status} ", fill=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(74)
        pdf.cell(0, 5, desc, ln=True)
    pdf.ln(3)

    pdf.h2("Flux SSE (Server-Sent Events) - Chat streaming")
    pdf.arrow_flow([
        ("Utilisateur frappe", BLUE_DARK),
        ("POST /scans/{id}/ask", BLUE_MED),
        ("httpx.stream(Ollama)", PURPLE),
        ("token par token", ORANGE),
        ("UI mot par mot", GREEN),
    ])
    pdf.bullet("Backend : StreamingResponse + httpx.stream() avec timeout read=180s")
    pdf.bullet("Frontend : fetch() + ReadableStream -> parsing SSE data: {token}")
    pdf.bullet("Persistance : conversation sauvegardee dans scans.json apres done=True")
    pdf.bullet("UX : spinner 'En train de reflechir' -> texte qui s'affiche mot par mot -> curseur clignotant")

    pdf.h2("Rapport PDF - Explication IA en francais simple")
    pdf.bullet("Appel synchrone Ollama avant generation PDF : _generate_simple_explanation(scan)")
    pdf.bullet("Prompt adapte : 5-8 phrases max, langage non-technique, regles IP privee/publique")
    pdf.bullet("Section 'Ce que ca signifie pour vous' ajoutee dans le PDF fpdf2")
    pdf.bullet("Indicateur de progression PDF : 4 etapes (Connexion / Analyse IA / Redaction / Mise en forme)")

    pdf.h2("Ameliorations du prompt IA")
    pdf.bullet("Detection automatique du type d'actif : IP privee vs domaine public via ipaddress stdlib")
    pdf.bullet("Regles explicites : pas de Let's Encrypt pour IP privee, adapter conseils routeur/NAS")
    pdf.bullet("Contexte senegalais : OVH, Sonatel, Arc Informatique mentionnes dans les recommandations")
    pdf.bullet("Historique des conversations visible sur la page resultats apres rechargement")

    # ── 4. CVE ────────────────────────────────────────────────────────────────
    pdf.h1("4. Module check_cve.py - Detection de vulnerabilites")

    pdf.h2("Architecture du module")
    pdf.body(
        "Le module fonctionne en deux etapes complementaires : (1) detection statique des CVE "
        "liees a la configuration TLS detectee par check_ssl, (2) recuperation de la banniere "
        "HTTP du serveur et interrogation de l'API NVD (NIST) pour trouver les CVE du logiciel."
    )
    pdf.ln(2)

    pdf.h2("Etape 1 : Mapping TLS -> CVE (instantane, sans reseau)")
    tls_cves = [
        ("TLSv1.0",     "CVE-2014-3566", "POODLE - Oracle de bourrage",         "HIGH"),
        ("TLSv1.0",     "CVE-2011-3389", "BEAST - CBC en TLS 1.0",              "MEDIUM"),
        ("TLSv1.1",     "CVE-2015-0204", "FREAK - Degradation RSA export",      "MEDIUM"),
        ("Cipher RC4",  "CVE-2015-2808", "Bar Mitzvah - Biais RC4",             "MEDIUM"),
        ("Cipher DES",  "CVE-2016-2183", "SWEET32 - Anniversaire 64 bits",      "HIGH"),
        ("Cipher NULL", "CVE-2014-0224", "CCS Injection - NULL cipher",         "HIGH"),
    ]
    for trigger, cve_id, name, severity in tls_cves:
        colors = {"HIGH": RED, "MEDIUM": ORANGE, "LOW": GRAY_MID}
        c = colors.get(severity, GRAY_MID)
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(28, 5, trigger)
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(*c)
        pdf.cell(28, 5, cve_id)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(70, 5, name)
        pdf.set_fill_color(*c)
        pdf.set_text_color(*WHITE)
        pdf.cell(20, 5, f" {severity} ", fill=True, ln=True)
    pdf.ln(3)

    pdf.h2("Etape 2 : Banniere HTTP -> API NVD")
    pdf.code_block([
        "GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Apache+2.4.49",
        "-> retourne les CVE officielles du NIST pour ce logiciel/version",
        "-> parsing : id, severity, cvss score, description (140 chars max)",
        "-> timeout : 10s, aucune cle API requise (gratuit)",
    ])
    pdf.bullet("Extraction de la banniere : header HTTP 'Server' (ex: Apache/2.4.49)")
    pdf.bullet("Parsing regex : 'Apache/2.4.49 (Unix)' -> keyword 'Apache 2.4.49'")
    pdf.bullet("Fallback propre si banniere vide ou API indisponible")

    pdf.h2("Affichage dans les resultats")
    pdf.bullet("Carte 'CVE identifiees' avec badge rouge du nombre total")
    pdf.bullet("Serveur detecte affiche (ex: 'Serveur detecte : nginx/1.18.0')")
    pdf.bullet("Chaque CVE : ID, titre, badge CVSS score, badge severity (CRITICAL/HIGH/MEDIUM)")
    pdf.bullet("La carte est masquee si aucune CVE detectee (hidden when empty)")
    pdf.bullet("Dashboard : compteur CVE calcule dynamiquement depuis les vrais scans")

    # ── 5. LUCIDE ─────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("5. Migration icones - SVG inline -> Lucide React")

    pdf.h2("Probleme : SVG inline dans le code source")
    pdf.body(
        "L'ancienne implementation definissait 35+ icones en SVG inline directement dans Icons.jsx. "
        "Chaque icone etait un element JSX statique avec ses paths SVG hardcodes. La fonction cloneIcon() "
        "manipulait ces elements comme des objets en ecrasant leurs props - une approche fragile et "
        "non standard. De plus, ui.jsx contenait des SVG inline pour Bell et Settings dans PageHeader."
    )

    pdf.h2("Solution : Lucide React")
    pdf.code_block([
        "npm install lucide-react  (tree-shakeable, 1500+ icones, TypeScript natif)",
        "",
        "# Avant - SVG inline fragile",
        "shield: <Icon d={<path d='M12 22s8-4 8-10V5l-8-3...'/>}/>",
        "",
        "# Apres - composant Lucide standard",
        "shield: Shield,   // reference au composant Lucide",
        "",
        "# cloneIcon adapte pour rendre des composants Lucide",
        "cloneIcon(Icons.shield, {size:20, color:'#fff'})  ->  <Shield size={20} color='#fff' />",
    ])

    pdf.h2("Mapping des 35 icones")
    mapping = [
        ("dashboard", "LayoutDashboard"), ("scan", "ScanLine"),       ("results", "FileText"),
        ("experts",   "Users"),           ("message", "MessageSquare"),("admin", "ShieldCheck"),
        ("shield",    "Shield"),          ("domain", "Globe"),         ("ip", "Server"),
        ("url",       "Link2"),           ("github", "GitBranch"),     ("alert", "AlertTriangle"),
        ("check",     "Check"),           ("download", "Download"),    ("send", "Send"),
        ("logout",    "LogOut"),          ("lock", "Lock"),            ("mail", "Mail"),
        ("sparkles",  "Sparkles"),        ("arrowLeft", "ArrowLeft"),  ("star", "Star"),
    ]
    cols = 3
    rows = [mapping[i:i+cols] for i in range(0, len(mapping), cols)]
    for row in rows:
        pdf.set_x(16)
        for icon_old, icon_new in row:
            pdf.set_font("Courier", "B", 7.5)
            pdf.set_text_color(*BLUE_MED)
            pdf.cell(28, 5, icon_old)
            pdf.set_font("Helvetica", "", 7.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.cell(4, 5, "->")
            pdf.set_font("Courier", "", 7.5)
            pdf.set_text_color(*GREEN)
            pdf.cell(30, 5, icon_new)
        pdf.ln(5)
    pdf.ln(2)

    pdf.h2("Compatibilite verifiee sur 14 fichiers")
    pdf.bullet("cloneIcon(Icons.xxx, {size, color}) -> OK (tous les call sites)")
    pdf.bullet("cloneIcon(Icons.star, {fill, color}) -> OK (fill passe via ...rest a Lucide)")
    pdf.bullet("icon={Icons.xxx} sur Badge/Button -> OK (cloneIcon appele en interne)")
    pdf.bullet("icon: Icons.xxx dans config nav -> OK (NavButton appelle cloneIcon)")
    pdf.bullet("Build Vite : 0 erreur, 297kb bundle, 2.34s")

    # ── 6. NAVIGATION ─────────────────────────────────────────────────────────
    pdf.h1("6. Refonte de la navigation")

    pdf.h2("Probleme initial")
    pdf.body(
        "/scan-results sans ID affichait 'Scan introuvable' car la page cherchait un ID dans "
        "useParams() sans le trouver. 'Voir tout' dans le dashboard redirigeait vers le meme "
        "composant qui renvoyait vers le dernier scan au lieu d'une liste."
    )

    pdf.h2("Architecture apres refonte")
    pdf.arrow_flow([
        ("/scan-results",    BLUE_MED),
        ("ScanListPage",     GREEN),
        ("Tableau + search", ORANGE),
    ])
    pdf.arrow_flow([
        ("/scan-results/:id", BLUE_MED),
        ("ScanResultsPage",   GREEN),
        ("Detail du scan",    ORANGE),
    ])

    pdf.h2("ScanListPage - Nouvelle page")
    pdf.bullet("Charge tous les scans via GET /scans au montage")
    pdf.bullet("Barre de recherche filtrant par cible ou type en temps reel")
    pdf.bullet("Tableau : Cible, Score, CVE, Statut, Date - clic pour aller au detail")
    pdf.bullet("Etat vide : icone + message propre si aucun scan")
    pdf.bullet("Etat vide recherche : 'Aucun resultat pour cette recherche'")

    pdf.h2("Navigation intelligente - Sidebar")
    pdf.code_block([
        "# 'Resultats scan' dans la sidebar",
        "const lastId = localStorage.getItem('cg-last-scan')",
        "navigate(lastId ? '/scan-results/' + lastId : '/scan-results')",
        "",
        "# Sauvegarde automatique a chaque visite d'un scan",
        "localStorage.setItem('cg-last-scan', id)",
    ])
    pdf.bullet("'Voir tout' dans le dashboard -> /scan-results (ScanListPage)")
    pdf.bullet("'Resultats scan' sidebar -> dernier scan visite si connu, sinon liste")
    pdf.bullet("Bouton 'Tous les scans' dans ScanResultsPage -> retour vers la liste")

    # ── 7. NETTOYAGE UI ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("7. Nettoyage de l'interface - Preparation jury")

    pdf.h2("Elements supprimes (visibles par le jury)")
    removals = [
        ("LoginPage",         "Bloc 'Comptes demo (sans backend)' avec 3 boutons email clickables"),
        ("LoginPage",         "Badge 'Connexion chiffree TLS 1.3' - affirmation fausse"),
        ("LoginPage",         "Encadre 'TLS 1.3 + rotation automatique JWT' - fausse promesse"),
        ("LoginPage",         "Copyright 'Memoire Master EC2LT - Ibrahima LY'"),
        ("ScanProgressPage",  "Bloc 'Chaine LLM - Fallback automatique' avec Ollama/Gemini/Groq"),
        ("ScanProgressPage",  "Connexion a Ollama mistral:7b (local) - revele la stack IA"),
        ("ScanProgressPage",  "LLM_CHAIN constant avec 3 modeles IA hardcodes"),
        ("ScanResultsPage",   "'Genere par Ollama mistral:7b - Fallback Gemini -> Groq Llama'"),
        ("ScanResultsPage",   "Date en anglais '14 May. 2026' -> 'Analysed le 14 mai. 2026'"),
        ("ScanResultsPage",   "'2 outils executes' -> 'Analyse SSL/TLS complete'"),
        ("Sidebar",           "Badge role 'Client' / 'Expert valide' sous le logo"),
        ("ScoreCard",         "Fausses categories DNS/Headers/Ports/Reputation (mocks)"),
        ("Dashboard",         "MOCK_SCANS comme fallback (faux scans si backend hors ligne)"),
        ("code source",       "Commentaires 'Demo role mapping', 'Demo fallback'"),
        ("code source",       "String 'demo-token' -> renomme 'session-token'"),
    ]
    for page, desc in removals:
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*RED)
        pdf.cell(28, 5, f"[{page}]")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_DARK)
        pdf.multi_cell(160, 5, desc)
    pdf.ln(2)

    pdf.h2("Textes humanises")
    humanized = [
        ("'running...'",              "'en cours'"),
        ("'Scan termine le'",         "'Analyse le'"),
        ("'Failles'",                 "'Problemes'"),
        ("'Multi-LLM'",               "'Rapports IA'"),
        ("'Scan introuvable'",        "'Aucun scan disponible'"),
        ("'Retour au dashboard'",     "'Tous les scans'"),
        ("'Acces chiffre TLS 1.3'",   "'Acces securise'"),
        ("'14 May. 2026'",            "'14 mai. 2026'"),
    ]
    for old, new in humanized:
        pdf.set_x(16)
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(*RED)
        pdf.cell(60, 5, old)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.cell(10, 5, "->")
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(*GREEN)
        pdf.cell(0, 5, new, ln=True)
    pdf.ln(2)

    # ── 8. MCP TOOLS ──────────────────────────────────────────────────────────
    pdf.h1("8. Outils MCP - Inventaire complet des 12 outils")

    groups = {
        "EASM (domain / ip / url)": [
            ("check_ssl()",       "Certificat SSL/TLS - validite, grade, expiration, cipher",  "IMPLEMENTE",  GREEN),
            ("check_cve()",       "CVE via TLS + banniere HTTP + API NVD (NIST)",               "IMPLEMENTE",  GREEN),
            ("check_dns()",       "DNS - SPF, DMARC, DKIM, MX, enregistrements",               "EN ATTENTE",  ORANGE),
            ("check_whois()",     "WHOIS - registrar, expiration du domaine",                   "EN ATTENTE",  ORANGE),
            ("scan_headers()",    "En-tetes HTTP - HSTS, CSP, X-Frame-Options, Referrer",       "EN ATTENTE",  ORANGE),
            ("scan_ports()",      "Ports ouverts - services exposes sur internet",               "EN ATTENTE",  ORANGE),
            ("scan_virustotal()", "Reputation - VirusTotal, listes noires",                     "EN ATTENTE",  ORANGE),
        ],
        "GitHub": [
            ("github_info()",     "Metadonnees - visibilite, branches, contributeurs",           "EN ATTENTE",  ORANGE),
            ("scan_bandit()",     "Bandit - vulnerabilites statiques Python",                    "EN ATTENTE",  ORANGE),
            ("scan_safety()",     "Safety - dependances avec CVE connues",                       "EN ATTENTE",  ORANGE),
            ("scan_trufflehog()", "TruffleHog - secrets et tokens exposes",                      "EN ATTENTE",  ORANGE),
        ],
        "Score & Rapport": [
            ("calculate_score()", "Score de securite pondere /100",                              "IMPLEMENTE",  GREEN),
            ("generate_report()", "Rapport PDF avec explication IA en francais simple",          "IMPLEMENTE",  GREEN),
        ],
    }

    for group_name, tools in groups.items():
        pdf.h2(group_name, BLUE_MED)
        for name, desc, status, color in tools:
            pdf.set_x(16)
            pdf.set_fill_color(*color)
            pdf.set_font("Helvetica", "B", 6.5)
            pdf.set_text_color(*WHITE)
            pdf.cell(24, 5, f" {status} ", fill=True)
            pdf.set_font("Courier", "B", 8)
            pdf.set_text_color(*BLUE_MED)
            pdf.set_x(42)
            pdf.cell(38, 5, name)
            pdf.set_font("Helvetica", "", 7.5)
            pdf.set_text_color(*GRAY_MID)
            pdf.cell(0, 5, desc, ln=True)
        pdf.ln(2)

    # ── 9. PROBLEMES RESOLUS ──────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("9. Problemes rencontres et solutions")

    issues = [
        (
            "Modele hermes3 - 'Service IA indisponible'",
            "Le tag 'hermes3' etait incorrect. Verification via GET /api/tags -> tag reel = 'hermes3:latest'. "
            "De plus le timeout de 60s etait trop court pour des reponses complexes.",
            "Correction du tag + timeout porte a 180s (read) via httpx.Timeout granulaire. "
            "Ajout de print() + traceback dans le catch pour diagnostiquer les erreurs futures.",
        ),
        (
            "lucide-react - export 'Github' inexistant",
            "La biblioteque Lucide n'exporte pas 'Github' (avec majuscule). "
            "Build Vite echoue avec MISSING_EXPORT.",
            "Verification via node -e pour lister les exports disponibles -> 'GitBranch' utilise a la place.",
        ),
        (
            "PostCSS - Warning @import apres @tailwind",
            "@import url(Google Fonts) etait place apres les directives @tailwind dans index.css, "
            "ce qui generait un avertissement PostCSS a chaque build.",
            "Deplacement de @import en ligne 1 du fichier, avant toute directive @tailwind.",
        ),
        (
            "IA - Mauvais conseils pour IP privees",
            "L'IA recommandait 'Let's Encrypt' et 'redemarrez le serveur' pour 192.168.1.1 "
            "alors que c'est un routeur domestique non accessible sur internet.",
            "Ajout de _detect_asset_type() avec ipaddress stdlib + regles explicites dans le prompt : "
            "ne jamais recommander Let's Encrypt pour une IP privee, adapter les conseils au type d'equipement.",
        ),
        (
            "PDF - UnicodeEncodeError sur '...' (U+2026)",
            "fpdf2 avec Helvetica ne supporte pas les caracteres Unicode comme les points de suspension "
            "ou les guillemets courbes. Erreur a la generation PDF.",
            "Fonction _ascii() avec remplacements explicites de tous les caracteres problematiques "
            "('...' -> '...', 'e' -> 'e', etc.) + normalisation NFKD + encode ASCII ignore.",
        ),
        (
            "ScanResultsPage - 'Scan introuvable' depuis sidebar",
            "/scan-results sans ID rendait ScanResultsPage avec id=undefined, "
            "declenchant l'etat vide 'Scan introuvable'.",
            "Creation de ScanListPage pour /scan-results (liste). Sidebar navigue vers "
            "le dernier scan visite (localStorage) ou la liste. Bouton retour pointe vers la liste.",
        ),
    ]

    for title, problem, solution in issues:
        pdf.set_fill_color(*BLUE_LIGHT)
        pdf.rect(12, pdf.get_y(), 186, 7, "F")
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*BLUE_DARK)
        pdf.set_xy(15, pdf.get_y() + 1.5)
        pdf.cell(0, 4, title, ln=True)
        pdf.ln(1)

        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*RED)
        pdf.cell(20, 4, "Probleme :")
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(37)
        pdf.multi_cell(161, 4, problem)

        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*GREEN)
        pdf.cell(20, 4, "Solution :")
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(37)
        pdf.multi_cell(161, 4, solution)
        pdf.ln(4)

    # ── 10. ETAT ACTUEL ────────────────────────────────────────────────────────
    pdf.h1("10. Etat actuel du projet")

    pdf.h2("Fonctionnalites operationnelles", GREEN)
    done = [
        "Scan SSL/TLS avec score /25, grade A+/A/B/C/F, detection expiration/auto-signe",
        "Detection CVE : mapping TLS + interrogation API NVD via banniere HTTP serveur",
        "Chat IA en streaming mot-a-mot (llama3:latest sur serveur Ollama distant)",
        "Rapport PDF avec explication en francais simple generee par IA",
        "Persistance des conversations dans scans.json (survie aux rechargements)",
        "Page liste scans avec recherche, page detail, navigation intelligente sidebar",
        "Score total calcule et affiche (SSL /25 + CVE dans le compte)",
        "Icones Lucide React sur toutes les pages (build optimise, tree-shaking)",
        "Detection IP privee vs domaine public dans les prompts IA",
        "Indicateur de progression PDF en 4 etapes (Connexion / IA / Redaction / Mise en forme)",
    ]
    for item in done:
        pdf.check(item)
    pdf.ln(3)

    pdf.h2("Prochaine etape recommandee", ORANGE)
    pdf.bullet("Implementer check_dns() : SPF, DMARC, DKIM, MX via Google DoH (dns.google) - zero dependance")
    pdf.bullet("Score DNS /25 : SPF+8, DMARC+8, MX+4, DKIM+5 -> score total /50 puis /100")
    pdf.bullet("Afficher section DNS dans ScanResultsPage a cote de la section SSL")
    pdf.bullet("Mettre a jour ScoreCard pour afficher les 2 barres (SSL + DNS)")
    pdf.bullet("Ajouter DNS dans le rapport PDF et dans le contexte IA")

    # ── SAVE ──────────────────────────────────────────────────────────────────
    output_path = "recap_session2_cyberguardian.pdf"
    pdf.output(output_path)
    print(f"PDF genere : {output_path}")


if __name__ == "__main__":
    generate()

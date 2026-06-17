"""
Guide explicatif des outils MCP — CyberGuardian EASM
Usage : python generate_mcp_guide.py
"""
from fpdf import FPDF
from datetime import datetime
import unicodedata


def _a(t):
    if not t: return ""
    t = str(t)
    for s, d in [("—","-"),("–","-"),("·","|"),("'","'"),("'","'"),
                 ("’","'"),("‘","'"),("“",'"'),("”",'"'),
                 ("«",'"'),("»",'"'),("…","..."),("•","-"),("→","->"),
                 ("✓","OK"),("⚠","!"),("**",""),("*","")]:
        t = t.replace(s, d)
    return unicodedata.normalize("NFKD", t).encode("ascii","ignore").decode("ascii")


BLUE_DARK  = (15,  41,  77)
BLUE_MED   = (31,  92, 153)
BLUE_LIGHT = (232, 241, 250)
GREEN      = (22, 163, 74)
GREEN_DARK = (5,  150,  80)
ORANGE     = (234, 88,  12)
RED        = (220,  38,  38)
PURPLE     = (109,  40, 217)
TEAL       = (15, 118, 110)
GRAY_DARK  = (30,  41,  59)
GRAY_MID   = (100, 116, 139)
GRAY_LIGHT = (226, 232, 240)
WHITE      = (255, 255, 255)
CODE_BG    = (22,  27,  34)
CODE_GREEN = (126, 231, 135)
CODE_BLUE  = (130, 200, 255)
CODE_GRAY  = (134, 153, 180)
YELLOW_BG  = (254, 249, 195)
YELLOW_BD  = (202, 138,   4)


class McpPDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*WHITE)
        self.set_xy(10, 4)
        self.cell(140, 10, "CyberGuardian EASM  |  Guide des outils MCP")
        self.set_font("Helvetica", "", 8)
        self.set_text_color(180, 200, 220)
        self.set_xy(0, 5)
        self.cell(200, 6, datetime.now().strftime("%d/%m/%Y"), align="R")
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y(), 200, self.get_y())
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.cell(0, 8, f"CyberGuardian EASM Platform  -  Page {self.page_no()}  -  Confidentiel", align="C")

    def h1(self, title, color=BLUE_MED):
        self.ln(3)
        self.set_fill_color(*color)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, _a(f"  {title}"), ln=True, fill=True)
        self.ln(3)

    def h2(self, title, color=BLUE_MED):
        self.ln(2)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*color)
        self.set_x(10)
        self.cell(0, 6, _a(title), ln=True)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)

    def body(self, text, indent=12):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_DARK)
        self.set_x(indent)
        self.multi_cell(210 - indent - 10, 5.2, _a(text))

    def bullet(self, text, indent=16, color=None):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*(color or GRAY_DARK))
        self.set_x(indent)
        self.cell(5, 5.5, "-")
        self.set_x(indent + 5)
        self.multi_cell(210 - indent - 15, 5.5, _a(text))

    def code_block(self, lines, title="Python"):
        self.ln(1)
        x, w = 10, 190
        y = self.get_y()
        content_lines = lines if isinstance(lines, list) else lines.split("\n")
        h = len(content_lines) * 5 + 8
        self.set_fill_color(*CODE_BG)
        self.rect(x, y, w, h, "F")
        self.set_fill_color(*BLUE_MED)
        self.rect(x, y, w, 6, "F")
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*WHITE)
        self.set_xy(x + 4, y + 0.5)
        self.cell(0, 5, _a(title))
        self.set_xy(x + 4, y + 7)
        for line in content_lines:
            la = _a(line)
            if la.strip().startswith("#"):
                self.set_text_color(*CODE_GRAY)
                self.set_font("Courier", "I", 7.5)
            elif any(kw in la for kw in ("def ", "class ", "return ", "import ", "from ")):
                self.set_text_color(*CODE_BLUE)
                self.set_font("Courier", "B", 7.5)
            else:
                self.set_text_color(*CODE_GREEN)
                self.set_font("Courier", "", 7.5)
            self.set_x(x + 4)
            self.cell(0, 5, la, ln=True)
        self.ln(3)

    def info_box(self, text, bg=BLUE_LIGHT, border=BLUE_MED):
        self.ln(1)
        x, w = 10, 190
        y = self.get_y()
        t = _a(text)
        n = t.count("\n") + 1
        h = n * 5.5 + 8
        self.set_fill_color(*bg)
        self.rect(x, y, w, h, "F")
        self.set_fill_color(*border)
        self.rect(x, y, 3, h, "F")
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_DARK)
        self.set_xy(x + 7, y + 4)
        self.multi_cell(w - 12, 5.5, t)
        self.ln(2)

    def tool_card(self, num, name, file, desc, inputs, outputs, score, status="Implemente"):
        self.ln(2)
        x, w = 10, 190
        y = self.get_y()
        h = 38
        # Fond
        self.set_fill_color(248, 250, 252)
        self.rect(x, y, w, h, "F")
        # Bande couleur gauche
        col = GREEN_DARK if status == "Implemente" else ORANGE
        self.set_fill_color(*col)
        self.rect(x, y, 4, h, "F")
        # Numero
        self.set_fill_color(*BLUE_MED)
        self.set_draw_color(*BLUE_MED)
        self.rect(x + 8, y + 4, 12, 10, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*WHITE)
        self.set_xy(x + 8, y + 4)
        self.cell(12, 10, _a(str(num)), align="C")
        # Nom outil
        self.set_font("Courier", "B", 9.5)
        self.set_text_color(*BLUE_MED)
        self.set_xy(x + 24, y + 5)
        self.cell(80, 6, _a(name))
        # Fichier
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY_MID)
        self.set_xy(x + 24, y + 11)
        self.cell(80, 5, _a(f"Fichier : {file}"))
        # Badge statut
        badge_col = GREEN_DARK if status == "Implemente" else ORANGE
        self.set_fill_color(*badge_col)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 7)
        bw = self.get_string_width(_a(status)) + 6
        self.set_xy(x + w - bw - 8, y + 5)
        self.cell(bw, 5.5, _a(status), fill=True)
        # Score
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*TEAL)
        self.set_xy(x + w - 30, y + 13)
        self.cell(22, 5, _a(f"Score : {score}"), align="R")
        # Description
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*GRAY_DARK)
        self.set_xy(x + 8, y + 19)
        self.multi_cell(w - 16, 4.5, _a(desc))
        # Entrees / Sorties
        self.set_font("Helvetica", "", 7.5)
        self.set_text_color(*GRAY_MID)
        row_y = y + 30
        self.set_xy(x + 8, row_y)
        self.cell(18, 4.5, "Entree :")
        self.set_text_color(*GRAY_DARK)
        self.cell(80, 4.5, _a(inputs))
        self.set_text_color(*GRAY_MID)
        self.cell(15, 4.5, "Sortie :")
        self.set_text_color(*GRAY_DARK)
        self.cell(0, 4.5, _a(outputs))
        # Bordure
        self.set_draw_color(*GRAY_LIGHT)
        self.rect(x, y, w, h, "D")
        self.ln(h + 4)


# ── Contenu ───────────────────────────────────────────────────────────────────

def build():
    pdf = McpPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ══ PAGE 1 — Couverture ═══════════════════════════════════════════════════
    pdf.add_page()

    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*BLUE_MED)
    pdf.cell(0, 14, "Outils MCP", ln=True, align="C")
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(*GRAY_DARK)
    pdf.cell(0, 10, "Definition, implementation et apports", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(0, 6, _a(f"CyberGuardian EASM Platform  -  {datetime.now().strftime('%d %B %Y')}"), ln=True, align="C")
    pdf.ln(5)

    # Bandeau intro
    pdf.set_fill_color(*BLUE_LIGHT)
    pdf.rect(10, pdf.get_y(), 190, 30, "F")
    pdf.set_fill_color(*BLUE_MED)
    pdf.rect(10, pdf.get_y(), 4, 30, "F")
    pdf.set_xy(18, pdf.get_y() + 5)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*BLUE_MED)
    pdf.cell(0, 5, "Ce document explique :", ln=True)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*GRAY_DARK)
    for item in [
        "Ce qu'est le protocole MCP (Model Context Protocol) et son origine",
        "Comment il a ete adapte dans CyberGuardian pour les outils de securite",
        "Les 8 outils implementes avec leur code et leur logique",
        "Comment l'IA exploite les resultats de chaque outil",
        "Les 4 outils restants a implementer",
    ]:
        pdf.set_x(18)
        pdf.cell(5, 5.5, "-")
        pdf.cell(0, 5.5, _a(item), ln=True)
    pdf.ln(6)

    # ══ SECTION 1 — Origine MCP ═══════════════════════════════════════════════
    pdf.h1("1. Qu'est-ce que le protocole MCP ?")

    pdf.body(
        "MCP (Model Context Protocol) est un protocole ouvert publie par Anthropic en novembre 2024. "
        "Son objectif : standardiser la facon dont les modeles de langage (LLM) comme Claude "
        "communiquent avec des outils et sources de donnees externes.\n\n"
        "Avant MCP, chaque integration etait ad hoc : il fallait ecrire du code specifique pour "
        "chaque outil, chaque API, chaque base de donnees. MCP introduit un contrat commun : "
        "un serveur MCP expose des outils, le LLM les decouvre et les appelle selon ses besoins."
    )
    pdf.ln(2)

    pdf.h2("Architecture officielle MCP (Anthropic)")
    pdf.code_block([
        "# Architecture MCP officielle",
        "Client LLM (Claude)  <-->  MCP Server  <-->  Outils / APIs / BDD",
        "",
        "# Le LLM appelle les outils via un protocole JSON standardise :",
        "{ 'tool': 'check_ssl', 'params': { 'target': 'e-senegal.sn' } }",
        "# Le serveur MCP execute et retourne :",
        "{ 'valid': true, 'grade': 'A+', 'days_until_expiry': 75, ... }",
    ], "Architecture MCP")
    pdf.ln(1)

    pdf.h2("Adaptation dans CyberGuardian")
    pdf.body(
        "Dans CyberGuardian, on a adapte ce concept a notre architecture FastAPI. "
        "Chaque outil de securite est un module Python independant que le backend appelle "
        "directement lors d'un scan. Les resultats sont ensuite stockes en base de donnees "
        "et transmis au LLM (Llama3) pour qu'il les interprete en langage naturel.\n\n"
        "Cette approche offre les memes avantages que MCP : modularite, reutilisabilite, "
        "separation des responsabilites - sans la complexite d'un serveur MCP dedie."
    )

    pdf.code_block([
        "# CyberGuardian — adaptation du concept MCP dans FastAPI",
        "from tools.check_ssl   import check_ssl        # MCP 1",
        "from tools.check_cve   import check_tls_cves   # MCP 2",
        "from tools.check_cve   import check_service_cves  # MCP 3",
        "from tools.github_tools import scan_github     # MCPs 4-8",
        "",
        "# Appel lors d'un POST /scans :",
        "ssl_result  = check_ssl(target)          # execute l'outil",
        "cves        = check_tls_cves(tls, cipher) # execute l'outil",
        "# Resultats -> PostgreSQL -> LLM -> Rapport IA",
    ], "routers/scans.py")

    # ══ SECTION 2 — Pourquoi MCP facilite ════════════════════════════════════
    pdf.h1("2. Pourquoi cette approche facilite le travail")

    benefits = [
        ("Modularite",
         "Chaque outil est dans son propre fichier Python. On peut modifier check_ssl.py "
         "sans toucher a check_cve.py. Les bugs sont isoles, les tests aussi."),
        ("Ajout d'outils sans refactoring",
         "Pour ajouter MCP 9 (check_headers), on cree tools/check_headers.py et on ajoute "
         "deux lignes dans scans.py. Le reste de l'application ne change pas."),
        ("Interpretation IA automatique",
         "Chaque outil retourne une structure JSON uniforme. Le LLM recoit un contexte "
         "structure (score, CVE, issues) et peut generer un rapport coherent sans "
         "connaitre les details d'implementation de chaque outil."),
        ("Reutilisabilite",
         "github_tools.py contient 5 fonctions (info, bandit, safety, trufflehog, npm). "
         "Chacune peut etre appelee independamment ou en combinaison selon le type de scan."),
        ("Observabilite",
         "Tous les resultats bruts sont persistes en JSON dans la colonne results "
         "de la table scans. On peut rejouer l'analyse IA sur un scan passe sans "
         "relancer les outils."),
    ]

    for i, (title, desc) in enumerate(benefits):
        pdf.set_x(12)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(0, 6, _a(f"{i+1}. {title}"), ln=True)
        pdf.body(desc, indent=18)
        pdf.ln(1)

    # ══ PAGE 2 — Outils implementes ══════════════════════════════════════════
    pdf.add_page()
    pdf.h1("3. Les 8 outils implementes")

    tools = [
        (1, "check_ssl()",       "tools/check_ssl.py",
         "Etablit une connexion SSL/TLS et analyse le certificat : validite, expiration, "
         "version TLS, suite de chiffrement, auto-signature, SAN.",
         "Domaine ou IP", "SSLResult (valid, grade, score/25, issues)", "/25 pts", "Implemente"),

        (2, "check_tls_cves()",  "tools/check_cve.py",
         "Verifie si la version TLS et la suite de chiffrement correspondent a des CVE "
         "connues (POODLE/TLS1.0, BEAST/TLS1.0, FREAK/TLS1.1, SWEET32/DES, RC4).",
         "tls_version, cipher_suite", "Liste de CVE [{id, severity, cvss, title}]", "Inclus SSL", "Implemente"),

        (3, "check_service_cves()", "tools/check_cve.py",
         "Recupere le header HTTP 'Server' (ex: cloudflare, nginx/1.18) et interroge "
         "l'API NVD (National Vulnerability Database) pour trouver les CVE associees.",
         "Domaine ou IP", "(server_banner, liste CVE NVD)", "Inclus SSL", "Implemente"),

        (4, "github_info()",     "tools/github_tools.py",
         "Appelle l'API GitHub REST v3 pour recuperer les metadonnees du depot : "
         "visibilite, langage, stars, forks, branches, contributeurs, licence.",
         "URL GitHub", "Dict (owner, repo, language, stars, ...)", "/30 pts", "Implemente"),

        (5, "scan_bandit()",     "tools/github_tools.py",
         "Clone le depot et execute Bandit, l'analyseur statique de securite Python. "
         "Detecte : injections SQL, eval sur entree utilisateur, mots de passe en dur, "
         "subprocess avec shell=True, etc.",
         "URL GitHub (Python)", "Liste findings [{severity, file, line, issue, cwe}]", "/30 pts", "Implemente"),

        (6, "scan_safety()",     "tools/github_tools.py",
         "Lit requirements.txt via l'API GitHub et interroge OSV.dev pour chaque "
         "dependance. Retourne les CVE avec package, version vulnerables et severite.",
         "URL GitHub (Python)", "Liste CVE [{package, version, cve, severity, desc}]", "/30 pts", "Implemente"),

        (7, "scan_trufflehog()", "tools/github_tools.py",
         "Scanne tous les fichiers du depot avec des regex pour detecter les secrets "
         "exposes : cles AWS (AKIA...), tokens GitHub (ghp_...), cles OpenAI (sk-...), "
         "cles privees, mots de passe hardcodes.",
         "URL GitHub", "Liste secrets [{type, file, line, value masquee}]", "/30 pts", "Implemente"),

        (8, "npm_audit()",       "tools/github_tools.py",
         "Pour les depots JavaScript/TypeScript, genere un package-lock.json sans "
         "installer les modules (--package-lock-only) puis execute npm audit --json "
         "pour obtenir les CVE des dependances npm.",
         "URL GitHub (JS/TS)", "Liste CVE [{package, severity, issue, range, fix}]", "/30 pts", "Implemente"),
    ]

    for t in tools:
        pdf.tool_card(*t)

    # ══ PAGE 3 — Zoom sur le code ══════════════════════════════════════════════
    pdf.add_page()
    pdf.h1("4. Zoom sur l'implementation — check_ssl()")

    pdf.body(
        "check_ssl() est l'outil fondateur du projet. Il illustre le pattern applique "
        "a tous les autres : entree simple (domaine), traitement independant, "
        "sortie structuree (dataclass), score calcule."
    )
    pdf.ln(1)

    pdf.h2("4.1  Structure de donnees de sortie (dataclass)", TEAL)
    pdf.code_block([
        "@dataclass",
        "class SSLResult:",
        "    target:             str",
        "    valid:              bool   # certificat valide ?",
        "    expired:            bool   # expire ?",
        "    self_signed:        bool   # auto-signe ?",
        "    days_until_expiry:  int    # jours restants",
        "    tls_version:        str    # TLSv1.3, TLSv1.2...",
        "    cipher_suite:       str    # ECDHE-RSA-AES256-GCM...",
        "    grade:              str    # A+, A, B, C, F",
        "    score:              int    # 0-25 pts",
        "    issues:             list   # problemes detectes",
    ], "tools/check_ssl.py — SSLResult")

    pdf.h2("4.2  Logique principale — connexion et analyse", TEAL)
    pdf.code_block([
        "def check_ssl(target, port=443, timeout=10):",
        "    hostname = _extract_hostname(target)",
        "    ctx = ssl.create_default_context()",
        "",
        "    # Connexion TCP + handshake TLS",
        "    with socket.create_connection((hostname, port)) as sock:",
        "        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:",
        "            result.tls_version  = ssock.version()    # 'TLSv1.3'",
        "            result.cipher_suite = ssock.cipher()[0]  # suite de chiffrement",
        "            cert = ssock.getpeercert()               # details certificat",
        "            result.issued_by    = _get_cn(cert['issuer'])",
        "            result.expiry_date  = cert['notAfter']   # date expiration",
        "",
        "    result.issues = _detect_issues(result)  # problemes detectes",
        "    result.score, result.grade = _calculate_score(result)",
        "    return result",
    ], "tools/check_ssl.py — check_ssl()")

    pdf.h2("4.3  Systeme de score /25 pts", TEAL)
    pdf.code_block([
        "def _calculate_score(r):",
        "    score = 25  # score parfait par defaut",
        "",
        "    if not r.valid:                  score -= 15  # cert invalide",
        "    if r.expired:                    score -= 10  # cert expire",
        "    elif r.days_until_expiry <= 30:  score -=  5  # expire bientot",
        "    if r.self_signed:                score -=  8  # auto-signe",
        "    if r.tls_version in ('TLSv1', 'TLSv1.1'):  score -= 7  # obsolete",
        "    if r.tls_version in ('SSLv2', 'SSLv3'):     score -= 10 # critique",
        "",
        "    # Grade selon le score",
        "    grade = 'A+' if score>=23 else 'A' if score>=20 else 'B' if score>=16 else 'F'",
        "    return max(0, score), grade",
    ], "tools/check_ssl.py — _calculate_score()")

    pdf.h2("4.4  Appel depuis le backend (routers/scans.py)", TEAL)
    pdf.code_block([
        "# POST /scans — lancement d'un scan EASM",
        "from tools.check_ssl import check_ssl",
        "from tools.check_cve import check_tls_cves, check_service_cves",
        "",
        "ssl = check_ssl(body.target)          # MCP 1 - analyse SSL",
        "tls_cves = check_tls_cves(            # MCP 2 - CVE TLS",
        "    ssl.tls_version, ssl.cipher_suite",
        ")",
        "server_banner, svc_cves = check_service_cves(body.target)  # MCP 3",
        "all_cves = tls_cves + svc_cves",
        "",
        "# Sauvegarde en base de donnees",
        "scan = Scan(",
        "    results = {'ssl': ssl_dict, 'cves': all_cves, 'server_banner': server_banner},",
        "    score   = ssl.score,",
        "    issues  = ssl.issues,",
        ")",
        "db.add(scan)",
    ], "routers/scans.py — integration des outils MCP")

    # ══ PAGE 4 — IA + outils a venir ══════════════════════════════════════════
    pdf.add_page()
    pdf.h1("5. Comment l'IA exploite les resultats des outils")

    pdf.body(
        "Apres chaque scan, les resultats JSON sont transmis au LLM (Llama3) via un "
        "prompt structure. L'IA n'a pas acces aux outils directement : elle recoit "
        "uniquement le rapport structure de chaque outil et genere une analyse en francais."
    )
    pdf.ln(2)

    pdf.h2("Flux complet : scan -> outils MCP -> IA -> rapport", BLUE_MED)
    pdf.code_block([
        "# 1. Scan lance -> outils MCP s'executent",
        "ssl_result    = check_ssl(target)         # MCP 1",
        "cves          = check_service_cves(target) # MCP 3",
        "",
        "# 2. Resultats sauvegardes en base",
        "scan.results = {'ssl': {...}, 'cves': [...], 'server_banner': '...'}",
        "",
        "# 3. Contexte construit pour le LLM (POST /scans/{id}/ask)",
        "context = f'''",
        "    Score de securite : {scan.score}/100",
        "    Serveur detecte : {server_banner}",
        "    SSL/TLS : valide={ssl.valid}, grade={ssl.grade}, version={ssl.tls_version}",
        "    CVE detectees ({len(cves)}) dont {nb_critical} CRITIQUE :",
        "    - CVE-2021-3761 CVSS=7.5 (HIGH) : ...",
        "    Reponds en francais simple et concis.",
        "'''",
        "",
        "# 4. LLM genere le rapport en streaming (token par token)",
        "# 5. Rapport sauvegarde dans scan.conversations",
    ], "Flux IA - routers/scans.py")

    pdf.info_box(
        "Le LLM ne 'sait' pas comment fonctionne check_ssl() ou check_service_cves().\n"
        "Il recoit uniquement des donnees structurees (score, liste CVE, issues) et\n"
        "les transforme en langage naturel adapte au contexte senegalais.\n"
        "C'est exactement le principe MCP : separation outil / intelligence."
    )

    pdf.h1("6. Les 4 outils a implementer (MCPs 9-12)")

    next_tools = [
        (9,  "check_headers()",  "tools/check_headers.py",
         "Verifie la presence et la configuration des en-tetes HTTP de securite. "
         "HSTS force HTTPS, CSP empeche les injections XSS, X-Frame-Options bloque le clickjacking.",
         "Domaine", "Dict {hsts, csp, x_frame, x_content_type, referrer}", "/25 pts", "A faire"),

        (10, "check_dns()",      "tools/check_dns.py",
         "Analyse les enregistrements DNS de securite. SPF empeche le spoofing d'email, "
         "DMARC definit la politique de rejet, DNSSEC garantit l'integrite des reponses DNS.",
         "Domaine", "Dict {spf, dmarc, dnssec, zone_transfer}", "/20 pts", "A faire"),

        (11, "scan_ports()",     "tools/scan_ports.py",
         "Execute nmap pour lister les ports TCP ouverts. Les ports inutiles exposes "
         "(FTP/21, Telnet/23, MySQL/3306) augmentent la surface d'attaque.",
         "IP ou domaine (Ubuntu)", "Liste ports [{port, service, state}]", "/15 pts", "A faire"),

        (12, "check_whois()",    "tools/check_whois.py",
         "Interroge les serveurs WHOIS pour verifier la date d'expiration du domaine, "
         "le registrar et les contacts. Un domaine qui expire peut etre racheté par un attaquant.",
         "Domaine", "Dict {expiry, registrar, days_left, alert}", "/15 pts", "A faire"),
    ]

    for t in next_tools:
        pdf.tool_card(*t)

    pdf.h2("Score EASM final apres implementation des 4 outils", TEAL)
    pdf.ln(1)
    score_rows = [
        ("MCP 1-3", "SSL/TLS + CVE",          "25 pts", GREEN_DARK),
        ("MCP 9",   "En-tetes HTTP securite",  "25 pts", BLUE_MED),
        ("MCP 10",  "DNS (SPF, DMARC, DNSSEC)","20 pts", PURPLE),
        ("MCP 11",  "Ports ouverts (nmap)",    "15 pts", ORANGE),
        ("MCP 12",  "WHOIS (expiration domaine)","15 pts", TEAL),
        ("TOTAL",   "",                         "100 pts", BLUE_DARK),
    ]
    x = 10
    for label, desc, pts, color in score_rows:
        is_total = label == "TOTAL"
        pdf.set_fill_color(*(BLUE_DARK if is_total else (248, 250, 252)))
        pdf.set_x(x)
        pdf.set_font("Helvetica", "B" if is_total else "", 8.5)
        pdf.set_text_color(*(WHITE if is_total else color))
        pdf.cell(25, 7, _a(label), border=1, fill=True)
        pdf.set_text_color(*(WHITE if is_total else GRAY_DARK))
        pdf.set_font("Helvetica", "", 8.5)
        pdf.cell(130, 7, _a(desc), border=1, fill=True)
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*(WHITE if is_total else color))
        pdf.cell(35, 7, _a(pts), border=1, fill=True, align="C")
        pdf.ln()
    pdf.ln(4)

    pdf.info_box(
        "Priorite d'implementation :\n"
        "  1. check_headers() - score eleve /25, faisable sur Windows, impact direct\n"
        "  2. check_dns()     - score /20, utilise uniquement des requetes DNS (dnspython)\n"
        "  3. check_whois()   - score /15, simple requete WHOIS (python-whois)\n"
        "  4. scan_ports()    - score /15, necessite Ubuntu + nmap (sudo apt install nmap)",
        bg=(232, 245, 233), border=(22, 163, 74)
    )

    out = "mcp_guide.pdf"
    pdf.output(out)
    print(f"[OK] {out}")


if __name__ == "__main__":
    build()

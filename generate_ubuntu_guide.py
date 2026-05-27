"""
Genere le guide de deploiement Ubuntu + prompt Claude Code pour reprendre le projet.
Usage : python generate_ubuntu_guide.py
"""
from fpdf import FPDF
from datetime import datetime
import unicodedata


def _a(text: str) -> str:
    """Convertit le texte en ASCII pur pour fpdf (police Helvetica)."""
    if not text:
        return ""
    text = str(text)
    replacements = [
        ("—", "-"), ("–", "-"), ("·", "|"),
        ("‘", "'"), ("’", "'"), ("“", '"'), ("”", '"'),
        ("«", '"'), ("»", '"'), ("…", "..."),
        ("•", "-"), ("‣", "-"), ("**", ""), ("*", ""),
        ("→", "->"), ("✔", "OK"), ("✘", "X"),
    ]
    for src, dst in replacements:
        text = text.replace(src, dst)
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")

# ── Palette ──────────────────────────────────────────────────────────────────
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
YELLOW     = (253, 224,  71)
TEAL       = (20, 184, 166)


class GuidePDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*WHITE)
        self.set_xy(10, 5)
        self.cell(140, 10, "CyberGuardian  |  Guide de deploiement Ubuntu", ln=False)
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
        self.cell(0, 8, "CyberGuardian EASM Platform  -  Guide Technique  -  Confidentiel", align="C")

    # ── Layout helpers ────────────────────────────────────────────────────────

    def h1(self, text):
        self.ln(3)
        self.set_fill_color(*BLUE_MED)
        self.set_text_color(*WHITE)
        self.set_font("Helvetica", "B", 10)
        self.cell(0, 8, _a(f"  {text}"), ln=True, fill=True)
        self.ln(3)

    def h2(self, txt, color=None):
        self.ln(2)
        c = color or BLUE_MED
        self.set_text_color(*c)
        self.set_font("Helvetica", "B", 9.5)
        self.set_x(10)
        self.cell(0, 7, _a(txt), ln=True)
        self.set_draw_color(*c)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)

    def body(self, text, indent=12, size=9):
        self.set_font("Helvetica", "", size)
        self.set_text_color(*GRAY_DARK)
        self.set_x(indent)
        self.multi_cell(210 - indent - 10, 5.5, _a(text))

    def bullet(self, text, indent=14, color=None):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(*(color or GRAY_DARK))
        self.set_x(indent)
        self.cell(5, 5.5, "-", ln=False)
        self.set_x(indent + 5)
        self.multi_cell(210 - indent - 15, 5.5, _a(text))

    def cmd_box(self, lines):
        """Bloc de commandes style terminal."""
        self.ln(1)
        x, w = 12, 186
        y = self.get_y()
        content = "\n".join(_a(l) for l in lines) if isinstance(lines, list) else _a(lines)
        n = content.count("\n") + 1
        h = n * 5.5 + 6
        self.set_fill_color(22, 27, 34)
        self.rect(x, y, w, h, "F")
        self.set_font("Courier", "", 8.5)
        self.set_text_color(126, 231, 135)
        self.set_xy(x + 4, y + 3)
        self.multi_cell(w - 8, 5.5, content)
        self.ln(3)

    def info_box(self, text, bg=BLUE_LIGHT, border=BLUE_MED):
        self.ln(1)
        x, w = 12, 186
        y = self.get_y()
        t = _a(text)
        lines = t.count("\n") + 1
        h = lines * 5.5 + 8
        self.set_fill_color(*bg)
        self.rect(x, y, w, h, "F")
        self.set_draw_color(*border)
        self.rect(x, y, 3, h, "F")
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_DARK)
        self.set_xy(x + 6, y + 4)
        self.multi_cell(w - 10, 5.5, t)
        self.ln(2)

    def tool_card(self, name, pkg, why, cmd):
        self.ln(1)
        x, w = 12, 186
        y = self.get_y()
        self.set_fill_color(248, 250, 252)
        self.set_draw_color(*GRAY_LIGHT)
        self.rect(x, y, w, 30, "FD")
        self.set_font("Helvetica", "B", 9.5)
        self.set_text_color(*BLUE_MED)
        self.set_xy(x + 4, y + 3)
        self.cell(60, 6, _a(name))
        self.set_font("Courier", "", 8)
        self.set_text_color(*PURPLE)
        self.cell(0, 6, _a(pkg), ln=True)
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_DARK)
        self.set_x(x + 4)
        self.multi_cell(w - 8, 5, _a(why))
        self.set_font("Courier", "B", 8)
        self.set_text_color(16, 185, 129)
        self.set_x(x + 4)
        self.cell(0, 5, _a(cmd), ln=True)
        self.ln(4)

    def prompt_box(self, text):
        """Encadre le prompt Claude Code."""
        self.ln(2)
        x, w = 10, 190
        y = self.get_y()
        self.set_fill_color(15, 23, 42)
        self.rect(x, y, w, 8, "F")
        self.set_font("Helvetica", "B", 8)
        self.set_text_color(*YELLOW)
        self.set_xy(x + 4, y + 1.5)
        self.cell(0, 5, "  PROMPT CLAUDE CODE  |  Copier-coller ce texte au debut de la conversation")
        self.ln(8)

        t = _a(text)
        lines = t.split("\n")
        block_y = self.get_y()
        self.set_fill_color(22, 27, 34)
        approx_h = len(lines) * 5 + 10
        self.rect(x, block_y, w, approx_h, "F")
        self.set_font("Courier", "", 7.5)
        self.set_text_color(203, 213, 225)
        self.set_xy(x + 4, block_y + 4)
        self.multi_cell(w - 8, 4.8, t)
        self.ln(4)


# ── Contenu ───────────────────────────────────────────────────────────────────

CLAUDE_PROMPT = """Tu reprends le projet CyberGuardian, une plateforme EASM (External Attack Surface Management)
developpee pour les PME senegalaises, dans le cadre d'un memoire de fin d'etudes.

=== ARCHITECTURE DU PROJET ===

backend/  (FastAPI, Python 3.11+)
  main.py                  -- point d'entree, inclut le router /scans
  routers/scans.py         -- endpoints : POST /scans, GET /scans, GET /scans/{id},
                              DELETE /scans/{id}, POST /scans/{id}/rerun,
                              POST /scans/{id}/ask (SSE streaming Ollama),
                              GET /scans/{id}/pdf
  tools/
    check_ssl.py           -- outil MCP 1+2+3 : SSL/TLS grade A-F, cipher, expiry, score /25
    check_cve.py           -- outil MCP 2+3 : CVE TLS (POODLE, BEAST) + banner serveur
    github_tools.py        -- outils MCP 4-8 : get_github_info, scan_bandit, scan_safety,
                              scan_trufflehog, scan_npm_audit
    generate_pdf.py        -- generation PDF bifurquee : EASM (SSL) vs GitHub
  data/scans.json          -- persistance JSON (pas de BDD)
  generate_recap.py        -- PDF recap session 1
  generate_recap2.py       -- PDF recap session 2
  generate_recap3.py       -- PDF recap session 3

frontend/  (React 18 + Vite + Tailwind CSS)
  src/
    pages/
      LoginPage.jsx         -- connexion, fallback offline, ROLE_MAP (client/expert/admin)
      DashboardPage.jsx     -- metriques separees SSL vs GitHub, ScoreCard, liste scans
      ScanResultsPage.jsx   -- resultats SSL ou GitHub (tabs Bandit/Safety/npm/TruffleHog/Infos)
      ScanListPage.jsx      -- liste + recherche + rerun + delete avec confirmation
      ExpertsPage.jsx       -- mise en relation avec experts
      MessagesPage.jsx      -- chat client-expert
      AdminPage.jsx         -- tableau de bord administrateur
      ScanProgressPage.jsx  -- ecran plein durant le scan (polling)
    components/
      ui.jsx                -- Card, Badge, SeverityBadge, Button, Skeleton, Tooltip,
                               RelativeTime, CopyValue, Toast/Toaster, LabeledInput,
                               Avatar, ScoreCard, PageHeader, SkeletonCard
      Sidebar.jsx           -- navigation (roles : client / expert / admin)
      ScanForm.jsx          -- formulaire lancement scan (domain/ip/url/github)
      Icons.jsx             -- tous les icones Lucide centralises
    lib/
      api.js                -- axios, baseURL localhost:8001, scanAPI.list/get/delete/rerun/pdf
      constants.js          -- MOCK_CONVERSATIONS, MOCK_EXPERTS (donnees demo)

=== CE QUI EST FAIT (8 outils MCP sur 12) ===

MCP 1  check_ssl()           -- OK
MCP 2  check_tls_cves()      -- OK
MCP 3  check_service_cves()  -- OK (banner HTTP + CVE connues Apache/nginx)
MCP 4  get_github_info()     -- OK (meta : stars, forks, langue, licence, branches)
MCP 5  scan_bandit()         -- OK (Python static analysis, LOC, CWE)
MCP 6  scan_safety()         -- OK (pip deps CVE via OSV.dev)
MCP 7  scan_trufflehog()     -- OK (regex secrets : AWS, GitHub token, OpenAI, etc.)
MCP 8  scan_npm_audit()      -- OK (JS/TS deps via OSV.dev)

=== CE QUI RESTE A FAIRE (4 outils MCP + deploiement) ===

MCP 9  check_headers()       -- En-tetes HTTP securite : HSTS, CSP, X-Frame-Options,
                                X-Content-Type-Options, Referrer-Policy
MCP 10 check_dns()           -- SPF, DMARC, DNSSEC, zone transfer
MCP 11 scan_ports()          -- Ports ouverts (socket scan sur top 20 ports communs)
MCP 12 check_whois()         -- Expiration domaine, registrar, contacts WHOIS

Ces 4 outils alimentent le score EASM global (actuellement base uniquement sur SSL /25).
Le score EASM devra etre refactorise vers /100 avec ponderation :
  SSL/TLS     : /25 pts (deja fait)
  Headers HTTP: /25 pts (MCP 9)
  DNS securite: /20 pts (MCP 10)
  Ports        : /15 pts (MCP 11)
  WHOIS/expiry : /15 pts (MCP 12)

=== DESIGN SYSTEM (applique) ===

Tokens CSS : --cg-primary #1F5C99, --cg-radius 8px, --cg-shadow
Composants ui.jsx : Card, Badge, SeverityBadge, Skeleton, Tooltip, RelativeTime, CopyValue, Toast
Classes : slate-* (pas gray-*), police Helvetica/JetBrains Mono

=== CONTEXTE MEMOIRE ===

Plateforme pour PME senegalaises. Langage : francais. Backend tourne sur Ubuntu 22.04 (migration
depuis Windows dev). Frontend sur Vite devserver (localhost:5173). Backend FastAPI (localhost:8001).
IA : Ollama llama3 sur serveur distant (fromager.unchk.sn:11435).
Pas de base de donnees : persistance JSON dans data/scans.json.

=== PROCHAINE ETAPE IMMEDIATE ===

On vient de migrer sur Ubuntu. Les outils systeme (trufflehog binaire, nmap, semgrep) sont
maintenant disponibles. Commencer par implementer MCP 9 (check_headers) dans backend/tools/check_headers.py,
l'integrer dans routers/scans.py pour les scans domain/ip/url, et afficher les resultats
dans ScanResultsPage.jsx (nouvel onglet "Headers" dans la section EASM).

Si tu as des questions sur l'architecture, lis d'abord routers/scans.py et tools/check_ssl.py
pour comprendre le pattern des outils MCP."""


def build():
    pdf = GuidePDF()
    pdf.set_auto_page_break(auto=True, margin=16)

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE DE GARDE
    # ══════════════════════════════════════════════════════════════════════════
    pdf.add_page()

    # Grand titre
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*BLUE_MED)
    pdf.set_x(10)
    pdf.cell(0, 14, "Guide de deploiement Ubuntu", ln=True, align="C")

    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(*GRAY_MID)
    pdf.set_x(10)
    pdf.cell(0, 8, "CyberGuardian EASM Platform", ln=True, align="C")

    pdf.set_font("Helvetica", "", 10)
    pdf.set_x(10)
    pdf.cell(0, 6, f"Genere le {datetime.now().strftime('%d %B %Y')}", ln=True, align="C")
    pdf.ln(6)

    # Bandeau statut
    pdf.set_fill_color(*BLUE_LIGHT)
    pdf.rect(10, pdf.get_y(), 190, 22, "F")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*BLUE_MED)
    pdf.set_xy(14, pdf.get_y() + 3)
    pdf.cell(0, 6, "Etat du projet au moment de la migration", ln=True)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*GRAY_DARK)
    pdf.set_x(14)
    pdf.cell(55, 5.5, "Outils MCP implementes :")
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*GREEN)
    pdf.cell(15, 5.5, "8 / 12")
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*GRAY_DARK)
    pdf.cell(40, 5.5, "   Scans types supportes :")
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*BLUE_MED)
    pdf.cell(0, 5.5, "EASM (SSL) + GitHub", ln=True)
    pdf.ln(6)

    # Sommaire
    pdf.h1("Sommaire")
    sommaire = [
        ("1.", "Pourquoi migrer sur Ubuntu ?",         "Ce que Windows ne peut pas faire"),
        ("2.", "Outils systeme a installer",           "Binaires, paquets apt et pip"),
        ("3.", "Installation pas a pas",               "Commandes pret a executer"),
        ("4.", "Verification de l'installation",       "Tests rapides pour chaque outil"),
        ("5.", "Lancement du projet",                  "Backend FastAPI + Frontend Vite"),
        ("6.", "Prompt Claude Code",                   "Reprendre le projet intelligemment"),
    ]
    for num, titre, sous in sommaire:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(14)
        pdf.cell(12, 6.5, num)
        pdf.cell(85, 6.5, titre)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*GRAY_MID)
        pdf.cell(0, 6.5, sous, ln=True)

    pdf.ln(4)

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1 — POURQUOI UBUNTU
    # ══════════════════════════════════════════════════════════════════════════
    pdf.h1("1. Pourquoi migrer sur Ubuntu ?")

    pdf.body(
        "Le projet CyberGuardian utilise des outils de securite qui ne fonctionnent pas "
        "correctement (ou pas du tout) sous Windows. La migration vers Ubuntu 22.04 LTS est "
        "necessaire pour que la plateforme puisse executer tous ses outils MCP en conditions reelles."
    )
    pdf.ln(3)

    raisons = [
        ("TruffleHog (binaire natif Linux)",
         "Le binaire officiel TruffleHog est compile pour Linux/macOS. Sur Windows, il faut "
         "Docker ou WSL, ce qui ralentit chaque scan GitHub et complique le deploiement. "
         "Sur Ubuntu, c'est un simple wget + chmod."),
        ("nmap (scan de ports, MCP 11)",
         "nmap necessite des droits sur les sockets bruts (raw sockets) pour les scans SYN. "
         "Ces droits sont bloques sur Windows sans configuration complexe. Sur Ubuntu, "
         "un simple 'apt install nmap' suffit et le scan fonctionne avec les droits normaux."),
        ("Semgrep (analyse statique avancee, futur MCP)",
         "Semgrep n'a pas de support Windows natif stable. Il est concu pour tourner en CI/CD "
         "Linux. Les regles de securite OWASP et CWE sont maintenues uniquement pour Linux."),
        ("Bandit + Safety (execution fiable)",
         "Ces outils pip fonctionnent sur Windows mais les chemins de fichiers (backslash) "
         "causent des erreurs lors des scans de depots clones. Sur Ubuntu, les chemins "
         "POSIX eliminent ces problemes."),
        ("Droits fichiers et clonage Git",
         "Le scan GitHub clone le depot dans un dossier temporaire (tempfile.mkdtemp). "
         "Sous Windows, les fichiers temporaires ont parfois des verrous qui empechent "
         "la suppression apres scan. Ubuntu n'a pas ce probleme."),
        ("Environnement de production coherent",
         "Le serveur de production sera Ubuntu. Developper aussi sur Ubuntu garantit que "
         "les commandes, les chemins et les permissions sont identiques entre dev et prod. "
         "Pas de 'ca marche chez moi mais pas sur le serveur'."),
    ]

    for titre, desc in raisons:
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*BLUE_MED)
        pdf.set_x(12)
        pdf.cell(5, 6, "-")
        pdf.cell(0, 6, titre, ln=True)
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(19)
        pdf.multi_cell(181, 5.5, desc)

    pdf.info_box(
        "Version recommandee : Ubuntu 22.04 LTS (Jammy Jellyfish).\n"
        "Python 3.11+ est disponible via deadsnakes PPA. Node 20 LTS via NodeSource.\n"
        "Le projet a ete developpe avec Python 3.11.9 et Node 20.14."
    )

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2 — OUTILS A INSTALLER
    # ══════════════════════════════════════════════════════════════════════════
    pdf.h1("2. Outils systeme a installer")

    pdf.body(
        "Chaque outil correspond a un ou plusieurs outils MCP de la plateforme. "
        "Le tableau ci-dessous indique pourquoi chaque outil est necessaire."
    )
    pdf.ln(3)

    tools = [
        ("Python 3.11+",   "apt / deadsnakes",
         "Runtime du backend FastAPI et de tous les outils MCP Python (Bandit, Safety, pip-audit).",
         "sudo apt install python3.11 python3.11-venv python3-pip"),
        ("git",            "apt",
         "Necessaire pour cloner les depots GitHub lors des scans MCP 4-8. "
         "Sans git, scan_github() echoue immediatement.",
         "sudo apt install git"),
        ("Node.js 20 LTS + npm", "NodeSource",
         "Necessaire pour npm audit (MCP 8). "
         "Le backend cree un package.json temporaire et execute 'npm audit --json'.",
         "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install nodejs"),
        ("nmap",           "apt",
         "Scan de ports (MCP 11 - a implementer). Detecte les services exposes "
         "(HTTP, FTP, SSH, RDP...) sans avoir besoin de Metasploit.",
         "sudo apt install nmap"),
        ("TruffleHog v3",  "binaire GitHub",
         "Detection de secrets exposes (MCP 7). Le binaire analyse le depot git clone "
         "avec son moteur de detection (plus precis que les regex manuelles).",
         "wget https://github.com/trufflesecurity/trufflehog/releases/latest/download/"
         "trufflehog_linux_amd64.tar.gz -O /tmp/th.tar.gz && "
         "tar -xzf /tmp/th.tar.gz -C /usr/local/bin/ && chmod +x /usr/local/bin/trufflehog"),
        ("Semgrep",        "pip",
         "Analyse statique avancee (complementaire a Bandit). "
         "Supporte Python, JS, TS, Java, Go avec regles OWASP/CWE maintenues.",
         "pip install semgrep"),
        ("whois",          "apt",
         "Lookup WHOIS pour MCP 12 (expiration domaine, registrar). "
         "Necessaire pour avertir les clients dont le domaine expire bientot.",
         "sudo apt install whois"),
    ]

    for name, pkg, why, cmd in tools:
        pdf.tool_card(name, f"  [{pkg}]", why, f"$ {cmd}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3 — INSTALLATION PAS A PAS
    # ══════════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.h1("3. Installation pas a pas")

    pdf.h2("3.1  Mise a jour du systeme", BLUE_MED)
    pdf.cmd_box([
        "sudo apt update && sudo apt upgrade -y",
        "sudo apt install -y build-essential curl wget git whois nmap",
    ])

    pdf.h2("3.2  Python 3.11 + environnement virtuel", BLUE_MED)
    pdf.cmd_box([
        "sudo add-apt-repository ppa:deadsnakes/ppa -y",
        "sudo apt install -y python3.11 python3.11-venv python3.11-dev",
        "# Dans le dossier backend du projet :",
        "cd ~/cyberguardian/backend",
        "python3.11 -m venv .venv",
        "source .venv/bin/activate",
        "pip install --upgrade pip",
        "pip install -r requirements.txt",
    ])

    pdf.h2("3.3  Node.js 20 LTS", BLUE_MED)
    pdf.cmd_box([
        "curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -",
        "sudo apt install -y nodejs",
        "node --version   # doit afficher v20.x.x",
        "npm --version    # doit afficher 10.x.x",
    ])

    pdf.h2("3.4  TruffleHog v3 (binaire natif)", BLUE_MED)
    pdf.info_box(
        "Le binaire TruffleHog remplace la detection regex manuelle dans github_tools.py.\n"
        "Une fois installe, le code peut appeler 'trufflehog git file://./repo --json'\n"
        "pour une detection plus precise (moins de faux positifs)."
    )
    pdf.cmd_box([
        "# Telecharger la derniere version stable",
        "wget https://github.com/trufflesecurity/trufflehog/releases/latest/download/"
        "trufflehog_linux_amd64.tar.gz -O /tmp/th.tar.gz",
        "tar -xzf /tmp/th.tar.gz -C /tmp/",
        "sudo mv /tmp/trufflehog /usr/local/bin/trufflehog",
        "sudo chmod +x /usr/local/bin/trufflehog",
        "trufflehog --version   # verification",
    ])

    pdf.h2("3.5  Semgrep", BLUE_MED)
    pdf.cmd_box([
        "source .venv/bin/activate   # si pas deja actif",
        "pip install semgrep",
        "semgrep --version",
    ])

    pdf.h2("3.6  Frontend (React + Vite)", BLUE_MED)
    pdf.cmd_box([
        "cd ~/cyberguardian/frontend",
        "npm install",
        "npm run dev   # lance sur http://localhost:5173",
    ])

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4 — VERIFICATION
    # ══════════════════════════════════════════════════════════════════════════
    pdf.h1("4. Verification de l'installation")

    pdf.body("Executer ces commandes pour confirmer que tout est operationnel :")
    pdf.ln(2)

    checks = [
        ("Python + FastAPI",  "python3.11 --version && python -c \"import fastapi; print('FastAPI OK')\""),
        ("Bandit",            "bandit --version"),
        ("TruffleHog",        "trufflehog --version"),
        ("nmap",              "nmap --version"),
        ("Node / npm",        "node --version && npm --version"),
        ("Semgrep",           "semgrep --version"),
        ("whois",             "whois example.com | head -5"),
        ("Git",               "git --version"),
        ("Backend FastAPI",   "cd backend && uvicorn main:app --host 0.0.0.0 --port 8001 --reload"),
    ]

    for label, cmd in checks:
        pdf.set_font("Helvetica", "B", 8.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(12)
        pdf.cell(48, 6, label)
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(*TEAL)
        pdf.cell(0, 6, f"$ {cmd}", ln=True)

    pdf.ln(2)
    pdf.info_box(
        "Test de scan complet (une fois le backend lance) :\n"
        "curl -X POST http://localhost:8001/scans \\\n"
        "     -H 'Content-Type: application/json' \\\n"
        "     -d '{\"target\": \"ec2lt.sn\", \"asset_type\": \"domain\"}'"
    )

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 5 — LANCEMENT
    # ══════════════════════════════════════════════════════════════════════════
    pdf.h1("5. Lancement du projet")

    pdf.h2("Terminal 1 - Backend FastAPI", GREEN)
    pdf.cmd_box([
        "cd ~/cyberguardian/backend",
        "source .venv/bin/activate",
        "uvicorn main:app --host 0.0.0.0 --port 8001 --reload",
        "# API disponible sur http://localhost:8001",
        "# Docs interactifs : http://localhost:8001/docs",
    ])

    pdf.h2("Terminal 2 - Frontend Vite", BLUE_MED)
    pdf.cmd_box([
        "cd ~/cyberguardian/frontend",
        "npm run dev",
        "# Interface sur http://localhost:5173",
    ])

    pdf.info_box(
        "Comptes de test disponibles (fallback offline) :\n"
        "  Client  : ibrahima.ly@ec2lt.sn  (n'importe quel mot de passe)\n"
        "  Expert  : expert@cyberguardian.sn\n"
        "  Admin   : admin@cyberguardian.sn"
    )

    pdf.h2("Variables d'environnement backend (optionnel)", GRAY_MID)
    pdf.cmd_box([
        "export OLLAMA_URL=https://fromager.unchk.sn:11435",
        "export OLLAMA_KEY=partner-2c58610f55694bcaa6b83a15635bf348",
        "# Ou creer un fichier .env et charger avec python-dotenv",
    ])

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6 — PROMPT CLAUDE CODE
    # ══════════════════════════════════════════════════════════════════════════
    pdf.add_page()
    pdf.h1("6. Prompt Claude Code — Reprendre le projet")

    pdf.body(
        "Copier-coller le texte ci-dessous au debut d'une nouvelle conversation Claude Code "
        "pour que l'IA comprenne exactement ou en est le projet et ce qu'il faut faire ensuite. "
        "Inutile de re-expliquer l'architecture : tout est dans le prompt."
    )
    pdf.ln(4)

    pdf.prompt_box(CLAUDE_PROMPT)

    pdf.ln(3)
    pdf.info_box(
        "Astuce : dans Claude Code (CLI), lance la commande :\n"
        "  claude --print \"$(cat prompt_cyberguardian.txt)\"\n"
        "pour injecter le prompt depuis un fichier sans copier-coller."
    )

    # ══════════════════════════════════════════════════════════════════════════
    # SAUVEGARDE
    # ══════════════════════════════════════════════════════════════════════════
    out = "ubuntu_deployment_guide.pdf"
    pdf.output(out)
    print(f"[OK] Guide genere : {out}")


if __name__ == "__main__":
    build()

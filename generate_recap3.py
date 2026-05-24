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
TEAL       = (6,  182, 212)


class RecapPDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(*WHITE)
        self.set_xy(10, 5)
        self.cell(130, 10, "CyberGuardian - Recapitulatif technique - Session 3", ln=False)
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

    def warn(self, text):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*ORANGE)
        self.set_x(16)
        self.multi_cell(182, 5, f"[!]  {text}")

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

    def score_badge(self, label, value, color):
        y = self.get_y()
        self.set_fill_color(*color)
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*WHITE)
        self.set_x(16)
        self.cell(40, 6, f" {label} : {value} ", fill=True)
        self.ln(8)


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
    pdf.cell(0, 8, "Recapitulatif technique - Session 3", ln=True)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*BLUE_MED)
    pdf.set_x(16)
    pdf.cell(0, 6, "Scan GitHub : outils MCP, score /30, detection langage, Ubuntu", ln=True)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(*GRAY_MID)
    pdf.set_x(16)
    pdf.cell(0, 6, f"Genere le {datetime.now().strftime('%d/%m/%Y a %H:%M')}  |  CyberGuardian EASM Platform", ln=True)
    pdf.ln(8)

    # ── 1. RESUME ─────────────────────────────────────────────────────────────
    pdf.h1("1. Resume de la session")
    pdf.body(
        "Cette session a porte sur l'implementation complete du scan de depot GitHub. "
        "Les 4 outils MCP GitHub (github_info, scan_bandit, scan_safety, scan_trufflehog) ont ete "
        "integres dans le backend et le frontend. L'outil npm_audit a ete ajoute pour les projets "
        "JavaScript/TypeScript. La selection des outils est desormais adaptee au langage detecte. "
        "Le score GitHub est note /30 (bonus) et non /100. Plusieurs corrections cosmétiques et "
        "logiques ont ete appliquees : affichage du langage, rapport IA, affichage du score. "
        "Les deux depots GitHub ont ete configures (backend pousse, frontend en attente). "
        "Enfin, une note importante sur le deploiement Ubuntu a ete documentee pour utiliser "
        "les vrais binaires (TruffleHog, Semgrep, nmap)."
    )
    pdf.ln(2)

    # ── 2. FICHIERS ───────────────────────────────────────────────────────────
    pdf.h1("2. Fichiers crees et modifies")

    pdf.h2("Nouveaux fichiers backend", GREEN)
    pdf.file_row("backend/tools/github_tools.py",  "4 outils MCP GitHub + npm audit + detection langage")
    pdf.file_row("backend/.gitignore",             "Ignore __pycache__, .venv, scans.json, *.pdf, .env")
    pdf.file_row("backend/.gitattributes",         "* text=auto eol=lf (supprime warnings LF/CRLF Windows)")
    pdf.file_row("backend/data/.gitkeep",          "Preserve le dossier data/ vide dans git")
    pdf.file_row("backend/generate_recap3.py",     "Script de generation du present document PDF")

    pdf.h2("Nouveaux fichiers frontend", GREEN)
    pdf.file_row("frontend/.gitignore",            "Ignore node_modules, dist, .env, .vite")
    pdf.file_row("frontend/.gitattributes",        "* text=auto eol=lf (supprime warnings LF/CRLF Windows)")

    pdf.h2("Fichiers backend modifies", ORANGE)
    pdf.file_row("backend/routers/scans.py",       "Branche github dans launch_scan + ask_ai + rapport IA", "MODIFIE", ORANGE)
    pdf.file_row("backend/requirements.txt",       "Ajout bandit==1.9.4", "MODIFIE", ORANGE)

    pdf.h2("Fichiers frontend modifies", ORANGE)
    pdf.file_row("frontend/src/pages/ScanResultsPage.jsx",
                 "GitHubSection, NaState, score/30, rapport automatique GitHub", "MODIFIE", ORANGE)

    # ── 3. TOOLS GITHUB ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("3. Module github_tools.py - Architecture des 4 outils MCP")

    pdf.h2("Vue d'ensemble")
    pdf.body(
        "Le module backend/tools/github_tools.py orchestre 4 outils de securite sur un depot "
        "GitHub. Le depot est clone une seule fois dans un repertoire temporaire, puis les outils "
        "pertinents sont executes selon le langage detecte. Le clone est supprime apres analyse."
    )
    pdf.ln(2)

    pdf.h2("Flux complet - scan_github(target)")
    pdf.arrow_flow([
        ("github_info()", BLUE_MED),
        ("_clone(owner,repo)", PURPLE),
        ("detect_language", TEAL),
        ("outils selon lang", ORANGE),
        ("score /30", GREEN),
    ])

    pdf.h2("1. github_info(owner, repo) - Metadonnees via API REST")
    pdf.code_block([
        "GET https://api.github.com/repos/{owner}/{repo}",
        "-> language, stars, forks, open_issues, visibility",
        "GET https://api.github.com/repos/{owner}/{repo}/branches",
        "-> liste des branches (noms)",
        "GET https://api.github.com/repos/{owner}/{repo}/contributors",
        "-> nombre de contributeurs (len de la liste)",
        "Conversion None -> 'N/A' pour chaque champ",
    ])
    pdf.ln(2)

    pdf.h2("2. _detect_language_from_files(tmpdir) - Detection par structure")
    pdf.body(
        "Utilise si l'API GitHub retourne None ou 'N/A' pour le champ language. "
        "Inspecte les fichiers presents dans le clone local."
    )
    pdf.code_block([
        "package.json present -> JavaScript (ou TypeScript si *.ts detecte)",
        "requirements.txt / setup.py / pyproject.toml / *.py -> Python",
        "go.mod -> Go",
        "Cargo.toml -> Rust",
        "pom.xml / build.gradle -> Java",
        "Aucun indicateur -> '' (chaine vide)",
    ])
    pdf.ln(2)

    pdf.h2("3. _run_bandit(tmpdir) - Analyse statique Python")
    pdf.code_block([
        "# Commande : python -m bandit (et non 'bandit' seul, introuvable sur Windows)",
        "subprocess.run([sys.executable, '-m', 'bandit', '-r', tmpdir, '-f', 'json', '-q', '--exit-zero'])",
        "-> parse JSON : issues[] avec severity (HIGH/MEDIUM/LOW) et confidence",
        "-> retourne {'findings': [...], 'summary': {high, medium, low}}",
        "Non-Python : {'findings': [], 'note': 'N/A - {language}'}",
    ])
    pdf.ln(2)

    pdf.h2("4. _run_safety(tmpdir) - CVE sur dependances Python (OSV.dev)")
    pdf.code_block([
        "# Lit requirements.txt, extrait nom+version, interroge OSV.dev",
        "POST https://api.osv.dev/v1/query  (gratuit, sans cle API)",
        "Body : {'package': {'name': pkg, 'ecosystem': 'PyPI'}, 'version': ver}",
        "-> retourne les CVE connues pour chaque dependance",
        "Non-Python : {'findings': [], 'note': 'N/A - {language}'}",
    ])
    pdf.ln(2)

    pdf.h2("5. _run_npm_audit(tmpdir) - CVE sur dependances JS/TS")
    pdf.code_block([
        "subprocess.run(['npm', 'audit', '--json'], cwd=tmpdir)",
        "# Format npm v7+ : cle 'vulnerabilities'",
        "# Format npm v6   : cle 'advisories'",
        "-> normalise en findings[] + summary{critical, high, moderate, low}",
        "Non-JS/TS : non appele (champ npm_audit absent ou None)",
    ])
    pdf.ln(2)

    pdf.h2("6. _run_trufflehog(tmpdir) - Secrets et tokens exposes")
    pdf.code_block([
        "# Version actuelle : regex Python (patterns courants sur Windows)",
        "Patterns : AWS key, private key, bearer token, password=, api_key=, secret=",
        "Scan recursif de tous les fichiers texte du clone",
        "-> findings[] avec file, line, pattern, snippet",
        "",
        "# Version Ubuntu (a venir) : binaire trufflehog officiel",
        "trufflehog git file://{tmpdir} --json  (700+ patterns, entropie Shannon)",
    ])

    # ── 4. SCORE /30 ──────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("4. Systeme de score GitHub - /30 (bonus)")

    pdf.h2("Principe")
    pdf.body(
        "Le scan GitHub est un bonus de 30 points, independant du score EASM /100. "
        "Le score demarre a 30 et des deductions sont appliquees selon les resultats. "
        "Le minimum est 0 (max(0, score)). Le champ 'max' retourne 30 pour que le frontend "
        "affiche correctement 'X/30' et non 'X/100'."
    )
    pdf.ln(2)

    pdf.h2("Deductions selon le langage detecte")

    # Python deductions
    pdf.set_x(16)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*BLUE_MED)
    pdf.cell(0, 6, "Projet Python (Bandit + Safety + TruffleHog)", ln=True)

    python_deduc = [
        ("Bandit HIGH",      "-5 pts",  RED),
        ("Bandit MEDIUM",    "-2 pts",  ORANGE),
        ("Bandit LOW",       "-1 pt",   GRAY_MID),
        ("Safety CRITICAL",  "-8 pts",  RED),
        ("Safety HIGH",      "-5 pts",  RED),
        ("Safety MEDIUM",    "-2 pts",  ORANGE),
        ("TruffleHog secret","-10 pts", PURPLE),
    ]
    for label, pts, color in python_deduc:
        pdf.set_x(20)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(50, 5, label)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*color)
        pdf.cell(0, 5, pts, ln=True)
    pdf.ln(3)

    # JS/TS deductions
    pdf.set_x(16)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*BLUE_MED)
    pdf.cell(0, 6, "Projet JavaScript / TypeScript (npm audit + TruffleHog)", ln=True)

    js_deduc = [
        ("npm critical",     "-8 pts",  RED),
        ("npm high",         "-5 pts",  RED),
        ("npm moderate",     "-2 pts",  ORANGE),
        ("npm low",          "-1 pt",   GRAY_MID),
        ("TruffleHog secret","-10 pts", PURPLE),
    ]
    for label, pts, color in js_deduc:
        pdf.set_x(20)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(50, 5, label)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*color)
        pdf.cell(0, 5, pts, ln=True)
    pdf.ln(3)

    # Other language
    pdf.set_x(16)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*BLUE_MED)
    pdf.cell(0, 6, "Autre langage (TruffleHog uniquement)", ln=True)
    pdf.set_x(20)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(*GRAY_DARK)
    pdf.cell(50, 5, "TruffleHog secret")
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_text_color(*PURPLE)
    pdf.cell(0, 5, "-10 pts", ln=True)
    pdf.ln(3)

    pdf.h2("Retour de scan_github()")
    pdf.code_block([
        "return {",
        "  'github_info': {...},   # metadonnees depot",
        "  'bandit':      {...},   # findings + note si N/A",
        "  'safety':      {...},   # findings + note si N/A",
        "  'trufflehog':  {...},   # findings (toujours execute)",
        "  'npm_audit':   {...},   # findings + summary (JS/TS seulement)",
        "  'langage':     'Python' | 'JavaScript' | 'TypeScript' | ...",
        "  'score':       27,      # score calcule",
        "  'max':         30,      # toujours 30 pour GitHub",
        "}",
    ])

    # ── 5. BACKEND scans.py ───────────────────────────────────────────────────
    pdf.h1("5. Modifications backend/routers/scans.py")

    pdf.h2("Branche GitHub dans launch_scan()")
    pdf.code_block([
        "elif body.asset_type == 'github':",
        "    gh = scan_github(body.target)",
        "    results['github_info'] = gh['github_info']",
        "    results['bandit']      = gh['bandit']",
        "    results['safety']      = gh['safety']",
        "    results['trufflehog']  = gh['trufflehog']",
        "    results['npm_audit']   = gh.get('npm_audit')",
        "    results['langage']     = gh.get('langage', 'N/A')",
        "    results['score_max']   = gh.get('max', 30)",
        "    total_score            = gh['score']",
        "    all_cves               = gh['safety'].get('findings', [])",
    ])

    pdf.h2("Contexte IA dynamique (ask_ai et _generate_simple_explanation)")
    pdf.body(
        "Avant la correction, l'IA recevait '30/100' dans son contexte car le score_max "
        "etait code en dur a 100. Apres correction :"
    )
    pdf.code_block([
        "score_max   = results.get('score_max', 30)",
        "score_label = (f'{score}/{score_max} - excellent, aucune faille detectee'",
        "               if scan['score'] == score_max",
        "               else f'{scan[\"score\"]}/{score_max}')",
        "context = f'Score GitHub : {score_label}...'",
    ])
    pdf.bullet("Score parfait -> message 'excellent, aucune faille detectee' dans le rapport IA")
    pdf.bullet("Score degrade -> liste des problemes identifies (secrets, CVE, Bandit HIGH)")

    # ── 6. FRONTEND ───────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("6. Modifications frontend/src/pages/ScanResultsPage.jsx")

    pdf.h2("Variables de score uniformisees")
    pdf.code_block([
        "const isGithub   = scan?.type === 'github'",
        "const scoreMax   = isGithub ? (scan?.results?.score_max ?? 30) : 100",
        "const score      = scan?.score ?? 0",
        "const scorePct   = Math.round((score / scoreMax) * 100)  // pour couleur/badge",
        "const scoreColor = scorePct >= 80 ? '#10B981' : scorePct >= 50 ? '#F59E0B' : '#EF4444'",
    ])
    pdf.bullet("scorePct remplace 'score' dans tous les comparateurs >= 80 / >= 50")
    pdf.bullet("Affichage : '${score}/${scoreMax}' partout (plus de '${score}/100' code en dur)")
    pdf.ln(2)

    pdf.h2("GitHubSection({ scan }) - Composant resultats GitHub")
    pdf.body(
        "Section dediee qui lit les donnees reelles depuis scan.results. "
        "Contient 5 onglets : Bandit, Safety, npm audit (si JS/TS), TruffleHog, Infos repo."
    )
    pdf.code_block([
        "const results  = scan?.results ?? {}",
        "const info     = results.github_info ?? {}",
        "const language = (results.langage ?? info.language ?? '').toLowerCase()",
        "const isPython = language === 'python'",
        "const isJsTs   = ['javascript', 'typescript'].includes(language)",
        "const bandit   = results.bandit?.findings ?? []",
        "const safety   = results.safety?.findings ?? []",
        "const truffle  = results.trufflehog?.findings ?? []",
        "const npm      = results.npm_audit?.findings ?? []",
    ])
    pdf.ln(2)

    pdf.h2("Onglets avec flag 'na' (N/A pour outils non pertinents)")
    pdf.code_block([
        "const TABS = [",
        "  { key:'bandit',     label:'Bandit',     na: !isPython },",
        "  { key:'safety',     label:'Safety',     na: !isPython },",
        "  { key:'npm',        label:'npm audit',  na:false, show:isJsTs },",
        "  { key:'trufflehog', label:'TruffleHog', na:false },",
        "  { key:'info',       label:'Infos repo', na:false },",
        "].filter(t => t.show !== false)",
    ])
    pdf.ln(2)

    pdf.h2("NaState - Composant boite info bleue")
    pdf.body(
        "Affiche un encadre bleu avec icone 'i' quand un outil n'est pas applicable "
        "au langage detecte. Remplace l'ancien badge 'N/A - TypeScript' peu clair."
    )
    pdf.code_block([
        "const NaState = ({ note }) => {",
        "  const detectedLang = (results.langage || info.language || '').trim()",
        "  const msg = detectedLang",
        "    ? `Bandit et Safety non applicables - projet ${detectedLang}`",
        "       + (isJsTs ? ' - npm audit utilise a la place' : '')",
        "    : note",
        "  return <div style={{background:'#EFF6FF', border:'1px solid #BFDBFE'}}>",
        "    <span>i</span> <span>{msg}</span>",
        "  </div>",
        "}",
    ])
    pdf.ln(2)

    pdf.h2("Corrections cosmetiques (3 corrections)")
    cosmetics = [
        ("En-tete 'Langue -'",
         "La stat 'Langue' dans le hero lisait scan.results.github_info.language "
         "qui pouvait etre null si l'API retournait None.",
         "Lecture en cascade : results.langage || github_info.language || '-'"
         " (langage detecte par scan_github en priorite)"),
        ("Sous-titre 'N/A * -'",
         "Le sous-titre de GitHubSection affichait 'N/A' (language non renseigne) "
         "et '-' (score non renseigne).",
         "Sous-titre : '{results.langage || info.language || 'N/A'} * {score}/{scoreMax}'"
         " - le score vient de scan.score et scoreMax de results.score_max"),
        ("Badge 'N/A - TypeScript'",
         "L'onglet Bandit affichait le texte brut du champ 'note' du backend, "
         "sans mise en forme, peu lisible pour un utilisateur.",
         "Composant NaState avec fond bleu et icone 'i', message contextuel "
         "incluant le langage detecte et mentionnant npm audit si applicable"),
    ]
    for title, problem, solution in cosmetics:
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
        pdf.cell(22, 4, "Probleme :")
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(39)
        pdf.multi_cell(159, 4, problem)
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*GREEN)
        pdf.cell(22, 4, "Solution :")
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(39)
        pdf.multi_cell(159, 4, solution)
        pdf.ln(4)

    # ── 7. RAPPORT AUTO ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("7. Rapport automatique - Branche GitHub")

    pdf.h2("Probleme initial")
    pdf.body(
        "Le 'Rapport automatique' (resume genere cote frontend) n'avait pas de branche "
        "GitHub. Il utilisait par defaut la logique SSL, ce qui generait un message absurde "
        "comme 'Aucune donnee SSL disponible pour ce scan.' pour un scan GitHub."
    )

    pdf.h2("Branche GitHub implementee dans ScanResultsPage.jsx")
    pdf.code_block([
        "if (isGithub) {",
        "  const lang = r.langage || r.github_info?.language || 'N/A'",
        "  const secretCount  = truffle.length",
        "  const cveCount     = safety.length + npm.length",
        "  const banditHighs  = bandit.filter(f => f.severity === 'HIGH').length",
        "",
        "  if (score === scoreMax) {",
        "    // Score parfait",
        "    lines.push(`Score parfait ${score}/${scoreMax} - aucune vulnerabilite detectee.`)",
        "  } else {",
        "    if (secretCount > 0)  lines.push(`${secretCount} secret(s) exposes - revocation immediate requise`)",
        "    if (cveCount > 0)     lines.push(`${cveCount} CVE dans les dependances - mise a jour recommandee`)",
        "    if (banditHighs > 0)  lines.push(`${banditHighs} probleme(s) Bandit HIGH detectes`)",
        "  }",
        "}",
    ])

    pdf.h2("Questions rapides dynamiques (GitHub)")
    pdf.body(
        "Les 3 questions proposees apres le scan sont generees dynamiquement selon les "
        "resultats reels, et non fixes. Exemples :"
    )
    quick_q = [
        ("Secrets detectes",    "Comment revoquer ces tokens immediatement ?"),
        ("CVE dans deps",       "Quelles dependances mettre a jour en priorite ?"),
        ("Bandit HIGH",         "Comment corriger ces vulnerabilites Python ?"),
        ("Score parfait",       "Quelles bonnes pratiques maintenir ?"),
        ("Bandit/Safety N/A",   "npm audit : que font ces paquets vulnerables ?"),
    ]
    for trigger, question in quick_q:
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(45, 5, f"[{trigger}]")
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(0, 5, question, ln=True)
    pdf.ln(3)

    # ── 8. GIT ────────────────────────────────────────────────────────────────
    pdf.h1("8. Configuration Git - Deux depots separes")

    pdf.h2("Structure retenue : 2 depots independants")
    pdf.body(
        "Le projet CyberGuardian est divise en deux depots GitHub independants pour "
        "faciliter le deploiement separe (backend sur Ubuntu, frontend sur Vercel/Netlify). "
        "Chaque depot a son propre .gitignore et .gitattributes."
    )
    pdf.ln(2)

    pdf.h2("Depot 1 : cyberguardian-backend", GREEN)
    pdf.bullet("URL : github.com/rootIbrahima/cyberguardian-backend")
    pdf.bullet("Statut : POUSSE (git push -u origin main OK)")
    pdf.bullet("Contenu : FastAPI, tools/, routers/, requirements.txt")
    pdf.code_block([
        "# Commandes executees",
        "cd backend",
        "git init && git add . && git commit -m 'Initial commit'",
        "git remote add origin https://github.com/rootIbrahima/cyberguardian-backend.git",
        "git push -u origin main",
    ])
    pdf.ln(2)

    pdf.h2("Depot 2 : cyberguardian-frontend", ORANGE)
    pdf.bullet("URL : a creer sur github.com/new -> cyberguardian-frontend")
    pdf.bullet("Statut : EN ATTENTE (depot GitHub pas encore cree)")
    pdf.code_block([
        "# Apres creation du depot sur github.com/new :",
        "cd frontend",
        "git remote set-url origin https://github.com/rootIbrahima/cyberguardian-frontend.git",
        "git push -u origin main",
    ])
    pdf.ln(2)

    pdf.h2("Fichiers de configuration Git crees")
    git_files = [
        ("backend/.gitignore",
         "__pycache__, *.py[cod], .venv, venv, env\n"
         "data/scans.json  (donnees utilisateur non committees)\n"
         "cg_gh_*/, cg_bandit_*/, cg_truffle_*/  (clones temporaires)\n"
         "*.pdf  (rapports generes localement)\n"
         ".env, .env.*, *.key, *.pem  (secrets)"),
        ("frontend/.gitignore",
         "node_modules/  (dependances npm)\n"
         "dist/  (build de production)\n"
         ".env, .env.local, .env.*.local  (variables d'environnement)\n"
         "*.tsbuildinfo, .vite/  (cache de build)"),
        ("backend/.gitattributes",
         "* text=auto eol=lf\n"
         "Supprime les warnings 'LF will be replaced by CRLF' sur Windows"),
        ("frontend/.gitattributes",
         "* text=auto eol=lf\n"
         "Meme configuration que le backend"),
    ]
    for fname, content in git_files:
        pdf.set_x(14)
        pdf.set_font("Courier", "B", 8)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(0, 6, fname, ln=True)
        pdf.set_x(20)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_MID)
        pdf.multi_cell(178, 4.5, content)
        pdf.ln(2)

    # ── 9. UBUNTU ─────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("9. Deploiement Ubuntu - Outils natifs (DERNIER MESSAGE DE SESSION)")

    pdf.set_fill_color(255, 237, 213)
    pdf.rect(12, pdf.get_y(), 186, 10, "F")
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(180, 70, 0)
    pdf.set_xy(15, pdf.get_y() + 2)
    pdf.cell(0, 6, "NOTE IMPORTANTE : Certains outils MCP necessitent Ubuntu pour fonctionner correctement", ln=True)
    pdf.ln(4)

    pdf.h2("Pourquoi Ubuntu ?")
    pdf.body(
        "Sur Windows, certains outils de securite ne sont pas disponibles en natif ou "
        "fonctionnent de maniere degradee. Le deploiement du backend sur Ubuntu 22.04+ "
        "permet d'utiliser les vrais binaires avec leurs capacites completes."
    )

    pdf.h2("TruffleHog - Detection de secrets (differences majeures)")

    pdf.set_x(14)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*RED)
    pdf.cell(90, 6, "Version Windows (actuelle)")
    pdf.set_text_color(*GREEN)
    pdf.cell(0, 6, "Version Ubuntu (a deployer)", ln=True)

    tf_diff = [
        ("Regex Python maison",            "Binaire trufflehog officiel (Go)"),
        ("~10 patterns hardcodes",          "700+ patterns (entropie Shannon + regex)"),
        ("Pas de detection d'entropie",     "Analyse entropie sur tokens/cles"),
        ("Faux negatifs probables",         "Detection des secrets git effacÿs"),
        ("Faux positifs possibles",         "Moins de faux positifs (contexte git)"),
        ("subprocess regex sur fichiers",   "trufflehog git file://{tmpdir} --json"),
    ]
    for old, new in tf_diff:
        pdf.set_x(14)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*RED)
        pdf.cell(90, 5, f"- {old}")
        pdf.set_text_color(*GREEN)
        pdf.cell(0, 5, f"+ {new}", ln=True)
    pdf.ln(3)

    pdf.h2("Installation sur Ubuntu 22.04+")
    pdf.code_block([
        "# TruffleHog (binaire officiel Go)",
        "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \\",
        "  | sh -s -- -b /usr/local/bin",
        "trufflehog --version  # verification",
        "",
        "# Semgrep (analyse statique multi-langage)",
        "pip install semgrep",
        "semgrep --version",
        "",
        "# nmap (scan de ports, detaille)",
        "sudo apt install nmap -y",
        "nmap --version",
        "",
        "# nikto (scan web - detecte misconfigs HTTP)",
        "sudo apt install nikto -y",
        "nikto -Version",
    ])
    pdf.ln(2)

    pdf.h2("Adaptation de github_tools.py pour Ubuntu")
    pdf.code_block([
        "# Remplacer _run_trufflehog() par :",
        "def _run_trufflehog(tmpdir: str) -> dict:",
        "    r = subprocess.run(",
        "        ['trufflehog', 'git', f'file://{tmpdir}', '--json', '--no-update'],",
        "        capture_output=True, text=True, timeout=120",
        "    )",
        "    findings = [json.loads(line) for line in r.stdout.strip().splitlines()]",
        "    return {'findings': findings}",
        "",
        "# Ajout de scan_semgrep() pour Go, Rust, Java, PHP",
        "def _run_semgrep(tmpdir: str, language: str) -> dict:",
        "    r = subprocess.run(",
        "        ['semgrep', '--config', 'auto', tmpdir, '--json'],",
        "        capture_output=True, text=True, timeout=180",
        "    )",
        "    ...",
    ])
    pdf.ln(2)

    pdf.h2("Outils MCP additionnels disponibles sur Ubuntu")
    ubuntu_tools = [
        ("nmap",      "scan_ports()",    "Scan TCP/UDP, detection services, version OS",             TEAL),
        ("nikto",     "scan_web()",      "Detection misconfigs HTTP, fichiers sensibles, headers",   BLUE_MED),
        ("semgrep",   "scan_semgrep()",  "Analyse statique multi-langage (Go, Java, PHP, Ruby...)",  PURPLE),
        ("masscan",   "scan_ports()",    "Scan de ports tres rapide pour grands reseaux",             ORANGE),
        ("whatweb",   "scan_tech()",     "Detection de technologie web (CMS, framework, version)",   GREEN),
    ]
    for binary, func, desc, color in ubuntu_tools:
        pdf.set_x(16)
        pdf.set_fill_color(*color)
        pdf.set_font("Courier", "B", 8)
        pdf.set_text_color(*WHITE)
        self_x = pdf.get_x()
        pdf.cell(20, 6, f" {binary} ", fill=True)
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(30, 6, func)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(0, 6, desc, ln=True)
    pdf.ln(3)

    pdf.h2("Prochaines etapes pour Ubuntu")
    pdf.bullet("Cloner cyberguardian-backend sur le serveur Ubuntu")
    pdf.bullet("python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt")
    pdf.bullet("Installer les binaires natifs : trufflehog, semgrep, nmap, nikto")
    pdf.bullet("Remplacer _run_trufflehog() par la version binaire officielle")
    pdf.bullet("Ajouter _run_semgrep() pour les projets non-Python/JS")
    pdf.bullet("Configurer uvicorn en tant que service systemd pour demarrage automatique")

    # ── 10. PROBLEMES RESOLUS ─────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("10. Problemes rencontres et solutions")

    issues = [
        (
            "bandit introuvable comme commande sur Windows",
            "subprocess.run(['bandit', '-r', tmpdir, ...]) echouait avec FileNotFoundError "
            "car 'bandit' n'est pas dans le PATH systeme de Windows meme apres pip install.",
            "Remplace par [sys.executable, '-m', 'bandit', ...]. Python trouve toujours "
            "son propre executable et -m charge le module bandit installe dans le venv.",
        ),
        (
            "Langue affichait 'inconnu' ou 'N/A'",
            "L'API GitHub retourne null pour certains repos (ex: repo sans extension .py visible). "
            "github_info() convertissait None en 'N/A', et le frontend affichait ce 'N/A'.",
            "Dans scan_github() : api_lang = info.get('language') or ''; if api_lang == 'N/A': api_lang = ''. "
            "Puis fallback _detect_language_from_files(tmpdir) sur le clone local. "
            "Frontend : results.langage || info.language || '-' en cascade.",
        ),
        (
            "IA disait 'posture critique 30/100' pour un score GitHub",
            "ask_ai() et _generate_simple_explanation() avaient score_max code en dur a 100. "
            "Le contexte IA recevait donc '30/100' au lieu de '30/30'.",
            "Lecture dynamique : score_max = results.get('score_max', 30). "
            "Construction de score_label avec ce score_max. "
            "Score parfait genere un message positif ('excellent, aucune faille') au lieu d'une alerte.",
        ),
        (
            "Rapport automatique affichait du contenu SSL pour un scan GitHub",
            "Le 'Rapport automatique' frontend n'avait pas de branche pour isGithub. "
            "La logique par defaut cherchait ssl.grade et n'en trouvait pas -> 'Aucune donnee SSL'.",
            "Ajout d'un if (isGithub) { ... } complet avec lecture de secrets/CVE/Bandit. "
            "Score parfait -> message positif. Sinon -> liste des vrais problemes detectes.",
        ),
        (
            "git push frontend echoue : 'Repository not found'",
            "Le depot cyberguardian-frontend n'existait pas encore sur GitHub au moment du push. "
            "Le remote pointait vers une URL inexistante.",
            "Creer d'abord le depot vide sur github.com/new, SANS initialiser avec README. "
            "Ensuite : git remote set-url origin <url> && git push -u origin main.",
        ),
        (
            "Warnings 'LF will be replaced by CRLF' sur git add (Windows)",
            "Git sur Windows convertit automatiquement les fins de ligne LF -> CRLF "
            "et affiche des avertissements pour chaque fichier au moment du git add.",
            "Ajout de .gitattributes : '* text=auto eol=lf' dans les deux depots. "
            "Force LF dans le depot git, quelle que soit la plateforme.",
        ),
        (
            "git commit echoue : 'Please tell me who you are'",
            "Git n'avait pas d'identite configuree dans le repo cree. "
            "Premiere utilisation de git sur cette machine.",
            "git config --global user.email 'xxx@xxx.com' && git config --global user.name 'xxx'. "
            "L'option --global evite de repeter la configuration pour chaque repo.",
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
        pdf.cell(22, 4, "Probleme :")
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(39)
        pdf.multi_cell(159, 4, problem)
        pdf.set_x(16)
        pdf.set_font("Helvetica", "B", 7.5)
        pdf.set_text_color(*GREEN)
        pdf.cell(22, 4, "Solution :")
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_DARK)
        pdf.set_x(39)
        pdf.multi_cell(159, 4, solution)
        pdf.ln(4)

    # ── 11. ETAT ACTUEL ───────────────────────────────────────────────────────
    pdf.add_page()
    pdf.h1("11. Etat actuel du projet")

    pdf.h2("Fonctionnalites operationnelles", GREEN)
    done = [
        "Scan SSL/TLS avec score /25, grade, detection expiration/auto-signe",
        "Detection CVE : mapping TLS + API NVD via banniere HTTP",
        "Chat IA en streaming (llama3:latest, Ollama distant)",
        "Rapport PDF avec explication IA en francais simple",
        "Page liste scans + navigation intelligente sidebar",
        "Scan GitHub : github_info + Bandit + Safety + TruffleHog + npm audit",
        "Detection automatique du langage (API GitHub + fallback fichiers)",
        "Selection d'outils selon le langage (Python vs JS/TS vs autre)",
        "Score GitHub /30 avec deductions selon severite",
        "Rapport IA GitHub avec score_max dynamique et message score parfait",
        "Rapport automatique frontend avec branche GitHub (secrets/CVE/Bandit)",
        "Questions rapides dynamiques selon les vrais resultats GitHub",
        "NaState (boite bleue) pour outils non applicables au langage",
        "Backend pousse sur GitHub (cyberguardian-backend)",
        "Git configure : .gitignore + .gitattributes sur les deux depots",
    ]
    for item in done:
        pdf.check(item)
    pdf.ln(3)

    pdf.h2("En attente / Prochaines etapes", ORANGE)
    pending = [
        "Creer le depot cyberguardian-frontend sur GitHub et pousser",
        "Deployer le backend sur Ubuntu : cloner, venv, pip install",
        "Installer TruffleHog binaire officiel et adapter github_tools.py",
        "Installer Semgrep pour analyse multi-langage (Go, Java, Ruby, PHP)",
        "Implementer check_dns() : SPF, DMARC, DKIM, MX - score /25",
        "Implementer scan_ports() avec nmap (Ubuntu) ou socket Python (Windows)",
        "Implementer scan_headers() : HSTS, CSP, X-Frame-Options, Referrer",
        "Implementer check_whois() : registrar, expiration domaine",
        "Implementer scan_virustotal() : reputation, listes noires (cle API requise)",
        "Configurer uvicorn comme service systemd sur Ubuntu",
    ]
    for item in pending:
        pdf.warn(item)

    pdf.ln(4)
    pdf.h2("Architecture MCP - Etat des 12 outils")
    groups = {
        "EASM (domain / ip / url)": [
            ("check_ssl()",       "SSL/TLS - score /25",                        "IMPLEMENTE", GREEN),
            ("check_cve()",       "CVE via TLS + banniere + API NVD",           "IMPLEMENTE", GREEN),
            ("check_dns()",       "SPF, DMARC, DKIM, MX",                       "EN ATTENTE", ORANGE),
            ("check_whois()",     "Registrar, expiration domaine",              "EN ATTENTE", ORANGE),
            ("scan_headers()",    "HSTS, CSP, X-Frame-Options",                 "EN ATTENTE", ORANGE),
            ("scan_ports()",      "Ports ouverts, services exposes",            "EN ATTENTE", ORANGE),
            ("scan_virustotal()", "Reputation, listes noires",                  "EN ATTENTE", ORANGE),
        ],
        "GitHub (score /30)": [
            ("github_info()",     "Metadonnees, visibilite, contributeurs",     "IMPLEMENTE", GREEN),
            ("scan_bandit()",     "Analyse statique Python",                    "IMPLEMENTE", GREEN),
            ("scan_safety()",     "CVE dependances Python (OSV.dev)",           "IMPLEMENTE", GREEN),
            ("scan_trufflehog()", "Secrets exposes (regex / binaire Ubuntu)",   "PARTIEL",    ORANGE),
            ("npm_audit()",       "CVE dependances JS/TS",                      "IMPLEMENTE", GREEN),
        ],
        "Score & Rapport": [
            ("calculate_score()", "Score pondere /100 (EASM) + /30 (GitHub)",  "IMPLEMENTE", GREEN),
            ("generate_report()", "PDF avec explication IA en francais",        "IMPLEMENTE", GREEN),
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

    output_path = "recap_session3_cyberguardian.pdf"
    pdf.output(output_path)
    print(f"PDF genere : {output_path}")


if __name__ == "__main__":
    generate()

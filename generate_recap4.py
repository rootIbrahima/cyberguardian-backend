"""
Recap Session 4 - Base de donnees PostgreSQL + Auth JWT + Frontend
Usage : python generate_recap4.py
"""
from fpdf import FPDF
from datetime import datetime
import unicodedata


def _a(t):
    if not t: return ""
    t = str(t)
    for s, d in [("—","-"),("–","-"),("·","|"),("'","'"),("'","'"),
                 (""",'"'),  (""",'"'), ("«",'"'), ("»",'"'), ("…","..."),
                 ("•","-"), ("→","->"), ("✓","OK"), ("**",""), ("*","")]:
        t = t.replace(s, d)
    return unicodedata.normalize("NFKD", t).encode("ascii","ignore").decode("ascii")


BLUE_DARK  = (15,  41,  77)
BLUE_MED   = (31,  92, 153)
BLUE_LIGHT = (232, 241, 250)
GREEN      = (16, 185, 129)
GREEN_DARK = (5,  150,  80)
ORANGE     = (245, 158, 11)
RED        = (239,  68,  68)
PURPLE     = (109,  40, 217)
GRAY_DARK  = (17,  24,  39)
GRAY_MID   = (107, 114, 128)
GRAY_LIGHT = (229, 231, 235)
WHITE      = (255, 255, 255)
YELLOW     = (253, 224,  71)
TEAL       = (20, 184, 166)
PG_BLUE    = (51,  103, 145)


class RecapPDF(FPDF):

    def header(self):
        self.set_fill_color(*BLUE_DARK)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(*WHITE)
        self.set_xy(10, 5)
        self.cell(140, 10, "CyberGuardian  |  Recapitulatif Session 4", ln=False)
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
        self.cell(0, 8, _a(f"  {title}"), ln=True, fill=True)
        self.ln(3)

    def h2(self, title, color=None):
        self.ln(1)
        c = color or BLUE_MED
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*c)
        self.set_x(10)
        self.cell(0, 6, _a(title), ln=True)
        self.set_draw_color(*GRAY_LIGHT)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(2)

    def body(self, text, indent=12):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_DARK)
        self.set_x(indent)
        self.multi_cell(210 - indent - 10, 5, _a(text))

    def bullet(self, text, indent=15, color=None):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*(color or GRAY_DARK))
        self.set_x(indent)
        self.cell(4, 5.5, "-")
        self.set_x(indent + 4)
        self.multi_cell(210 - indent - 14, 5.5, _a(text))

    def kv(self, key, value, key_w=55, vcolor=None):
        self.set_font("Helvetica", "", 8.5)
        self.set_text_color(*GRAY_MID)
        self.set_x(14)
        self.cell(key_w, 5.5, _a(key))
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*(vcolor or GRAY_DARK))
        self.cell(0, 5.5, _a(value), ln=True)

    def code(self, lines, comment_color=None):
        self.ln(1)
        x, w = 10, 190
        y = self.get_y()
        content = "\n".join(_a(l) for l in lines) if isinstance(lines, list) else _a(lines)
        n = content.count("\n") + 1
        h = n * 5 + 7
        self.set_fill_color(22, 27, 34)
        self.rect(x, y, w, h, "F")
        self.set_font("Courier", "", 8)
        self.set_xy(x + 4, y + 3.5)
        for line in (lines if isinstance(lines, list) else lines.split("\n")):
            la = _a(line)
            if la.startswith("--") or la.startswith("#"):
                self.set_text_color(134, 153, 180)
            else:
                self.set_text_color(126, 231, 135)
            self.set_x(x + 4)
            self.cell(0, 5, la, ln=True)
        self.ln(3)

    def sql(self, lines):
        self.ln(1)
        x, w = 10, 190
        y = self.get_y()
        content_lines = lines if isinstance(lines, list) else lines.split("\n")
        h = len(content_lines) * 5 + 7
        self.set_fill_color(15, 30, 50)
        self.rect(x, y, w, h, "F")
        # Barre titre SQL
        self.set_fill_color(*PG_BLUE)
        self.rect(x, y, w, 6, "F")
        self.set_font("Helvetica", "B", 7)
        self.set_text_color(*WHITE)
        self.set_xy(x + 4, y + 0.5)
        self.cell(0, 5, "PostgreSQL")
        self.set_xy(x + 4, y + 7)
        for line in content_lines:
            la = _a(line)
            if la.strip().startswith("--"):
                self.set_text_color(100, 140, 180)
                self.set_font("Courier", "I", 8)
            elif any(la.upper().strip().startswith(kw) for kw in
                     ("SELECT","INSERT","UPDATE","DELETE","CREATE","DROP","ALTER","GRANT","\\","WITH")):
                self.set_text_color(130, 200, 255)
                self.set_font("Courier", "B", 8)
            else:
                self.set_text_color(190, 220, 255)
                self.set_font("Courier", "", 8)
            self.set_x(x + 4)
            self.cell(0, 5, la, ln=True)
        self.ln(3)

    def badge(self, text, bg, fg=None):
        self.set_fill_color(*bg)
        self.set_text_color(*(fg or WHITE))
        self.set_font("Helvetica", "B", 7.5)
        tw = self.get_string_width(_a(text)) + 6
        self.cell(tw, 5.5, _a(text), fill=True)

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
        self.set_xy(x + 6, y + 4)
        self.multi_cell(w - 10, 5.5, t)
        self.ln(2)

    def schema_table(self, title, columns, color):
        self.ln(1)
        x, w = 14, 182
        y = self.get_y()
        # En-tete
        self.set_fill_color(*color)
        self.rect(x, y, w, 7, "F")
        self.set_font("Helvetica", "B", 8.5)
        self.set_text_color(*WHITE)
        self.set_xy(x + 4, y + 1)
        self.cell(0, 5, _a(title), ln=True)
        # Colonnes
        row_h = 6
        for i, (col, typ, note) in enumerate(columns):
            row_y = self.get_y()
            bg = (248, 250, 252) if i % 2 == 0 else WHITE
            self.set_fill_color(*bg)
            self.rect(x, row_y, w, row_h, "F")
            self.set_font("Courier", "B" if col in ("id","email","target") else "", 8)
            self.set_text_color(*PURPLE)
            self.set_xy(x + 4, row_y + 0.5)
            self.cell(45, row_h - 1, _a(col))
            self.set_font("Courier", "", 8)
            self.set_text_color(*TEAL)
            self.cell(42, row_h - 1, _a(typ))
            self.set_font("Helvetica", "", 8)
            self.set_text_color(*GRAY_MID)
            self.cell(0, row_h - 1, _a(note), ln=True)
        # Bordure
        self.set_draw_color(*GRAY_LIGHT)
        self.rect(x, y, w, self.get_y() - y, "D")
        self.ln(4)


# ── Contenu ───────────────────────────────────────────────────────────────────

def build():
    pdf = RecapPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ══ PAGE 1 — Couverture ══════════════════════════════════════════════════
    pdf.add_page()

    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*BLUE_MED)
    pdf.set_x(10)
    pdf.cell(0, 12, _a("Session 4 - Base de donnees & Auth"), ln=True, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*GRAY_MID)
    pdf.cell(0, 7, "CyberGuardian EASM Platform", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, _a(f"Genere le {datetime.now().strftime('%d %B %Y')}"), ln=True, align="C")
    pdf.ln(5)

    # Bandeau statut
    pdf.set_fill_color(*BLUE_LIGHT)
    pdf.rect(10, pdf.get_y(), 190, 26, "F")
    pdf.set_xy(14, pdf.get_y() + 3)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(*BLUE_MED)
    pdf.cell(0, 6, "Ce qui a ete realise dans cette session", ln=True)
    pdf.set_x(14)
    items = [
        ("Remplacement du fichier JSON par PostgreSQL",           GREEN),
        ("Creation des tables users + scans avec SQLAlchemy ORM", GREEN),
        ("Systeme d'authentification JWT (login / register)",     GREEN),
        ("Page d'inscription publique sur le frontend",           GREEN),
        ("Script seed.py pour initialiser les comptes",           GREEN),
        ("Email pre-rempli supprime sur la page login",           GREEN),
    ]
    for text, color in items:
        pdf.set_font("Helvetica", "", 8.5)
        pdf.set_text_color(*color)
        pdf.set_x(14)
        pdf.cell(4, 5.5, "-")
        pdf.cell(0, 5.5, _a(text), ln=True)
    pdf.ln(4)

    # ══ SECTION 1 — Avant / Apres ════════════════════════════════════════════
    pdf.h1("1. Avant / Apres — Ce qui a change")

    headers = ["Aspect", "Avant (JSON)", "Apres (PostgreSQL)"]
    rows = [
        ("Stockage scans",     "data/scans.json",           "Table scans (PostgreSQL)"),
        ("Stockage users",     "ROLE_MAP code en dur",       "Table users (hashes)"),
        ("Authentification",   "Fallback localStorage",      "JWT signe + verifie en base"),
        ("Isolation donnees",  "Tout le monde voit tout",    "Chaque user voit ses scans"),
        ("Email login",        "ibrahima.ly@ec2lt.sn fixe",  "Champ vide, saisie libre"),
        ("Inscription",        "Impossible",                 "Page /register publique"),
        ("Mot de passe",       "Aucun (pas de BDD)",         "Hash sha256_crypt"),
        ("Persistance",        "Perte si fichier corrompu",  "Transactions ACID"),
    ]
    col_w = [46, 66, 66]
    x = 10
    # En-tete tableau
    pdf.set_fill_color(*BLUE_MED)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_x(x)
    for i, h in enumerate(headers):
        pdf.cell(col_w[i], 7, _a(h), border=1, fill=True)
    pdf.ln()
    # Lignes
    for j, row in enumerate(rows):
        bg = (248, 250, 252) if j % 2 == 0 else WHITE
        pdf.set_fill_color(*bg)
        pdf.set_x(x)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(col_w[0], 6, _a(row[0]), border=1, fill=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*RED)
        pdf.cell(col_w[1], 6, _a(row[1]), border=1, fill=True)
        pdf.set_text_color(*GREEN_DARK)
        pdf.cell(col_w[2], 6, _a(row[2]), border=1, fill=True)
        pdf.ln()
    pdf.ln(4)

    # ══ SECTION 2 — Fichiers crees ═══════════════════════════════════════════
    pdf.h1("2. Fichiers crees / modifies")

    files = [
        ("CREE",    "backend/database.py",                   "Connexion PostgreSQL via SQLAlchemy, session get_db()"),
        ("CREE",    "backend/models.py",                     "Modeles ORM : User + Scan avec methode to_dict()"),
        ("CREE",    "backend/auth.py",                       "JWT (jose), hash sha256_crypt, dependencies FastAPI"),
        ("CREE",    "backend/routers/auth.py",               "POST /auth/token  POST /auth/register  GET /auth/me"),
        ("CREE",    "backend/seed.py",                       "Initialise les 3 comptes par defaut"),
        ("MODIFIE", "backend/routers/scans.py",              "Remplace _load()/_save() JSON par Session SQLAlchemy"),
        ("MODIFIE", "backend/main.py",                       "Ajoute router auth + Base.metadata.create_all()"),
        ("MODIFIE", "backend/requirements.txt",              "Ajout : sqlalchemy, psycopg2-binary, jose, passlib"),
        ("MODIFIE", "backend/database.py",                   "DATABASE_URL pointe vers PostgreSQL"),
        ("CREE",    "frontend/src/pages/RegisterPage.jsx",   "Page inscription publique (/register)"),
        ("MODIFIE", "frontend/src/pages/LoginPage.jsx",      "Email vide + bouton -> /register"),
        ("MODIFIE", "frontend/src/lib/api.js",               "authAPI.register() + changePassword()"),
        ("MODIFIE", "frontend/src/App.jsx",                  "Route publique /register"),
    ]
    for status, path, desc in files:
        pdf.set_x(12)
        c = GREEN_DARK if status == "CREE" else ORANGE
        pdf.set_fill_color(*c)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", "B", 7)
        tw = pdf.get_string_width(status) + 4
        pdf.cell(tw, 5, _a(status), fill=True)
        pdf.set_font("Courier", "", 8.5)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(78, 5, _a(f"  {path}"))
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_MID)
        pdf.cell(0, 5, _a(desc), ln=True)
    pdf.ln(3)

    # ══ PAGE 2 — Schema BDD ══════════════════════════════════════════════════
    pdf.add_page()
    pdf.h1("3. Schema de la base de donnees PostgreSQL")

    pdf.body("Deux tables principales gerees par SQLAlchemy ORM. La colonne results et issues "
             "sont stockees en JSON natif (PostgreSQL JSONB en production).")
    pdf.ln(3)

    pdf.schema_table("TABLE  users", [
        ("id",            "INTEGER",  "Cle primaire auto-incrementee"),
        ("email",         "VARCHAR",  "Unique, indexe — sert d'identifiant de connexion"),
        ("name",          "VARCHAR",  "Nom affiche dans l'interface"),
        ("password_hash", "VARCHAR",  "Hash sha256_crypt (jamais le mot de passe en clair)"),
        ("role",          "VARCHAR",  "client | expert | admin"),
        ("is_active",     "BOOLEAN",  "False = compte desactive (bannissement admin)"),
        ("created_at",    "VARCHAR",  "ISO 8601 UTC"),
    ], PG_BLUE)

    pdf.schema_table("TABLE  scans", [
        ("id",             "INTEGER", "Cle primaire auto-incrementee"),
        ("user_id",        "INTEGER", "FK -> users.id  (NULL si scan anonyme)"),
        ("target",         "VARCHAR", "Domaine, IP, URL ou lien GitHub"),
        ("type",           "VARCHAR", "domain | ip | url | github"),
        ("type_label",     "VARCHAR", "Domaine | IP | URL | GitHub"),
        ("score",          "INTEGER", "Score calcule (/100 EASM ou /30 GitHub)"),
        ("status",         "VARCHAR", "completed | running | critical"),
        ("vulns",          "INTEGER", "Nombre de problemes detectes"),
        ("cve",            "INTEGER", "Nombre de CVE identifiees"),
        ("date",           "VARCHAR", "Date lisible en francais"),
        ("results",        "JSON",    "Resultats bruts des outils MCP (ssl, bandit, etc.)"),
        ("issues",         "JSON",    "Liste des problemes formates pour l'affichage"),
        ("conversations",  "JSON",    "Historique des questions IA pour ce scan"),
    ], (50, 120, 80))

    pdf.h2("Relation entre les tables", GRAY_MID)
    pdf.code([
        "users (1) ----< scans (N)",
        "  Un utilisateur peut avoir plusieurs scans",
        "  Un scan appartient a un seul utilisateur (ou aucun si anonyme)",
        "",
        "# Acces selon le role :",
        "#   client  -> SELECT * FROM scans WHERE user_id = mon_id",
        "#   admin   -> SELECT * FROM scans  (tous les scans)",
        "#   expert  -> SELECT * FROM scans WHERE user_id = mon_id",
    ])

    # ══ SECTION 4 — Auth JWT ════════════════════════════════════════════════
    pdf.h1("4. Fonctionnement de l'authentification JWT")

    pdf.body("Chaque requete authentifiee envoie un token Bearer dans le header HTTP. "
             "Le backend le decode, verifie la signature et retrouve l'utilisateur en base.")
    pdf.ln(2)

    steps = [
        ("1", "Login",        "POST /auth/token", "email + password (form)",          "access_token JWT + user info"),
        ("2", "Inscription",  "POST /auth/register", "email + name + password + role", "access_token JWT + user info"),
        ("3", "Profil",       "GET /auth/me",      "Authorization: Bearer <token>",    "id, email, name, role"),
        ("4", "Scan",         "POST /scans",       "Authorization: Bearer <token>",    "scan associe au user_id"),
        ("5", "Liste scans",  "GET /scans",        "Authorization: Bearer <token>",    "scans filtres par user_id"),
    ]
    x = 10
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(*BLUE_MED)
    pdf.set_text_color(*WHITE)
    for lbl, w in [("#",8),("Action",28),("Endpoint",42),("Entree",52),("Sortie",50)]:
        pdf.cell(w, 6, lbl, border=1, fill=True)
    pdf.ln()
    for j, (num, action, endpoint, inp, out) in enumerate(steps):
        bg = (248, 250, 252) if j % 2 == 0 else WHITE
        pdf.set_fill_color(*bg)
        pdf.set_font("Helvetica", "B", 8)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(8, 6, num, border=1, fill=True)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(28, 6, _a(action), border=1, fill=True)
        pdf.set_font("Courier", "", 7.5)
        pdf.set_text_color(*GREEN_DARK)
        pdf.cell(42, 6, _a(endpoint), border=1, fill=True)
        pdf.set_font("Helvetica", "", 7.5)
        pdf.set_text_color(*GRAY_MID)
        pdf.cell(52, 6, _a(inp), border=1, fill=True)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(50, 6, _a(out), border=1, fill=True)
        pdf.ln()
    pdf.ln(3)

    pdf.info_box(
        "Structure du token JWT decode :\n"
        "  { sub: '3',  role: 'client',  name: 'Ibrahima LY',  exp: 1748... }\n"
        "  sub = user_id en base  |  expire apres 7 jours  |  signe avec SECRET_KEY"
    )

    # ══ PAGE 3 — Commandes PostgreSQL ════════════════════════════════════════
    pdf.add_page()
    pdf.h1("5. Commandes PostgreSQL essentielles")

    pdf.h2("5.1  Se connecter a la base", PG_BLUE)
    pdf.sql([
        "-- Via psql (terminal)",
        "psql -U cguser -d cyberguardian",
        "",
        "-- Via pgAdmin 4 : clic droit sur 'cyberguardian' -> Query Tool",
        "",
        "-- Se connecter a la base une fois dans psql",
        "\\c cyberguardian",
    ])

    pdf.h2("5.2  Explorer la structure", PG_BLUE)
    pdf.sql([
        "-- Lister les tables",
        "\\dt",
        "",
        "-- Voir la structure d'une table",
        "\\d users",
        "\\d scans",
        "",
        "-- Voir toutes les colonnes avec types",
        "SELECT column_name, data_type FROM information_schema.columns",
        "WHERE table_name = 'scans';",
    ])

    pdf.h2("5.3  Lire les donnees", PG_BLUE)
    pdf.sql([
        "-- Tous les utilisateurs",
        "SELECT id, email, role, is_active, created_at FROM users;",
        "",
        "-- Les 10 derniers scans",
        "SELECT id, target, type, score, status, date FROM scans",
        "ORDER BY id DESC LIMIT 10;",
        "",
        "-- Scans d'un utilisateur specifique",
        "SELECT s.id, s.target, s.score, s.date",
        "FROM scans s JOIN users u ON s.user_id = u.id",
        "WHERE u.email = 'ibrahima.ly@ec2lt.sn';",
        "",
        "-- Comptage des scans par utilisateur",
        "SELECT u.email, u.role, COUNT(s.id) AS nb_scans",
        "FROM users u LEFT JOIN scans s ON s.user_id = u.id",
        "GROUP BY u.id ORDER BY nb_scans DESC;",
    ])

    pdf.h2("5.4  Modifier des donnees", PG_BLUE)
    pdf.sql([
        "-- Changer le role d'un utilisateur",
        "UPDATE users SET role = 'expert' WHERE email = 'test@test.sn';",
        "",
        "-- Desactiver un compte",
        "UPDATE users SET is_active = FALSE WHERE id = 5;",
        "",
        "-- Supprimer un scan",
        "DELETE FROM scans WHERE id = 3;",
        "",
        "-- Supprimer tous les scans d'un user",
        "DELETE FROM scans WHERE user_id = 2;",
    ])

    pdf.h2("5.5  Analyses utiles", PG_BLUE)
    pdf.sql([
        "-- Score moyen par type de scan",
        "SELECT type, ROUND(AVG(score), 1) AS score_moyen, COUNT(*) AS nb",
        "FROM scans GROUP BY type;",
        "",
        "-- Scans avec CVE detectees",
        "SELECT target, type, score, cve, date FROM scans",
        "WHERE cve > 0 ORDER BY cve DESC;",
        "",
        "-- Voir les conversations IA d'un scan (JSON)",
        "SELECT id, target, jsonb_array_length(conversations::jsonb) AS nb_questions",
        "FROM scans WHERE conversations != '[]';",
        "",
        "-- Taille de la base",
        "SELECT pg_size_pretty(pg_database_size('cyberguardian'));",
    ])

    pdf.h2("5.6  Maintenance", PG_BLUE)
    pdf.sql([
        "-- Sauvegarder la base",
        "pg_dump -U cguser cyberguardian > backup_$(date +%Y%m%d).sql",
        "",
        "-- Restaurer une sauvegarde",
        "psql -U cguser cyberguardian < backup_20260525.sql",
        "",
        "-- Reinitialiser (ATTENTION : supprime tout)",
        "DROP TABLE scans; DROP TABLE users;",
        "-- Puis relancer : python seed.py",
        "",
        "-- Voir les connexions actives",
        "SELECT pid, usename, application_name, state",
        "FROM pg_stat_activity WHERE datname = 'cyberguardian';",
    ])

    # ══ PAGE 4 — Comptes + commandes de lancement ════════════════════════════
    pdf.add_page()
    pdf.h1("6. Comptes par defaut (seed.py)")

    accounts = [
        ("admin@cyberguardian.sn",  "Admin2026!",  "admin",  "Acces total, voit tous les scans"),
        ("expert@cyberguardian.sn", "Expert2026!", "expert", "Voit ses missions et scans"),
        ("ibrahima.ly@ec2lt.sn",    "Client2026!", "client", "Voit uniquement ses propres scans"),
    ]
    role_colors = {"admin": RED, "expert": ORANGE, "client": GREEN_DARK}
    x = 10
    pdf.set_fill_color(*BLUE_MED)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", "B", 8.5)
    for lbl, w in [("Email", 68), ("Mot de passe", 38), ("Role", 22), ("Description", 52)]:
        pdf.cell(w, 7, lbl, border=1, fill=True)
    pdf.ln()
    for j, (email, pwd, role, desc) in enumerate(accounts):
        bg = (248, 250, 252) if j % 2 == 0 else WHITE
        pdf.set_fill_color(*bg)
        pdf.set_font("Courier", "", 8.5)
        pdf.set_text_color(*BLUE_MED)
        pdf.cell(68, 6, email, border=1, fill=True)
        pdf.set_text_color(*GRAY_DARK)
        pdf.cell(38, 6, pwd, border=1, fill=True)
        rc = role_colors.get(role, GRAY_MID)
        pdf.set_text_color(*rc)
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(22, 6, role, border=1, fill=True)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(*GRAY_MID)
        pdf.cell(52, 6, _a(desc), border=1, fill=True)
        pdf.ln()
    pdf.ln(3)

    pdf.info_box(
        "Pour ajouter un nouveau compte via psql (sans seed.py) :\n"
        "  -- Le mot de passe est hache par Python (sha256_crypt), pas via SQL directement.\n"
        "  -- Utiliser l'endpoint POST /auth/register ou relancer seed.py apres modification."
    )

    pdf.h1("7. Commandes de lancement du projet")

    pdf.h2("Initialisation (une seule fois)", GREEN_DARK)
    pdf.code([
        "cd backend",
        "",
        "# Installer les dependances",
        "pip install -r requirements.txt",
        "",
        "# Creer les tables et les comptes par defaut",
        "python seed.py",
    ])

    pdf.h2("Demarrage quotidien", BLUE_MED)
    pdf.code([
        "# Terminal 1 — Backend FastAPI",
        "cd backend",
        "python -m uvicorn main:app --reload --port 8001",
        "# API : http://localhost:8001",
        "# Docs : http://localhost:8001/docs",
        "",
        "# Terminal 2 — Frontend React",
        "cd frontend",
        "npm run dev",
        "# Interface : http://localhost:5173",
    ])

    pdf.h2("Verification que tout fonctionne", GRAY_MID)
    pdf.code([
        "# Test login (doit retourner un access_token)",
        'curl -X POST http://localhost:8001/auth/token \\',
        '     -d "username=admin@cyberguardian.sn&password=Admin2026!"',
        "",
        "# Test liste scans (avec token)",
        'curl http://localhost:8001/scans \\',
        '     -H "Authorization: Bearer <token_ci_dessus>"',
        "",
        "# Docs interactives avec tous les endpoints",
        "# Ouvrir : http://localhost:8001/docs",
    ])

    pdf.ln(2)
    pdf.info_box(
        "Prochaines etapes du projet :\n"
        "  MCP 9  -> check_headers()  : En-tetes HTTP securite (HSTS, CSP, X-Frame-Options)\n"
        "  MCP 10 -> check_dns()      : SPF, DMARC, DNSSEC\n"
        "  MCP 11 -> scan_ports()     : Ports ouverts (nmap)\n"
        "  MCP 12 -> check_whois()    : Expiration domaine, registrar\n"
        "  Refactorisation score EASM : /100 avec ponderation des 4 outils",
        bg=(232, 245, 233), border=(76, 175, 80)
    )

    out = "recap_session4_postgresql.pdf"
    pdf.output(out)
    print(f"[OK] {out}")


if __name__ == "__main__":
    build()

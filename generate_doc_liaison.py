# -*- coding: utf-8 -*-
"""Document explicatif : liaison sécurisée des comptes Telegram (PDF)."""
import os
from fpdf import FPDF

DARK = (15, 41, 77); BLUE = (31, 92, 153); GRAY = (90, 98, 110)
GREEN = (26, 122, 74); ORANGE = (176, 92, 12)
GRAYL = (229, 231, 235); CODE_BG = (245, 246, 250)
BOXBG = (237, 243, 250)
F = "Seg"; FD = r"C:\Windows\Fonts"


class PDF(FPDF):
    def header(self):
        self.set_fill_color(*DARK); self.rect(0, 0, 210, 15, "F")
        self.set_font(F, "B", 10); self.set_text_color(255, 255, 255)
        self.set_xy(10, 4); self.cell(0, 7, "CyberGuardian · Liaison sécurisée Telegram")
        self.set_font(F, "", 8); self.set_text_color(180, 200, 220)
        self.set_xy(0, 5); self.cell(200, 6, "Note technique", align="R"); self.ln(13)

    def footer(self):
        self.set_y(-11); self.set_font(F, "", 7.5); self.set_text_color(*GRAY)
        self.cell(0, 8, f"CyberGuardian · Mémoire de Master EC2LT · Page {self.page_no()}", align="C")

    def h1(self, t, color=BLUE):
        if self.get_y() > 245: self.add_page()
        self.ln(3); y = self.get_y()
        self.set_fill_color(*color); self.rect(10, y + 0.5, 2.5, 5.5, "F")
        self.set_font(F, "B", 12.5); self.set_text_color(*DARK)
        self.set_xy(15, y); self.cell(0, 7, t, ln=True)
        self.set_draw_color(*GRAYL); self.line(10, self.get_y() + 0.5, 200, self.get_y() + 0.5)
        self.ln(3)

    def p(self, t):
        self.set_font(F, "", 10); self.set_text_color(20, 24, 32)
        self.set_x(12); self.multi_cell(186, 5.3, t); self.ln(1)

    def note(self, t, color=GREEN):
        self.set_font(F, "I", 9.3); self.set_text_color(*color); self.set_x(12)
        self.multi_cell(186, 4.8, t); self.ln(1)

    def etape(self, num, titre, corps, fichier):
        if self.get_y() > 250: self.add_page()
        y = self.get_y()
        # pastille numérotée
        self.set_fill_color(*BLUE); self.ellipse(12, y, 7, 7, "F")
        self.set_font(F, "B", 11); self.set_text_color(255, 255, 255)
        self.set_xy(12, y + 0.7); self.cell(7, 6, str(num), align="C")
        # titre + corps
        self.set_font(F, "B", 10.5); self.set_text_color(*DARK)
        self.set_xy(22, y); self.cell(0, 6, titre, ln=True)
        self.set_font(F, "", 9.7); self.set_text_color(30, 34, 42)
        self.set_x(22); self.multi_cell(176, 5, corps)
        self.set_font(F, "I", 8.6); self.set_text_color(*GRAY)
        self.set_x(22); self.cell(0, 5, "Fichier : " + fichier, ln=True)
        self.ln(2.5)

    def kv(self, k, v):
        if self.get_y() > 272: self.add_page()
        self.set_x(12)
        self.set_font(F, "B", 9.6); self.set_text_color(*BLUE)
        self.cell(58, 5.4, k)
        self.set_font(F, "", 9.6); self.set_text_color(20, 24, 32)
        x = self.get_x(); y = self.get_y()
        self.multi_cell(128, 5.4, v)
        self.ln(0.8)


pdf = PDF()
pdf.add_font(F, "", os.path.join(FD, "segoeui.ttf"))
pdf.add_font(F, "B", os.path.join(FD, "segoeuib.ttf"))
pdf.add_font(F, "I", os.path.join(FD, "segoeuii.ttf"))
pdf.set_auto_page_break(auto=True, margin=14)
pdf.add_page()

pdf.set_font(F, "B", 16); pdf.set_text_color(15, 23, 35)
pdf.cell(0, 9, "Liaison sécurisée d'un compte à Telegram", ln=True)
pdf.set_font(F, "", 9.5); pdf.set_text_color(*GRAY)
pdf.multi_cell(0, 5, "Note technique expliquant le mécanisme qui associe un compte de la plateforme "
                     "CyberGuardian au compte Telegram de son propriétaire, de façon vérifiable et sûre.")
pdf.ln(2)

# Problème
pdf.h1("1. Le problème")
pdf.p("Telegram n'expose jamais le numéro de téléphone d'un utilisateur à un bot. Lorsqu'une personne "
      "écrit au bot, l'API ne transmet qu'un identifiant technique : le chat_id (un entier). Dans la "
      "base, un client est identifié par son user_id.")
pdf.p("La question est donc : comment prouver de façon fiable que le chat_id Telegram appartient bien à "
      "un compte précis de la plateforme ? On ne peut pas se fier au numéro (on ne l'a pas), ni demander "
      "à l'utilisateur de taper son email dans Telegram (n'importe qui pourrait taper l'email d'un autre).")

# Solution
pdf.h1("2. La solution : un code à usage unique (preuve de possession)")
pdf.p("Un jeton de liaison à usage unique et expirant, proche du principe de l'association d'appareils "
      "d'OAuth. Seul le propriétaire du compte web peut générer le code ; ce code circule du web vers "
      "Telegram par la main de l'utilisateur, ce qui prouve qu'il contrôle les deux côtés.")

pdf.etape(1, "Génération (côté web, authentifié)",
          "Connecté avec son jeton JWT, le client demande un code. Le backend produit un code aléatoire "
          "CG-XXXXXX, valable 5 minutes, et invalide les anciens codes non utilisés.",
          "services/telegram_liaison.py · generer_code_liaison()")
pdf.etape(2, "Transport par l'utilisateur",
          "Il envoie « /start CG-XXXXXX » au bot (lien profond t.me/MonBot?start=CG-XXXXXX). Le code "
          "passe du web à Telegram physiquement par la personne : c'est ce qui lie les deux identités.",
          "Telegram (lien profond)")
pdf.etape(3, "Vérification et liaison (côté bot)",
          "Telegram pousse le message sur le webhook. Le backend extrait le chat_id et le code, valide "
          "(non utilisé, non expiré, chat_id libre), puis scelle l'association chat_id <-> user_id.",
          "routers/telegram_webhook.py + services/telegram_liaison.py · verifier_code_et_lier()")
pdf.etape(4, "Résolution à chaque message",
          "Ensuite, à chaque message, le bot retrouve le compte à partir du seul chat_id, et ne sert que "
          "les données de ce client.",
          "services/telegram_liaison.py · get_user_par_chat_id()")

# Modèle de données
pdf.h1("3. Le modèle de données")
pdf.p("Deux tables, dans models.py :")
pdf.kv("TelegramCode", "jeton temporaire : code (unique), user_id, expire_at, utilise.")
pdf.kv("TelegramLink", "lien permanent : user_id (unique) <-> chat_id (unique), actif.")
pdf.p("Point clé : les contraintes d'unicité au niveau SQL portent les invariants métier. "
      "user_id unique garantit un seul Telegram par compte ; chat_id unique garantit un seul compte "
      "par Telegram. La base refuse structurellement toute violation, même en cas de bug applicatif.")

# Sécurité
pdf.h1("4. Les garanties de sécurité")
pdf.kv("Code à usage unique", "champ utilise passé à True après liaison ; anciens codes invalidés à "
       "chaque nouvelle génération.")
pdf.kv("Code expirant", "comparaison datetime.utcnow() > expire_at (TTL 5 min) : fenêtre d'attaque minimale.")
pdf.kv("Génération réservée", "route protégée par JWT : il faut être connecté pour obtenir un code.")
pdf.kv("Pas de vol de chat_id", "avant de lier, on vérifie que le chat_id n'est pas déjà rattaché à un "
       "autre compte actif ; sinon, refus.")
pdf.kv("Backend maître", "le bot ne stocke rien de sensible ; token du bot et clé IA dans backend/.env, "
       "jamais dans le code (chargés via config.py).")
pdf.kv("Webhook robuste", "le endpoint renvoie toujours HTTP 200, sinon Telegram ré-émet le message en "
       "boucle (idempotence de la livraison).")

# Fichiers
pdf.h1("5. Les fichiers concernés")
pdf.kv("models.py", "schéma TelegramCode et TelegramLink (contraintes d'unicité).")
pdf.kv("services/telegram_liaison.py", "logique : génération, vérification, résolution, déliaison.")
pdf.kv("routers/telegram_liaison.py", "API REST côté web (génération du code, statut, déliaison).")
pdf.kv("routers/telegram_webhook.py", "réception des messages Telegram, déclenchement de la liaison.")
pdf.kv("config.py", "chargement des secrets (token du bot) depuis .env.")
pdf.kv("frontend/.../SettingsPage.jsx", "interface : génération du code, affichage, détection de la liaison.")

# Synthèse
pdf.h1("6. En une phrase", GREEN)
pdf.p("Le web (authentifié par JWT) émet un jeton à usage unique ; l'utilisateur le transporte vers "
      "Telegram ; le webhook le vérifie et scelle l'association chat_id <-> user_id en base, sous "
      "contraintes d'unicité. À partir de là, le chat_id sert de clé d'identité pour servir au client "
      "uniquement ses propres données.")
pdf.note("Deux questions fréquentes : (1) pourquoi un code et pas le numéro ? Parce que Telegram ne donne "
         "pas le numéro, et qu'un code à usage unique transporté par l'utilisateur est une preuve de "
         "possession des deux comptes. (2) Et si le code est intercepté ? Fenêtre de 5 min, usage unique, "
         "et il faudrait en plus accéder au Telegram de la victime : risque résiduel faible et borné.")

pdf.output("../Note-Liaison-Telegram.pdf")
print("PDF généré : Note-Liaison-Telegram.pdf (racine du projet)")

# -*- coding: utf-8 -*-
"""Étude comparative des canaux de messagerie pour l'agent de support (PDF)."""
import os
from fpdf import FPDF

DARK = (15, 41, 77); BLUE = (31, 92, 153); GRAY = (90, 98, 110)
GREEN = (26, 122, 74); ORANGE = (176, 92, 12)
GRAYL = (229, 231, 235); HEADBG = (231, 238, 246)
F = "Seg"; FD = r"C:\Windows\Fonts"


class PDF(FPDF):
    def header(self):
        self.set_fill_color(*DARK); self.rect(0, 0, 210, 15, "F")
        self.set_font(F, "B", 10); self.set_text_color(255, 255, 255)
        self.set_xy(10, 4); self.cell(0, 7, "CyberGuardian · Choix du canal de messagerie")
        self.set_font(F, "", 8); self.set_text_color(180, 200, 220)
        self.set_xy(0, 5); self.cell(200, 6, "Étude comparative", align="R"); self.ln(13)

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

    def h2(self, t):
        if self.get_y() > 262: self.add_page()
        self.set_font(F, "B", 10.5); self.set_text_color(*BLUE); self.set_x(11)
        self.cell(0, 6, t, ln=True); self.ln(0.5)

    def p(self, t):
        self.set_font(F, "", 10); self.set_text_color(20, 24, 32)
        self.set_x(12); self.multi_cell(186, 5.3, t); self.ln(1)

    def item(self, t, mark=None):
        if self.get_y() > 274: self.add_page()
        self.set_x(13)
        if mark:
            col = GREEN if mark == "+" else ORANGE
            self.set_font(F, "B", 10); self.set_text_color(*col)
            self.cell(5, 5.2, mark)
        else:
            self.set_font(F, "", 10); self.set_text_color(20, 24, 32)
            self.cell(4, 5.2, "·")
        self.set_font(F, "", 10); self.set_text_color(20, 24, 32)
        self.multi_cell(178, 5.2, t); self.ln(0.4)

    def kv(self, k, v):
        if self.get_y() > 272: self.add_page()
        self.set_x(12)
        self.set_font(F, "B", 9.6); self.set_text_color(*BLUE)
        self.cell(52, 5.4, k)
        self.set_font(F, "", 9.6); self.set_text_color(20, 24, 32)
        self.multi_cell(134, 5.4, v)
        self.ln(0.8)

    def note(self, t, color=GREEN):
        self.set_font(F, "I", 9.3); self.set_text_color(*color); self.set_x(12)
        self.multi_cell(186, 4.8, t); self.ln(1)

    def ligne_tab(self, cells, widths, head=False):
        lh = 3.7
        self.set_font(F, "B" if head else "", 7.7)
        lignes = [self.multi_cell(w - 2, lh, c, dry_run=True, output="LINES")
                  for w, c in zip(widths, cells)]
        h = max(len(l) for l in lignes) * lh + 2.2
        if self.get_y() + h > 280:
            self.add_page()
        y0 = self.get_y(); x = 12
        for w, c in zip(widths, cells):
            self.set_draw_color(*GRAYL)
            if head:
                self.set_fill_color(*HEADBG); self.rect(x, y0, w, h, "DF")
                self.set_text_color(*DARK)
            else:
                self.rect(x, y0, w, h)
                self.set_text_color(25, 29, 38)
            self.set_xy(x + 1, y0 + 1.1)
            self.multi_cell(w - 2, lh, c)
            x += w
        self.set_y(y0 + h)


pdf = PDF()
pdf.add_font(F, "", os.path.join(FD, "segoeui.ttf"))
pdf.add_font(F, "B", os.path.join(FD, "segoeuib.ttf"))
pdf.add_font(F, "I", os.path.join(FD, "segoeuii.ttf"))
pdf.set_auto_page_break(auto=True, margin=14)
pdf.add_page()

pdf.set_font(F, "B", 16); pdf.set_text_color(15, 23, 35)
pdf.cell(0, 9, "Choix du canal de messagerie pour l'agent de support", ln=True)
pdf.set_font(F, "", 9.5); pdf.set_text_color(*GRAY)
pdf.multi_cell(0, 5, "Étude comparative des canaux disponibles (WhatsApp, Telegram, SMS, e-mail, "
                     "Messenger, Signal), justification du choix de Telegram pour le prototype, et "
                     "analyse de la portabilité du mécanisme de liaison vers un autre canal.")
pdf.ln(2)

# 1. Besoin et critères
pdf.h1("1. Le besoin et les critères d'évaluation")
pdf.p("L'agent de support doit : (1) envoyer des alertes de sécurité proactives (chute de score, "
      "expiration SSL, secret exposé) ; (2) répondre aux questions du client en langage naturel ; "
      "(3) offrir une navigation simple (boutons) à des dirigeants de PME non techniciens. "
      "Six critères ont guidé la comparaison :")
pdf.item("Adoption par la cible (PME sénégalaises), le canal doit être déjà installé.")
pdf.item("Coût de l'API : un prototype de mémoire ne peut pas financer un canal payant.")
pdf.item("Ouverture de l'API : création du bot sans processus de validation commerciale.")
pdf.item("Messages proactifs : l'alerte de sécurité part de la plateforme, pas du client.")
pdf.item("Richesse d'interface, boutons, mise en forme, liens profonds.")
pdf.item("Sécurité et identité : sécurisation du webhook, identification fiable du client.")

# 2. Panorama
pdf.h1("2. Panorama des canaux étudiés")

pdf.h2("WhatsApp Business (API Cloud de Meta)")
pdf.item("Adoption dominante au Sénégal : c'est là que vivent réellement les PME.", "+")
pdf.item("Peut initier une conversation vers un client (message template) avec son consentement.", "+")
pdf.item("API fermée : compte Meta Business vérifié, numéro dédié, processus de validation.", "-")
pdf.item("Messages libres uniquement dans une fenêtre de 24 h après le dernier message du client ; "
         "au-delà, seuls des modèles pré-approuvés par Meta sont autorisés, et facturés. Or une "
         "alerte de sécurité arrive par définition hors fenêtre.", "-")
pdf.item("Facturation par conversation/message selon la catégorie : coût récurrent dès le prototype.", "-")

pdf.h2("Telegram (Bot API)")
pdf.item("API entièrement gratuite et ouverte : un bot se crée en 2 minutes via BotFather, "
         "sans validation ni compte entreprise.", "+")
pdf.item("Messages proactifs libres et gratuits vers tout utilisateur ayant démarré le bot "
         "(le /start initial constitue l'opt-in anti-spam).", "+")
pdf.item("Interface riche : boutons inline, HTML, indicateur de saisie, lien profond "
         "t.me/bot?start=CODE, idéal pour la liaison par code.", "+")
pdf.item("Confidentialité : le bot ne voit jamais le numéro du client (identifiant opaque chat_id).", "+")
pdf.item("Adoption plus faible que WhatsApp au Sénégal, c'est la vraie limite du choix.", "-")

pdf.h2("SMS (API opérateurs / agrégateurs)")
pdf.item("Universel : fonctionne sans Internet ni smartphone, pertinent en zone rurale.", "+")
pdf.item("Coût par message, pas de boutons ni de conversation riche, pas d'assistant IA praticable.", "-")

pdf.h2("E-mail")
pdf.item("Gratuit et universel ; adapté aux rapports périodiques.", "+")
pdf.item("Faible engagement pour l'urgence : une alerte critique lue trois jours plus tard ne sert à rien.", "-")

pdf.h2("Facebook Messenger")
pdf.item("API existante mais validation d'application par Meta, fenêtre de 24 h similaire à WhatsApp, "
         "et usage en recul chez les professionnels de la cible.", "-")

pdf.h2("Signal")
pdf.item("Aucune API bot officielle : les solutions existantes sont non officielles et fragiles, "
         "inutilisable proprement pour un service.", "-")

# 3. Tableau
pdf.h1("3. Tableau comparatif")
W = [24, 32, 44, 32, 18, 36]
pdf.ligne_tab(["Canal", "Coût API", "Messages proactifs", "Identifiant", "Boutons", "Adoption cible"], W, head=True)
pdf.ligne_tab(["Telegram", "Gratuite, ouverte", "Libres après /start (opt-in)", "chat_id (numéro masqué)", "Oui", "Modérée, en hausse"], W)
pdf.ligne_tab(["WhatsApp", "Payante (templates), compte vérifié", "Templates pré-approuvés hors fenêtre 24 h", "Numéro (wa_id)", "Oui (limités)", "Très forte (dominante)"], W)
pdf.ligne_tab(["SMS", "Payante (par SMS)", "Libres (opt-in)", "Numéro", "Non", "Universelle (sans Internet)"], W)
pdf.ligne_tab(["E-mail", "Gratuite", "Libres (risque spam)", "Adresse e-mail", "Non (liens)", "Forte, peu réactive"], W)
pdf.ligne_tab(["Messenger", "Gratuite, validation app", "Fenêtre 24 h + tags", "PSID (opaque)", "Oui", "Faible en B2B"], W)
pdf.ligne_tab(["Signal", "Pas d'API officielle", "—", "Numéro", "—", "Faible"], W)
pdf.ln(2)

# 4. Pourquoi Telegram
pdf.h1("4. Pourquoi Telegram pour ce prototype")
pdf.p("Le choix ne prétend pas que Telegram est plus répandu que WhatsApp au Sénégal, il ne l'est "
      "pas. C'est un arbitrage d'ingénierie entre la portée et la faisabilité :")
pdf.kv("Coût nul", "l'API Bot est gratuite sans limite pratique ; l'API WhatsApp facture chaque "
       "template, intenable pour un prototype et structurant pour le futur modèle économique.")
pdf.kv("Zéro barrière", "pas de compte entreprise vérifié ni de processus d'approbation Meta : le "
       "bot a été opérationnel le jour même.")
pdf.kv("Proactivité native", "les alertes de sécurité partent librement ; sur WhatsApp, chaque "
       "format d'alerte devrait être soumis à Meta comme template et payé à l'envoi.")
pdf.kv("Liaison élégante", "le lien profond t.me/bot?start=CODE transporte le code de liaison en "
       "un clic, le pendant WhatsApp (wa.me/<numéro>?text=CODE) existe mais expose le numéro du bot "
       "et pré-remplit un message que le client doit encore envoyer.")
pdf.kv("Confidentialité", "Telegram ne révèle jamais le numéro du client au bot : on stocke un "
       "identifiant opaque, pas une donnée personnelle sensible, favorable au regard de la loi "
       "sénégalaise 2008-12 sur la protection des données personnelles.")
pdf.note("Position assumée : Telegram est le canal du prototype, pas la fin de l'histoire. "
         "L'architecture est prête pour le multi-canal (section 6), et WhatsApp est la cible "
         "naturelle de production une fois le modèle économique en place.")

# 5. Portabilité de la liaison
pdf.h1("5. Un autre canal changerait-il le principe de liaison ?")
pdf.p("Non : et c'est le point le plus important de cette étude. Le mécanisme implémenté "
      "(code à usage unique, expirant, transporté par l'utilisateur = preuve de possession des deux "
      "comptes) est un patron d'architecture indépendant du canal. Seuls deux éléments varient : "
      "l'identifiant externe et le sens de transport du code.")
pdf.kv("Telegram (implémenté)", "identifiant opaque chat_id ; le code va du web vers le bot "
       "(deep link /start CODE). Le code est obligatoire car le numéro n'est pas visible.")
pdf.kv("WhatsApp", "l'identifiant EST le numéro (wa_id). Deux variantes possibles : (a) le même "
       "code via wa.me/<numéro>?text=CODE, identique à l'existant ; (b) un OTP inversé : le client "
       "saisit son numéro sur le web, la plateforme envoie le code SUR WhatsApp, il le ressaisit. "
       "La variante (a) reste préférable : pas de numéro à stocker ni d'erreur de saisie.")
pdf.kv("SMS", "OTP classique (le code part vers le téléphone), même preuve de possession, "
       "sens inversé.")
pdf.kv("E-mail", "lien magique signé : le jeton à usage unique est dans l'URL au lieu d'un message. "
       "Même principe, transport différent.")
pdf.p("La généralisation est directe : la table TelegramLink (user_id ↔ chat_id) deviendrait "
      "ChannelLink (user_id, canal, identifiant_externe), et l'envoi de messages passerait par une "
      "interface commune, envoyer_message(canal, destinataire, contenu), dont Telegram serait la "
      "première implémentation. Le webhook sécurisé existe chez tous les fournisseurs (secret "
      "partagé chez Telegram, signature HMAC X-Hub-Signature-256 chez Meta, même patron que le "
      "webhook GitHub étudié par ailleurs).")

# 6. Trajectoire
pdf.h1("6. Trajectoire recommandée", GREEN)
pdf.item("Aujourd'hui (fait) : Telegram, coût nul, toutes les fonctionnalités, validation du concept.")
pdf.item("Étape 2 : abstraction multi-canal (ChannelLink + interface d'envoi) : préparée par la "
         "structure actuelle en services.")
pdf.item("Étape 3 : WhatsApp Business API en production, via un fournisseur agréé (BSP) ; le coût "
         "des templates s'intègre au modèle d'abonnement de la surveillance continue.")
pdf.item("Étape 4 : SMS en canal de secours pour les alertes critiques (zones sans data, dirigeants "
         "sans smartphone).")
pdf.note("En une phrase : WhatsApp est là où sont les clients, Telegram est là où un prototype "
         "peut exister, et le mécanisme de liaison, lui, ne changera pas.")

pdf.output("../Etude-Canaux-Messagerie.pdf")
print("PDF généré : Etude-Canaux-Messagerie.pdf (racine du projet)")

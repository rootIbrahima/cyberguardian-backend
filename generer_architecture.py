"""
Document d'architecture et de technologies de déploiement.

Destiné à l'encadrant : ce qui compose la plateforme, sur quoi elle tourne, et
comment une requête la traverse. Les valeurs sont relevées sur l'installation
réelle, jamais supposées : versions du système et des bibliothèques, unité
systemd, configuration du serveur web, émetteur du certificat.

Le rendu réutilise le moteur du rapport de scan : mêmes polices, même palette.

Usage, depuis le dossier backend/ :
    python generer_architecture.py
"""

from datetime import datetime

from fpdf import FPDF

from tools.generate_pdf import FONT, _clean, _register_fonts

URL      = "https://cyberguardian.207-180-196-65.nip.io"
VERSION_PG = "PostgreSQL 14.24"    # relevé sur le serveur

BLEU     = (31, 92, 153)
ARDOISE  = (30, 41, 59)
GRIS     = (100, 116, 139)
GRIS_CLR = (226, 232, 240)
VERT     = (26, 122, 74)
AMBRE    = (133, 79, 11)
FOND     = (248, 250, 252)


class Doc(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font(FONT, "", 8)
        self.set_text_color(*GRIS)
        self.cell(0, 6, _clean("CyberGuardian — Architecture et déploiement"), align="L")
        self.cell(0, 6, _clean(URL.replace("https://", "")), align="R",
                  new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*GRIS_CLR)
        self.line(self.l_margin, self.get_y(), self.w - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-14)
        self.set_font(FONT, "", 8)
        self.set_text_color(*GRIS)
        self.cell(0, 6, _clean(f"Page {self.page_no() - 1}"), align="C")


def titre(pdf, texte, avant=6):
    if pdf.get_y() > pdf.h - 45:
        pdf.add_page()
    pdf.ln(avant)
    pdf.set_font(FONT, "B", 15)
    pdf.set_text_color(*ARDOISE)
    pdf.multi_cell(0, 7, _clean(texte), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*BLEU)
    pdf.set_line_width(0.6)
    y = pdf.get_y() + 1
    pdf.line(pdf.l_margin, y, pdf.l_margin + 22, y)
    pdf.set_line_width(0.2)
    pdf.ln(4)


def sous_titre(pdf, texte):
    if pdf.get_y() > pdf.h - 38:
        pdf.add_page()
    pdf.ln(2)
    pdf.set_font(FONT, "B", 10.5)
    pdf.set_text_color(*BLEU)
    pdf.multi_cell(0, 5.5, _clean(texte), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def para(pdf, texte, taille=9.5, couleur=ARDOISE):
    pdf.set_font(FONT, "", taille)
    pdf.set_text_color(*couleur)
    pdf.multi_cell(0, 4.8, _clean(texte), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1.5)


def tableau(pdf, entetes, lignes, largeurs):
    if pdf.get_y() + 8 + len(lignes) * 6 > pdf.h - 22:
        pdf.add_page()
    if entetes:
        pdf.set_font(FONT, "B", 8.5)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(*GRIS)
        for h, l in zip(entetes, largeurs):
            pdf.cell(l, 7, _clean(h), border=0, fill=True, align="L")
        pdf.ln()
    pdf.set_font(FONT, "", 8.5)
    pdf.set_text_color(*ARDOISE)
    pdf.set_draw_color(*GRIS_CLR)
    for ligne in lignes:
        if pdf.get_y() > pdf.h - 24:
            pdf.add_page()
        for valeur, l in zip(ligne, largeurs):
            pdf.cell(l, 6, _clean(str(valeur)), border="B", align="L")
        pdf.ln()
    pdf.ln(3)


def encadre(pdf, titre_bloc, lignes, couleur=BLEU, fond=FOND):
    hauteur = 7 + len(lignes) * 4.8 + 3
    if pdf.get_y() + hauteur > pdf.h - 20:
        pdf.add_page()
    y0 = pdf.get_y()
    pdf.set_fill_color(*fond)
    pdf.rect(pdf.l_margin, y0, pdf.w - pdf.l_margin - pdf.r_margin, hauteur, "F")
    pdf.set_fill_color(*couleur)
    pdf.rect(pdf.l_margin, y0, 1.2, hauteur, "F")
    pdf.set_xy(pdf.l_margin + 5, y0 + 2.5)
    pdf.set_font(FONT, "B", 9)
    pdf.set_text_color(*couleur)
    pdf.cell(0, 4.5, _clean(titre_bloc), new_x="LMARGIN", new_y="NEXT")
    for ligne in lignes:
        pdf.set_x(pdf.l_margin + 5)
        pdf.set_font(FONT, "", 9)
        pdf.set_text_color(*ARDOISE)
        pdf.multi_cell(pdf.w - pdf.l_margin - pdf.r_margin - 8, 4.8,
                       _clean(ligne), new_x="LMARGIN", new_y="NEXT")
    pdf.set_y(y0 + hauteur + 3)


# ── Schéma d'architecture ─────────────────────────────────────────────────────

def boite(pdf, x, y, w, h, titre_b, lignes, bordure=BLEU, fond=(255, 255, 255)):
    pdf.set_fill_color(*fond)
    pdf.set_draw_color(*bordure)
    pdf.set_line_width(0.4)
    pdf.rect(x, y, w, h, "DF")
    pdf.set_xy(x + 3, y + 2.2)
    pdf.set_font(FONT, "B", 8.5)
    pdf.set_text_color(*bordure)
    pdf.cell(w - 6, 4, _clean(titre_b))
    pdf.set_font(FONT, "", 7.5)
    pdf.set_text_color(*GRIS)
    for i, ligne in enumerate(lignes):
        pdf.set_xy(x + 3, y + 6.8 + i * 3.6)
        pdf.cell(w - 6, 3.4, _clean(ligne))
    pdf.set_line_width(0.2)


def fleche(pdf, x1, y1, x2, y2, etiquette=""):
    pdf.set_draw_color(*GRIS)
    pdf.set_line_width(0.3)
    pdf.line(x1, y1, x2, y2)
    # pointe
    pdf.line(x2, y2, x2 - 1.4, y2 - 2.2)
    pdf.line(x2, y2, x2 + 1.4, y2 - 2.2)
    if etiquette:
        pdf.set_font(FONT, "", 6.8)
        pdf.set_text_color(*GRIS)
        pdf.set_xy(x2 + 2, (y1 + y2) / 2 - 2)
        pdf.cell(60, 3, _clean(etiquette))
    pdf.set_line_width(0.2)


def schema(pdf):
    G = pdf.l_margin
    L = pdf.w - pdf.l_margin - pdf.r_margin
    y = pdf.get_y()

    boite(pdf, G + L / 2 - 35, y, 70, 13, "Navigateur du client",
          ["React 18 · page unique"], ARDOISE)
    fleche(pdf, G + L / 2, y + 13, G + L / 2, y + 22, "HTTPS · TLS 1.3 · Let's Encrypt")

    y2 = y + 22
    hauteur_vps = 74
    pdf.set_draw_color(*BLEU)
    pdf.set_fill_color(250, 252, 254)
    pdf.rect(G, y2, L, hauteur_vps, "DF")
    pdf.set_xy(G + 3, y2 + 2)
    pdf.set_font(FONT, "B", 8)
    pdf.set_text_color(*BLEU)
    pdf.cell(L - 6, 4, _clean("Serveur privé virtuel Contabo · Ubuntu 22.04.5 LTS · noyau 5.15"))

    interieur = G + 5
    largeur_i = L - 10

    boite(pdf, interieur, y2 + 9, largeur_i, 14, "nginx 1.18",
          ["/      fichiers statiques du frontend compilé",
           "/api   transmis à 127.0.0.1:8001, préfixe retiré"], VERT)

    boite(pdf, interieur, y2 + 27, largeur_i * 0.56, 16, "uvicorn + FastAPI",
          ["unité systemd, redémarrage automatique",
           "écoute uniquement en boucle locale"], BLEU)

    boite(pdf, interieur + largeur_i * 0.60, y2 + 27, largeur_i * 0.40, 16,
          "Minuterie systemd", ["surveillance quotidienne à 03:00",
                                "réanalyse les actifs échus"], AMBRE)

    boite(pdf, interieur, y2 + 47, largeur_i * 0.56, 14, VERSION_PG,
          ["accès local, jamais exposé au réseau"], BLEU)

    boite(pdf, interieur + largeur_i * 0.60, y2 + 47, largeur_i * 0.40, 14,
          "Outils d'analyse", ["nmap, git, bandit"], BLEU)

    fleche(pdf, G + L * 0.30, y2 + 23, G + L * 0.30, y2 + 27)
    fleche(pdf, G + L * 0.30, y2 + 43, G + L * 0.30, y2 + 47)

    y3 = y2 + hauteur_vps + 4
    fleche(pdf, G + L / 2, y2 + hauteur_vps, G + L / 2, y3 + 3, "appels sortants")

    boite(pdf, G, y3 + 6, L, 17, "Services externes",
          ["Ollama sur l'infrastructure UN-CHK (Diamniadio) — rapports rédigés, assistant",
           "Telegram et SMTP — remise des alertes, via Apprise",
           "VirusTotal, AbuseIPDB, OSV, EPSS, certSpotter, API GitHub — enrichissement"],
          GRIS)

    pdf.set_y(y3 + 27)


# ── Pages ─────────────────────────────────────────────────────────────────────

def page_couverture(pdf):
    pdf.add_page()
    pdf.set_fill_color(*BLEU)
    pdf.rect(0, 0, pdf.w, 70, "F")
    pdf.set_xy(pdf.l_margin, 22)
    pdf.set_font(FONT, "B", 26)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 12, _clean("CyberGuardian"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin)
    pdf.set_font(FONT, "", 12)
    pdf.cell(0, 7, _clean("Architecture et technologies de déploiement"),
             new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(84)
    para(pdf, "Ce document décrit la composition de la plateforme, l'infrastructure "
              "qui la porte, et le chemin qu'une requête y parcourt. Les valeurs "
              "indiquées sont relevées sur l'installation en service, non "
              "supposées : versions du système et des bibliothèques, unité de "
              "service, configuration du serveur web, émetteur du certificat.", 10)

    tableau(pdf, [], [
        ["Auteur",              "Ibrahima LY"],
        ["Formation",           "Master, EC2LT"],
        ["Plateforme en ligne", URL.replace("https://", "")],
        ["Dépôt backend",       "github.com/rootIbrahima/cyberguardian-backend"],
        ["Dépôt frontend",      "github.com/rootIbrahima/cyberguardian-frontend"],
        ["Relevé effectué le",  datetime.now().strftime("%d/%m/%Y")],
    ], [48, 122])

    encadre(pdf, "Principe directeur", [
        "Un seul serveur porte l'ensemble. Le choix n'est pas un compromis mais une "
        "réponse au contexte : une plateforme destinée à des organisations "
        "sénégalaises de taille modeste doit pouvoir être exploitée par une "
        "personne, sur une machine dont le coût mensuel reste marginal.",
        "L'architecture reste toutefois découpée en couches indépendantes, chacune "
        "pouvant être déplacée sur sa propre machine sans modifier le code.",
    ])


def page_schema(pdf):
    pdf.add_page()
    titre(pdf, "Vue d'ensemble", avant=0)
    para(pdf, "Le navigateur ne dialogue qu'avec nginx. Celui-ci sert les fichiers "
              "du frontend compilé et transmet au backend tout ce qui commence par "
              "/api. L'application Python n'écoute que sur la boucle locale : elle "
              "n'est joignable depuis internet qu'à travers le serveur web.")
    schema(pdf)

    sous_titre(pdf, "Ce que le découpage garantit")
    para(pdf, "La base de données et l'API ne sont pas exposées. Un seul port est "
              "ouvert vers l'extérieur, celui du serveur web, qui termine le "
              "chiffrement et applique les règles d'accès. Le service applicatif "
              "redémarre seul en cas d'arrêt inattendu, et la minuterie de "
              "surveillance s'exécute indépendamment de lui : une panne de "
              "l'application n'annule pas les analyses planifiées, elle les diffère.")


def page_technologies(pdf):
    pdf.add_page()
    titre(pdf, "Technologies par couche", avant=0)

    sous_titre(pdf, "Interface")
    tableau(pdf, ["Composant", "Version", "Rôle"], [
        ["React",            "18.3",  "Bibliothèque d'interface, composants fonctionnels"],
        ["Vite",             "8.2",   "Compilation et regroupement du code livré"],
        ["React Router",     "7.18",  "Navigation côté client, routes protégées par rôle"],
        ["Tailwind CSS",     "3.x",   "Feuilles de style, jetons de couleur du projet"],
        ["axios",            "1.x",   "Appels à l'API, jeton d'authentification injecté"],
    ], [42, 24, 104])

    sous_titre(pdf, "Service applicatif")
    tableau(pdf, ["Composant", "Version", "Rôle"], [
        ["Python",           "3.10.12", "Interpréteur du serveur"],
        ["FastAPI",          "0.136.3", "Cadre applicatif, 53 routes, OpenAPI 3.1"],
        ["uvicorn",          "0.49.0",  "Serveur ASGI, un processus, boucle locale"],
        ["SQLAlchemy",       "2.0.35",  "Accès aux données et description du schéma"],
        ["pydantic",         "2.13.4",  "Validation des entrées et des réponses"],
        ["psycopg2",         "2.9.9",   "Connecteur PostgreSQL"],
        ["httpx",            "0.28.1",  "Client HTTP des outils d'analyse"],
        ["Apprise",          "1.12.0",  "Abstraction des canaux de notification"],
    ], [42, 24, 104])

    sous_titre(pdf, "Données et outils système")
    tableau(pdf, ["Composant", "Version", "Rôle"], [
        [VERSION_PG.replace("PostgreSQL ", "PostgreSQL "), "", "Base de données, accès local uniquement"],
        ["nmap",             "",        "Relevé des ports ouverts"],
        ["git",              "",        "Clonage des dépôts analysés"],
        ["Bandit",           "",        "Analyse statique du code Python des dépôts"],
    ], [42, 24, 104])

    sous_titre(pdf, "Infrastructure")
    tableau(pdf, ["Composant", "Version", "Rôle"], [
        ["Ubuntu Server",    "22.04.5 LTS", "Système, noyau 5.15"],
        ["nginx",            "1.18.0",      "Terminaison TLS, fichiers statiques, proxy inverse"],
        ["systemd",          "",            "Service applicatif et minuterie de surveillance"],
        ["Certbot",          "",            "Certificat Let's Encrypt, renouvellement automatique"],
        ["Contabo",          "",            "Hébergeur du serveur privé virtuel"],
    ], [42, 24, 104])


def page_deploiement(pdf):
    pdf.add_page()
    titre(pdf, "Déploiement et exploitation", avant=0)

    sous_titre(pdf, "Disposition sur le serveur")
    tableau(pdf, [], [
        ["/var/www/cyberguardian/backend",       "code Python et environnement virtuel"],
        ["/var/www/cyberguardian/frontend/dist", "interface compilée, servie par nginx"],
        ["backend/.env",                          "secrets, hors dépôt, jamais versionné"],
    ], [72, 98])

    sous_titre(pdf, "Service applicatif")
    para(pdf, "Une unité systemd lance uvicorn dans l'environnement virtuel, en "
              "écoute sur la boucle locale au port 8001. Elle démarre après le "
              "service de base de données et se relance automatiquement cinq "
              "secondes après un arrêt inattendu.", 9)
    tableau(pdf, [], [
        ["Commande",   "venv/bin/uvicorn main:app --host 127.0.0.1 --port 8001"],
        ["Relance",    "automatique, délai de 5 secondes"],
        ["Dépendance", "démarre après postgresql.service"],
    ], [30, 140])

    sous_titre(pdf, "Serveur web et chiffrement")
    para(pdf, "nginx sert l'interface compilée et transmet les appels d'API au "
              "service local. Le certificat est délivré par Let's Encrypt et "
              "renouvelé automatiquement par Certbot ; sa durée de validité est de "
              "quatre-vingt-dix jours. La connexion négociée est en TLS 1.3 avec la "
              "suite TLS_AES_256_GCM_SHA384.", 9)

    sous_titre(pdf, "Surveillance planifiée")
    para(pdf, "Une minuterie systemd déclenche chaque nuit à trois heures un script "
              "autonome qui réanalyse les actifs dont l'échéance est venue, compare "
              "chaque résultat au précédent et n'alerte qu'en cas d'écart réel. Le "
              "choix d'un ordonnanceur système plutôt qu'applicatif est délibéré : "
              "un fil interne se dédoublerait en développement, disparaîtrait à "
              "chaque redémarrage et ne laisserait aucune trace consultable.", 9)

    sous_titre(pdf, "Mise en production")
    para(pdf, "Le code est publié sur deux dépôts Git. Une mise à jour consiste à "
              "récupérer les modifications, appliquer les évolutions de schéma par "
              "un script idempotent, redémarrer le service, puis recompiler "
              "l'interface. Un script de vérification interroge ensuite les URL "
              "publiques pour confirmer qu'elles atteignent les services attendus.", 9)


def page_flux(pdf):
    pdf.add_page()
    titre(pdf, "Deux parcours de bout en bout", avant=0)

    sous_titre(pdf, "Une analyse demandée par un client")
    tableau(pdf, [], [
        ["1", "Le navigateur envoie la cible à l'API, jeton JWT en en-tête."],
        ["2", "Un garde-fou résout le nom et refuse toute adresse interne."],
        ["3", "Le scan est enregistré « en cours » et la réponse part aussitôt."],
        ["4", "Les outils s'exécutent en tâche de fond : TLS, DNS, en-têtes, ports, réputation, sous-domaines."],
        ["5", "Le score est calculé sur les seuls critères réellement mesurés."],
        ["6", "Le résultat est comparé au scan précédent de la même cible."],
        ["7", "En cas d'écart, une alerte part sur les canaux du client."],
        ["8", "Une analyse rédigée est préparée pendant que le client consulte."],
    ], [8, 162])
    para(pdf, "L'inversion opérée à la troisième étape est ce qui rend la page de "
              "progression honnête : elle suit l'exécution réelle au lieu de laisser "
              "l'utilisateur derrière un bouton figé.", 8.5, GRIS)

    sous_titre(pdf, "Une alerte jusqu'au destinataire")
    tableau(pdf, [], [
        ["1", "Le moteur de comparaison relève un écart : port ouvert, secret exposé, certificat proche du terme, chute de score."],
        ["2", "Une notification est écrite en base, l'envoi programmé pour la validation de la transaction."],
        ["3", "Un fil séparé pousse le message sur chaque canal du destinataire."],
        ["4", "L'issue est inscrite sur la notification : remise, échec, canal fautif."],
        ["5", "La console d'administration compte les échecs des sept derniers jours."],
    ], [8, 162])
    para(pdf, "Programmer l'envoi sur la validation de la transaction évite "
              "d'annoncer un événement encore susceptible d'être annulé. Le fil "
              "séparé évite qu'un aller-retour vers Telegram ou un serveur de "
              "messagerie ne pèse sur la réponse rendue au client.", 8.5, GRIS)


def page_securite(pdf):
    pdf.add_page()
    titre(pdf, "Sécurité de la plateforme et limites", avant=0)

    sous_titre(pdf, "Mesures en place")
    tableau(pdf, [], [
        ["Périmètre des analyses", "Toute cible interne est refusée : boucle locale, réseaux privés, métadonnées d'hébergeur."],
        ["Authentification",       "Jetons JWT ; mots de passe hachés par bcrypt."],
        ["Secrets au repos",       "Jeton OAuth GitHub chiffré en base par Fernet."],
        ["Webhook",                "Secret partagé vérifié par comparaison à temps constant."],
        ["Cloisonnement",          "Un expert n'accède au rapport qu'après contrat signé, et pour quarante-huit heures."],
        ["Supervision",            "L'administration voit les conversations, jamais leur contenu."],
        ["Exposition réseau",      "Un seul port ouvert ; base de données et API en boucle locale."],
        ["Quota",                  "Plafond d'analyses par cible et par période de vingt-quatre heures."],
    ], [46, 124])

    sous_titre(pdf, "Limites assumées")
    tableau(pdf, [], [
        ["Serveur unique",    "Aucune redondance : une panne matérielle interrompt le service."],
        ["Un seul processus", "uvicorn tourne sans réplique ; la charge simultanée reste modeste par construction."],
        ["Modèle de langage", "Hébergé sur une infrastructure tierce mutualisée, avec des délais de trente secondes à plus de deux minutes selon sa charge."],
        ["Réassociation DNS", "Le garde-fou résout puis analyse en deux temps ; l'attaque reste théoriquement possible."],
        ["Sauvegardes",       "Exportées à la main avant chaque évolution de schéma, sans automatisation à ce jour."],
    ], [46, 124])

    encadre(pdf, "Vérifiabilité", [
        "Le code des deux dépôts est public. L'historique documente chaque décision "
        "et les mesures qui l'ont motivée : durées relevées, écarts constatés, "
        "défauts trouvés et corrigés.",
        "Un script du projet contrôle que les URL publiques atteignent les services "
        "attendus, et la console d'administration expose l'état de huit services en "
        "moins de deux secondes.",
    ])


def generer(chemin="architecture-cyberguardian.pdf") -> str:
    pdf = Doc()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(20, 16, 20)
    _register_fonts(pdf)
    page_couverture(pdf)
    page_schema(pdf)
    page_technologies(pdf)
    page_deploiement(pdf)
    page_flux(pdf)
    page_securite(pdf)
    pdf.output(chemin)
    return chemin


if __name__ == "__main__":
    print("  document ecrit dans " + generer())

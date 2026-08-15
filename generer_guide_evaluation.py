"""
Guide d'évaluation de CyberGuardian, à remettre à l'encadrant.

Le document présente la plateforme en ligne, ce qu'elle fait, et surtout ce que
l'évaluateur peut vérifier lui-même : comptes de démonstration, parcours guidés,
résultats attendus. Un mémoire s'apprécie mieux sur une plateforme qu'on a
manipulée que sur des captures d'écran.

Le rendu réutilise le moteur du rapport de scan : mêmes polices, même palette,
même traitement des accents. Le guide ressemble ainsi aux documents que la
plateforme produit elle-même.

Usage, depuis le dossier backend/ :
    python generer_guide_evaluation.py
"""

from datetime import datetime

from fpdf import FPDF

from config import (SEED_ADMIN_PASSWORD, SEED_CLIENT_PASSWORD,
                    SEED_EXPERT_PASSWORD)
from tools.generate_pdf import FONT, _clean, _register_fonts

URL = "https://cyberguardian.207-180-196-65.nip.io"

BLEU     = (31, 92, 153)
ARDOISE  = (30, 41, 59)
GRIS     = (100, 116, 139)
GRIS_CLR = (226, 232, 240)
VERT     = (26, 122, 74)
AMBRE    = (133, 79, 11)
ROUGE    = (153, 27, 27)


class Guide(FPDF):
    def header(self):
        if self.page_no() == 1:
            return
        self.set_font(FONT, "", 8)
        self.set_text_color(*GRIS)
        self.cell(0, 6, _clean("CyberGuardian — Guide d'évaluation"), align="L")
        self.cell(0, 6, _clean(URL.replace("https://", "")), align="R", new_x="LMARGIN", new_y="NEXT")
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


def titre(pdf, texte, taille=15, espace_avant=6):
    if pdf.get_y() > pdf.h - 45:
        pdf.add_page()
    pdf.ln(espace_avant)
    pdf.set_font(FONT, "B", taille)
    pdf.set_text_color(*ARDOISE)
    pdf.multi_cell(0, 7, _clean(texte), new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(*BLEU)
    pdf.set_line_width(0.6)
    y = pdf.get_y() + 1
    pdf.line(pdf.l_margin, y, pdf.l_margin + 22, y)
    pdf.set_line_width(0.2)
    pdf.ln(4)


def sous_titre(pdf, texte):
    if pdf.get_y() > pdf.h - 40:
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


def puces(pdf, items, taille=9.5):
    pdf.set_font(FONT, "", taille)
    for item in items:
        if pdf.get_y() > pdf.h - 25:
            pdf.add_page()
        pdf.set_text_color(*BLEU)
        pdf.cell(5, 4.8, _clean("-"))
        pdf.set_text_color(*ARDOISE)
        pdf.multi_cell(0, 4.8, _clean(item), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1.5)


def encadre(pdf, titre_bloc, lignes, couleur=BLEU, fond=(248, 250, 252)):
    """Bloc mis en valeur : accès, avertissement, résultat attendu."""
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


def tableau(pdf, entetes, lignes, largeurs):
    if pdf.get_y() + 8 + len(lignes) * 6 > pdf.h - 20:
        pdf.add_page()
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
        if pdf.get_y() > pdf.h - 25:
            pdf.add_page()
        for valeur, l in zip(ligne, largeurs):
            pdf.cell(l, 6, _clean(str(valeur)), border="B", align="L")
        pdf.ln()
    pdf.ln(3)


def etape(pdf, numero, intitule, actions, attendu):
    """Un test guidé : ce qu'on fait, ce qu'on doit obtenir."""
    if pdf.get_y() > pdf.h - 55:
        pdf.add_page()
    pdf.set_font(FONT, "B", 10)
    pdf.set_text_color(*BLEU)
    pdf.multi_cell(0, 5.5, _clean(f"Test {numero} — {intitule}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(0.5)
    pdf.set_font(FONT, "", 9.5)
    for a in actions:
        pdf.set_x(pdf.l_margin + 3)
        pdf.set_text_color(*GRIS)
        pdf.cell(4, 4.8, _clean(">"))
        pdf.set_text_color(*ARDOISE)
        pdf.multi_cell(0, 4.8, _clean(a), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)
    pdf.set_x(pdf.l_margin + 3)
    pdf.set_font(FONT, "B", 9)
    pdf.set_text_color(*VERT)
    pdf.cell(24, 4.8, _clean("Attendu :"))
    pdf.set_font(FONT, "", 9)
    pdf.set_text_color(*ARDOISE)
    pdf.multi_cell(0, 4.8, _clean(attendu), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)


# ── Pages ─────────────────────────────────────────────────────────────────────

def page_couverture(pdf):
    pdf.add_page()
    pdf.set_fill_color(*BLEU)
    pdf.rect(0, 0, pdf.w, 78, "F")

    pdf.set_xy(pdf.l_margin, 26)
    pdf.set_font(FONT, "B", 27)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 12, _clean("CyberGuardian"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin)
    pdf.set_font(FONT, "", 12)
    pdf.cell(0, 7, _clean("Plateforme de gestion de la surface d'attaque externe"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin)
    pdf.set_font(FONT, "B", 10)
    pdf.cell(0, 7, _clean("Guide d'évaluation"), new_x="LMARGIN", new_y="NEXT")

    pdf.set_y(96)
    para(pdf, "Ce document accompagne la plateforme mise en ligne. Il décrit ce "
              "qu'elle fait, comment y accéder, et propose douze parcours de "
              "vérification menant chacun à un résultat observable. Il indique "
              "aussi, sans les contourner, les limites du travail réalisé.", 10)

    encadre(pdf, "Accès à la plateforme", [
        f"Adresse : {URL}",
        "Aucune installation requise, la plateforme fonctionne dans un navigateur.",
        "Les identifiants de démonstration figurent en page suivante.",
    ])

    pdf.ln(4)
    tableau(pdf,
            ["", ""],
            [["Auteur",        "Ibrahima LY"],
             ["Formation",     "Master, EC2LT"],
             ["Dépôt backend", "github.com/rootIbrahima/cyberguardian-backend"],
             ["Dépôt frontend","github.com/rootIbrahima/cyberguardian-frontend"],
             ["Document établi le", datetime.now().strftime("%d/%m/%Y")]],
            [45, 125])

    pdf.set_y(pdf.h - 32)
    pdf.set_font(FONT, "", 8)
    pdf.set_text_color(*GRIS)
    pdf.multi_cell(0, 4, _clean(
        "Les analyses portent exclusivement sur des actifs publics. La plateforme "
        "refuse toute cible interne (boucle locale, réseaux privés, métadonnées "
        "d'hébergeur) afin de ne pas servir de relais de reconnaissance."),
        new_x="LMARGIN", new_y="NEXT")


def page_acces(pdf):
    pdf.add_page()
    titre(pdf, "Accès et comptes de démonstration", espace_avant=0)
    para(pdf, "Trois comptes permettent de parcourir la plateforme sous chacun des "
              "rôles. Les rôles ne voient pas les mêmes écrans et n'ont pas les "
              "mêmes droits : c'est en changeant de compte que le cloisonnement "
              "des accès devient visible.")

    # Les mots de passe viennent de .env et ne figurent jamais dans ce fichier :
    # les deux dépôts sont publics, une valeur écrite ici serait lisible de tous.
    # Le PDF produit, lui, n'est pas destiné au dépôt.
    tableau(pdf,
            ["Rôle", "Identifiant", "Mot de passe"],
            [["Client",         "ibrahima.ly@ec2lt.sn",    SEED_CLIENT_PASSWORD or "(voir .env)"],
             ["Expert validé",  "expert@cyberguardian.sn", SEED_EXPERT_PASSWORD or "(voir .env)"],
             ["Administrateur", "admin@cyberguardian.sn",  SEED_ADMIN_PASSWORD  or "(voir .env)"]],
            [38, 76, 56])

    encadre(pdf, "À la fin de l'évaluation", [
        "Ces mots de passe sont ceux d'une démonstration et n'ont pas vocation à "
        "rester actifs. Ils seront changés une fois l'évaluation terminée.",
    ], couleur=AMBRE, fond=(255, 251, 235))

    sous_titre(pdf, "Ce que chaque rôle peut faire")
    tableau(pdf,
            ["Rôle", "Périmètre"],
            [["Client", "Analyse ses actifs, consulte ses rapports, sollicite un expert"],
             ["Expert", "Répond aux demandes, accède au rapport selon le niveau de mission"],
             ["Admin",  "Supervise la plateforme, valide les experts, propose des correctifs"]],
            [28, 142])

    sous_titre(pdf, "Cibles utilisables pour les essais")
    puces(pdf, [
        "scanme.nmap.org : cible officielle de test du projet Nmap, prévue pour "
        "être analysée. Elle présente de vraies vulnérabilités et donne un score bas.",
        "Un domaine public de votre choix : ec2lt.sn, un site institutionnel, votre "
        "propre domaine.",
        "Un dépôt GitHub public : l'analyse porte alors sur le code, les dépendances "
        "et les secrets éventuellement exposés.",
    ])
    para(pdf, "Une adresse interne (127.0.0.1, 192.168.x.x) est refusée par la "
              "plateforme avec un message explicite. C'est un comportement voulu, "
              "et le test 11 le vérifie.", couleur=GRIS)


def page_fonctionnalites(pdf):
    pdf.add_page()
    titre(pdf, "Ce que fait la plateforme", espace_avant=0)
    para(pdf, "CyberGuardian analyse la surface d'attaque externe d'une organisation, "
              "en surveille l'évolution, et met le client en relation avec un expert "
              "lorsqu'une correction dépasse ses moyens.")

    sous_titre(pdf, "Analyse")
    puces(pdf, [
        "Onze outils d'analyse : certificat et protocole TLS, enregistrements DNS "
        "(SPF, DMARC, DKIM, DNSSEC), WHOIS, en-têtes HTTP de sécurité, ports "
        "ouverts, réputation de l'actif, et pour les dépôts GitHub l'analyse "
        "statique du code, les dépendances vulnérables et les secrets exposés.",
        "Score sur cent, pondéré sur cinq critères. Les vulnérabilités connues sont "
        "enrichies de leur score CVSS et de leur probabilité d'exploitation EPSS, "
        "qui distingue une faille théorique d'une faille réellement exploitée.",
        "Rapport PDF détaillé, comprenant une analyse rédigée en français courant "
        "par un modèle de langage.",
        "Assistant conversationnel : le client interroge les résultats de son scan "
        "en langage naturel.",
    ])

    sous_titre(pdf, "Surveillance continue")
    puces(pdf, [
        "Un actif placé sous surveillance est réanalysé automatiquement, chaque "
        "semaine ou chaque jour selon le choix du client.",
        "À chaque passage, le résultat est comparé au précédent. Six écarts sont "
        "détectés : secret exposé, port sensible ouvert, vulnérabilité grave, "
        "certificat proche de son terme, signalement de réputation, chute de score.",
        "Une alerte n'est émise que sur un changement, jamais sur un état. Un "
        "certificat expirant dans trente jours produit une alerte, pas trente.",
        "Les alertes partent par courriel et sur Telegram, au choix du client.",
    ])

    sous_titre(pdf, "Mise en relation avec un expert")
    puces(pdf, [
        "Annuaire d'experts vérifiés : pièce d'identité et diplôme contrôlés par "
        "l'administrateur avant publication du profil.",
        "Messagerie interne avec accès progressif au rapport en trois niveaux. "
        "L'expert voit d'abord le score seul, puis le détail par critère une fois "
        "la mission acceptée, puis le rapport complet après signature du contrat, "
        "et pour quarante-huit heures seulement.",
        "Le client note l'expert à l'issue de la mission ; la réputation affichée "
        "est la moyenne des notes réelles.",
    ])

    sous_titre(pdf, "Correction assistée")
    puces(pdf, [
        "Un client peut autoriser la correction de son dépôt GitHub. La plateforme "
        "ouvre alors une proposition de modification (Pull Request) mettant à jour "
        "les dépendances vulnérables.",
        "Jamais d'écriture directe sur le dépôt : la correction reste soumise à la "
        "relecture et à la validation du client.",
    ])

    sous_titre(pdf, "Supervision")
    puces(pdf, [
        "Console d'administration : état des services, posture de sécurité des "
        "clients, validation des experts, gestion des comptes.",
        "Le contrôle d'état vérifie huit points en deux secondes : canaux de "
        "notification, serveur d'inférence, URL publiques, sources de réputation, "
        "cohérence de la configuration, scans anormaux, remise des alertes.",
    ])


def page_tests(pdf):
    pdf.add_page()
    titre(pdf, "Parcours de vérification", espace_avant=0)
    para(pdf, "Douze tests, du plus simple au plus révélateur. Chacun indique le "
              "résultat attendu, de sorte qu'un écart soit immédiatement visible. "
              "Les six premiers se font depuis le compte client.")

    etape(pdf, 1, "Lancer une analyse",
          ["Se connecter avec le compte client.",
           "Depuis le tableau de bord, saisir scanme.nmap.org et choisir « Domaine ».",
           "Lancer l'analyse."],
          "La page de progression apparaît immédiatement et montre les outils qui "
          "s'exécutent l'un après l'autre. L'analyse dure une minute environ. Le "
          "score obtenu est bas, aux alentours de 28 sur 100 : cette cible est "
          "volontairement vulnérable.")

    etape(pdf, 2, "Lire le rapport",
          ["Ouvrir le scan terminé depuis « Mes scans »."],
          "Le détail du score par critère, la liste des problèmes classés par "
          "gravité, et les vulnérabilités connues avec leur score CVSS. Deux "
          "vulnérabilités graves sont attendues sur cette cible, dont une critique "
          "notée 9,8 sur 10.")

    etape(pdf, 3, "Télécharger le rapport PDF",
          ["Depuis la page de résultats, cliquer sur « Télécharger PDF »."],
          "Le document arrive en moins d'une seconde : l'analyse rédigée a été "
          "préparée pendant le scan et non au moment du clic. Il contient une "
          "explication en français courant, destinée à un lecteur non informaticien.")

    etape(pdf, 4, "Interroger l'assistant",
          ["Sur la même page, poser une question dans l'assistant, "
           "par exemple : « quelle faille dois-je corriger en premier ? »"],
          "La réponse s'écrit progressivement. Le modèle est hébergé sur "
          "l'infrastructure de l'UN-CHK à Diamniadio et partagé : comptez de trente "
          "secondes à deux minutes selon sa charge. Un bouton permet d'interrompre "
          "la génération.")

    etape(pdf, 5, "Mettre l'actif sous surveillance",
          ["Sur la page de résultats, cliquer sur « Surveiller cet actif »."],
          "Le bouton passe au vert et indique « Sous surveillance ». L'actif sera "
          "réanalysé chaque semaine et le client prévenu de tout changement. Le "
          "premier passage n'est pas immédiat : le scan qui vient d'être consulté "
          "sert précisément de point de comparaison.")

    etape(pdf, 6, "Solliciter un expert",
          ["Ouvrir « Experts », choisir un profil, cliquer sur « Contacter ».",
           "Écrire un message dans la conversation qui s'ouvre."],
          "La conversation démarre au niveau 1 : l'expert ne voit que le score "
          "global et le nombre de failles, pas le détail.")

    pdf.add_page()
    para(pdf, "Les tests 7 et 8 se font depuis le compte expert. Le mécanisme "
              "d'accès progressif ne se constate qu'en changeant de rôle.", couleur=GRIS)

    etape(pdf, 7, "Répondre en tant qu'expert",
          ["Se déconnecter, se reconnecter avec le compte expert.",
           "Ouvrir la conversation reçue et y répondre."],
          "La conversation passe au niveau 2. L'expert voit désormais le score "
          "détaillé par critère, mais toujours pas le rapport complet.")

    etape(pdf, 8, "Signer le contrat",
          ["Revenir sur le compte client, ouvrir la conversation.",
           "Signer le contrat numérique proposé."],
          "Niveau 3 : l'expert accède au rapport complet, pour quarante-huit heures. "
          "Passé ce délai l'accès se referme de lui-même, sans intervention.")

    para(pdf, "Les tests 9 à 12 se font depuis le compte administrateur.", couleur=GRIS)

    etape(pdf, 9, "Consulter l'état des services",
          ["Se connecter avec le compte administrateur.",
           "La console s'ouvre sur le bandeau d'état ; cliquer sur « Détail »."],
          "Huit contrôles, chacun dans l'un de trois états : fonctionnel, en défaut, "
          "ou non configuré. La distinction est délibérée : un canal non installé "
          "n'est pas une panne.")

    etape(pdf, 10, "Lire la posture des clients",
          ["Dans la console, ouvrir l'onglet « Posture »."],
          "Une ligne par client : actifs surveillés, score moyen ramené sur cent, "
          "pire actif, tendance depuis l'analyse précédente, vulnérabilités graves. "
          "Les comptes dont un actif recule apparaissent en tête.")

    etape(pdf, 11, "Vérifier le refus des cibles internes",
          ["Depuis n'importe quel compte, tenter une analyse de 127.0.0.1, "
           "puis de 192.168.1.1."],
          "Les deux tentatives sont refusées avec un message explicite, avant toute "
          "requête réseau. Sans cette garde, la plateforme servirait de relais pour "
          "analyser des réseaux internes qui ne lui appartiennent pas.")

    etape(pdf, 12, "Vérifier le cloisonnement des données",
          ["Depuis le compte administrateur, ouvrir « Conversations » et "
           "sélectionner un échange entre un client et un expert."],
          "L'administrateur voit les deux parties, l'actif concerné, le niveau de "
          "mission, le volume de l'échange et son ancienneté — mais pas le contenu "
          "des messages. Ceux-ci portent les failles des actifs du client : un "
          "compte capable de tout lire concentrerait précisément ce qu'un attaquant "
          "recherche.")


def page_limites(pdf):
    pdf.add_page()
    titre(pdf, "Choix techniques et limites", espace_avant=0)
    para(pdf, "Cette section signale les limites du travail réalisé et les décisions "
              "qui les expliquent. Les taire rendrait l'évaluation moins utile.")

    sous_titre(pdf, "Limites assumées")
    puces(pdf, [
        "Le garde-fou contre les cibles internes résout le nom puis analyse en deux "
        "temps. Une attaque par réassociation DNS reste théoriquement possible. Ce "
        "niveau de protection est cohérent avec un analyseur passif, mais il est "
        "juste de le signaler.",
        "Le serveur d'inférence est mutualisé : le même texte a été chronométré "
        "à 28 secondes puis à 139 secondes selon sa charge. Les rapports rédigés "
        "sont donc préparés pendant le scan, et non au moment du téléchargement.",
        "La surveillance repose sur un ordonnanceur du système et non sur "
        "l'application. Un ordonnanceur interne se dédoublerait en développement et "
        "disparaîtrait à chaque redémarrage, sans laisser de trace.",
        "L'alerte sur l'expiration prochaine d'un certificat est détectée à chaque "
        "analyse, donc au rythme de la surveillance. Une détection quotidienne "
        "indépendante du cycle d'analyse reste à ajouter.",
        "La suite de tests automatisés couvre les invariants de sécurité et le "
        "moteur de comparaison. Elle ne couvre pas l'interface.",
    ])

    sous_titre(pdf, "Décisions dont le raisonnement mérite l'attention")
    puces(pdf, [
        "Une alerte n'est émise que sur un changement. Alerter sur un état ferait "
        "produire trente messages identiques à un certificat expirant dans trente "
        "jours, et le destinataire couperait ses notifications. Un premier scan est "
        "traité comme un changement depuis rien.",
        "Les scores sont ramenés sur cent avant toute moyenne. Un dépôt GitHub est "
        "noté sur trente ; mêler les barèmes ferait passer un dépôt parfait pour un "
        "actif en perdition.",
        "Un actif ne compte qu'une fois dans la posture d'un client, par son dernier "
        "scan. Sinon la mesure refléterait l'assiduité plutôt que la sécurité.",
        "Les jetons d'accès aux dépôts sont chiffrés au repos. Ils portent un droit "
        "d'écriture : une fuite de la base donnerait accès au code des clients.",
        "L'administrateur ne peut pas écrire dans une conversation, ni signer un "
        "contrat, ni noter un expert à la place d'un client.",
    ])

    sous_titre(pdf, "Vérifiabilité")
    para(pdf, "L'ensemble du code est publié sur les deux dépôts indiqués en "
              "couverture. L'historique des modifications documente chaque décision "
              "et les mesures qui l'ont motivée : durées relevées, écarts constatés, "
              "défauts trouvés et corrigés.")

    encadre(pdf, "En cas de difficulté pendant l'évaluation", [
        "Une analyse qui semble figée : la page de progression suit l'exécution "
        "réelle des outils ; certaines cibles répondent lentement.",
        "Une réponse de l'assistant qui tarde : le serveur d'inférence est partagé, "
        "le bouton d'arrêt reste disponible.",
        f"La plateforme reste accessible à l'adresse {URL.replace('https://', '')}.",
    ])


def generer(chemin="guide-evaluation-cyberguardian.pdf") -> str:
    pdf = Guide()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.set_margins(20, 16, 20)
    _register_fonts(pdf)

    page_couverture(pdf)
    page_acces(pdf)
    page_fonctionnalites(pdf)
    page_tests(pdf)
    page_limites(pdf)

    pdf.output(chemin)
    return chemin


if __name__ == "__main__":
    fichier = generer()
    print(f"  guide écrit dans {fichier}")

"""
Rejeu du moteur de comparaison sur l'historique, pour chiffrer H3.

L'hypothèse H3 soutient que la détection d'écarts entre deux mesures produit
des alertes plus exploitables que l'évaluation d'un état. Elle se vérifie par
rejeu : le moteur ne dépendant ni de la base ni du réseau, on peut lui
soumettre les analyses déjà accumulées et compter ce que chaque règle aurait
émis.

Deux règles sont confrontées sur le même corpus :

    règle de l'écart   comparer(précédent, courant) pour chaque analyse, et
                       comparer(None, courant) pour la première d'un couple.
                       C'est le comportement réel de la plateforme.

    règle de l'état    comparer(None, courant) pour chaque analyse, sans
                       exception. C'est ce qu'un dispositif fondé sur l'état
                       courant aurait émis à chaque passage.

Trois choix de méthode, imposés par la production et par les données :

  - le regroupement se fait sur le couple (propriétaire, cible), et non sur la
    cible seule, parce que la production cherche le scan précédent du même
    propriétaire. Plusieurs cibles de la base ont été analysées par des comptes
    différents, les confondre fabriquerait des transitions qui n'ont pas eu lieu ;
  - l'ordre chronologique est reconstitué à partir de l'identifiant et non de
    la date, une majorité des lignes n'ayant pas d'horodatage renseigné.
    L'identifiant est attribué à l'insertion, l'ordre est donc le bon ;
  - un silence est constaté par type d'alerte et non par intitulé : le même
    événement produit deux libellés différents selon la règle, puisque l'un
    énumère tout l'état observé et l'autre le seul écart.

Le script ne modifie rien : il n'ouvre qu'une session de lecture, et les noms
de cible sont remplacés par un identifiant anonyme, les résultats étant
destinés à un document déposé.

Usage, depuis le dossier backend/ :
    python mesurer_h3.py              synthèse
    python mesurer_h3.py --detail     + le détail couple par couple
"""

import sys
from collections import Counter, OrderedDict

from database import SessionLocal
from models import Scan
from services.comparaison import comparer

# Ordre d'affichage des types, du plus grave au moins grave, pour que les deux
# répartitions se lisent ligne à ligne.
TYPES = ["secret", "cve", "port", "ssl", "reputation", "score"]

LIBELLES = {
    "secret":     "Secret exposé",
    "cve":        "Vulnérabilité grave",
    "port":       "Port sensible ouvert",
    "ssl":        "Certificat",
    "reputation": "Réputation",
    "score":      "Chute de score",
}


def charger(db) -> "OrderedDict[tuple, list]":
    """Analyses terminées, groupées par couple (propriétaire, cible) et
    ordonnées par identifiant croissant.

    Les analyses sans propriétaire sont écartées : la production ne les compare
    jamais, faute de destinataire à prévenir."""
    scans = (db.query(Scan)
             .filter(Scan.status == "completed", Scan.user_id.isnot(None))
             .order_by(Scan.id)
             .all())

    couples: "OrderedDict[tuple, list]" = OrderedDict()
    for scan in scans:
        # La cible n'est pas normalisée : la production compare les chaînes
        # telles quelles, une différence de casse y sépare bel et bien deux
        # historiques. Le rejeu doit reproduire ce comportement, pas le corriger.
        couples.setdefault((scan.user_id, scan.target), []).append(scan)
    return couples


def rejouer(couples) -> dict:
    """Applique les deux règles et relève tout ce qui sera rapporté."""
    bilan = {
        "analyses":        0,
        "couples":         len(couples),
        "transitions":     0,
        "etat_alertes":    0,
        "ecart_alertes":   0,
        "etat_messages":   0,   # une notification groupée par analyse alertante
        "ecart_messages":  0,
        "etat_types":      Counter(),
        "ecart_types":     Counter(),
        "silences":        0,
        "silences_justifies":     0,
        "silences_non_justifies": [],
        "detail":          [],
    }

    for rang, ((_, cible), scans) in enumerate(couples.items(), 1):
        # Identifiant anonyme : le mémoire est déposé, les cibles analysées
        # appartiennent à des tiers.
        anonyme = f"C{rang:02d}"
        nature  = "dépôt" if scans[0].type == "github" else "réseau"
        deja_signales: set[str] = set()      # types déjà alertés par la règle de l'écart
        lignes_detail = []

        precedent = None
        for scan in scans:
            courant = scan.to_dict()
            bilan["analyses"] += 1

            etat  = comparer(None, courant)
            ecart = comparer(precedent, courant)
            if precedent is not None:
                bilan["transitions"] += 1

            bilan["etat_alertes"]  += len(etat)
            bilan["ecart_alertes"] += len(ecart)
            bilan["etat_messages"]  += 1 if etat else 0
            bilan["ecart_messages"] += 1 if ecart else 0
            for a in etat:
                bilan["etat_types"][a.type] += 1
            for a in ecart:
                bilan["ecart_types"][a.type] += 1

            # Un silence : un type que la règle de l'état aurait signalé et que
            # la règle de l'écart tait. Il est justifié si le propriétaire avait
            # déjà reçu cette information lors d'un passage antérieur.
            types_ecart = {a.type for a in ecart}
            for a in etat:
                if a.type in types_ecart:
                    continue
                bilan["silences"] += 1
                if a.type in deja_signales:
                    bilan["silences_justifies"] += 1
                    verdict = "justifié"
                else:
                    bilan["silences_non_justifies"].append({
                        "cible":  anonyme,
                        "nature": nature,
                        "scan":   scan.id,
                        "type":   a.type,
                        "titre":  a.titre,
                    })
                    verdict = "NON JUSTIFIÉ"
                lignes_detail.append(
                    f"      silence sur « {LIBELLES.get(a.type, a.type)} » : {verdict}"
                )

            deja_signales.update(types_ecart)
            lignes_detail.append(
                f"    scan {scan.id:>4} : état {len(etat)} alerte(s), "
                f"écart {len(ecart)} alerte(s)"
            )
            precedent = courant

        bilan["detail"].append((anonyme, nature, len(scans), lignes_detail))

    return bilan


def afficher(b: dict, detail: bool) -> None:
    trait = "-" * 68
    print()
    print("=" * 68)
    print("  REJEU DU MOTEUR DE COMPARAISON SUR L'HISTORIQUE".center(68))
    print("=" * 68)

    print(f"\nCorpus")
    print(trait)
    print(f"  Analyses rejouées                        {b['analyses']:>6}")
    print(f"  Couples (propriétaire, cible) distincts  {b['couples']:>6}")
    print(f"  Transitions entre analyses consécutives  {b['transitions']:>6}")

    etat, ecart = b["etat_alertes"], b["ecart_alertes"]
    reduction = (etat - ecart) / etat * 100 if etat else 0.0
    print(f"\nAlertes émises")
    print(trait)
    print(f"  Règle de l'état                          {etat:>6}")
    print(f"  Règle de l'écart                         {ecart:>6}")
    print(f"  Réduction                                {reduction:>5.1f} %")

    me, mc = b["etat_messages"], b["ecart_messages"]
    red_m = (me - mc) / me * 100 if me else 0.0
    print(f"\nNotifications reçues (une par analyse alertante)")
    print(trait)
    print(f"  Règle de l'état                          {me:>6}")
    print(f"  Règle de l'écart                         {mc:>6}")
    print(f"  Réduction                                {red_m:>5.1f} %")

    print(f"\nRépartition par type de cas")
    print(trait)
    print(f"  {'Type':<24}{'état':>8}{'écart':>8}{'écart / état':>16}")
    for t in TYPES:
        e, c = b["etat_types"].get(t, 0), b["ecart_types"].get(t, 0)
        if not (e or c):
            continue
        part = f"{c / e * 100:.0f} %" if e else "-"
        print(f"  {LIBELLES.get(t, t):<24}{e:>8}{c:>8}{part:>16}")

    nj = b["silences_non_justifies"]
    print(f"\nSilences")
    print(trait)
    print(f"  Total                                    {b['silences']:>6}")
    print(f"  Justifiés (déjà signalé auparavant)      {b['silences_justifies']:>6}")
    print(f"  Non justifiés                            {len(nj):>6}")

    if nj:
        print(f"\n  Détail des silences non justifiés :")
        for s in nj:
            print(f"    {s['cible']} ({s['nature']}), scan {s['scan']} - "
                  f"{LIBELLES.get(s['type'], s['type'])}")
            print(f"      {s['titre']}")
    else:
        print("\n  Aucun silence non justifié : tout constat tu par la règle de")
        print("  l'écart avait déjà été signalé au propriétaire auparavant.")

    if detail:
        print(f"\nDétail par couple")
        print(trait)
        for anonyme, nature, n, lignes in b["detail"]:
            print(f"\n  {anonyme} ({nature}, {n} analyse(s))")
            for l in lignes:
                print(l)

    print()


if __name__ == "__main__":
    db = SessionLocal()
    try:
        couples = charger(db)
        if not couples:
            print("Aucune analyse terminée dans la base : rien à rejouer.")
            sys.exit(0)
        afficher(rejouer(couples), detail="--detail" in sys.argv)
    finally:
        db.close()

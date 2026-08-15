"""
Passages de surveillance : réanalyse les actifs dont l'échéance est venue.

Script autonome, appelé par un ordonnanceur du système et non par
l'application. Ce choix a trois raisons. Un fil interne à uvicorn se
dédoublerait à chaque rechargement en développement ; il disparaîtrait à chaque
redémarrage du service sans que rien ne le signale ; et il n'aurait aucune
trace consultable, alors qu'ici journalctl conserve tout. Aucune dépendance
n'est ajoutée non plus, là où un ordonnanceur applicatif en demanderait une.

Le script ne contient aucune logique d'analyse ni d'alerte : il crée des scans
ordinaires, qui empruntent le chemin habituel et déclenchent la comparaison
avec le scan précédent déjà en place. Il ne décide que du « quoi » et du
« quand ».

Usage, depuis le dossier backend/ :
    python taches_planifiees.py             exécute les passages dus
    python taches_planifiees.py --a-blanc   les affiche sans rien lancer
    python taches_planifiees.py --limite 5  s'arrête après cinq actifs

Installation d'un passage quotidien, la nuit :

    /etc/systemd/system/cyberguardian-surveillance.service
        [Service]
        Type=oneshot
        WorkingDirectory=/var/www/cyberguardian/backend
        ExecStart=/var/www/cyberguardian/backend/venv/bin/python taches_planifiees.py

    /etc/systemd/system/cyberguardian-surveillance.timer
        [Timer]
        OnCalendar=*-*-* 03:00:00
        Persistent=true
        [Install]
        WantedBy=timers.target

    systemctl enable --now cyberguardian-surveillance.timer
"""

import sys
import time

from database import SessionLocal
from horodatage import maintenant_iso
from models import Scan
from services.surveillance import echues, enregistrer_passage

# Les analyses s'enchaînent une par une, avec une pause entre deux cibles. Un
# scan mobilise nmap et plusieurs services tiers pendant une minute environ ;
# vingt lancés de front saturent la machine et ressemblent, vues du dehors, à
# une reconnaissance agressive.
PAUSE_ENTRE_CIBLES = 20


def executer(a_blanc: bool = False, limite: int | None = None) -> int:
    db = SessionLocal()
    try:
        dues = echues(db, limite)
        if not dues:
            print("  aucun actif à réanalyser")
            return 0

        print(f"  {len(dues)} actif(s) à réanalyser")
        for surveillance in dues:
            print(f"    [{surveillance.frequence}] {surveillance.target} "
                  f"(échéance {surveillance.prochain_passage})")
        if a_blanc:
            print("\n  exécution à blanc, rien n'a été lancé")
            return len(dues)

        # Import tardif : charger le routeur des scans tire tout l'outillage
        # d'analyse, inutile lorsqu'il n'y a rien à faire ou en exécution à blanc.
        from routers.scans import creer_et_executer

        faits = 0
        for i, surveillance in enumerate(dues):
            if i:
                time.sleep(PAUSE_ENTRE_CIBLES)
            # Pas de caractère hors Latin-1 dans les sorties : la console
            # Windows utilise cp1252 et lève une exception sur une flèche.
            print(f"\n  >> {surveillance.target}")
            try:
                # Sans rédaction : personne ne lit un rapport écrit la nuit, et
                # le modèle tourne sur un serveur mutualisé. Le texte sera
                # produit au premier téléchargement du PDF.
                scan_id = creer_et_executer(surveillance.user_id, surveillance.target,
                                            surveillance.asset_type, redaction=False)
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                etat = scan.status if scan else "inconnu"
                print(f"    scan {scan_id} : {etat}"
                      + (f", score {scan.score}" if scan and scan.score is not None else ""))
                enregistrer_passage(db, surveillance, scan)
                faits += 1
            except Exception as e:
                # Un actif injoignable ne doit pas emporter les suivants.
                # L'échéance est repoussée malgré tout : sans cela le même actif
                # serait retenté à chaque passage, indéfiniment.
                print(f"    [!] échec sur {surveillance.target} : {type(e).__name__} : {e}")
                enregistrer_passage(db, surveillance, None)
        return faits
    finally:
        db.close()


if __name__ == "__main__":
    a_blanc = "--a-blanc" in sys.argv
    limite = None
    if "--limite" in sys.argv:
        try:
            limite = int(sys.argv[sys.argv.index("--limite") + 1])
        except (IndexError, ValueError):
            sys.exit("--limite attend un nombre")

    print(f"=== Surveillance CyberGuardian, {maintenant_iso()} ===\n")
    faits = executer(a_blanc=a_blanc, limite=limite)
    print(f"\n{faits} passage(s) effectué(s).")

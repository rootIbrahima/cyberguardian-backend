"""
État de santé de la plateforme, pour la console d'administration.

Une journée entière a été consacrée à diagnostiquer un webhook Telegram déclaré
sur la mauvaise URL, un PUBLIC_BASE_URL amputé de son préfixe et un canal
e-mail non configuré. Aucun de ces défauts n'était visible depuis la
plateforme : il fallait interroger l'API Telegram à la main et lire un .env en
SSH. Rien ne se voyait, et pendant ce temps les clients ne recevaient plus
leurs alertes.

Chaque contrôle rend un état sur trois valeurs, et la nuance compte :

    ok       le service fonctionne
    alerte   il devrait fonctionner et ne fonctionne pas
    absent   il n'est pas configuré, ce qui peut être un choix

Confondre « en panne » et « pas installé » ferait clignoter en rouge une
plateforme parfaitement saine, et le rouge cesserait vite d'être lu.

Les sondes réseau sont menées de front : le serveur d'inférence est mutualisé
et répond parfois en cinq secondes, trois contrôles en file d'attente feraient
attendre la page une quinzaine de secondes.
"""

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from config import (ABUSEIPDB_API_KEY, FRONTEND_URL, OLLAMA_KEY, OLLAMA_MODEL,
                    OLLAMA_URL, PUBLIC_BASE_URL, SMTP_HOST, SMTP_PASSWORD,
                    SMTP_USER, TELEGRAM_BOT_TOKEN, TELEGRAM_BOT_USERNAME,
                    VIRUSTOTAL_API_KEY, incoherences)
from horodatage import ecoule_depuis, maintenant
from models import Notification, Scan

# Au-delà, un scan « en cours » ne l'est plus : le processus qui le portait a
# disparu et le client reste devant une page de progression qui tourne à vide.
MINUTES_SCAN_BLOQUE = 20

_DELAI = httpx.Timeout(connect=5.0, read=12.0, write=5.0, pool=5.0)


def _pluriel(nombre: int, singulier: str, pluriel: str) -> str:
    """Accorde le libellé au nombre. Les formes « 1 envoi(s) » et
    « 1 destinataire(s) concerné(s) » se lisent comme un décompte de machine et
    font douter le lecteur de ce qu'on lui annonce."""
    return f"{nombre} {singulier if nombre <= 1 else pluriel}"


def _bloc(cle: str, titre: str, etat: str, detail: str, **extra) -> dict:
    return {"cle": cle, "titre": titre, "etat": etat, "detail": detail, **extra}


# ── Sondes réseau ─────────────────────────────────────────────────────────────

def _telegram() -> dict:
    """Le webhook est le seul endroit où se voit une livraison en échec : le
    bot ne peut pas signaler qu'il ne reçoit rien."""
    if not TELEGRAM_BOT_TOKEN:
        return _bloc("telegram", "Telegram", "absent", "Aucun bot configuré")

    api = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"
    try:
        bot  = httpx.get(f"{api}/getMe", timeout=_DELAI).json().get("result", {})
        info = httpx.get(f"{api}/getWebhookInfo", timeout=_DELAI).json().get("result", {})
    except Exception as e:
        return _bloc("telegram", "Telegram", "alerte",
                     f"API Telegram injoignable ({type(e).__name__})")

    reel = bot.get("username", "")
    if reel and TELEGRAM_BOT_USERNAME != reel:
        return _bloc("telegram", "Telegram", "alerte",
                     f"TELEGRAM_BOT_USERNAME vaut « {TELEGRAM_BOT_USERNAME} » "
                     f"alors que le bot est @{reel} : les liens de liaison "
                     f"mènent ailleurs")

    if not info.get("url"):
        return _bloc("telegram", "Telegram", "alerte",
                     f"@{reel} n'a aucun webhook déclaré, il ne recevra rien")

    erreur = info.get("last_error_message")
    if erreur:
        detail = f"Dernière livraison en échec : {erreur}"
        if "405" in erreur:
            detail += " — le préfixe du reverse proxy manque dans l'URL déclarée"
        return _bloc("telegram", "Telegram", "alerte", detail, webhook=info["url"])

    attente = info.get("pending_update_count", 0)
    return _bloc("telegram", "Telegram", "ok",
                 f"@{reel} · {attente} message(s) en attente",
                 webhook=info["url"])


def _modele() -> dict:
    """Un modèle déchargé n'est pas une panne, mais le premier client de la
    journée paiera son rechargement : l'information mérite d'être lue."""
    if not OLLAMA_URL:
        return _bloc("modele", "Modèle de langage", "absent", "Aucun serveur configuré")

    debut = time.perf_counter()
    try:
        reponse = httpx.get(f"{OLLAMA_URL}/api/ps",
                            headers={"Authorization": f"Bearer {OLLAMA_KEY}"},
                            timeout=_DELAI)
        reponse.raise_for_status()
        charges = [m.get("model") or m.get("name") for m in reponse.json().get("models", [])]
    except Exception as e:
        return _bloc("modele", "Modèle de langage", "alerte",
                     f"{OLLAMA_URL} injoignable ({type(e).__name__}) : "
                     f"rapports rédigés et assistant indisponibles")

    ms = int((time.perf_counter() - debut) * 1000)
    if OLLAMA_MODEL in charges:
        return _bloc("modele", "Modèle de langage", "ok",
                     f"{OLLAMA_MODEL} chargé en mémoire · réponse en {ms} ms")
    return _bloc("modele", "Modèle de langage", "ok",
                 f"{OLLAMA_MODEL} déchargé, le prochain rapport paiera son "
                 f"chargement · réponse en {ms} ms")


def _url_publique() -> dict:
    """PUBLIC_BASE_URL doit atteindre FastAPI, pas les fichiers statiques.
    C'est là-dessus que se construit le retour d'autorisation GitHub."""
    if not PUBLIC_BASE_URL:
        return _bloc("url", "URL publique", "absent",
                     "PUBLIC_BASE_URL vide : l'autorisation GitHub renverra 503")
    try:
        reponse = httpx.get(f"{PUBLIC_BASE_URL}/openapi.json", timeout=_DELAI)
    except Exception as e:
        return _bloc("url", "URL publique", "alerte",
                     f"{PUBLIC_BASE_URL} injoignable ({type(e).__name__})")

    type_contenu = reponse.headers.get("content-type", "")
    if reponse.status_code == 200 and "json" in type_contenu:
        return _bloc("url", "URL publique", "ok",
                     f"{PUBLIC_BASE_URL} atteint bien l'API")

    if reponse.status_code in (502, 503, 504):
        cause = "le proxy répond mais rien n'écoute derrière"
    elif "html" in type_contenu:
        cause = "cette URL mène aux fichiers statiques, le préfixe du proxy y manque"
    else:
        cause = f"réponse {reponse.status_code} inattendue"
    return _bloc("url", "URL publique", "alerte", f"{PUBLIC_BASE_URL} : {cause}")


# ── Contrôles locaux ──────────────────────────────────────────────────────────

def _email() -> dict:
    if not SMTP_HOST:
        return _bloc("email", "Alertes e-mail", "absent",
                     "Aucun compte d'envoi : les alertes ne partent que sur Telegram")
    if not (SMTP_USER and SMTP_PASSWORD):
        return _bloc("email", "Alertes e-mail", "alerte",
                     "SMTP_HOST renseigné mais l'identifiant ou le mot de passe manque")
    return _bloc("email", "Alertes e-mail", "ok", f"{SMTP_USER} via {SMTP_HOST}")


def _reputation() -> dict:
    """Sans clé, le critère de réputation est exclu du score au lieu d'être
    compté à zéro : les scores restent justes, mais reposent sur un critère de
    moins, ce que rien n'indique aujourd'hui."""
    presentes = [nom for nom, cle in (("VirusTotal", VIRUSTOTAL_API_KEY),
                                      ("AbuseIPDB", ABUSEIPDB_API_KEY)) if cle]
    if len(presentes) == 2:
        return _bloc("reputation", "Réputation des actifs", "ok",
                     "VirusTotal et AbuseIPDB interrogés")
    if presentes:
        return _bloc("reputation", "Réputation des actifs", "alerte",
                     f"Seul {presentes[0]} est configuré, l'autre source manque")
    return _bloc("reputation", "Réputation des actifs", "absent",
                 "Aucune clé : le critère est exclu du score, qui porte sur quatre "
                 "critères au lieu de cinq")


def _configuration() -> dict:
    ecarts = incoherences()
    if ecarts:
        return _bloc("config", "Cohérence du .env", "alerte",
                     " · ".join(e.splitlines()[0] for e in ecarts), ecarts=ecarts)
    return _bloc("config", "Cohérence du .env", "ok",
                 f"Backend {PUBLIC_BASE_URL or '—'} · site {FRONTEND_URL}")


def _remises(db: Session) -> dict:
    """Notifications dont l'envoi externe a échoué sur les sept derniers jours.

    Un Telegram délié, un SMTP en refus ou une adresse devenue invalide
    laissaient jusqu'ici un client sans ses alertes, sans que la plateforme en
    sache rien. Les notifications antérieures au suivi ont un état nul et sont
    donc ignorées : leur sort n'a pas été enregistré."""
    depuis = (maintenant() - timedelta(days=7)).isoformat(timespec="seconds")
    recentes = (db.query(Notification)
                .filter(Notification.created_at >= depuis,
                        Notification.remise_etat.isnot(None)))

    # Seuls les échecs dont la cause a été enregistrée sont retenus. Les autres
    # datent d'avant le suivi canal par canal, où un envoi était marqué en échec
    # dès qu'un seul canal échouait, même si un autre avait remis le message :
    # ils ne permettent pas de dire si le destinataire a été privé de son
    # alerte. Alerter dessus ferait chercher une panne qui n'existe peut-être
    # pas, et c'est exactement ce qui vient de se produire.
    echecs = recentes.filter(Notification.remise_etat == "echec",
                             Notification.remise_erreur.isnot(None)).all()
    indetermines = recentes.filter(Notification.remise_etat == "echec",
                                   Notification.remise_erreur.is_(None)).count()
    total = recentes.count()
    # Un canal peut échouer sans que le destinataire soit privé de l'alerte, un
    # autre ayant pris le relais. La remise est alors réussie, mais le canal
    # fautif demande tout de même une correction : le taire le rendrait
    # définitivement invisible.
    boiteux = (recentes.filter(Notification.remise_etat == "ok",
                               Notification.remise_erreur.isnot(None)).all())

    if not total:
        # Pas d'envoi n'est pas un défaut de configuration : les canaux peuvent
        # être en parfait état sans qu'aucun événement ne se soit produit.
        # Classer ce cas en « absent » faisait annoncer « 1 non configuré » à
        # une plateforme dont tous les canaux fonctionnaient.
        return _bloc("remises", "Remise des notifications", "ok",
                     "Aucun envoi à signaler sur les sept derniers jours")
    if not echecs and not boiteux:
        detail = f"{_pluriel(total, 'envoi', 'envois')} sur sept jours, aucun échec"
        if indetermines:
            # Mentionné sans alerter : l'information existe, elle ne conclut rien.
            reste = _pluriel(
                indetermines,
                "envoi plus ancien reste indéterminé, sa cause n'ayant pas été enregistrée",
                "envois plus anciens restent indéterminés, leur cause n'ayant pas été enregistrée",
            )
            detail += f" — {reste}"
        return _bloc("remises", "Remise des notifications", "ok", detail)

    if not echecs:
        motifs = sorted({b.remise_erreur for b in boiteux if b.remise_erreur})
        detail = (f"{_pluriel(len(boiteux), 'envoi a', 'envois ont')} emprunté un canal "
                  f"en panne sur {total}, mais le destinataire a été prévenu par un autre")
        return _bloc("remises", "Remise des notifications", "alerte",
                     detail + (f" — {motifs[0]}" if motifs else ""))

    destinataires = {e.user_id for e in echecs}
    motifs = sorted({e.remise_erreur for e in echecs if e.remise_erreur})

    # Une phrase, pas un décompte. « 1 envoi(s) en échec sur 12, 1
    # destinataire(s) concerné(s) » énonçait des chiffres justes sans dire ce
    # qui s'était passé ni s'il fallait agir.
    manquees = _pluriel(len(echecs), "notification n'a", "notifications n'ont")
    prives   = _pluriel(len(destinataires),
                        "client est resté sans son information",
                        "clients sont restés sans leur information")
    detail = f"{manquees} atteint personne sur {total} : {prives}"
    detail += f". Cause : {motifs[0]}"
    if boiteux:
        detail += (f". Par ailleurs, {_pluriel(len(boiteux), 'envoi a', 'envois ont')} "
                   f"emprunté un canal en panne sans conséquence pour le destinataire")
    return _bloc("remises", "Remise des notifications", "alerte", detail)


def _scans(db: Session) -> dict:
    """Un scan en échec ou figé n'est signalé nulle part : le client reste
    devant une page de progression, et personne côté plateforme ne l'apprend."""
    echecs = (db.query(Scan).filter(Scan.status == "failed")
              .order_by(Scan.id.desc()).limit(10).all())

    bloques = []
    for scan in db.query(Scan).filter(Scan.status == "running").all():
        age = ecoule_depuis(scan.created_at)
        if age and age.total_seconds() > MINUTES_SCAN_BLOQUE * 60:
            bloques.append(scan)

    details = [{"id": s.id, "cible": s.target, "date": s.date,
                "cause": "échec"} for s in echecs]
    details += [{"id": s.id, "cible": s.target, "date": s.date,
                 "cause": "figé en cours"} for s in bloques]

    total = db.query(func.count(Scan.id)).scalar() or 0
    if not details:
        return _bloc("scans", "Scans", "ok", f"{total} scans, aucun en échec")
    return _bloc("scans", "Scans", "alerte",
                 f"{len(echecs)} en échec, {len(bloques)} figé(s) depuis plus de "
                 f"{MINUTES_SCAN_BLOQUE} minutes",
                 anomalies=details)


# ── Assemblage ────────────────────────────────────────────────────────────────

def etat_complet(db: Session) -> dict:
    """État de tous les services. Les sondes réseau sont lancées ensemble :
    menées l'une après l'autre, elles cumuleraient leurs délais."""
    with ThreadPoolExecutor(max_workers=3) as pool:
        reseau = [f.result() for f in
                  [pool.submit(_telegram), pool.submit(_modele), pool.submit(_url_publique)]]

    controles = reseau + [_email(), _reputation(), _configuration(),
                          _remises(db), _scans(db)]
    ordre = {"alerte": 0, "absent": 1, "ok": 2}
    controles.sort(key=lambda c: ordre[c["etat"]])

    return {
        "controles": controles,
        "alertes":   sum(1 for c in controles if c["etat"] == "alerte"),
        "absents":   sum(1 for c in controles if c["etat"] == "absent"),
    }

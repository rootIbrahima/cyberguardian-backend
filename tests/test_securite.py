"""
Tests des invariants de sécurité de la plateforme.

Ces contrôles portent sur les propriétés qui, si elles se cassaient, exposeraient
les clients : périmètre des scans, cloisonnement des rapports, authenticité du
webhook, confidentialité des jetons et robustesse des mots de passe. Ils ne
dépendent ni de la base de données ni du réseau, hormis la résolution DNS
publique nécessaire au garde-fou de cibles.

Lancement, depuis le dossier backend/ :
    python -m pytest tests/ -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from auth import besoin_rehachage, hash_password, verify_password          # noqa: E402
from services.chiffrement import chiffrer, dechiffrer                       # noqa: E402
from tools.target_guard import (                                            # noqa: E402
    CibleInterdite,
    extraire_hote,
    resoudre_et_valider,
)


# ── Périmètre des scans : aucune cible interne ────────────────────────────────

@pytest.mark.parametrize("cible", [
    "127.0.0.1",            # boucle locale
    "10.0.0.1",             # réseau privé classe A
    "192.168.1.1",          # réseau privé classe C
    "172.16.0.5",           # réseau privé classe B
    "169.254.169.254",      # métadonnées des hébergeurs cloud
    "0.0.0.0",              # nosec B104, cible de test refusée, aucune écoute réseau
    "::1",                  # boucle locale IPv6
    "localhost",            # nom résolvant vers la boucle locale
    "http://127.0.0.1:8001",
])
def test_cible_interne_refusee(cible):
    with pytest.raises(CibleInterdite):
        resoudre_et_valider(cible)


@pytest.mark.parametrize("cible", ["scanme.nmap.org", "8.8.8.8", "https://example.com/page"])
def test_cible_publique_acceptee(cible):
    hote, ip = resoudre_et_valider(cible)
    assert hote and ip


def test_cible_non_resolvable_refusee():
    with pytest.raises(CibleInterdite):
        resoudre_et_valider("domaine-qui-nexiste-pas-cyberguardian.invalid")


@pytest.mark.parametrize("brut,attendu", [
    ("https://cei.unchk.sn/page?x=1", "cei.unchk.sn"),
    ("http://example.com",            "example.com"),
    ("example.com:8080",              "example.com"),
    ("[2001:db8::1]:443",             "2001:db8::1"),
])
def test_extraction_hote(brut, attendu):
    assert extraire_hote(brut) == attendu


def test_extraction_hote_conserve_le_port_si_demande():
    assert extraire_hote("example.com:8080", garder_port=True) == "example.com:8080"


# ── Confidentialité des jetons stockés ────────────────────────────────────────

def test_chiffrement_aller_retour():
    jeton = "gho_jetonDeTestQuiNeDoitPasFuiter1234567890"
    chiffre = chiffrer(jeton)
    assert jeton not in chiffre, "le jeton ne doit jamais apparaître en clair"
    assert dechiffrer(chiffre) == jeton


def test_dechiffrement_valeur_historique_non_prefixee():
    """Un jeton antérieur au chiffrement reste lisible (migration sans rupture)."""
    assert dechiffrer("jeton-en-clair-historique") == "jeton-en-clair-historique"


# ── Mots de passe ─────────────────────────────────────────────────────────────

def test_hachage_bcrypt():
    empreinte = hash_password("MotDePasseSolide2026!")
    assert empreinte.startswith(("$2a$", "$2b$", "$2y$"))
    assert verify_password("MotDePasseSolide2026!", empreinte)
    assert not verify_password("mauvais-mot-de-passe", empreinte)
    assert not besoin_rehachage(empreinte)


def test_ancien_hachage_sha256_toujours_accepte():
    """Les comptes créés avant la migration doivent pouvoir se connecter,
    et être signalés comme à re-hacher."""
    from passlib.hash import sha256_crypt

    ancien = sha256_crypt.hash("Client2026!")
    assert verify_password("Client2026!", ancien)
    assert not verify_password("autre", ancien)
    assert besoin_rehachage(ancien)


def test_empreinte_vide_refusee():
    assert not verify_password("peu importe", "")


# ── Authenticité du webhook Telegram ──────────────────────────────────────────

# ── Réputation : le critère ne doit jamais pénaliser à tort ───────────────────

def test_reputation_sans_cle_est_exclue_du_score(monkeypatch):
    """Sans clé configurée, le critère vaut None (exclu du calcul) et non zéro :
    une mesure absente n'est pas un risque avéré."""
    from tools import check_reputation as mod

    monkeypatch.setattr(mod, "VIRUSTOTAL_API_KEY", "")
    monkeypatch.setattr(mod, "ABUSEIPDB_API_KEY", "")
    r = mod.check_reputation("example.com")
    assert r.score is None
    assert r.error and "clé" in r.error.lower()


def test_reputation_penalise_les_signalements():
    """Le barème doit distinguer une cible saine d'une cible signalée."""
    from tools.check_reputation import ReputationResult, _calculate_score

    saine = ReputationResult(target="x", vt_disponible=True, vt_total_moteurs=70,
                             abuse_disponible=True, abuse_score=0)
    assert _calculate_score(saine) == 15

    signalee = ReputationResult(target="x", vt_disponible=True, vt_malveillant=4,
                                vt_total_moteurs=70, abuse_disponible=True,
                                abuse_score=90)
    assert _calculate_score(signalee) == 0

    moderee = ReputationResult(target="x", vt_disponible=True, vt_malveillant=1,
                               vt_total_moteurs=70, abuse_disponible=True,
                               abuse_score=30)
    assert 0 < _calculate_score(moderee) < 15


def test_score_global_couvre_cent_points():
    """Les cinq critères réunis totalisent bien 100 points."""
    from tools.calculate_score import WEIGHTS

    assert sum(WEIGHTS.values()) == 100
    detail = __import__("tools.calculate_score", fromlist=["calculate_score"]).calculate_score(
        {"dns": 25, "ssl": 25, "headers": 20, "ports": 15, "reputation": 15}
    )
    assert detail["score"] == 100
    assert detail["not_evaluated"] == []


@pytest.fixture
def client_webhook():
    """Application minimale exposant uniquement le routeur Telegram, pour tester
    le filtrage sans dépendre du reste de la plateforme."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from routers import telegram_webhook

    app = FastAPI()
    app.include_router(telegram_webhook.router)
    return TestClient(app), telegram_webhook


@pytest.mark.parametrize("entete", [None, "", "mauvais-secret"])
def test_webhook_refuse_secret_absent_ou_faux(client_webhook, monkeypatch, entete):
    """Sans le bon en-tête, la requête est rejetée : sinon quiconque connaît
    l'URL publique peut forger un message au nom d'un utilisateur lié."""
    client, module = client_webhook
    monkeypatch.setattr(module, "TELEGRAM_WEBHOOK_SECRET", "secret-de-test")

    entetes = {} if entete is None else {"X-Telegram-Bot-Api-Secret-Token": entete}
    reponse = client.post("/telegram/webhook", json={"message": {"text": "bonjour"}},
                          headers=entetes)
    assert reponse.status_code == 403


def test_webhook_accepte_le_bon_secret(client_webhook, monkeypatch):
    client, module = client_webhook
    monkeypatch.setattr(module, "TELEGRAM_WEBHOOK_SECRET", "secret-de-test")

    # Charge utile sans chat_id : le handler renvoie {"ok": True} sans rien traiter,
    # ce qui suffit à prouver que le filtrage a laissé passer la requête.
    reponse = client.post("/telegram/webhook", json={"message": {}},
                          headers={"X-Telegram-Bot-Api-Secret-Token": "secret-de-test"})
    assert reponse.status_code == 200

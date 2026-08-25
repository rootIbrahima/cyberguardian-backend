"""
Tests du repli entre modèles de langage.

Le serveur d'inférence mutualisé a connu deux pannes prolongées en deux jours :
l'API répondait en moins d'une seconde tandis qu'aucune génération n'aboutissait.
Ces contrôles vérifient qu'un fournisseur de secours prend alors le relais, et
surtout qu'il ne le prend pas quand la source première fonctionne — les invites
portent les vulnérabilités des actifs de nos clients, elles ne doivent pas
quitter le pays sans nécessité.

Lancement, depuis le dossier backend/ :
    python -m pytest tests/test_modele.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import services.modele as M                                                   # noqa: E402


@pytest.fixture
def secours_actif(monkeypatch):
    """Simule un fournisseur de secours renseigné dans .env."""
    monkeypatch.setattr(M, "secours_configure", lambda: True)


def _casse(*a, **k):
    raise RuntimeError("serveur d'inférence bloqué")


# ── Texte complet ─────────────────────────────────────────────────────────────

def test_source_premiere_seule_quand_elle_repond(monkeypatch):
    """Le secours n'est pas sollicité : les données restent au Sénégal."""
    appels = []
    monkeypatch.setattr(M, "_ollama", lambda p, j: "réponse locale")
    monkeypatch.setattr(M, "_secours", lambda p, j: appels.append(1) or "secours")
    assert M.generer("question") == "réponse locale"
    assert appels == [], "le secours a été appelé alors que la source répondait"


def test_repli_lorsque_la_source_est_bloquee(monkeypatch, secours_actif):
    monkeypatch.setattr(M, "_ollama", _casse)
    monkeypatch.setattr(M, "_secours", lambda p, j: "réponse de secours")
    assert M.generer("question") == "réponse de secours"


def test_reponse_vide_declenche_aussi_le_repli(monkeypatch, secours_actif):
    """Un serveur qui répond une chaîne vide est aussi inutile qu'un serveur muet."""
    monkeypatch.setattr(M, "_ollama", lambda p, j: "")
    monkeypatch.setattr(M, "_secours", lambda p, j: "réponse de secours")
    assert M.generer("question") == "réponse de secours"


def test_sans_secours_configure_l_echec_reste_silencieux(monkeypatch):
    """Chaîne vide plutôt qu'exception : un rapport ne doit pas échouer parce
    que sa rédaction manque."""
    monkeypatch.setattr(M, "secours_configure", lambda: False)
    monkeypatch.setattr(M, "_ollama", _casse)
    assert M.generer("question") == ""


def test_les_deux_sources_en_panne(monkeypatch, secours_actif):
    monkeypatch.setattr(M, "_ollama", _casse)
    monkeypatch.setattr(M, "_secours", _casse)
    assert M.generer("question") == ""


# ── Flux, pour l'assistant conversationnel ────────────────────────────────────

def test_flux_sans_repli_quand_la_source_repond(monkeypatch):
    appels = []
    monkeypatch.setattr(M, "_ollama_flux", lambda p, j: iter(["Bon", "jour"]))
    monkeypatch.setattr(M, "_secours_flux", lambda p, j: appels.append(1) or iter([]))
    assert "".join(M.generer_flux("q")) == "Bonjour"
    assert appels == []


def test_flux_bascule_avant_le_premier_jeton(monkeypatch, secours_actif):
    monkeypatch.setattr(M, "_ollama_flux", _casse)
    monkeypatch.setattr(M, "_secours_flux", lambda p, j: iter(["Se", "cours"]))
    assert "".join(M.generer_flux("q")) == "Secours"


def test_flux_interrompu_en_cours_garde_l_acquis(monkeypatch, secours_actif):
    """Basculer après le premier jeton coudrait deux débuts de réponse l'un à
    l'autre, ce qui se voit à l'écran. Mieux vaut une réponse écourtée."""
    def partiel(p, j):
        yield "Début de rép"
        raise RuntimeError("connexion perdue")

    secours = []
    monkeypatch.setattr(M, "_ollama_flux", partiel)
    monkeypatch.setattr(M, "_secours_flux", lambda p, j: secours.append(1) or iter(["autre"]))
    assert "".join(M.generer_flux("q")) == "Début de rép"
    assert secours == [], "le secours a recousu une réponse déjà commencée"


def test_flux_vide_declenche_le_repli(monkeypatch, secours_actif):
    monkeypatch.setattr(M, "_ollama_flux", lambda p, j: iter([]))
    monkeypatch.setattr(M, "_secours_flux", lambda p, j: iter(["Secours"]))
    assert "".join(M.generer_flux("q")) == "Secours"

"""
Tests du moteur de comparaison de scans.

Ces contrôles portent sur ce qui déclenche une alerte et, tout aussi important,
sur ce qui n'en déclenche pas : une plateforme qui alerte sur un état stable
finit par n'être plus lue. Le module comparé ne touchant ni la base ni le
réseau, ces tests s'exécutent en quelques millisecondes.

Lancement, depuis le dossier backend/ :
    python -m pytest tests/test_comparaison.py -v
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services.comparaison import comparer, resumer                            # noqa: E402


def scan(score=90, ports=None, secrets=None, cves=None, jours_ssl=200,
         reputation=None, bareme=None, duree_ssl=None) -> dict:
    """Scan minimal, à la forme de Scan.to_dict(), pour n'exposer dans chaque
    test que le champ dont il parle."""
    resultats = {
        "ports":      {"open_ports": ports or []},
        "trufflehog": {"findings":   secrets or []},
        "cves":       cves or [],
        "ssl":        {"days_until_expiry": jours_ssl, "duree_validite": duree_ssl},
        "reputation": reputation or {},
    }
    if bareme:
        resultats["score_max"] = bareme
    return {"score": score, "results": resultats}


def types(alertes) -> set[str]:
    return {a.type for a in alertes}


# ── Absence de bruit : deux scans identiques ne disent rien ───────────────────

def test_aucune_alerte_entre_deux_scans_identiques():
    precedent = scan(score=77, ports=[{"port": 22, "service": "SSH", "severity": "MEDIUM"}])
    courant   = scan(score=77, ports=[{"port": 22, "service": "SSH", "severity": "MEDIUM"}])
    assert comparer(precedent, courant) == []


def test_ports_d_information_ignores():
    """80 et 443 ouverts sont le fonctionnement normal d'un site web."""
    courant = scan(ports=[{"port": 80,  "service": "HTTP",  "severity": "INFO"},
                          {"port": 443, "service": "HTTPS", "severity": "INFO"}])
    assert comparer(None, courant) == []


def test_amelioration_du_score_ne_declenche_rien():
    assert comparer(scan(score=60), scan(score=85)) == []


def test_chute_sous_le_seuil_ignoree():
    """Neuf points d'écart relèvent autant de la variation de mesure que d'une
    dégradation réelle."""
    assert comparer(scan(score=90), scan(score=81)) == []


# ── Chute de score ────────────────────────────────────────────────────────────

def test_chute_de_score_signalee():
    alertes = comparer(scan(score=90), scan(score=70))
    assert types(alertes) == {"score"}
    assert alertes[0].gravite == "haute"


def test_effondrement_du_score_est_critique():
    assert comparer(scan(score=90), scan(score=50))[0].gravite == "critique"


def test_bareme_github_normalise():
    """Sur un dépôt noté sur 30, six points perdus valent vingt points sur cent
    et doivent alerter là où le seuil brut de dix les laisserait passer."""
    avant  = scan(score=30, bareme=30)
    apres  = scan(score=24, bareme=30)
    assert types(comparer(avant, apres)) == {"score"}


# ── Secrets exposés ───────────────────────────────────────────────────────────

CLE = {"type": "Private Key", "file": "certificats/serveur.pem", "line": 1}


def test_nouveau_secret_est_critique():
    alertes = comparer(scan(), scan(secrets=[CLE]))
    assert [a.gravite for a in alertes if a.type == "secret"] == ["critique"]


def test_secret_deja_connu_ne_realerte_pas():
    assert comparer(scan(secrets=[CLE]), scan(secrets=[CLE])) == []


def test_secret_au_premier_scan_est_signale():
    """Sans point de comparaison, l'état observé fait foi."""
    assert "secret" in types(comparer(None, scan(secrets=[CLE])))


def test_meme_cle_dans_un_autre_fichier_est_une_fuite_distincte():
    ailleurs = {**CLE, "file": "config/backup.pem"}
    assert "secret" in types(comparer(scan(secrets=[CLE]), scan(secrets=[CLE, ailleurs])))


# ── Expiration du certificat ──────────────────────────────────────────────────

def test_franchissement_du_palier_trente_jours():
    alertes = comparer(scan(jours_ssl=45), scan(jours_ssl=28))
    assert types(alertes) == {"ssl"}
    assert alertes[0].gravite == "moyenne"


def test_palier_deja_franchi_ne_realerte_pas():
    """Le cas qui décide de l'utilité du produit : sans cette règle, un
    certificat à trente jours produirait trente alertes identiques."""
    assert comparer(scan(jours_ssl=28), scan(jours_ssl=27)) == []


def test_paliers_successifs_reelevent_la_gravite():
    assert comparer(scan(jours_ssl=28), scan(jours_ssl=12))[0].gravite == "haute"
    assert comparer(scan(jours_ssl=12), scan(jours_ssl=5))[0].gravite  == "critique"


def test_certificat_expire_est_critique():
    alertes = comparer(scan(jours_ssl=3), scan(jours_ssl=-2))
    assert alertes[0].type    == "ssl"
    assert alertes[0].gravite == "critique"


def test_certificat_expire_ne_realerte_pas_chaque_jour():
    assert comparer(scan(jours_ssl=-2), scan(jours_ssl=-3)) == []


def test_renouvellement_efface_l_alerte():
    assert comparer(scan(jours_ssl=5), scan(jours_ssl=365)) == []


# ── Ports et vulnérabilités ───────────────────────────────────────────────────

# Sévérités telles que check_ports les produit réellement : en français. Les
# écrire en anglais ici avait masqué le fait que le moteur ne les reconnaissait
# pas et classait MySQL ouvert en « moyenne ».
MYSQL = {"port": 3306, "service": "MySQL", "severity": "CRITIQUE"}
SSH   = {"port": 22,   "service": "SSH",   "severity": "MOYEN"}


def test_nouveau_port_critique():
    alertes = comparer(scan(ports=[SSH]), scan(ports=[SSH, MYSQL]))
    assert types(alertes) == {"port"}
    assert alertes[0].gravite == "critique"
    assert "3306" in alertes[0].titre


def test_port_referme_ne_declenche_rien():
    assert comparer(scan(ports=[SSH, MYSQL]), scan(ports=[SSH])) == []


def test_ports_multiples_regroupes_en_une_alerte():
    """Une notification par port ouvert pousserait à toutes les ignorer."""
    alertes = comparer(scan(), scan(ports=[SSH, MYSQL]))
    assert len(alertes) == 1
    assert alertes[0].gravite == "critique"   # la pire des deux


@pytest.mark.parametrize("severite", ["CRITIQUE", "CRITICAL"])
def test_severite_reconnue_dans_les_deux_langues(severite):
    """check_ports étiquette en français, le NVD en anglais : une gravité non
    reconnue ferait silencieusement passer un port critique pour anodin."""
    port = {"port": 3306, "service": "MySQL", "severity": severite}
    assert comparer(scan(), scan(ports=[port]))[0].gravite == "critique"


def test_cve_grave_signalee_et_cve_moyenne_ignoree():
    grave  = {"id": "CVE-2024-0001", "severity": "CRITICAL", "cvss": 9.8}
    banale = {"id": "CVE-2012-2378", "severity": "MEDIUM",   "cvss": 4.3}
    assert types(comparer(scan(), scan(cves=[banale]))) == set()
    assert types(comparer(scan(), scan(cves=[grave])))  == {"cve"}


# ── Réputation ────────────────────────────────────────────────────────────────

SIGNALE = {"vt_disponible": True, "vt_malveillant": 4, "vt_total_moteurs": 90}
SAIN    = {"vt_disponible": True, "vt_malveillant": 0, "vt_total_moteurs": 90}


def test_bascule_vers_signale():
    assert types(comparer(scan(reputation=SAIN), scan(reputation=SIGNALE))) == {"reputation"}


def test_signalement_persistant_ne_realerte_pas():
    assert comparer(scan(reputation=SIGNALE), scan(reputation=SIGNALE)) == []


# ── Composition du message ────────────────────────────────────────────────────

def test_alertes_triees_par_gravite():
    alertes = comparer(
        scan(score=90, jours_ssl=45),
        scan(score=70, jours_ssl=28, secrets=[CLE]),
    )
    assert [a.gravite for a in alertes] == ["critique", "haute", "moyenne"]


def test_titre_porte_la_gravite_maximale():
    alertes = comparer(scan(), scan(secrets=[CLE]))
    titre, corps = resumer("ec2lt.sn", alertes)
    assert titre == "Alerte critique : ec2lt.sn"
    assert "secret" in corps.lower()


def test_resume_vide_sans_alerte():
    assert resumer("ec2lt.sn", []) == ("", "")


# ── Durée de vie du certificat ────────────────────────────────────────────────

def test_certificat_court_ne_previent_pas_a_trente_jours():
    """Un certificat de 90 jours passe sous les 30 restants à chaque cycle sans
    que rien n'aille mal : facebook.com et google.com vivent ainsi en
    permanence. Alerter là-dessus reviendrait à le faire tous les 80 jours sur
    la majeure partie du web."""
    assert comparer(scan(jours_ssl=45, duree_ssl=90),
                    scan(jours_ssl=25, duree_ssl=90)) == []


def test_certificat_court_previent_a_trois_jours():
    """À ce stade, le renouvellement automatique a eu sa chance et ne l'a pas
    saisie : il reste de quoi intervenir à la main."""
    alertes = comparer(scan(jours_ssl=5, duree_ssl=90),
                       scan(jours_ssl=2, duree_ssl=90))
    assert types(alertes) == {"ssl"}
    assert alertes[0].gravite == "critique"


def test_certificat_long_conserve_le_preavis_de_trente_jours():
    """Renouvelé à la main, il demande un préavis que personne ne peut deviner."""
    assert types(comparer(scan(jours_ssl=45, duree_ssl=365),
                          scan(jours_ssl=25, duree_ssl=365))) == {"ssl"}


def test_duree_inconnue_conserve_le_preavis_long():
    """Scans antérieurs à l'enregistrement de la durée : une alerte de trop vaut
    mieux qu'un certificat expiré en silence."""
    assert types(comparer(scan(jours_ssl=45), scan(jours_ssl=25))) == {"ssl"}

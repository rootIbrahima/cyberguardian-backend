"""
Outils #6 et #7 du CDC : scan_virustotal() et scan_abuseipdb().

Cinquième et dernier critère du score global : la réputation. Les quatre autres
mesurent la configuration ; celui-ci mesure l'historique. Un domaine peut être
parfaitement configuré et pourtant figurer dans des listes noires parce qu'il a
été compromis, qu'il héberge du phishing ou que son adresse a servi à des
attaques. Aucune analyse de configuration ne révèle cela.

Deux sources indépendantes et complémentaires :
  VirusTotal  agrège plus de 70 moteurs de réputation (domaine ou IP)
  AbuseIPDB   recense les signalements d'abus émis par la communauté (IP)

Les deux exigent une clé gratuite, à placer dans .env :
  https://www.virustotal.com/gui/my-apikey
  https://www.abuseipdb.com/account/api

Sans clé, le critère est exclu du score plutôt que compté à zéro : l'absence de
mesure n'est pas une absence de risque, et pénaliser la cible pour une
configuration manquante côté serveur d'analyse serait trompeur.

Pèse 15 pts dans le score global.
"""

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Optional

import httpx

from config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
from tools.target_guard import extraire_hote

_TIMEOUT = 12
_VT_URL  = "https://www.virustotal.com/api/v3"
_ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

# Seuils du score de confiance AbuseIPDB (0 à 100) et pénalité associée
_PALIERS_ABUSE = [(75, 10, "CRITIQUE"), (50, 7, "HAUT"), (25, 4, "MOYEN"), (1, 2, "BAS")]


@dataclass
class ReputationResult:
    target: str
    ip: Optional[str] = None
    # VirusTotal
    vt_disponible: bool = False
    vt_malveillant: int = 0          # moteurs signalant la cible comme malveillante
    vt_suspect: int = 0
    vt_inoffensif: int = 0
    vt_total_moteurs: int = 0
    # AbuseIPDB
    abuse_disponible: bool = False
    abuse_score: int = 0             # indice de confiance 0-100
    abuse_signalements: int = 0
    abuse_pays: Optional[str] = None
    abuse_fournisseur: Optional[str] = None
    # Synthèse
    sources: list[str] = field(default_factory=list)
    score: Optional[int] = None      # None = critère non évalué, exclu du calcul
    issues: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def _resoudre_ip(hote: str) -> Optional[str]:
    try:
        ipaddress.ip_address(hote)
        return hote
    except ValueError:
        pass
    try:
        return socket.gethostbyname(hote)
    except socket.gaierror:
        return None


def _interroger_virustotal(hote: str, est_ip: bool, r: ReputationResult) -> None:
    chemin = f"ip_addresses/{hote}" if est_ip else f"domains/{hote}"
    try:
        rep = httpx.get(f"{_VT_URL}/{chemin}",
                        headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=_TIMEOUT)
    except Exception:
        return
    if rep.status_code != 200:
        return

    stats = ((rep.json().get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {}
    r.vt_disponible    = True
    r.vt_malveillant   = stats.get("malicious", 0)
    r.vt_suspect       = stats.get("suspicious", 0)
    r.vt_inoffensif    = stats.get("harmless", 0)
    r.vt_total_moteurs = sum(stats.values())
    r.sources.append("VirusTotal")


def _interroger_abuseipdb(ip: str, r: ReputationResult) -> None:
    try:
        rep = httpx.get(_ABUSE_URL,
                        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=_TIMEOUT)
    except Exception:
        return
    if rep.status_code != 200:
        return

    d = rep.json().get("data") or {}
    r.abuse_disponible    = True
    r.abuse_score         = d.get("abuseConfidenceScore", 0)
    r.abuse_signalements  = d.get("totalReports", 0)
    r.abuse_pays          = d.get("countryCode")
    r.abuse_fournisseur   = d.get("isp")
    r.sources.append("AbuseIPDB")


def check_reputation(target: str) -> ReputationResult:
    hote   = extraire_hote(target)
    result = ReputationResult(target=hote)

    if not VIRUSTOTAL_API_KEY and not ABUSEIPDB_API_KEY:
        result.error = ("Aucune clé de réputation configurée (VIRUSTOTAL_API_KEY, "
                        "ABUSEIPDB_API_KEY). Critère exclu du score.")
        return result

    est_ip = True
    try:
        ipaddress.ip_address(hote)
    except ValueError:
        est_ip = False

    result.ip = hote if est_ip else _resoudre_ip(hote)

    if VIRUSTOTAL_API_KEY:
        _interroger_virustotal(hote, est_ip, result)
    # AbuseIPDB ne traite que des adresses IP
    if ABUSEIPDB_API_KEY and result.ip:
        _interroger_abuseipdb(result.ip, result)

    if not result.sources:
        result.error = ("Aucune source de réputation n'a répondu (clé invalide, quota "
                        "dépassé ou service indisponible). Critère exclu du score.")
        return result

    result.issues = _detect_issues(result)
    result.score  = _calculate_score(result)
    return result


def _detect_issues(r: ReputationResult) -> list[dict]:
    issues = []

    if r.vt_malveillant:
        issues.append({
            "severity": "CRITIQUE" if r.vt_malveillant >= 3 else "HAUT",
            "color":    "red",
            "title":    f"Signalé comme malveillant par {r.vt_malveillant} moteur(s) de sécurité",
            "desc":     f"Sur les {r.vt_total_moteurs} moteurs consultés via VirusTotal, "
                        f"{r.vt_malveillant} classent cette cible comme malveillante. Les "
                        "navigateurs et les passerelles de messagerie s'appuient sur ces "
                        "listes : vos emails peuvent être bloqués et votre site signalé "
                        "aux visiteurs. Demandez une réévaluation après avoir corrigé "
                        "l'origine du signalement.",
            "tool":     "scan_virustotal()",
        })
    elif r.vt_suspect:
        issues.append({
            "severity": "MOYEN",
            "color":    "yellow",
            "title":    f"Classée suspecte par {r.vt_suspect} moteur(s) de sécurité",
            "desc":     "Aucun moteur ne signale la cible comme franchement malveillante, "
                        "mais plusieurs la jugent suspecte. Surveillez l'évolution : c'est "
                        "souvent le signe d'un hébergement partagé avec des sites douteux.",
            "tool":     "scan_virustotal()",
        })

    for seuil, _, severite in _PALIERS_ABUSE:
        if r.abuse_disponible and r.abuse_score >= seuil:
            issues.append({
                "severity": severite,
                "color":    {"CRITIQUE": "red", "HAUT": "orange",
                             "MOYEN": "yellow", "BAS": "blue"}[severite],
                "title":    f"Adresse IP signalée pour abus (indice {r.abuse_score}/100)",
                "desc":     f"{r.abuse_signalements} signalement(s) sur les 90 derniers jours "
                            "concernant cette adresse : tentatives d'intrusion, envoi de spam "
                            "ou balayage de ports. Si vous partagez cette adresse avec "
                            "d'autres clients de votre hébergeur, demandez une adresse "
                            "dédiée ; sinon, vérifiez qu'aucune machine de votre réseau "
                            "n'est compromise.",
                "tool":     "scan_abuseipdb()",
            })
            break

    return issues


def _calculate_score(r: ReputationResult) -> int:
    """Score /15 pts : 15 par défaut, diminué selon les signalements constatés."""
    score = 15

    # VirusTotal : un seul moteur sérieux qui signale suffit à peser lourd
    score -= min(10, r.vt_malveillant * 4)
    score -= min(3, r.vt_suspect)

    # AbuseIPDB : pénalité par palier d'indice de confiance
    for seuil, penalite, _ in _PALIERS_ABUSE:
        if r.abuse_disponible and r.abuse_score >= seuil:
            score -= penalite
            break

    return max(0, score)

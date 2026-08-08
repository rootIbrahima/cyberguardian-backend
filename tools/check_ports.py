"""
Outil #9 du CDC : scan_ports()
Scan de ports réseau non intrusif (Nmap SAFE) : connexion TCP franche
(-sT), sans découverte d'hôte (-Pn) donc sans paquet ICMP/ARP forgé, aucune
technique d'évasion, aucun paquet malformé. Limité à une liste restreinte de
ports courants pour rester rapide et proportionné à un contrôle EASM passif.
Pèse 15 pts dans le score global (exposition de services internes).
"""

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

import nmap

from tools.target_guard import extraire_hote

# Délai maximal accordé à nmap pour l'ensemble des ports d'un hôte. Une valeur
# trop courte est pire qu'inutile : nmap abandonne en cours de route et rapporte
# des états partiels, ce qui produit des ports « ouverts » différents à chaque
# exécution. Observé avec 8 s sur une cible lointaine, où Telnet, RDP et MySQL
# étaient annoncés ouverts alors qu'aucun ne répondait.
_TIMEOUT_SEC = 60

# Délai d'une connexion de confirmation. Court volontairement : un service qui
# accepte les connexions répond en quelques centaines de millisecondes, tandis
# qu'un port faussement signalé ouvert laisse la connexion expirer.
_CONFIRMATION_SEC = 5

# port -> (service, sévérité si ouvert, recommandation)
PORT_CATALOG: dict[int, tuple[str, str, str]] = {
    21:    ("FTP",                  "HAUT",     "FTP transmet les identifiants en clair. Migrez vers SFTP/FTPS."),
    22:    ("SSH",                  "INFO",     "Port d'administration standard. Vérifiez l'authentification par clé et le fail2ban."),
    23:    ("Telnet",               "CRITIQUE", "Telnet transmet tout en clair, y compris les mots de passe. Désactivez-le et utilisez SSH."),
    25:    ("SMTP",                 "INFO",     "Port mail standard si ce serveur envoie des emails."),
    53:    ("DNS",                  "INFO",     "Normal pour un serveur faisant autorité sur ce domaine."),
    80:    ("HTTP",                 "INFO",     "Port web standard. Vérifiez la redirection vers HTTPS."),
    110:   ("POP3",                 "MOYEN",    "POP3 sans TLS expose les identifiants. Utilisez POP3S (995)."),
    135:   ("RPC Windows",          "HAUT",     "Service RPC Windows : ne doit jamais être exposé sur Internet."),
    139:   ("NetBIOS",              "HAUT",     "Partage de fichiers Windows historique : à restreindre au réseau local."),
    143:   ("IMAP",                 "MOYEN",    "IMAP sans TLS expose les identifiants. Utilisez IMAPS (993)."),
    443:   ("HTTPS",                "INFO",     "Port web sécurisé standard."),
    445:   ("SMB",                  "CRITIQUE", "SMB exposé sur Internet est la porte d'entrée de nombreux rançongiciels (WannaCry). À fermer immédiatement."),
    1433:  ("Microsoft SQL Server", "CRITIQUE", "Base de données exposée directement sur Internet. Restreignez-la à un VPN ou un réseau privé."),
    3306:  ("MySQL",                "CRITIQUE", "Base de données exposée directement sur Internet. Restreignez-la à un VPN ou un réseau privé."),
    3389:  ("RDP",                  "CRITIQUE", "Le bureau à distance exposé est la cible n°1 des attaques par force brute et rançongiciels."),
    5432:  ("PostgreSQL",           "CRITIQUE", "Base de données exposée directement sur Internet. Restreignez-la à un VPN ou un réseau privé."),
    5900:  ("VNC",                  "CRITIQUE", "VNC est souvent mal protégé et permet une prise de contrôle du poste s'il est exposé."),
    6379:  ("Redis",                "CRITIQUE", "Redis n'exige aucune authentification par défaut : un accès public équivaut à un accès total."),
    8080:  ("HTTP alternatif",      "BAS",      "Souvent une interface d'administration. Vérifiez qu'elle est protégée par authentification."),
    9200:  ("Elasticsearch",        "CRITIQUE", "De nombreuses fuites de données proviennent d'instances Elasticsearch exposées sans authentification."),
    27017: ("MongoDB",              "CRITIQUE", "MongoDB sans authentification exposé publiquement est une des premières causes de fuite de données."),
}

_SEVERITY_COLOR = {"CRITIQUE": "red", "HAUT": "orange", "MOYEN": "yellow", "BAS": "blue", "INFO": "blue"}
_SEVERITY_PENALTY = {"CRITIQUE": 6, "HAUT": 3, "MOYEN": 2, "BAS": 0, "INFO": 0}


@dataclass
class PortsResult:
    target: str
    reachable: bool = False
    open_ports: list[dict] = field(default_factory=list)     # {port, service, severity}
    ports_scanned: int = 0
    # None si l'outil n'a pas pu s'exécuter (nmap absent, incident technique) :
    # exclu du score global plutôt que compté comme 0/15, pour ne pas pénaliser
    # la cible d'un problème d'infrastructure côté serveur d'analyse.
    score: Optional[int] = None
    issues: list[dict] = field(default_factory=list)
    error: Optional[str] = None


def _scanner() -> nmap.PortScanner:
    """Ajoute les emplacements Windows courants à la recherche du binaire nmap :
    l'installeur officiel (winget/exe) ne modifie pas toujours le PATH d'un
    processus déjà démarré."""
    search_path = (
        "nmap", "/usr/bin/nmap", "/usr/local/bin/nmap", "/sw/bin/nmap", "/opt/local/bin/nmap",
        r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe",
    )
    return nmap.PortScanner(nmap_search_path=search_path)


def _confirmer_ouverture(hote: str, ports: list[int]) -> list[int]:
    """Ne conserve que les ports acceptant réellement une connexion TCP.

    Nmap conclut à l'ouverture dès qu'une sonde reçoit une réponse ; les
    dispositifs anti-scan en renvoient sur des ports pourtant fermés. Une
    connexion complète, établie puis refermée immédiatement, tranche sans
    ambiguïté et reste aussi peu intrusive que le scan lui-même.

    Les vérifications sont menées de front : séquentielles, elles ajouteraient
    plusieurs secondes par port au temps total du scan.
    """
    if not ports:
        return []

    def joignable(port: int) -> int | None:
        with socket.socket() as s:
            s.settimeout(_CONFIRMATION_SEC)
            try:
                return port if s.connect_ex((hote, port)) == 0 else None
            except OSError:
                return None

    with ThreadPoolExecutor(max_workers=min(10, len(ports))) as executor:
        confirmes = [p for p in executor.map(joignable, ports) if p is not None]
    return sorted(confirmes)


def check_ports(target: str) -> PortsResult:
    host = extraire_hote(target)
    result = PortsResult(target=host)
    ports = sorted(PORT_CATALOG)
    result.ports_scanned = len(ports)

    try:
        nm = _scanner()
    except nmap.PortScannerError:
        # Incident d'infrastructure (outil absent) : score laissé à None, exclu
        # du calcul global plutôt que compté comme une faille de la cible.
        result.error = "Nmap n'est pas installé ou introuvable sur le serveur."
        return result

    try:
        nm.scan(
            hosts=host,
            arguments=(
                f"-sT -Pn -T3 --max-retries 2 --host-timeout {_TIMEOUT_SEC}s "
                f"-p {','.join(str(p) for p in ports)}"
            ),
        )
    except Exception as e:
        result.error = f"Scan de ports impossible : {e}"
        return result

    # nmap indexe ses résultats par IP résolue, pas par le nom d'hôte fourni
    # (un seul hôte scanné à la fois : le premier suffit à le retrouver). Une
    # liste vide ici signifie presque toujours une résolution DNS impossible,
    # un vrai résultat sur la cible, à la différence des deux cas ci-dessus.
    hosts_found = nm.all_hosts()
    if not hosts_found:
        result.error = "Cible non résolvable pour le scan de ports."
        result.score = 0
        result.issues.append({
            "severity": "MOYEN",
            "color":    "yellow",
            "title":    "Scan de ports impossible : cible non résolvable",
            "desc":     "Le nom ou l'adresse fourni n'a pas pu être résolu pour tester les ports réseau.",
            "tool":     "scan_ports()",
        })
        return result

    result.reachable = True
    tcp = nm[hosts_found[0]].get("tcp", {})
    candidats = [p for p in ports if tcp.get(p, {}).get("state") == "open"]

    # Nmap seul ne suffit pas : certaines protections anti-scan répondent aux
    # sondes sur des ports pourtant filtrés, ce qui les fait passer pour
    # ouverts. Observé sur un hébergement OVH, où deux exécutions successives
    # donnaient des listes différentes incluant Telnet, RDP et MySQL, alors
    # qu'aucun de ces services n'acceptait la moindre connexion. Chaque
    # candidat est donc confirmé par une connexion TCP réellement établie.
    for port in _confirmer_ouverture(hosts_found[0], candidats):
        service, severity, _ = PORT_CATALOG[port]
        result.open_ports.append({"port": port, "service": service, "severity": severity})

    result.issues = _detect_issues(result)
    result.score = _calculate_score(result)
    return result


def _detect_issues(r: PortsResult) -> list[dict]:
    issues = []
    for p in r.open_ports:
        severity = p["severity"]
        if severity == "INFO":
            continue
        _, _, reco = PORT_CATALOG[p["port"]]
        issues.append({
            "severity": severity,
            "color":    _SEVERITY_COLOR[severity],
            "title":    f"Port {p['port']} ouvert ({p['service']})",
            "desc":     reco,
            "tool":     "scan_ports()",
        })
    return issues


def _calculate_score(r: PortsResult) -> int:
    """Score /15 pts : 15 par défaut, pénalité par port ouvert selon sa sévérité."""
    score = 15
    for p in r.open_ports:
        score -= _SEVERITY_PENALTY[p["severity"]]
    return max(0, score)

"""
Garde-fou des cibles de scan (CDC §7.1 — outils non intrusifs et périmètre
strictement externe).

CyberGuardian évalue la surface d'attaque EXTERNE publique. Sans contrôle, une
cible comme 127.0.0.1, 192.168.1.1 ou 169.254.169.254 (métadonnées des
fournisseurs cloud) transformerait la plateforme en relais de reconnaissance
vers des réseaux internes : le client obtiendrait en retour les en-têtes, le
certificat et surtout les ports ouverts d'une machine qu'il n'a pas le droit de
scanner. La cible est donc résolue puis vérifiée avant tout appel réseau.

Limite connue : la résolution et le scan ont lieu en deux temps, une attaque par
réassociation DNS (DNS rebinding) reste théoriquement possible. Le niveau de
protection retenu est cohérent avec un scanner passif.
"""

import ipaddress
import socket


class CibleInterdite(Exception):
    """Cible interne, réservée ou non résolvable — le scan est refusé."""


def extraire_hote(target: str, garder_port: bool = False) -> str:
    """Extrait le nom d'hôte d'un domaine, d'une IP ou d'une URL.
    garder_port=True conserve « :8080 » (utile pour reconstruire une URL)."""
    target = (target or "").strip()
    for prefixe in ("https://", "http://"):
        if target.startswith(prefixe):
            target = target[len(prefixe):]
    hote = target.split("/")[0]
    if garder_port:
        return hote
    # IPv6 littérale entre crochets : [2001:db8::1]:443
    if hote.startswith("["):
        return hote[1:].split("]")[0]
    return hote.split(":")[0]


def _verifier_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Refuse toute adresse qui ne relève pas de l'internet public."""
    if ip.is_loopback:
        raise CibleInterdite(
            "Cette adresse désigne la machine qui exécute CyberGuardian "
            "(boucle locale). Seuls les actifs publics peuvent être analysés."
        )
    if ip.is_link_local:
        raise CibleInterdite(
            "Cette adresse est un lien local (169.254.0.0/16), utilisée notamment "
            "par les services de métadonnées des hébergeurs cloud. Analyse refusée."
        )
    if ip.is_private:
        raise CibleInterdite(
            "Cette adresse appartient à un réseau privé. CyberGuardian évalue la "
            "surface d'attaque externe : indiquez un domaine, une IP publique ou "
            "une URL accessible depuis internet."
        )
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise CibleInterdite(
            "Cette adresse est réservée par l'IANA et ne correspond à aucun actif "
            "analysable."
        )


def resoudre_et_valider(target: str) -> tuple[str, str]:
    """Vérifie qu'une cible relève bien de l'internet public.
    Retourne (hôte, adresse IP résolue) ou lève CibleInterdite.
    Toutes les adresses résolues sont contrôlées : un nom pointant à la fois
    vers une IP publique et une IP interne est refusé."""
    hote = extraire_hote(target)
    if not hote:
        raise CibleInterdite("Aucune cible fournie.")

    # Cas 1 — adresse IP saisie directement (pas de résolution nécessaire)
    ip_litterale = None
    try:
        ip_litterale = ipaddress.ip_address(hote)
    except ValueError:
        pass
    if ip_litterale is not None:
        _verifier_ip(ip_litterale)
        return hote, str(ip_litterale)

    # Cas 2 — nom de domaine : toutes les adresses résolues doivent être publiques
    try:
        infos = socket.getaddrinfo(hote, None)
    except socket.gaierror:
        raise CibleInterdite(
            f"Le nom « {hote} » n'a pas pu être résolu. Vérifiez l'orthographe du "
            "domaine ou son existence dans le DNS public."
        )

    adresses = {info[4][0] for info in infos}
    for adresse in adresses:
        _verifier_ip(ipaddress.ip_address(adresse))

    return hote, sorted(adresses)[0]

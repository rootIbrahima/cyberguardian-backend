"""
Horodatage unique pour toute l'application.

Deux conventions coexistaient : auth.py et seed.py écrivaient en UTC avec fuseau,
les scans, messages et notifications en heure locale sans fuseau. Comparer les
deux familles lève une TypeError, et un changement de fuseau du serveur décale
silencieusement les fenêtres glissantes (quota 24 h, accès expert 48 h).

Tout ce qui est écrit à partir d'ici porte son fuseau. La lecture reste
tolérante : les valeurs déjà en base, sans fuseau, sont interprétées dans le
fuseau du serveur, ce qui préserve leur sens d'origine.
"""

from datetime import datetime, timezone


def maintenant() -> datetime:
    """Instant courant, avec fuseau, en UTC."""
    return datetime.now(timezone.utc)


def maintenant_iso() -> str:
    """Instant courant au format ISO, à la seconde, fuseau compris."""
    return maintenant().isoformat(timespec="seconds")


def lire(valeur: str | None) -> datetime | None:
    """Analyse une date ISO, quelle que soit la convention d'écriture.

    Une valeur sans fuseau se voit attribuer celui du serveur : c'est ainsi
    qu'elle a été écrite, et l'interpréter en UTC la décalerait."""
    if not valeur:
        return None
    try:
        dt = datetime.fromisoformat(valeur)
    except (TypeError, ValueError):
        return None
    return dt.astimezone() if dt.tzinfo is None else dt


def ecoule_depuis(valeur: str | None):
    """Durée écoulée depuis une date ISO, ou None si elle est illisible."""
    dt = lire(valeur)
    return None if dt is None else maintenant() - dt


def anterieur_ou_egal(a: str | None, b: str | None) -> bool:
    """« a » est-il antérieur ou égal à « b » ? Comparaison sur les instants,
    jamais sur les chaînes : deux conventions d'écriture différentes se
    compareraient dans le désordre."""
    da, db = lire(a), lire(b)
    return bool(da and db and da <= db)

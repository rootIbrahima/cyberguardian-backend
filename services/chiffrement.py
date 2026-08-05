"""
Chiffrement symétrique des secrets stockés en base (CDC §6.2, aucun secret en
clair). Concerne aujourd'hui le jeton OAuth GitHub : sa portée public_repo
autorise l'écriture sur les dépôts du client, une fuite de la base donnerait
donc un accès en modification à leur code. Le jeton est chiffré au repos et
déchiffré uniquement au moment de l'appel à l'API GitHub.

Algorithme : Fernet (AES-128-CBC + HMAC-SHA256), fourni par la bibliothèque
cryptography déjà présente via python-jose[cryptography].

Génération de la clé à placer dans ENCRYPTION_KEY (.env) :
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Sans ENCRYPTION_KEY, les valeurs sont laissées en clair et un avertissement est
émis au démarrage : le développement reste possible, la production non conforme
est visible plutôt que silencieuse.
"""

import warnings

from cryptography.fernet import Fernet, InvalidToken

from config import ENCRYPTION_KEY

_PREFIXE = "fernet:"   # marque les valeurs chiffrées, pour migrer sans casser l'existant

_fernet: Fernet | None = None
if ENCRYPTION_KEY:
    try:
        _fernet = Fernet(ENCRYPTION_KEY.encode())
    except (ValueError, TypeError):
        warnings.warn(
            "ENCRYPTION_KEY invalide : les jetons seront stockés en clair. "
            "Générez une clé avec Fernet.generate_key().",
            RuntimeWarning,
        )
else:
    warnings.warn(
        "ENCRYPTION_KEY absente de .env : les jetons OAuth sont stockés en clair.",
        RuntimeWarning,
    )


def chiffrer(valeur: str) -> str:
    """Chiffre une valeur avant stockage. Sans clé configurée, renvoie la valeur
    telle quelle pour ne pas bloquer un environnement de développement."""
    if not valeur or _fernet is None:
        return valeur
    return _PREFIXE + _fernet.encrypt(valeur.encode()).decode()


def dechiffrer(valeur: str) -> str:
    """Déchiffre une valeur lue en base. Les valeurs non préfixées sont
    antérieures au chiffrement et sont renvoyées telles quelles."""
    if not valeur or not valeur.startswith(_PREFIXE):
        return valeur
    if _fernet is None:
        raise RuntimeError(
            "Jeton chiffré en base mais ENCRYPTION_KEY absente : impossible de le lire."
        )
    try:
        return _fernet.decrypt(valeur[len(_PREFIXE):].encode()).decode()
    except InvalidToken:
        raise RuntimeError(
            "Jeton illisible : ENCRYPTION_KEY ne correspond pas à celle utilisée "
            "lors du chiffrement. Le client doit reconnecter son compte GitHub."
        )

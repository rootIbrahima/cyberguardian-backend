from datetime import datetime, timedelta, timezone
import bcrypt
from jose import JWTError, jwt
from passlib.hash import sha256_crypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db
import models

from config import JWT_SECRET_KEY as SECRET_KEY

ALGORITHM  = "HS256"
TOKEN_EXPIRE_DAYS = 7

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token", auto_error=False)

# bcrypt ne prend en compte que les 72 premiers octets du mot de passe.
_BCRYPT_MAX_OCTETS = 72
_PREFIXES_BCRYPT   = ("$2a$", "$2b$", "$2y$")

# bcrypt est appelé directement plutôt que via passlib : passlib 1.7.4 lit
# bcrypt.__about__, supprimé depuis bcrypt 4.1, et lève une erreur au premier
# hachage. passlib reste utilisé pour vérifier les comptes créés avant la
# migration, encore hachés en sha256_crypt.


def hash_password(password: str) -> str:
    octets = password.encode("utf-8")[:_BCRYPT_MAX_OCTETS]
    return bcrypt.hashpw(octets, bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    octets = plain.encode("utf-8")[:_BCRYPT_MAX_OCTETS]
    if hashed.startswith(_PREFIXES_BCRYPT):
        try:
            return bcrypt.checkpw(octets, hashed.encode())
        except ValueError:
            return False
    try:
        return sha256_crypt.verify(plain, hashed)   # compte antérieur à la migration
    except (ValueError, TypeError):
        return False


def besoin_rehachage(hashed: str) -> bool:
    """Vrai si le mot de passe est encore stocké dans l'ancien format."""
    return not (hashed or "").startswith(_PREFIXES_BCRYPT)


def create_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRE_DAYS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _decode(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def get_current_user_optional(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User | None:
    if not token:
        return None
    payload = _decode(token)
    if not payload:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    # Un compte désactivé perd l'accès immédiatement, même avec un token valide
    if user and not user.is_active:
        return None
    return user


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    user = get_current_user_optional(token, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Non authentifié",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Accès réservé aux administrateurs")
    return current_user

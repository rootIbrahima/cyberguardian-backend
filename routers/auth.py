from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from pydantic import BaseModel
from database import get_db
import models
import auth as auth_utils

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterBody(BaseModel):
    email:    str
    name:     str
    password: str
    role:     str = "client"


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password:     str


def _token_response(user: models.User) -> dict:
    token = auth_utils.create_token({
        "sub":  str(user.id),
        "role": user.role,
        "name": user.name,
    })
    return {
        "access_token": token,
        "token_type":   "bearer",
        "user": {
            "id":    user.id,
            "email": user.email,
            "name":  user.name,
            "role":  user.role,
        },
    }


@router.post("/token")
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db:   Session = Depends(get_db),
):
    user = db.query(models.User).filter(models.User.email == form.username).first()
    if not user or not auth_utils.verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email ou mot de passe incorrect")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Compte désactivé")
    return _token_response(user)


@router.post("/register")
def register(body: RegisterBody, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.email == body.email).first():
        raise HTTPException(status_code=400, detail="Cet email est déjà utilisé")
    user = models.User(
        email         = body.email,
        name          = body.name,
        password_hash = auth_utils.hash_password(body.password),
        # Toujours client : le rôle expert s'obtient uniquement par candidature
        # validée par l'admin (CDC §4.2), jamais à l'inscription.
        role          = "client",
        created_at    = datetime.now(timezone.utc).isoformat(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return _token_response(user)


@router.get("/me")
def get_me(current_user: models.User = Depends(auth_utils.get_current_user)):
    return {
        "id":         current_user.id,
        "email":      current_user.email,
        "name":       current_user.name,
        "role":       current_user.role,
        "created_at": current_user.created_at,
    }


@router.put("/me/password")
def change_password(
    body:         ChangePasswordBody,
    current_user: models.User  = Depends(auth_utils.get_current_user),
    db:           Session      = Depends(get_db),
):
    if not auth_utils.verify_password(body.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")
    current_user.password_hash = auth_utils.hash_password(body.new_password)
    db.commit()
    return {"message": "Mot de passe mis à jour"}

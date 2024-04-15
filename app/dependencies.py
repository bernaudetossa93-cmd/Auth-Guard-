"""Dependances FastAPI : utilisateur courant et verification CSRF."""
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import security
from app.config import get_settings
from app.database import get_db
from app.models import User
from app.services import auth_service


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    token = request.cookies.get(get_settings().session_cookie_name)
    return auth_service.get_user_from_token(db, token)


def get_current_user(user: User | None = Depends(get_optional_user)) -> User:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise. Veuillez vous connecter.",
        )
    return user


def require_csrf(request: Request) -> None:
    cookie = request.cookies.get(get_settings().csrf_cookie_name)
    header = request.headers.get("X-CSRF-Token")
    if not security.is_valid_csrf(cookie, header):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Jeton CSRF manquant ou invalide. Rechargez la page et réessayez.",
        )

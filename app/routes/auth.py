"""Routes API d'authentification (/api/v1)."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app import security
from app.config import get_settings
from app.database import get_db
from app.dependencies import get_current_user, require_csrf
from app.models import User
from app.schemas import (
    AuthResponse,
    CsrfResponse,
    LoginRequest,
    MessageResponse,
    ProtectedResponse,
    RegisterRequest,
    UserOut,
)
from app.services import auth_service

router = APIRouter(prefix="/api/v1", tags=["auth"])


def _set_session_cookie(response: Response, token: str) -> None:
    s = get_settings()
    response.set_cookie(
        key=s.session_cookie_name,
        value=token,
        max_age=s.session_max_age_seconds,
        httponly=True,
        secure=s.cookie_secure,
        samesite=s.cookie_samesite,
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    s = get_settings()
    response.delete_cookie(
        key=s.session_cookie_name,
        httponly=True,
        secure=s.cookie_secure,
        samesite=s.cookie_samesite,
        path="/",
    )


@router.get("/auth/csrf", response_model=CsrfResponse)
def get_csrf_token(response: Response):
    """Emet un jeton CSRF : copie dans un cookie HttpOnly et dans le corps JSON."""
    s = get_settings()
    token = security.generate_csrf_token()
    response.set_cookie(
        key=s.csrf_cookie_name,
        value=token,
        max_age=s.session_max_age_seconds,
        httponly=True,
        secure=s.cookie_secure,
        samesite="strict",
        path="/",
    )
    return CsrfResponse(csrf_token=token)


@router.post(
    "/auth/register",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_csrf)],
)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    try:
        user = auth_service.register_user(db, payload.name, payload.email, payload.password)
    except auth_service.EmailAlreadyRegistered:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte existe déjà avec cette adresse email.",
        )
    return AuthResponse(message="Compte créé avec succès.", user=UserOut.model_validate(user))


@router.post("/auth/login", response_model=AuthResponse, dependencies=[Depends(require_csrf)])
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    try:
        user = auth_service.authenticate(db, payload.email, payload.password)
    except auth_service.InvalidCredentials:
        # Meme message que l'email existe ou non.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou mot de passe incorrect.",
        )
    # Nouvelle session a chaque connexion (evite la fixation de session).
    auth_service.delete_session(db, request.cookies.get(get_settings().session_cookie_name))
    token = auth_service.create_session(db, user)
    _set_session_cookie(response, token)
    return AuthResponse(message="Connexion réussie.", user=UserOut.model_validate(user))


@router.post("/auth/logout", response_model=MessageResponse, dependencies=[Depends(require_csrf)])
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    auth_service.delete_session(db, request.cookies.get(get_settings().session_cookie_name))
    _clear_session_cookie(response)
    return MessageResponse(message="Déconnexion réussie.")


@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return UserOut.model_validate(user)


@router.get("/protected", response_model=ProtectedResponse)
def protected(user: User = Depends(get_current_user)):
    return ProtectedResponse(
        message=f"Accès autorisé. Bonjour {user.name}, cette ressource est réservée aux utilisateurs connectés.",
        user_id=user.id,
    )

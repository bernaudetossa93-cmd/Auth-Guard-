"""Logique metier d'authentification (independante de HTTP)."""
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import security
from app.config import get_settings
from app.models import User, UserSession, utcnow


class EmailAlreadyRegistered(Exception):
    pass


class InvalidCredentials(Exception):
    pass


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def register_user(db: Session, name: str, email: str, password: str) -> User:
    if get_user_by_email(db, email) is not None:
        raise EmailAlreadyRegistered()
    user = User(name=name, email=email, password_hash=security.hash_password(password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:  # inscription concurrente avec le meme email
        db.rollback()
        raise EmailAlreadyRegistered()
    return user


def authenticate(db: Session, email: str, password: str) -> User:
    user = get_user_by_email(db, email)
    if user is None:
        security.burn_dummy_verification(password)
        raise InvalidCredentials()
    if not security.verify_password(user.password_hash, password):
        raise InvalidCredentials()
    if security.needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)
        db.commit()
    return user


def create_session(db: Session, user: User) -> str:
    """Cree une session et renvoie le jeton brut (a placer dans le cookie)."""
    token = security.generate_session_token()
    db.add(
        UserSession(
            token_hash=security.hash_token(token),
            user_id=user.id,
            expires_at=utcnow() + timedelta(seconds=get_settings().session_max_age_seconds),
        )
    )
    db.commit()
    return token


def get_user_from_token(db: Session, token: str | None) -> User | None:
    if not token:
        return None
    session = db.scalar(
        select(UserSession).where(UserSession.token_hash == security.hash_token(token))
    )
    if session is None:
        return None
    if session.expires_at <= utcnow():
        db.delete(session)
        db.commit()
        return None
    return session.user


def delete_session(db: Session, token: str | None) -> None:
    if not token:
        return
    session = db.scalar(
        select(UserSession).where(UserSession.token_hash == security.hash_token(token))
    )
    if session is not None:
        db.delete(session)
        db.commit()

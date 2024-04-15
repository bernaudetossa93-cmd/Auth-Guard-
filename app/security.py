"""Hachage des mots de passe, jetons de session et jetons CSRF."""
import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import get_settings

_hasher = PasswordHasher()  # Argon2id, parametres par defaut recommandes

# Hash factice : verifie quand l'email est inconnu pour garder un temps de
# reponse comparable et ne pas reveler l'existence d'un compte.
_DUMMY_HASH = _hasher.hash("mot-de-passe-factice-pour-egaliser-le-temps")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def burn_dummy_verification(password: str) -> None:
    verify_password(_DUMMY_HASH, password)


# --- Sessions -------------------------------------------------------------

def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- CSRF (cookie + en-tete, jeton signe) ----------------------------------

def _sign(nonce: str) -> str:
    key = get_settings().secret_key.encode("utf-8")
    return hmac.new(key, nonce.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_csrf_token() -> str:
    nonce = secrets.token_urlsafe(24)
    return f"{nonce}.{_sign(nonce)}"


def is_valid_csrf(cookie_value: str | None, header_value: str | None) -> bool:
    if not cookie_value or not header_value:
        return False
    if not hmac.compare_digest(cookie_value, header_value):
        return False
    nonce, _, signature = cookie_value.partition(".")
    return bool(nonce) and hmac.compare_digest(signature, _sign(nonce))

"""Configuration de l'application, lue depuis les variables d'environnement / .env."""
import secrets
from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./authguard.db"
    # Si vide, une cle aleatoire est generee au demarrage (voir get_settings).
    secret_key: str = ""
    cookie_secure: bool = False
    cookie_samesite: Literal["lax", "strict"] = "lax"
    session_max_age_seconds: int = 8 * 60 * 60
    session_cookie_name: str = "authguard_session"
    csrf_cookie_name: str = "authguard_csrf"


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.secret_key:
        # Evite une cle par defaut connue de tous. Les jetons CSRF deja emis
        # deviennent invalides apres un redemarrage ; le frontend en redemande un.
        settings.secret_key = secrets.token_urlsafe(48)
    return settings

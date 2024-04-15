"""Fixtures de test : base SQLite temporaire, isolee de la base de developpement."""
import os
import tempfile

# Doit etre defini AVANT l'import de l'application.
_tmp_dir = tempfile.mkdtemp(prefix="authguard-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp_dir}/test.db"
os.environ["SECRET_KEY"] = "cle-de-test-uniquement"
os.environ["COOKIE_SECURE"] = "false"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402

USER = {"name": "Alice Martin", "email": "alice@authguard.dev", "password": "Secret123"}


@pytest.fixture(autouse=True)
def fresh_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def csrf_headers(client: TestClient) -> dict:
    token = client.get("/api/v1/auth/csrf").json()["csrf_token"]
    return {"X-CSRF-Token": token}


def post(client: TestClient, url: str, json: dict | None = None):
    return client.post(url, json=json, headers=csrf_headers(client))


@pytest.fixture
def registered(client):
    response = post(client, "/api/v1/auth/register", USER)
    assert response.status_code == 201
    return USER


@pytest.fixture
def logged_in(client, registered):
    response = post(client, "/api/v1/auth/login", {"email": USER["email"], "password": USER["password"]})
    assert response.status_code == 200
    return client

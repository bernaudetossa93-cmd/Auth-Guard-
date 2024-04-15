from sqlalchemy import select

from app.models import User, UserSession
from tests.conftest import USER, csrf_headers, post

REGISTER = "/api/v1/auth/register"
LOGIN = "/api/v1/auth/login"
LOGOUT = "/api/v1/auth/logout"
ME = "/api/v1/auth/me"
PROTECTED = "/api/v1/protected"


# --- Inscription -------------------------------------------------------------

def test_register_success(client, db):
    response = post(client, REGISTER, USER)
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == USER["email"]
    assert body["user"]["name"] == USER["name"]
    assert "password" not in body["user"] and "password_hash" not in body["user"]
    assert db.scalar(select(User).where(User.email == USER["email"])) is not None


def test_register_normalizes_email(client, db):
    post(client, REGISTER, {**USER, "email": "  ALICE@AuthGuard.dev "})
    assert db.scalar(select(User)).email == "alice@authguard.dev"


def test_register_duplicate_email_returns_409(client, registered):
    response = post(client, REGISTER, {**USER, "name": "Autre"})
    assert response.status_code == 409


def test_register_validation_errors(client):
    response = post(client, REGISTER, {"name": "A", "email": "pas-un-email", "password": "court"})
    assert response.status_code == 422
    body = response.json()
    fields = {e["field"] for e in body["errors"]}
    assert {"name", "email", "password"} <= fields
    assert all(e["message"] for e in body["errors"])


def test_register_weak_password_rejected(client):
    response = post(client, REGISTER, {**USER, "password": "uniquementdeslettres"})
    assert response.status_code == 422
    assert response.json()["errors"][0]["field"] == "password"


def test_register_missing_fields(client):
    response = post(client, REGISTER, {})
    assert response.status_code == 422
    assert {e["field"] for e in response.json()["errors"]} == {"name", "email", "password"}


# --- Hachage -----------------------------------------------------------------

def test_password_is_hashed_with_argon2(client, db):
    post(client, REGISTER, USER)
    user = db.scalar(select(User))
    assert user.password_hash != USER["password"]
    assert USER["password"] not in user.password_hash
    assert user.password_hash.startswith("$argon2")


def test_same_password_gives_different_hashes(client, db):
    post(client, REGISTER, USER)
    post(client, REGISTER, {**USER, "email": "bob@authguard.dev", "name": "Bob"})
    hashes = [u.password_hash for u in db.scalars(select(User))]
    assert len(hashes) == 2 and hashes[0] != hashes[1]


def test_session_token_not_stored_in_clear(logged_in, db):
    token = logged_in.cookies.get("authguard_session")
    stored = db.scalar(select(UserSession))
    assert token and stored.token_hash != token


# --- Connexion ---------------------------------------------------------------

def test_login_success_sets_secure_cookie(client, registered):
    response = post(client, LOGIN, {"email": USER["email"], "password": USER["password"]})
    assert response.status_code == 200
    assert response.json()["user"]["email"] == USER["email"]
    cookie = response.headers["set-cookie"].lower()
    assert "authguard_session=" in cookie
    assert "httponly" in cookie
    assert "samesite=lax" in cookie


def test_login_wrong_password(client, registered):
    response = post(client, LOGIN, {"email": USER["email"], "password": "MauvaisMdp1"})
    assert response.status_code == 401
    assert "authguard_session" not in client.cookies


def test_login_unknown_email_same_response_as_wrong_password(client, registered):
    wrong_password = post(client, LOGIN, {"email": USER["email"], "password": "MauvaisMdp1"})
    unknown_email = post(client, LOGIN, {"email": "inconnu@authguard.dev", "password": "MauvaisMdp1"})
    assert unknown_email.status_code == wrong_password.status_code == 401
    assert unknown_email.json() == wrong_password.json()


def test_login_email_is_case_insensitive(client, registered):
    response = post(client, LOGIN, {"email": "ALICE@AUTHGUARD.DEV", "password": USER["password"]})
    assert response.status_code == 200


def test_login_invalid_payload(client):
    response = post(client, LOGIN, {"email": "x"})
    assert response.status_code == 422


# --- Routes protegees --------------------------------------------------------

def test_me_and_protected_after_login(logged_in):
    me = logged_in.get(ME)
    assert me.status_code == 200
    assert me.json()["email"] == USER["email"]
    protected = logged_in.get(PROTECTED)
    assert protected.status_code == 200
    assert protected.json()["user_id"] == me.json()["id"]


def test_protected_routes_refuse_anonymous(client):
    assert client.get(ME).status_code == 401
    assert client.get(PROTECTED).status_code == 401


def test_protected_routes_refuse_forged_cookie(client):
    client.cookies.set("authguard_session", "jeton-invente")
    assert client.get(ME).status_code == 401
    assert client.get(PROTECTED).status_code == 401


def test_dashboard_redirects_anonymous_to_login(client):
    response = client.get("/dashboard", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_expired_session_is_refused(logged_in, db):
    from datetime import timedelta

    session = db.scalar(select(UserSession))
    session.expires_at = session.expires_at - timedelta(days=1)
    db.commit()
    assert logged_in.get(ME).status_code == 401
    assert db.scalar(select(UserSession)) is None


# --- Deconnexion -------------------------------------------------------------

def test_logout_invalidates_session(logged_in, db):
    token = logged_in.cookies.get("authguard_session")
    response = post(logged_in, LOGOUT)
    assert response.status_code == 200
    assert db.scalar(select(UserSession)) is None
    assert logged_in.get(ME).status_code == 401
    assert logged_in.get(PROTECTED).status_code == 401

    # L'ancien cookie, rejoue, ne doit plus fonctionner.
    logged_in.cookies.set("authguard_session", token)
    assert logged_in.get(ME).status_code == 401


# --- CSRF --------------------------------------------------------------------

def test_post_without_csrf_token_is_refused(client):
    assert client.post(REGISTER, json=USER).status_code == 403
    assert client.post(LOGIN, json={"email": USER["email"], "password": USER["password"]}).status_code == 403


def test_post_with_mismatched_csrf_token_is_refused(client):
    csrf_headers(client)  # pose le cookie
    response = client.post(REGISTER, json=USER, headers={"X-CSRF-Token": "autre.valeur"})
    assert response.status_code == 403


def test_post_with_forged_signed_token_is_refused(client):
    forged = "nonce-forge.0000"
    client.cookies.set("authguard_csrf", forged)
    response = client.post(REGISTER, json=USER, headers={"X-CSRF-Token": forged})
    assert response.status_code == 403


def test_logout_requires_csrf(logged_in):
    assert logged_in.post(LOGOUT).status_code == 403
    assert logged_in.get(ME).status_code == 200  # toujours connecte


# --- Pages -------------------------------------------------------------------

def test_pages_render(client):
    for path in ("/login", "/register"):
        response = client.get(path)
        assert response.status_code == 200
        assert "AuthGuard" in response.text

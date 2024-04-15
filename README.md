# AuthGuard API

Petite application d'authentification full-stack : FastAPI, SQLAlchemy, SQLite, Pydantic, Jinja2, HTML/CSS/JavaScript natif.

## Installation (Windows, PowerShell)

```powershell
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Si l'activation est bloquée : `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

Générez une clé secrète et collez-la dans `SECRET_KEY` (fichier `.env`) :

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

## Lancement

```powershell
python -m uvicorn app.main:app --reload
```

Ouvrir http://127.0.0.1:8000. La base `authguard.db` est créée automatiquement. Documentation interactive de l'API : http://127.0.0.1:8000/docs

## Tests

```powershell
python -m pytest -q
```

Les tests utilisent une base SQLite temporaire, séparée de `authguard.db`.

## API

| Méthode | Route | Description | Auth |
|---|---|---|---|
| GET | `/api/v1/auth/csrf` | Émet un jeton CSRF | non |
| POST | `/api/v1/auth/register` | Inscription (201) | non |
| POST | `/api/v1/auth/login` | Connexion, pose le cookie de session | non |
| POST | `/api/v1/auth/logout` | Déconnexion | non requise |
| GET | `/api/v1/auth/me` | Profil de l'utilisateur connecté | oui |
| GET | `/api/v1/protected` | Ressource protégée | oui |

Pages : `/register`, `/login`, `/dashboard`.

Erreurs : `{"detail": "..."}`. Pour les erreurs de validation (422) : `{"detail": "...", "errors": [{"field": "...", "message": "..."}]}`.

## Sécurité

- Mots de passe hachés avec Argon2id (`argon2-cffi`), jamais stockés ni renvoyés en clair.
- Session côté serveur : cookie `HttpOnly` + `SameSite` (`lax` par défaut), `Secure` activable. Seul le hash SHA-256 du jeton de session est stocké en base. Nouvelle session à chaque connexion, durée limitée.
- CSRF : toutes les requêtes `POST` exigent l'en-tête `X-CSRF-Token` égal au cookie CSRF (`HttpOnly`, `SameSite=Strict`) et signé par HMAC.
- Connexion : message identique si l'email est inconnu ou si le mot de passe est faux, avec vérification factice pour limiter les différences de temps de réponse.
- En-têtes : CSP stricte (aucun script ni style inline), `X-Frame-Options`, `nosniff`.

En production : servir en HTTPS et mettre `COOKIE_SECURE=true`.

## Limites connues (hors périmètre du MVP)

- Pas de limitation du nombre de tentatives de connexion (rate limiting).
- L'inscription renvoie 409 si l'email existe déjà, ce qui permet de tester l'existence d'un email. Seule la connexion est protégée contre cela.
- Pas de vérification d'email, ni de réinitialisation de mot de passe.

## Structure

```
app/
  main.py            application, gestion des erreurs, en-têtes
  config.py          configuration (.env)
  database.py        moteur et session SQLAlchemy
  models.py          modèles SQLAlchemy (User, UserSession)
  schemas.py         schémas Pydantic
  security.py        Argon2, jetons de session, CSRF
  dependencies.py    utilisateur courant, vérification CSRF
  routes/            auth.py (API), pages.py (HTML)
  services/          auth_service.py (logique métier)
  templates/         pages Jinja2
  static/            css/ et js/
tests/               tests Pytest
```

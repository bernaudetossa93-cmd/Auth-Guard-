"""Point d'entree FastAPI : python -m uvicorn app.main:app"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app import models  # noqa: F401  (enregistre les tables)
from app.database import Base, engine
from app.routes import auth, pages

BASE_DIR = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="AuthGuard API", version="1.0.0", lifespan=lifespan)

app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.include_router(auth.router)
app.include_router(pages.router)


# --- Erreurs de validation : format coherent et messages en francais --------

def _french_message(error: dict) -> str:
    kind = error.get("type", "")
    field = str(error["loc"][-1]) if error.get("loc") else ""
    ctx = error.get("ctx") or {}
    if kind == "missing":
        return "Ce champ est obligatoire."
    if kind == "string_too_short":
        return f"Ce champ doit contenir au moins {ctx.get('min_length')} caractères."
    if kind == "string_too_long":
        return f"Ce champ ne doit pas dépasser {ctx.get('max_length')} caractères."
    if kind in ("string_type", "string_parsing"):
        return "Ce champ doit être une chaîne de caractères."
    if field == "email":
        return "Adresse email invalide."
    if kind == "value_error":
        return str(error.get("msg", "")).removeprefix("Value error, ")
    return "Valeur invalide."


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_request: Request, exc: RequestValidationError):
    errors = []
    for error in exc.errors():
        if error.get("type") == "json_invalid":
            return JSONResponse(
                status_code=422,
                content={"detail": "Le corps de la requête n'est pas un JSON valide.", "errors": []},
            )
        field = ".".join(str(p) for p in error["loc"] if p not in ("body", "query", "path"))
        errors.append({"field": field, "message": _french_message(error)})
    return JSONResponse(
        status_code=422,
        content={"detail": "Les données envoyées sont invalides.", "errors": errors},
    )


# --- En-tetes de securite ----------------------------------------------------

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    path = request.url.path
    if not path.startswith(("/docs", "/redoc", "/openapi.json")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
    if path.startswith("/api/") or path in ("/dashboard", "/login", "/register"):
        response.headers["Cache-Control"] = "no-store"
    return response

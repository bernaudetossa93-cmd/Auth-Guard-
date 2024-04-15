"""Pages HTML (rendues avec Jinja2). Les donnees viennent de l'API via JavaScript."""
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.dependencies import get_optional_user
from app.models import User

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))
router = APIRouter(include_in_schema=False)


@router.get("/")
def index(user: User | None = Depends(get_optional_user)):
    return RedirectResponse("/dashboard" if user else "/login", status_code=303)


@router.get("/register")
def register_page(request: Request, user: User | None = Depends(get_optional_user)):
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(request, "register.html", {"title": "Inscription"})


@router.get("/login")
def login_page(request: Request, user: User | None = Depends(get_optional_user)):
    if user:
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"title": "Connexion"})


@router.get("/dashboard")
def dashboard_page(request: Request, user: User | None = Depends(get_optional_user)):
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dashboard.html", {"title": "Tableau de bord"})

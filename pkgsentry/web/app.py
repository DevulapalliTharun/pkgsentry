"""The dashboard and a read-only JSON API over the scan history. It never starts a scan and never writes to the history.

Everything shown comes from attacker-controlled text (package names, code, addresses), so: Jinja auto-escaping is on,
there is no JavaScript and no inline style, and a strict Content-Security-Policy blocks anything that slips through."""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from pkgsentry.fetch.pypi import validate_name
from pkgsentry.safe import defang, show_key
from pkgsentry.storage import StoredScan, ensure_schema, load_package, load_scans
from pkgsentry.web import views

_HERE = Path(__file__).resolve().parent
_SECURITY_HEADERS = {
    # Nothing but our own stylesheet and images: a script, frame or form post to elsewhere cannot run.
    "Content-Security-Policy": ("default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; "
                                "form-action 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def create_app(db: Path, allowed_hosts: list[str] | None = None) -> FastAPI:
    if not db.is_file():
        raise ValueError(f"no scan history at {db}; run scan --db {db} first")
    ensure_schema(db)  # a history file from an earlier step gains the newer tables
    app = FastAPI(title="PkgSentry", docs_url=None, redoc_url=None)  # the docs pages load scripts from a CDN
    # A browser on another website could otherwise reach this server through DNS rebinding.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or ["127.0.0.1", "localhost"])
    templates = Jinja2Templates(directory=_HERE / "templates")
    templates.env.filters.update(defang=defang, show_key=show_key, level_class=views.level_class)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.update(_SECURITY_HEADERS)
        return response

    @app.exception_handler(HTTPException)
    async def show_error(request: Request, error: HTTPException):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": error.detail}, status_code=error.status_code)
        return templates.TemplateResponse(request, "error.html", {"status": error.status_code, "page": "", "detail":
                                          error.detail}, status_code=error.status_code)

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request, level: str = "", q: str = ""):
        return templates.TemplateResponse(request, "overview.html",
                                          {"page": "overview", "view": views.overview(load_scans(db, signals=True),
                                                                                       level, q)})

    @app.get("/campaigns", response_class=HTMLResponse)
    def campaigns(request: Request):
        return templates.TemplateResponse(request, "campaigns.html", {
            "page": "campaigns", "campaigns": views.campaigns_from(load_scans(db))})

    @app.get("/package/{name}", response_class=HTMLResponse)
    def package(request: Request, name: str):
        scans = _package_scans(db, name)
        everything = load_scans(db)
        return templates.TemplateResponse(request, "package.html", {
            "page": "overview", "name": name, "scans": scans, "level": views.top_level(s.level for s in scans),
            "related": views.related(everything, name),
            "campaign": next((c.number for c in views.campaigns_from(everything) if name in c.packages), None)})

    @app.get("/api/overview")
    def api_overview():
        view = views.overview(load_scans(db))
        return {"packages": view.packages, "scans": view.scans, "levels": view.levels,
                "campaigns": len(view.campaigns), "linked_packages": view.linked_packages,
                "indicators": view.indicators}

    @app.get("/api/scans")
    def api_scans(level: str = "", q: str = ""):
        view = views.overview(load_scans(db, signals=True), level, q)
        return [{**_scan_json(row.scan), "campaign": row.campaign} for row in view.rows]

    @app.get("/api/packages/{name}")
    def api_package(name: str):
        return [_scan_json(scan, detail=True) for scan in _package_scans(db, name)]

    @app.get("/api/campaigns")
    def api_campaigns():
        return [{"number": c.number, "level": c.level, "packages": c.levels,
                 "links": [{"key": key, "packages": names} for key, names in c.links]}
                for c in views.campaigns_from(load_scans(db))]

    return app


def _package_scans(db: Path, name: str) -> list[StoredScan]:
    try:
        validate_name(name)
    except ValueError:
        raise HTTPException(404, "no such package") from None
    scans = load_package(db, name)
    if not scans:
        raise HTTPException(404, "no such package")
    return scans


def _scan_json(scan: StoredScan, detail: bool = False) -> dict:
    data = {"package": scan.package, "version": scan.version, "kind": scan.kind, "score": scan.score,
            "level": scan.level, "sha256": scan.sha256, "scanned_at": scan.scanned_at,
            "signals": [{"category": s.category, "points": s.points, "strength": s.strength, "context": s.context,
                         "detail": s.detail, "path": s.path, "line": s.line} for s in scan.signals]}
    data["indicators"] = [{"kind": i.kind, "value": i.value, "defanged": defang(i.value), "key": i.key, "path": i.path,
                           "line": i.line, "hidden_in_base64": i.hidden} for i in scan.indicators]
    if detail:
        data["excerpts"] = [{"tag": e.tag, "path": e.path, "flagged_lines": list(e.flagged), "rules": e.rules,
                             "code": list(e.body)} for e in scan.excerpts]
    return data

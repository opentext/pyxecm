"""Maintenance Page that can be enabled by the customizer."""

import os
from datetime import datetime

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
from pytz import UTC
from starlette.exceptions import HTTPException as StarletteHTTPException

from pyxecm.maintenance_page.settings import settings

app = FastAPI(openapi_url=None)

base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, "static")
templates = Jinja2Templates(directory=settings.templates_dir)


@app.get("/favicon.avif", include_in_schema=False)
async def favicon() -> FileResponse:
    """Serve the favicon."""
    return FileResponse(path=os.path.join(static_dir, "favicon.avif"))


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> Jinja2Templates:
    """Handle HTTP Exceptions."""

    if exc.status_code == 404:
        return templates.TemplateResponse(
            request=request,
            name="maintenance.html",
            context={
                "maint_title": settings.title,
                "maint_text": settings.text,
                "maint_footer": settings.footer,
                "status_url": settings.status_url,
                "copyright_year": datetime.now(tz=UTC).year,
            },
            status_code=513,
        )
    else:
        return templates.TemplateResponse("error.html", {"request": request, "status_code": exc.status_code})


def run_maintenance_page() -> None:
    """Start the FASTAPI Webserver."""
    uvicorn.run(app, host=settings.host, port=settings.port)

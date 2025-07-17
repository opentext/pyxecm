"""API Implemenation for the Customizer to start and control the payload processing."""

import logging
import mimetypes
import os
import signal
import tempfile
from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse

from pyxecm_api.auth.functions import get_authorized_user
from pyxecm_api.auth.models import User

from .functions import PAYLOAD_LIST, list_files_in_directory
from .models import CustomizerStatus

router = APIRouter()

logger = logging.getLogger("pyxecm_api.common")


@router.get("/", include_in_schema=False)
async def redirect_to_api(request: Request) -> RedirectResponse:
    """Redirect from / to /api.

    Returns:
        None

    """
    return RedirectResponse(url=f"{request.url.path}api")


@router.get(path="/status", name="Get Status")
async def get_status() -> CustomizerStatus:
    """Get the status of the Customizer."""

    df = PAYLOAD_LIST.get_payload_items()

    if df is None:
        raise HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail="Payload list is empty.",
        )

    all_status = df["status"].value_counts().to_dict()

    return CustomizerStatus(
        version=2,
        customizer_duration=(all_status.get("running", None)),
        customizer_end_time=None,
        customizer_start_time=None,
        status_details=all_status,
        status="Running" if "running" in all_status else "Stopped",
        debug=df["log_debug"].sum(),
        info=df["log_info"].sum(),
        warning=df["log_warning"].sum(),
        error=df["log_error"].sum(),
        critical=df["log_critical"].sum(),
    )


@router.get("/api/shutdown", include_in_schema=False)
def shutdown(user: Annotated[User, Depends(get_authorized_user)]) -> JSONResponse:
    """Endpoint to end the application."""

    logger.warning(
        "Shutting down the API - Requested via api by user -> %s",
        user.id,
    )
    os.kill(os.getpid(), signal.SIGTERM)

    return JSONResponse({"status": "shutdown"}, status_code=HTTPStatus.ACCEPTED)


@router.get(path="/browser_automations/assets", tags=["payload"])
def list_browser_automation_files(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
) -> JSONResponse:
    """List all browser automation files."""

    result = list_files_in_directory(
        os.path.join(
            tempfile.gettempdir(),
            "browser_automations",
        )
    )

    return JSONResponse(result)


@router.get(path="/browser_automations/download", tags=["payload"])
def get_browser_automation_file(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    file: Annotated[str, Query(description="File name")],
) -> FileResponse:
    """Download the logfile for a specific payload."""

    filename = os.path.join(tempfile.gettempdir(), "browser_automations", file)

    if not os.path.isfile(filename):
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="File -> '{}' not found".format(filename),
        )

    media_type, _ = mimetypes.guess_type(filename)

    with open(filename, "rb") as f:
        content = f.read()

    return Response(
        content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{os.path.basename(filename)}"',
        },
    )

"""Define router for v1_otcs."""

import logging
import os
import shutil
from http import HTTPStatus
from threading import Lock, Thread
from typing import Annotated

import anyio
from fastapi import APIRouter, Body, Depends, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pyxecm_customizer.k8s import K8s

from pyxecm_api.auth.functions import get_authorized_user
from pyxecm_api.auth.models import User
from pyxecm_api.common.functions import get_k8s_object, get_otcs_logs_lock, get_settings
from pyxecm_api.settings import CustomizerAPISettings

from .functions import collect_otcs_logs

router = APIRouter(prefix="/api/v1/otcs", tags=["otcs"])

logger = logging.getLogger("pyxecm_api.v1_otcs")


@router.put(path="/logs", tags=["otcs"])
async def put_otcs_logs(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    otcs_logs_lock: Annotated[dict[str, Lock], Depends(get_otcs_logs_lock)],
    hosts: Annotated[list[str], Body()],
) -> JSONResponse:
    """Collect the logs from the given OTCS instances."""

    if "all" in hosts:
        hosts = []
        for sts in ["otcs-admin", "otcs-frontend", "otcs-backend-search", "otcs-da"]:
            try:
                sts_replicas = k8s_object.get_stateful_set_scale(sts)

                if sts_replicas is None:
                    logger.debug("Cannot get statefulset {sts}")
                    continue

                hosts.extend([f"{sts}-{i}" for i in range(sts_replicas.status.replicas)])
            except Exception as e:
                raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR) from e

    msg = {}
    for host in hosts:
        if host not in otcs_logs_lock:
            otcs_logs_lock[host] = Lock()

        if not otcs_logs_lock[host].locked():
            Thread(target=collect_otcs_logs, args=(host, k8s_object, otcs_logs_lock[host], settings)).start()
            msg[host] = {"status": "ok", "message": "Logs are being collected"}
        else:
            msg[host] = {"status": "error", "message": "Logs are already being collected"}

    status = (
        HTTPStatus.TOO_MANY_REQUESTS if any(msg[host]["status"] == "error" for host in msg) else HTTPStatus.ACCEPTED
    )
    return JSONResponse(msg, status_code=status)


@router.post("/logs/upload", tags=["otcs"], include_in_schema=True)
async def post_otcs_log_file(
    file: Annotated[UploadFile, File(...)],
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    key: str = "",
) -> JSONResponse:
    """Upload a file to disk.

    Args:
        file: File to be uploaded.
        settings: CustomizerAPISettings.
        key: Key to validate the upload.

    Returns:
        JSONResponse: Status of the upload

    """
    if key != settings.upload_key:
        raise HTTPException(status_code=403, detail="Invalid Uploadkey")

    os.makedirs(settings.upload_folder, exist_ok=True)

    try:
        async with await anyio.open_file(os.path.join(settings.upload_folder, file.filename), "wb") as f:
            # Process the file in chunks instead of loading the entire file into memory
            while True:
                chunk = await file.read(65536)  # Read 64KB at a time
                if not chunk:
                    break
                await f.write(chunk)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Something went wrong") from e
    finally:
        await file.close()

    return {"message": f"Successfully uploaded {file.filename}"}


@router.get("/logs", tags=["otcs"])
async def get_otcs_log_files(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    otcs_logs_lock: Annotated[dict[str, Lock], Depends(get_otcs_logs_lock)],
) -> JSONResponse:
    """List all otcs logs that can be downloaded."""

    os.makedirs(settings.upload_folder, exist_ok=True)

    files = []
    for filename in sorted(os.listdir(settings.upload_folder)):
        file_path = os.path.join(settings.upload_folder, filename)
        if os.path.isfile(file_path):
            file_size = os.path.getsize(file_path)
            files.append({"filename": filename, "size": file_size})

    response = {"status": {host: bool(otcs_logs_lock[host].locked()) for host in otcs_logs_lock}, "files": files}

    # Extend response with all hosts
    for sts in ["otcs-admin", "otcs-frontend", "otcs-backend-search", "otcs-da"]:
        try:
            sts_replicas = k8s_object.get_stateful_set_scale(sts)

            if sts_replicas is None:
                logger.debug("Cannot get statefulset {sts}")
                continue

            for i in range(sts_replicas.status.replicas):
                host = f"{sts}-{i}"

                if host in otcs_logs_lock:
                    response["status"][host] = otcs_logs_lock[host].locked()
                else:
                    response["status"][host] = False

        except Exception as e:
            raise HTTPException(status_code=HTTPStatus.INTERNAL_SERVER_ERROR) from e

    return JSONResponse(response, status_code=HTTPStatus.OK)


@router.delete("/logs", tags=["otcs"])
async def delete_otcs_log_files(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
) -> JSONResponse:
    """Delete all otcs log files."""
    shutil.rmtree(settings.upload_folder)
    return JSONResponse({"message": "Successfully deleted all files"}, status_code=HTTPStatus.OK)


@router.delete("/logs/{file_name}", tags=["otcs"])
async def delete_otcs_log_file(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    file_name: str,
) -> FileResponse:
    """Delete single OTCS log archive."""
    file_path = os.path.join(settings.upload_folder, file_name)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    try:
        os.remove(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{e}") from e

    return JSONResponse({"message": f"Successfully deleted {file_name}"}, status_code=HTTPStatus.OK)


@router.get("/logs/{file_name}", tags=["otcs"])
async def get_otcs_log_file(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    file_name: str,
) -> FileResponse:
    """Download OTCS log archive."""
    file_path = os.path.join(settings.upload_folder, file_name)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(file_path, media_type="application/octet-stream", filename=file_name)

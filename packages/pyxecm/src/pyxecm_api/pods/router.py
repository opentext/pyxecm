"""Define router for the pods of the namespace.

Only included when the setting pod_access is on (it follows ws_terminal): these endpoints give
the same access to the pods as a terminal in them.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import contextlib
import logging
import posixpath
from http import HTTPStatus
from typing import Annotated

import anyio
from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pyxecm_customizer.k8s import K8s

from pyxecm_api.auth.functions import get_authorized_user
from pyxecm_api.auth.models import User
from pyxecm_api.common.functions import get_k8s_object, get_settings
from pyxecm_api.settings import CustomizerAPISettings, api_settings
from pyxecm_api.v1_payload.functions import GrowingFileResponse, lines_request_from_query, run_log_read
from pyxecm_api.v1_payload.log_reader import LogLinesRequest, read_log_info, read_log_lines
from pyxecm_api.v1_payload.models import PayloadLogLines

from .functions import (
    UPLOAD_SCRIPT,
    ProcessResponse,
    acquire_transfer,
    check_file_name,
    check_path,
    command_error,
    content_disposition,
    list_folder,
    pod_item,
    probe_path,
    release_transfer,
    resolve_target,
    shell,
    start_exec,
    stop_process,
)
from .log_spool import LogSession, LogSpool, TooManySessionsError
from .models import (
    PodFileListing,
    PodFileUploaded,
    PodList,
    PodLogInfo,
    PodLogRequest,
    PodLogSession,
)

router = APIRouter(prefix="/api/v1/pods", tags=["pods"])

logger = logging.getLogger("pyxecm_api.pods")

LOG_SPOOL = LogSpool(api_settings)

ContainerQuery = Annotated[
    str | None,
    Query(description="The container. Without it, the default container of the pod."),
]


@router.get(path="")
async def get_pods(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
) -> PodList:
    """List the pods of the namespace with their containers and what runs them."""

    pods = await anyio.to_thread.run_sync(k8s_object.list_pods)
    if pods is None:
        raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail="Cannot list the pods")

    items = sorted((pod_item(pod) for pod in pods.items), key=lambda item: item.name)
    return PodList(namespace=k8s_object.get_namespace(), pods=items)


@router.get(path="/{pod}/files")
async def get_pod_files(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    pod: str,
    path: Annotated[str, Query(description="The folder to list (absolute).")] = "/",
    container: ContainerQuery = None,
) -> PodFileListing:
    """List a folder in a container of a pod (at most 5,000 entries)."""

    target = await resolve_target(k8s_object, pod, container)
    path = check_path(path)
    entries, truncated = await list_folder(target, path)
    return PodFileListing(pod=pod, container=target.container, path=path, entries=entries, truncated=truncated)


@router.get(path="/{pod}/files/download")
async def download_pod_file(
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    pod: str,
    path: Annotated[str, Query(description="The file or folder to download (absolute).")],
    container: ContainerQuery = None,
) -> ProcessResponse:
    """Download a file from a container of a pod, or a folder as a .tar.gz archive.

    The content is sent while it is read in the pod. A file is announced with its size, an
    archive is not (its size is not known before it is made).
    """

    target = await resolve_target(k8s_object, pod, container)
    path = check_path(path)
    kind, size = await probe_path(target, path)

    token = acquire_transfer()
    try:
        if kind == "file":
            name = posixpath.basename(path)
            # A file that grows while it is sent (a log) is sent up to the size it had.
            process = await start_exec(target, ["head", "-c", str(size), "--", path])
            headers = {"Content-Length": str(size)}
        else:
            parent, folder = posixpath.split(path)
            if not folder:
                parent, folder = "/", "."
            name = "{}.tar.gz".format(folder if folder != "." else pod)
            process = await start_exec(target, ["tar", "-C", parent, "-czf", "-", "--", folder])
            headers = {}
    except BaseException:
        release_transfer(token)
        raise

    description = "'{}' of pod -> '{}' (container -> '{}')".format(path, pod, target.container)
    logger.info("User -> '%s' downloads %s", user.id, description)
    headers["Content-Disposition"] = content_disposition(name)
    return ProcessResponse(process, token, description, media_type="application/octet-stream", headers=headers)


@router.post(path="/{pod}/files/upload")
async def upload_pod_file(
    request: Request,
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    settings: Annotated[CustomizerAPISettings, Depends(get_settings)],
    pod: str,
    path: Annotated[str, Query(description="The folder to upload into (absolute).")],
    name: Annotated[str, Query(description="The name of the file.")],
    container: ContainerQuery = None,
    overwrite: Annotated[bool, Query(description="Replace a file of that name.")] = False,
    unchanged_since: Annotated[
        int | None,
        Query(
            description="The modification time (seconds since the epoch) the file must still have - "
            "it was not changed since it was opened for editing. Otherwise 412.",
        ),
    ] = None,
) -> PodFileUploaded:
    """Upload a file into a folder of a container of a pod.

    The request body is the content of the file (not a form) and must have a Content-Length.
    The file only appears once it arrived completely. Without `overwrite`, an existing file
    of the same name is answered with 409. A replaced file keeps its permissions and owner, and
    a link stays a link (the file it points to is written).
    """

    length = request.headers.get("content-length")
    if length is None or not length.isdigit():
        raise HTTPException(status_code=HTTPStatus.LENGTH_REQUIRED, detail="The upload needs a Content-Length")
    size = int(length)
    if size > settings.pod_upload_max_bytes:
        raise HTTPException(
            status_code=HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
            detail="The file is larger than {} bytes".format(settings.pod_upload_max_bytes),
        )

    target = await resolve_target(k8s_object, pod, container)
    path = check_path(path)
    name = check_file_name(name)
    file_path = posixpath.join(path, name)

    token = acquire_transfer()
    try:
        process = await start_exec(
            target,
            shell(
                UPLOAD_SCRIPT,
                path,
                name,
                "1" if overwrite else "0",
                str(size),
                "" if unchanged_since is None else str(unchanged_since),
            ),
            stdin=True,
        )
        try:
            received = 0
            # The script may stop reading before everything was sent (the file exists): the
            # rest of the body is not wanted then, its exit code tells why.
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > size:
                        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="More data than announced")
                    process.stdin.write(chunk)
                    await process.stdin.drain()
                process.stdin.close()
            stdout, stderr = await process.communicate()
        finally:
            await stop_process(process)
    finally:
        release_transfer(token)

    if process.returncode:
        raise command_error(process.returncode, stderr, file_path)
    if received != size:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="The upload is incomplete")

    logger.info(
        "User -> '%s' uploaded '%s' (%s bytes) into pod -> '%s' (container -> '%s')",
        user.id,
        file_path,
        size,
        pod,
        target.container,
    )
    written = stdout.decode("utf-8", errors="replace").strip()
    return PodFileUploaded(
        pod=pod,
        container=target.container,
        path=file_path,
        size=size,
        mtime=int(written) if written.isdigit() else None,
    )


@router.post(path="/{pod}/logs")
async def open_pod_log(
    user: Annotated[User, Depends(get_authorized_user)],
    k8s_object: Annotated[K8s, Depends(get_k8s_object)],
    pod: str,
    log: Annotated[PodLogRequest, Body()],
) -> PodLogSession:
    """Open a log of a pod: the output of a container, or a file in it.

    The log is followed into a copy that is read with the `info`, `lines` and `download`
    endpoints of the returned session - the same way as a payload log. A session nobody reads
    for a while ends (404): open the log again then.
    """

    target = await resolve_target(k8s_object, pod, log.container)
    path = None
    if log.source == "file":
        path = check_path(log.path)
        kind, _size = await probe_path(target, path)
        if kind != "file":
            raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="'{}' is a folder".format(path))

    try:
        session = await anyio.to_thread.run_sync(LOG_SPOOL.open, target, log.source, path)
    except TooManySessionsError as exc:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="Too many pod logs are open, try again later",
        ) from exc

    logger.info("User -> '%s' opened the log -> %s of pod -> '%s'", user.id, path or log.source, pod)
    return PodLogSession(id=session.id, pod=pod, container=target.container, source=log.source, path=path)


def get_log_session(pod: str, session_id: str) -> LogSession:
    """Get an opened log of a pod.

    Raises:
        HTTPException:
            There is no such log (any more) (404).

    """

    session = LOG_SPOOL.get(session_id)
    if session is None or session.target.pod != pod:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="The log is not open (any more)")
    return session


@router.get(path="/{pod}/logs/{session_id}/info")
async def get_pod_log_info(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    session: Annotated[LogSession, Depends(get_log_session)],
) -> PodLogInfo:
    """Describe the copy of a pod log, like the info of a payload log."""

    try:
        info = await run_log_read(None, read_log_info, session.spool, session.running())
    except FileNotFoundError as exc:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="The log is not open (any more)") from exc

    return PodLogInfo(**info, capped=session.capped, error=session.error())


@router.get(path="/{pod}/logs/{session_id}/lines")
async def get_pod_log_lines(
    request: Request,
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    session: Annotated[LogSession, Depends(get_log_session)],
    lines_request: Annotated[LogLinesRequest, Depends(lines_request_from_query)],
) -> PayloadLogLines:
    """Read a window of lines of a pod log, optionally filtered - like the lines of a payload log."""

    try:
        result = await run_log_read(request, read_log_lines, session.spool, session.running(), lines_request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="The log is not open (any more)") from exc

    return PayloadLogLines(**result)


@router.get(path="/{pod}/logs/{session_id}/download")
async def download_pod_log(
    user: Annotated[User, Depends(get_authorized_user)],  # noqa: ARG001
    session: Annotated[LogSession, Depends(get_log_session)],
) -> Response:
    """Download the copy of a pod log as it is now."""

    if session.path:
        name = posixpath.basename(session.path)
    else:
        name = "{}_{}{}.log".format(
            session.target.pod,
            session.target.container,
            "_previous" if session.source == "previous" else "",
        )
    return GrowingFileResponse(
        session.spool,
        media_type="application/octet-stream",
        headers={"Content-Disposition": content_disposition(name), "Cache-Control": "no-cache"},
    )

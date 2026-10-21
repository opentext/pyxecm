"""API Implementation for the Customizer to start and control the payload processing."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import asyncio
import logging
import os
import threading
from collections.abc import AsyncGenerator, Callable
from http import HTTPStatus
from typing import Annotated, Any

import anyio
from anyio.lowlevel import RunVar
from fastapi import HTTPException, Query, Request
from fastapi.responses import FileResponse
from opentelemetry import trace
from pyxecm_customizer.exceptions import PayloadImportError
from pyxecm_customizer.payload import load_payload
from starlette.types import Message, Receive, Scope, Send

from pyxecm_api.common.functions import PAYLOAD_LIST
from pyxecm_api.settings import api_settings

from .log_reader import DEFAULT_LIMIT, DEFAULT_MAX_BYTES, LogLinesRequest, build_lines_request

tracer = trace.get_tracer(__name__)
logger = logging.getLogger("pyxecm_api.v1_payload")

# Number of log files that are read or searched at the same time. It keeps the worker threads
# (and the CPU) available for the rest of the API while large logs are scanned.
LOG_READERS = 4
# Interval at which a running log read checks whether its client is still connected.
CLIENT_CHECK_SECONDS = 0.25
_log_read_limiter: RunVar[anyio.CapacityLimiter] = RunVar("log_read_limiter")

# Initialize the global Payloadlist object


def import_payload(
    payload: str | None = None,
    payload_dir: str | None = None,
    enabled: bool | None = None,
    dependencies: bool | None = None,
) -> None:
    """Automatically load payload items from disk of a given directory.

    Args:
        payload (str):
            The name of the payload.
        payload_dir (str):
            The local path.
        enabled (bool, optional):
            Automatically start the processing (True), or only define items (False).
            Defaults to False.
        dependencies (bool, optional):
            Automatically add dependency on the last payload in the queue

    """

    def import_payload_file(
        filename: str,
        enabled: bool | None,
        dependencies: bool | None,
    ) -> None:
        if not os.path.isfile(filename):
            return

        if not (filename.endswith((".yaml", ".tfvars", ".tf", ".yml.gz.b64"))):
            logger.debug("Skipping file: %s", filename)
            return

        # Load payload file
        payload_content = load_payload(filename)
        if payload_content is None:
            exception = f"The import of payload -> {filename} failed. Payload content could not be loaded."
            raise PayloadImportError(exception)

        payload_options = payload_content.get("payloadOptions", {})

        if enabled is None:
            enabled = payload_options.get("enabled", True)
            enabled = False if isinstance(enabled, str) and enabled.lower() == "false" else bool(enabled)

        # read name from options section if specified, otherwise take filename
        name = payload_options.get("name", os.path.basename(filename))

        # Get the loglevel from payloadOptions if set, otherwise use the default loglevel
        loglevel = payload_options.get("loglevel", api_settings.loglevel)

        # Get the git_url
        git_url = payload_options.get("git_url", None)

        # Dependency Management
        if dependencies is None:
            dependencies = []

            # Get all dependencies from payloadOptions and resolve their ID
            for dependency_name in payload_options.get("dependencies", []):
                dependend_item = PAYLOAD_LIST.get_payload_item_by_name(dependency_name)

                if dependend_item is None:
                    exception = (
                        f"The import of payload -> {name} failed. Dependencies cannot be resolved: {dependency_name}",
                    )
                    raise PayloadImportError(
                        exception,
                    )
                # Add the ID to the list of dependencies
                dependencies.append(dependend_item["index"])

        elif dependencies:
            try:
                payload_items = len(PAYLOAD_LIST.get_payload_items()) - 1
                dependencies = [payload_items] if payload_items != -1 else []
            except Exception:
                dependencies = []
        else:
            dependencies = []

        customizer_settings = payload_content.get("customizerSettings", {})

        logger.info("Adding payload: %s", filename)
        payload = PAYLOAD_LIST.add_payload_item(
            name=name,
            filename=filename,
            status="planned",
            logfile=f"{api_settings.logfolder}/{name}.log",
            dependencies=dependencies,
            enabled=enabled,
            git_url=git_url,
            loglevel=loglevel,
            customizer_settings=customizer_settings,
        )
        dependencies = payload["index"]

        return

    if payload is None and payload_dir is None:
        exception = "No payload or payload_dir provided"
        raise ValueError(exception)

    if payload and os.path.isdir(payload) and payload_dir is None:
        payload_dir = payload

    if payload_dir is None:
        try:
            import_payload_file(payload, enabled, dependencies)
        except PayloadImportError as exc:
            logger.error(exc)
            logger.debug(exc, exc_info=True)
        return

    elif not os.path.isdir(payload_dir):
        return

    for filename in sorted(os.listdir(payload_dir)):
        try:
            with tracer.start_as_current_span("import_payload") as t:
                t.set_attribute("payload", filename)
                import_payload_file(os.path.join(payload_dir, filename), enabled, dependencies)
        except PayloadImportError as exc:
            logger.error(exc)
            logger.debug(exc, exc_info=True)


def prepare_dependencies(dependencies: list) -> list | None:
    """Convert the dependencies string to a list of integers."""
    try:
        list_all = dependencies[0].split(",")
    except IndexError:
        return None

    # Remove empty values from the list
    items = list(filter(None, list_all))
    converted_list = []
    for item in items:
        try:
            converted_list.append(int(item))
        except ValueError:
            continue

    return converted_list


async def tail_log(file_path: str) -> AsyncGenerator[str]:
    """Asynchronously follow the log file like `tail -f`."""
    try:
        async with await anyio.open_file(file_path) as file:
            # Move the pointer to the end of the file
            await file.seek(0, os.SEEK_END)

            while True:
                # Read new line
                line = await file.readline()
                if not line:
                    # Sleep for a little while before checking for new lines
                    await asyncio.sleep(0.5)
                    continue
                yield line
    except asyncio.exceptions.CancelledError:
        pass


class GrowingFileResponse(FileResponse):
    """A file download for a file that may be appended to while it is sent.

    The size of the file is announced before its content is sent. The plain `FileResponse`
    then sends the file up to its end, which is more than announced if the file grew meanwhile,
    and the server aborts such a response. This response sends exactly the announced bytes.
    Everything else, `Range` requests included, is the behaviour of `FileResponse`.
    """

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Send the response.

        Args:
            scope (Scope):
                The ASGI connection scope.
            receive (Receive):
                The ASGI receive channel.
            send (Send):
                The ASGI send channel.

        """

        remaining: int | None = None
        complete = False

        async def send_bounded(message: Message) -> None:
            nonlocal remaining, complete

            if message["type"] == "http.response.start":
                for name, value in message.get("headers", []):
                    if name.lower() == b"content-length":
                        remaining = int(value)
            elif message["type"] == "http.response.body" and remaining is not None:
                # Whatever is read beyond the announced size is dropped.
                if complete:
                    return
                body = message.get("body", b"")
                if len(body) >= remaining:
                    message = {**message, "body": body[:remaining], "more_body": False}
                    complete = True
                remaining -= len(message["body"])
            await send(message)

        # Have the file sent by this response, not by the server, which knows nothing
        # about the announced size.
        extensions = scope.get("extensions") or {}
        if "http.response.pathsend" in extensions:
            scope = {**scope, "extensions": {k: v for k, v in extensions.items() if k != "http.response.pathsend"}}

        await super().__call__(scope, receive, send_bounded)


def _get_log_read_limiter() -> anyio.CapacityLimiter:
    """Get the limiter for concurrent log reads of the running event loop."""

    try:
        return _log_read_limiter.get()
    except LookupError:
        limiter = anyio.CapacityLimiter(LOG_READERS)
        _log_read_limiter.set(limiter)
        return limiter


async def run_log_read(request: Request | None, function: Callable[..., Any], *args: Any) -> Any:  # noqa: ANN401
    """Run a function that reads a log file in a worker thread, off the event loop.

    Args:
        request (Request | None):
            The request the result is for. If given, the function gets a `threading.Event`
            as its last argument, which is set as soon as the client disconnects, so that
            a long scan stops when nobody waits for its result any more.
        function (Callable):
            The function to run.
        *args (Any):
            The arguments of the function.

    Returns:
        Any:
            The result of the function.

    """

    limiter = _get_log_read_limiter()
    if request is None:
        return await anyio.to_thread.run_sync(function, *args, limiter=limiter)

    cancel = threading.Event()
    result = None
    error: Exception | None = None

    async def watch_client() -> None:
        # Most reads are done long before the first look at the connection.
        while True:
            await anyio.sleep(CLIENT_CHECK_SECONDS)
            if await request.is_disconnected():
                break
        cancel.set()

    try:
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(watch_client)
            # An error must not leave the task group: it would arrive wrapped in a group.
            try:
                result = await anyio.to_thread.run_sync(function, *args, cancel, limiter=limiter)
            except Exception as exc:
                error = exc
            task_group.cancel_scope.cancel()
    finally:
        # Also stops the scan if this request itself is cancelled.
        cancel.set()

    if error is not None:
        raise error
    return result


def lines_request_from_query(
    offset: Annotated[
        int | None,
        Query(description="Byte offset to start at. It is snapped back to the start of the line containing it."),
    ] = None,
    line: Annotated[
        int | None,
        Query(description="Line number (1-based) to start at. Alternative to the offset."),
    ] = None,
    direction: Annotated[
        str,
        Query(
            description="'forward' returns the lines from the start position on, "
            "'backward' the lines before it. Without start position, 'forward' starts "
            "at the beginning of the logfile and 'backward' at its end.",
        ),
    ] = "forward",
    limit: Annotated[int, Query(description="Maximum number of lines to return (0 to 5000).")] = DEFAULT_LIMIT,
    max_bytes: Annotated[
        int,
        Query(description="Soft cap on the summed size of the returned lines. At most 4 MiB are used."),
    ] = DEFAULT_MAX_BYTES,
    levels: Annotated[
        str | None,
        Query(
            description="Comma separated list of the levels to return (DEBUG, INFO, WARNING, ERROR). "
            "Lines without a level are always returned. An empty value returns only those.",
        ),
    ] = None,
    q: Annotated[str | None, Query(description="Text to search for. Only matching lines are returned.")] = None,
    regex: Annotated[bool, Query(description="The search text is a regular expression (Python syntax).")] = False,
    case: Annotated[bool, Query(description="Match the case of the search text.")] = False,
    word: Annotated[bool, Query(description="Match whole words only.")] = False,
    count_only: Annotated[
        bool,
        Query(description="Return no lines but count them. The limit and max_bytes are ignored."),
    ] = False,
) -> LogLinesRequest:
    """Read the query parameters of a request for log lines (a dependency of the `/lines` endpoints).

    The payload logs and the pod logs are read with the same parameters (see `build_lines_request`).

    Raises:
        HTTPException:
            A parameter is invalid (400).

    Returns:
        LogLinesRequest:
            The request.

    """

    try:
        return build_lines_request(
            offset=offset,
            line=line,
            direction=direction,
            limit=limit,
            max_bytes=max_bytes,
            levels=levels,
            q=q,
            regex=regex,
            case=case,
            word=word,
            count_only=count_only,
        )
    except ValueError as exc:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail=str(exc)) from exc

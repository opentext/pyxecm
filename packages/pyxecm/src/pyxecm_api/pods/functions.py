"""Define functions for the pods: check what a request names, run commands in pods, list folders."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import asyncio
import contextlib
import logging
import os
import posixpath
import re
import stat
from collections.abc import AsyncIterator
from dataclasses import dataclass
from http import HTTPStatus
from typing import Any
from urllib.parse import quote

import anyio
from anyio.lowlevel import RunVar
from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from kubernetes.client import V1Pod
from pyxecm_customizer.k8s import K8s
from starlette.types import Receive, Scope, Send

from pyxecm_api.settings import api_settings

from .models import PodContainer, PodFileEntry, PodItem

logger = logging.getLogger("pyxecm_api.pods")

# Names as Kubernetes allows them: a pod is named like a DNS subdomain, a container like a DNS
# label. Checking them keeps a name from being taken for an option of kubectl.
POD_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
CONTAINER_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
MAX_PATH_LENGTH = 4096
MAX_NAME_BYTES = 255

# Most entries of a folder that are listed, and the most output read for them.
MAX_ENTRIES = 5000
MAX_LISTING_BYTES = 16 * 1024 * 1024
# Time a command that only looks at something (a listing, a file's size) may take.
SCRIPT_TIMEOUT_SECONDS = 60
CHUNK_BYTES = 256 * 1024
# Time an ended command gets to close its pipes.
STOP_TIMEOUT_SECONDS = 10

# Exit codes of the scripts below, and what they mean for a request.
EXIT_NOT_FOUND = 3
EXIT_NOT_A_FOLDER = 4
EXIT_NO_PERMISSION = 5
EXIT_EXISTS = 17
EXIT_IS_A_FOLDER = 21
EXIT_INCOMPLETE = 22
EXIT_CHANGED = 23

# Lists a folder: with GNU find, the entries separated by NUL bytes (any name works). Where find
# has no -printf (busybox), with stat, one entry per line, after a "#stat" line.
LIST_SCRIPT = r"""
[ -e "$1" ] || exit 3
[ -d "$1" ] || exit 4
cd -- "$1" 2>/dev/null || exit 5
[ -r . ] || exit 5
if find . -maxdepth 0 -printf '' 2>/dev/null; then
  exec find . -mindepth 1 -maxdepth 1 -printf '%y\0%Y\0%s\0%T@\0%m\0%u\0%g\0%l\0%f\0'
fi
echo '#stat'
set -- .[!.]* ..?* *
for f do
  shift
  if [ -e "$f" ] || [ -L "$f" ]; then set -- "$@" "$f"; fi
done
[ $# -eq 0 ] || exec stat -c '%f/%s/%Y/%a/%U/%G/%n' -- "$@"
"""
LIST_FIELDS = 9

# Tells what a path is: "dir", or "file <size>".
PROBE_SCRIPT = r"""
[ -e "$1" ] || exit 3
[ -r "$1" ] || exit 5
if [ -d "$1" ]; then echo dir; exit 0; fi
[ -f "$1" ] || exit 4
s=$(stat -L -c %s -- "$1" 2>/dev/null) || s=$(( $(wc -c < "$1") ))
echo "file $s"
"""

# Writes stdin into the file $2 of the folder $1: first into a part file, which is renamed once
# exactly $4 bytes arrived, so an upload that breaks off leaves nothing behind. $3 = 1 replaces an
# existing file - keeping its permissions and owner, and through a link the file it points to (an
# edited script stays executable, a linked config stays linked). $5, if set, is the modification
# time (seconds) the file must still have: it was not changed since it was opened for editing.
# Prints the modification time of the written file.
UPLOAD_SCRIPT = r"""
[ -e "$1" ] || exit 3
[ -d "$1" ] || exit 4
target="$1/$2"
[ ! -d "$target" ] || exit 21
[ "$3" = 1 ] || [ ! -e "$target" ] || exit 17
dest="$target"
if [ -L "$target" ]; then dest=$(readlink -f -- "$target") && [ -n "$dest" ] || exit 5; fi
[ ! -d "$dest" ] || exit 21
mtime() { stat -c %Y -- "$1" 2>/dev/null || date -r "$1" +%s; }
if [ -n "$5" ] && [ -e "$dest" ] && [ "$(mtime "$dest")" != "$5" ]; then exit 23; fi
part="$(dirname -- "$dest")/.$(basename -- "$dest").part-$$"
if ! cat > "$part"; then rm -f -- "$part"; exit 5; fi
size=$(stat -c %s -- "$part" 2>/dev/null) || size=$(( $(wc -c < "$part") ))
if [ "$size" -ne "$4" ]; then rm -f -- "$part"; exit 22; fi
if [ -e "$dest" ]; then
  mode=$(stat -c %a -- "$dest" 2>/dev/null || stat -f %Lp "$dest" 2>/dev/null) && chmod "$mode" "$part" 2>/dev/null
  owner=$(stat -c %u:%g -- "$dest" 2>/dev/null) && chown "$owner" "$part" 2>/dev/null
fi
mv -f -- "$part" "$dest" || { rm -f -- "$part"; exit 5; }
mtime "$dest"
"""

_transfer_limiter: RunVar[anyio.CapacityLimiter] = RunVar("pod_transfer_limiter")


@dataclass(frozen=True)
class PodTarget:
    """A container of a pod that commands run in."""

    namespace: str
    pod: str
    container: str


def is_pod_name(name: str) -> bool:
    """Check whether a name is a valid pod name."""

    return bool(POD_NAME_RE.match(name))


def is_container_name(name: str) -> bool:
    """Check whether a name is a valid container name."""

    return bool(CONTAINER_NAME_RE.match(name))


def check_path(path: str | None) -> str:
    """Check a path that a request names and normalize it.

    Args:
        path (str | None):
            The path. It has to be absolute.

    Raises:
        HTTPException:
            The path is missing, relative, too long or contains a NUL character (400).

    Returns:
        str:
            The normalized path ("/opt/x/../y/" -> "/opt/y").

    """

    if not path or not path.startswith("/") or "\0" in path or len(path) > MAX_PATH_LENGTH:
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="The path has to be absolute: '{}'".format(path))
    normalized = posixpath.normpath(path)
    # normpath keeps a leading "//" (POSIX allows it a meaning), a pod does not need that.
    return "/" + normalized.lstrip("/")


def check_file_name(name: str | None) -> str:
    """Check the name of a file that is uploaded.

    Raises:
        HTTPException:
            The name is empty, too long or not a plain file name (400).

    Returns:
        str:
            The name.

    """

    if (
        not name
        or name in (".", "..")
        or "/" in name
        or "\0" in name
        or len(name.encode("utf-8", errors="surrogateescape")) > MAX_NAME_BYTES
    ):
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Invalid file name: '{}'".format(name))
    return name


def workload_of(pod: V1Pod) -> tuple[str | None, str | None]:
    """Tell what runs a pod.

    A pod of a Deployment is owned by a ReplicaSet whose name is the name of the Deployment and
    the hash of the pod template - the Deployment is what keeps its name.

    Returns:
        tuple[str | None, str | None]:
            The kind and the name of the workload, None for a pod nothing owns.

    """

    for owner in pod.metadata.owner_references or []:
        if not owner.controller:
            continue
        if owner.kind == "ReplicaSet":
            template_hash = (pod.metadata.labels or {}).get("pod-template-hash")
            if template_hash and owner.name.endswith("-" + template_hash):
                return "Deployment", owner.name[: -len(template_hash) - 1]
        return owner.kind, owner.name
    return None, None


def default_container(pod: V1Pod) -> str:
    """Get the container that kubectl uses when none is named."""

    annotated = (pod.metadata.annotations or {}).get("kubectl.kubernetes.io/default-container")
    names = [container.name for container in pod.spec.containers]
    return annotated if annotated in names else names[0]


def pod_item(pod: V1Pod) -> PodItem:
    """Summarize a pod for the pod list."""

    statuses = {status.name: status for status in (pod.status.container_statuses or [])}
    containers = []
    for container in pod.spec.containers:
        status = statuses.get(container.name)
        state, reason = "unknown", None
        if status and status.state:
            if status.state.running:
                state = "running"
            elif status.state.waiting:
                state, reason = "waiting", status.state.waiting.reason
            elif status.state.terminated:
                state, reason = "terminated", status.state.terminated.reason
        containers.append(
            PodContainer(
                name=container.name,
                ready=bool(status and status.ready),
                restarts=status.restart_count if status else 0,
                state=state,
                reason=reason,
            )
        )

    kind, workload = workload_of(pod)
    labels = pod.metadata.labels or {}
    return PodItem(
        name=pod.metadata.name,
        workload_kind=kind,
        workload=workload,
        # A pod that is being deleted still reports its phase (Running).
        phase="Terminating" if pod.metadata.deletion_timestamp else (pod.status.phase or "Unknown"),
        ready=bool(containers) and all(container.ready for container in containers),
        restarts=sum(container.restarts for container in containers),
        created=pod.metadata.creation_timestamp,
        app=labels.get("app.kubernetes.io/name") or labels.get("app"),
        release=labels.get("app.kubernetes.io/instance") or labels.get("release"),
        containers=containers,
        default_container=default_container(pod),
        is_self=pod.metadata.name == os.environ.get("HOSTNAME"),
    )


async def resolve_target(k8s: K8s, pod: str, container: str | None) -> PodTarget:
    """Check the pod and container a request names.

    Args:
        k8s (K8s):
            The Kubernetes object.
        pod (str):
            The name of the pod.
        container (str | None):
            The name of the container, None for the default container of the pod.

    Raises:
        HTTPException:
            A name is invalid (400), the pod or container does not exist (404).

    Returns:
        PodTarget:
            The container to run commands in.

    """

    if not is_pod_name(pod) or (container is not None and not is_container_name(container)):
        raise HTTPException(status_code=HTTPStatus.BAD_REQUEST, detail="Invalid pod or container name")

    found = await anyio.to_thread.run_sync(k8s.get_pod, pod)
    if found is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Pod -> '{}' not found".format(pod))

    if container is None:
        container = default_container(found)
    elif container not in [item.name for item in found.spec.containers]:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail="Container -> '{}' not found in pod -> '{}'".format(container, pod),
        )

    return PodTarget(namespace=k8s.get_namespace(), pod=pod, container=container)


def kubectl_exec_args(target: PodTarget, command: list[str], *, stdin: bool = False) -> list[str]:
    """Build the command line that runs a command in a container (kubectl exec).

    Everything a request names is an argument of its own, after "--": nothing is interpreted
    by a shell or taken for an option of kubectl.
    """

    args = ["kubectl", "exec", "--namespace={}".format(target.namespace), "--container={}".format(target.container)]
    if stdin:
        args.append("--stdin")
    return [*args, target.pod, "--", *command]


def shell(script: str, *args: str) -> list[str]:
    """Build a command that runs a shell script with arguments ($1, $2, ...)."""

    return ["sh", "-c", script, "sh", *args]


async def start_exec(target: PodTarget, command: list[str], *, stdin: bool = False) -> asyncio.subprocess.Process:
    """Start a command in a container."""

    return await asyncio.create_subprocess_exec(
        *kubectl_exec_args(target, command, stdin=stdin),
        stdin=asyncio.subprocess.PIPE if stdin else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def stop_process(process: asyncio.subprocess.Process) -> None:
    """End a process (if it still runs) and wait for it, even when the request is cancelled.

    asyncio only reports a process as ended once all its pipes are closed: the input is closed
    and what is left of the output read, or the wait never ends (a download the client broke
    off leaves output nobody reads).
    """

    with anyio.CancelScope(shield=True), anyio.move_on_after(STOP_TIMEOUT_SECONDS) as scope:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        if process.stdin is not None:
            process.stdin.close()
        with contextlib.suppress(Exception):
            while await process.stdout.read(CHUNK_BYTES):
                pass
        with contextlib.suppress(Exception):
            await process.wait()
    if scope.cancelled_caught:
        logger.warning("Process -> %s did not end in time", process.pid)


def command_error(code: int, stderr: bytes, path: str = "") -> HTTPException:
    """Turn the failure of a command in a container into the response for it.

    Args:
        code (int):
            The exit code.
        stderr (bytes):
            What the command (or kubectl) wrote to stderr.
        path (str, optional):
            The path the command worked on.

    Returns:
        HTTPException:
            The error to raise.

    """

    message = stderr.decode("utf-8", errors="replace").strip()
    known = {
        EXIT_NOT_FOUND: (HTTPStatus.NOT_FOUND, "'{}' does not exist".format(path)),
        EXIT_NOT_A_FOLDER: (HTTPStatus.BAD_REQUEST, "'{}' is not a folder or regular file".format(path)),
        EXIT_NO_PERMISSION: (HTTPStatus.FORBIDDEN, "No permission for '{}'".format(path)),
        EXIT_EXISTS: (HTTPStatus.CONFLICT, "'{}' already exists".format(path)),
        EXIT_IS_A_FOLDER: (HTTPStatus.CONFLICT, "'{}' is a folder".format(path)),
        EXIT_INCOMPLETE: (HTTPStatus.BAD_REQUEST, "The upload to '{}' is incomplete".format(path)),
        EXIT_CHANGED: (HTTPStatus.PRECONDITION_FAILED, "'{}' was changed since it was opened".format(path)),
    }
    if code in known:
        status, detail = known[code]
        if message and code == EXIT_NO_PERMISSION:
            detail = "{}: {}".format(detail, message.splitlines()[-1])
        return HTTPException(status_code=status, detail=detail)

    if "executable file not found" in message or ("sh" in message and "no such file or directory" in message.lower()):
        return HTTPException(
            status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
            detail="The container has no shell (sh), its files cannot be accessed",
        )

    logger.warning("Command in pod failed with exit code -> %s: %s", code, message)
    return HTTPException(
        status_code=HTTPStatus.BAD_GATEWAY,
        detail=message.splitlines()[-1] if message else "The command failed with exit code {}".format(code),
    )


async def run_script(target: PodTarget, script: str, *args: str, path: str = "") -> bytes:
    """Run a short shell script in a container and get its output.

    Raises:
        HTTPException:
            The script failed (see `command_error`) or took too long (504).

    Returns:
        bytes:
            What the script wrote to stdout.

    """

    process = await start_exec(target, shell(script, *args))
    try:
        with anyio.fail_after(SCRIPT_TIMEOUT_SECONDS):
            stdout, stderr = await process.communicate()
    except TimeoutError as exc:
        raise HTTPException(status_code=HTTPStatus.GATEWAY_TIMEOUT, detail="The pod did not answer in time") from exc
    finally:
        await stop_process(process)

    if process.returncode:
        raise command_error(process.returncode, stderr, path)
    return stdout


async def probe_path(target: PodTarget, path: str) -> tuple[str, int]:
    """Tell what a path in a container is.

    Raises:
        HTTPException:
            The path does not exist (404), cannot be read (403) or is neither a folder nor
            a regular file (400).

    Returns:
        tuple[str, int]:
            "dir" and 0, or "file" and the size of the file.

    """

    output = (await run_script(target, PROBE_SCRIPT, path, path=path)).decode("utf-8", errors="replace").split()
    if output[:1] == ["dir"]:
        return "dir", 0
    if len(output) == 2 and output[0] == "file" and output[1].isdigit():
        return "file", int(output[1])
    raise HTTPException(status_code=HTTPStatus.BAD_GATEWAY, detail="Unexpected answer of the pod: {}".format(output))


_FIND_TYPES = {"f": "file", "d": "dir", "l": "link"}
_FIND_TARGET_TYPES = {"f": "file", "d": "dir", "N": "missing"}


def _decode_name(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def parse_find_listing(output: bytes) -> list[PodFileEntry]:
    """Read the entries of a folder as GNU find prints them (see `LIST_SCRIPT`)."""

    fields = output.split(b"\0")
    entries = []
    for start in range(0, len(fields) - LIST_FIELDS + 1, LIST_FIELDS):
        kind, target_kind, size, mtime, mode, owner, group, link, name = fields[start : start + LIST_FIELDS]
        entry_type = _FIND_TYPES.get(kind.decode(), "other")
        is_link = entry_type == "link"
        entries.append(
            PodFileEntry(
                name=_decode_name(name),
                type=entry_type,
                link=_decode_name(link) if is_link else None,
                target_type=_FIND_TARGET_TYPES.get(target_kind.decode(), "other") if is_link else None,
                size=int(size or 0),
                mtime=float(mtime) if mtime else None,
                mode=mode.decode(),
                owner=_decode_name(owner),
                group=_decode_name(group),
            )
        )
    return entries


def parse_stat_listing(output: bytes) -> list[PodFileEntry]:
    """Read the entries of a folder as stat prints them where find has no -printf (see `LIST_SCRIPT`)."""

    entries = []
    for line in output.split(b"\n"):
        parts = line.split(b"/", 6)
        if len(parts) != 7:
            continue
        raw_mode, size, mtime, mode, owner, group, name = parts
        try:
            file_mode = int(raw_mode, 16)
        except ValueError:
            continue
        if stat.S_ISLNK(file_mode):
            entry_type = "link"
        elif stat.S_ISDIR(file_mode):
            entry_type = "dir"
        elif stat.S_ISREG(file_mode):
            entry_type = "file"
        else:
            entry_type = "other"
        entries.append(
            PodFileEntry(
                name=_decode_name(name),
                type=entry_type,
                size=int(size) if size.isdigit() else 0,
                mtime=float(mtime) if mtime.isdigit() else None,
                mode=mode.decode(),
                owner=_decode_name(owner),
                group=_decode_name(group),
            )
        )
    return entries


async def list_folder(target: PodTarget, path: str) -> tuple[list[PodFileEntry], bool]:
    """List a folder in a container.

    A folder can have any number of entries: reading stops after `MAX_ENTRIES` of them.

    Raises:
        HTTPException:
            The folder cannot be listed (see `command_error`) or the pod did not answer in time.

    Returns:
        tuple[list[PodFileEntry], bool]:
            The entries and whether there are more.

    """

    process = await start_exec(target, shell(LIST_SCRIPT, path))
    output = bytearray()
    truncated = False
    stderr_task = asyncio.ensure_future(process.stderr.read())
    try:
        with anyio.fail_after(SCRIPT_TIMEOUT_SECONDS):
            while chunk := await process.stdout.read(CHUNK_BYTES):
                output += chunk
                separators = (
                    output.count(b"\n") if output.startswith(b"#stat\n") else output.count(b"\0") // LIST_FIELDS
                )
                if separators > MAX_ENTRIES or len(output) > MAX_LISTING_BYTES:
                    truncated = True
                    break
            if not truncated:
                await process.wait()
    except TimeoutError as exc:
        raise HTTPException(status_code=HTTPStatus.GATEWAY_TIMEOUT, detail="The pod did not answer in time") from exc
    finally:
        await stop_process(process)
        stderr = await stderr_task

    if not truncated and process.returncode:
        # GNU find reports entries it cannot stat but lists the others: that is a listing.
        if not output:
            raise command_error(process.returncode, stderr, path)
        logger.debug("Listing of '%s' in pod -> '%s' reported: %s", path, target.pod, stderr)

    if output.startswith(b"#stat\n"):
        entries = parse_stat_listing(bytes(output[len(b"#stat\n") :]))
    else:
        entries = parse_find_listing(bytes(output))
    if len(entries) > MAX_ENTRIES:
        entries, truncated = entries[:MAX_ENTRIES], True
    return entries, truncated


def _get_transfer_limiter() -> anyio.CapacityLimiter:
    try:
        return _transfer_limiter.get()
    except LookupError:
        limiter = anyio.CapacityLimiter(api_settings.pod_transfer_concurrency)
        _transfer_limiter.set(limiter)
        return limiter


def acquire_transfer() -> object:
    """Take one of the transfer slots (see the setting pod_transfer_concurrency).

    Raises:
        HTTPException:
            All slots are taken (429).

    Returns:
        object:
            The token to give back with `release_transfer`.

    """

    token = object()
    try:
        _get_transfer_limiter().acquire_on_behalf_of_nowait(token)
    except anyio.WouldBlock as exc:
        raise HTTPException(
            status_code=HTTPStatus.TOO_MANY_REQUESTS,
            detail="Too many downloads and uploads are running, try again in a moment",
        ) from exc
    return token


def release_transfer(token: object) -> None:
    """Give back a transfer slot."""

    _get_transfer_limiter().release_on_behalf_of(token)


def content_disposition(file_name: str) -> str:
    """Build the Content-Disposition header of a download (any characters in the name)."""

    fallback = "".join(char if 32 <= ord(char) < 127 and char not in '"\\' else "_" for char in file_name)
    return "attachment; filename=\"{}\"; filename*=UTF-8''{}".format(fallback, quote(file_name, safe=""))


class ProcessResponse(StreamingResponse):
    """The output of a command in a container, sent as it arrives.

    Whatever ends the response - all sent, the client went away, an error - the command is ended
    and the transfer slot given back.
    """

    def __init__(self, process: asyncio.subprocess.Process, token: object, description: str, **kwargs: Any) -> None:  # noqa: ANN401
        """Send the stdout of a started process.

        Args:
            process (asyncio.subprocess.Process):
                The process (kubectl exec).
            token (object):
                The transfer slot (see `acquire_transfer`).
            description (str):
                What is sent, for the log.
            **kwargs (Any):
                Passed on to the StreamingResponse (headers, media type).

        """

        self.process = process
        self.token = token
        self.description = description
        self.stderr_task = asyncio.ensure_future(process.stderr.read())
        super().__init__(self._body(), **kwargs)

    async def _body(self) -> AsyncIterator[bytes]:
        while chunk := await self.process.stdout.read(CHUNK_BYTES):
            yield chunk
        await self.process.wait()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Send the response, then end the process and give the slot back."""

        try:
            await super().__call__(scope, receive, send)
        finally:
            ended = self.process.returncode is not None
            stderr = b""
            try:
                await stop_process(self.process)
                with anyio.CancelScope(shield=True), anyio.move_on_after(STOP_TIMEOUT_SECONDS):
                    stderr = await self.stderr_task
            finally:
                release_transfer(self.token)
            if not ended:
                logger.info("Download of %s was cancelled", self.description)
            elif self.process.returncode:
                logger.warning(
                    "Download of %s ended with exit code -> %s: %s",
                    self.description,
                    self.process.returncode,
                    stderr.decode("utf-8", errors="replace").strip(),
                )

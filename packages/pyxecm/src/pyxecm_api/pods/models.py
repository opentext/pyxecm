"""Define models for the pods."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

from pyxecm_api.v1_payload.models import PayloadLogInfo


class PodContainer(BaseModel):
    """A container of a pod."""

    name: str
    ready: bool
    restarts: int
    # "running", "waiting", "terminated" or "unknown".
    state: str
    # Why the container is waiting or terminated (e.g. CrashLoopBackOff).
    reason: str | None = None


class PodItem(BaseModel):
    """A pod of the namespace."""

    name: str
    # What runs the pod (StatefulSet, Deployment, DaemonSet, Job ...) and its name. A pod of a
    # Deployment gets a new name whenever it is replaced, the workload keeps its name.
    workload_kind: str | None
    workload: str | None
    phase: str
    ready: bool
    restarts: int
    created: datetime | None
    app: str | None
    # The Helm release the pod belongs to (its app.kubernetes.io/instance label, or the older
    # release label) - None for a pod Helm did not deploy, or whose chart does not label it.
    release: str | None = None
    containers: list[PodContainer]
    default_container: str
    # The pod of the Customizer itself.
    is_self: bool


class PodList(BaseModel):
    """The pods of the namespace."""

    namespace: str
    pods: list[PodItem]


class PodFileEntry(BaseModel):
    """An entry of a folder in a pod."""

    name: str
    type: Literal["file", "dir", "link", "other"]
    # For a link: what it points to, and the type of that ("missing" for a broken link,
    # None where it cannot be told).
    link: str | None = None
    target_type: Literal["file", "dir", "other", "missing"] | None = None
    size: int
    # Seconds since the epoch.
    mtime: float | None
    # Permission bits in octal, e.g. "755".
    mode: str
    owner: str
    group: str


class PodFileListing(BaseModel):
    """The entries of a folder in a pod."""

    pod: str
    container: str
    path: str
    entries: list[PodFileEntry]
    # The folder has more entries than are listed.
    truncated: bool


class PodFileUploaded(BaseModel):
    """A file uploaded into a pod."""

    pod: str
    container: str
    path: str
    size: int
    # The modification time of the written file (seconds since the epoch), to save it again.
    mtime: int | None = None


class PodLogRequest(BaseModel):
    """The log to open: the output of a container or a file in it."""

    container: str | None = None
    # "stdout": the output of the container, followed. "previous": the output of the previous
    # instance of the container (after a restart). "file": a file in the container, followed.
    source: Literal["stdout", "previous", "file"] = "stdout"
    path: str | None = None


class PodLogSession(BaseModel):
    """An opened log: read it with the info, lines and download endpoints of the session."""

    id: str
    pod: str
    container: str
    source: str
    path: str | None


class PodLogInfo(PayloadLogInfo):
    """What the info endpoint of a payload log tells, plus the state of the copy of the pod log."""

    # The copy reached its maximum size and is not followed any more.
    capped: bool
    # Why following the log ended, if it ended with an error.
    error: str | None

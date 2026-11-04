"""Collect what the cluster looks like when a payload failed, for the manager's deployment analysis.

The manager cannot reach every cluster (VPN): neither the Customizer API nor the Kubernetes API.
So the Customizer pushes the pod status, the output of pods that are not ready or restarted and the
Content Server logs from inside, right when a payload failed - pods restart and logs rotate soon
after. ManagerPushClient.push_failure_snapshot runs collect() and uploads the files it returns to
POST /api/customizer/run/<run_id>/snapshot (the manager's docs/customizer-failure-snapshots.md).

Every file is written to a temporary file (gzip), never held in memory: an OTCS log archive can
be hundreds of MB. The caller deletes the files once they are uploaded.
"""

from __future__ import annotations

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import gzip
import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from kubernetes.client.exceptions import ApiException

if TYPE_CHECKING:
    from kubernetes.client import V1Pod

    from pyxecm_customizer.k8s import K8s

default_logger = logging.getLogger("pyxecm_customizer.failure_snapshot")

# Lines of a container's output read (from its end) - what the manager's analysis reads of it.
POD_OUTPUT_LINES = 5000
# Pods whose output is pushed at most - the ones that are not ready or restarted.
MAX_OUTPUT_PODS = 10
# OTCS hosts whose logs are pushed at most - the manager's analysis reads up to four.
MAX_OTCS_HOSTS = 4
MAX_EVENTS = 10
OTCS_LOG_PATHS = ("opt/opentext/cs/logs", "opt/opentext/cs_persist/contentserver.log")
# Archives of the files changed in the last N minutes, tried in turn while the archive is too large.
OTCS_LOG_WINDOWS = (None, 240, 60, 15)
OTCS_COLLECT_TIMEOUT = 15 * 60
# The container the OTCS logs are in, by pod name prefix (as for PUT /api/v1/otcs/logs).
OTCS_CONTAINERS = {
    "otcs-frontend": "otcs-frontend-container",
    "otcs-admin": "otcs-admin-container",
}


@dataclass
class SnapshotFile:
    """One gzip file to push, described as the manager's snapshot endpoint expects it."""

    kind: str  # "pods", "pod_output" or "otcs"
    name: str
    path: Path
    container: str = ""
    previous: bool = False
    truncated: bool = False


def collect(k8s: K8s, max_bytes: int, logger: logging.Logger = default_logger) -> list[SnapshotFile]:
    """Collect the pod status, the output of the pods in trouble and the OTCS logs as gzip files.

    Whatever cannot be read is left out (and logged) - a snapshot never raises.
    """

    response = k8s.list_pods()
    if response is None:
        logger.warning("Failure snapshot: cannot list the pods.")
        return []
    pods = [pod for pod in response.items if pod.metadata.name != os.environ.get("HOSTNAME")]

    files = [_gzip_text("pods", "pods", pod_status(k8s, pods, logger))]
    files += _pod_outputs(k8s, pods, logger)
    files += _otcs_logs(k8s, pods, max_bytes, logger)
    return [file for file in files if file is not None]


def in_trouble(pod: V1Pod) -> bool:
    """Tell whether a pod is not ready or restarted (a completed pod, e.g. of a Job, is not)."""

    if pod.status.phase == "Succeeded":
        return False
    statuses = pod.status.container_statuses or []
    return not statuses or any(not cs.ready or cs.restart_count for cs in statuses)


def pod_status(k8s: K8s, pods: list[V1Pod], logger: logging.Logger = default_logger) -> str:
    """Describe the pods: phase, readiness, restarts, why a container waits or ended, and the events of the pods in trouble."""

    rows = []
    for pod in sorted(pods, key=lambda p: p.metadata.name):
        statuses = pod.status.container_statuses or []
        ready = bool(statuses) and all(cs.ready for cs in statuses)
        phase = "Terminating" if pod.metadata.deletion_timestamp else (pod.status.phase or "Unknown")
        containers = "; ".join(_container_status(cs) for cs in statuses)
        rows.append(
            f"{pod.metadata.name}: {phase}, {'ready' if ready else 'NOT READY'}, "
            f"{sum(cs.restart_count for cs in statuses)} restarts, created {pod.metadata.creation_timestamp} - {containers}"
        )
        if in_trouble(pod):
            rows += [
                f"  condition {condition.type}: {condition.status} ({condition.reason}: {condition.message})"
                for condition in pod.status.conditions or []
                if condition.status != "True"
            ]
            rows += [f"  event {event}" for event in _events(k8s, pod.metadata.name, logger)]
    return "\n".join(rows) or "No pods."


def _container_status(cs: object) -> str:
    state = cs.state
    if state and state.waiting:
        text = f"waiting ({state.waiting.reason}{': ' + state.waiting.message if state.waiting.message else ''})"
    elif state and state.terminated:
        text = f"terminated ({state.terminated.reason}, exit code {state.terminated.exit_code})"
    elif state and state.running:
        text = "running"
    else:
        text = "unknown"
    last = cs.last_state.terminated if cs.last_state else None
    if last:
        text += f", last terminated ({last.reason}, exit code {last.exit_code}, at {last.finished_at})"
    return f"{cs.name}: {text}, {cs.restart_count} restarts{'' if cs.ready else ', not ready'}"


def _events(k8s: K8s, pod_name: str, logger: logging.Logger) -> list[str]:
    try:
        events = (
            k8s.get_core_v1_api()
            .list_namespaced_event(namespace=k8s.get_namespace(), field_selector=f"involvedObject.name={pod_name}")
            .items
        )
    except ApiException as error:
        logger.debug("Failure snapshot: cannot read the events of pod -> '%s': %s", pod_name, error.reason)
        return []
    events.sort(key=lambda e: str(e.last_timestamp or e.event_time or e.metadata.creation_timestamp or ""))
    return [
        f"{e.last_timestamp or e.event_time} {e.type} {e.reason}: {e.message}{f' (x{e.count})' if e.count else ''}"
        for e in events[-MAX_EVENTS:]
    ]


def _pod_outputs(k8s: K8s, pods: list[V1Pod], logger: logging.Logger) -> list[SnapshotFile | None]:
    files: list[SnapshotFile | None] = []
    for pod in [pod for pod in pods if in_trouble(pod)][:MAX_OUTPUT_PODS]:
        for cs in pod.status.container_statuses or []:
            if cs.ready and not cs.restart_count:
                continue
            for previous in (False, True) if cs.restart_count else (False,):
                try:
                    output = k8s.get_core_v1_api().read_namespaced_pod_log(
                        name=pod.metadata.name,
                        namespace=k8s.get_namespace(),
                        container=cs.name,
                        previous=previous,
                        tail_lines=POD_OUTPUT_LINES,
                    )
                except ApiException as error:
                    # E.g. a container that never started, or no previous container left.
                    logger.debug(
                        "Failure snapshot: no output of container -> '%s' of pod -> '%s' (previous=%s): %s",
                        cs.name,
                        pod.metadata.name,
                        previous,
                        error.reason,
                    )
                    continue
                file = _gzip_text("pod_output", pod.metadata.name, output or "")
                file.container, file.previous = cs.name, previous
                # tail_lines cuts silently - as many lines as asked for means there were (likely) more.
                file.truncated = (output or "").count("\n") >= POD_OUTPUT_LINES
                files.append(file)
    return files


def _gzip_text(kind: str, name: str, text: str) -> SnapshotFile:
    handle, path = tempfile.mkstemp(prefix=f"snapshot-{kind}-", suffix=".gz")
    with os.fdopen(handle, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb") as file:
        file.write(text.encode("utf-8"))
    return SnapshotFile(kind=kind, name=name, path=Path(path))


def otcs_hosts(pods: list[V1Pod]) -> list[str]:
    """Return the running OTCS frontends and admin servers - the frontends serve the Customizer's requests."""

    names = sorted(pod.metadata.name for pod in pods if pod.status.phase == "Running")
    return ([n for n in names if n.startswith("otcs-frontend")] + [n for n in names if n.startswith("otcs-admin")])[
        :MAX_OTCS_HOSTS
    ]


def _otcs_logs(k8s: K8s, pods: list[V1Pod], max_bytes: int, logger: logging.Logger) -> list[SnapshotFile | None]:
    files: list[SnapshotFile | None] = []
    for host in otcs_hosts(pods):
        container = next((c for prefix, c in OTCS_CONTAINERS.items() if host.startswith(prefix)), None)
        files.append(otcs_archive(k8s.get_namespace(), host, container, max_bytes, logger))
    return files


def otcs_script(window: int | None) -> str:
    """Return the shell command that writes the tar.gz of the OTCS logs to stdout (window: only files changed in the last minutes)."""

    logs, persisted = OTCS_LOG_PATHS
    if window is None:
        return f"cd / && tar czf - --ignore-failed-read {logs} {persisted} 2>/dev/null"
    return (
        f"cd / && find {logs} -type f -mmin -{window} 2>/dev/null"
        f" | tar czf - --ignore-failed-read -T - {persisted} 2>/dev/null"
    )


def otcs_archive(
    namespace: str, host: str, container: str | None, max_bytes: int, logger: logging.Logger = default_logger
) -> SnapshotFile | None:
    """Archive the Content Server logs of an OTCS pod into a temporary tar.gz - None if none fits max_bytes.

    The archive streams from `kubectl exec` straight to disk (the Kubernetes client's exec decodes
    stdout as text, which breaks a binary archive). Too large, only the newest files are tried.
    """

    handle, name = tempfile.mkstemp(prefix=f"snapshot-otcs-{host}-", suffix=".tar.gz")
    os.close(handle)
    path = Path(name)
    command = ["kubectl", "exec", "-n", namespace, host]
    if container:
        command += ["-c", container]
    for window in OTCS_LOG_WINDOWS:
        try:
            with path.open("wb") as file:
                result = subprocess.run(
                    [*command, "--", "sh", "-c", otcs_script(window)],
                    stdout=file,
                    stderr=subprocess.PIPE,
                    timeout=OTCS_COLLECT_TIMEOUT,
                    check=False,
                )
        except (OSError, subprocess.TimeoutExpired) as error:
            logger.warning("Failure snapshot: cannot archive the OTCS logs of -> '%s': %s", host, error)
            break
        size = path.stat().st_size
        # tar ends with 1 when a log changed while it was read - the archive is still complete.
        if result.returncode not in (0, 1) or size == 0:
            logger.warning(
                "Failure snapshot: archiving the OTCS logs of -> '%s' failed (exit code %s): %s",
                host,
                result.returncode,
                result.stderr.decode("utf-8", errors="replace")[:300],
            )
            break
        if size <= max_bytes:
            return SnapshotFile(kind="otcs", name=host, path=path, truncated=window is not None)
        logger.info(
            "Failure snapshot: the OTCS logs of -> '%s' are %s MB%s - trying newer files only.",
            host,
            size // (1024 * 1024),
            f" (last {window} min)" if window else "",
        )
    path.unlink(missing_ok=True)
    return None

"""Asynchronous push client for customizer run history."""

from __future__ import annotations

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import gzip
import logging
import queue
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast

import requests
from requests_toolbelt import MultipartEncoder

if TYPE_CHECKING:
    from collections.abc import Callable

    import pandas as pd

    from pyxecm_customizer.failure_snapshot import SnapshotFile

from pyxecm_customizer import failure_snapshot
from pyxecm_customizer.k8s import K8s
from pyxecm_customizer.settings import ManagerPushSettings
from pyxecm_customizer.version import customizer_version


class ManagerPushClient:
    """Deliver customizer run data without blocking payload processing."""

    def __init__(
        self,
        settings: ManagerPushSettings | None = None,
        logger: logging.Logger | None = None,
        sleep: Callable[[float], None] = time.sleep,
        collect_snapshot: Callable[[int], list[SnapshotFile]] | None = None,
    ) -> None:
        """Initialize the optional manager transport and its worker.

        collect_snapshot(max_bytes) collects the files of a failure snapshot (default: from the
        cluster, see failure_snapshot.collect).
        """

        self.settings = settings or ManagerPushSettings()
        self.logger = logger or logging.getLogger(__name__)
        self._sleep = sleep
        self._queue: queue.Queue[tuple[str, tuple[object, ...]]] | None = None
        self._worker: threading.Thread | None = None
        self.session: requests.Session | None = None
        self._run_id = self.settings.run_id or (str(uuid.uuid4()) if self.settings.enabled else "")
        self._artifacts: dict[str, str] | None = None
        self._collect_snapshot = collect_snapshot or self._collect_from_cluster
        # One snapshot collection at a time, and not more often than snapshot_interval_seconds.
        self._snapshot_lock = threading.Lock()
        self._last_snapshot: float | None = None

        if self.settings.enabled:
            self.logger.info(
                "Manager push enabled=%s url=%s",
                self.settings.enabled,
                self.settings.url or "<unset>",
            )

            self._queue = queue.Queue(maxsize=self.settings.queue_size)
            self.session = requests.Session()
            self.session.trust_env = False
            if self.settings.proxy:
                self.session.proxies = {
                    "http": self.settings.proxy,
                    "https": self.settings.proxy,
                }
            self.session.verify = self.settings.ca_bundle or self.settings.tls_verify
            self.session.headers.update({"X-Instance-Key": self.settings.key})
            self._worker = threading.Thread(
                target=self._worker_loop,
                daemon=True,
                name="ManagerPush",
            )
            self._worker.start()

    @property
    def run_id(self) -> str:
        """Return the stable run identity used by this process."""

        return self._run_id

    def push_run(
        self,
        status: str,
        started_at: object | None = None,
        finished_at: object | None = None,
    ) -> None:
        """Queue a run status update."""

        if not self.settings.enabled:
            return

        payload = {
            "schema_version": 1,
            "run_id": self.run_id,
            "source": "customizer",
            "status": status,
            "started_at": self._timestamp(started_at),
            "finished_at": self._timestamp(finished_at),
            "customizer_version": self._version(),
        }
        artifacts = self._artifacts_version()
        if artifacts:
            payload["artifacts_version"] = artifacts
        self._enqueue("run", payload)

    def push_payload_result(self, payload_row: pd.Series) -> None:
        """Queue a payload result row for delivery."""

        if not self.settings.enabled:
            return

        row = payload_row
        payload = {
            "index": int(cast("int | str", row.name)),
            "name": row["name"],
            "status": row["status"],
            "start_time": self._timestamp(row["start_time"]),
            "stop_time": self._timestamp(row["stop_time"]),
            "duration": row["duration"],
            "log_debug": int(row.get("log_debug", 0) or 0),
            "log_info": int(row.get("log_info", 0) or 0),
            "log_warning": int(row.get("log_warning", 0) or 0),
            "log_error": int(row.get("log_error", 0) or 0),
            "log_critical": int(row.get("log_critical", 0) or 0),
        }
        self._enqueue("payload", payload)

    def push_payload_log(
        self,
        index: int,
        name: str,
        logfile_path: str | Path,
        truncated: bool = False,
    ) -> None:
        """Queue a payload log upload for delivery."""

        if not self.settings.enabled:
            return

        self._enqueue("log", (index, name, str(logfile_path), truncated))

    def push_failure_snapshot(self, payload_index: int | None, reason: str) -> None:
        """Collect the pod status, pod output and OTCS logs in the background and queue their upload.

        For the manager's deployment analysis of clusters it cannot reach (VPN) - pods restart and
        logs rotate soon after a failure. Never blocks or fails the deployment: skipped while a
        collection runs or within snapshot_interval_seconds of the last one (a newer snapshot
        replaces the older one in the manager).
        """

        if not self.settings.enabled or not self.settings.push_snapshots:
            return
        now = time.monotonic()
        if self._last_snapshot is not None and now - self._last_snapshot < self.settings.snapshot_interval_seconds:
            self.logger.debug("Skipping failure snapshot: the last one is too recent.")
            return
        if not self._snapshot_lock.acquire(blocking=False):
            self.logger.debug("Skipping failure snapshot: another one is being collected.")
            return
        self._last_snapshot = now
        taken_at = self._timestamp(datetime.now(UTC))
        threading.Thread(
            target=self._snapshot,
            args=(payload_index, reason, taken_at),
            daemon=True,
            name="ManagerSnapshot",
        ).start()

    def _snapshot(self, payload_index: int | None, reason: str, taken_at: str | None) -> None:
        try:
            files = self._collect_snapshot(self.settings.max_snapshot_bytes)
        except Exception:
            self.logger.exception("Failure snapshot could not be collected")
            return
        finally:
            self._snapshot_lock.release()
        self.logger.info("Pushing failure snapshot (%s) with %d files to the manager.", reason, len(files))
        for file in files:
            self._enqueue("snapshot", (file, payload_index, reason, taken_at))

    def _collect_from_cluster(self, max_bytes: int) -> list[SnapshotFile]:
        return failure_snapshot.collect(K8s(logger=self.logger), max_bytes=max_bytes, logger=self.logger)

    def _enqueue(self, kind: str, payload: object) -> None:
        if self._queue is None:
            return
        try:
            self._queue.put_nowait((kind, (payload,)))
        except queue.Full:
            self.logger.warning("Dropping manager push item because the queue is full: %s", kind)
            if kind == "snapshot":
                cast("tuple[SnapshotFile, ...]", payload)[0].path.unlink(missing_ok=True)

    def _worker_loop(self) -> None:
        if self._queue is None:
            return
        work_queue = self._queue
        while True:
            item = work_queue.get()
            try:
                kind, args = item
                if kind == "run":
                    self._post_json("/api/customizer/run", cast("dict[str, object]", args[0]))
                elif kind == "payload":
                    self._post_json(
                        f"/api/customizer/run/{self.run_id}/payload",
                        cast("dict[str, object]", args[0]),
                    )
                elif kind == "snapshot":
                    self._post_snapshot(*cast("tuple[SnapshotFile, int | None, str, str | None]", args[0]))
                else:
                    self._post_log(*cast("tuple[int, str, str, bool]", args[0]))
            except Exception:
                self.logger.exception("Unexpected manager push worker failure")
            finally:
                work_queue.task_done()

    def _post_json(self, path: str, payload: dict[str, object]) -> None:
        self._request_with_retry(
            method="post",
            path=path,
            timeout=(5, 30),
            json=payload,
        )

    def _post_log(self, index: int, name: str, logfile_path: str, truncated: bool) -> None:
        self.logger.debug("Preparing manager log upload for payload '%s'", name)
        data, was_truncated = self._gzip_log(Path(logfile_path))
        files = {"file": (Path(logfile_path).name, data, "application/gzip")}
        form = {"truncated": str(truncated or was_truncated).lower()}
        self._request_with_retry(
            method="post",
            path=f"/api/customizer/run/{self.run_id}/payload/{index}/log",
            timeout=(5, 120),
            files=files,
            data=form,
        )

    def _post_snapshot(self, file: SnapshotFile, payload_index: int | None, reason: str, taken_at: str | None) -> None:
        fields = {
            "kind": file.kind,
            "name": file.name,
            "container": file.container,
            "previous": str(file.previous).lower(),
            "payload_index": "" if payload_index is None else str(payload_index),
            "reason": reason,
            "taken_at": taken_at or "",
            "truncated": str(file.truncated).lower(),
        }
        try:
            with file.path.open("rb") as handle:

                def body() -> dict[str, object]:
                    # Streamed from the file (an OTCS archive can be hundreds of MB), anew for every attempt.
                    handle.seek(0)
                    encoder = MultipartEncoder(fields={**fields, "file": (file.path.name, handle, "application/gzip")})
                    return {"data": encoder, "headers": {"Content-Type": encoder.content_type}}

                self._request_with_retry(
                    method="post",
                    path=f"/api/customizer/run/{self.run_id}/snapshot",
                    timeout=(5, 900),
                    body=body,
                )
        finally:
            file.path.unlink(missing_ok=True)

    def _request_with_retry(
        self,
        method: str,
        path: str,
        timeout: tuple[int, int],
        body: Callable[[], dict[str, object]] | None = None,
        **kwargs: object,
    ) -> None:
        """Send a request, retrying as the manager asks; body() returns fresh request arguments per attempt."""

        attempts = 0
        not_found_deadline = time.monotonic() + 30 * 60
        if self.session is None:
            return
        session = self.session
        while True:
            attempts += 1
            try:
                response = session.request(
                    method=method,
                    url=self.settings.url.rstrip("/") + path,
                    timeout=timeout,
                    **kwargs,  # pyright: ignore[reportArgumentType]
                    **(body() if body else {}),  # pyright: ignore[reportArgumentType]
                )
            except requests.RequestException as error:
                if attempts >= 4:
                    self.logger.warning("Manager push failed after retries: %s", error)
                    return
                self._sleep(min(2**attempts, 30))
                continue

            if response.ok:
                return
            if response.status_code == 404 and time.monotonic() < not_found_deadline:
                self._sleep(min(2 ** min(attempts, 8), 300))
                continue
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                delay = float(retry_after) if retry_after and retry_after.isdigit() else min(2**attempts, 300)
                self._sleep(delay)
                continue
            if 500 <= response.status_code < 600 and attempts < 4:
                self._sleep(min(2**attempts, 30))
                continue
            if response.status_code == 413:
                self.logger.warning("Manager rejected an oversized upload: %s", path)
            else:
                self.logger.warning("Manager push returned HTTP %s: %s", response.status_code, path)
            return

    def _gzip_log(self, path: Path) -> tuple[bytes, bool]:
        content = path.read_bytes()
        compressed = gzip.compress(content)
        if len(compressed) <= self.settings.max_log_bytes:
            return compressed, False

        text = content.decode("utf-8", errors="replace")
        marker = "\n... LOG TRUNCATED BY CUSTOMIZER MANAGER PUSH ...\n"
        target = max(1, len(text) // 2)
        while target > 1:
            candidate = (text[:target] + marker + text[-target:]).encode("utf-8")
            compressed = gzip.compress(candidate)
            if len(compressed) <= self.settings.max_log_bytes:
                return compressed, True
            target //= 2
        return gzip.compress(marker.encode("utf-8")), True

    @staticmethod
    def _timestamp(value: object | None) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            return value
        if isinstance(value, datetime):
            timestamp = value.isoformat()
            return timestamp.replace("+00:00", "Z")
        return str(value)

    @staticmethod
    def _version() -> str:
        return customizer_version()

    def _artifacts_version(self) -> dict[str, str] | None:
        """Return which commit of the payload content the deployment runs ({"commit", "branch", ...}).

        Read once from the payload image (customizer-artifacts serves its build's version.json); None
        while it cannot be read - an image built before version.json, or the service not up yet.
        """

        if self._artifacts is not None or not self.settings.artifacts_version_url:
            return self._artifacts
        try:
            # Its own session: the service is in the cluster, not behind the manager's proxy.
            with requests.Session() as session:
                session.trust_env = False
                response = session.get(self.settings.artifacts_version_url, timeout=3)
            data = response.json() if response.ok else None
        except (requests.RequestException, ValueError):
            return None
        if isinstance(data, dict) and data.get("commit") and data["commit"] != "unknown":
            self._artifacts = {
                key: str(value) for key, value in data.items() if key in ("commit", "branch", "pipeline_id")
            }
        return self._artifacts

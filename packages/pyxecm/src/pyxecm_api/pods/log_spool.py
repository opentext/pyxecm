"""Copies of pod logs that are read like payload logs.

A log of a pod - the output of a container, or a file in it - is followed by kubectl into a file
of the Customizer (the spool). That file is read with the line index of the payload logs, so a
pod log of any size can be searched, filtered and paged through, while it grows.

Everybody who looks at the same log shares one copy. A copy nobody read for a while
(pod_log_idle_seconds) is stopped and deleted; following stops when the copy reaches
pod_log_max_bytes.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import contextlib
import logging
import os
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field

from pyxecm_api.settings import CustomizerAPISettings
from pyxecm_api.v1_payload.log_reader import drop_index

from .functions import PodTarget, kubectl_exec_args

logger = logging.getLogger("pyxecm_api.pods")

# How often the copies are checked for their size and for being read.
WATCH_SECONDS = 2.0
# How much of the error output of kubectl is reported.
ERROR_BYTES = 2048


@dataclass
class LogSession:
    """A log of a pod that is copied into a file."""

    id: str
    target: PodTarget
    source: str
    path: str | None
    spool: str
    errors: str
    process: subprocess.Popen
    last_read: float = field(default_factory=time.monotonic)
    capped: bool = False

    @property
    def key(self) -> tuple:
        """What makes two requests for a log the same log."""

        return (self.target.pod, self.target.container, self.source, self.path)

    def running(self) -> bool:
        """Check whether the log is still followed."""

        return self.process.poll() is None

    def error(self) -> str | None:
        """Tell why following the log ended, if it ended with an error."""

        if self.capped or self.process.poll() in (None, 0):
            return None
        try:
            with open(self.errors, "rb") as file:
                file.seek(max(0, os.path.getsize(self.errors) - ERROR_BYTES))
                text = file.read().decode("utf-8", errors="replace").strip()
        except OSError:
            text = ""
        return text or "Following the log ended with exit code {}".format(self.process.returncode)

    def stop(self) -> None:
        """Stop following the log."""

        if self.process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                self.process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.process.wait(timeout=5)

    def delete(self) -> None:
        """Stop following the log and delete the copy."""

        self.stop()
        drop_index(self.spool)
        for name in (self.spool, self.errors):
            with contextlib.suppress(FileNotFoundError):
                os.remove(name)


class TooManySessionsError(Exception):
    """More logs are followed than allowed (pod_log_max_sessions)."""


class LogSpool:
    """The copies of pod logs of the Customizer."""

    def __init__(self, settings: CustomizerAPISettings) -> None:
        """Remember the settings; nothing is started before the first log is opened."""

        self._settings = settings
        self._lock = threading.Lock()
        self._sessions: dict[str, LogSession] = {}
        self._watcher: threading.Thread | None = None
        self._stopped = threading.Event()

    def _command(self, target: PodTarget, source: str, path: str | None) -> list[str]:
        if source == "file":
            # The last pod_log_max_bytes of the file, then what is appended (also after the
            # file was rotated).
            return kubectl_exec_args(target, ["tail", "-c", str(self._settings.pod_log_max_bytes), "-F", "--", path])

        args = [
            "kubectl",
            "logs",
            "--namespace={}".format(target.namespace),
            "--container={}".format(target.container),
        ]
        # The previous instance of a container has ended: its output is complete.
        args.append("--previous" if source == "previous" else "--follow")
        return [*args, target.pod]

    def _start_watcher(self) -> None:
        if self._watcher is None or not self._watcher.is_alive():
            # A copy left behind by an earlier run of the Customizer is of no use.
            shutil.rmtree(self._settings.pod_log_spool_dir, ignore_errors=True)
            os.makedirs(self._settings.pod_log_spool_dir, exist_ok=True)
            self._stopped.clear()
            self._watcher = threading.Thread(target=self._watch, name="PodLogSpool", daemon=True)
            self._watcher.start()

    def open(self, target: PodTarget, source: str, path: str | None) -> LogSession:
        """Open a log: the copy that is already made of it, or a new one.

        Args:
            target (PodTarget):
                The container.
            source (str):
                "stdout", "previous" or "file".
            path (str | None):
                The file for the source "file".

        Raises:
            TooManySessionsError:
                The maximum number of followed logs is reached.

        Returns:
            LogSession:
                The log.

        """

        key = (target.pod, target.container, source, path)
        with self._lock:
            self._start_watcher()
            for session in list(self._sessions.values()):
                if session.key != key:
                    continue
                # A copy that is still followed, complete (the previous container) or full is
                # the log; one whose follower ended (the container restarted) is made again.
                if session.running() or session.capped or (source == "previous" and session.error() is None):
                    session.last_read = time.monotonic()
                    return session
                del self._sessions[session.id]
                session.delete()

            if sum(session.running() for session in self._sessions.values()) >= self._settings.pod_log_max_sessions:
                raise TooManySessionsError

            session_id = uuid.uuid4().hex
            spool = os.path.join(self._settings.pod_log_spool_dir, session_id + ".log")
            errors = os.path.join(self._settings.pod_log_spool_dir, session_id + ".err")
            with open(spool, "wb") as stdout, open(errors, "wb") as stderr:
                process = subprocess.Popen(
                    self._command(target, source, path),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    start_new_session=True,
                )
            session = LogSession(
                id=session_id,
                target=target,
                source=source,
                path=path,
                spool=spool,
                errors=errors,
                process=process,
            )
            self._sessions[session_id] = session
            logger.info(
                "Following the log -> %s of pod -> '%s' (container -> '%s')",
                path or source,
                target.pod,
                target.container,
            )
            return session

    def get(self, session_id: str) -> LogSession | None:
        """Get an opened log and note that it is read."""

        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session.last_read = time.monotonic()
            return session

    def check(self) -> None:
        """Stop the copies that are full, delete the ones nobody reads."""

        now = time.monotonic()
        with self._lock:
            for session in list(self._sessions.values()):
                if now - session.last_read > self._settings.pod_log_idle_seconds:
                    logger.info(
                        "Nobody reads the log -> %s of pod -> '%s'", session.path or session.source, session.target.pod
                    )
                    del self._sessions[session.id]
                    session.delete()
                    continue
                if session.running():
                    try:
                        size = os.path.getsize(session.spool)
                    except OSError:
                        continue
                    if size >= self._settings.pod_log_max_bytes:
                        session.capped = True
                        session.stop()

    def _watch(self) -> None:
        while not self._stopped.wait(WATCH_SECONDS):
            try:
                self.check()
            except Exception:
                logger.exception("Checking the pod logs failed")

    def close(self) -> None:
        """Stop and delete all copies (when the Customizer shuts down)."""

        self._stopped.set()
        with self._lock:
            for session in self._sessions.values():
                session.delete()
            self._sessions.clear()

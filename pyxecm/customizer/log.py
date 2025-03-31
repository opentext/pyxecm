"""Common logging handler for VictoriaLogs and the LogCountFilter."""

import contextlib
import logging
import socket
from datetime import datetime, timezone

import requests

try:
    import pandas as pd

    pandas_installed = True
except ModuleNotFoundError:
    pandas_installed = False


class VictoriaLogsHandler(logging.Handler):
    """Logging handler for VictoriaLogs.

    Args:
        logging (_type_): _description_

    """

    def __init__(
        self,
        host: str,
        port: int = 9428,
        accountid: int = 0,
        projectid: int = 0,
        **kwargs: str | int,
    ) -> None:
        """Initialize the log handler.

        Args:
            host (_type_): _description_
            port (int, optional): _description_. Defaults to 9428.
            accountid (int, optional): _description_. Defaults to 0.
            projectid (int, optional): _description_. Defaults to 0.
            kwargs (dict[str, Any]): ability to add additional arguments into the request body

        """
        logging.Handler.__init__(self)
        self.url = f"http://{host}:{port}/insert/jsonline?_stream_fields=host,app&_msg_field=msg&_time_field=time"
        self.accountid = accountid
        self.projectid = projectid
        self.kwargs = kwargs

    def emit(self, record: logging.LogRecord) -> None:
        """Send request to VictoriaLogs.

        Args:
            record (_type_): _description_

        """
        payload = {
            "host": socket.gethostname(),
            "processid": record.process,
            "logger": record.name,
            "level": record.levelname,
            "thread": record.threadName,
            "threadid": record.thread,
            "time": datetime.now(timezone.utc).isoformat(),
            "msg": f"[{record.levelname}] {record.getMessage()}",
            "module": record.module,
        }
        payload.update(self.kwargs)

        headers = {
            "Content-type": "application/json",
            "AccountID": str(self.accountid),
            "ProjectID": str(self.projectid),
        }

        with contextlib.suppress(Exception):
            requests.post(self.url, headers=headers, json=payload, timeout=1)


class LogCountFilter(logging.Filter):
    """LogFilter to be assinged to thread_logger to count the number os messages by level."""

    def __init__(self, payload_items: pd.DataFrame, index: int) -> None:
        """LogCountFilter initializer.

        Args:
            payload_items (pd.DataFrame): _description_
            index (int): _description_

        """
        super().__init__()
        self.index = index
        self.payload_items = payload_items

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter method.

        Args:
            record (_type_): _description_

        Returns:
            bool: _description_

        """
        level_name = (record.levelname).lower()
        self.payload_items.loc[self.index, f"log_{level_name}"] += 1
        return True

"""The log format of the Customizer, the LogCountFilter and the record start rule of its logs."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import re

import pandas as pd

# The format of the Customizer's log records: the Customizer log, the payload logs and stdout.
# Everything that reads these logs derives its rules from here (see record_start_pattern()),
# so a change here is all it takes.
LOG_DATE_FORMAT = "%d-%b-%Y %H:%M:%S"
LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] [%(threadName)s] %(message)s"

LOG_LEVEL_NAMES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# The regular expressions of the strftime directives a date format may use. Month and day names
# are those of the C locale.
_DATE_DIRECTIVES = {
    "d": r"\d{2}",
    "m": r"\d{2}",
    "y": r"\d{2}",
    "Y": r"\d{4}",
    "H": r"\d{2}",
    "I": r"\d{2}",
    "M": r"\d{2}",
    "S": r"\d{2}",
    "f": r"\d{6}",
    "j": r"\d{3}",
    "b": "[A-Za-z]{3}",
    "a": "[A-Za-z]{3}",
    "B": "[A-Za-z]+",
    "A": "[A-Za-z]+",
    "p": "[AP]M",
    "z": r"[+-]\d{4}",
    "%": "%",
}
# logging.Formatter's asctime without a date format: "2026-10-06 14:56:30,123".
_DEFAULT_ASCTIME = r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}"
_FIELD_RE = re.compile(r"%(?:%|\((\w+)\)([-#0 +]*)(\d*)(?:\.\d+)?[sdfr])")
_SPECIAL = frozenset("\\^$.|?*+()[]{}/")


def _literal(text: str) -> str:
    """Escape text for a regular expression that Python and JavaScript read the same way."""

    return "".join("\\" + char if char in _SPECIAL else char for char in text)


def _date_pattern(datefmt: str | None) -> str:
    """Translate a strftime date format into a regular expression."""

    if datefmt is None:
        return _DEFAULT_ASCTIME
    parts = []
    position = 0
    for match in re.finditer(r"%(.)", datefmt):
        parts.append(_literal(datefmt[position : match.start()]))
        directive = match[1]
        if directive not in _DATE_DIRECTIVES:
            message = "Unsupported date format directive -> '%{}' in '{}'.".format(directive, datefmt)
            raise ValueError(message)
        parts.append(_DATE_DIRECTIVES[directive])
        position = match.end()
    parts.append(_literal(datefmt[position:]))
    return "".join(parts)


def record_start_pattern(fmt: str = LOG_FORMAT, datefmt: str | None = LOG_DATE_FORMAT) -> str:
    """Return the regular expression that recognizes the first line of a log record.

    The pattern is derived from a logging format: it matches the start of a line up to and
    including the level name, which is group 1 and ends the match. A level name anywhere else in
    a line (e.g. in a message that quotes another log) does not count. Only syntax that Python
    and JavaScript read the same way is used: the manager UI gets the pattern from the log info
    endpoint and applies it with the multiline flag.

    Args:
        fmt (str, optional):
            The %-style logging format. It must contain %(levelname)s.
        datefmt (str | None, optional):
            The strftime date format of %(asctime)s, None for logging's default.

    Returns:
        str:
            The regular expression.

    Raises:
        ValueError:
            The format has no level name or uses an unsupported date directive.

    """

    parts = ["^"]
    position = 0
    for match in _FIELD_RE.finditer(fmt):
        parts.append(_literal(fmt[position : match.start()]))
        position = match.end()
        field, flags, width = match.groups()
        if field is None:
            parts.append("%")
        elif field == "levelname":
            # A padded level name ("%(levelname)8s") is right-aligned unless the flags say "-".
            if width and "-" not in flags:
                parts.append(" *")
            parts.append("({})(?![A-Za-z0-9_])".format("|".join(LOG_LEVEL_NAMES)))
            return "".join(parts)
        elif field == "asctime":
            parts.append(_date_pattern(datefmt))
        else:
            # Anything else in front of the level name (logger name, thread name, ...).
            parts.append(".*?")
    message = "The log format -> '{}' has no %(levelname)s.".format(fmt)
    raise ValueError(message)


class LogCountFilter(logging.Filter):
    """LogFilter to be assigned to thread_logger to count the number of messages by level."""

    def __init__(self, payload_items: pd.DataFrame, index: int) -> None:
        """LogCountFilter initializer.

        Args:
            payload_items (pd.DataFrame):
                The payload items data frame with the `log_<level>` counter columns.
            index (int):
                The row index of the payload item whose counters are incremented.

        """
        super().__init__()
        self.index = index
        self.payload_items = payload_items

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter method.

        Args:
            record (logging.LogRecord):
                The log record. Its level name selects the counter to increment.

        Returns:
            bool:
                Always True (the record is never filtered out).

        """
        level_name = (record.levelname).lower()
        self.payload_items.loc[self.index, f"log_{level_name}"] += 1
        return True

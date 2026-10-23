"""Structured error capture for pyxecm API calls.

Most pyxecm methods return None (or False) in case of an error and only write the
reason to the log. Callers that need the reason - e.g. AI agents or MCP tools that
have to tell the user *why* something failed - can wrap their calls in a
`capture_errors()` block. All errors recorded inside the block are collected as
structured error objects (`OTCSError`, `OTDSError`, ... - all
subclasses of `PyxecmError`). Return values and logging are not affected:

```python
from pyxecm import capture_errors

with capture_errors() as errors:
    node = otcs.create_item(parent_id=4711, item_name="Contracts", item_type=0)

if node is None:
    print(errors.to_agent_message(fallback="Failed to create folder"))
```

Outside of a `capture_errors()` block recording is a no-op.

The collector is stored in a context variable. It is visible in the current thread and
in asyncio tasks created inside the block, but NOT in threads that are started without
copying the context (use `contextvars.copy_context().run` for that).
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2026, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import contextlib
import json
import logging
import os
import threading
import urllib.parse
import warnings
from collections import deque
from collections.abc import Generator, Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import ClassVar

DEFAULT_MAX_ERRORS = 1000


class ErrorCategory(StrEnum):
    """Category of an error - what an upper layer (or agent) can react to."""

    NOT_FOUND = "not_found"
    PERMISSION_DENIED = "permission_denied"
    ALREADY_EXISTS = "already_exists"
    VALIDATION = "validation"
    AUTHENTICATION = "authentication"
    CONFLICT = "conflict"
    SERVER = "server"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    UNKNOWN = "unknown"


class ErrorSeverity(StrEnum):
    """Severity of an error. Matches the log level the error has been logged with.

    DEBUG is used for failures the calling code expects and handles itself,
    e.g. a lookup with show_error=False that checks if an item exists.
    """

    ERROR = "error"
    WARNING = "warning"
    DEBUG = "debug"


# Text patterns (lower case) to categorize error messages. Content Server returns
# HTTP 500 for many different problems, so the status code alone is not enough.
# The order matters - the first matching category wins:
CATEGORY_PATTERNS: list[tuple[ErrorCategory, tuple[str, ...]]] = [
    (
        ErrorCategory.AUTHENTICATION,
        (
            "not authenticated",
            "authentication failed",
            "reauthentication failed",
            "invalid ticket",
            "session expired",
            "session has expired",
            "login failed",
            "invalid credentials",
        ),
    ),
    (
        ErrorCategory.ALREADY_EXISTS,
        ("already exist", "duplicate", "already in use"),
    ),
    (
        # Before PERMISSION_DENIED: Content Server reports items that do not exist and items the
        # user cannot see with the same message ("Either it does not exist, or you do not have
        # permission to access it") - for the user the item does not exist in both cases:
        ErrorCategory.NOT_FOUND,
        (
            "not found",
            "cannot find",
            "can't find",
            "couldn't find",
            "could not find",
            "unable to find",
            "does not exist",
            "doesn't exist",
            "no such",
            "not exist",
        ),
    ),
    (
        # Only phrases that describe a missing permission - not just the word
        # "permission" as this is also part of messages like "Failed to assign permission":
        ErrorCategory.PERMISSION_DENIED,
        (
            "permission denied",
            "no permission",
            "insufficient permission",
            "insufficient privilege",
            "not have permission",
            "not have the permission",
            "not have sufficient",
            "not have the required",
            "you do not have",
            "you don't have",
            "not authorized",
            "not permitted",
            "access denied",
            "access is denied",
            "forbidden",
        ),
    ),
    (ErrorCategory.TIMEOUT, ("timed out", "timeout")),
    (
        ErrorCategory.CONNECTION,
        ("connection error", "cannot connect", "unable to connect", "connection refused", "not ready"),
    ),
    (
        ErrorCategory.VALIDATION,
        (
            "invalid",
            "missing",
            "required",
            "must be",
            "must not",
            "not valid",
            "not supported",
            "unsupported",
            "cannot be empty",
            "is empty",
            "malformed",
            "wrong",
            "illegal",
        ),
    ),
]

# Status codes that are unambiguous on their own:
STATUS_CATEGORIES = {
    401: ErrorCategory.AUTHENTICATION,
    403: ErrorCategory.PERMISSION_DENIED,
    404: ErrorCategory.NOT_FOUND,
}

# Status codes that are only used if the text does not tell more:
FALLBACK_STATUS_CATEGORIES = {
    400: ErrorCategory.VALIDATION,
    408: ErrorCategory.TIMEOUT,
    409: ErrorCategory.CONFLICT,
    422: ErrorCategory.VALIDATION,
    504: ErrorCategory.TIMEOUT,
}


def categorize_error(status_code: int | None = None, text: str | None = None) -> ErrorCategory:
    """Determine the error category from an HTTP status code and / or an error text.

    Args:
        status_code (int | None, optional):
            The HTTP status code (if the error comes from a REST call).
        text (str | None, optional):
            The error text, e.g. the error message returned by the server.

    Returns:
        ErrorCategory:
            The determined category. ErrorCategory.UNKNOWN if nothing matches.

    """

    if status_code in STATUS_CATEGORIES:
        return STATUS_CATEGORIES[status_code]

    if text:
        lower_text = text.lower()
        for category, patterns in CATEGORY_PATTERNS:
            if any(pattern in lower_text for pattern in patterns):
                return category

    if status_code in FALLBACK_STATUS_CATEGORIES:
        return FALLBACK_STATUS_CATEGORIES[status_code]
    if status_code is not None and status_code >= 500:
        return ErrorCategory.SERVER

    return ErrorCategory.UNKNOWN


# end function definition


def extract_server_message(response_text: str | None) -> str | None:
    """Extract the error message from the body of an error response.

    OpenText REST APIs return errors as JSON like {"error": "..."} (sometimes
    with additional "errorDetail"). HTML responses (e.g. from a proxy) are ignored.

    Args:
        response_text (str | None):
            The body of the HTTP response.

    Returns:
        str | None:
            The error message or None if the body has no recognizable error message.

    """

    if not response_text or response_text.lstrip().startswith("<"):
        return None

    try:
        body = json.loads(response_text)
    except ValueError:
        # Plain text error responses are used as they are (but not unlimited):
        return response_text.strip()[:1000] or None

    if not isinstance(body, dict):
        return None

    for key in ("error", "errorMessage", "message", "error_description"):
        value = body.get(key)
        if isinstance(value, str) and value:
            detail = body.get("errorDetail")
            if isinstance(detail, str) and detail and detail not in value:
                return "{}; {}".format(value, detail)
            return value
        if isinstance(value, dict):
            # Some APIs nest the error: {"error": {"message": "..."}}
            nested = value.get("message") or value.get("description")
            if isinstance(nested, str) and nested:
                return nested

    return None


# end function definition


def sanitize_url(url: str | None) -> str | None:
    """Remove query string and fragment from a URL as they may contain sensitive data.

    Args:
        url (str | None):
            The URL to sanitize.

    Returns:
        str | None:
            The URL without query string and fragment.

    """

    if not url:
        return url

    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None

    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


# end function definition


@dataclass(frozen=True)
class PyxecmError:
    """A single recorded error - the base class for the errors of all pyxecm modules.

    Each module has its own subclass (OTCSError, OTDSError, ...), so callers can
    check where an error comes from with isinstance() or ErrorCollector.of_type().

    These objects describe errors - they are collected, not raised.

    Attributes:
        message (str):
            Human readable description of what failed (the log message).
        category (ErrorCategory):
            The category of the error.
        severity (ErrorSeverity):
            The severity (log level) of the error.
        source (str):
            The pyxecm module that recorded the error, e.g. "otcs" (class variable).
        status_code (int | None):
            The HTTP status code if the error comes from a REST call.
        server_message (str | None):
            The error message returned by the server (e.g. Content Server).
        method (str | None):
            The HTTP method of the failed REST call.
        url (str | None):
            The URL of the failed REST call (without query string).
        timestamp (datetime):
            When the error has been recorded (UTC).

    """

    source: ClassVar[str] = "pyxecm"

    message: str
    category: ErrorCategory = ErrorCategory.UNKNOWN
    severity: ErrorSeverity = ErrorSeverity.ERROR
    status_code: int | None = None
    server_message: str | None = None
    method: str | None = None
    url: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_agent_message(self) -> str:
        """Return a concise description of the error that can be shown to an agent or user.

        It does not include the URL.

        Returns:
            str:
                The error description including server message and category.

        """

        text = self.message
        if self.server_message and self.server_message not in text:
            text = "{}: {}".format(text, self.server_message) if text else self.server_message

        details = ["category: {}".format(self.category)]
        if self.status_code is not None:
            details.append("HTTP status: {}".format(self.status_code))

        return "{} ({})".format(text, ", ".join(details))

    # end method definition


@dataclass(frozen=True)
class OTCSError(PyxecmError):
    """An error recorded by the Content Server module (OTCS class)."""

    source: ClassVar[str] = "otcs"


@dataclass(frozen=True)
class OTDSError(PyxecmError):
    """An error recorded by the Directory Services module (OTDS class)."""

    source: ClassVar[str] = "otds"


@dataclass(frozen=True)
class OTAWPError(PyxecmError):
    """An error recorded by the Process Automation / AppWorks module (OTAWP class)."""

    source: ClassVar[str] = "otawp"


@dataclass(frozen=True)
class OTACError(PyxecmError):
    """An error recorded by the Archive Center module (OTAC class)."""

    source: ClassVar[str] = "otac"


@dataclass(frozen=True)
class OTCAError(PyxecmError):
    """An error recorded by the Content Aviator module (OTCA class)."""

    source: ClassVar[str] = "otca"


@dataclass(frozen=True)
class OTKDError(PyxecmError):
    """An error recorded by the Knowledge Discovery module (OTKD class)."""

    source: ClassVar[str] = "otkd"


@dataclass(frozen=True)
class OTMMError(PyxecmError):
    """An error recorded by the Media Management module (OTMM class)."""

    source: ClassVar[str] = "otmm"


@dataclass(frozen=True)
class OTPDError(PyxecmError):
    """An error recorded by the PowerDocs module (OTPD class)."""

    source: ClassVar[str] = "otpd"


@dataclass(frozen=True)
class AVTSError(PyxecmError):
    """An error recorded by the Aviator Search module (AVTS class)."""

    source: ClassVar[str] = "avts"


@dataclass(frozen=True)
class CoreShareError(PyxecmError):
    """An error recorded by the Core Share module (CoreShare class)."""

    source: ClassVar[str] = "coreshare"


class ErrorCollector:
    """Collects the errors recorded inside a `capture_errors()` block.

    The collector is thread-safe. It keeps the most recent `max_errors` records.
    """

    def __init__(self, max_errors: int = DEFAULT_MAX_ERRORS) -> None:
        """Initialize the collector.

        Args:
            max_errors (int, optional):
                The maximum number of records to keep. Older records are dropped.

        """

        self._errors: deque[PyxecmError] = deque(maxlen=max_errors)
        self._lock = threading.Lock()
        self._dropped = 0

    # end method definition

    def add(self, record: PyxecmError) -> None:
        """Add a record to the collector.

        Args:
            record (PyxecmError):
                The record to add.

        """

        with self._lock:
            if self._errors.maxlen is not None and len(self._errors) == self._errors.maxlen:
                self._dropped += 1
            self._errors.append(record)

    # end method definition

    @property
    def errors(self) -> list[PyxecmError]:
        """Return all collected records (oldest first)."""

        with self._lock:
            return list(self._errors)

    # end method definition

    def of_type(self, error_class: type[PyxecmError]) -> list[PyxecmError]:
        """Return the collected records of a specific type, e.g. only OTCSError.

        Args:
            error_class (type[PyxecmError]):
                The error class to filter for (subclasses are included).

        Returns:
            list[PyxecmError]:
                The matching records (oldest first).

        """

        return [error for error in self.errors if isinstance(error, error_class)]

    # end method definition

    @property
    def dropped(self) -> int:
        """Return the number of records dropped because max_errors was exceeded."""

        return self._dropped

    # end method definition

    @property
    def last(self) -> PyxecmError | None:
        """Return the most recent record (any severity)."""

        with self._lock:
            return self._errors[-1] if self._errors else None

    # end method definition

    @property
    def root_cause(self) -> PyxecmError | None:
        """Return the record that most likely explains why the operation failed.

        High-level methods often call other methods internally and may log
        follow-up errors (like "Failed to create item") after the real
        cause (like the server error of the REST call) - or they use an expected
        failure (like a lookup that finds nothing) as part of their logic. So the
        root cause is determined like this:

        1. Ignore DEBUG records (expected failures) unless there is nothing else.
        2. Prefer records with a known category over ErrorCategory.UNKNOWN.
        3. Among those, take the most recent one.

        Returns:
            PyxecmError | None:
                The root cause or None if nothing has been recorded.

        """

        errors = self.errors
        if not errors:
            return None

        candidates = [error for error in errors if error.severity != ErrorSeverity.DEBUG] or errors
        specific = [error for error in candidates if error.category != ErrorCategory.UNKNOWN]

        return (specific or candidates)[-1]

    # end method definition

    def to_agent_message(self, fallback: str = "The operation failed") -> str:
        """Return a concise description of the root cause for an agent or user.

        Args:
            fallback (str, optional):
                The message to return if no error has been recorded.

        Returns:
            str:
                The description of the root cause or the fallback.

        """

        root_cause = self.root_cause

        return root_cause.to_agent_message() if root_cause else fallback

    # end method definition

    def __iter__(self) -> Iterator[PyxecmError]:
        """Iterate over the collected records (oldest first)."""

        return iter(self.errors)

    # end method definition

    def __len__(self) -> int:
        """Return the number of collected records."""

        with self._lock:
            return len(self._errors)

    # end method definition

    def __bool__(self) -> bool:
        """Return True if at least one record (any severity) has been collected."""

        return len(self) > 0

    # end method definition


# All collectors of the (nested) capture_errors() blocks that are currently active:
_active_collectors: ContextVar[tuple[ErrorCollector, ...]] = ContextVar("pyxecm_error_collectors", default=())


@contextmanager
def capture_errors(max_errors: int = DEFAULT_MAX_ERRORS) -> Generator[ErrorCollector]:
    """Collect all errors recorded by pyxecm inside the with-block.

    Blocks can be nested - an error is recorded in all active collectors.

    Args:
        max_errors (int, optional):
            The maximum number of records to keep. Older records are dropped.

    Yields:
        ErrorCollector:
            The collector with the recorded errors.

    """

    collector = ErrorCollector(max_errors=max_errors)
    token = _active_collectors.set((*_active_collectors.get(), collector))
    try:
        yield collector
    finally:
        try:
            _active_collectors.reset(token)
        except ValueError:
            # The block has been exited in a different context (e.g. a generator
            # that is closed elsewhere) - just remove this collector:
            _active_collectors.set(tuple(c for c in _active_collectors.get() if c is not collector))


# end function definition


def is_capturing() -> bool:
    """Return True if a capture_errors() block is active in the current context."""

    return bool(_active_collectors.get())


# end function definition


def format_log_message(message: object, args: tuple) -> str:
    """Format a message with %-style arguments like the logging module does.

    Args:
        message (object):
            The (format) message.
        args (tuple):
            The arguments for the format string.

    Returns:
        str:
            The formatted message. If formatting fails, the unformatted message.

    """

    text = str(message)
    if args:
        with suppress(TypeError, ValueError, KeyError):
            text = text % args

    return text


# end function definition


def record_error(
    message: object,
    *args: object,
    category: ErrorCategory | None = None,
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    error_class: type[PyxecmError] = PyxecmError,
    status_code: int | None = None,
    server_message: str | None = None,
    method: str | None = None,
    url: str | None = None,
) -> PyxecmError | None:
    """Record an error in all active collectors.

    This is a no-op if no capture_errors() block is active. It never raises
    an exception, so it cannot change the behavior of the calling code.

    Args:
        message (object):
            Description of what failed. Can be a %-style format string for args.
        *args (object):
            Arguments for a %-style format string in message.
        category (ErrorCategory | None, optional):
            The category. If None, it is determined from status code and texts.
        severity (ErrorSeverity, optional):
            The severity (log level) of the error.
        error_class (type[PyxecmError], optional):
            The class of the recorded error - the one of the recording module, e.g. OTCSError.
        status_code (int | None, optional):
            The HTTP status code if the error comes from a REST call.
        server_message (str | None, optional):
            The error message returned by the server.
        method (str | None, optional):
            The HTTP method of the failed REST call.
        url (str | None, optional):
            The URL of the failed REST call. Query string and fragment are removed.

    Returns:
        PyxecmError | None:
            The recorded error or None if nothing has been recorded.

    """

    collectors = _active_collectors.get()
    if not collectors:
        return None

    try:
        text = format_log_message(message, args)
        if category is None:
            # For REST call errors only the server message is used to determine the
            # category - the message describes the operation (like "Failed to assign
            # permission") and not the reason:
            category_text = server_message if status_code is not None or server_message else text
            category = categorize_error(status_code=status_code, text=category_text)
        record = error_class(
            message=text,
            category=category,
            severity=severity,
            status_code=status_code,
            server_message=server_message,
            method=method,
            url=sanitize_url(url),
        )
        for collector in collectors:
            collector.add(record)
    except Exception:  # recording must never break the calling code
        return None

    return record


# end function definition


# The warning should point to the code that called pyxecm - not to the pyxecm
# method that passes the parameter on (e.g. OTCS.create_item() -> OTCS.do_request())
# or to the wrapper of the @tracer.start_as_current_span decorator (in contextlib).
# The contextlib entry has no ".py" extension: CPython does not compare the last
# character of the file name, so a prefix that is the complete file name never matches.
_PYXECM_PACKAGE_DIRS = (
    *(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), package) + os.sep
        for package in ("pyxecm", "pyxecm_customizer")
    ),
    os.path.splitext(contextlib.__file__)[0],
)


def warn_parse_error_response_deprecated() -> None:
    """Warn that the parse_error_response parameter is deprecated.

    The error details are available via capture_errors() for all pyxecm calls,
    so the parameter will be removed in a future version.
    """

    warnings.warn(
        message=(
            "The parameter parse_error_response is deprecated and will be removed in a future version. "
            "Use capture_errors() to get the error details instead, e.g. errors.root_cause.server_message."
        ),
        category=DeprecationWarning,
        skip_file_prefixes=_PYXECM_PACKAGE_DIRS,
    )


# end function definition


def request_error_severity(show_error: bool, show_warning: bool = True) -> ErrorSeverity:
    """Return the severity of a failed REST call that matches its log level.

    Args:
        show_error (bool):
            The show_error parameter of do_request() - True logs an error.
        show_warning (bool, optional):
            The show_warning parameter of do_request() - only used if show_error is False.
            For do_request() methods without this parameter, use the default (True).

    Returns:
        ErrorSeverity:
            ERROR, WARNING or DEBUG (DEBUG = the caller expects the failure, e.g. a lookup
            checking if an item exists).

    """

    if show_error:
        return ErrorSeverity.ERROR
    if show_warning:
        return ErrorSeverity.WARNING

    return ErrorSeverity.DEBUG


# end function definition


def record_request_error(
    message: str,
    method: str,
    url: str,
    response: object | None = None,
    category: ErrorCategory | None = None,
    severity: ErrorSeverity = ErrorSeverity.ERROR,
    error_class: type[PyxecmError] = PyxecmError,
) -> None:
    """Record a failed REST call for an active capture_errors() block.

    Used by the do_request() methods of the pyxecm classes. This is a no-op if no
    capture_errors() block is active and it never raises an exception.

    Args:
        message (str):
            Description of the failed operation (typically the failure message).
        method (str):
            The HTTP method of the REST call.
        url (str):
            The URL of the REST call. Query string and fragment are removed.
        response (object | None, optional):
            The requests.Response of the REST call (if there is one).
        category (ErrorCategory | None, optional):
            The error category. If None, it is determined from the response.
        severity (ErrorSeverity, optional):
            The severity - should match the level the error has been logged with.
        error_class (type[PyxecmError], optional):
            The class of the recorded error, e.g. OTCSError.

    """

    # Avoid extracting the server message if nobody is interested:
    if not is_capturing():
        return

    # Recording must never change the outcome of the REST call - e.g. reading
    # the text of a broken (streamed) response could raise an exception:
    try:
        status_code = response.status_code if response is not None else None
        server_message = extract_server_message(response.text) if response is not None else None
    except Exception:  # recording must never break the REST call
        status_code = server_message = None

    record_error(
        message or "{} request failed".format(method),
        category=category,
        severity=severity,
        error_class=error_class,
        status_code=status_code,
        server_message=server_message,
        method=method,
        url=url,
    )


# end function definition


class ReportingLogger:
    """Logger proxy whose error() and warning() can also record the message.

    Behaves like the wrapped logging.Logger - all other attributes and methods
    (debug(), info(), getChild(), addFilter(), ...) are passed through. In addition,
    error() and warning() accept these keyword arguments:

    * report (bool) - if True, the message is also recorded for an active
      capture_errors() block (as an instance of error_class). Use it where a method
      gives up and the message explains why. Recording does not depend on the log level.
    * category (ErrorCategory | None) - the error category if the message text does not
      tell it clearly. Only used with report=True.

    ```python
    self.logger.error("Volume type -> %s not found!", volume_type, report=True)
    ```
    """

    def __init__(self, logger: logging.Logger, error_class: type[PyxecmError] = PyxecmError) -> None:
        """Initialize the proxy.

        Args:
            logger (logging.Logger):
                The logger to wrap. If it is a ReportingLogger, its logger is wrapped.
            error_class (type[PyxecmError], optional):
                The class of the recorded errors, e.g. OTCSError.

        """

        self._logger = logger._logger if isinstance(logger, ReportingLogger) else logger  # noqa: SLF001
        self._error_class = error_class

    # end method definition

    @property
    def wrapped_logger(self) -> logging.Logger:
        """Return the wrapped logger."""

        return self._logger

    # end method definition

    def error(
        self,
        msg: object,
        *args: object,
        report: bool = False,
        category: ErrorCategory | None = None,
        **kwargs: object,
    ) -> None:
        """Log an error - and record it if report is True.

        Args:
            msg (object):
                The log message. Can be a %-style format string for args.
            *args (object):
                Arguments for the format string.
            report (bool, optional):
                If True, record the error for an active capture_errors() block.
            category (ErrorCategory | None, optional):
                The error category. If None, it is determined from the message.
            **kwargs (object):
                Additional keyword arguments for the logger (like exc_info).

        """

        # One more stack level -> the log record shows the caller, not this proxy:
        kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 1
        self._logger.error(msg, *args, **kwargs)
        if report:
            record_error(msg, *args, category=category, severity=ErrorSeverity.ERROR, error_class=self._error_class)

    # end method definition

    def warning(
        self,
        msg: object,
        *args: object,
        report: bool = False,
        category: ErrorCategory | None = None,
        **kwargs: object,
    ) -> None:
        """Log a warning - and record it if report is True.

        Args:
            msg (object):
                The log message. Can be a %-style format string for args.
            *args (object):
                Arguments for the format string.
            report (bool, optional):
                If True, record the warning for an active capture_errors() block.
            category (ErrorCategory | None, optional):
                The error category. If None, it is determined from the message.
            **kwargs (object):
                Additional keyword arguments for the logger (like exc_info).

        """

        kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 1
        self._logger.warning(msg, *args, **kwargs)
        if report:
            record_error(msg, *args, category=category, severity=ErrorSeverity.WARNING, error_class=self._error_class)

    # end method definition

    def __getattr__(self, name: str) -> object:
        """Pass all other attributes and methods to the wrapped logger."""

        # Avoid endless recursion if the proxy is not initialized yet (e.g. during copy / unpickling):
        if name in ("_logger", "_error_class") or name.startswith("__"):
            raise AttributeError(name)

        return getattr(self._logger, name)

    # end method definition

    def __repr__(self) -> str:
        """Return a readable representation."""

        return "<ReportingLogger {!r} ({})>".format(self._logger, self._error_class.__name__)

    # end method definition


class ReportingLoggerAttribute:
    """Class attribute for the logger of a pyxecm class.

    Every logger assigned to the attribute is wrapped in a ReportingLogger, so
    self.logger.error(..., report=True) works for the default logger, for the logger
    passed to the constructor and for a logger that is assigned later:

    ```python
    class OTDS:
        logger = ReportingLoggerAttribute(default_logger, error_class=OTDSError)
    ```
    """

    def __init__(self, default_logger: logging.Logger, error_class: type[PyxecmError]) -> None:
        """Initialize the attribute.

        Args:
            default_logger (logging.Logger):
                The logger used if no logger has been assigned to an instance.
            error_class (type[PyxecmError]):
                The class of the recorded errors, e.g. OTDSError.

        """

        self._default = ReportingLogger(default_logger, error_class=error_class)
        self._error_class = error_class
        self._attribute_name = "_reporting_logger"

    # end method definition

    def __set_name__(self, owner: type, name: str) -> None:
        """Remember where the logger of an instance is stored."""

        self._attribute_name = "_{}_reporting".format(name)

    # end method definition

    def __get__(self, instance: object | None, owner: type | None = None) -> ReportingLogger:
        """Return the logger of the instance (or the default logger)."""

        if instance is None:
            return self._default

        return instance.__dict__.get(self._attribute_name, self._default)

    # end method definition

    def __set__(self, instance: object, logger: logging.Logger) -> None:
        """Wrap the assigned logger in a ReportingLogger."""

        instance.__dict__[self._attribute_name] = ReportingLogger(logger, error_class=self._error_class)

    # end method definition

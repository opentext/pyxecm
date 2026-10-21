"""Windowed reading, level filtering and searching of payload log files of any size.

A payload log can grow to several gigabytes. Nothing in this module reads a whole log into
memory: the file is read in chunks, and a small in-memory index per log file makes every byte
offset resolvable to a line number and a log level.

Terms used throughout this module:

* Offsets are byte offsets into the log file, never character positions.
* A line ends at a line feed. A trailing carriage return is not part of its text. A line is
  at most `MAX_LINE_BYTES` long (terminator included); longer lines are split at that length
  so that a file without line feeds cannot exhaust the memory.
* A record start is a line carrying a level marker (see `RECORD_RE`). The level of a line is
  the level of the nearest record start at or before it, `CRITICAL` counting as `ERROR`.
* Only complete lines are served. The unterminated end of the file is a line only once the
  payload is no longer running.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import re
import threading
import time
from array import array
from bisect import bisect_left, bisect_right
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import accumulate
from typing import BinaryIO

from pyxecm_customizer.log import LOG_LEVEL_NAMES, record_start_pattern

logger = logging.getLogger("pyxecm_api.v1_payload")

# Version of the log reading contract reported by the info endpoint.
CONTRACT_VERSION = 1

# Level names by level code. Code 0 means "no level" (lines before the first record start).
LEVEL_NAMES = (None, "DEBUG", "INFO", "WARNING", "ERROR")
LEVEL_CODES = {b"DEBUG": 1, b"INFO": 2, b"WARNING": 3, b"ERROR": 4, b"CRITICAL": 4}
FILTER_LEVELS = {"DEBUG": 1, "INFO": 2, "WARNING": 3, "ERROR": 4}
ALL_LEVELS_MASK = 0b11110

# Distance between two checkpoints of the line index.
CHECKPOINT_BYTES = 64 * 1024
# Size of the chunks the index builder reads.
READ_BYTES = 1024 * 1024
# Longest line (terminator included). Must not be smaller than READ_BYTES.
MAX_LINE_BYTES = 1024 * 1024
# Size of the pieces a scan reads: it starts small and doubles up to the maximum.
SCAN_BLOCK_BYTES = 64 * 1024
SCAN_BLOCK_BYTES_MAX = 1024 * 1024

# A needle found more often than this at the start of a block is too frequent there for
# testing just the lines that contain it.
NEEDLE_SAMPLE_BYTES = 64 * 1024
NEEDLE_SAMPLE_HITS = 20

# Limits of a single request.
DEFAULT_LIMIT = 500
MAX_LIMIT = 5000
DEFAULT_MAX_BYTES = 1024 * 1024
MAX_MAX_BYTES = 4 * 1024 * 1024
SCAN_BUDGET_SECONDS = 1.0
SCAN_BUDGET_BYTES = 256 * 1024 * 1024
# How long a request waits for the index to catch up before it reports "indexing".
INDEX_WAIT_SECONDS = 0.5

# The index builder pauses briefly after this many bytes, so that the threads of a running
# deployment get the interpreter lock without having to fight for it.
YIELD_EVERY_BYTES = 4 * 1024 * 1024
YIELD_SECONDS = 0.001

_NEWLINE = b"\n"
_LINE_FEED = 10
_NON_ASCII = 128
_WORD_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _record_re(pattern: str) -> re.Pattern[bytes]:
    """Compile the record start rule (see record_start_pattern()) for the index and the scans.

    The rest of the line is consumed, so consecutive matches belong to different lines. Where the
    part in front of the level name has a fixed width (as with the default log format), it is
    checked by a look-behind after the first letter of the level name, which keeps the fast
    literal scan of the regular expression engine.
    """

    rest = rb"[^\n]*"
    head, _, tail = pattern.encode().partition(b"(" + b"|".join(name.encode() for name in LOG_LEVEL_NAMES) + b")")
    try:
        names = (
            name[:1] + rb"(?<=" + head + name[:1] + rb")" + name[1:] for name in (n.encode() for n in LOG_LEVEL_NAMES)
        )
        return re.compile(rb"(" + rb"|".join(names) + rb")" + tail + rest, re.MULTILINE)
    except re.error:
        # Look-behinds need a fixed width.
        return re.compile(pattern.encode() + rest, re.MULTILINE)


# The record start rule, derived from the log format of the Customizer: the level is the first
# word after the timestamp at the start of a line. The info endpoint hands the same rule to the
# manager UI, so both always agree on what a record start is.
RECORD_START_PATTERN = record_start_pattern()
RECORD_RE = _record_re(RECORD_START_PATTERN)

# Characters outside ASCII that Python's case-insensitive matching treats as equal to an ASCII
# letter, with their UTF-8 encodings.
_FOLD_EXTRAS = {
    "i": (b"\xc4\xb0", b"\xc4\xb1"),
    "s": (b"\xc5\xbf",),
    "k": (b"\xe2\x84\xaa",),
}


class LogChangedError(Exception):
    """The log file was replaced while it was read."""


@dataclass(frozen=True, slots=True)
class LogQuery:
    """A compiled search query.

    Attributes:
        pattern (re.Pattern[str]):
            Decides whether the text of a line matches.
        needle (bytes | None):
            Bytes every matching line contains (lower case if `fold` is set). Used to skip
            lines quickly; None if no such bytes are known.
        fold (bool):
            Whether the needle has to be searched ignoring the case of ASCII letters.
        extras (tuple[bytes, ...]):
            Byte sequences that make the needle unreliable for a piece of the log.
        exact (bool):
            Whether the needle is the whole query: where the needle is found, the query
            matches, provided the word boundaries are as required.
        word_left (bool):
            Whether an exact needle must not directly follow a word character.
        word_right (bool):
            Whether an exact needle must not be directly followed by a word character.

    """

    pattern: re.Pattern[str]
    needle: bytes | None = None
    fold: bool = False
    extras: tuple[bytes, ...] = ()
    exact: bool = False
    word_left: bool = False
    word_right: bool = False

    def matches(self, raw: bytes) -> bool:
        """Check whether a line matches the query.

        Args:
            raw (bytes):
                The bytes of the line without the line feed.

        Returns:
            bool:
                True if the query matches somewhere in the line.

        """

        return self.pattern.search(decode_line(raw)) is not None


@dataclass(frozen=True, slots=True)
class LogLinesRequest:
    """The parameters of a request for log lines.

    Attributes:
        offset (int | None):
            Byte offset to start at. It is snapped back to the start of its line.
        line (int | None):
            1-based line number to start at (alternative to `offset`).
        backward (bool):
            Return the lines before the start position instead of the lines from it on.
        limit (int):
            Maximum number of lines to return.
        max_bytes (int):
            Soft cap for the summed size of the returned lines.
        levels (int | None):
            Bit mask of the level codes that pass. None lets every level pass.
        query (LogQuery | None):
            The search query. None lets every line pass.
        count_only (bool):
            Count the passing lines instead of returning them.

    """

    offset: int | None = None
    line: int | None = None
    backward: bool = False
    limit: int = DEFAULT_LIMIT
    max_bytes: int = DEFAULT_MAX_BYTES
    levels: int | None = None
    query: LogQuery | None = None
    count_only: bool = False


@dataclass(frozen=True, slots=True)
class IndexView:
    """A consistent snapshot of a line index.

    The checkpoint containers are shared with the index. They only ever grow, and a view must
    not look beyond its own `checkpoints` count.

    Attributes:
        ident (tuple[int, int]):
            Device and inode of the indexed file.
        size (int):
            Size of the file in bytes as far as known.
        complete (bool):
            Whether the index has seen the file up to `size`.
        indexed_bytes (int):
            End of the indexed lines.
        lines (int):
            Number of indexed lines.
        level (int):
            Level code in effect at `indexed_bytes`.
        counts (tuple[int, ...]):
            Number of record starts per level code.
        offsets (array):
            Byte offset of each checkpoint. Checkpoints are line starts.
        line_nos (array):
            Number of lines before each checkpoint.
        levels (bytearray):
            Level code in effect at each checkpoint.
        forced (tuple[int, ...]):
            Numbers of the checkpoints that start an overlong line, which was split and
            therefore does not end with a line feed.
        checkpoints (int):
            Number of checkpoints this view may use.

    """

    ident: tuple[int, int]
    size: int
    complete: bool
    indexed_bytes: int
    lines: int
    level: int
    counts: tuple[int, ...]
    offsets: array
    line_nos: array
    levels: bytearray
    forced: tuple[int, ...]
    checkpoints: int


class LogIndex:
    """Incremental line index of one log file.

    The index knows the number of lines, the number of record starts per level and a sparse
    list of checkpoints (byte offset, line number, level in effect). It is extended by a
    background thread and held in memory only; it needs about 17 bytes per checkpoint, which
    is some 270 KiB per gigabyte of log.
    """

    def __init__(self, path: str) -> None:
        """Initialize the index.

        Args:
            path (str):
                The path of the log file.

        """

        self.path = path
        self._lock = threading.Lock()
        self._changed = threading.Condition(self._lock)
        self._ident: tuple[int, int] | None = None
        self._generation = 0
        self._building = False
        self._clear()

    # end method definition

    def _clear(self) -> None:
        """Forget everything known about the file. The caller holds the lock."""

        # A builder thread of the previous generation notices the new one and stops.
        self._generation += 1
        self._building = False
        self._offsets = array("q", [0])
        self._line_nos = array("q", [0])
        self._levels = bytearray(1)
        self._forced: list[int] = []
        self._indexed = 0
        self._scanned = 0
        self._lines = 0
        self._level = 0
        self._counts = [0] * len(LEVEL_NAMES)

    # end method definition

    def refresh(self, stat_result: os.stat_result, wait: float = INDEX_WAIT_SECONDS) -> IndexView:
        """Bring the index up to date with the file and return a snapshot.

        Starts the background thread if the file has content the index has not seen, and
        waits for it for a limited time. The thread keeps running after this method returned.

        Args:
            stat_result (os.stat_result):
                The current status of the log file.
            wait (float, optional):
                The maximum time in seconds to wait for the index to catch up.

        Returns:
            IndexView:
                The snapshot. Its `complete` flag tells whether the index caught up.

        """

        ident = (stat_result.st_dev, stat_result.st_ino)
        size = stat_result.st_size
        deadline = time.monotonic() + wait

        with self._changed:
            # The file was replaced or it shrank: start over.
            if ident != self._ident or size < self._indexed:
                self._ident = ident
                self._clear()

            started_at = -1
            while self._scanned < size and self._ident == ident:
                if not self._building:
                    # A thread that ended without getting anywhere is not started again
                    # by the same request.
                    if started_at == self._scanned:
                        break
                    started_at = self._scanned
                    self._building = True
                    threading.Thread(
                        target=self._build,
                        args=(self._generation,),
                        name="LogIndex",
                        daemon=True,
                    ).start()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._changed.wait(remaining)

            if self._ident != ident:
                # Another request found a newer file under the same path meanwhile:
                # nothing is known about the file of this request.
                return IndexView(
                    ident=ident,
                    size=size,
                    complete=False,
                    indexed_bytes=0,
                    lines=0,
                    level=0,
                    counts=(0,) * len(LEVEL_NAMES),
                    offsets=array("q", [0]),
                    line_nos=array("q", [0]),
                    levels=bytearray(1),
                    forced=(),
                    checkpoints=1,
                )

            return IndexView(
                ident=ident,
                size=max(size, self._scanned),
                complete=self._scanned >= size,
                indexed_bytes=self._indexed,
                lines=self._lines,
                level=self._level,
                counts=tuple(self._counts),
                offsets=self._offsets,
                line_nos=self._line_nos,
                levels=self._levels,
                forced=tuple(self._forced),
                checkpoints=len(self._offsets),
            )

    # end method definition

    def _build(self, generation: int) -> None:
        """Extend the index up to the end of the file (body of the background thread).

        Args:
            generation (int):
                The generation of the index the thread was started for.

        """

        try:
            with open(self.path, "rb") as file:
                stat_result = os.fstat(file.fileno())
                with self._lock:
                    if generation != self._generation or (stat_result.st_dev, stat_result.st_ino) != self._ident:
                        return
                    position = self._indexed
                    lines = self._lines
                    level = self._level
                    last_checkpoint = self._offsets[-1]

                file.seek(position)
                carry = b""
                since_yield = 0

                while True:
                    chunk = file.read(READ_BYTES)
                    if not chunk:
                        break
                    data = carry + chunk if carry else chunk
                    checkpoints: list[tuple[int, int, int]] = []
                    forced: list[int] = []
                    counts = [0] * len(LEVEL_NAMES)

                    # Only the first line of the data can be overlong: every other line
                    # starts inside the chunk that was just read.
                    if len(data) >= MAX_LINE_BYTES and data.find(_NEWLINE, 0, MAX_LINE_BYTES) < 0:
                        # The overlong line gets a checkpoint of its own ...
                        if last_checkpoint != position:
                            checkpoints.append((position, lines, level))
                        forced.append(position)
                        found = RECORD_RE.findall(data, 0, MAX_LINE_BYTES)
                        if found:
                            level = LEVEL_CODES[found[0]]
                            counts[level] += 1
                        lines += 1
                        # ... and so does the line after it. That line must not be looked at
                        # together with the overlong one: it starts at a word boundary.
                        data = data[MAX_LINE_BYTES:]
                        position += MAX_LINE_BYTES
                        last_checkpoint = position
                        checkpoints.append((last_checkpoint, lines, level))

                    end = data.rfind(_NEWLINE) + 1
                    start = 0
                    while start < end:
                        due = last_checkpoint + CHECKPOINT_BYTES - position
                        if due <= start:
                            last_checkpoint = position + start
                            checkpoints.append((last_checkpoint, lines, level))
                            due = start + CHECKPOINT_BYTES
                        # A segment ends at the first line start at or after the due position.
                        stop = data.find(_NEWLINE, due - 1, end) + 1 if due < end else end
                        if not stop:
                            stop = end
                        found = RECORD_RE.findall(data, start, stop)
                        if found:
                            for name in found:
                                counts[LEVEL_CODES[name]] += 1
                            level = LEVEL_CODES[found[-1]]
                        lines += data.count(_NEWLINE, start, stop)
                        start = stop

                    with self._changed:
                        if generation != self._generation:
                            return
                        for offset, line_no, level_code in checkpoints:
                            self._offsets.append(offset)
                            self._line_nos.append(line_no)
                            self._levels.append(level_code)
                        for offset in forced:
                            self._forced.append(bisect_left(self._offsets, offset))
                        for code, count in enumerate(counts):
                            self._counts[code] += count
                        self._lines = lines
                        self._level = level
                        self._indexed = position + end
                        self._scanned = position + len(data)
                        self._changed.notify_all()

                    carry = data[end:]
                    position += end

                    since_yield += len(chunk)
                    if since_yield >= YIELD_EVERY_BYTES:
                        since_yield = 0
                        time.sleep(YIELD_SECONDS)
        except OSError as exc:
            logger.warning("Cannot index log file -> '%s'; error -> %s", self.path, exc)
        finally:
            with self._changed:
                if generation == self._generation:
                    self._building = False
                self._changed.notify_all()

    # end method definition


# end class definition

_INDEXES: dict[str, LogIndex] = {}
_INDEXES_LOCK = threading.Lock()


def get_index(path: str) -> LogIndex:
    """Get the line index of a log file, creating it if necessary.

    Args:
        path (str):
            The path of the log file.

    Returns:
        LogIndex:
            The index of the file.

    """

    with _INDEXES_LOCK:
        index = _INDEXES.get(path)
        if index is None:
            index = _INDEXES[path] = LogIndex(path)
        return index


def drop_index(path: str) -> None:
    """Discard the line index of a log file, e.g. because the file is gone.

    Args:
        path (str):
            The path of the log file.

    """

    with _INDEXES_LOCK:
        _INDEXES.pop(path, None)


def decode_line(raw: bytes) -> str:
    """Convert the bytes of a line to its text.

    Args:
        raw (bytes):
            The bytes of the line without the line feed.

    Returns:
        str:
            The text of the line: without a trailing carriage return and with invalid
            UTF-8 replaced.

    """

    if raw.endswith(b"\r"):
        raw = raw[:-1]
    return raw.decode("utf-8", "replace")


def parse_levels(value: str | None) -> int | None:
    """Convert the level filter of a request.

    Args:
        value (str | None):
            Comma separated level names. None means all levels, an empty value means no
            level (only lines without a level pass).

    Raises:
        ValueError:
            If the value names an unknown level.

    Returns:
        int | None:
            The bit mask of the passing level codes, or None if every level passes.

    """

    if value is None:
        return None

    mask = 0
    for name in value.split(","):
        name = name.strip().upper()
        if not name:
            continue
        if name not in FILTER_LEVELS:
            message = "Unknown level -> '{}'. Allowed levels are {}.".format(name, ", ".join(FILTER_LEVELS))
            raise ValueError(message)
        mask |= 1 << FILTER_LEVELS[name]

    return None if mask == ALL_LEVELS_MASK else mask


def compile_query(q: str | None, *, regex: bool = False, case: bool = False, word: bool = False) -> LogQuery | None:
    """Compile the search query of a request.

    Args:
        q (str | None):
            The search text. None or an empty text means no query.
        regex (bool, optional):
            Treat the text as a regular expression (Python syntax) instead of literally.
        case (bool, optional):
            Match the case exactly.
        word (bool, optional):
            Match whole words only: neither end of the match may lie between two word
            characters.

    Raises:
        ValueError:
            If the text is not a valid regular expression.

    Returns:
        LogQuery | None:
            The compiled query, or None if there is nothing to search for.

    """

    if not q:
        return None

    expression = q if regex else re.escape(q)
    if word:
        boundary = r"(?:(?<!\w)|(?!\w))"
        expression = boundary + "(?:" + expression + ")" + boundary
    try:
        pattern = re.compile(expression, 0 if case else re.IGNORECASE)
    except (re.error, RecursionError, OverflowError) as exc:
        message = "Invalid regular expression -> {}".format(exc)
        raise ValueError(message) from exc

    if regex or "\n" in q or "\ufffd" in q:
        return LogQuery(pattern=pattern)

    # Without regular expression every matching line contains the text itself. With the case
    # ignored this is only safe for the ASCII part of the text, where the case rules are simple.
    if q.isascii() and "\r" not in q:
        # Pure ASCII text is found reliably in the bytes of the log. Only the word boundaries
        # are left to check, at the ends of the text that are word characters themselves.
        return LogQuery(
            pattern=pattern,
            needle=(q if case else q.lower()).encode("ascii"),
            fold=not case,
            extras=() if case else _fold_extras(q.lower()),
            exact=True,
            word_left=word and _is_word(q[0]),
            word_right=word and _is_word(q[-1]),
        )
    if case:
        try:
            return LogQuery(pattern=pattern, needle=q.encode("utf-8"))
        except UnicodeEncodeError:
            return LogQuery(pattern=pattern)

    run = max(re.findall(r"[\x00-\x7f]+", q), key=len, default="").lower()
    if not run:
        return LogQuery(pattern=pattern)

    return LogQuery(pattern=pattern, needle=run.encode("ascii"), fold=True, extras=_fold_extras(run))


def _is_word(character: str) -> bool:
    """Check whether an ASCII character is a word character (letter, digit or underscore)."""

    return character.isalnum() or character == "_"


def _fold_extras(text: str) -> tuple[bytes, ...]:
    """Get the byte sequences that equal a letter of a lower case text when the case is ignored."""

    return tuple(sequence for letter, sequences in _FOLD_EXTRAS.items() if letter in text for sequence in sequences)


def build_lines_request(
    *,
    offset: int | None = None,
    line: int | None = None,
    direction: str = "forward",
    limit: int = DEFAULT_LIMIT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    levels: str | None = None,
    q: str | None = None,
    regex: bool = False,
    case: bool = False,
    word: bool = False,
    count_only: bool = False,
) -> LogLinesRequest:
    """Check and convert the parameters of a request for log lines.

    Args:
        offset (int | None, optional):
            The byte offset to start at.
        line (int | None, optional):
            The 1-based line number to start at. Only one of `offset` and `line` may be given.
        direction (str, optional):
            "forward" or "backward".
        limit (int, optional):
            The maximum number of lines to return (0 to `MAX_LIMIT`).
        max_bytes (int, optional):
            The soft cap for the summed size of the returned lines.
        levels (str | None, optional):
            The level filter (see `parse_levels`).
        q (str | None, optional):
            The search text (see `compile_query`).
        regex (bool, optional):
            Treat the search text as a regular expression.
        case (bool, optional):
            Match the case of the search text.
        word (bool, optional):
            Match whole words only.
        count_only (bool, optional):
            Count the passing lines instead of returning them.

    Raises:
        ValueError:
            If a parameter is invalid. The message says which one and why.

    Returns:
        LogLinesRequest:
            The request.

    """

    message = None
    if offset is not None and line is not None:
        message = "Only one of 'offset' and 'line' may be given."
    elif offset is not None and offset < 0:
        message = "The offset must not be negative."
    elif line is not None and line < 1:
        message = "The line must be 1 or higher."
    elif direction not in ("forward", "backward"):
        message = "Unknown direction -> '{}'. Allowed directions are forward, backward.".format(direction)
    elif not 0 <= limit <= MAX_LIMIT:
        message = "The limit must be between 0 and {}.".format(MAX_LIMIT)
    elif max_bytes < 0:
        message = "The value of max_bytes must not be negative."
    if message:
        raise ValueError(message)

    return LogLinesRequest(
        offset=offset,
        line=line,
        backward=direction == "backward",
        limit=limit,
        max_bytes=max_bytes,
        levels=parse_levels(levels),
        query=compile_query(q, regex=regex, case=case, word=word),
        count_only=count_only,
    )


class _Block:
    """A piece of the log made of whole lines, with what is known about its position."""

    __slots__ = ("_levels", "_number", "_number_at", "_starts", "base", "data", "level", "lines_before")

    def __init__(self, data: bytes, base: int, lines_before: int, level: int) -> None:
        """Initialize the block.

        Args:
            data (bytes):
                The bytes of the block. Starts at a line start and ends at one, or with a
                line that has no line feed (overlong line, end of the file).
            base (int):
                The byte offset of the block in the file.
            lines_before (int):
                The number of lines before the block.
            level (int):
                The level code in effect at the start of the block.

        """

        self.data = data
        self.base = base
        self.lines_before = lines_before
        self.level = level
        self._starts: list[int] | None = None
        self._levels: list[int] = []
        self._number = lines_before + 1
        self._number_at = 0

    def _records(self) -> list[int]:
        """Find the record starts of the block: the positions of their lines and their levels."""

        if self._starts is None:
            data = self.data
            starts = []
            levels = []
            for match in RECORD_RE.finditer(data):
                starts.append(data.rfind(_NEWLINE, 0, match.start()) + 1)
                levels.append(LEVEL_CODES[match[1]])
            self._starts = starts
            self._levels = levels
        return self._starts

    def level_of(self, start: int) -> int:
        """Get the level code of the line starting at a position of the block."""

        index = bisect_right(self._records(), start) - 1
        return self._levels[index] if index >= 0 else self.level

    def number_of(self, start: int) -> int:
        """Get the line number of the line starting at a position of the block."""

        if start >= self._number_at:
            self._number += self.data.count(_NEWLINE, self._number_at, start)
        else:
            self._number -= self.data.count(_NEWLINE, start, self._number_at)
        self._number_at = start
        return self._number

    def spans(self, mask: int | None) -> list[tuple[int, int]]:
        """Get the ranges of the block whose lines pass a level filter.

        Args:
            mask (int | None):
                The bit mask of the passing level codes. None lets every level pass.

        Returns:
            list[tuple[int, int]]:
                The ranges in ascending order. Each starts at a line start and ends at one
                or at the end of the block.

        """

        size = len(self.data)
        if mask is None:
            return [(0, size)] if size else []

        starts = self._records()
        spans = []
        begin = 0
        # Lines without a level always pass.
        passing = self.level == 0 or bool(mask >> self.level & 1)
        for start, level in zip(starts, self._levels, strict=True):
            now_passing = bool(mask >> level & 1)
            if now_passing != passing:
                if passing and start > begin:
                    spans.append((begin, start))
                begin = start
                passing = now_passing
        if passing and size > begin:
            spans.append((begin, size))
        return spans


def _lines(data: bytes, begin: int, end: int, *, reverse: bool) -> Iterator[tuple[int, int]]:
    """Walk the lines of a range of a block.

    Args:
        data (bytes):
            The bytes of the block.
        begin (int):
            The start of the range, a line start.
        end (int):
            The end of the range, a line start or the end of the block.
        reverse (bool):
            Walk from the last line to the first one.

    Yields:
        tuple[int, int]:
            Start of a line and position of its line feed (or the end of the block).

    """

    if reverse:
        position = end
        while position > begin:
            stop = position - 1 if data[position - 1] == _LINE_FEED else position
            found = data.rfind(_NEWLINE, begin, stop)
            position = begin if found < 0 else found + 1
            yield position, stop
    else:
        position = begin
        while position < end:
            stop = data.find(_NEWLINE, position, end)
            if stop < 0:
                stop = end
            yield position, stop
            position = stop + 1


def _count_lines(data: bytes, begin: int, end: int) -> int:
    """Count the lines of a range of a block (arguments as for `_lines`)."""

    if end <= begin:
        return 0
    return data.count(_NEWLINE, begin, end) + (data[end - 1] != _LINE_FEED)


def _needle_lines(
    data: bytes, haystack: bytes, begin: int, end: int, query: LogQuery, *, reverse: bool
) -> Iterator[tuple[int, int]]:
    """Walk the lines of a range of a block that match a query with a needle.

    Only the lines containing the needle are looked at more closely.

    Args:
        data (bytes):
            The bytes of the block.
        haystack (bytes):
            The bytes to find the needle in: the block, in lower case if the query asks for it.
        begin (int):
            The start of the range, a line start.
        end (int):
            The end of the range, a line start or the end of the block.
        query (LogQuery):
            The query.
        reverse (bool):
            Walk from the last line to the first one.

    Yields:
        tuple[int, int]:
            Start of a matching line and position of its line feed (or the end of the block).

    """

    needle = query.needle
    position = end if reverse else begin
    while begin < position if reverse else position < end:
        hit = haystack.rfind(needle, begin, position) if reverse else haystack.find(needle, position, end)
        if hit < 0:
            return
        found = data.rfind(_NEWLINE, begin, hit)
        start = begin if found < 0 else found + 1
        stop = data.find(_NEWLINE, hit, end)
        if stop < 0:
            stop = end
        if not query.exact:
            passing = query.matches(data[start:stop])
        elif query.word_left or query.word_right:
            passing = _word_hit(data, haystack, start, stop, query)
        else:
            passing = True
        if passing:
            yield start, stop
        position = start if reverse else stop + 1


def _word_hit(data: bytes, haystack: bytes, start: int, stop: int, query: LogQuery) -> bool:
    """Check whether the exact needle of a query is found as a whole word in a line.

    Args:
        data (bytes):
            The bytes of the block.
        haystack (bytes):
            The bytes to find the needle in.
        start (int):
            The start of the line.
        stop (int):
            The position of the line feed of the line (or the end of the block).
        query (LogQuery):
            The query.

    Returns:
        bool:
            True if the query matches the line.

    """

    needle = query.needle
    hit = haystack.find(needle, start, stop)
    while hit >= 0:
        end = hit + len(needle)
        before = data[hit - 1] if query.word_left and hit > start else _LINE_FEED
        after = data[end] if query.word_right and end < stop else _LINE_FEED
        if before >= _NON_ASCII or after >= _NON_ASCII:
            # Whether the neighbour is a word character takes the full rules to tell.
            return query.matches(data[start:stop])
        if before not in _WORD_BYTES and after not in _WORD_BYTES:
            return True
        hit = haystack.find(needle, hit + 1, stop)
    return False


def _split_text(piece: bytes) -> list[str]:
    """Split a piece of a block into the texts of its lines."""

    text = piece.decode("utf-8", "replace")
    if "\r" in text:
        text = text.replace("\r\n", "\n")
    texts = text.split("\n")
    if piece.endswith(_NEWLINE):
        texts.pop()
    elif texts[-1].endswith("\r"):
        texts[-1] = texts[-1][:-1]
    return texts


def _pattern_lines(data: bytes, begin: int, end: int, query: LogQuery, *, reverse: bool) -> Iterator[tuple[int, int]]:
    """Walk the lines of a range of a block that match a query, testing every line.

    Arguments and result as for `_needle_lines`.
    """

    piece = data if begin == 0 and end == len(data) else data[begin:end]
    if not piece:
        return
    search = query.pattern.search
    hits = [number for number, text in enumerate(_split_text(piece)) if search(text)]
    if not hits:
        return

    # Byte position of every line of the piece: the summed lengths of the lines before it
    # plus their line feeds.
    parts = piece.split(_NEWLINE)
    ends = list(accumulate(map(len, parts)))
    for number in reversed(hits) if reverse else hits:
        stop = begin + ends[number] + number
        yield stop - len(parts[number]), stop


def _count_pattern_lines(data: bytes, begin: int, end: int, query: LogQuery) -> int:
    """Count the lines of a range of a block that match a query, testing every line."""

    piece = data if begin == 0 and end == len(data) else data[begin:end]
    if not piece:
        return 0
    search = query.pattern.search
    return sum(1 for text in _split_text(piece) if search(text))


def _haystack(data: bytes, query: LogQuery) -> bytes | None:
    """Decide whether the needle of a query is of use for a block.

    Args:
        data (bytes):
            The bytes of the block.
        query (LogQuery):
            The query.

    Returns:
        bytes | None:
            The bytes to find the needle in, or None if every line of the block has to be
            tested instead.

    """

    needle = query.needle
    if needle is None:
        return None
    # The block has characters that equal ASCII letters when the case is ignored.
    if query.extras and not data.isascii() and any(extra[:1] in data and extra in data for extra in query.extras):
        return None
    haystack = data.lower() if query.fold else data
    # Testing single lines only pays off as long as few of them contain the needle.
    if not query.exact and haystack.count(needle, 0, NEEDLE_SAMPLE_BYTES) > NEEDLE_SAMPLE_HITS:
        return None
    return haystack


def _passing_lines(block: _Block, request: LogLinesRequest, *, reverse: bool) -> Iterator[tuple[int, int]]:
    """Walk the lines of a block that pass the level filter and the query of a request.

    Args:
        block (_Block):
            The block.
        request (LogLinesRequest):
            The request.
        reverse (bool):
            Walk from the last line to the first one.

    Yields:
        tuple[int, int]:
            Start of a passing line and position of its line feed (or the end of the block).

    """

    data = block.data
    spans = block.spans(request.levels)
    if reverse:
        spans.reverse()
    query = request.query

    if query is None:
        for begin, end in spans:
            yield from _lines(data, begin, end, reverse=reverse)
        return

    haystack = _haystack(data, query)
    for begin, end in spans:
        if haystack is None:
            yield from _pattern_lines(data, begin, end, query, reverse=reverse)
        else:
            yield from _needle_lines(data, haystack, begin, end, query, reverse=reverse)


def _count_passing_lines(block: _Block, request: LogLinesRequest) -> int:
    """Count the lines of a block that pass the level filter and the query of a request."""

    data = block.data
    spans = block.spans(request.levels)
    query = request.query

    if query is None:
        return sum(_count_lines(data, begin, end) for begin, end in spans)
    haystack = _haystack(data, query)
    if haystack is None:
        return sum(_count_pattern_lines(data, begin, end, query) for begin, end in spans)
    return sum(1 for begin, end in spans for _ in _needle_lines(data, haystack, begin, end, query, reverse=False))


class _Scan:
    """One request for log lines against a snapshot of the index."""

    def __init__(
        self,
        file: BinaryIO,
        view: IndexView,
        request: LogLinesRequest,
        *,
        tail: bool,
        deadline: float,
        budget_bytes: int,
        cancel: threading.Event | None,
    ) -> None:
        """Initialize the scan.

        Args:
            file (BinaryIO):
                The open log file.
            view (IndexView):
                The snapshot of the index.
            request (LogLinesRequest):
                The request.
            tail (bool):
                Whether the unterminated end of the file counts as a line.
            deadline (float):
                The monotonic time at which the scan has to stop.
            budget_bytes (int):
                The number of bytes after which the scan has to stop.
            cancel (threading.Event | None):
                Set when the result is no longer wanted.

        """

        self.file = file
        self.view = view
        self.request = request
        self.tail = tail
        # The end of the lines this scan may serve.
        self.end = view.size if tail else view.indexed_bytes
        self.deadline = deadline
        self.budget_bytes = budget_bytes
        self.cancel = cancel
        self.scanned = 0
        self.lines: list[dict] = []
        self.matched = 0
        self.text_bytes = 0
        self.max_bytes = min(request.max_bytes, MAX_MAX_BYTES)

    def _read(self, begin: int, end: int) -> bytes:
        """Read a range of the file."""

        self.file.seek(begin)
        data = self.file.read(end - begin)
        if len(data) != end - begin:
            # The file is shorter than its index: it was truncated meanwhile.
            raise LogChangedError
        self.scanned += len(data)
        return data

    def _segment_end(self, checkpoint: int) -> int:
        """Get the end of the segment starting at a checkpoint."""

        view = self.view
        return view.offsets[checkpoint + 1] if checkpoint + 1 < view.checkpoints else view.indexed_bytes

    def _exhausted(self) -> bool:
        """Check whether the scan has to stop: budget used up or result no longer wanted."""

        return (
            self.scanned >= self.budget_bytes
            or time.monotonic() >= self.deadline
            or (self.cancel is not None and self.cancel.is_set())
        )

    def resolve(self) -> int | None:
        """Find the start position of the request.

        Returns:
            int | None:
                The byte offset of the line start the request starts at, or None if the
                index does not reach that far yet.

        """

        view = self.view
        request = self.request
        indexed = view.indexed_bytes

        if request.line is not None:
            wanted = request.line - 1
            if wanted > view.lines or (wanted == view.lines and not self.tail):
                return self.end if view.complete else None
            if wanted == view.lines:
                return indexed
            checkpoint = bisect_right(view.line_nos, wanted, 0, view.checkpoints) - 1
            position = view.offsets[checkpoint]
            skip = wanted - view.line_nos[checkpoint]
            if skip:
                data = self._read(position, self._segment_end(checkpoint))
                found = -1
                for _ in range(skip):
                    found = data.find(_NEWLINE, found + 1)
                position += found + 1
            return position

        if request.offset is None:
            if not request.backward:
                return 0
            return self.end if view.complete else None

        offset = request.offset
        if offset >= self.end:
            return self.end if view.complete or offset == indexed else None
        if offset >= indexed:
            return indexed
        checkpoint = bisect_right(view.offsets, offset, 0, view.checkpoints) - 1
        position = view.offsets[checkpoint]
        if offset > position and checkpoint not in view.forced:
            data = self._read(position, offset)
            position += data.rfind(_NEWLINE) + 1
        return position

    def _block_from(self, position: int, target: int) -> _Block:
        """Read the block that starts at a line start and is about `target` bytes long."""

        view = self.view
        if position >= view.indexed_bytes:
            return _Block(self._read(position, self.end), position, view.lines, view.level)

        count = view.checkpoints
        checkpoint = bisect_right(view.offsets, position, 0, count) - 1
        lines_before = view.line_nos[checkpoint]
        level = view.levels[checkpoint]
        begin = view.offsets[checkpoint]
        if begin < position:
            # The block starts inside a segment: look at the lines of the segment before it.
            lead = self._read(begin, position)
            lines_before += lead.count(_NEWLINE)
            found = RECORD_RE.findall(lead)
            if found:
                level = LEVEL_CODES[found[-1]]

        forced = view.forced
        next_forced = bisect_right(forced, checkpoint)
        if next_forced and forced[next_forced - 1] == checkpoint:
            last = checkpoint + 1
        else:
            last = bisect_left(view.offsets, position + target, checkpoint + 1, count)
            if next_forced < len(forced):
                last = min(last, forced[next_forced])
        end = view.offsets[last] if last < count else view.indexed_bytes
        return _Block(self._read(position, end), position, lines_before, level)

    def _block_before(self, position: int, target: int) -> _Block:
        """Read the block that ends at a line start and is about `target` bytes long."""

        view = self.view
        if position > view.indexed_bytes:
            return _Block(
                self._read(view.indexed_bytes, position),
                view.indexed_bytes,
                view.lines,
                view.level,
            )

        last = bisect_left(view.offsets, position, 0, view.checkpoints) - 1
        forced = view.forced
        previous_forced = bisect_right(forced, last)
        if previous_forced and forced[previous_forced - 1] == last:
            first = last
        else:
            first = max(bisect_right(view.offsets, position - target, 0, last + 1) - 1, 0)
            if previous_forced:
                first = max(first, forced[previous_forced - 1] + 1)
        begin = view.offsets[first]
        return _Block(self._read(begin, position), begin, view.line_nos[first], view.levels[first])

    def _collect(self, block: _Block, *, reverse: bool) -> int | None:
        """Add the passing lines of a block to the result.

        Args:
            block (_Block):
                The block.
            reverse (bool):
                Walk from the last line of the block to the first one.

        Returns:
            int | None:
                None if the whole block was looked at. Otherwise the byte offset at which
                the limits of the request stopped the scan.

        """

        request = self.request
        if request.count_only:
            self.matched += _count_passing_lines(block, request)
            return None

        data = block.data
        for start, stop in _passing_lines(block, request, reverse=reverse):
            raw = data[start:stop]
            following = min(stop + 1, len(data))
            if self.lines and self.text_bytes + len(raw) > self.max_bytes:
                # The line does not fit any more: the next request starts with it.
                return block.base + (following if reverse else start)
            self.lines.append(
                {
                    "n": block.number_of(start),
                    "offset": block.base + start,
                    "level": LEVEL_NAMES[block.level_of(start)],
                    "text": decode_line(raw),
                }
            )
            self.matched += 1
            self.text_bytes += len(raw)
            if self.matched >= request.limit or self.text_bytes >= self.max_bytes:
                return block.base + (start if reverse else following)
        return None

    def run(self, position: int) -> tuple[int, int]:
        """Scan from the start position until a limit of the request or the budget is reached.

        Args:
            position (int):
                The start position as found by `resolve`.

        Returns:
            tuple[int, int]:
                The byte range that was scanned completely.

        """

        request = self.request
        if not request.count_only and request.limit <= 0:
            return position, position

        target = SCAN_BLOCK_BYTES_MAX if request.count_only else SCAN_BLOCK_BYTES
        origin = position
        first = True
        if request.backward:
            while position > 0:
                if not first and self._exhausted():
                    break
                block = self._block_before(position, target)
                stopped_at = self._collect(block, reverse=True)
                if stopped_at is not None:
                    position = stopped_at
                    break
                position = block.base
                target = min(target * 2, SCAN_BLOCK_BYTES_MAX)
                first = False
                # Let other threads (a running deployment) have the interpreter lock.
                time.sleep(0)
            self.lines.reverse()
            return position, origin

        while position < self.end:
            if not first and self._exhausted():
                break
            block = self._block_from(position, target)
            stopped_at = self._collect(block, reverse=False)
            if stopped_at is not None:
                position = stopped_at
                break
            position = block.base + len(block.data)
            target = min(target * 2, SCAN_BLOCK_BYTES_MAX)
            first = False
            time.sleep(0)
        return origin, position


def _open_log(path: str, wait: float) -> tuple[BinaryIO, IndexView]:
    """Open a log file and get an up-to-date snapshot of its index.

    Args:
        path (str):
            The path of the log file.
        wait (float):
            The maximum time in seconds to wait for the index to catch up.

    Raises:
        FileNotFoundError:
            If the log file does not exist.

    Returns:
        tuple[BinaryIO, IndexView]:
            The open file (to be closed by the caller) and the snapshot.

    """

    try:
        file = open(path, "rb")  # noqa: SIM115
    except FileNotFoundError:
        drop_index(path)
        raise
    try:
        # The status of the open file is used, so that file and snapshot belong together
        # even if the path gets a new file at this very moment.
        view = get_index(path).refresh(os.fstat(file.fileno()), wait=wait)
    except BaseException:
        file.close()
        raise
    return file, view


def _has_tail(view: IndexView, running: bool) -> bool:
    """Check whether the unterminated end of the file counts as a line."""

    return not running and view.complete and view.size > view.indexed_bytes


def read_log_info(path: str, running: bool, wait: float = INDEX_WAIT_SECONDS) -> dict:
    """Describe a log file and the progress of its index.

    Args:
        path (str):
            The path of the log file.
        running (bool):
            Whether the payload writing the log is still running.
        wait (float, optional):
            The maximum time in seconds to wait for the index to catch up.

    Raises:
        FileNotFoundError:
            If the log file does not exist.

    Returns:
        dict:
            The fields of the info response.

    """

    file, view = _open_log(path, wait)
    with file:
        lines = view.lines
        counts = list(view.counts)
        indexed = view.indexed_bytes
        if _has_tail(view, running):
            file.seek(indexed)
            found = RECORD_RE.findall(file.read(view.size - indexed))
            if found:
                counts[LEVEL_CODES[found[0]]] += 1
            lines += 1
            indexed = view.size

    return {
        "version": CONTRACT_VERSION,
        "size": view.size,
        "indexed_bytes": indexed,
        "indexing": not view.complete,
        "lines": lines,
        "counts": {name: counts[code] for name, code in sorted(FILTER_LEVELS.items(), key=lambda item: -item[1])},
        "running": running,
        "record_start": RECORD_START_PATTERN,
    }


def read_log_lines(
    path: str,
    running: bool,
    request: LogLinesRequest,
    cancel: threading.Event | None = None,
    *,
    wait: float | None = None,
    budget_seconds: float | None = None,
    budget_bytes: int | None = None,
) -> dict:
    """Read a window of lines from a log file.

    Args:
        path (str):
            The path of the log file.
        running (bool):
            Whether the payload writing the log is still running.
        request (LogLinesRequest):
            What to read.
        cancel (threading.Event | None, optional):
            Set by the caller when the result is no longer wanted; the scan then stops.
        wait (float | None, optional):
            The maximum time in seconds to wait for the index to catch up.
        budget_seconds (float | None, optional):
            The time after which the scan stops and reports how far it got.
        budget_bytes (int | None, optional):
            The number of scanned bytes after which the scan stops.

    Raises:
        FileNotFoundError:
            If the log file does not exist.

    Returns:
        dict:
            The fields of the lines response.

    """

    budget_seconds = SCAN_BUDGET_SECONDS if budget_seconds is None else budget_seconds
    deadline = time.monotonic() + budget_seconds
    wait = min(INDEX_WAIT_SECONDS if wait is None else wait, budget_seconds)

    # A file that is replaced while it is read is read again, once.
    for attempt in range(2):
        file, view = _open_log(path, wait)
        with file:
            tail = _has_tail(view, running)
            scan = _Scan(
                file,
                view,
                request,
                tail=tail,
                deadline=deadline,
                budget_bytes=SCAN_BUDGET_BYTES if budget_bytes is None else budget_bytes,
                cancel=cancel,
            )
            try:
                position = scan.resolve()
                if position is None or (
                    # Nothing of what a forward request asks for is indexed yet.
                    not view.complete and not request.backward and position >= scan.end
                ):
                    covered = False
                    if position is None:
                        position = view.indexed_bytes if request.offset is None else min(request.offset, view.size)
                        if request.line is None and request.offset is None:
                            position = view.size
                    start = end = position
                else:
                    covered = True
                    start, end = scan.run(position)
            except LogChangedError:
                if attempt:
                    raise
                drop_index(path)
                continue
        break

    return {
        "lines": scan.lines if covered else [],
        "matched": scan.matched if covered else 0,
        "start": start,
        "end": end,
        "bof": start == 0,
        "eof": view.complete and end >= scan.end,
        "size": view.size,
        "indexing": not view.complete,
        "indexed_bytes": view.size if tail else view.indexed_bytes,
        "running": running,
    }

"""Helper to wait for services / pods to become ready with a configurable timeout."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import time
from collections.abc import Callable

default_logger = logging.getLogger("pyxecm_customizer.wait")

# Share of the wait time after which a limited wait reports that it is still waiting:
WAIT_LOG_MILESTONES = (0.25, 0.5, 0.75, 0.9)
# Seconds between two of these reports of a wait without limit:
WAIT_LOG_INTERVAL = 600


class WaitBudget:
    """Limit for the time several waits may take together (e.g. all waits of a customizer run)."""

    def __init__(self, total: float) -> None:
        """Initialize the WaitBudget.

        Args:
            total (float):
                The number of seconds all waits may take together.

        """

        self.total = total
        self.spent: float = 0

    # end method definition

    def remaining(self) -> float:
        """Get the number of seconds that are left in the budget.

        Returns:
            float:
                The remaining seconds. 0 if the budget is exhausted.

        """

        return max(0, self.total - self.spent)

    # end method definition

    def spend(self, seconds: float) -> None:
        """Deduct the duration of a wait from the budget.

        Args:
            seconds (float):
                The number of seconds the wait took.

        """

        self.spent += seconds

    # end method definition


# end class definition


def next_log_time(start: float, end: float | None, now: float) -> float:
    """Determine when a wait should report the next time that it is still waiting.

    Args:
        start (float):
            The start of the wait (time.monotonic() based).
        end (float | None):
            The end of the wait or None if the wait has no limit.
        now (float):
            The current time.

    Returns:
        float:
            The time of the next report. The end of the wait if no milestone is left.

    """

    if end is None:
        return now + WAIT_LOG_INTERVAL

    milestones = (start + (end - start) * milestone for milestone in WAIT_LOG_MILESTONES)
    return next((milestone for milestone in milestones if milestone > now), end)


def wait_until[T](
    check: Callable[[], T | None],
    what: str,
    timeout: int = 0,
    interval: int = 30,
    budget: WaitBudget | None = None,
    on_timeout: Callable[[], None] | None = None,
    logger: logging.Logger = default_logger,
) -> T | None:
    """Call check() until it returns a truthy value or the timeout expires.

    A first check that succeeds does not wait and costs nothing. With an exhausted
    budget a service that is ready still passes, only one that is not ready fails at once.

    The check runs every interval, but to keep the log readable the wait is only reported
    when it starts, at the WAIT_LOG_MILESTONES of the wait time and, for a wait without
    limit, every WAIT_LOG_INTERVAL seconds.

    Args:
        check (Callable[[], T | None]):
            Function that is called repeatedly. A truthy return value ends the wait.
        what (str):
            Description of what we are waiting for (used in log messages).
        timeout (int, optional):
            Maximum number of seconds to wait. 0 = wait forever. Defaults to 0.
        interval (int, optional):
            Seconds to sleep between two checks. Defaults to 30.
        budget (WaitBudget | None, optional):
            Optional budget shared by several waits, e.g. for an overall limit of all
            waits of a customizer run. The earlier of timeout and budget wins.
        on_timeout (Callable[[], None] | None, optional):
            Optional callback invoked once the timeout is reached (e.g. to log diagnostics).
        logger (logging.Logger, optional):
            The logger to use.

    Returns:
        T | None:
            The (truthy) result of check() or None if the timeout was reached.

    """

    start = time.monotonic()

    result = check()
    if result:
        return result

    end = start + timeout if timeout and timeout > 0 else None
    if budget is not None:
        budget_end = start + budget.remaining()
        end = budget_end if end is None else min(end, budget_end)

    log_time = start

    try:
        while True:
            now = time.monotonic()
            if end is not None and now >= end:
                logger.error(
                    "%s did not become ready within %d seconds - giving up!",
                    what,
                    int(now - start),
                )
                if on_timeout:
                    try:
                        on_timeout()
                    except Exception as err:
                        logger.debug("Failed to collect diagnostics after timeout: %s", err)
                return None

            sleep_time = interval if end is None else max(0, min(interval, end - now))
            if now >= log_time:
                logger.warning(
                    "%s is not ready yet after %d seconds. Checking every %d seconds%s...",
                    what,
                    int(now - start),
                    interval,
                    f" ({int(end - now)} seconds left until timeout)" if end is not None else "",
                )
                log_time = next_log_time(start, end, now)
            time.sleep(sleep_time)

            result = check()
            if result:
                return result
    finally:
        if budget is not None:
            budget.spend(time.monotonic() - start)

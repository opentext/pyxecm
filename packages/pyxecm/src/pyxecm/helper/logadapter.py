"""Custom adapter to prefix all messages with a custom prefix."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging


class PrefixLogAdapter(logging.LoggerAdapter):
    """Prefix all messages with a custom prefix."""

    def process(self, msg: str, kwargs: dict) -> tuple[str, dict]:
        """Prefix the log message with the value of `extra["prefix"]` in square brackets.

        Args:
            msg (str):
                The log message.
            kwargs (dict):
                The keyword arguments of the logging call. Returned unchanged.

        Returns:
            tuple[str, dict]:
                The prefixed message and the unchanged keyword arguments.

        """

        return "[{}] {}".format(self.extra["prefix"], msg), kwargs

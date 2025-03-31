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
        """TODO _summary_.

        Args:
            msg (_type_): TODO _description_
            kwargs (_type_): TODO _description_

        Returns:
            _type_: _description_

        """

        return "[{}] {}".format(self.extra["prefix"], msg), kwargs

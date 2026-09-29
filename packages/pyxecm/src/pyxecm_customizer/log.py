"""Common logging handler for VictoriaLogs and the LogCountFilter."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging

import pandas as pd


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

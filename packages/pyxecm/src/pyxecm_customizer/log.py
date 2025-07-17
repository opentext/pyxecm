"""Common logging handler for VictoriaLogs and the LogCountFilter."""

import logging

import pandas as pd


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

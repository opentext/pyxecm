"""Definition for all custom exception."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"


class StopOnError(Exception):
    """Custom exception to stop customizer on error."""

    def __init__(self, message: str) -> None:
        """Initialize the StopOnErrorException with a message.

        Args:
            message (str):
                The error message.

        """
        super().__init__(message)


class PayloadImportError(Exception):
    """Custom exception if the import of the payload failed."""

    def __init__(self, message: str) -> None:
        """Initialize the PayloadImportException with a message.

        Args:
            message (str):
                The error message.

        """
        super().__init__(message)

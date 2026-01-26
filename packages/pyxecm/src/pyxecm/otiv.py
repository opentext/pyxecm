"""OTIV Module to keep Intelligent Viewing specific data."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
from importlib.metadata import version

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otiv"

default_logger = logging.getLogger(MODULE_NAME)


class OTIV:
    """Class OTIV is used to manage stettings for OpenText Intelligent Viewing."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    def __init__(
        self,
        resource_name: str,
        product_name: str,
        product_description: str,
        license_file: str,
        default_license: str = "FULLTIME_USERS_REGULAR",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the OTIV class for Intelligent Viewing.

        Args:
            resource_name (str):
                The OTDS resource name.
            product_name (str):
                The OTDS product name for licensing.
            product_description (str):
                The OTDS product description for licensing.
            license_file (str):
                The path to license file.
            default_license (str, optional):
                Defaults to "FULLTIME_USERS_REGULAR".
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otiv")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        # Initialize otiv_config as an empty dictionary
        otiv_config = {}

        otiv_config["resource"] = resource_name
        otiv_config["product"] = product_name
        otiv_config["description"] = product_description
        otiv_config["license_file"] = license_file
        otiv_config["license"] = default_license

        self._config = otiv_config

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict:
                The configuration dictionary.

        """
        return self._config

    # end method definition

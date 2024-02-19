"""
OTIV Module to keep Intelligent Viewing specific data
such as connection parameters, license information ...

Class: OTIV
Methods:

__init__ : class initializer
config : returns config data set
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging

logger = logging.getLogger("pyxecm.otiv")


class OTIV:
    """Used to manage stettings for OpenText Intelligent Viewing."""

    _config: dict

    def __init__(
        self,
        resource_name: str,
        product_name: str,
        product_description: str,
        license_file: str,
        default_license: str = "FULLTIME_USERS_REGULAR",
    ):
        """Initialize the OTIV class for Intelligent Viewing

        Args:
            resource_name (str): OTDS resource name
            product_name (str): OTDS product name for licensing
            license_file (str): path to license file
            default_license (str, optional): Defaults to "FULLTIME_USERS_REGULAR".
        """

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
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    # end method definition

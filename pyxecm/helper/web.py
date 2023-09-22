"""
Module to implement functions to execute Web Requests

Class: HTTP
Methods:

__init__ : class initializer
check_host_reachable: checks if a server / host is reachable
http_request: make a HTTP request to a defined URL / endpoint (e.g. a Web Hook)

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2023, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import socket
import requests

logger = logging.getLogger("pyxecm.web")

requestHeaders = {"Content-Type": "application/x-www-form-urlencoded"}


class HTTP(object):
    """Used to issue HTTP request and test if hosts are reachable."""

    _config = None

    def __init__(self):
        """Initialize the HTTP object

        Args:
        """

    def check_host_reachable(self, hostname: str, port: int = 80) -> bool:
        """Check if a server / web address is reachable

        Args:
            hostname (str): endpoint hostname
            port (int): endpoint port
        Results:
            bool: True is reachable, False otherwise
        """

        logger.info(
            "Test if host -> %s is reachable on port -> %s ...", hostname, str(port)
        )
        try:
            socket.getaddrinfo(hostname, port)
        except socket.gaierror as exception:
            logger.warning(
                "Address-related error - cannot reach host -> %s; error -> %s",
                hostname,
                exception.strerror,
            )
            return False
        except socket.error as exception:
            logger.warning(
                "Connection error - cannot reach host -> %s; error -> %s",
                hostname,
                exception.strerror,
            )
            return False
        else:
            logger.info("Host is reachable at -> %s:%s", hostname, str(port))
            return True

    # end method definition

    def http_request(
        self,
        url: str,
        method: str = "POST",
        payload: dict = {},
        headers: dict = {},
        timeout: int = 60,
    ):
        """Issues an http request

        Args:
            url (str): URL of the request
            method (str, optional): Method of the request (POST, PUT, GET, ...). Defaults to "POST".
            payload (dict, optional): Request payload. Defaults to {}.
            headers (dict, optional): Request header. Defaults to {}. If {} then a default
                                      value defined in "requestHeaders" is used.
            timeout (int): timeout in seconds

        Returns:
            Response of call
        """

        if not headers:
            headers = requestHeaders

        logger.info(
            "Make HTTP Request to URL -> %s using -> %s method with payload -> %s",
            url,
            method,
            str(payload),
        )

        response = requests.request(
            method=method, url=url, data=payload, headers=headers, timeout=timeout
        )

        if not response.ok:
            logger.error(
                "HTTP request -> %s to url -> %s failed; error -> %s",
                method,
                url,
                response.text,
            )

        return response

    # end method definition

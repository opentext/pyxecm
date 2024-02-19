"""
Module to implement functions to execute Web Requests

Class: HTTP
Methods:

__init__ : class initializer
check_host_reachable: checks if a server / host is reachable
http_request: make a HTTP request to a defined URL / endpoint (e.g. a Web Hook)

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import socket
import time
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
        payload: dict | None = None,
        headers: dict | None = None,
        timeout: int = 60,
        retries: int = 0,
        wait_time: int = 0,
    ):
        """Issues an http request to a given URL.

        Args:
            url (str): URL of the request
            method (str, optional): Method of the request (POST, PUT, GET, ...). Defaults to "POST".
            payload (dict, optional): Request payload. Defaults to None.
            headers (dict, optional): Request header. Defaults to None. If None then a default
                                      value defined in "requestHeaders" is used.
            timeout (int, optional): timeout in seconds
            retries (int, optional): number of retries. If -1 then unlimited retries.
            wait_time (int, optional): number of seconds to wait after each try
        Returns:
            Response of call
        """

        if not headers:
            headers = requestHeaders

        logger.info(
            "Make HTTP Request to URL -> %s using -> %s method with payload -> %s (max number of retries = %s)",
            url,
            method,
            str(payload),
            str(retries),
        )

        try_counter = 1

        while True:
            response = requests.request(
                method=method, url=url, data=payload, headers=headers, timeout=timeout
            )

            if not response.ok and retries == 0:
                logger.error(
                    "HTTP request -> %s to url -> %s failed; status -> %s; error -> %s",
                    method,
                    url,
                    response.status_code,
                    response.text,
                )
                return response

            elif response.ok:
                logger.info(
                    "HTTP request -> %s to url -> %s succeeded with status -> %s!",
                    method,
                    url,
                    response.status_code,
                )
                if wait_time > 0:
                    logger.info("Sleeping %s seconds...", wait_time)
                    time.sleep(wait_time)
                return response

            else:
                logger.warning(
                    "HTTP request -> %s to url -> %s failed (try %s); status -> %s; error -> %s",
                    method,
                    url,
                    try_counter,
                    response.status_code,
                    response.text,
                )
                if wait_time > 0:
                    logger.warning(
                        "Sleeping %s seconds and then trying once more...",
                        str(wait_time),
                    )
                    time.sleep(wait_time)
                else:
                    logger.warning("Trying once more...")
                retries -= 1
                try_counter += 1

    # end method definition

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
from lxml import html

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

        logger.debug(
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
            logger.debug("Host is reachable at -> %s:%s", hostname, str(port))
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
        wait_on_status: list | None = None,
        show_error: bool = True,
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
            wait_on_status (list, optional): list of status codes we want to wait on. If None
                                             or empty then we wait for all return codes if
                                             wait_time > 0
        Returns:
            Response of call
        """

        if not headers:
            headers = requestHeaders

        message = "Make HTTP Request to URL -> {} using -> {} method".format(
            url, method
        )
        if payload:
            message += " with payload -> {}".format(payload)
        if retries:
            message += " (max number of retries -> {}, wait time between retries -> {})".format(
                retries, wait_time
            )
            try:
                retries = int(retries)
            except ValueError:
                logger.warning(
                    "HTTP request -> retries is not a valid integer value: %s, defaulting to 0 retries ",
                    retries,
                )
                retries = 0

        logger.debug(message)

        try_counter = 1

        while True:
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    data=payload,
                    headers=headers,
                    timeout=timeout,
                )
                logger.debug("%s", response.text)
            except Exception as exc:
                response = None
                logger.warning(
                    "HTTP request -> %s to url -> %s failed failed (try %s); error -> %s",
                    method,
                    url,
                    try_counter,
                    exc,
                )

                # do we have an error and don't want to retry?
            if response is not None:
                # Do we have a successful result?
                if response.ok:
                    logger.debug(
                        "HTTP request -> %s to url -> %s succeeded with status -> %s!",
                        method,
                        url,
                        response.status_code,
                    )

                    if wait_on_status and response.status_code in wait_on_status:
                        logger.debug(
                            "%s is in wait_on_status list: %s",
                            response.status_code,
                            wait_on_status,
                        )
                    else:
                        return response

                elif not response.ok:
                    message = "HTTP request -> {} to url -> {} failed; status -> {}; error -> {}".format(
                        method,
                        url,
                        response.status_code,
                        (
                            response.text
                            if response.headers.get("content-type")
                            == "application/json"
                            else "see debug log"
                        ),
                    )
                    if show_error and retries == 0:
                        logger.error(message)
                    else:
                        logger.warning(message)

            # Check if another retry is allowed, if not return None
            if retries == 0:
                return None

            if wait_time > 0:
                logger.warning(
                    "Sleeping %s seconds and then trying once more...",
                    str(wait_time),
                )
                time.sleep(wait_time)

            retries -= 1
            try_counter += 1

    # end method definition

    def download_file(
        self,
        url: str,
        filename: str,
        timeout: int = 120,
        retries: int = 0,
        wait_time: int = 0,
        wait_on_status: list | None = None,
        show_error: bool = True,
    ) -> bool:
        """Download a file from a URL

        Args:
            url (str): URL
            filename (str): filename to save
            timeout (int, optional): timeout in seconds
            retries (int, optional): number of retries. If -1 then unlimited retries.
            wait_time (int, optional): number of seconds to wait after each try
            wait_on_status (list, optional): list of status codes we want to wait on. If None
                                             or empty then we wait for all return codes if
                                             wait_time > 0

        Returns:
            bool: True if successful, False otherwise
        """

        response = self.http_request(
            url=url,
            method="GET",
            retries=retries,
            timeout=timeout,
            wait_time=wait_time,
            wait_on_status=wait_on_status,
            show_error=show_error,
        )

        if response is None:
            return False

        if response.ok:
            with open(filename, "wb") as f:
                f.write(response.content)
            logger.debug("File downloaded successfully as -> %s", filename)
            return True

        return False

    # end method definition

    def extract_content(self, url: str, xpath: str) -> str | None:
        """Extract a string from a response of a HTTP request
           based on an XPath.

        Args:
            url (str): URL to open
            xpath (str): XPath expression to apply to the result

        Returns:
            str | None: Extracted string or None in case of an error.
        """

        # Send a GET request to the URL
        response = requests.get(url, timeout=None)

        # Check if request was successful
        if response.status_code == 200:
            # Parse the HTML content
            tree = html.fromstring(response.content)

            # Extract content using XPath
            elements = tree.xpath(xpath)

            # Get text content of all elements and join them
            content = "\n".join([elem.text_content().strip() for elem in elements])

            # Return the extracted content
            return content
        else:
            # If request was not successful, print error message
            logger.error(response.status_code)
            return None

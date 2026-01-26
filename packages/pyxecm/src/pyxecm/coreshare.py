"""CoreShare Module to interact with the Core Share API.

See:
    - [Confluence](https://confluence.opentext.com/pages/viewpage.action?spaceKey=OTC&title=APIs+Consumption+based+on+roles)
    - [swagger.otxlab.net](https://swagger.otxlab.net/ui/?branch=master&yaml=application-specific/core/core-api.yaml)

Authentication - get Client Secrets:
    1. Login to Core Share as a Tenant Admin User.
    2. Navigate to Security Page.
    3. On OAuth Confidential Clients section provide Description and Redirect URLs. It will populate a
    dialog with Client Secret.
    4. Copy Client Secret as it will not be available anywhere once the dialog is closed.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import os
import platform
import sys
import time
import urllib.parse
from http import HTTPStatus
from importlib.metadata import version
from urllib.parse import parse_qs, urlparse

import requests

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".coreshare"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

default_logger = logging.getLogger(MODULE_NAME)

REQUEST_LOGIN_HEADERS = {
    "User-Agent": USER_AGENT,
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}

REQUEST_TIMEOUT = 60.0
REQUEST_RETRY_DELAY = 20.0
REQUEST_MAX_RETRIES = 2

CONTENT_MANAGER_ROLE_ID = 5
GROUP_ADMIN_ROLE_ID = 3


class CoreShare:
    """Class CoreShare is used to retrieve and automate settings and objects (users, groups) in Core Share."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    def __init__(
        self,
        base_url: str,
        sso_url: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the CoreShare object.

        Args:
            base_url (str):
                The base URL of the Core Share tenant.
            sso_url (str):
                The single sign on URL of the Core Share tenant.
            client_id (str):
                The Core Share Client ID.
            client_secret (str):
                The Core Share client secret.
            username (str):
                The admin user name in Core Share.
            password (str):
                The admin password in Core Share.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """
        if logger != default_logger:
            self.logger = logger.getChild("coreshare")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        core_share_config = {}

        # Store the credentials and parameters in a config dictionary:
        core_share_config["clientId"] = client_id
        core_share_config["clientSecret"] = client_secret
        core_share_config["username"] = username
        core_share_config["password"] = password

        # Set the Core Share URLs and REST API endpoints:
        core_share_config["baseUrl"] = base_url
        core_share_config["ssoUrl"] = sso_url
        core_share_config["restUrlv1"] = core_share_config["baseUrl"] + "/api/v1"
        core_share_config["restUrlv3"] = core_share_config["baseUrl"] + "/api/v3"
        core_share_config["groupsUrl"] = core_share_config["restUrlv1"] + "/groups"
        core_share_config["usersUrlv1"] = core_share_config["restUrlv1"] + "/users"
        core_share_config["usersUrlv3"] = core_share_config["restUrlv3"] + "/users"
        core_share_config["invitesUrl"] = core_share_config["restUrlv1"] + "/invites"
        core_share_config["foldersUrlv1"] = core_share_config["restUrlv1"] + "/folders"
        core_share_config["foldersUrlv3"] = core_share_config["restUrlv3"] + "/folders"
        core_share_config["documentsUrlv1"] = core_share_config["restUrlv1"] + "/documents"
        core_share_config["documentsUrlv3"] = core_share_config["restUrlv3"] + "/documents"
        core_share_config["searchUrl"] = core_share_config["baseUrl"] + "/search/v1"
        core_share_config["searchUserUrl"] = core_share_config["searchUrl"] + "/user"
        core_share_config["searchGroupUrl"] = core_share_config["searchUrl"] + "/user/group-all"

        core_share_config["sessionsUrl"] = core_share_config["restUrlv1"] + "/sessions"
        core_share_config["tokenUrl"] = core_share_config["ssoUrl"] + "/otdsws/oauth2/token"
        core_share_config["sessionsUrl"] = core_share_config["restUrlv1"] + "/sessions"

        # Tenant Admin User Authentication information (Session URL):
        core_share_config["authorizationUrlAdmin"] = (
            core_share_config["sessionsUrl"]
            + "?client={'type':'web'}"
            + "&email="
            + urllib.parse.quote(username)
            + "&password="
            + urllib.parse.quote(password)
        )

        # Tenant Service User Authentication information:
        core_share_config["authorizationUrlCredentials"] = (
            core_share_config["tokenUrl"]
            + "?client_id="
            + client_id
            + "&client_secret="
            + client_secret
            + "&grant_type=client_credentials"
        )
        core_share_config["authorizationUrlPassword"] = (
            core_share_config["tokenUrl"]
            + "?client_id="
            + client_id
            + "&client_secret="
            + client_secret
            + "&grant_type=password"
            + "&username="
            + urllib.parse.quote(username)
            + "&password="
            + urllib.parse.quote(password)
        )

        self._access_token_user = None
        self._access_token_admin = None

        self._config = core_share_config

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict:
                The configuration dictionary.

        """

        return self._config

    # end method definition

    def credentials(self) -> dict:
        """Get credentials (username + password).

        Returns:
            dict:
                A dictionary with username and password.

        """

        return {
            "username": self.config()["username"],
            "password": self.config()["password"],
        }

    # end method definition

    def set_credentials(self, username: str = "admin", password: str = "") -> None:
        """Set the credentials for Core Share based on username and password.

        Args:
            username (str, optional): Username. Defaults to "admin".
            password (str, optional): Password of the user. Defaults to "".

        """

        self.logger.info("Change Core Share credentials to user -> %s...", username)

        self.config()["username"] = username
        self.config()["password"] = password

        # As the Authorization URLs include username password
        # we have to update them as well:
        self.config()["authorizationUrlAdmin"] = (
            self.config()["sessionsUrl"]
            + "?client={'type':'web'}"
            + "&email="
            + urllib.parse.quote(username)
            + "&password="
            + urllib.parse.quote(password)
        )

        self.config()["authorizationUrlPassword"] = (
            self.config()["tokenUrl"]
            + "?client_id="
            + self.config()["clientId"]
            + "&client_secret="
            + self.config()["clientSecret"]
            + "&grant_type=password"
            + "&username="
            + urllib.parse.quote(username)
            + "&password="
            + urllib.parse.quote(password)
        )

    # end method definition

    def request_header_admin(self, content_type: str = "application/json") -> dict:
        """Return the request header used for application calls that require administrator credentials.

        Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional):
                Custom content type for the request.
                Typical values:
                * application/json - Used for sending JSON-encoded data
                * application/x-www-form-urlencoded - The default for HTML forms.
                  Data is sent as key-value pairs in the body of the request, similar to query parameters.
                * multipart/form-data - Used for file uploads or when a form includes non-ASCII characters

        Return:
            dict:
                The request header values.

        """

        request_header = {
            "User-Agent": USER_AGENT,
            "Authorization": "Bearer {}".format(self._access_token_admin),
        }
        if content_type:
            request_header["Content-Type"] = content_type

        return request_header

    # end method definition

    def request_header_user(self, content_type: str = "application/json") -> dict:
        """Return the request header used for Application calls that require user (non-admin) credentials.

        Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional):
                The content type for the request.

        Return:
            dict:
                The request header values.

        """

        request_header = {
            "User-Agent": USER_AGENT,
            "Authorization": "Bearer {}".format(self._access_token_user),
        }
        if content_type:
            request_header["Content-Type"] = content_type

        return request_header

    # end method definition

    def do_request(
        self,
        url: str,
        method: str = "GET",
        headers: dict | None = None,
        data: dict | None = None,
        json_data: dict | None = None,
        files: dict | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        show_warning: bool = False,
        warning_message: str = "",
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
        parse_request_response: bool = True,
        user_credentials: bool = False,
        verify: bool = True,
    ) -> dict | None:
        """Call an OTDS REST API in a safe way.

        Args:
            url (str):
                The URL to send the request to.
            method (str, optional):
                HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                Request Headers. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                The file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (float | None, optional):
                Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.
            show_warning (bool, optional):
                Whether or not an warning should be logged in case of a
                failed REST call.
                If False, then only a warning is logged. Defaults to True.
            warning_message (str, optional):
                Specific warning message. Defaults to "". If not given the error_message will be used.
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            max_retries (int, optional):
                How many retries on Connection errors? Default is REQUEST_MAX_RETRIES.
            retry_forever (bool, optional):
                Eventually wait forever - without timeout. Defaults to False.
            parse_request_response (bool, optional):
                If True the response.text will be interpreted as json and loaded into a dictionary.
                True is the default.
            user_credentials (bool, optional):
                Defines if admin or user credentials are used for the REST API call.
                Default = False = admin credentials
            verify (bool, optional):
                Specify whether or not SSL certificates should be verified when making an HTTPS request.
                Default = True

        Returns:
            dict | None:
                Response of OTDS REST API or None in case of an error.

        """

        if headers is None:
            self.logger.error(
                "Missing request header. Cannot send request to Core Share!",
            )
            return None

        # In case of an expired session we reauthenticate and
        # try 1 more time. Session expiration should not happen
        # twice in a row:
        retries = 0

        while True:
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    timeout=timeout,
                    verify=verify,
                )

                if response.ok:
                    if success_message:
                        self.logger.info(success_message)
                    if parse_request_response:
                        return self.parse_request_response(response)
                    else:
                        return response
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    if user_credentials:
                        self.logger.debug(
                            "User session has expired - try to re-authenticate...",
                        )
                        self.authenticate_user(revalidate=True)
                        # Make sure to not change the content type:
                        headers = self.request_header_user(
                            content_type=headers.get("Content-Type", None),
                        )
                    else:
                        self.logger.warning(
                            "Admin session has expired - try to re-authenticate...",
                        )
                        self.authenticate_admin(revalidate=True)
                        # Make sure to not change the content type:
                        headers = self.request_header_admin(
                            content_type=headers.get("Content-Type", None),
                        )
                    retries += 1
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    if content_type == "text/html":
                        response_text = "HTML content (only printed in debug log)"
                    elif "image" in content_type:
                        response_text = "Image content (not printed)"
                    else:
                        response_text = response.text

                    if show_error:
                        self.logger.error(
                            "%s; status -> %s/%s; error -> %s",
                            failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response_text,
                        )
                    elif show_warning:
                        self.logger.warning(
                            "%s; status -> %s/%s; warning -> %s",
                            warning_message if warning_message else failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response_text,
                        )
                    if content_type == "text/html":
                        self.logger.debug(
                            "%s; status -> %s/%s; warning -> %s",
                            failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response.text,
                        )
                    return None
            except requests.exceptions.Timeout:
                if retries <= max_retries:
                    self.logger.warning(
                        "Request timed out. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; timeout error!",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                    else:
                        return None
            except requests.exceptions.ConnectionError:
                if retries <= max_retries:
                    self.logger.warning(
                        "Connection error. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; connection error!",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                        time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                    else:
                        return None
            # end try
            self.logger.debug(
                "Retrying REST API %s call -> %s... (retry = %s)",
                method,
                url,
                str(retries),
            )
        # end while True

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Convert the request response to a dict in a safe way.

        This also handles exceptions. It first tries to load the response.text
        via json.loads() that produces a dict output. Only if response.text is
        not set or is empty it just converts the response_object to a dict using
        the vars() built-in method.

        Args:
            response_object (object):
                This is reponse object returned by the request call.
            additional_error_message (str, optional):
                Can be used to provide a more specific error message
                in case an error occurs.
            show_error (bool, optional):
                True: write an error to the log file (this is the default)
                False: write a warning to the log file

        Returns:
            dict: response information or None in case of an error

        """

        if not response_object:
            return None

        try:
            dict_object = json.loads(response_object.text) if response_object.text else vars(response_object)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSon. {}; error -> {}".format(
                    additional_error_message,
                    exception,
                )
            else:
                message = "Cannot decode response as JSon; error -> {}".format(
                    exception,
                )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            return None
        else:
            return dict_object

    # end method definition

    def lookup_result_value(
        self,
        response: dict,
        key: str,
        value: str,
        return_key: str,
    ) -> str | None:
        """Lookup a property value based on a provided key / value pair in the response of an Core Share REST API call.

        Args:
            response (dict):
                REST response from an Core Share REST Call
            key (str):
                The property name (key).
            value (str):
                The value to find in the item with the matching key.
            return_key (str):
                Determines which value to return based on the name of the dict key.

        Returns:
            str | None:
                The value of the property with the key defined in "return_key"
                 or None if the lookup fails.

        """

        if not response:
            return None
        if "results" not in response:
            return None

        results = response["results"]

        if not results or not isinstance(results, list):
            return None

        for result in results:
            if key in result and result[key] == value and return_key in result:
                return result[return_key]
        return None

    # end method definition

    def exist_result_item(
        self,
        response: dict,
        key: str,
        value: str,
        results_marker: str = "results",
    ) -> bool:
        """Check existence of key / value pair in the response properties of a Core Share API call.

        Args:
            response (dict):
                REST response from a Core Share API call
            key (str):
                A property name (key)
            value (str):
                The value to find in the item with the matching key.
            results_marker (str, optional):
                The name of the data structure for the results.

        Returns:
            bool:
                True, if the value was found, False otherwise.

        """

        if not response:
            return False

        if results_marker in response:
            results = response[results_marker]
            if not results or not isinstance(results, list):
                return False

            for result in results:
                if value == result[key]:
                    return True
        else:
            if key not in response:
                return False
            if value == response[key]:
                return True

        return False

    # end method definition

    def get_result_value(
        self,
        response: dict | list,
        key: str,
        index: int = 0,
    ) -> str | None:
        """Get value of a result property with a given key of a Core Share API call.

        Args:
            response (dict or list):
                REST response from a Core Share REST Call
            key (str):
                The property name (key).
            index (int, optional):
                Index to use (1st element has index 0).
                Defaults to 0.

        Returns:
            str:
                The value for the key, None in case of an error.

        """

        if not response:
            return None

        # response is mostly a dictionary but in some cases also a list (e.g. add_group_member())
        if isinstance(response, list):
            if len(response) - 1 < index:
                return None
            if key not in response[index]:
                return None
            value = response[index][key]
            return value

        if isinstance(response, dict):
            # Does response have a "results" substructure?
            if "results" in response:
                # we expect results to be a list!
                values = response["results"]
                if not values or not isinstance(values, list) or len(values) - 1 < index:
                    return None
                if key not in values[index]:
                    return None
                value = values[index][key]
            else:  # simple response as dictionary - try to find key in response directly:
                if key not in response:
                    return None
                value = response[key]

            return value

        return None

    # end method definition

    def authenticate_admin(
        self,
        revalidate: bool = False,
    ) -> str | None:
        """Authenticate at Core Share as Tenant Admin.

        Args:
            revalidate (bool, optional):
                Defines whether or not a re-athentication is enforced
                (e.g. if session has timed out with 401 error).

        Returns:
            str:
                The access token. Also stores access token in self._access_token.
                None in case of error.

        """

        # Already authenticated and session still valid?
        if self._access_token_admin and not revalidate:
            self.logger.debug(
                "Session still valid - return existing access token -> %s",
                str(self._access_token_admin),
            )
            return self._access_token_admin

        request_url = self.config()["authorizationUrlAdmin"]

        request_header = REQUEST_LOGIN_HEADERS

        self.logger.debug(
            "Requesting Core Share Admin Access Token from -> %s",
            request_url,
        )

        response = None
        self._access_token_admin = None

        try:
            response = requests.post(
                request_url,
                headers=request_header,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.ConnectionError as exception:
            self.logger.warning(
                "Unable to connect to -> %s : %s",
                request_url,
                exception,
            )
            return None

        if response.ok:
            authenticate_dict = self.parse_request_response(response)
            if not authenticate_dict:
                return None
            else:
                cookies = response.cookies
                if "AccessToken" in cookies:
                    access_token = cookies["AccessToken"]

                    # String manipulation to extract pure AccessToken
                    if access_token.startswith("s%3A"):
                        access_token = access_token[4:]
                        access_token = access_token.rsplit(".", 1)[0]

                    # Store authentication access_token:
                    self._access_token_admin = access_token
                    self.logger.debug(
                        "Tenant Admin Access Token -> %s",
                        self._access_token_admin,
                    )
                else:
                    return None
        else:
            self.logger.error(
                "Failed to request a Core Share Tenant Admin Access Token; error -> %s",
                response.text,
            )
            return None

        return self._access_token_admin

    # end method definition

    def authenticate_user(
        self,
        revalidate: bool = False,
        grant_type: str = "password",
    ) -> str | None:
        """Authenticate at Core Share as Tenant Service User (TSU) with client ID and client secret.

        Args:
            revalidate (bool, optional):
                Defines whether or not a re-athentication is enforced
                (e.g. if session has timed out with 401 error).
            grant_type (str, optional):
                Can either be "client_credentials" (default) or "password".

        Returns:
            str:
                The access token. Also stores access token in self._access_token.
                None in case of error.

        """

        # Already authenticated and session still valid?
        if self._access_token_user and not revalidate:
            self.logger.debug(
                "Session still valid - return existing access token -> %s",
                str(self._access_token_user),
            )
            return self._access_token_user

        request_header = REQUEST_LOGIN_HEADERS
        request_url = self.config()["tokenUrl"]

        self.logger.debug(
            "Requesting Core Share Tenant Service User Access Token from -> %s",
            request_url,
        )

        response = None
        self._access_token_user = None

        authentication_body_post = {
            "grant_type": grant_type,
            "client_id": self.config()["clientId"],
            "client_secret": self.config()["clientSecret"],
        }

        if grant_type == "password":
            authentication_body_post["username"] = self.config()["username"]
            authentication_body_post["password"] = self.config()["password"]

        try:
            response = requests.post(
                request_url,
                headers=request_header,
                data=authentication_body_post,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.ConnectionError as exception:
            self.logger.warning(
                "Unable to connect to -> %s : %s",
                request_url,
                exception,
            )
            return None

        if response.ok:
            authenticate_dict = self.parse_request_response(response)
            if not authenticate_dict:
                return None
            else:
                # Store authentication access_token:
                self._access_token_user = authenticate_dict["access_token"]
                self.logger.debug(
                    "Tenant Service User Access Token -> %s",
                    self._access_token_user,
                )
        else:
            self.logger.error(
                "Failed to request a Core Share Tenant Service User Access Token; error -> %s",
                response.text,
            )
            return None

        return self._access_token_user

    # end method definition

    def get_groups(self, offset: int = 0, count: int = 25) -> dict | None:
        """Get Core Share groups.

        Args:
            offset (int, optional):
                The index of first group (for pagination). Defaults to 0.
            count (int, optional):
                The number of groups to return (page length). Defaults to 25.

        Returns:
            dict | None:
                Dictionary with the Core Share group data or None if the request fails.

            Example response:
            {
                '_links': {
                    'self': {'href': '/api/v1/groups?offset=undefined&count=25'},
                    'next': {'href': '/api/v1/groups?offset=NaN&count=25'}
                },
                'results': [
                    {
                        'id': '2593534258421173790',
                        'type': 'group',
                        'tenantId': '2157293035593927996',
                        'displayName': 'Innovate',
                        'name': 'Innovate',
                        'createdAt': '2024-05-01T09:29:36.370Z',
                        'uri': '/api/v1/groups/2593534258421173790',
                        'imageuri': '/img/app/group-default-lrg.png',
                        'thumbnailUri': '/img/app/group-default-sm.png',
                        'defaultImageUri': True,
                        'description': 'Demo Company Top Level Group',
                        'tenantName': 'terrarium'
                    }
                ]
            }

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()
        request_url = self.config()["groupsUrl"] + "?offset={}&count={}".format(
            offset,
            count,
        )

        self.logger.debug("Get Core Share groups; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Core Share groups",
            user_credentials=True,
        )

    # end method definition

    def get_groups_iterator(
        self,
        count: int | None = None,
    ) -> iter:
        """Get an iterator object that can be used to traverse all Core Share groups.

        Returning a generator avoids loading a large number of items into memory at once. Instead you
        can iterate over the potential large list of Core Share groups.

        Example usage:
            groups = core_share_object.get_groups_iterator(page_size=10)
            for group in groups:
                logger.info("Traversing Core Share group -> %s", group["name"])

        Args:
            count (int | None, optional):
                The chunk size for the number of groups returned by one
                REST API call. If None, then a default of 250 is used.

        Returns:
            iter:
                A generator yielding one OTDS group per iteration.
                If the REST API fails, returns no value.

        """

        offset = 0

        while True:
            response = self.get_groups(
                offset=offset,
                count=count,
            )
            if not response or not response.get("results", []):
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["results"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.

            next_page_url = response["_links"].get("next")
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return
            next_page_url = next_page_url.get("href")

            # Extract the query string from the URL
            query = urlparse(next_page_url).query

            # Parse the query parameters into a dictionary
            params = parse_qs(query)

            # Get the 'offset' value as an integer (it's a list by default)
            offset = int(params.get("offset", [0])[0])

    # end method definition

    def add_group(
        self,
        group_name: str,
        description: str = "",
    ) -> dict | None:
        """Add a new Core Share group. This requires a Tenent Admin authorization.

        Args:
            group_name (str):
                The name of the new Core Share group.
            description (str, optional):
                The description of the new Core Share group.

        Returns:
            dict | None:
                Dictionary with the Core Share Group data or None if the request fails.

            Example response:
            {
                "id": "2593534258421173790",
                "state": "enabled",
                "isEnabled": true,
                "isDeleted": false,
                "uri": "/api/v1/groups/2593534258421173790",
                "description": "Demo Company Top Level Group",
                "name": "Innovate",
                "imageUri": "/img/icons/mimeIcons/mime_group32.svg",
                "thumbnailUri": "/img/icons/mimeIcons/mime_group32.svg",
                "defaultImageUri": true,
                "memberCount": 0,
                "createdAt": "2024-05-01T09:29:36.370Z",
                "type": "group",
                "isSync": false,
                "tenantId": "2157293035593927996"
            }

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = self.config()["groupsUrl"]

        payload = {"name": group_name, "description": description}

        self.logger.debug(
            "Adding Core Share group -> %s; calling -> %s",
            group_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Core Share group -> '{}'".format(group_name),
            user_credentials=False,
        )

    # end method definition

    def get_group_members(self, group_id: str) -> dict | None:
        """Get Core Share group members.

        Args:
            group_id (str):
                The ID of the group to deliver the members for.

        Returns:
            dict | None:
                Dictionary with the Core Share group membership data or None if the request fails.

            Example response:
            {
                'groupMembers': [
                    {
                        'id': '2422700172682204885',
                        'type': 'user',
                        'tenantId': '2157293035593927996',
                        'firstName': 'Andy',
                        'lastName': 'Wyatt',
                        'displayName': 'Andy Wyatt',
                        'title': 'Buyer',
                        'company': 'terrarium',
                        'email': 'awyatt@M365x41497014.onmicrosoft.com',
                        'otSaaSUID': 'f5a6b58e-ad43-4e2d-a3e6-5c0fcd5cd4b1',
                        'otSaaSPID': 'aa49f566-0874-41e9-9924-452852ebaf7a',
                        'uri': '/api/v1/users/2422700172682204885',
                        'imageuri': '/img/app/profile-default-lrg.png',
                        'thumbnailUri': '/img/app/topbar-profile-default-sm.png',
                        'defaultImageUri': True,
                        'isSpecificGroupAdmin': False
                    }
                ],
                'pending': [

                ],
                'count': 0
            }

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = self.config()["groupsUrl"] + "/{}".format(group_id) + "/members"

        self.logger.debug(
            "Get members for Core Share group with ID -> %s; calling -> %s",
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get members of Core Share group -> '{}'".format(
                group_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def add_group_member(
        self,
        group_id: str,
        user_id: str,
        is_group_admin: bool = False,
    ) -> list | None:
        """Add a Core Share user to a Core Share group.

        Args:
            group_id (str):
                ID of the Core Share group.
            user_id (str):
                ID of the Core Share user.
            is_group_admin (bool, optional):
                Whether or not the member is a group administrator.
                Default is False.

        Returns:
            list | None:
                Dictionary with the Core Share group membership or None if the request fails.

            Example Response ('errors' is only output if success = False):
            [
                {
                    'member': 'alewis@qa.idea-te.eimdemo.com',
                    'success': True,
                    'user': {
                        'id': '2595801699801110696',
                        'email': 'alewis@qa.idea-te.eimdemo.com',
                        'otSaaSUID': '41325224-bbcf-4238-82b4-a9283be74821',
                        'otSaaSPID': 'aa49f566-0874-41e9-9924-452852ebaf7a',
                        'uri': '/api/v1/users/2595801699801110696',
                        'tenantId': '2157293035593927996',
                        'title': 'Records Manager',
                        'company': 'Innovate',
                        'lastName': 'Lewis',
                        'firstName': 'Anne',
                        'displayName': 'Lewis Anne',
                        'type': 'user',
                        'imageUri': 'https://core.opentext.com/api/v1/users/2595801699801110696/photo?id=0fbedc509fdfa1d27bcb5b3615714988e5f8e24598f0fc74b776ff049faef1f2',
                        'thumbnailUri': 'https://core.opentext.com/api/v1/users/2595801699801110696/photo?s=small&id=0fbedc509fdfa1d27bcb5b3615714988e5f8e24598f0fc74b776ff049faef1f2',
                        'defaultImageUri': False,
                        'isConfirmed': True,
                        'isEnabled': True
                    }
                    'errors': [
                        {
                            'code': 'groupInvitationExists',
                            'message': 'The user has already been invited to the group'
                        }
                    ]
                }
            ]

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = self.config()["groupsUrl"] + "/{}".format(group_id) + "/members"

        user = self.get_user_by_id(user_id=user_id)
        user_email = self.get_result_value(response=user, key="email")

        payload = {"members": [user_email], "specificGroupRole": is_group_admin}

        self.logger.debug(
            "Add Core Share user -> '%s' (%s) as %s to Core Share group with ID -> %s; calling -> %s",
            user_email,
            user_id,
            "group member" if not is_group_admin else "group admin",
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Core Share user -> '{}' to Core Share group with ID -> {}".format(
                user_email,
                group_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def remove_group_member(
        self,
        group_id: str,
        user_id: str,
        is_group_admin: bool = False,
    ) -> list | None:
        """Remove a Core Share user from a Core Share group.

        Args:
            group_id (str):
                The ID of the Core Share Group.
            user_id (str):
                The ID of the Core Share User.
            is_group_admin (bool, optional):
                True, if the member is a group admin.
                Default is False.

        Returns:
            list | None:
                Dictionary with the Core Share group membership or None if the request fails.

            Example Response ('errors' is only output if success = False):
            [
                {
                    'member': 'alewis@qa.idea-te.eimdemo.com',
                    'success': True,
                    'errors': [
                        {
                            'code': 'groupInvitationExists',
                            'message': 'The user has already been invited to the group'
                        }
                    ]
                }
            ]

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = self.config()["groupsUrl"] + "/{}".format(group_id) + "/members"

        user = self.get_user_by_id(user_id=user_id)
        user_email = self.get_result_value(response=user, key="email")

        payload = {"members": [user_email], "specificGroupRole": is_group_admin}

        self.logger.debug(
            "Remove Core Share user -> '%s' (%s) as %s from Core Share group with ID -> %s; calling -> %s",
            user_email,
            user_id,
            "group member" if not is_group_admin else "group admin",
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to remove Core Share user -> '{}' ({}) from Core Share group with ID -> {}".format(
                user_email,
                user_id,
                group_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def get_group_by_id(self, group_id: str) -> dict | None:
        """Get a Core Share group by its ID.

        Args:
            group_id (str):
                The ID of the Core Share group.

        Returns:
            dict | None:
                Dictionary with the Core Share group data or None if the request fails.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = self.config()["groupsUrl"] + "/" + group_id

        self.logger.debug(
            "Get Core Share group with ID -> %s; calling -> %s",
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Core Share group with ID -> {}".format(
                group_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def get_group_by_name(self, name: str) -> dict | None:
        """Get Core Share group by its name.

        Args:
            name (str):
                The name of the group to search.

        Returns:
            dict | None:
                Dictionary with the Core Share group data or None if the request fails.

            Example Response:
            {
                'results': [
                    {
                        'id': '2594934169968578199',
                        'type': 'group',
                        'tenantId': '2157293035593927996',
                        'displayName': 'Test Group',
                        'name': 'Test Group',
                        'createdAt': '2024-05-03T07:50:58.830Z',
                        'uri': '/api/v1/groups/2594934169968578199',
                        'imageuri': '/img/app/group-default-lrg.png',
                        'thumbnailUri': '/img/app/group-default-sm.png',
                        'defaultImageUri': True,
                        'description': '',
                        'tenantName': 'terrarium'
                    }
                ],
                'total': 1
            }

        """

        groups = self.search_groups(
            query_string=name,
        )

        return groups

    # end method definition

    def search_groups(self, query_string: str) -> dict | None:
        """Search Core Share group(s) using a query string.

        Args:
            query_string(str): Query for the group name / property

        Returns:
            dict | None: Dictionary with the Core Share user data or None if the request fails.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = self.config()["searchGroupUrl"] + "?q=" + query_string

        self.logger.debug(
            "Search Core Share group by -> %s; calling -> %s",
            query_string,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot find Core Share group with name / property -> {}".format(
                query_string,
            ),
            user_credentials=False,
        )

    # end method definition

    def get_users(self) -> list | None:
        """Get Core Share users.

        Args:
            None

        Returns:
            list | None:
                List with the Core Share user data or None if the request fails.

            Example response (it is a list!):
            [
                {
                    'id': '2400020228198108758',
                    'type': 'user',
                    'tenantId': '2157293035593927996',
                    'firstName': 'Technical Marketing',
                    'lastName': 'Service',
                    'displayName': 'Technical Marketing Service',
                    'title': 'Service User',
                    'company': 'terrarium',
                    'email': 'tm-service@opentext.com',
                    'otSaaSUID': 'fdb07113-4854-4f63-a208-55759ee925ce',
                    'otSaaSPID': 'aa49f566-0874-41e9-9924-452852ebaf7a',
                    'state': 'enabled',
                    'isEnabled': True,
                    'isConfirmed': True,
                    'quota': 2147483648,
                    'usage': 10400,
                    'uri': '/api/v1/users/2400020228198108758',
                    'imageuri': '/img/app/profile-default-lrg.png',
                    'thumbnailUri': '/img/app/topbar-profile-default-sm.png',
                    'defaultImageUri': True
                    'rootId': '2400020231108955735'
                    'userRoot' : {
                        {
                            'size': 0,
                            'id': '2400020231108955735',
                            'resourceType': 1,
                            'name': 'Files',
                            'createdById': '2400020228198108758',
                            'created': '2023-08-08T09:31:46.654Z',
                            'lastModified': '2023-09-19T15:11:56.925Z',
                            'lastModifiedById': '2400020228198108758',
                            'currentVersionNumber': None,
                            'currentVersionId': None,
                            'childCount': '4',
                            'shareCount': 1,
                            'deleteCount': 0,
                            'trashState': 0,
                            'imageId': None,
                            'thumbnailId': None,
                            'tedsImageId': None,
                            'tedsThumbnailId': None,
                            'parentId': None,
                            'tagCount': 0,
                            'versionCommentCount': 0,
                            'draftCommentCount': 0,
                            'subTypeId': None,
                            'contentOriginId': None,
                            'externalData': None,
                            'tenantId': '2157293035593927996',
                            'nodeType': 1,
                            'likesCount': 0,
                            'commentCount': 0,
                            'createdAt': '2023-08-08T09:31:46.655Z',
                            'updatedAt': '2023-09-19T15:11:56.925Z'
                        }
                    }
                    ...
                },
                ...
            ]

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = self.config()["usersUrlv1"]

        self.logger.debug("Get Core Share users; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Core Share users",
            user_credentials=False,
        )

    # end method definition

    def get_user_by_id(self, user_id: str) -> dict | None:
        """Get a Core Share user by its ID.

        Args:
            user_id (str):
                The ID of the user.

        Returns:
            dict | None:
                Dictionary with the Core Share user data or None if the request fails.

            Response example:
            {
                'accessRoles': [],
                'commentCount': 0,
                'company': 'terrarium',
                'createdAt': '2024-04-19T11:58:34.240Z',
                'defaultImageUri': True,
                'disabledAt': None,
                'displayName': 'Sato Ken',
                'email': 'ksato@idea-te.eimdemo.com',
                'firstName': 'Ken',
                'id': '2584911925942946703',
                'otSaaSUID': '6cab5035-abbc-481c-b049-10b4efae7408',
                'otSaaSPID': 'aa49f566-0874-41e9-9924-452852ebaf7a',
                'imageUri': 'https://core.opentext.com/img/app/profile-default-lrg.png',
                'invitedAt': '2024-04-19T11:58:36.307Z',
                'isAdmin': False,
                'isConfirmed': True,
                'isEnabled': True,
                'isSync': False,
                'lastLoginDate': -1,
                'lastName': 'Sato',
                'likesCount': 0,
                'rootId': '2584911935422073756',
                'state': 'enabled',
                'stateChanged': '2024-04-19T12:03:23.736Z',
                'tenantId': '2157293035593927996',
                'thumbnailUri': 'https://core.opentext.com/img/app/topbar-profile-default-sm.png',
                'title': 'Real Estate Manager',
                'type': 'user',
                'updatedAt': '2024-04-19T12:03:23.731Z',
                'uri': '/api/v1/users/2584911925942946703',
                'userRoot': {
                    'size': 0,
                    'id': '2584911935422073756',
                    'resourceType': 1,
                    'name': 'Files',
                    'createdById': '2584911925942946703',
                    'created': '2024-04-19T11:58:35.370Z',
                    'lastModified': '2024-04-19T11:58:35.370Z',
                    'lastModifiedById': '2584911925942946703',
                    'currentVersionNumber': None,
                    'currentVersionId': None,
                    'childCount': '0',
                    'shareCount': 1,
                    'deleteCount': 0,
                    'trashState': 0,
                    'imageId': None,
                    'thumbnailId': None,
                    'tedsImageId': None,
                    'tedsThumbnailId': None,
                    'parentId': None,
                    ...
                },
                'hasRequestedDelete': False,
                'defaultBaseUrl': 'https://core.opentext.com',
                'quota': 10737418240,
                'usage': 0
            }

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()
        request_url = self.config()["usersUrlv1"] + "/" + user_id

        self.logger.debug(
            "Get Core Share user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Core Share user with ID -> {}".format(
                user_id,
            ),
            user_credentials=True,
        )

    # end method definition

    def get_user_by_name(
        self,
        first_name: str,
        last_name: str,
        user_status: str = "internal-native",
    ) -> dict | None:
        """Get Core Share user by its first and last name.

        Args:
            first_name (str):
                First name of the users to search.
            last_name (str):
                Last name of the users to search.
            user_status (str, optional):
                Type of users. Possible values:
                * internal-enabled
                * internal-pending
                * internal-locked
                * internal-native   (non-SSO)
                * internal-sso

        Returns:
            dict | None:
                Dictionary with the Core Share user data or None if the request fails.

        """

        # Search the users with this first and last name (and hope this is unique ;-).
        users = self.search_users(
            query_string=first_name + " " + last_name,
            user_status=user_status,
        )

        return users

    # end method definition

    def get_user_by_email(
        self,
        email: str,
        user_status: str = "internal-native",
    ) -> dict | None:
        """Get Core Share user by its email address.

        Args:
            email (str):
                Email address of the users to search.
            user_status (str, optional):
                Type of users. Possible values:
                * internal-enabled
                * internal-pending
                * internal-locked
                * internal-native   (non-SSO)
                * internal-sso

        Returns:
            dict | None:
                Dictionary with the Core Share user data or None if the request fails.

        """

        # Search the users with this first and last name (and hope this is unique ;-).
        users = self.search_users(
            query_string=email,
            user_status=user_status,
        )

        return users

    # end method definition

    def search_users(
        self,
        query_string: str,
        user_status: str = "internal-native",
        page_size: int = 100,
    ) -> dict | None:
        """Search Core Share user(s) by name / property. Needs to be a Tenant Administrator to do so.

        Args:
            query_string (str):
                The string to query the user(s).
            user_status (str, optional):
                The type of users. Possible values:
                * internal-enabled
                * internal-pending
                * internal-locked
                * internal-native   (non-SSO)
                * internal-sso
            page_size (int, optional):
                The maximum number of results per page. We set the default to 100 (Web UI uses 25)

        Returns:
            dict | None: Dictionary with the Core Share user data or None if the request fails.

            Example response:
            {
                "results": [
                    {
                        "id": "2422698421996494632",
                        "type": "user",
                        "tenantId": "2157293035593927996",
                        "firstName": "Andy",
                        "lastName": "Wyatt",
                        "displayName": "Andy Wyatt",
                        "title": "Buyer",
                        "company": "terrarium",
                        "email": "awyatt@M365x46777101.onmicrosoft.com",
                        "otSaaSUID": "0842d1e1-acfc-425b-994a-e2dcb4d333c6",
                        "otSaaSPID": "aa49f566-0874-41e9-9924-452852ebaf7a",
                        "state": "enabled",
                        "isEnabled": true,
                        "isConfirmed": true,
                        "isAdmin": false,
                        "accessRoles": [],
                        "hasBeenDelegated": null,
                        "createdAt": "2023-09-08T16:29:17.680Z",
                        "lastLoginDate": "2023-10-05T16:14:16Z",
                        "quota": 1073741824,
                        "usage": 0,
                        "rootId": "2422698425964306217",
                        "uri": "/api/v1/users/2422698421996494632",
                        "imageuri": "/img/app/profile-default-lrg.png",
                        "thumbnailUri": "/img/app/topbar-profile-default-sm.png",
                        "defaultImageUri": true
                    },
                    ...
                ]
            }

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()
        request_url = (
            self.config()["searchUserUrl"]
            + "/{}".format(user_status)
            + "?q="
            + query_string
            + "&pageSize="
            + str(page_size)
        )

        self.logger.debug(
            "Search Core Share user by -> %s; calling -> %s",
            query_string,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to search Core Share user with name / property -> {}".format(
                query_string,
            ),
            user_credentials=False,
        )

    # end method definition

    def add_user(
        self,
        first_name: str,
        last_name: str,
        email: str,
        password: str | None = None,
        title: str | None = None,
        company: str | None = None,
    ) -> dict | None:
        """Add a new Core Share user. This requires a Tenent Admin authorization.

        Args:
            first_name (str):
                First name of the new user
            last_name (str):
                Last name of the new user
            email (str):
                Email of the new Core Share user
            password (str | None, optional):
                Password of the new Core Share user
            title (str | None, optional):
                Title of the user
            company (str | None, optional):
                Name of the Company of the user

        Returns:
            dict | None:
                Dictionary with the Core Share User data or None if the request fails.

            Example response:
            {
                "accessRoles": [],
                "commentCount": 0,
                "company": "terrarium",
                "createdAt": "2024-05-01T09:43:22.962Z",
                "defaultImageUri": true,
                "disabledAt": null,
                "displayName": "Tester Theo",
                "email": "theo@tester.com",
                "firstName": "Theo",
                "id": "2593541192377435562",
                "otSaaSUID": "77043e17-105c-418f-b4ba-1bef9f15937c",
                "otSaaSPID": "aa49f566-0874-41e9-9924-452852ebaf7a",
                "imageUri": "https://core.opentext.com/img/app/profile-default-lrg.png",
                "invitedAt": "2024-05-01T09:43:23.658Z",
                "isAdmin": false,
                "isConfirmed": false,
                "isEnabled": true,
                "isSync": false,
                "lastLoginDate": -1,
                "lastName": "Tester",
                "likesCount": 0,
                "rootId": "2593541195170842028",
                "state": "pending",
                "stateChanged": "2024-05-01T09:43:22.959Z",
                "tenantId": "2157293035593927996",
                "thumbnailUri": "https://core.opentext.com/img/app/topbar-profile-default-sm.png",
                "title": "VP Product Management",
                "type": "user",
                "updatedAt": "2024-05-01T09:43:23.658Z",
                "uri": "/api/v1/users/2593541192377435562",
                "hasRequestedDelete": false,
                "defaultBaseUrl": "https://core.opentext.com",
                "quota": 10737418240,
                "usage": 0
            }

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        # here we want the request to determine the content type automatically:
        request_header = self.request_header_admin(content_type="")
        request_url = self.config()["invitesUrl"]

        payload = {
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "quota": 10737418240,
        }
        if password:
            payload["password"] = password
        if title:
            payload["title"] = title
        if company:
            payload["company"] = company

        self.logger.debug(
            "Adding Core Share user -> %s %s; calling -> %s",
            first_name,
            last_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Core Share user -> '{} {}' ({})".format(
                first_name,
                last_name,
                email,
            ),
            user_credentials=False,
        )

    # end method definition

    def resend_user_invite(self, user_id: str) -> dict:
        """Resend the invite for a Core Share user.

        Args:
            user_id (str):
                The Core Share user ID.

        Returns:
            dict:
                Response from the Core Share API.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()

        request_url = self.config()["usersUrlv1"] + "/{}".format(user_id)

        self.logger.debug(
            "Resend invite for Core Share user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        update_data = {"resend": True}

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            json_data=update_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to resend invite for Core Share user with ID -> {}".format(
                user_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def update_user(self, user_id: str, update_data: dict) -> dict:
        """Update a Core Share user.

        Args:
            user_id (str):
                The ID of the Core Share user.
            update_data (dict):
                The updated user data.

        Returns:
            dict:
                REST response or None if the REST call has failed.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()

        request_url = self.config()["usersUrlv1"] + "/{}".format(user_id)

        self.logger.debug(
            "Update data of Core Share user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        if "email" in update_data and "password" not in update_data:
            self.logger.warning(
                "Trying to update the email without providing the password. This is likely to fail...",
            )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            json_data=update_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update Core Share user with ID -> {}".format(
                user_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def add_user_access_role(self, user_id: str, role_id: int) -> dict:
        """Add an access role to a Core Share user.

        Args:
            user_id (str):
                The Core Share user ID.
            role_id (int):
                The role ID:
                - Content Manager = 5
                - Group Admin = 3

        Returns:
            dict:
                Response from the Core Share API.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()

        request_url = self.config()["usersUrlv1"] + "/{}".format(user_id) + "/roles/" + str(role_id)

        self.logger.debug(
            "Add access role -> %s to Core Share user with ID -> %s; calling -> %s",
            str(role_id),
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add access role with ID -> {} to Core Share user with ID -> {}".format(
                role_id,
                user_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def remove_user_access_role(self, user_id: str, role_id: int) -> dict:
        """Remove an access role from a Core Share user.

        Args:
            user_id (str):
                The Core Share user ID.
            role_id (int):
                The role ID:
                * Content Manager = 5
                * Group Admin = 3

        Returns:
            dict:
                Response from the Core Share API.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()

        request_url = self.config()["usersUrlv1"] + "/{}".format(user_id) + "/roles/" + str(role_id)

        self.logger.debug(
            "Remove access role with ID -> %s from Core Share user with ID -> %s; calling -> %s",
            str(role_id),
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to remove access role with ID -> {} from Core Share user with ID -> {}".format(
                role_id,
                user_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def update_user_access_roles(
        self,
        user_id: str,
        is_admin: bool | None = None,
        is_content_manager: bool | None = None,
        is_group_admin: bool | None = None,
    ) -> dict:
        """Define the access roles of a Core Share user.

        Args:
            user_id (str):
                The ID of the Core Share user.
            is_content_manager (bool | None, optional):
                Assign Content Manager Role if True.
                Removes Content Manager Role if False.
                Does nothing if None.
                Defaults to None.
            is_group_admin (bool | None, optional):
                Assign Group Admin Role if True.
                Removes Group Admin Role if False.
                Does nothing if None.
                Defaults to None.
            is_admin (bool | None, optional):
                Makes user Admin if True.
                Removes Admin rights if False.
                Does nothing if None.
                Defaults to None.

        Returns:
            dict:
                Response from the Core Share API.

        """

        response = None

        # Admins don't have/need specific access roles. They are controled by isAdmin flag.
        if is_admin is not None:
            update_data = {}
            update_data["isAdmin"] = is_admin
            response = self.update_user(user_id=user_id, update_data=update_data)

        # Only for non-admins the other two roles are usable:
        if is_content_manager is not None:
            if is_content_manager:
                response = self.add_user_access_role(
                    user_id=user_id,
                    role_id=CONTENT_MANAGER_ROLE_ID,
                )
            else:
                response = self.remove_user_access_role(
                    user_id=user_id,
                    role_id=CONTENT_MANAGER_ROLE_ID,
                )

        if is_group_admin is not None:
            if is_group_admin:
                response = self.add_user_access_role(
                    user_id=user_id,
                    role_id=GROUP_ADMIN_ROLE_ID,
                )
            else:
                response = self.remove_user_access_role(
                    user_id=user_id,
                    role_id=GROUP_ADMIN_ROLE_ID,
                )

        return response

    # end method definition

    def update_user_password(
        self,
        user_id: str,
        password: str,
        new_password: str,
    ) -> dict:
        """Update the password of a Core Share user.

        Args:
            user_id (str):
                The Core Share user ID.
            password (str):
                The old user password.
            new_password (str):
                The new user password.

        Returns:
            dict:
                Response from the Core Share API.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()

        request_url = self.config()["usersUrlv1"] + "/{}".format(user_id)

        self.logger.debug(
            "Update password of Core Share user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        update_data = {"password": password, "newpassword": new_password}

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            json_data=update_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update password of Core Share user with ID -> {}".format(
                user_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def update_user_photo(
        self,
        user_id: str,
        photo_path: str,
        mime_type: str = "image/jpeg",
    ) -> dict | None:
        """Update the Core Share user photo.

        Args:
            user_id (str):
                The Core Share user ID.
            photo_path (str):
                The file system path with the location of the photo.
            mime_type (str, optional):
                The mime type of the photo. Default is "image/jpeg".

        Returns:
            dict | None:
                Dictionary with the Core Share User data or None if the request fails.

        """

        if not self._access_token_user:
            self.authenticate_user()

        # Check if the photo file exists
        if not os.path.isfile(photo_path):
            self.logger.error("Photo file -> '%s' not found for Core Share user with ID -> %s!", photo_path, user_id)
            return None

        try:
            # Read the photo file as binary data
            with open(photo_path, "rb") as image_file:
                photo_data = image_file.read()
        except OSError:
            # Handle any errors that occurred while reading the photo file
            self.logger.error(
                "Error reading photo file -> '%s' for Core Share user with ID -> '%s'!", photo_path, user_id
            )
            return None

        request_url = self.config()["usersUrlv3"] + "/{}".format(user_id) + "/photo"
        files = {
            "file": (photo_path, photo_data, mime_type),
        }

        self.logger.debug(
            "Update profile photo of Core Share user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=self.request_header_user(content_type=""),
            files=files,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update profile photo of Core Share user with ID -> '{}'".format(
                user_id,
            ),
            user_credentials=True,
            verify=False,
        )

    # end method definition

    def get_folders(self, parent_id: str) -> list | None:
        """Get Core Share folders under a given parent ID.

        This runs under user credentials (not admin!)

        Args:
            parent_id (str):
                ID of the parent folder or the root ID of a user

        Returns:
            list | None:
                List with the Core Share folders data or None if the request fails.

            Example response (it is a list!):
            [
                {
                    'id': '2599466250228733940',
                    'name': 'Global Trade AG (50031)',
                    'size': 0,
                    'created': '2024-05-09T13:55:24.899Z',
                    'lastModified': '2024-05-09T13:55:33.069Z',
                    'shareCount': 2,
                    'isShared': True,
                    'parentId': '2599466244163770353',
                    'uri': '/api/v1/folders/2599466250228733940',
                    'commentCount': 0,
                    'isDeleted': False,
                    'isLiked': False,
                    'likesCount': 0,
                    'locks': [],
                    'createdBy': {
                        'id': '2597156105373095597',
                        'email': '6ccf1cb3-177e-4930-8baf-2d421cf92a5f',
                        'uri': '/api/v1/users/2597156105373095597',
                        'tenantId': '2595192600759637225',
                        'tier': 'tier3',
                        'title': '',
                        'company': '',
                        'lastName': '',
                        'firstName': 'OpenText Service User',
                        'displayName': 'OpenText Service User',
                        'type': 'user',
                        'imageUri': 'https://core.opentext.com/img/app/profile-default-lrg.png',
                        'thumbnailUri': 'https://core.opentext.com/img/app/topbar-profile-default-sm.png',
                        'defaultImageUri': True,
                        'isConfirmed': True,
                        'isEnabled': True
                    },
                    'lastModifiedBy': {...},
                    'owner': {...},
                    'permission': 1,
                    'hasAttachments': False,
                    'resourceType': 'folder',
                    'tagCount': 0,
                    'resourceSubType': {},
                    'contentOriginId': '0D949C67-473D-448C-8F4B-B2CCA769F586',
                    'externalData': None,
                    'childCount': 7,
                    'contentOriginator': {
                        'id': '0D949C67-473D-448C-8F4B-B2CCA769F586',
                        'name': 'IDEA-TE-QA',
                        'imageUri': '/api/v1/tenants/2595192600759637225/contentOriginator/images/0D949C67'
                    }
                }
            ]

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()
        request_url = (
            self.config()["foldersUrlv1"]
            + "/{}".format(parent_id)
            + "/children"
            + "?limit=25&order=lastModified:desc&filter=any"
        )

        self.logger.debug(
            "Get Core Share folders under parent -> %s; calling -> %s",
            parent_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Core Share folders under parent -> {}".format(
                parent_id,
            ),
            user_credentials=True,
        )

    # end method definition

    def unshare_folder(self, resource_id: str) -> dict | None:
        """Unshare Core Share folder with a given resource ID.

        Args:
            resource_id (str):
                The ID of the folder (resource) to unshare with all collaborators.

        Returns:
            dict | None:
                Dictionary with the Core Share folders data or None if the request fails.

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()
        request_url = self.config()["foldersUrlv1"] + "/{}".format(resource_id) + "/collaborators"

        self.logger.debug(
            "Unshare Core Share folder -> %s; calling -> %s",
            resource_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to unshare Core Share folder with ID -> {}".format(
                resource_id,
            ),
            user_credentials=True,
        )

    # end method definition

    def delete_folder(self, resource_id: str) -> dict | None:
        """Delete Core Share folder with a given resource ID.

        Args:
            resource_id (str):
                The ID of the folder (resource) to delete.

        Returns:
            dict | None:
                Dictionary with the Core Share request data or None if the request fails.

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()
        request_url = self.config()["foldersUrlv1"] + "/{}".format(resource_id)

        payload = {"state": "deleted"}

        self.logger.debug(
            "Delete Core Share folder -> %s; calling -> %s",
            resource_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to delete Core Share folder -> {}".format(
                resource_id,
            ),
            user_credentials=True,
        )

    # end method definition

    def delete_document(self, resource_id: str) -> dict | None:
        """Delete Core Share document with a given resource ID.

        Args:
            resource_id (str):
                The ID of the document (resource) to delete.

        Returns:
            dict | None:
                Dictionary with the Core Share request data or None if the request fails.

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()
        request_url = self.config()["documentsUrlv1"] + "/{}".format(resource_id)

        payload = {"state": "deleted"}

        self.logger.debug(
            "Delete Core Share document -> %s; calling -> %s",
            resource_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to delete Core Share document -> {}".format(
                resource_id,
            ),
            user_credentials=True,
        )

    # end method definition

    def leave_share(self, user_id: str, resource_id: str) -> dict | None:
        """Remove a Core Share user from a share (i.e. the user leaves the share).

        Args:
            user_id (str):
                The Core Share user ID.
            resource_id (str):
                The Core Share ID of the shared folder.

        Returns:
            dict | None:
                Reponse of the REST call or None in case of an error.

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()

        request_url = self.config()["foldersUrlv1"] + "/{}".format(resource_id) + "/collaborators/" + str(user_id)

        payload = {"action": "LEAVE_SHARE"}

        self.logger.debug(
            "User with ID -> %s leaves Core Share shared folder with ID -> %s; calling -> %s",
            user_id,
            resource_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
            failure_message="User with ID -> {} failed to leave Core Share folder with ID -> {}".format(
                user_id,
                resource_id,
            ),
            user_credentials=True,
        )

    # end method definition

    def stop_share(self, user_id: str, resource_id: str) -> dict | None:
        """Stop of share of a user.

        Args:
            user_id (str):
                The Core Share user ID.
            resource_id (str):
                The Core Share ID of the shared folder.

        Returns:
            dict | None:
                Response of the REST call or None in case of an error.

        """

        if not self._access_token_user:
            self.authenticate_user()

        request_header = self.request_header_user()

        request_url = self.config()["foldersUrlv1"] + "/{}".format(resource_id) + "/collaborators"

        self.logger.debug(
            "User -> %s stops sharing Core Share shared folder -> %s; calling -> %s",
            user_id,
            resource_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="User with ID -> {} failed to stop sharing Core Share folder with ID -> {}".format(
                user_id,
                resource_id,
            ),
            user_credentials=True,
        )

    # end method definition

    def cleanup_user_files(
        self,
        user_id: str,
        user_login: str,
        user_password: str,
    ) -> bool:
        """Cleanup files of a user.

        This handles different types of resources.
           * Local resources - not shared
           * Resources shared by the user
           * Resources shared by other users or groups
           This method inpersonate as the user. Only the user can delete its folders.
           The Core Share admin is not entitled to do this.

        Args:
            user_id (str):
                The Core Share user ID.
            user_login (str):
                The Core Share email (= login) of the user.
            user_password (str):
                The Core Share password of the user.

        Returns:
            bool:
                True = success, False in case of an error.

        """

        user = self.get_user_by_id(user_id=user_id)
        user_id = self.get_result_value(user, "id")
        user_root_folder_id = self.get_result_value(user, "rootId")

        is_confirmed = self.get_result_value(response=user, key="isConfirmed")
        if not is_confirmed:
            self.logger.info(
                "User -> %s (%s) is not yet confirmed - so it cannot have files to cleanup.",
                user_login,
                user_id,
            )
            return True

        self.logger.info("Inpersonate as user -> %s to cleanup files...", user_login)

        # Save admin credentials the class has been initialized with:
        admin_credentials = self.credentials()

        # Change the credentials to the user owning the file - admin
        # is not allowed to see user files!
        self.set_credentials(username=user_login, password=user_password)

        # Authenticate as given user:
        self.authenticate_user(revalidate=True)

        success = True

        # Get all folders of the user:
        response = self.get_folders(parent_id=user_root_folder_id)
        if not response or not response["results"]:
            self.logger.info("User -> %s (%s) has no items to cleanup!", user_login, user_id)
        else:
            items = response["results"]
            for item in items:
                if item["isShared"]:
                    if item["owner"]["id"] == user_id:
                        self.logger.info(
                            "User -> %s (%s) stops sharing item -> %s (%s)...",
                            user_login,
                            user_id,
                            item["name"],
                            item["id"],
                        )
                        response = self.stop_share(
                            user_id=user_id,
                            resource_id=item["id"],
                        )
                        if not response:
                            success = False
                        self.logger.info(
                            "User -> %s deletes unshared item -> %s (%s)...",
                            user_id,
                            item["name"],
                            item["id"],
                        )
                        response = self.delete_folder(item["id"])
                        if not response:
                            success = False
                    else:
                        self.logger.info(
                            "User -> %s leaves shared folder -> '%s' (%s)...",
                            user_id,
                            item["name"],
                            item["id"],
                        )
                        response = self.leave_share(
                            user_id=user_id,
                            resource_id=item["id"],
                        )
                        if not response:
                            success = False
                else:
                    self.logger.info(
                        "User -> %s deletes local item -> '%s' (%s) of type -> '%s'...",
                        user_id,
                        item["name"],
                        item["id"],
                        item["resourceType"],
                    )
                    if item["resourceType"] == "folder":
                        response = self.delete_folder(item["id"])
                    elif item["resourceType"] == "document":
                        response = self.delete_document(item["id"])
                    else:
                        self.logger.error(
                            "Unsupport resource type -> '%s'!",
                            item["resourceType"],
                        )
                        response = None
                    if not response:
                        success = False

        self.logger.info(
            "End inpersonation and switch back to admin account -> %s...",
            admin_credentials["username"],
        )

        # Reset credentials to admin:
        self.set_credentials(
            admin_credentials["username"],
            admin_credentials["password"],
        )
        # Authenticate as administrator the class has been initialized with:
        self.authenticate_user(revalidate=True)

        return success

    # end method definition

    def get_group_shares(self, group_id: str) -> dict | None:
        """Get (incoming) shares of a Core Share group.

        Args:
            group_id (str):
                The Core Share group ID.

        Returns:
            dict | None:
                Incoming shares or None if the request fails.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()

        request_url = self.config()["groupsUrl"] + "/{}".format(group_id) + "/shares/incoming"

        self.logger.debug(
            "Get shares of Core Share group -> %s; calling -> %s",
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get shares of Core Share group -> {}".format(
                group_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def revoke_group_share(self, group_id: str, resource_id: str) -> dict | None:
        """Revoke sharing of a folder with a group.

        Args:
            group_id (str):
                The Core Share group ID.
            resource_id (str):
                The ID of the Core share folder.

        Returns:
            dict | None:
                Response or None if the request fails.

        """

        if not self._access_token_admin:
            self.authenticate_admin()

        request_header = self.request_header_admin()

        request_url = (
            self.config()["foldersUrlv1"] + "/{}".format(resource_id) + "/collaboratorsAsAdmin/" + str(group_id)
        )

        self.logger.debug(
            "Revoke sharing of folder with ID -> '%s' with group with ID -> '%s'; calling -> %s",
            resource_id,
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to revoke sharing Core Share folder with ID -> '{}' with group with ID -> '{}'!".format(
                resource_id,
                group_id,
            ),
            user_credentials=False,
        )

    # end method definition

    def cleanup_group_shares(self, group_id: str) -> bool:
        """Cleanup all incoming shares of a group.

        The Core Share admin is required to do this.

        Args:
            group_id (str):
                The Core Share group ID.

        Returns:
            bool:
                True = success, False in case of an error.

        """

        response = self.get_group_shares(group_id=group_id)

        if not response or not response["shares"]:
            self.logger.info("Group -> %s has no shares to revoke.", group_id)
            return True

        success = True

        items = response["shares"]
        for item in items:
            self.logger.info(
                "Revoke sharing of folder -> '%s' (%s) with group -> %s...",
                item["name"],
                item["id"],
                group_id,
            )
            response = self.revoke_group_share(
                group_id=group_id,
                resource_id=item["id"],
            )
            if not response:
                success = False

        return success

    # end method definition

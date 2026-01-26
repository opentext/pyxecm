"""OTDS Module to implement functions to read / write OTDS objects.

This includes Ressources, Users, Groups, Licenses, Trusted Sites, OAuth Clients, ...

The documentation for the used REST APIs can be found here:
    - [https://developer.opentext.com](https://developer.opentext.com/ce/products/opentext-directory-services)


!!! tip
    Important: userIDs consists of login name + "@" + partition name
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import base64
import json
import logging
import os
import platform
import sys
import tempfile
import time
import urllib.parse
from http import HTTPStatus
from importlib.metadata import version

import requests

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otds"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/json",
}

REQUEST_FORM_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_TIMEOUT = 60.0
REQUEST_RETRY_DELAY = 20.0
REQUEST_MAX_RETRIES = 2

default_logger = logging.getLogger(MODULE_NAME)


class OTDS:
    """Class OTDS is used to automate stettings in OpenText Directory Services (OTDS)."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        otds_ticket: str | None = None,
        oauth_token: str | None = None,
        bind_password: str | None = None,
        admin_partition: str = "otds.admin",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the OTDS object.

        Args:
            protocol (str):
                This is either http or https.
            hostname (str):
                The hostname of OTDS.
            port (int):
                The port number - typically 80 or 443.
            username (str, optional):
                The OTDS user name. Optional if otds_ticket is provided.
            password (str, optional):
                The OTDS password. Optional if otds_ticket is provided.
            client_id (str | None, optional):
                Client ID for grant type authentication.
            client_secret (str | None, optional):
                Client secret for grant type authentication.
            otds_ticket (str | None, optional):
                Pre-known authentication ticket of OTDS.
            oauth_token (str | None, optional):
                Pre-known OAuth token for OTDS.
            bind_password (str | None, optional): TODO
            admin_partition (str, optional):
                Name of the admin partition. Default is "otds.admin".
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otds")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        # Initialize otdsConfig as an empty dictionary
        otds_config = {}

        otds_config["hostname"] = hostname or "otds"
        otds_config["protocol"] = protocol or "http"
        otds_config["port"] = port or 80
        otds_config["username"] = username or "admin"
        otds_config["password"] = password or ""
        otds_config["clientId"] = client_id or ""
        otds_config["clientSecret"] = client_secret or ""
        otds_config["bindPassword"] = bind_password or ""
        otds_config["adminPartition"] = admin_partition

        # If a pre-existing OTDS ticket is provided we use it:
        self._otds_ticket = otds_ticket
        if otds_ticket:
            self._cookie = {"OTDSTicket": otds_ticket}
        else:
            self._cookie = None
        # If a pre-existing OAuth token is provided we use it:
        if oauth_token:
            self._token = oauth_token
        else:
            self._token = None

        otds_base_url = protocol + "://" + otds_config["hostname"]
        if str(port) not in ["80", "443"]:
            otds_base_url += ":{}".format(port)
        otds_base_url += "/otdsws"
        otds_config["baseUrl"] = otds_base_url

        otds_rest_url = otds_base_url + "/rest"
        otds_config["restUrl"] = otds_rest_url

        otds_config["partitionUrl"] = otds_rest_url + "/partitions"
        otds_config["identityproviderprofiles"] = otds_rest_url + "/identityproviderprofiles"
        otds_config["accessRoleUrl"] = otds_rest_url + "/accessroles"
        otds_config["credentialUrl"] = otds_rest_url + "/authentication/credentials"
        otds_config["tokenUrl"] = otds_rest_url + "/authentication/token"
        otds_config["tokenInfoUrl"] = otds_rest_url + "/authentication/oauth/tokeninfo"
        otds_config["ticketforuserUrl"] = otds_rest_url + "/authentication/ticketforuser"
        otds_config["oauthClientUrl"] = otds_rest_url + "/oauthclients"
        otds_config["oauthTokenUrl"] = otds_base_url + "/oauth2/token"
        otds_config["resourceUrl"] = otds_rest_url + "/resources"
        otds_config["licenseUrl"] = otds_rest_url + "/licensemanagement/licenses"
        otds_config["usersUrl"] = otds_rest_url + "/users"
        otds_config["currentUserUrl"] = otds_rest_url + "/currentuser"
        otds_config["groupsUrl"] = otds_rest_url + "/groups"
        otds_config["systemConfigUrl"] = otds_rest_url + "/systemconfig"
        otds_config["authHandlerUrl"] = otds_rest_url + "/authhandlers"
        otds_config["consolidationUrl"] = otds_rest_url + "/consolidation"
        otds_config["rolesUrl"] = otds_rest_url + "/roles"

        self._config = otds_config

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict:
                The configuration dictionary.

        """
        return self._config

    # end method definition

    def cookie(self) -> dict:
        """Return the login cookie of OTDS.

        This is set by the authenticate() method

        Returns:
            dict:
                The OTDS cookie.

        """
        return self._cookie

    # end method definition

    def set_cookie(self, ticket: str) -> dict:
        """Return the login cookie of OTDS.

        This is set by the authenticate() method

        Args:
            ticket (str):
                The new ticket value for the cookie.

        Returns:
            dict:
                The updated OTDS cookie.

        """

        self._cookie["OTDSTicket"] = ticket

        return self._cookie

    # end method definition

    def get_access_token(self) -> str | None:
        """Get the access token for OAuth2 authentication.

        Returns:
            str | None:
                The access token, or None in case of an error.

        """

        return self._token

    # end method definition

    def set_access_token(self, token: str) -> str | None:
        """Get the access token for OAuth2 authentication.

        Args:
            token (str):
                The new token value.

        Returns:
            str | None:
                The access token, or None in case of an error.

        """

        self._token = token

        return self._token

    # end method definition

    def get_access_token_info(self, resource_id: str | None = None) -> str | None:
        """Get the access token information for OAuth2 authentication.

        Returns:
            str | None:
                The access token, or None in case of an error.

        """

        request_url = self.config()["tokenInfoUrl"]

        token_info_body = {"token": self._token}
        if resource_id:
            token_info_body["resourceId"] = resource_id

        self.logger.debug(
            "Get OAuth token info%s; calling -> %s",
            " for resource -> '{}'".format(resource_id) if resource_id else "",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=token_info_body,
            timeout=None,
            failure_message="Failed to get OAuth token info{}".format(
                " for resource -> '{}'".format(resource_id) if resource_id else ""
            ),
        )

    # end method definition

    def credentials(self) -> dict:
        """Return the credentials (username + password).

        Returns:
            dict:
                The dictionary with username and password.

        """

        return {
            "userName": self.config()["username"],
            "password": self.config()["password"],
        }

    # end method definition

    def client_credentials(
        self, grant_type: str = "client_credentials", scope: str | None = None, **kwargs: dict[str, str]
    ) -> dict:
        """Return the client credentials (client_id + client_secret).

        Args:
            grant_type (str, optional):
                The grant type for the client credentials. Optional.
                Defaults to "client_credentials".
            scope (str | None, optional):
                The scope for the client credentials. Optional.
                Use "otdsssoticket" to get a standard / legacy OTDS ticket.
            **kwargs:
                Additional keyword arguments to add to the credentials dictionary.

        Returns:
            dict:
                The dictionary with client_id and client_secret.

        """

        cred = {
            "grant_type": grant_type,
            "client_id": self.config()["clientId"],
            "client_secret": self.config()["clientSecret"],
        }

        if scope:
            cred["scope"] = scope

        cred.update(dict(kwargs))

        return cred

    # end method definition

    def base_url(self) -> str:
        """Return the base URL of OTDS.

        Returns:
            str:
                The base URL.

        """

        return self.config()["baseUrl"]

    # end method definition

    def rest_url(self) -> str:
        """Return the REST URL of OTDS.

        Returns:
            str:
                The REST URL.

        """

        return self.config()["restUrl"]

    # end method definition

    def credential_url(self) -> str:
        """Return the Credentials URL of OTDS.

        Returns:
            str:
                The credentials URL.

        """

        return self.config()["credentialUrl"]

    # end method definition

    def auth_handler_url(self) -> str:
        """Return the Auth Handler URL of OTDS.

        Returns:
            str:
                The auth handler URL.

        """

        return self.config()["authHandlerUrl"]

    # end method definition
    def synchronized_partition_url(self) -> str:
        """Return the Partition URL of OTDS.

        Returns:
            str:
                The synchronized partition URL.

        """

        return self.config()["identityproviderprofiles"]

    # end of method definition

    def partition_url(self) -> str:
        """Return the partition URL of OTDS.

        Returns:
            str:
                The partition URL.

        """

        return self.config()["partitionUrl"]

    # end method definition

    def access_role_url(self) -> str:
        """Return the access role URL of OTDS.

        Returns:
            str:
                The access role URL.

        """

        return self.config()["accessRoleUrl"]

    # end method definition

    def oauth_client_url(self) -> str:
        """Return the OAuth client URL of OTDS.

        Returns:
            str:
                The OAuth client URL.

        """

        return self.config()["oauthClientUrl"]

    # end method definition

    def resource_url(self) -> str:
        """Return the resource URL of OTDS.

        Returns:
            str:
                The resource URL.

        """

        return self.config()["resourceUrl"]

    # end method definition

    def license_url(self) -> str:
        """Return the License URL of OTDS.

        Returns:
            str:
                The license URL.

        """

        return self.config()["licenseUrl"]

    # end method definition

    def token_url(self) -> str:
        """Return the token URL of OTDS.

        Returns:
            str:
                The token URL.

        """

        return self.config()["oauthTokenUrl"]

    # end method definition

    def users_url(self) -> str:
        """Return the users URL of OTDS.

        Returns:
            str:
                The users URL.

        """

        return self.config()["usersUrl"]

    # end method definition

    def current_user_url(self) -> str:
        """Return the current user URL of OTDS.

        Returns:
            str:
                The current user URL.

        """

        return self.config()["currentUserUrl"]

    # end method definition

    def groups_url(self) -> str:
        """Return the groups URL of OTDS.

        Returns:
            str:
                The groups URL.

        """

        return self.config()["groupsUrl"]

    # end method definition

    def system_config_url(self) -> str:
        """Return the system config URL of OTDS.

        Returns:
            str:
                The system config URL.

        """

        return self.config()["systemConfigUrl"]

    # end method definition

    def consolidation_url(self) -> str:
        """Return the consolidation URL of OTDS.

        Returns:
            str:
                The consolidation URL.

        """

        return self.config()["consolidationUrl"]

    # end method definition

    def admin_partition_name(self) -> str:
        """Return OTDS admin partition name.

        Returns:
            str:
                The OTDS admin partition name.

        """

        return self.config()["adminPartition"]

    # end method definition

    def request_header(self, content_type: str = "application/json") -> dict:
        """Return the request header used for requests.

        Consists of Bearer access token and Content Type

        Args:
            service_type (str, optional):
                Service type for which the header should be returned.
                Either "chat" or "embed". "chat" is the default.

            content_type (str, optional):
                Custom content type for the request.
                Typical values:
                * application/json - Used for sending JSON-encoded data
                * application/x-www-form-urlencoded - The default for HTML forms.
                  Data is sent as key-value pairs in the body of the request, similar to query parameters.
                * multipart/form-data - Used for file uploads or when a form includes non-ASCII characters

        Returns:
            dict: The request header values.

        """

        request_header = REQUEST_HEADERS

        if content_type:
            request_header["Content-Type"] = content_type

        if self._token is not None:
            request_header["Authorization"] = "Bearer {}".format(self._token)

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
    ) -> dict | None:
        """Call an OTDS REST API in a safe way.

        Args:
            url (str):
                The URL to send the request to.
            method (str, optional):
                The HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                The request headers. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                File-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (float | None, optional):
                The timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
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
                Defines if the response.text should be interpreted as json and loaded into a dictionary.
                True is the default.

        Returns:
            dict | None:
                Response of OTDS REST API or None in case of an error.

        """

        if headers is None:
            headers = self.request_header()

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
                    cookies=self.cookie(),
                    timeout=timeout,
                )

                # Attempt to parse JSON safely:
                try:
                    response_json = response.json()
                except ValueError:
                    response_json = {}

                # Check for expired OTDS ticket. This typically gives an error like this:
                # status -> 400/Bad Request; error -> {"status":1034,"error":"Expired OTDS SSO ticket","errorDetails":null}
                expired_token = response_json.get("error") == "Expired OTDS SSO ticket"

                if response.ok:
                    if success_message:
                        self.logger.info(success_message)
                    return self.parse_request_response(response) if parse_request_response else response
                # Check if Session has expired - then re-authenticate and try once more
                elif retries == 0 and (response.status_code == 401 or (response.status_code == 400 and expired_token)):
                    self.logger.info("Session expired. Re-authenticating and retrying...")
                    self.authenticate(revalidate=True)
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    response_text = (
                        "HTML content (only printed in debug log)" if content_type == "text/html" else response.text
                    )

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
                        "%s; timeout error.",
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
                        "Connection error (%s)! Retrying in %d seconds... %d/%d",
                        url,
                        REQUEST_RETRY_DELAY,
                        retries,
                        max_retries,
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    self.logger.error(
                        "%s; connection error.",
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
            self.logger.info(
                "Retrying REST API %s call -> %s... (retry = %s, cookie -> %s)",
                method,
                url,
                str(retries),
                str(self.cookie()),
            )
        # end while True

    # end method definition

    def parse_request_response(
        self,
        response_object: object,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Convert the request response to a dict in a safe way that also handles exceptions.

        Args:
            response_object (object):
                This is reponse object delivered by the request call.
            additional_error_message (str, optional):
                Print a custom error message.
            show_error (bool, optional):
                If True, log an error, if False log a warning.

        Returns:
            dict | None:
                Response dictionary or None in case of an error.

        """

        if not response_object:
            return None

        if not response_object.text:
            self.logger.warning("Response text is empty. Cannot decode response.")
            return None

        try:
            dict_object = json.loads(response_object.text)
        except json.JSONDecodeError as e:
            if additional_error_message:
                message = "Cannot decode response as JSon. {}; error -> {}".format(
                    additional_error_message,
                    e,
                )
            else:
                message = "Cannot decode response as JSon; error -> {}".format(e)
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            return None
        else:
            return dict_object

    # end method definition

    def authenticate(
        self, revalidate: bool = False, grant_type: str | None = None, show_error: bool = True
    ) -> dict | None:
        """Authenticate at Directory Services and retrieve OTDS ticket.

        Args:
            revalidate (bool, optional):
                Determine if a re-athentication is enforced.
                (e.g. if session has timed out with 401 error)
            grant_type (str | None, optional):
                The grant type to use for authentication.
                Possible values are "password", "client_credentials", or None. Defaults to None.
                If None is given, the method tries to determine the grant type automatically:
                * If username and password are given, "password" is used.
                * If client_id and client_secret are given, "client_credentials" is used.
                * If both are given, "password" is used.
                * If none of the above is given, an error is logged and None is returned.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed authentication.
                If False, then only a warning is logged. Defaults to True.

        Returns:
            dict | None:
                Cookie information. Also stores cookie information in self._cookie

        """

        # Already authenticated and session still valid?
        if self._cookie and not revalidate:
            self.logger.debug(
                "Session still valid - return existing cookie -> %s",
                str(self._cookie),
            )
            return self._cookie

        otds_ticket = "NotSet"

        self.logger.debug(
            "Requesting OTDS ticket from -> %s using grant type -> '%s'...", self.credential_url(), grant_type
        )

        response = None

        if not grant_type:
            if self.config()["username"] and self.config()["password"]:
                grant_type = "password"
            elif self.config()["clientId"] and self.config()["clientSecret"]:
                grant_type = "client_credentials"
            else:
                self.logger.error(
                    "Cannot determine grant type automatically - please provide username/password or client_id/client_secret for authentication."
                )
                return None

        try:
            if grant_type == "client_credentials":
                request_url = self.token_url()
                headers = REQUEST_FORM_HEADERS
                data = self.client_credentials()
                json_data = None
                result_value = "access_token"
            elif grant_type == "password":
                request_url = self.credential_url()
                headers = REQUEST_HEADERS
                data = None
                json_data = self.credentials()
                result_value = "ticket"
            else:
                self.logger.error("Unsupported grant type -> '%s' - exit", grant_type)
                return None
            response = requests.post(
                url=request_url,
                headers=headers,
                data=data,
                json=json_data,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exception:
            self.logger.warning(
                "Unable to connect to OTDS authentication endpoint -> %s%s. OTDS service may not be ready yet.",
                self.credential_url(),
                "; error -> {}".format(str(exception)) if str(exception) else "",
            )
            return None

        if response.ok:
            authenticate_dict = self.parse_request_response(response)
            if not authenticate_dict:
                return None
            else:
                otds_ticket = authenticate_dict[result_value]
                self.logger.debug("Ticket / token -> %s", otds_ticket)
        else:
            if show_error:
                self.logger.error(
                    "Failed to request an OTDS ticket / access token; error -> %s",
                    response.text,
                )
            else:
                self.logger.warning(
                    "Failed to request an OTDS ticket / access token; warning -> %s",
                    response.text,
                )
            return None

        # Store authentication ticket:
        self._otds_ticket = otds_ticket
        if grant_type == "password":
            self._cookie = {"OTDSTicket": otds_ticket}
            self._token = None
            return self._cookie
        elif grant_type == "client_credentials":
            self._token = otds_ticket
            self._cookie = None
            return self._token

        return None

    # end method definition

    def impersonate_user(
        self,
        user_id: str,
        partition: str = "Content Server Members",
        ticket: str = "",
    ) -> dict | None:
        """Impersonate as a user.

        Args:
            partition (str):
                The partition of the user.
            user_id (str):
                The ID (= login) of the user.
            ticket (str, optional):
                Optional, if the ticket to impersonate with is already known.
                Defaults to "".

        Returns:
            dict | None:
                Information about the impersonated user.

        Example ticket based response:
        {
            'token': None,
            'userId': 'nwheeler@Content Server Members',
            'ticket': '*OTDSSSO*Adh...*',
            'resourceID': None,
            'failureReason': None,
            'passwordExpirationTime': 0,
            'continuation': False,
            'continuationContext': None,
            'continuationData': None
        }
        Example token based response:
        {
            'access_token': 'eyJraWQiOiJ...',
            'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'token_type': 'Bearer',
            'expires_in': 3600
        }

        """

        # Check if we have a token-based authentication:
        if self._token is not None:
            request_url = self.token_url()

            impersonate_post_body = self.client_credentials(
                scope=None,
                grant_type="urn:ietf:params:oauth:grant-type:token-exchange",
                subject_token_type="urn:opentext.com:oauth:string:user_id",
                subject_token=user_id + "@" + partition,
            )

            self.logger.debug(
                "Impersonate user -> '%s' with token -> '%s'; calling -> %s",
                user_id,
                self._token,
                request_url,
            )

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=REQUEST_FORM_HEADERS,
                data=impersonate_post_body,
                timeout=None,
                failure_message="Failed to impersonate as user -> '{}' with OTDS token".format(user_id),
            )
        else:  # ticket-based authentication
            if not ticket:
                ticket = self._otds_ticket

            request_url = self.config()["ticketforuserUrl"]

            impersonate_post_body = {
                "userName": user_id + "@" + partition,
                "ticket": ticket,
            }

            self.logger.debug(
                "Impersonate user -> '%s' with ticket -> '%s'; calling -> %s",
                user_id,
                ticket,
                request_url,
            )

            response = self.do_request(
                url=request_url,
                method="POST",
                json_data=impersonate_post_body,
                timeout=None,
                failure_message="Failed to impersonate as user -> '{}' with OTDS ticket".format(user_id),
            )

        return response

    # end method definition

    def add_application_role(
        self,
        name: str,
        partition_id: str = "OAuthClients",
        description: str = "",
        values: list | None = None,
        custom_attributes: list | None = None,
    ) -> dict | None:
        """Add a new application role to partition.

        Args:
            name (str):
                The name of the new partition.
            partition_id (str, optional):
                ID of the partition to add the role to, defaults to "OAuthClients".
            description (str):
                The description of the new partition.
            values (list, optional):
                List of optional values to pass with the create request.
            custom_attributes (list, optional):
                List of optional custom attributes to pass with the create request.

        Returns:
            dict | None:
                Request response or None if the creation fails.

        """

        if values is None:
            values = []
        role_post_body_json = {
            "name": name,
            "description": description,
            "userPartitionID": partition_id,
            "values": values if values else [],
            "customAttributes": custom_attributes if custom_attributes else [],
        }

        request_url = self.config()["rolesUrl"]

        self.logger.debug(
            "Adding application role -> '%s' (%s) to partition -> '%s' ; calling -> %s",
            name,
            description,
            partition_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=role_post_body_json,
            timeout=None,
            failure_message="Failed to add application role -> '{}'".format(name),
        )

    # end method definition

    def get_application_role(self, name: str, partition: str = "OAuthClients", show_error: bool = True) -> dict | None:
        """Get an existing application role from OTDS.

        Args:
            name (str):
                The name of the application role to retrieve.
            partition (str):
                Partition of the application role.
            show_error (bool, optional):
                Defines whether or not we want to log an error
                if the partition is not found.

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        request_url = "{}?where_filter={}".format(self.config()["rolesUrl"], name)

        self.logger.debug(
            "Get application role -> '%s' in partition -> '%s'; calling -> %s",
            name,
            partition,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get application role -> '{}' in partition -> '{}'".format(name, partition),
            show_error=show_error,
        )

        role = next(
            (role for role in response.get("roles") if role["name"] == name and role["userPartitionID"] == partition),
            None,
        )

        return role

    # end method definition

    def assign_user_to_application_role(
        self,
        user_id: str,
        user_partition: str,
        role_name: str,
        role_partition: str = "OAuthClients",
    ) -> bool:
        """Assign an OTDS user to an application role in OTDS.

        Args:
            user_id (str):
                The ID of the user (= login name) to assign to the license.
            user_partition (str):
                The user partition in OTDS, e.g. "Content Server Members".
            role_name (str):
                Name of the application role to be assigned.
            role_partition (str):
                The name of the partition of the Role, defaults to "OAuthClients".

        Returns:
            bool:
                True if successful or False if the REST call fails or the license is not found.

        """

        user = self.get_user(user_partition, user_id)
        if user:
            user_location = user["location"]
        else:
            self.logger.error(
                "Cannot find user -> '%s' in partition -> '%s'! Cannot assign user to application role -> '%s'.",
                user_id,
                user_partition,
                role_name,
            )
            return False

        role = self.get_application_role(name=role_name, partition=role_partition)
        if role:
            role_location = role.get("location")
        else:
            self.logger.warning("Cannot find application role -> '%s' in partition -> '%s'!", role_name, role_partition)
            return False

        role_post_body_json = {
            "stringList": [
                role_location,
            ],
        }

        request_url = self.users_url() + "/" + user_location + "/roles"

        self.logger.debug(
            "Assign user -> '%s' (%s) to application role -> '%s' (%s); calling -> %s",
            user_id,
            user_partition,
            role_name,
            role_partition,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=role_post_body_json,
            timeout=None,
            failure_message="Failed to assign user -> '{}' to application role -> '{}'!".format(
                user_id,
                role_name,
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            self.logger.debug(
                "Added user -> '%s' to application role -> '%s'.",
                user_id,
                role_name,
            )
            return True

        return False

    # end method definition

    def assign_group_to_application_role(
        self,
        group_id: str,
        group_partition: str,
        role_name: str,
        role_partition: str = "OAuthClients",
    ) -> bool:
        """Assign an OTDS group to an application role in OTDS.

        Args:
            group_id (str):
                The ID of the group to assign to the application role.
            group_partition (str):
                The group partition in OTDS, e.g. "Content Server Members".
            role_name (str):
                Name of the application role to be assigned.
            role_partition (str):
                The name of the partition of the Role, defaults to "OAuthClients".

        Returns:
            bool:
                True if successful or False if the REST call fails or the license is not found.

        """

        group = self.get_group(group=group_id)
        if group:
            group_location = group["location"]
        else:
            self.logger.error(
                "Cannot find group -> '%s'! Cannot assign group to application role -> '%s'.", group_id, role_name
            )
            return False

        role = self.get_application_role(name=role_name, partition=role_partition)
        if role:
            role_location = role.get("location")
        else:
            self.logger.warning("Cannot find application role -> '%s' in partition -> '%s'!", role_name, role_partition)
            return False

        role_post_body_json = {
            "stringList": [
                role_location,
            ],
        }

        request_url = self.groups_url() + "/" + group_location + "/roles"

        self.logger.debug(
            "Assign group -> '%s' (%s) to application role -> '%s' (%s); calling -> %s",
            group_id,
            group_partition,
            role_name,
            role_partition,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=role_post_body_json,
            timeout=None,
            failure_message="Failed to assign application role -> '{}' to group -> '{}'".format(
                role_name,
                group_id,
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            self.logger.debug(
                "Added application role -> '%s' to group -> '%s'",
                role_name,
                group_id,
            )
            return True

        return False

    # end method definition

    def add_partition(self, name: str, description: str) -> dict | None:
        """Add a new user partition to OTDS.

        Args:
            name (str):
                The name of the new partition.
            description (str):
                The description of the new partition.

        Returns:
            dict | None:
                Request response or None if the creation fails.

        """

        partition_post_body_json = {"name": name, "description": description}

        request_url = self.partition_url()

        self.logger.debug(
            "Adding user partition -> '%s' (%s); calling -> %s",
            name,
            description,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=partition_post_body_json,
            timeout=None,
            failure_message="Failed to add user partition -> '{}'".format(name),
        )

    # end method definition

    def get_partition(self, name: str, show_error: bool = True) -> dict | None:
        """Get an existing user partition from OTDS.

        Args:
            name (str):
                The name of the partition to retrieve.
            show_error (bool, optional):
                Defines whether or not we want to log an error
                if the partition is not found.

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        request_url = "{}/{}".format(self.config()["partitionUrl"], name)

        self.logger.debug(
            "Get user partition -> '%s'; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get user partition -> '{}'".format(name),
            show_error=show_error,
        )

    # end method definition

    def add_user(
        self,
        partition: str,
        name: str,
        description: str = "",
        first_name: str = "",
        last_name: str = "",
        email: str = "",
    ) -> dict | None:
        """Add a new user to a user partition in OTDS.

        Args:
            partition (str):
                The name of the OTDS user partition (needs to exist).
            name (str):
                The login name of the new user.
            description (str, optional):
                The description of the new user. Default is empty string.
            first_name (str, optional):
                The optional first name of the new user.
            last_name (str, optional):
                The optional last name of the new user.
            email (str, optional):
                The email address of the new user.

        Returns:
            dict | None:
                Request response or None if the creation fails.

        """

        user_post_body_json = {
            "userPartitionID": partition,
            "values": [
                {"name": "sn", "values": [last_name]},
                {"name": "givenName", "values": [first_name]},
                {"name": "mail", "values": [email]},
            ],
            "name": name,
            "description": description,
        }

        request_url = self.users_url()

        self.logger.debug(
            "Adding user -> '%s' to partition -> '%s'; calling -> %s",
            name,
            partition,
            request_url,
        )
        self.logger.debug("User Attributes -> %s", str(user_post_body_json))

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=user_post_body_json,
            timeout=None,
            failure_message="Failed to add user -> '{}'".format(name),
        )

    # end method definition

    def get_user(self, partition: str, user_id: str) -> dict | None:
        """Get an existing user by its partition and user ID.

        Args:
            partition (str):
                The name of the partition the user is in.
            user_id (str):
                The ID of the user (= login name).

        Returns:
            dict | None:
                Request response or None if the user was not found.

        """

        request_url = self.users_url() + "/" + user_id + "@" + partition

        self.logger.debug(
            "Get user -> '%s' in partition -> '%s'; calling -> %s",
            user_id,
            partition,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get user -> '{}'".format(user_id),
        )

    # end method definition

    def get_users(
        self,
        partition: str = "",
        where_filter: str | None = None,
        where_location: str | None = None,
        where_state: str | None = None,
        limit: int | None = None,
        page_size: int | None = None,
        attributes_as_keys: bool = True,
        next_page_cookie: str | None = None,
    ) -> dict | None:
        """Get all users in a partition. Additional filters can be applied.

        Args:
            partition (str, optional):
                The name of the partition.
            where_filter (str | None, optional):
                Filter returned users. This is a string filter.
                If None, no filtering applies.
            where_location (str | None, optional):
                Filter based on the DN of the Organizational Unit.
            where_state (str | None, optional):
                Filter returned users by their state. Possible values are 'enabled' and 'disabled'.
                If None, no filtering based on state applies.
            limit (int, optional):
                The maximum number of users to return. None = unlimited.
            page_size (int, optional):
                The chunk size for the number of users returned by one
                REST API call. If None, then a default of 250 is used.
            attributes_as_keys (bool, optional):
                If True, it creates a much simpler to parse result structure
                per user that includes the user attributes in a "attributes"
                dictionary where the keys are the attribute names and the
                values the attribute values.
                'attributes': {
                    'schemaType' = ['3']
                    'cn' = ['psopentext.com']
                    ...
                }
                If False a "values" list with "name" and "values" elements is created:
                'values': [
                        {
                            'name': 'schemaType',
                            'values': ['3']
                        },
                        {
                            'name': 'cn',
                            'values': ['xyz@opentext.com']
                        },
                        ...
                ]
                Default is True (= attributes as keys).
            next_page_cookie (str, optional):
                A key returned by a former call to this method in with
                a return key 'nextPageCookie' (see example below). This
                can be used to get the next page of result items.

        Returns:
            dict | None:
                Request response or None if the user was not found.

        Example:
        {
            'actualPageSize': 21,
            'users': [
                {
                    'userPartitionID': 'Content Server Members',
                    'name': 'ps@opentext.com',
                    'location': 'oTPerson=04f2d12b-b7aa-4797-b4eb-1b6e6bd5ce2e,orgunit=users,partition=Content Server Members,dc=identity,dc=opentext,dc=net',
                    'id': 'ps@opentext.com',
                    'attributes': {
                        'oTExternalID3': ['ps@opentext.com'],
                        'entryUUID': ['04f2d12b-b7aa-4797-b4eb-1b6e6bd5ce2e'],
                        'oTExternalID4': ['Content Server Membersps@opentext.com'],
                        'mail': ['ps@opentext.com'],
                        'displayName': ['Paul Smith'],
                        'oTMemberOf': ['oTGroup=6381fcfe-7b30-4bbb-b849-2cbd8f3a0a48,dc=identity,dc=opentext,dc=net'],
                        'description': ['test description'],
                        'title': ['Lead Systems Analyst'],
                        'oTExternalID1': ['ps@opentext.com'],
                        'modifyTimestamp': ['2025-01-24T10:19:22Z'],
                        'oTExternalID2': ['ps@opentext.com@Content Server Members'],
                        'createTimestamp': ['2025-01-24T10:18:53Z'],
                        'passwordChangedTime': ['2025-01-24T10:18:53Z'],
                        'UserMustChangePasswordAtNextSignIn': ['false'],
                        'sn': ['Smith'],
                        'entryDN': ['oTPerson=04f2d12b-b7aa-4797-b4eb-1b6e6bd5ce2e,orgunit=users,partition=Content Server Members,dc=identity,dc=opentext,dc=net'],
                        'oTObjectGUID': ['BPLRK7eqR5e06xtua9XOLg=='],
                        'UserCannotChangePassword': ['true'],
                        'oTLastLoginTimestamp': ['2025-01-24T10:19:21Z'],
                        'oTSource': ['cs'],
                        'PasswordNeverExpires': ['true'],
                        'givenName': ['Paul'],
                        'cn': ['ps@opentext.com'],
                        'pwdReset': ['true'],
                        'oTObjectIDInResource': ['3b461d9f-ed1d-4be3-859a-316d8eb35aa5:6650'],
                        'accountLockedOut': ['false'],
                        'schemaType': ['3'],
                        'accountDisabled': ['false']
                    }
                    'values': [], # empty because this example is with attrAsKeys = True
                    'customAttributes': None,
                    'objectClass': 'oTPerson',
                    'uuid': '04f2d12b-b7aa-4797-b4eb-1b6e6bd5ce2e',
                    'description': 'test description',
                    'originUUID': None,
                    'urlId': 'xyz@opentext.com',
                    'urlLocation': 'oTPerson=04f2d12b-b7aa-4797-b4eb-1b6e6bd5ce2e,orgunit=users,partition=Content Server Members,dc=identity,dc=opentext,dc=net'
                },
                ...
            ],
            'nextPageCookie': 'JIHw2CLHSoeTOmo7Ng/bPw==',
            'requestedPageSize': 250
        }

        """

        # Add query parameters (these are NOT passed via JSon body!)
        query = {}
        if partition:
            query["where_partition_name"] = partition
        if where_filter:
            query["where_filter"] = where_filter
        if where_location:
            query["where_location"] = where_location
        if where_state:
            query["where_state"] = where_state
        if limit:
            query["limit"] = limit
        if page_size:
            query["page_size"] = page_size
        if attributes_as_keys:
            query["attrsAsKeys"] = attributes_as_keys
        if next_page_cookie:
            query["next_page_cookie"] = next_page_cookie

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.users_url()
        if query:
            request_url += "?{}".format(encoded_query)

        if partition:
            self.logger.debug(
                "Get all users in partition -> '%s' (limit -> %s); calling -> %s",
                partition,
                limit,
                request_url,
            )
            failure_message = "Failed to get all users in partition -> '{}'".format(
                partition,
            )
        else:
            self.logger.debug(
                "Get all users (limit -> %s); calling -> %s",
                limit,
                request_url,
            )
            failure_message = "Failed to get all users"

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message=failure_message,
        )

    # end method definition

    def get_users_iterator(
        self,
        partition: str = "",
        where_state: str | None = None,
        where_filter: str | None = None,
        where_location: str | None = None,
        page_size: int | None = None,
    ) -> iter:
        """Get an iterator object that can be used to traverse all members for a given users partition.

        Filters such as user state, location, etc. can be applied.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of OTDS users.

        Example usage:
            users = otds_object.get_users_iterator(partition="Content Server Members", page_size=10)
            for user in users:
                logger.info("Traversing user -> %s", user["name"])

        Args:
            partition (str, optional):
                The name of the partition.
            where_filter (str | None, optional):
                Filter returned users. This is a string filter.
                If None, no filtering applies.
            where_location (str | None, optional):
                Filter based on the DN of the Organizational Unit.
            where_state (str | None, optional):
                Filter returned users by their state. Possible values are 'enabled' and 'disabled'.
                If None, no filtering based on state applies.
            page_size (int, optional):
                The chunk size for the number of users returned by one
                REST API call. If None, then a default of 250 is used.

        Returns:
            iter:
                A generator yielding one OTDS user per iteration.
                If the REST API fails, returns no value.

        """

        next_page_cookie = None

        while True:
            response = self.get_users(
                partition=partition,
                where_filter=where_filter,
                where_location=where_location,
                where_state=where_state,
                page_size=page_size,
                next_page_cookie=next_page_cookie,
            )
            if not response or "users" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["users"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_cookie = response["nextPageCookie"]
            if not next_page_cookie:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_current_user(self) -> dict | None:
        """Get the currently logged in user.

        Returns:
            dict | None:
                Request response or None if the user was not found.

        """

        request_url = self.current_user_url()

        self.logger.debug(
            "Get current user; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get current user",
        )

    # end method definition

    def update_user(
        self,
        partition: str,
        user_id: str,
        attribute_name: str,
        attribute_value: str,
    ) -> dict | None:
        """Update a user attribute with a new value.

        Args:
            partition (str):
                The name of the partition the user is in.
            user_id (str):
                The ID of the user (= login name).
            attribute_name (str):
                The name of the attribute.
            attribute_value (str):
                The new (updated) value of the attribute.

        Returns:
            dict | None:
                Request response or None if the update fails.

        """

        if attribute_name in ["description"]:
            user_patch_body_json = {
                "userPartitionID": partition,
                attribute_name: attribute_value,
            }
        else:
            user_patch_body_json = {
                "userPartitionID": partition,
                "values": [{"name": attribute_name, "values": [attribute_value]}],
            }

        request_url = self.users_url() + "/" + user_id

        self.logger.debug(
            "Update user -> '%s' attribute -> '%s' to value -> '%s'; calling -> %s",
            user_id,
            attribute_name,
            attribute_value,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PATCH",
            json_data=user_patch_body_json,
            timeout=None,
            failure_message="Failed to update user -> '{}'".format(user_id),
        )

    # end method definition

    def delete_user(self, partition: str, user_id: str) -> bool:
        """Delete an existing user.

        Args:
            partition (str):
                The name of the partition the user is in.
            user_id (str):
                The ID (= login name) of the user to delete.

        Returns:
            bool:
                True = success, False = error

        """

        request_url = self.users_url() + "/" + user_id + "@" + partition

        self.logger.debug(
            "Delete user -> '%s' in partition -> '%s'; calling -> %s",
            user_id,
            partition,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="DELETE",
            timeout=None,
            failure_message="Failed to delete user -> '{}'".format(user_id),
            parse_request_response=False,
        )

        bool(response and response.ok)

    # end method definition

    def reset_user_password(self, user_id: str, password: str) -> bool:
        """Reset a password of an existing user.

        Args:
            user_id (str):
                The Id (= login name) of the user.
            password (str):
                The new password of the user.

        Returns:
            bool:
                True = success, False = error.

        """

        user_post_body_json = {"newPassword": password}

        request_url = "{}/{}/password".format(self.users_url(), user_id)

        self.logger.debug(
            "Resetting password for user -> '%s'; calling -> %s",
            user_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="PUT",
            json_data=user_post_body_json,
            timeout=None,
            failure_message="Failed to reset password for user -> '{}'".format(user_id),
            parse_request_response=False,
        )

        bool(response and response.ok)

    # end method definition

    def add_group(self, partition: str, name: str, description: str) -> dict | None:
        """Add a new user group to a user partition in OTDS.

        Args:
            partition (str):
                The name of the OTDS user partition (needs to exist).
            name (str):
                The name of the new group.
            description (str):
                The description of the new group.

        Returns:
            dict | None:
                Request response (json) or None if the creation fails.

        """

        group_post_body_json = {
            "userPartitionID": partition,
            "name": name,
            "description": description,
        }

        request_url = self.groups_url()

        self.logger.debug(
            "Adding group -> '%s' to partition -> '%s'; calling -> %s",
            name,
            partition,
            request_url,
        )
        self.logger.debug("Group Attributes -> %s", str(group_post_body_json))

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=group_post_body_json,
            timeout=None,
            failure_message="Failed to reset password for user -> '{}'".format(name),
        )

    # end method definition

    def get_group(self, group: str, show_error: bool = True) -> dict | None:
        """Get a OTDS group by its group name.

        Args:
            group (str):
                The ID of the group (= group name).
            show_error (bool, optional):
                If True, log an error if resource is not found. Otherwise log a warning.

        Returns:
            dict | None:
                Request response or None if the group was not found.

        Example:
            {
                'numMembers': 7,
                'userPartitionID': 'Content Server Members',
                'name': 'Sales',
                'location': 'oTGroup=3f921294-b92a-4c9e-bf7c-b50df16bb937,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net',
                'id': 'Sales@Content Server Members',
                'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...],
                'description': None,
                'uuid': '3f921294-b92a-4c9e-bf7c-b50df16bb937',
                'objectClass': 'oTGroup',
                'customAttributes': None,
                'originUUID': None,
                'urlId': 'Sales@Content Server Members',
                'urlLocation': 'oTGroup=3f921294-b92a-4c9e-bf7c-b50df16bb937,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net'
            }

        """

        request_url = self.groups_url() + "/" + group

        self.logger.debug("Get group -> '%s'; calling -> %s", group, request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get group -> '{}'".format(group),
            show_error=show_error,
        )

    # end method definition

    def get_groups(
        self,
        partition: str = "",
        where_filter: str | None = None,
        where_location: str | None = None,
        limit: int | None = None,
        page_size: int | None = None,
        attributes_as_keys: bool = True,
        next_page_cookie: str | None = None,
    ) -> dict | None:
        """Get all groups in a partition. Additional filters can be applied.

        Args:
            partition (str, optional):
                The name of the partition.
            where_filter (str | None, optional):
                Filter returned groups. This is a string filter.
                If None, no filtering applies.
            where_location (str | None, optional):
                Filter based on the DN of the Organizational Unit.
            limit (int, optional):
                The maximum number of groups to return. None = unlimited.
            page_size (int, optional):
                The chunk size for the number of groups returned by one
                REST API call. If None, then a default of 250 is used.
            attributes_as_keys (bool, optional):
                If True, it creates a much simpler to parse result structure
                per group that includes the group attributes in a "attributes"
                dictionary where the keys are the attribute names and the
                values the attribute values.
                'attributes': {
                    'schemaType' = ['3']
                    'cn' = [...]
                    ...
                }
                If False a "values" list with "name" and "values" elements is created:
                'values': [
                        {
                            'name': 'schemaType',
                            'values': ['3']
                        },
                        {
                            'name': 'cn',
                            'values': ['...']
                        },
                        ...
                ]
                Default is True (= attributes as keys).
            next_page_cookie (str, optional):
                A key returned by a former call to this method in with
                a return key 'nextPageCookie' (see example below). This
                can be used to get the next page of result items.

        Returns:
            dict | None:
                Request response or None if the user was not found.

        Example:
        {
            'groups': [
                {
                    'numMembers': 0,
                    'userPartitionID': 'Content Server Members',
                    'name': 'Unified_ArchiveLink',
                    'location': 'oTGroup=050a3c27-7636-4406-a94e-dcc4947fa21f,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net',
                    'id': 'Unified_ArchiveLink@Content Server Members',
                    'attributes': {
                        'oTExternalID3': [...],
                        'entryUUID': [...],
                        'oTExternalID4': [...],
                        'oTObjectIDInResource': [...],
                        'oTSource': [...],
                        'schemaType': [...],
                        'cn': [...],
                        'oTObjectGUID': [...],
                        'oTExternalID1': [...],
                        'entryDN': [...],
                        'oTExternalID2': [...],
                        'createTimestamp': [...]
                    },
                    'values': None,
                    'customAttributes': None,
                    'objectClass': 'oTGroup',
                    'uuid': '050a3c27-7636-4406-a94e-dcc4947fa21f',
                    'description': None,
                    'originUUID': None,
                    'urlId': 'Unified_ArchiveLink@Content Server Members',
                    'urlLocation': 'oTGroup=050a3c27-7636-4406-a94e-dcc4947fa21f,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net'
                },
                {
                    'numMembers': 0,
                    'userPartitionID': 'Content Server Members',
                    'name': 'R&D',
                    'location': 'oTGroup=24356f83-5636-47f0-9ac3-9646d3b34804,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net',
                    'id': 'R&D@Content Server Members',
                    'attributes': {
                        'oTExternalID3': [...],
                        'entryUUID': [...],
                        'oTExternalID4': [...],
                        'oTObjectIDInResource': [...],
                        'oTSource': [...],
                        'schemaType': [...],
                        'cn': [...],
                        'oTObjectGUID': [...],
                        'oTExternalID1': [...],
                        'entryDN': [...],
                        'oTExternalID2': [...],
                        'createTimestamp': [...]
                    },
                    'values': None,
                    'customAttributes': None,
                    'objectClass': 'oTGroup',
                    'uuid': '24356f83-5636-47f0-9ac3-9646d3b34804',
                    'description': None,
                    'originUUID': None,
                    'urlId': 'R&D@Content Server Members',
                    'urlLocation': 'oTGroup=24356f83-5636-47f0-9ac3-9646d3b34804,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net'
                },
                ...
            ],
            'actualPageSize': 5,
            'nextPageCookie': 'JIHw2CLHSoeTOmo7Ng/bPw==',
            'requestedPageSize': 5
        }

        """

        # Add query parameters (these are NOT passed via request body!)
        query = {}
        if partition:
            query["where_partition_name"] = partition
        if where_filter:
            query["where_filter"] = where_filter
        if where_location:
            query["where_location"] = where_location
        if limit:
            query["limit"] = limit
        if page_size:
            query["page_size"] = page_size
        if attributes_as_keys:
            query["attrsAsKeys"] = attributes_as_keys
        if next_page_cookie:
            query["next_page_cookie"] = next_page_cookie

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.groups_url()
        if query:
            request_url += "?{}".format(encoded_query)

        if partition:
            self.logger.debug(
                "Get all groups in partition -> '%s' (limit -> %s, page size -> %s); calling -> %s",
                partition,
                str(limit),
                str(page_size),
                request_url,
            )
            failure_message = "Failed to get all groups in partition -> '{}'!".format(
                partition,
            )
        else:
            self.logger.debug(
                "Get all groups (limit -> %s); calling -> %s",
                limit,
                request_url,
            )
            failure_message = "Failed to get all groups"

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message=failure_message,
        )

    # end method definition

    def get_groups_iterator(
        self,
        partition: str = "",
        where_filter: str | None = None,
        where_location: str | None = None,
        page_size: int | None = None,
    ) -> iter:
        """Get an iterator object that can be used to traverse all groups for a given users partition.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of OTDS groups.

        Example usage:
            groups = otds_object.get_groups_iterator(partition="Content Server Members", page_size=10)
            for group in groups:
                logger.info("Traversing group -> %s", group["name"])

        Args:
            partition (str, optional):
                The name of the partition.
            where_filter (str | None, optional):
                Filter returned groups. This is a string filter.
                If None, no filtering applies.
            where_location (str | None, optional):
                Filter based on the DN of the Organizational Unit.
            page_size (int | None, optional):
                The chunk size for the number of groups returned by one
                REST API call. If None, then a default of 250 is used.

        Returns:
            iter:
                A generator yielding one OTDS group per iteration.
                If the REST API fails, returns no value.

        """

        next_page_cookie = None

        while True:
            response = self.get_groups(
                partition=partition,
                where_filter=where_filter,
                where_location=where_location,
                page_size=page_size,
                next_page_cookie=next_page_cookie,
            )
            if not response or "groups" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["groups"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_cookie = response["nextPageCookie"]
            if not next_page_cookie:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def add_user_to_group(self, user: str, group: str) -> bool:
        """Add an existing user to an existing group in OTDS.

        Args:
            user (str):
                The name of the OTDS user (needs to exist).
            group (str):
                The name of the OTDS group (needs to exist).

        Returns:
            bool:
                True, if the request is successful, False otherwise.

        """

        user_to_group_post_body_json = {"stringList": [group]}

        request_url = self.users_url() + "/" + user + "/memberof"

        self.logger.debug(
            "Adding user -> '%s' to group -> '%s'; calling -> %s",
            user,
            group,
            request_url,
        )

        # OTDS delivers an empty response.text for the API, so we don't parse it here:
        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=user_to_group_post_body_json,
            timeout=None,
            failure_message="Failed to add user -> '{}' to group -> '{}'".format(
                user,
                group,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def add_group_to_parent_group(self, group: str, parent_group: str) -> bool:
        """Add an existing group to an existing parent group in OTDS.

        Args:
            group (str):
                The name of the OTDS group (needs to exist).
            parent_group (str):
                The name of the OTDS parent group (needs to exist).

        Returns:
            bool:
                True, if the request is successful, False otherwise.

        """

        group_to_parent_group_post_body_json = {"stringList": [parent_group]}

        request_url = self.groups_url() + "/" + group + "/memberof"

        self.logger.debug(
            "Adding group -> '%s' to parent group -> '%s'; calling -> %s",
            group,
            parent_group,
            request_url,
        )

        # OTDS delivers an empty response.text for the API, so we don't parse it here:
        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=group_to_parent_group_post_body_json,
            timeout=None,
            failure_message="Failed to add group -> '{}' to parent group -> '{}'".format(
                group,
                parent_group,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def add_resource(
        self,
        name: str,
        description: str = "",
        display_name: str = "",
        allow_impersonation: bool = True,
        resource_id: str | None = None,
        secret: str | None = None,  # needs to be 16 bytes!
        additional_payload: dict | None = None,
    ) -> dict | None:
        """Add an OTDS resource.

        Args:
            name (str):
                The name of the new OTDS resource.
            description (str):
                The optional description of the new OTDS resource.
            display_name (str, optional):
                The optional display name of the OTDS resource.
            allow_impersonation (bool):
                Defines whether or not the resource allows impersonation.
            resource_id (str | None, optional):
                Allows to set a predefined resource ID. This requires the
                secret parameter in additon.
            secret (str):
                A 24 charcters secret key. Required to set a predefined resource ID.
            additional_payload (dict, optional):
                Additional values for the JSON payload.

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        """

        resource_post_body = {
            "resourceName": name,
            "description": description,
            "displayName": display_name,
            "allowImpersonation": allow_impersonation,
        }

        if resource_id and not secret:
            self.logger.error(
                "A resource ID can only be specified if a secret value is also provided!",
            )
            return None

        if resource_id:
            resource_post_body["resourceID"] = resource_id
        if secret:
            if len(secret) != 24 or not secret.endswith("=="):
                self.logger.warning(
                    "The secret should by 24 characters long and should end with '=='",
                )
            resource_post_body["secretKey"] = secret

        # Check if there's additional payload for the body provided to handle special cases:
        if additional_payload:
            # Merge additional payload:
            resource_post_body.update(additional_payload)

        request_url = self.config()["resourceUrl"]

        self.logger.debug(
            "Adding resource -> '%s' ('%s'); calling -> %s",
            name,
            description,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=resource_post_body,
            timeout=None,
            failure_message="Failed to add resource -> '{}'".format(name),
        )

    # end method definition

    def get_resource(self, name: str, show_error: bool = False) -> dict | None:
        """Get an existing OTDS resource.

        Args:
            name (str):
                The name of the new OTDS resource.
            show_error (bool, optional):
                If True, log an error if resource is not found. Else log just a warning.

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        Example:
            {
                'resourceName': 'cs',
                'id': 'cs',
                'description': 'Content Server',
                'displayName': 'IDEA-TE DEV - Extended ECM 24.4.0',
                'resourceID': 'd441e5cb-68ef-4cb7-a8a0-037ba6b35522',
                'resourceState': 1,
                'userSynchronizationState': True,
                'resourceDN': 'oTResource=d441e5cb-68ef-4cb7-a8a0-037ba6b35522,dc=identity,dc=opentext,dc=net',
                'resourceType': 'cs',
                'accessRoleList': [{...}],
                'impersonateList': None,
                'impersonateAnonymousList': None,
                'pcCreatePermissionAllowed': True,
                'pcModifyPermissionAllowed': True,
                'pcDeletePermissionAllowed': True,
                'logoutURL': 'https://otawp.dev.idea-te.eimdemo.com/home/system/wcp/sso/sso_logout.htm',
                'logoutMethod': 'GET',
                'allowImpersonation': True,
                'connectionHealthy': True,
                'connectorName': 'Content Server',
                'connectorid': 'cs',
                'userAttributeMapping': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}],
                'groupAttributeMapping': [{...}, {...}],
                'connectionParamInfo': [{...}, {...}, {...}, {...}, {...}, {...}, {...}],
                'logonStyle': None,
                'logonUXVersion': 0
            }

        """

        request_url = "{}/{}".format(self.config()["resourceUrl"], name)

        self.logger.debug("Get resource -> '%s'; calling -> %s", name, request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get resource -> '{}'".format(name),
            show_error=show_error,
        )

    # end method definition

    def update_resource(
        self,
        name: str,
        resource: object,
        show_error: bool = True,
    ) -> dict | None:
        """Update an existing OTDS resource.

        Args:
            name (str):
                The name of the OTDS resource to update.
            resource (object):
                The updated resource object of get_resource called before
            show_error (bool, optional):
                If True, log an error if resource is not found. Else just log a warning.

        Returns:
            dict | None:
                Request response (json) or None if the REST call fails.

        """

        request_url = "{}/{}".format(self.config()["resourceUrl"], name)

        self.logger.debug("Updating resource -> '%s'; calling -> %s", name, request_url)

        return self.do_request(
            url=request_url,
            method="PUT",
            json_data=resource,
            timeout=None,
            failure_message="Failed to update resource -> '{}'".format(name),
            show_error=show_error,
        )

    # end method definition

    def activate_resource(self, resource_id: str) -> dict | None:
        """Activate an OTDS resource.

        Args:
            resource_id (str):
                The ID of the OTDS resource to update.

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        resource_post_body_json = {}

        request_url = "{}/{}/activate".format(self.config()["resourceUrl"], resource_id)

        self.logger.debug(
            "Activating resource -> '%s'; calling -> %s",
            resource_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=resource_post_body_json,
            timeout=None,
            failure_message="Failed to activate resource -> '{}'".format(resource_id),
        )

    # end method definition

    def get_access_roles(self) -> dict | None:
        """Get a list of all OTDS access roles.

        Args:
            None

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        request_url = self.config()["accessRoleUrl"]

        self.logger.debug("Retrieving access roles; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get access roles",
        )

    # end method definition

    def get_access_role(self, access_role: str) -> dict | None:
        """Get an OTDS access role.

        Args:
            access_role (str):
                The name of the access role.

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        request_url = self.config()["accessRoleUrl"] + "/" + access_role

        self.logger.debug(
            "Get access role -> '%s'; calling -> %s",
            access_role,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get access role -> '{}'".format(access_role),
        )

    # end method definition

    def add_partition_to_access_role(
        self,
        access_role: str,
        partition: str,
        location: str = "",
    ) -> bool:
        """Add an OTDS partition to an OTDS access role.

        Args:
            access_role (str):
                The name of the OTDS access role.
            partition (str):
                The name of the partition.
            location (str, optional):
                This is kind of a unique identifier DN (Distinguished Name)
                most of the times you will want to keep it to empty string ("")

        Returns:
            bool:
                True if partition is in access role or has been successfully added.
                False if partition has been not been added (error)

        """

        access_role_post_body_json = {
            "userPartitions": [{"name": partition, "location": location}],
        }

        request_url = "{}/{}/members".format(
            self.config()["accessRoleUrl"],
            access_role,
        )

        self.logger.debug(
            "Add user partition -> '%s' to access role -> '%s'; calling -> %s",
            partition,
            access_role,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=access_role_post_body_json,
            timeout=None,
            failure_message="Failed to add partition -> '{}' to access role -> '{}'".format(
                partition,
                access_role,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def add_user_to_access_role(
        self,
        access_role: str,
        user_id: str,
        location: str = "",
    ) -> bool:
        """Add an OTDS user to an OTDS access role.

        Args:
            access_role (str):
                The name of the OTDS access role.
            user_id (str):
                The ID of the user (= login name) to add to the access role.
            location (str, optional):
                This is kind of a unique identifier DN (Distinguished Name)
                most of the times you will want to keep it to empty string ("").

        Returns:
            bool:
                True if user is in access role or has been successfully added.
                False if user has not been added (error).

        """

        # get existing members to check if user is already a member:
        access_roles_get_response = self.get_access_role(access_role)
        if not access_roles_get_response:
            return False

        # Checking if user already added to access role
        access_role_users = access_roles_get_response["accessRoleMembers"]["users"]
        for user in access_role_users:
            if user["displayName"] == user_id:
                self.logger.debug(
                    "User -> '%s' already added to access role -> '%s'",
                    user_id,
                    access_role,
                )
                return True

        self.logger.debug(
            "User -> '%s' is not yet in access role -> '%s' - adding...",
            user_id,
            access_role,
        )

        # create payload for REST call:
        access_role_post_body_json = {
            "users": [{"name": user_id, "location": location}],
        }

        request_url = "{}/{}/members".format(
            self.config()["accessRoleUrl"],
            access_role,
        )

        self.logger.debug(
            "Add user -> %s to access role -> %s; calling -> %s",
            user_id,
            access_role,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=access_role_post_body_json,
            timeout=None,
            failure_message="Failed to add user -> '{}' to access role -> '{}'".format(
                user_id,
                access_role,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def add_group_to_access_role(
        self,
        access_role: str,
        group: str,
        location: str = "",
    ) -> bool:
        """Add an OTDS group to an OTDS access role.

        Args:
            access_role (str):
                The name of the OTDS access role.
            group (str):
                The name of the group to add to the access role.
            location (str, optional):
                This is kind of a unique identifier DN (Distinguished Name)
                most of the times you will want to keep it to empty string ("").

        Returns:
            bool:
                True if group is in access role or has been successfully added.
                False if group has been not been added (error)

        """

        # get existing members to check if user is already a member:
        access_roles_get_response = self.get_access_role(access_role)
        if not access_roles_get_response:
            return False

        # Checking if group already added to access role
        access_role_groups = access_roles_get_response["accessRoleMembers"]["groups"]
        for access_role_group in access_role_groups:
            if access_role_group["name"] == group:
                self.logger.debug(
                    "Group -> '%s' already added to access role -> '%s'.",
                    group,
                    access_role,
                )
                return True

        self.logger.debug(
            "Group -> '%s' is not yet in access role -> '%s' - adding...",
            group,
            access_role,
        )

        # create payload for REST call:
        access_role_post_body_json = {"groups": [{"name": group, "location": location}]}

        request_url = "{}/{}/members".format(
            self.config()["accessRoleUrl"],
            access_role,
        )

        self.logger.debug(
            "Add group -> '%s' to access role -> '%s'; calling -> %s",
            group,
            access_role,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=access_role_post_body_json,
            timeout=None,
            failure_message="Failed to add group -> '{}' to access role -> '{}'".format(
                group,
                access_role,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def update_access_role_attributes(
        self,
        name: str,
        attribute_list: list,
    ) -> dict | None:
        """Update some attributes of an existing OTDS access role.

        Args:
            name (str):
                The name of the existing access role.
            attribute_list (list):
                A list of attribute name and attribute value pairs.
                The values need to be a list as well.
                Example values:
                [
                    {
                        name: "pushAllGroups",
                        values: ["True"]
                    }
                ]

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        # Return if list is empty:
        if not attribute_list:
            return None

        # create payload for REST call:
        access_role = self.get_access_role(name)
        if not access_role:
            self.logger.error("Failed to get access role -> '%s'! Cannot update its attributes.", name)
            return None

        access_role_put_body_json = {"attributes": attribute_list}

        request_url = "{}/{}/attributes".format(self.config()["accessRoleUrl"], name)

        self.logger.debug(
            "Update access role -> '%s' with attributes -> %s; calling -> %s",
            name,
            str(access_role_put_body_json),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            json_data=access_role_put_body_json,
            timeout=None,
            failure_message="Failed to update access role -> '{}'".format(access_role),
        )

    # end method definition

    def add_license_to_resource(
        self,
        path_to_license_file: str,
        product_name: str,
        product_description: str,
        resource_id: str,
        update: bool = True,
    ) -> dict | None:
        """Add a product license to an OTDS resource.

        Args:
            path_to_license_file (str):
                A fully qualified filename of the license file.
            product_name (str):
                The product name.
            product_description (str):
                The product description.
            resource_id (str):
                OTDS resource ID (this is ID not the resource name!).
            update (bool, optional):
                Whether or not an existing license should be updated (default = True).

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        """

        self.logger.debug("Reading license file -> '%s'...", path_to_license_file)
        try:
            with open(path_to_license_file, encoding="UTF-8") as license_file:
                license_content = license_file.read()
        except OSError:
            self.logger.error(
                "Error opening license file -> '%s'!",
                path_to_license_file,
            )
            return None

        license_post_body_json = {
            "description": product_description,
            "name": product_name,
            "values": [
                {"name": "oTLicenseFile", "values": license_content},
                {"name": "oTLicenseResource", "values": resource_id},
                {"name": "oTLicenseFingerprintGenerator", "values": [None]},
            ],
        }

        request_url = self.license_url()
        # Check if we want to update an existing license:
        if update:
            existing_license = self.get_license_for_resource(resource_id)
            if existing_license:
                request_url += "/" + existing_license[0]["id"]
            else:
                self.logger.info(
                    "No existing license found for product -> '%s' and resource -> '%s' - adding a new license...",
                    product_name,
                    resource_id,
                )
                # change strategy to create a new license:
                update = False

        self.logger.debug(
            "%s product license -> '%s' for product -> '%s' to resource ->'%s'; calling -> %s",
            "Adding" if not update else "Updating",
            path_to_license_file,
            "{} ({})".format(product_name, product_description) if product_description else product_name,
            resource_id,
            request_url,
        )

        if update:
            # Do a REST PUT call for update an existing license:
            return self.do_request(
                url=request_url,
                method="PUT",
                json_data=license_post_body_json,
                timeout=None,
                failure_message="Failed to update product license -> '{}' for product -> '{}' to resource -> '{}'".format(
                    path_to_license_file,
                    "{} ({})".format(product_name, product_description) if product_description else product_name,
                    resource_id,
                ),
            )
        else:
            # Do a REST POST call for creation of a new license:
            return self.do_request(
                url=request_url,
                method="POST",
                json_data=license_post_body_json,
                timeout=None,
                failure_message="Failed to add product license -> '{}' for product -> '{}' to resource -> '{}'".format(
                    path_to_license_file,
                    "{} ({})".format(product_name, product_description) if product_description else product_name,
                    resource_id,
                ),
            )

    # end method definition

    def get_license_for_resource(self, resource_id: str) -> dict | None:
        """Get a product license for a resource in OTDS.

        Args:
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).

        Returns:
            dict | None:
                Licenses for a resource or None if the REST call fails.

        Example:
            {
                '_oTLicenseType': 'NON-PRODUCTION',
                '_oTLicenseResource': '7382094f-a434-4714-9696-82864b6803da',
                '_oTLicenseResourceName': 'cs',
                '_oTLicenseProduct': 'EXTENDED_ECM',
                'name': 'EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da',
                'location': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
                'id': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
                'description': 'CS license',
                'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
            }

        """

        request_url = self.license_url() + "/assignedlicenses?resourceID=" + resource_id + "&validOnly=false"

        self.logger.debug(
            "Get license for resource -> %s; calling -> %s",
            resource_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get license for resource -> '{}'".format(
                resource_id,
            ),
        )

        if not response:
            return None

        return response["licenseObjects"]["_licenses"]

    # end method definition

    def delete_license_from_resource(self, resource_id: str, license_id: str) -> bool:
        """Delete a product license for a resource in OTDS.

        Args:
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).
            license_id (str):
                The OTDS license ID (this is the ID not the license name!).

        Returns:
            bool:
                True if successful or False if the REST call fails

        """

        request_url = "{}/{}".format(self.license_url(), license_id)

        self.logger.debug(
            "Deleting product license -> '%s' from resource -> '%s'; calling -> %s",
            license_id,
            resource_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="DELETE",
            timeout=None,
            failure_message="Failed to delete license -> '{}' for resource -> '{}'".format(
                license_id,
                resource_id,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def assign_user_to_license(
        self,
        partition: str,
        user_id: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
        license_type: str = "Full",
    ) -> bool:
        """Assign an OTDS user to a product license (feature) in OTDS.

        licenses have this format:
        {
          '_oTLicenseType': 'NON-PRODUCTION',
          '_oTLicenseResource': '7382094f-a434-4714-9696-82864b6803da',
          '_oTLicenseResourceName': 'cs',
          '_oTLicenseProduct': 'EXTENDED_ECM',
          'name': 'EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da',
          'location': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'id': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'description': 'CS license',
          'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
        }

        Args:
            partition (str):
                The user partition in OTDS, e.g. "Content Server Members".
            user_id (str):
                The ID of the user (= login name) to assign to the license.
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).
            license_feature (str):
                The name of the license feature.
            license_name (str):
                The name of the license to assign.
            license_type (str, optional):
                The type of the license. Default is "Full", Extended ECM also has "Occasional".

        Returns:
            bool:
                True if successful or False if the REST call fails or the license is not found.

        """

        licenses = self.get_license_for_resource(resource_id)
        if not licenses:
            self.logger.error(
                "Resource with ID -> '%s' does not exist or has no licenses!",
                resource_id,
            )
            return False

        for lic in licenses:
            if lic["_oTLicenseProduct"] == license_name:
                license_id = lic["id"]
                break
        else:
            self.logger.error(
                "Cannot find license -> '%s' for resource with ID -> '%s'!",
                license_name,
                resource_id,
            )
            return False

        user = self.get_user(partition, user_id)
        if user:
            user_location = user["location"]
        else:
            self.logger.error("Cannot find location for user -> '%s'!", user_id)
            return False

        license_post_body_json = {
            "_oTLicenseType": license_type,
            "_oTLicenseProduct": "users",
            "name": user_location,
            "values": [{"name": "counter", "values": [license_feature]}],
        }

        request_url = self.license_url() + "/object/" + license_id

        self.logger.debug(
            "Assign license feature -> '%s' of license -> '%s' associated with resource -> '%s' to user -> '%s'; calling -> %s",
            license_feature,
            license_id,
            resource_id,
            user_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=license_post_body_json,
            timeout=None,
            failure_message="Failed to add license feature -> '{}' associated with resource ID -> '{}' to user -> '{}'".format(
                license_feature,
                resource_id,
                user_id,
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            self.logger.debug(
                "Added license feature -> '%s' to user -> '%s'.",
                license_feature,
                user_id,
            )
            return True

        return False

    # end method definition

    def assign_partition_to_license(
        self,
        partition_name: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
        license_type: str = "Full",
    ) -> bool:
        """Assign an OTDS partition to a product license (feature).

        licenses have this format:
        {
          '_oTLicenseType': 'NON-PRODUCTION',
          '_oTLicenseResource': '7382094f-a434-4714-9696-82864b6803da',
          '_oTLicenseResourceName': 'cs',
          '_oTLicenseProduct': 'EXTENDED_ECM',
          'name': 'EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da',
          'location': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'id': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'description': 'CS license',
          'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
        }

        Args:
            partition_name (str):
                The user partition in OTDS, e.g. "Content Server Members".
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).
            license_feature (str):
                The name of the license feature, e.g. "X2" or "ADDON_ENGINEERING".
            license_name (str):
                The name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG".
            license_type (str, optional):
                The license type. Default is "Full", Extended ECM also has "Occasional"

        Returns:
            bool:
                True if successful or False if the REST call fails or the license is not found.

        """

        licenses = self.get_license_for_resource(resource_id)
        if not licenses:
            self.logger.error(
                "Resource with ID -> '%s' does not exist or has no licenses!",
                resource_id,
            )
            return False

        for lic in licenses:
            if lic["_oTLicenseProduct"] == license_name:
                license_id = lic["id"]
                break
        else:
            self.logger.error(
                "Cannot find license -> %s for resource -> %s",
                license_name,
                resource_id,
            )
            return False

        license_post_body_json = {
            "_oTLicenseType": license_type,
            "_oTLicenseProduct": "partitions",
            "name": partition_name,
            "values": [{"name": "counter", "values": [license_feature]}],
        }

        request_url = self.license_url() + "/object/" + license_id

        self.logger.debug(
            "Assign license feature -> '%s' of license -> '%s' associated with resource -> '%s' to partition -> '%s'; calling -> %s",
            license_feature,
            license_id,
            resource_id,
            partition_name,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=license_post_body_json,
            timeout=None,
            failure_message="Failed to add license feature -> '{}' associated with resource ID -> '{}' to partition -> '{}'".format(
                license_feature,
                resource_id,
                partition_name,
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            self.logger.debug(
                "Added license feature -> '%s' to partition -> '%s'",
                license_feature,
                partition_name,
            )
            return True

        return False

    # end method definition

    def get_licensed_objects(
        self,
        resource_id: str,
        license_feature: str,
        license_name: str,
    ) -> dict | None:
        """Return the licensed objects for a license + license feature associated with an OTDS resource (like "cs").

        Licensed objects can be users, groups, or partitions.

        licenses have this format:
        {
          '_oTLicenseType': 'NON-PRODUCTION',
          '_oTLicenseResource': '7382094f-a434-4714-9696-82864b6803da',
          '_oTLicenseResourceName': 'cs',
          '_oTLicenseProduct': 'EXTENDED_ECM',
          'name': 'EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da',
          'location': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'id': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'description': 'CS license',
          'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
        }

        Args:
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).
            license_feature (str):
                The name of the license feature, e.g. "X2" or "ADDON_ENGINEERING".
            license_name (str):
                The name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG".

        Returns:
            dict | None:
                The data structure of licensed objects or None in case of an error.

        Example:
            {
                'status': 0,
                'displayString': 'Success',
                'exceptions': None,
                'retValue': 0,
                'listGroupsResults': {
                    'groups': [...],
                    'actualPageSize': 0,
                    'nextPageCookie': None,
                    'requestedPageSize': 250
                },
                'listUsersResults': {
                    'users': [...],
                    'actualPageSize': 53,
                    'nextPageCookie': None,
                    'requestedPageSize': 250
                },
                'listUserPartitionResult': {
                    '_userPartitions': [...],
                    'warningMessage': None,
                    'actualPageSize': 0,
                    'nextPageCookie': None,
                    'requestedPageSize': 250
                },
                'version': 1
            }

        """

        licenses = self.get_license_for_resource(resource_id)
        if not licenses:
            self.logger.error(
                "Resource with ID -> '%s' does not exist or has no licenses!",
                resource_id,
            )
            return False

        for lic in licenses:
            if lic["_oTLicenseProduct"] == license_name:
                license_location = lic["location"]
                break
        else:
            self.logger.error(
                "Cannot find license -> %s for resource -> %s",
                license_name,
                resource_id,
            )
            return False

        request_url = self.license_url() + "/object/" + license_location + "?counter=" + license_feature

        self.logger.debug(
            "Get licensed objects for license -> '%s' and license feature -> '%s' associated with resource -> '%s'; calling -> %s",
            license_name,
            license_feature,
            resource_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get licensed objects for license -> '{}' and license feature -> '{}' associated with resource -> '{}'".format(
                license_name,
                license_feature,
                resource_id,
            ),
        )

    # end method definition

    def is_user_licensed(
        self,
        user_name: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
    ) -> bool:
        """Check if a user is licensed for a license and license feature associated with a particular OTDS resource.

        Args:
            user_name (str):
                The login name of the OTDS user.
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).
            license_feature (str):
                The name of the license feature, e.g. "X2" or "ADDON_ENGINEERING".
            license_name (str):
                The name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG".

        Returns:
            bool:
                True if the user is licensed and False otherwise.

        """

        response = self.get_licensed_objects(
            resource_id=resource_id,
            license_feature=license_feature,
            license_name=license_name,
        )

        if not response or not response["listUsersResults"]:
            return False

        users = response["listUsersResults"]["users"]

        if not users:
            return False

        user = next(
            (item for item in users if item["name"] == user_name),
            None,
        )

        return bool(user)

    # end method definition

    def is_group_licensed(
        self,
        group_name: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
    ) -> bool:
        """Check if a group is licensed for a license and license feature associated with a particular OTDS resource.

        Args:
            group_name (str):
                The name of the OTDS user group.
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).
            license_feature (str):
                The name of the license feature, e.g. "X2" or "ADDON_ENGINEERING".
            license_name (str):
                The name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG".

        Returns:
            bool:
                True if the group is licensed and False otherwise.

        """

        response = self.get_licensed_objects(
            resource_id=resource_id,
            license_feature=license_feature,
            license_name=license_name,
        )

        if not response or not response["listGroupsResults"]:
            return False

        groups = response["listGroupsResults"]["groups"]

        if not groups:
            return False

        group = next(
            (item for item in groups if item["name"] == group_name),
            None,
        )

        return bool(group)

    # end method definition

    def is_partition_licensed(
        self,
        partition_name: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
    ) -> bool:
        """Check if a partition is licensed for a license feature associated with a particular OTDS resource.

        Args:
            partition_name (str):
                The name of the OTDS user partition, e.g. "Content Server Members".
            resource_id (str):
                The OTDS resource ID (this is ID not the resource name!).
            license_feature (str):
                The name of the license feature, e.g. "X2" or "ADDON_ENGINEERING".
            license_name (str):
                The name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG".

        Returns:
            bool:
                True if the partition is licensed and False otherwise.

        """

        response = self.get_licensed_objects(
            resource_id=resource_id,
            license_feature=license_feature,
            license_name=license_name,
        )

        if not response or not response["listUserPartitionResult"]:
            return False

        partitions = response["listUserPartitionResult"]["_userPartitions"]

        if not partitions:
            return False

        partition = next(
            (item for item in partitions if item["name"] == partition_name),
            None,
        )

        return bool(partition)

    # end method definition

    def import_synchronized_partition_members(self, name: str) -> bool:
        """Import users and groups to partition.

        Args:
            name (str):
                The name of the partition in which users need to be imported.

        Returns:
            bool:
                True = Success, False = Error.

        """

        command = {"command": "import"}
        request_url = self.synchronized_partition_url() + f"/{name}/command"

        self.logger.debug(
            "Importing users and groups into partition -> '%s'; calling -> %s",
            name,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=command,
            timeout=None,
            failure_message="Failed to import users and groups to synchronized partition -> '{}'".format(
                name,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok and response.status_code == 204)

    # end of method definition

    def add_synchronized_partition(
        self,
        name: str,
        description: str,
        data: dict,
    ) -> dict | None:
        """Add a new synchronized partition to OTDS.

        Args:
            name (str):
                The name of the new synchronized partition.
            description (str):
                The description of the new synchronized partition.
            data (dict):
                The data for creating synchronized partition

        Returns:
            dict | None:
                Request response or None if the creation fails.

        """

        synchronized_partition_post_body_json = {
            "ipConnectionParameter": [],
            "ipAuthentication": {},
            "objectClassNameMapping": [],
            "basicInfo": {},
            "basicAttributes": [],
        }
        synchronized_partition_post_body_json.update(data)

        request_url = self.synchronized_partition_url()
        self.logger.debug(
            "Adding synchronized partition -> '%s' ('%s'); calling -> %s",
            name,
            description,
            request_url,
        )
        synchronized_partition_post_body_json["ipAuthentication"]["bindPassword"] = self.config()["bindPassword"]

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=synchronized_partition_post_body_json,
            timeout=None,
            failure_message="Failed to add synchronized partition -> '{}'".format(name),
        )

    # end of method definition

    def add_system_attribute(
        self,
        name: str,
        value: str,
        description: str = "",
    ) -> dict | None:
        """Add a new system attribute to OTDS.

        Args:
            name (str):
                The name of the new system attribute.
            value (str):
                The value of the system attribute.
            description (str, optional):
                The optional description of the system attribute.

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        """

        system_attribute_post_body_json = {
            "name": name,
            "value": value,
            "friendlyName": description,
        }

        request_url = "{}/system_attributes".format(self.config()["systemConfigUrl"])

        if description:
            self.logger.debug(
                "Add system attribute -> '%s' ('%s') with value -> %s; calling -> %s",
                name,
                description,
                value,
                request_url,
            )
        else:
            self.logger.debug(
                "Add system attribute -> '%s' with value -> %s; calling -> %s",
                name,
                value,
                request_url,
            )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=system_attribute_post_body_json,
            timeout=None,
            failure_message="Failed to add system attribute -> '{}' with value -> '{}'".format(
                name,
                value,
            ),
        )

    # end method definition

    def get_trusted_sites(self) -> dict | None:
        """Get all configured OTDS trusted sites.

        Args:
            None

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        request_url = "{}/whitelist".format(self.config()["systemConfigUrl"])

        self.logger.debug("Get trusted sites; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get trusted sites",
        )

    # end method definition

    def add_trusted_site(self, trusted_site: str) -> dict | None:
        """Add a new OTDS trusted site.

        Args:
            trusted_site (str):
                The name of the new trusted site.

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        trusted_site_post_body_json = {"stringList": [trusted_site]}

        # we need to first retrieve the existing sites and then
        # append the new one:
        existing_trusted_sites = self.get_trusted_sites()

        if existing_trusted_sites:
            trusted_site_post_body_json["stringList"].extend(
                existing_trusted_sites["stringList"],
            )

        request_url = "{}/whitelist".format(self.config()["systemConfigUrl"])

        self.logger.debug(
            "Add trusted site -> '%s'; calling -> %s",
            trusted_site,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="PUT",
            json_data=trusted_site_post_body_json,
            timeout=None,
            failure_message="Failed to add trusted site -> '{}'".format(trusted_site),
            parse_request_response=False,  # don't parse it!
        )

        if not response or not response.ok:
            return None

        return response

    # end method definition

    def enable_audit(
        self,
        enable: bool = True,
        days_to_keep: int = 7,
        event_types: list | None = None,
    ) -> dict | None:
        """Enable the OTDS Audit.

        Args:
            enable (bool, optional):
                True = enable audit, False = disable audit.
            days_to_keep (int, optional):
                Days to keep the audit information. Default = 7 Days.
            event_types (list, optional):
                A list of event types to record.
                If None then a default list will be used.

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        if event_types is None:
            event_types = [
                "User Create",
                "Group Create",
                "User Delete",
                "Group Delete",
                "User Modify",
                "Group Modify",
                "Initial authentication successful",
                "Initial authentication failed",
                "Impersonation",
                "Import Finished",
                "Access Denied",
                "Authentication code incorrect",
                "Authentication code required",
                "User locked out",
                "Consolidate Partition with identity provider",
                "Recycle Bin User Deleted",
                "Recycle Bin Group Deleted",
                "User Moved to Recycle Bin",
                "Group Moved to Recycle Bin",
                "User Restored from Recycle Bin",
                "Group Restored from Recycle Bin",
                "Scheduled Cleanup",
                "Consolidation finished",
                "Monitoring session finished",
                "User Rename",
                "Group Rename",
                "Role Create",
                "Role Delete",
                "Role Modify",
                "Role Rename",
                "Recycle Bin Role Deleted",
                "Role Moved to Recycle Bin",
                "Role Restored from Recycle Bin",
                "Set group members",
                "Set group members for moved in objects",
                "User logout",
                "Password change successful",
                "Password change failed",
                "Add Parent Object",
                "Remove Parent Object",
                "OAuth Client Create",
                "OAuth Client Delete",
                "OAuth Client Modify",
                "Tenant Create",
                "Tenant Delete",
                "Tenant Modify",
                "Migration",
            ]

        audit_put_body_json = {
            "daysToKeep": str(days_to_keep),
            "enabled": enable,
            "auditTo": "DATABASE",
            "eventIDs": event_types,
        }

        request_url = "{}/audit".format(self.config()["systemConfigUrl"])

        if enable:
            self.logger.debug("Enable audit; calling -> %s", request_url)
            failure_message = "Failed to enable audit"
        else:
            self.logger.debug("Disable audit; calling -> %s", request_url)
            failure_message = "Failed to disable audit"

        return self.do_request(
            url=request_url,
            method="PUT",
            json_data=audit_put_body_json,
            timeout=None,
            failure_message=failure_message,
            parse_request_response=False,
        )

    # end method definition

    def add_oauth_client(
        self,
        client_id: str,
        description: str,
        redirect_urls: list | None = None,
        allow_impersonation: bool = True,
        confidential: bool = True,
        auth_scopes: list | None = None,  # None = "Global"
        allowed_scopes: list | None = None,  # in OTDS UI: Permissible scopes
        default_scopes: list | None = None,  # in OTDS UI: Default scopes
        secret: str = "",
    ) -> dict | None:
        """Add a new OAuth client to OTDS.

        Args:
            client_id (str):
                The name of the new OAuth client (should not have blanks).
            description (str):
                The description of the OAuth client.
            redirect_urls (list):
                A list of redirect URLs (strings).
            allow_impersonation (bool, optional):
                Whether or not to allow impersonation.
            confidential (bool, optional):
                is confidential
            auth_scopes (list, optional):
                The authorization scope. If empty then "Global" is assumed.
            allowed_scopes (list, optional):
                In the OTDS UI this is called Permissible scopes.
            default_scopes (list, optional):
                In the OTDS UI this is called Default scopes.
            secret (str, optional):
                Predefined OAuth client secret. If empty a new secret is generated.

        Returns:
            dict | None:
                Request response or None if the creation fails.

        Example:
            {
                "description": "string",
                "redirectURLs": [
                    "string"
                ],
                "id": "string",
                "location": "string",
                "accessTokenLifeTime": 0,
                "refreshTokenLifeTime": 0,
                "authCodeLifeTime": 0,
                "allowRefreshToken": true,
                "allowImpersonation": true,
                "useSessionRefreshTokenLifeTime": true,
                "allowedScopes": [
                    "string"
                ],
                "defaultScopes": [
                    "string"
                ],
                "impersonateList": [
                    "string"
                ],
                "confidential": true,
                "secret": "string",
                "customAttributes": [
                    {
                    "type": "string",
                    "name": "string",
                    "value": "string"
                    }
                ],
                "logoutURL": "string",
                "logoutMethod": "string",
                "authScopes": [
                    "string"
                ],
                "uuid": "string",
                "name": "string",
                "urlId": "string",
                "urlLocation": "string"
            }

        """

        # Avoid linter warning W0102:
        if redirect_urls is None:
            redirect_urls = []
        if auth_scopes is None:
            auth_scopes = []
        if allowed_scopes is None:
            allowed_scopes = []
        if default_scopes is None:
            default_scopes = []

        oauth_client_post_body_json = {
            "id": client_id,
            "description": description,
            "redirectURLs": redirect_urls,
            "accessTokenLifeTime": 1000,
            "refreshTokenLifeTime": 20000,
            "authCodeLifeTime": 20000,
            "allowRefreshToken": True,
            "allowImpersonation": allow_impersonation,
            "useSessionRefreshTokenLifeTime": True,
            "confidential": confidential,
            "authScopes": auth_scopes,
            "allowedScopes": allowed_scopes,
            "defaultScopes": default_scopes,
        }

        # Do we have a predefined client secret?
        if secret:
            oauth_client_post_body_json["secret"] = secret

        request_url = self.oauth_client_url()

        self.logger.debug(
            "Adding oauth client -> '%s' (%s); calling -> %s",
            description,
            client_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=oauth_client_post_body_json,
            timeout=None,
            failure_message="Failed to add OAuth client -> {}".format(client_id),
        )

    # end method definition

    def get_oauth_client(self, client_id: str, show_error: bool = True) -> dict | None:
        """Get an existing OAuth client from OTDS.

        Args:
            client_id (str):
                The name (= ID) of the OAuth client to retrieve
            show_error (bool, optional):
                Whether or not we want to log an error if partion is not found.

        Returns:
            dict | None:
                Request response (dictionary) or None if the client is not found.

        """

        request_url = "{}/{}".format(self.oauth_client_url(), client_id)

        self.logger.debug(
            "Get oauth client -> '%s'; calling -> %s",
            client_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get oauth client -> '{}'".format(client_id),
            show_error=show_error,
        )

    # end method definition

    def update_oauth_client(self, client_id: str, updates: dict) -> dict | None:
        """Update an OAuth client with new values.

        Args:
            client_id (str):
                The name (= ID) of the OAuth client.
            updates (dict):
                New values for OAuth client, e.g.
                {"description": "this is the new value"}

        Returns:
            dict | None:
                Request response (json) or None if the REST call fails.

        """

        oauth_client_patch_body_json = updates

        request_url = "{}/{}".format(self.oauth_client_url(), client_id)

        self.logger.debug(
            "Update OAuth client -> '%s' with -> %s; calling -> %s",
            client_id,
            str(updates),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PATCH",
            json_data=oauth_client_patch_body_json,
            timeout=None,
            failure_message="Failed to update OAuth client -> '{}'".format(client_id),
        )

    # end method definition

    def add_oauth_clients_to_access_role(self, access_role_name: str) -> dict | None:
        """Add OAuth clients (in the "OAuthClients" partition) to an OTDS access role.

        Args:
            access_role_name (str):
                The name of the OTDS access role.

        Returns:
            dict | None:
                Response of REST call or None in case of an error.

        """

        request_url = self.config()["accessRoleUrl"] + "/" + access_role_name

        self.logger.debug(
            "Get access role -> '%s'; calling -> %s",
            access_role_name,
            request_url,
        )

        access_role = self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to retrieve access role -> '{}'".format(
                access_role_name,
            ),
        )
        if not access_role:
            return None

        # Checking if OAuthClients partition already added to access role
        user_partitions = access_role["accessRoleMembers"]["userPartitions"]
        for user_partition in user_partitions:
            if user_partition["userPartition"] == "OAuthClients":
                self.logger.error(
                    "OAuthClients partition already added to role -> '%s'!",
                    access_role_name,
                )
                return None

        # Getting location info for the OAuthClients partition
        # so it can be added to access roles json
        request_url = self.config()["partitionsUrl"] + "/OAuthClients"

        response = self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get partition info for OAuthClients for role -> '{}'".format(
                access_role_name,
            ),
        )
        if not response:
            return None

        oauth_client_location = response["location"]

        # adding OAuthClients info to acess roles organizational units
        oauth_clients_ou_block = {
            "location": oauth_client_location,
            "name": oauth_client_location,
            "userPartition": None,
        }
        access_role["accessRoleMembers"]["organizationalUnits"].append(
            oauth_clients_ou_block,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            timeout=None,
            warning_message="Failed to add OAuthClients to access role -> '{}'".format(
                access_role_name,
            ),
            show_error=False,
            show_warning=True,
            parse_request_response=False,
        )

    # end method definition

    def get_auth_handler(self, name: str, show_error: bool = True) -> dict | None:
        """Get the OTDS auth handler with a given name.

        Args:
            name (str):
                The name of the authentication handler
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.

        Returns:
            dict | None:
                The auth handler dictionary, or None in case of an error.

        Example:
            {
                '_name': 'Salesforce',
                '_id': 'Salesforce',
                '_description': 'Salesforce OAuth Authentication Handler',
                '_class': 'com.opentext.otds.as.drivers.http.OAuth2Handler',
                '_enabled': True,
                '_credentialBased': True,
                '_priority': 10,
                '_scope': None,
                '_properties': [
                    {
                        '_key': 'com.opentext.otds.as.drivers.http.oauth2.provider_name',
                        '_name': 'Provider Name',
                        '_description': 'The name of the authentication provider. This name is displayed on the login page.',
                        '_required': True,
                        '_fileBased': False,
                        '_fileName': False,
                        '_fileExtensions': None,
                        '_value': 'Salesforce',
                        '_allowedValues': None,
                        ...
                    },
                    ...
                ]
                '_authPrincipalAttrNames': ['oTExtraAttr0'],
                'createPermission': True,
                'readPermission': True,
                'updatePermission': True,
                'deletePermission': True,
                'enablePermission': True,
            }

        """

        request_url = "{}/{}".format(self.auth_handler_url(), name)

        self.logger.debug(
            "Getting authentication handler -> '%s'; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get authentication handler -> '{}'".format(name),
            show_error=show_error,
        )

    # end method definition

    def add_auth_handler_saml(
        self,
        name: str,
        description: str,
        scope: str | None,
        provider_name: str,
        saml_url: str,
        otds_sp_endpoint: str,
        enabled: bool = True,
        priority: int = 5,
        active_by_default: bool = False,
        auth_principal_attributes: list | None = None,
        nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    ) -> dict | None:
        """Add a new SAML authentication handler.

        Args:
            name (str):
                The name of the new authentication handler.
            description (str):
                The description of the new authentication handler.
            scope (str):
                The name of the user partition (to define a scope of the auth handler)
            provider_name (str):
                The description of the new authentication handler.
            saml_url (str):
                The SAML URL.
            otds_sp_endpoint (str):
                The external(!) service provider URL of OTDS.
            enabled (bool, optional):
                Defines if the handler should be enabled or disabled. Default is True = enabled.
            priority (int, optional):
                Priority of the Authentical Handler (compared to others). Default is 5
            active_by_default (bool, optional):
                Defines whether OTDS should redirect immediately to provider page
                (not showing the OTDS login at all).
            auth_principal_attributes (list, optional):
                List of Authentication principal attributes
            nameid_format (str, optional):
                Specifies which NameID format supported by the identity provider
                contains the desired user identifier. The value in this identifier
                must correspond to the value of the user attribute specified for the
                authentication principal attribute.

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        """

        if auth_principal_attributes is None:
            auth_principal_attributes = ["oTExternalID1", "oTUserID1"]

        auth_handler_post_body_json = {
            "_name": name,
            "_description": description,
            "_class": "com.opentext.otds.as.drivers.saml.SAML2Handler",
            "_enabled": str.lower(str(enabled)),
            "_priority": str(priority),
            "_authPrincipalAttrNames": auth_principal_attributes,
            "_scope": scope,
            "_properties": [
                {
                    "_key": "com.opentext.otds.as.drivers.saml.provider_name",
                    "_name": "Identity Provider (IdP) Name",
                    "_description": "The name of the identity provider. This should be a single word since it will be part of the metadata URL.",
                    "_value": provider_name,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.provider_metadata_description",
                    "_name": "IdP Metadata URL",
                    "_description": "The URL for the IdP's federation metadata. The metadata will be automatically updated by OTDS daily at midnight.",
                    "_value": saml_url,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.provider_nameid_format",
                    "_name": "IdP NameID Format",
                    "_description": "Specifies which NameID format supported by the identity provider contains the desired user identifier. The value in this identifier must correspond to the value of the user attribute specified for the authentication principal attribute. This value is usually set to urn:oasis:names:tc:SAML:2.0:nameid-format:persistent or urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress. Please ensure this is consistent with the identity provider's configuration.",
                    "_value": nameid_format,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml._impersonator_claim",
                    "_name": "Claim for impersonating user",
                    "_description": "A claim that contains the ID of the actor/impersonator for the user identified by NameID. It must be in the same format as NameID.",
                    "_value": "loggedinuserid",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.sp_url",
                    "_name": "OTDS SP Endpoint",
                    "_description": "Specifies the service provider URL that will be used to identify OTDS to the identity provider. If not specified, the URL will be taken from the request. This generally needs to be configured for environments in which OTDS is behind a reverse-proxy.",
                    "_value": otds_sp_endpoint,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.enable_sp_sso",
                    "_name": "Active By Default",
                    "_description": "Whether to activate this handler for any request to the OTDS login page. If true, any login request to the OTDS login page will be redirected to the IdP. If false, the user has to select the provider on the login page.",
                    "_value": active_by_default,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml._signature_alg",
                    "_name": "XML Signature Algorithm",
                    "_description": "Only relevant when certificate and private key are configured. Default is http://www.w3.org/2000/09/xmldsig#rsa-sha1. Valid values are defined at http://www.w3.org/TR/xmldsig-core1/#sec-AlgID.",
                    "_value": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.use_acs_url",
                    "_name": "Use AssertionConsumerServiceURL",
                    "_description": "Set to true to have the SAML AuthnRequest use AssertionConsumerServiceURL instead of AssertionConsumerServiceIndex",
                    "_value": "true",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.grace_period",
                    "_name": "Grace Period",
                    "_description": 'Specifies the number of minutes to allow for "NotBefore" and "NotOnOrAfter" fields when validating assertions in order to account for time difference between the identity provider and this service provider.',
                    "_value": "5",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.auth_request_binding",
                    "_name": "Auth Request Binding",
                    "_description": "Specifies the preferred SAML binding to use for sending the AuthnRequest, provided it is supported by the identity provider.",
                    "_value": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.auth_response_binding",
                    "_name": "Auth Response Binding",
                    "_description": "Specifies the SAML binding to use for the response to an AuthnRequest",
                    "_value": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim1",
                    "_name": "Claim 1",
                    "_description": "SAML attribute/claim that should be mapped to an OTDS user attribute. This value is case sensitive. Note that mapped claims are only relevant if the corresponding account is auto-provisioned in OTDS. See the Administration Guide for details.",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute1",
                    "_name": "OTDS Attribute 1",
                    "_description": "OTDS user attribute to which the SAML attribute/claim should be mapped",
                    "_value": "mail",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim2",
                    "_name": "Claim 2",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute2",
                    "_name": "OTDS Attribute 2",
                    "_value": "givenName",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim3",
                    "_name": "Claim 3",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute3",
                    "_name": "OTDS Attribute 3",
                    "_value": "sn",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim4",
                    "_name": "Claim 4",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute4",
                    "_name": "OTDS Attribute 4",
                    "_value": "displayName",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim5",
                    "_name": "Claim 5",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute5",
                    "_name": "OTDS Attribute 5",
                    "_value": "oTStreetAddress",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim6",
                    "_name": "Claim 6",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute6",
                    "_name": "OTDS Attribute 6",
                    "_value": "l",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim7",
                    "_name": "Claim 7",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/stateorprovince",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute7",
                    "_name": "OTDS Attribute 7",
                    "_value": "st",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim8",
                    "_name": "Claim 8",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute8",
                    "_name": "OTDS Attribute 8",
                    "_value": "postalCode",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim9",
                    "_name": "Claim 9",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute9",
                    "_name": "OTDS Attribute 9",
                    "_value": "countryName",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim10",
                    "_name": "Claim 10",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/otherphone",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute10",
                    "_name": "OTDS Attribute 10",
                    "_value": "oTTelephoneNumber",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim11",
                    "_name": "Claim 11",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/homephone",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute11",
                    "_name": "OTDS Attribute 11",
                    "_value": "homePhone",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim12",
                    "_name": "Claim 12",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute12",
                    "_name": "OTDS Attribute 12",
                    "_value": "birthDate",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim13",
                    "_name": "Claim 13",
                    "_value": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute13",
                    "_name": "OTDS Attribute 13",
                    "_value": "gender",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim14",
                    "_name": "Claim 14",
                    "_value": "",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute14",
                    "_name": "OTDS Attribute 14",
                    "_value": "",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim15",
                    "_name": "Claim 15",
                    "_value": "http://schemas.xmlsoap.org/claims/Group",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute15",
                    "_name": "OTDS Attribute 15",
                    "_value": "oTMemberOf",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim16",
                    "_name": "Claim 16",
                    "_value": "http://schemas.xmlsoap.org/claims/Department",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute16",
                    "_name": "OTDS Attribute 16",
                    "_value": "oTDepartment",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim17",
                    "_name": "Claim 17",
                    "_value": "http://schemas.xmlsoap.org/claims/Title",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute17",
                    "_name": "OTDS Attribute 17",
                    "_value": "title",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim18",
                    "_name": "Claim 18",
                    "_value": "",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute18",
                    "_name": "OTDS Attribute 18",
                    "_value": "",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim19",
                    "_name": "Claim 19",
                    "_value": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute19",
                    "_name": "OTDS Attribute 19",
                    "_value": "oTMemberOf",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claim20",
                    "_name": "Claim 20",
                    "_value": "",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.claimAttribute20",
                    "_name": "OTDS Attribute 20",
                    "_value": "",
                },
            ],
        }

        request_url = self.auth_handler_url()

        self.logger.debug(
            "Adding SAML auth handler -> '%s' ('%s'); calling -> %s",
            name,
            description,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=auth_handler_post_body_json,
            timeout=None,
            failure_message="Failed to add SAML auth handler -> '{}'".format(name),
        )

    # end method definition

    def add_auth_handler_sap(
        self,
        name: str,
        description: str,
        scope: str | None,
        certificate_file: str,
        certificate_password: str,
        enabled: bool = True,
        priority: int = 10,
        auth_principal_attributes: list | None = None,
    ) -> dict | None:
        """Add a new SAP authentication handler.

        Args:
            name (str):
                The name of the new authentication handler.
            description (str):
                The description of the new authentication handler.
            scope (str):
                The name of the user partition (to define a scope of the auth handler)
            certificate_file (str):
                A fully qualified file name (with path) to the certificate file.
            certificate_password (str):
                The password of the certificate.
            enabled (bool, optional):
                Defines if the handler should be enabled or disabled. Default is True = enabled.
            priority (int, optional):
                Priority of the Authentical Handler (compared to others). Default is 10.
            auth_principal_attributes (list, optional):
                List of Authentication principal attributes.

        Returns:
            dict | None: Request response (json) or None if the REST call fails.

        """

        # Avoid linter warning W0102 by establishing the default value inside the method:
        if auth_principal_attributes is None:
            auth_principal_attributes = ["oTExternalID1"]

        # 1. Prepare the body for the AuthHandler REST call:
        auth_handler_post_body_json = {
            "_name": name,
            "_description": description,
            "_class": "com.opentext.otds.as.drivers.sapssoext.SAPSSOEXTAuthHandler",
            "_enabled": str.lower(str(enabled)),
            "_priority": str(priority),
            "_authPrincipalAttrNames": auth_principal_attributes,
            "_scope": scope,
            "_properties": [
                {
                    "_key": "com.opentext.otds.as.drivers.sapssoext.certificate_description1",
                    "_name": "SAP Certificate 1 Description",
                    "_description": "Specifies a custom description for the corresponding certificate.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": os.path.basename(
                        certificate_file,
                    ),  # "TM6_Sandbox.pse" - file name only
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.sapssoext.certificate1",
                    "_name": "SAP Certificate (PSE) 1",
                    "_description": "Specifies a certificate (.pse file) to use to decode SAP tokens. Note: The selected file does not need to reside on the server since only its contents will be stored on the server. Clear the string in this field in order to delete the certificate stored on the server.",
                    "_required": False,
                    "_fileBased": True,
                    "_fileName": False,
                    "_fileExtensions": ["pse"],
                    "_value": None,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.sapssoext.certificate_pass1",
                    "_name": "SAP Certificate 1 Password",
                    "_description": "Specifies the password for the corresponding .pse file.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": certificate_password,
                    "_allowedValues": None,
                    "_confidential": True,
                    "_keepOriginal": False,
                },
            ],
        }

        # 2. Create the auth handler in OTDS
        request_url = self.auth_handler_url()

        self.logger.debug(
            "Adding SAP auth handler -> '%s' ('%s'); calling -> %s",
            name,
            description,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=auth_handler_post_body_json,
            timeout=None,
            failure_message="Failed to add SAP auth handler -> '{}'".format(name),
            parse_request_response=False,
        )
        if not response or not response.ok:
            return None

        # 3. Upload the certificate file:

        # Check that the certificate (PSE) file is readable:
        self.logger.debug("Reading certificate file -> '%s'...", certificate_file)
        try:
            # PSE files are binary - so we need to open with "rb":
            with open(certificate_file, "rb") as cert_file:
                cert_content = cert_file.read()
                if not cert_content:
                    self.logger.error(
                        "No data in certificate file -> '%s'!",
                        certificate_file,
                    )
                    return None
        except OSError:
            self.logger.error(
                "Unable to open certificate file -> '%s'!",
                certificate_file,
            )
            return None

        # Check that we have the binary certificate file - this is what OTDS expects. If the file content is
        # base64 encoded we will decode it and write it back into the same file
        try:
            # If file is not base64 encoded the next statement will throw an exception
            cert_content_decoded = base64.b64decode(cert_content, validate=True)
            cert_content_encoded = base64.b64encode(cert_content_decoded).decode(
                "utf-8",
            )
            if cert_content_encoded == cert_content.decode("utf-8"):
                self.logger.debug(
                    "Certificate file -> '%s' is base64 encoded",
                    certificate_file,
                )
                cert_file_encoded = True
            else:
                cert_file_encoded = False
        except TypeError:
            self.logger.debug(
                "Certificate file -> '%s' is not base64 encoded!",
                certificate_file,
            )
            cert_file_encoded = False

        if cert_file_encoded:
            certificate_file = os.path.join(tempfile.gettempdir(), os.path.basename(certificate_file))
            self.logger.debug(
                "Writing decoded certificate file -> %s...",
                certificate_file,
            )
            try:
                # PSE files need to be binary - so we need to open with "wb":
                with open(certificate_file, "wb") as cert_file:
                    cert_file.write(base64.b64decode(cert_content))
            except OSError:
                self.logger.error(
                    "Failed writing to file -> '%s'!",
                    certificate_file,
                )
                return None

        auth_handler_post_data = {
            "file1_property": "com.opentext.otds.as.drivers.sapssoext.certificate1",
        }

        request_url = self.auth_handler_url() + "/" + name + "/files"

        self.logger.debug(
            "Uploading certificate file -> '%s' for SAP auth handler -> '%s' ('%s'); calling -> %s",
            certificate_file,
            name,
            description,
            request_url,
        )

        # It is important to send the file pointer and not the actual file content
        # otherwise the file is sent base64 encoded, which we don't want:
        with open(certificate_file, "rb") as file_obj:
            auth_handler_post_files = {
                "file1": (
                    os.path.basename(certificate_file),
                    file_obj,
                    "application/octet-stream",
                ),
            }

            # It is important to NOT pass the headers parameter here!
            # Basically, if you specify a files parameter (a dictionary),
            # then requests will send a multipart/form-data POST automatically:
            response = requests.post(
                url=request_url,
                data=auth_handler_post_data,
                files=auth_handler_post_files,
                cookies=self.cookie(),
                timeout=REQUEST_TIMEOUT,
            )

        if not response.ok:
            self.logger.error(
                "Failed to upload certificate file -> '%s' for SAP auth handler -> '%s'; error -> %s (%s)",
                certificate_file,
                name,
                response.text,
                response.status_code,
            )
            return None

        return response

    # end method definition

    def add_auth_handler_oauth(
        self,
        name: str,
        description: str,
        scope: str | None,
        provider_name: str,
        client_id: str,
        client_secret: str,
        active_by_default: bool = False,
        authorization_endpoint: str = "",
        token_endpoint: str = "",
        scope_string: str = "",
        enabled: bool = True,
        priority: int = 10,
        auth_principal_attributes: list | None = None,
    ) -> dict | None:
        """Add a new OAuth authentication handler.

        Args:
            name (str):
                The name of the new authentication handler.
            description (str):
                The description of the new authentication handler.
            scope (str):
                The name of the user partition (to define a scope of the auth handler).
            provider_name (str):
                The name of the authentication provider. This name is displayed on the login page.
            client_id (str):
                The client ID.
            client_secret (str):
                The client secret.
            active_by_default (bool, optional):
                Defines, whether to activate this handler for any request to the OTDS login page.
                If True, any login request to the OTDS login page will be redirected to this OAuth provider.
                If False, the user has to select the provider on the login page.
            authorization_endpoint (str, optional):
                The URL to redirect the browser to for authentication.
                It is used to retrieve the authorization code or an OIDC id_token.
            token_endpoint (str, optional):
                The URL from which to retrieve the access token.
                Not strictly required with OpenID Connect if using the implicit flow.
            scope_string (str, optional):
                Space delimited scope values to send. Include 'openid' to use OpenID Connect.
            enabled (bool, optional):
                Defines if the handler should be enabled or disabled. Default is True = enabled.
            priority (int, optional):
                Priority of the Authentical Handler (compared to others). Default is 5.
            auth_principal_attributes (list, optional):
                List of Authentication principal attributes.

        Returns:
            dict | None:
                Request response (dictionary) or None if the REST call fails.

        """

        # Avoid linter warning W0102:
        if auth_principal_attributes is None:
            auth_principal_attributes = ["oTExtraAttr0"]

        # 1. Prepare the body for the AuthHandler REST call:
        auth_handler_post_body_json = {
            "_name": name,
            "_description": description,
            "_class": "com.opentext.otds.as.drivers.http.OAuth2Handler",
            "_enabled": str.lower(str(enabled)),
            "_priority": str(priority),
            "_authPrincipalAttrNames": auth_principal_attributes,
            "_scope": scope,
            "_properties": [
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.provider_name",
                    "_name": "Provider Name",
                    "_description": "The name of the authentication provider. This name is displayed on the login page.",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": provider_name,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.active_by_default",
                    "_name": "Active By Default",
                    "_description": "Whether to activate this handler for any request to the OTDS login page. If true, any login request to the OTDS login page will be redirected to this OAuth provider. If false, the user has to select the provider on the login page.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": active_by_default,
                    "_allowedValues": ["true", "false"],
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.client_id",
                    "_name": "Client ID",
                    "_description": "The Client ID",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": client_id,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.client_secret",
                    "_name": "Client Secret",
                    "_description": "The Client Secret",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": client_secret,
                    "_allowedValues": None,
                    "_confidential": True,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.scope_string",
                    "_name": "Scope String",
                    "_description": "Space delimited scope values to send. Include 'openid' to use OpenID Connect.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": scope_string,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.get_code_url",
                    "_name": "Authorization Endpoint",
                    "_description": "The URL to redirect the browser to for authentication. It is used to retrieve the authorization code or an OIDC id_token.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": authorization_endpoint,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.get_access_token_url",
                    "_name": "Token Endpoint",
                    "_description": "The URL from which to retrieve the access token. Not strictly required with OpenID Connect if using the implicit flow.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": token_endpoint,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.get_user_info_url",
                    "_name": "User Info Endpoint",
                    "_description": "The URL from which to retrieve the JSON object representing the authorized user",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "{id}",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.user_identifier",
                    "_name": "User Identifier Field",
                    "_description": "The field corresponding to the user's unique ID at this provider",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "username",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.field1",
                    "_name": "Response Field 1",
                    "_description": "A field in the JSON response that should be mapped to an OTDS attribute. This value is case sensitive. Mapped fields are only relevant for auto-provisioned accounts.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "email",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute1",
                    "_name": "OTDS Attribute 1",
                    "_description": "OTDS user attribute to which the response field should be mapped.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "mail",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.field2",
                    "_name": "Response Field 2",
                    "_description": "",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "first_name",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute2",
                    "_name": "OTDS Attribute 2",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "givenName",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.field3",
                    "_name": "Response Field 3",
                    "_description": "",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "last_name",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute3",
                    "_name": "OTDS Attribute 3",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "sn",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute4",
                    "_name": "OTDS Attribute 4",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "displayName",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute5",
                    "_name": "OTDS Attribute 5",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTStreetAddress",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute6",
                    "_name": "OTDS Attribute 6",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "l",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute7",
                    "_name": "OTDS Attribute 7",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "st",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute8",
                    "_name": "OTDS Attribute 8",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "postalCode",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute9",
                    "_name": "OTDS Attribute 9",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "countryName",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute10",
                    "_name": "OTDS Attribute 10",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTTelephoneNumber",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute11",
                    "_name": "OTDS Attribute 11",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTMemberOf",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute12",
                    "_name": "OTDS Attribute 12",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTDepartment",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute13",
                    "_name": "OTDS Attribute 13",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "title",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
            ],
        }

        request_url = self.auth_handler_url()

        self.logger.debug(
            "Adding OAuth auth handler -> '%s' ('%s'); calling -> %s",
            name,
            description,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=auth_handler_post_body_json,
            timeout=None,
            failure_message="Failed to add OAuth auth handler -> '{}'".format(name),
        )

        # end method definition

    def consolidate(self, resource_name: str) -> bool:
        """Consolidate an OTDS resource.

        Args:
            resource_name (str):
                The name of the resource to be consolidated.

        Returns:
            bool:
                True, if the consolidation succeeded or False if it failed.

        """

        resource = self.get_resource(resource_name)
        if not resource:
            self.logger.error(
                "Resource -> '%s' not found - cannot consolidate!",
                resource_name,
            )
            return False

        resource_dn = resource["resourceDN"]
        if not resource_dn:
            self.logger.error("Resource DN is empty - cannot consolidate!")
            return False

        consolidation_post_body_json = {
            "cleanupUsersInResource": False,
            "cleanupGroupsInResource": False,
            "resourceList": [resource_dn],
            "objectToConsolidate": resource_dn,
        }

        request_url = "{}".format(self.consolidation_url())

        self.logger.debug(
            "Consolidation of resource -> '%s' (%s); calling -> %s",
            resource_name,
            resource_dn,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=consolidation_post_body_json,
            timeout=None,
            failure_message="Failed to consolidate resource -> '{}'".format(
                resource_name,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def impersonate_resource(
        self,
        resource_name: str,
        allow_impersonation: bool = True,
        impersonation_list: list | None = None,
    ) -> bool:
        """Configure impersonation for an OTDS resource.

        Args:
             resource_name (str):
                 Name of the resource to configure impersonation for.
             allow_impersonation (bool, optional):
                 Whether to turn on or off impersonation (default = True)
             impersonation_list (list, optional):
                 A list of users to restrict it to (default = empty list = all users)

        Returns:
             bool:
                True if the impersonation setting succeeded or False if it failed.

        """

        # Avoid linter warning W0102:
        if impersonation_list is None:
            impersonation_list = []

        impersonation_put_body_json = {
            "allowImpersonation": allow_impersonation,
            "impersonateList": impersonation_list,
        }

        request_url = "{}/{}/impersonation".format(self.resource_url(), resource_name)

        self.logger.debug(
            "Impersonation settings for resource -> '%s'; calling -> %s",
            resource_name,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="PUT",
            json_data=impersonation_put_body_json,
            timeout=None,
            failure_message="Failed to set impersonation for resource -> '{}'".format(
                resource_name,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def impersonate_oauth_client(
        self,
        client_id: str,
        allow_impersonation: bool = True,
        impersonation_list: list | None = None,
    ) -> bool:
        """Configure impersonation for an OTDS OAuth Client.

        Args:
            client_id (str):
                The ID of the OAuth Client to configure impersonation for.
            allow_impersonation (bool | None, optional):
                Defines whether to turn on or off impersonation (default = True).
            impersonation_list (list | None, optional):
                A list of users to restrict it to; (default = empty list = all users).

        Returns:
            bool:
                True if the impersonation setting succeeded or False if it failed.

        """

        # Avoid linter warning W0102 by establishing the default inside the method:
        if impersonation_list is None:
            impersonation_list = []

        impersonation_put_body_json = {
            "allowImpersonation": allow_impersonation,
            "impersonateList": impersonation_list,
        }

        request_url = "{}/{}/impersonation".format(self.oauth_client_url(), client_id)

        self.logger.debug(
            "Impersonation settings for OAuth Client -> '%s'; calling -> %s",
            client_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="PUT",
            json_data=impersonation_put_body_json,
            timeout=None,
            failure_message="Failed to set impersonation for OAuth Client -> '{}'".format(
                client_id,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

    def get_password_policy(self) -> dict | None:
        """Get the global password policy.

        Args:
            None

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        Example:
            {
                'passwordHistoryMaximumCount': 3,
                'daysBeforeNewPasswordMayBeChanged': 1,
                'passwordMaximumDuration': 90,
                'daysBeforeOldPasswordMayBeReused': 0,
                'lockoutFailureCount': 0,
                'lockoutDuration': 15,
                'minimumNumberOfCharacters': 8,
                'complexPasswordValidationEnabled': True,
                'minimumNumberOfDigits': 1,
                'minimumNumberOfSymbols': 1,
                'minimumNumberOfUppercase': 1,
                'minimumNumberOfLowercase': 1,
                'minimumChangesToPreviousPassword': 0,
                'maxNumberOfConsecutiveANCharsInPassword': 0,
                'blockCommonPassword': False
                ...
            }

        """

        request_url = "{}/passwordpolicy".format(self.config()["systemConfigUrl"])

        self.logger.debug("Getting password policy; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            timeout=None,
            failure_message="Failed to get password policy",
        )

    # end method definition

    def update_password_policy(self, update_values: dict) -> bool:
        """Update the global password policy.

        Args:
            update_values (dict):
                New values for selected settings.
                A value of 0 means the settings is deactivated.

        Example:
            {
                'passwordHistoryMaximumCount': 3,
                'daysBeforeNewPasswordMayBeChanged': 1,
                'passwordMaximumDuration': 90,
                'daysBeforeOldPasswordMayBeReused': 0,
                'lockoutFailureCount': 0,
                'lockoutDuration': 15,
                'minimumNumberOfCharacters': 8,
                'complexPasswordValidationEnabled': True,
                'minimumNumberOfDigits': 1,
                'minimumNumberOfSymbols': 1,
                'minimumNumberOfUppercase': 1,
                'minimumNumberOfLowercase': 1,
                'minimumChangesToPreviousPassword': 0,
                'maxNumberOfConsecutiveANCharsInPassword': 0,
                'blockCommonPassword': False
                ...
            }

        Returns:
            bool:
                True if the REST call succeeds, otherwise False. We use a boolean return
                value as the response of the REST call does not have meaningful content.

        """

        request_url = "{}/passwordpolicy".format(self.config()["systemConfigUrl"])

        self.logger.debug(
            "Update password policy with these new values -> %s; calling -> %s",
            str(update_values),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="PUT",
            json_data=update_values,
            timeout=None,
            failure_message="Failed to update password policy with values -> {}".format(
                update_values,
            ),
            parse_request_response=False,
        )

        return bool(response and response.ok)

    # end method definition

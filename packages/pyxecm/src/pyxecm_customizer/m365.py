"""M365 Module to interact with the MS Graph API.

See also https://learn.microsoft.com/en-us/graph/
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import os
import re
import time
import urllib.parse
import zipfile
from datetime import UTC, datetime
from http import HTTPStatus
from urllib.parse import quote

import requests
from pyxecm.helper import HTTP

from .browser_automation import BrowserAutomation

default_logger = logging.getLogger("pyxecm_customizer.m365")

request_login_headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}

REQUEST_TIMEOUT = 60.0
REQUEST_RETRY_DELAY = 20.0
REQUEST_MAX_RETRIES = 3


class M365:
    """Used to automate stettings in Microsoft 365 via the Graph API."""

    logger: logging.Logger = default_logger

    _config: dict
    _access_token = None
    _user_access_token = None
    _http_object: HTTP | None = None

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        domain: str,
        sku_id: str,
        teams_app_name: str,
        teams_app_external_id: str,
        sharepoint_app_root_site: str = "",
        sharepoint_app_client_id: str = "",
        sharepoint_app_client_secret: str = "",
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the M365 object.

        Args:
            tenant_id (str):
                The M365 Tenant ID.
            client_id (str):
                The M365 Client ID.
            client_secret (str):
                The M365 Client Secret.
            domain (str):
                The M365 domain.
            sku_id (str):
                License SKU for M365 users.
            teams_app_name (str):
                The name of the Extended ECM app for MS Teams.
            teams_app_external_id (str):
                The external ID of the Extended ECM app for MS Teams
            sharepoint_app_root_site (str):
                The URL to the SharePoint root site.
            sharepoint_app_client_id (str):
                The SharePoint App client ID.
            sharepoint_app_client_secret (str):
                The SharePoint App client secret.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("m365")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        m365_config = {}

        # Set the authentication endpoints and credentials
        m365_config["tenantId"] = tenant_id
        m365_config["clientId"] = client_id
        m365_config["clientSecret"] = client_secret
        m365_config["domain"] = domain
        m365_config["skuId"] = sku_id
        m365_config["teamsAppName"] = teams_app_name
        m365_config["teamsAppExternalId"] = teams_app_external_id  # this is the external App ID
        m365_config["teamsAppInternalId"] = None  # will be set later...
        m365_config["sharepointAppRootSite"] = sharepoint_app_root_site
        m365_config["sharepointAppClientId"] = sharepoint_app_client_id
        m365_config["sharepointAppClientSecret"] = sharepoint_app_client_secret
        m365_config["authenticationUrl"] = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(tenant_id)
        m365_config["graphUrl"] = "https://graph.microsoft.com/v1.0/"
        m365_config["betaUrl"] = "https://graph.microsoft.com/beta/"
        m365_config["directoryObjects"] = m365_config["graphUrl"] + "directoryObjects"

        # Set the data for the token request
        m365_config["tokenData"] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }

        m365_config["meUrl"] = m365_config["graphUrl"] + "me"
        m365_config["groupsUrl"] = m365_config["graphUrl"] + "groups"
        m365_config["usersUrl"] = m365_config["graphUrl"] + "users"
        m365_config["teamsUrl"] = m365_config["graphUrl"] + "teams"
        m365_config["teamsTemplatesUrl"] = m365_config["graphUrl"] + "teamsTemplates"
        m365_config["teamsAppsUrl"] = m365_config["graphUrl"] + "appCatalogs/teamsApps"
        m365_config["directoryUrl"] = m365_config["graphUrl"] + "directory"
        m365_config["securityUrl"] = m365_config["betaUrl"] + "security"
        m365_config["applicationsUrl"] = m365_config["graphUrl"] + "applications"

        m365_config["sitesUrl"] = m365_config["betaUrl"] + "sites"

        self._config = m365_config
        self._http_object = HTTP(logger=self.logger)

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """

        return self._config

    def credentials(self) -> dict:
        """Return the login credentials.

        Returns:
            dict:
                A dictionary with (admin) login credentials for M365.

        """

        return self.config()["tokenData"]

    def credentials_user(self, username: str, password: str, scope: str = "Files.ReadWrite") -> dict:
        """Get user credentials.

        In some cases MS Graph APIs cannot be called via
        application permissions (client_id, client_secret)
        but requires a token of a user authenticated
        with username + password. This is e.g. the case
        to upload a MS teams app to the catalog.

        See https://learn.microsoft.com/en-us/graph/api/teamsapp-publish

        Args:
            username (str):
                The M365 username.
            password (str):
                The password of the M365 user.
            scope (str):
                The scope of the delegated permission.
                It is important to provide a scope for the intended operation
                like "Files.ReadWrite".

        Returns:
            dict:
                A dictionary with the (user) credentials for M365.

        """

        # Use OAuth2 / ROPC (Resource Owner Password Credentials):
        credentials = {
            "client_id": self.config()["clientId"],
            "client_secret": self.config()["clientSecret"],
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": scope,
        }

        return credentials

    # end method definition

    def request_header(self, content_type: str = "application/json") -> dict:
        """Return the request header used for Application calls.

        Consists of Bearer access token and Content Type.

        Args:
            content_type (str, optional):
                The content type for the request. Default is "application/json".

        Returns:
            dict:
                The request header values.

        """

        request_header = {
            "Authorization": "Bearer {}".format(self._access_token),
            "Content-Type": content_type,
        }

        return request_header

    # end method definition

    def request_header_user(self, content_type: str = "application/json") -> dict:
        """Return the request header used for user specific calls.

        Consists of Bearer access token and Content Type.

        Args:
            content_type (str, optional):
                The content type for the request.

        Returns:
            dict:
                The request header values.

        """

        request_header = {
            "Content-Type": content_type,
        }

        if not self._user_access_token:
            self.logger.error("No M365 user is authenticated! Cannot include Bearer token in request header!")
        else:
            request_header["Authorization"] = "Bearer {}".format(self._user_access_token)

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
        params: dict | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        show_warning: bool = False,
        warning_message: str = "",
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
        parse_request_response: bool = True,
        stream: bool = False,
    ) -> dict | None:
        """Call an M365 Graph API in a safe way.

        Args:
            url (str):
                URL to send the request to.
            method (str, optional):
                HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                Request Headers. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None.
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            params (dict | None, optional):
                Add key-value pairs to the query string of the URL.
                When you use the params parameter, requests automatically appends
                the key-value pairs to the URL as part of the query string
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
                Defines whether the response.text should be interpreted as json and loaded into a dictionary.
                True is the default.
            stream (bool, optional):
                This parameter is used to control whether the response content should be immediately
                downloaded or streamed incrementally.

        Returns:
            dict | None:
                Response of M365 Graph REST API or None in case of an error.

        """

        if headers is None:
            self.logger.error(
                "Missing request header. Cannot send request to Microsoft M365 Graph API!",
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
                    params=params,
                    headers=headers,
                    timeout=timeout,
                    stream=stream,
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
                    self.logger.debug("Session has expired - try to re-authenticate...")
                    self.authenticate(revalidate=True)
                    headers = self.request_header()
                    retries += 1
                elif response.status_code in [502, 503, 504] and retries < REQUEST_MAX_RETRIES:
                    self.logger.warning(
                        "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                        response.status_code,
                        (retries + 1) * 60,
                    )
                    time.sleep((retries + 1) * 60)
                    retries += 1
                elif response.status_code in [404, 429] and retries < REQUEST_MAX_RETRIES:
                    self.logger.warning(
                        "M365 Graph API is too slow or throtteling calls -> %s; retrying in %s seconds...",
                        response.status_code,
                        (retries + 1) * 60,
                    )
                    time.sleep((retries + 1) * 60)
                    retries += 1
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
        """Convert the request response (JSon) to a Python dict in a safe way.

        It first tries to load the response.text via json.loads() that produces a
        dict output. Only if response.text is not set or is empty it just converts the
        response_object to a dict using the vars() built-in method.

        Args:
            response_object (object):
                This is reponse object delivered by the request call.
            additional_error_message (str, optional):
                Use a more specific error message in case of an error.
            show_error (bool, optional):
                True: write an error to the log file
                False: write a warning to the log file

        Returns:
            dict:
                API response information or None in case of an error.

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

    def exist_result_item(
        self,
        response: dict | None,
        key: str,
        value: str,
        sub_dict_name: str = "",
    ) -> bool:
        """Check existence of key / value pair in the response properties of an MS Graph API call.

        Args:
            response (dict | None):
                REST response from an MS Graph REST Call.
            key (str):
                The property name (key).
            value (str):
                The value to find in the item with the matching key
            sub_dict_name (str, optional):
                Some MS Graph API calls include nested dict structures that can be requested
                with an "expand" query parameter. In such a case we use the sub_dict_name to
                access it.

        Returns:
            bool:
                True if the value was found, False otherwise

        """

        if not response:
            return False
        if "value" not in response:
            return False

        values = response["value"]
        if not values or not isinstance(values, list):
            return False

        if not sub_dict_name:
            for item in values:
                if value == item[key]:
                    return True
        else:
            for item in values:
                if sub_dict_name not in item:
                    return False
                if value == item[sub_dict_name][key]:
                    return True

        return False

    # end method definition

    def get_result_value(
        self,
        response: dict | None,
        key: str,
        index: int = 0,
        sub_dict_name: str = "",
    ) -> str | None:
        """Get value of a result property with a given key of an MS Graph API call.

        Args:
            response (dict | None):
                REST response from an MS Graph REST Call.
            key (str):
                The property name (key).
            index (int, optional):
                Index to use (1st element has index 0).
                Defaults to 0.
            sub_dict_name (str):
                Some MS Graph API calls include nested dict structures that can
                be requested with an "expand" query parameter. In such
                a case we use the sub_dict_name to access it.

        Returns:
            str | None:
                The value for the key, None otherwise.

        """

        if not response:
            return None
        if "value" not in response:  # If Graph APIs are called with specific IDs (and not name lookups)
            # they may not return a list of dicts calles "values" but a single dict directly
            if sub_dict_name and sub_dict_name in response:
                sub_structure = response[sub_dict_name]
                # also the substructure could be a list
                if isinstance(sub_structure, list):
                    sub_structure = sub_structure[index]
                return sub_structure[key]
            elif key in response:
                return response[key]
            else:
                return None

        values = response["value"]
        if not values or not isinstance(values, list) or len(values) - 1 < index:
            return None

        if not sub_dict_name:
            return values[index][key]
        else:
            sub_structure = values[index][sub_dict_name]
            if isinstance(sub_structure, list):
                # here we assume it is the first element of the
                # substructure. If really required for specific
                # use cases we may introduce a second index in
                # the future.
                sub_structure = sub_structure[0]
            return sub_structure[key]

    # end method definition

    def lookup_result_value(
        self,
        response: dict,
        key: str,
        value: str,
        return_key: str,
        sub_dict_name: str = "",
    ) -> str | None:
        """Look up a property value for a provided key-value pair of a REST response.

        Args:
            response (dict):
                The REST response from an OTCS REST call, containing property data.
            key (str):
                Property name (key) to match in the response.
            value (str):
                Value to find in the item with the matching key.
            return_key (str):
                Name of the dictionary key whose value should be returned.
            sub_dict_name (str):
                Some MS Graph API calls include nested dict structures that can
                be requested with an "expand" query parameter. In such
                a case we use the sub_dict_name to access it.

        Returns:
            str | None:
                The value of the property specified by "return_key" if found,
                or None if the lookup fails.

        """

        if not response:
            return None

        results = response.get("value", response)

        # check if results is a list or a dict (both is possible -
        # dependent on the actual REST API):
        if isinstance(results, dict):
            # result is a dict - we don't need index value:
            if sub_dict_name and sub_dict_name in results:
                results = results[sub_dict_name]
            if key in results and results[key] == value and return_key in results:
                return results[return_key]
            else:
                return None
        elif isinstance(results, list):
            # result is a list - we need index value
            for result in results:
                if sub_dict_name and sub_dict_name in result:
                    result = result[sub_dict_name]
                if key in result and result[key] == value and return_key in result:
                    return result[return_key]
            return None
        else:
            self.logger.error(
                "Result needs to be a list or dictionary but it is of type -> '%s'!",
                str(type(results)),
            )
            return None

    # end method definition

    def authenticate(self, revalidate: bool = False) -> str | None:
        """Authenticate at M365 Graph API with client ID and client secret.

        Args:
            revalidate (bool, optional):
                Determins if a re-athentication is enforced.
                (e.g. if session has timed out with 401 error)

        Returns:
            str | None:
                The access token. Also stores access token in self._access_token.
                None in case of an error.

        """

        # Already authenticated and session still valid?
        if self._access_token and not revalidate:
            self.logger.debug(
                "Session still valid - return existing access token -> %s",
                str(self._access_token),
            )
            return self._access_token

        request_url = self.config()["authenticationUrl"]
        request_header = request_login_headers

        self.logger.debug("Requesting M365 Access Token from -> %s", request_url)

        authenticate_post_body = self.credentials()
        authenticate_response = None

        try:
            authenticate_response = requests.post(
                request_url,
                data=authenticate_post_body,
                headers=request_header,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.ConnectionError as exception:
            self.logger.warning(
                "Unable to connect to -> %s : %s",
                self.config()["authenticationUrl"],
                str(exception),
            )
            return None

        if authenticate_response.ok:
            authenticate_dict = self.parse_request_response(authenticate_response)
            if not authenticate_dict:
                return None
            access_token = authenticate_dict["access_token"]
            self.logger.debug("Access Token -> %s", access_token)
        else:
            self.logger.error(
                "Failed to request an M365 Access Token; error -> %s",
                authenticate_response.text,
            )
            return None

        # Store authentication access_token:
        self._access_token = access_token

        return self._access_token

    # end method definition

    def authenticate_user(self, username: str, password: str, scope: str | None = None) -> str | None:
        """Authenticate at M365 Graph API with username and password.

        Args:
            username (str):
                The name (email) of the M365 user.
            password (str):
                The password of the M365 user.
            scope (str):
                The scope of the delegated permission. E.g. "Files.ReadWrite".
                Multiple delegated permissions should be separated by spaces.

        Returns:
            str | None:
                The access token for the user. Also stores access token in self._access_token.
                None in case of an error.

        """

        request_url = self.config()["authenticationUrl"]
        request_header = request_login_headers

        if not username:
            self.logger.error("Missing user name - cannot authenticate at M365!")
            return None
        if not password:
            self.logger.error(
                "Missing password for user -> '%s' - cannot authenticate at M365!",
                username,
            )
            return None

        self.logger.debug(
            "Requesting M365 Access Token for user -> %s from -> %s%s",
            username,
            request_url,
            " with scope -> '{}'".format(scope) if scope else "",
        )

        authenticate_post_body = self.credentials_user(username=username, password=password, scope=scope)
        authenticate_response = None

        try:
            authenticate_response = requests.post(
                request_url,
                data=authenticate_post_body,
                headers=request_header,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.ConnectionError as exception:
            self.logger.warning(
                "Unable to connect to -> %s with username -> %s: %s",
                self.config()["authenticationUrl"],
                username,
                str(exception),
            )
            return None

        if authenticate_response.ok:
            authenticate_dict = self.parse_request_response(authenticate_response)
            if not authenticate_dict:
                return None
            access_token = authenticate_dict["access_token"]
            self.logger.debug("User Access Token -> %s", access_token)
        else:
            self.logger.error(
                "Failed to request an M365 Access Token for user -> '%s'; error -> %s",
                username,
                authenticate_response.text,
            )
            return None

        # Store authentication access_token:
        self._user_access_token = access_token

        return self._user_access_token

    # end method definition

    def get_users(self, max_number: int = 250, next_page_url: str | None = None) -> dict | None:
        """Get list all all users in M365 tenant.

        Args:
            max_number (int, optional):
                The maximum result values (limit).
            next_page_url (str, optional):
                The MS Graph URL to retrieve the next page of M365 users (pagination).
                This is used for the iterator get_users_iterator() below.

        Returns:
            dict | None:
                Dictionary of all M365 users.

        """

        request_url = next_page_url if next_page_url else self.config()["usersUrl"]
        request_header = self.request_header()

        self.logger.debug(
            "Get list of all M365 users%s; calling -> %s",
            " (paged)" if next_page_url else "",
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            params={"$top": str(max_number)} if not next_page_url else None,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get list of M365 users!",
        )

        return response

    # end method definition

    def get_users_iterator(
        self,
    ) -> iter:
        """Get an iterator object that can be used to traverse all M365 users.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of users.

        Example usage:
            users = m365_object.get_users_iterator()
            for user in users:
                logger.info("Traversing M365 user -> '%s'...", user.get("displayName", "<undefined name>"))

        Returns:
            iter:
                A generator yielding one M365 user per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_users(
                next_page_url=next_page_url,
            )
            if not response or "value" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["value"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("@odata.nextLink", None)
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_user(self, user_email: str, user_id: str | None = None, show_error: bool = False) -> dict | None:
        """Get a M365 User based on its email or ID.

        Args:
            user_email (str):
                The M365 user email.
            user_id (str | None, optional):
                The ID of the M365 user (alternatively to user_email). Optional.
            show_error (bool):
                Whether or not an error should be displayed if the
                user is not found.

        Returns:
            dict:
                User information or None if the user couldn't be retrieved (e.g. because it doesn't exist
                or if there is a permission problem).

        Example:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#users/$entity',
                'businessPhones': [],
                'displayName': 'Bob Davis',
                'givenName': 'Bob',
                'id': '72c80809-094f-4e6e-98d4-25a736385d10',
                'jobTitle': None,
                'mail': 'bdavis@M365x61936377.onmicrosoft.com',
                'mobilePhone': None,
                'officeLocation': None,
                'preferredLanguage': None,
                'surname': 'Davis',
                'userPrincipalName': 'bdavis@M365x61936377.onmicrosoft.com'
            }

        """

        # Some sanity checks:
        if user_email and ("@" not in user_email or "." not in user_email):
            self.logger.error(
                "User email -> %s is not a valid email address!",
                user_email,
            )
            return None

        # if there's an alias in the E-Mail Adress we remove it as
        # MS Graph seems to not support an alias to lookup a user object.
        if user_email and "+" in user_email:
            self.logger.info(
                "Removing Alias from email address -> %s to determine M365 principal name...",
                user_email,
            )
            # Find the index of the '+' character
            alias_index = user_email.find("+")

            # Find the index of the '@' character
            domain_index = user_email.find("@")

            # Construct the email address without the alias
            user_email = user_email[:alias_index] + user_email[domain_index:]
            self.logger.info(
                "M365 user principal name -> '%s'.",
                user_email,
            )

        request_url = self.config()["usersUrl"] + "/" + str(user_email if user_email else user_id)
        request_header = self.request_header()

        self.logger.debug(
            "Get M365 user -> '%s'; calling -> %s",
            str(user_email if user_email else user_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get M365 user -> '{}'".format(user_email if user_email else user_id),
            show_error=show_error,
        )

    # end method definition

    def add_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        location: str = "US",
        department: str = "",
        company_name: str = "Innovate",
    ) -> dict | None:
        """Add a M365 user.

        Args:
            email (str):
                The email address of the user. This is also the unique identifier.
            password (str):
                The password of the user.
            first_name (str):
                The first name of the user.
            last_name (str):
                The last name of the user.
            location (str, optional):
                The country ISO 3166-1 alpha-2 code (e.g. US, CA, FR, DE, CN, ...)
            department (str, optional):
                The department of the user.
            company_name (str):
                The name of the company the user works for.

        Returns:
            dict | None:
                User information or None if the user couldn't be created (e.g. because it exisits already
                or if a permission problem occurs).

        """

        user_post_body = {
            "accountEnabled": True,
            "displayName": first_name + " " + last_name,
            "givenName": first_name,
            "surname": last_name,
            "mailNickname": email.split("@")[0],
            "userPrincipalName": email,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": password,
            },
            "usageLocation": location,
        }
        if department:
            user_post_body["department"] = department
        if company_name:
            user_post_body["companyName"] = company_name

        request_url = self.config()["usersUrl"]
        request_header = self.request_header()

        self.logger.debug("Adding M365 user -> %s; calling -> %s", email, request_url)

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=json.dumps(user_post_body),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add M365 user -> '{}'".format(email),
        )

    # end method definition

    def update_user(self, user_id: str, updated_settings: dict) -> dict | None:
        """Update selected properties of an M365 user.

        Documentation on user properties is here: https://learn.microsoft.com/en-us/graph/api/user-update

        Args:
            user_id (str):
                The ID of the user (can also be email). This is also the unique identifier.
            updated_settings (dict):
                The new data to update the user with.

        Returns:
            dict | None:
                Response of the M365 Graph API  or None if the call fails.

        """

        request_url = self.config()["usersUrl"] + "/" + user_id
        request_header = self.request_header()

        self.logger.debug(
            "Updating M365 user with ID -> %s with -> %s; calling -> %s",
            user_id,
            str(updated_settings),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PATCH",
            headers=request_header,
            json_data=updated_settings,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update M365 user -> '{}' with -> {}".format(
                user_id,
                updated_settings,
            ),
        )

    # end method definition

    def get_user_licenses(self, user_id: str) -> dict | None:
        """Get the assigned license SKUs of a user.

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).

        Returns:
            dict:
                A list of user licenses or None if request fails.

        Example:
            {
                '@odata.context': "https://graph.microsoft.com/v1.0/$metadata#users('a5875311-f0a5-486d-a746-bd7372b91115')/licenseDetails",
                'value': [
                    {
                        'id': '8DRPYHK6IUOra-Nq6L0A7GAn38eBLPdOtXhbU5K1cd8',
                        'skuId': 'c7df2760-2c81-4ef7-b578-5b5392b571df',
                        'skuPartNumber': 'ENTERPRISEPREMIUM',
                        'servicePlans': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
                    }
                ]
            }

        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/licenseDetails"
        request_header = self.request_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get M365 licenses of M365 user -> {}".format(user_id),
        )

    # end method definition

    def assign_license_to_user(self, user_id: str, sku_id: str) -> dict | None:
        """Add an M365 license to a user (e.g. to use Office 365).

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user)
            sku_id (str):
                M365 GUID of the SKU.
                (e.g. c7df2760-2c81-4ef7-b578-5b5392b571df for E5 and
                6fd2c87f-b296-42f0-b197-1e91e994b900 for E3)

        Returns:
            dict:
                The API response or None if request fails.

        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/assignLicense"
        request_header = self.request_header()

        # Construct the request body for assigning the E5 license
        license_post_body = {
            "addLicenses": [
                {
                    "disabledPlans": [],
                    "skuId": sku_id,  # "c42b9cae-ea4f-4a69-9ca5-c53bd8779c42"
                },
            ],
            "removeLicenses": [],
        }

        self.logger.debug(
            "Assign M365 license -> %s to M365 user -> %s; calling -> %s",
            sku_id,
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=license_post_body,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to assign M365 license -> {} to M365 user -> {}".format(
                sku_id,
                user_id,
            ),
        )

    # end method definition

    def get_user_photo(self, user_id: str, show_error: bool = True) -> bytes | None:
        """Get the photo of a M365 user.

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).
            show_error (bool, optional):
                Whether or not an error should be logged if the user
                does not have a photo in M365.

        Returns:
            bytes:
                Image of the user photo or None if the user photo couldn't be retrieved.

        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/photo/$value"
        # Set image as content type:
        request_header = self.request_header("image/*")

        self.logger.debug(
            "Get photo of user -> %s; calling -> %s",
            user_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get photo of M365 user -> {}".format(user_id),
            warning_message="M365 User -> {} does not yet have a photo.".format(
                user_id,
            ),
            show_error=show_error,
            parse_request_response=False,  # the response is NOT JSON!
        )

        if response and response.ok and response.content:
            return response.content  # this is the actual image - not json!

        return None

    # end method definition

    def download_user_photo(self, user_id: str, photo_path: str) -> str | None:
        """Download the M365 user photo and save it to the local file system.

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).
            photo_path (str):
                The directory where the photo should be saved.

        Returns:
            str:
                The name of the photo file in the file system (with full path) or None if
                the call of the REST API fails.

        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/photo/$value"
        request_header = self.request_header("application/json")

        self.logger.debug(
            "Downloading photo for M365 user with ID -> %s; calling -> %s",
            user_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to download photo for M365 user with ID -> {}".format(
                user_id,
            ),
            stream=True,
            parse_request_response=False,
        )

        if response and response.ok:
            content_type = response.headers.get("Content-Type", "image/png")
            if content_type == "image/jpeg":
                file_extension = "jpg"
            elif content_type == "image/png":
                file_extension = "png"
            else:
                file_extension = "img"  # Default extension if type is unknown
            file_path = os.path.join(
                photo_path,
                "{}.{}".format(user_id, file_extension),
            )

            try:
                with open(file_path, "wb") as file:
                    file.writelines(response.iter_content(chunk_size=8192))
            except OSError:
                self.logger.error(
                    "Error saving photo for user with ID -> %s!",
                    user_id,
                )
            else:
                self.logger.info(
                    "Photo for M365 user with ID -> %s saved to -> '%s'.",
                    user_id,
                    file_path,
                )
                return file_path

        return None

    # end method definition

    def update_user_photo(self, user_id: str, photo_path: str) -> dict | None:
        """Update the M365 user photo.

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).
            photo_path (str):
                The file system path with the location of the photo file.

        Returns:
            dict | None:
                Response of Graph REST API or None if the user photo couldn't be updated.

        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/photo/$value"
        # Set image as content type:
        request_header = self.request_header("image/*")

        # Check if the photo file exists
        if not os.path.isfile(photo_path):
            self.logger.error("Photo file -> %s not found!", photo_path)
            return None

        try:
            # Read the photo file as binary data
            with open(photo_path, "rb") as image_file:
                photo_data = image_file.read()
        except OSError:
            # Handle any errors that occurred while reading the photo file
            self.logger.error(
                "Error reading photo file -> %s!",
                photo_path,
            )
            return None

        data = photo_data

        self.logger.debug(
            "Update M365 user with ID -> %s with photo -> %s; calling -> %s",
            user_id,
            photo_path,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update M365 user with ID -> {} with photo -> '{}'".format(
                user_id,
                photo_path,
            ),
        )

    # end method definition

    def get_user_drive(self, user_id: str, me: bool = False) -> dict | None:
        """Get the mysite (OneDrive) of the user.

        It may be required to do this before certain other operations
        are possible. These operations may require that the mydrive
        is initialized for that user. If you get errors like
        "User's mysite not found." this may be the case.

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).
            me (bool, optional):
                Should be True if the user itself is accessing the drive.

        Returns:
            dict:
                A list of user licenses or None if request fails.

        Example:
        {
            '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#drives/$entity',
            'createdDateTime': '2025-04-10T23:43:26Z',
            'description': '',
            'id': 'b!VsxYN1IbrEqbiwMiba_M7FCkNAhL5LRFnQEZpEYbxDAxvvcvUMAhSqfgWW_4eAUP',
            'lastModifiedDateTime': '2025-04-12T15:50:20Z',
            'name': 'OneDrive',
            'webUrl': 'https://ideateqa-my.sharepoint.com/personal/jbenham_qa_idea-te_eimdemo_com/Documents',
            'driveType': 'business',
            'createdBy': {
                'user': {
                    'displayName': 'System Account'
                }
            },
            'lastModifiedBy': {
                'user': {
                    'email': 'jbenham@qa.idea-te.eimdemo.com',
                    'id': '470060cc-4d9f-439e-8a6e-8d567c5bda80',
                    'displayName': 'Jeff Benham'
                }
            },
            'owner': {
                'user': {...}
            },
            'quota': {
                'deleted': 0,
                'remaining': 1099511518137,
                'state': 'normal',
                'total': 1099511627776,
                'used': 109639
            }
        }

        """

        request_url = self.config()["meUrl"] if me else self.config()["usersUrl"] + "/" + user_id
        request_url += "/drive"
        request_header = self.request_header_user() if me else self.request_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get mySite (drive) of M365 user -> {}".format(user_id),
        )

    # end method definition

    def get_groups(
        self,
        max_number: int = 250,
        next_page_url: str | None = None,
    ) -> dict | None:
        """Get list all all groups in M365 tenant.

        Args:
            max_number (int, optional):
                The maximum result values (limit).
            next_page_url (str, optional):
                The MS Graph URL to retrieve the next page of M365 groups (pagination).
                This is used for the iterator get_groups_iterator() below.

        Returns:
            dict:
                A dictionary of all groups or None in case of an error.

        """

        request_url = next_page_url if next_page_url else self.config()["groupsUrl"]
        request_header = self.request_header()

        self.logger.debug(
            "Get list of all M365 groups%s; calling -> %s",
            " (paged)" if next_page_url else "",
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            params={"$top": str(max_number)} if not next_page_url else None,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get list of M365 groups",
        )

        return response

    # end method definition

    def get_groups_iterator(
        self,
    ) -> iter:
        """Get an iterator object that can be used to traverse all M365 groups.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of groups.

        Example usage:
            groups = m365_object.get_groups_iterator()
            for group in groups:
                logger.info("Traversing M365 group -> '%s'...", group.get("displayName", "<undefined name>"))

        Returns:
            iter:
                A generator yielding one M365 group per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_groups(
                next_page_url=next_page_url,
            )
            if not response or "value" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["value"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("@odata.nextLink", None)
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_group(self, group_name: str, show_error: bool = False) -> dict | None:
        """Get a M365 Group based on its name.

        Args:
            group_name (str):
                The M365 Group name.
            show_error (bool):
                Should an error be logged if group is not found.

        Returns:
            dict:
                Group information or None if the group doesn't exist.

        Example:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#groups',
                'value': [
                    {
                        'id': 'b65f7dba-3ed1-49df-91bf-2bf99affcc8d',
                        'deletedDateTime': None,
                        'classification': None,
                        'createdDateTime': '2023-04-01T13:46:26Z',
                        'creationOptions': [],
                        'description': 'Engineering & Construction',
                        'displayName': 'Engineering & Construction',
                        'expirationDateTime': None,
                        'groupTypes': ['Unified'],
                        'isAssignableToRole': None,
                        'mail': 'Engineering&Construction@M365x61936377.onmicrosoft.com',
                        'mailEnabled': True,
                        'mailNickname': 'Engineering&Construction',
                        'membershipRule': None,
                        'membershipRuleProcessingState': None,
                        'onPremisesDomainName': None,
                        'onPremisesLastSyncDateTime': None,
                        'onPremisesNetBiosName': None,
                        'onPremisesSamAccountName': None,
                        'onPremisesSecurityIdentifier': None,
                        'onPremisesSyncEnabled': None,
                        'preferredDataLocation': None,
                        'preferredLanguage': None,
                        'proxyAddresses': ['SPO:SPO_d9deb3e7-c72f-4e8d-80fb-5d9411ca1458@SPO_604f34f0-ba72-4321-ab6b-e36ae8bd00ec', ...],
                        'renewedDateTime': '2023-04-01T13:46:26Z',
                        'resourceBehaviorOptions': [],
                        'resourceProvisioningOptions': [],
                        'securityEnabled': False,
                        'securityIdentifier': 'S-1-12-1-3059711418-1239367377-4180393873-2379022234',
                        'theme': None,
                        'visibility': 'Public',
                        'onPremisesProvisioningErrors': []
                    },
                    {
                        'id': '61359860-302e-4016-b5cc-abff2293dff1',
                        ...
                    }
                ]
            }

        """

        query = {"$filter": "displayName eq '" + group_name + "'"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["groupsUrl"] + "?" + encoded_query
        request_header = self.request_header()

        self.logger.debug(
            "Get M365 group -> '%s'; calling -> %s",
            group_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get M365 group -> '{}'".format(group_name),
            show_error=show_error,
        )

    # end method definition

    def add_group(
        self,
        name: str,
        security_enabled: bool = False,
        mail_enabled: bool = True,
    ) -> dict | None:
        """Add a M365 Group.

        Args:
            name (str):
                The name of the group.
            security_enabled (bool, optional):
                Whether or not this group is used for permission management.
            mail_enabled (bool, optional):
                Whether or not this group is email enabled.

        Returns:
            dict | None:
                Group information or None if the group couldn't be created (e.g. because it exisits already).

        Example:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#groups/$entity',
                'id': '28906460-a69c-439e-84ca-c70becf37655',
                'deletedDateTime': None,
                'classification': None,
                'createdDateTime': '2023-04-01T11:40:13Z',
                'creationOptions': [],
                'description': None,
                'displayName': 'Test',
                'expirationDateTime': None,
                'groupTypes': ['Unified'],
                'isAssignableToRole': None,
                'mail': 'Diefenbruch@M365x61936377.onmicrosoft.com',
                'mailEnabled': True,
                'mailNickname': 'Test',
                'membershipRule': None,
                'membershipRuleProcessingState': None,
                'onPremisesDomainName': None,
                'onPremisesLastSyncDateTime': None,
                'onPremisesNetBiosName': None,
                'onPremisesSamAccountName': None,
                'onPremisesSecurityIdentifier': None,
                'onPremisesSyncEnabled': None,
                'onPremisesProvisioningErrors': [],
                'preferredDataLocation': None,
                'preferredLanguage': None,
                'proxyAddresses': ['SMTP:Test@M365x61936377.onmicrosoft.com'],
                'renewedDateTime': '2023-04-01T11:40:13Z',
                'resourceBehaviorOptions': [],
                'resourceProvisioningOptions': [],
                'securityEnabled': True,
                'securityIdentifier': 'S-1-12-1-680551520-1134470812-197642884-1433859052',
                'theme': None,
                'visibility': 'Public'
            }

        """

        group_post_body = {
            "displayName": name,
            "mailEnabled": mail_enabled,
            "mailNickname": name.replace(" ", ""),
            "securityEnabled": security_enabled,
            "groupTypes": ["Unified"],
        }

        request_url = self.config()["groupsUrl"]
        request_header = self.request_header()

        self.logger.debug("Adding M365 group -> '%s'; calling -> %s", name, request_url)
        self.logger.debug("M365 group attributes -> %s", str(group_post_body))

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=json.dumps(group_post_body),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add M365 group -> '{}'".format(name),
        )

    # end method definition

    def get_group_members(self, group_name: str) -> dict | None:
        """Get members (users and groups) of the specified group.

        Args:
            group_name (str):
                The name of the group.

        Returns:
            dict | None:
                Response of Graph REST API or None if the REST call fails.

        """

        response = self.get_group(group_name=group_name)
        group_id = self.get_result_value(response=response, key="id", index=0)
        if not group_id:
            self.logger.error(
                "M365 Group -> '%s' does not exist! Cannot retrieve group members.",
                group_name,
            )
            return None

        query = {"$select": "id,displayName,mail,userPrincipalName"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/members?" + encoded_query
        request_header = self.request_header()

        self.logger.debug(
            "Get members of M365 group -> %s (%s); calling -> %s",
            group_name,
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get members of M365 group -> '{}' ({})".format(
                group_name,
                group_id,
            ),
        )

    # end method definition

    def add_group_member(self, group_id: str, member_id: str) -> dict | None:
        """Add a member (user or group) to a (parent) group.

        Args:
            group_id (str):
                The M365 GUID of the group.
            member_id (str):
                The M365 GUID of the new member.

        Returns:
            dict | None:
                Response of the MS Graph API call or None if the call fails.

        """

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/members/$ref"
        request_header = self.request_header()

        group_member_post_body = {
            "@odata.id": self.config()["directoryObjects"] + "/" + member_id,
        }

        self.logger.debug(
            "Adding member -> %s to group -> %s; calling -> %s",
            member_id,
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=json.dumps(group_member_post_body),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add member -> {} to M365 group -> {}".format(
                member_id,
                group_id,
            ),
        )

    # end method definition

    def is_member(self, group_id: str, member_id: str, show_error: bool = True) -> bool:
        """Check whether a M365 user is already in a M365 group.

        Args:
            group_id (str):
                The M365 GUID of the group.
            member_id (str):
                The M365 GUID of the user (member).
            show_error (bool):
                Whether or not an error should be logged if the user
                is not a member of the group.

        Returns:
            bool:
                True if the user is in the group. False otherwise.

        """

        # don't encode this URL - this has not been working!!
        request_url = self.config()["groupsUrl"] + f"/{group_id}/members?$filter=id eq '{member_id}'"
        request_header = self.request_header()

        self.logger.debug(
            "Check if user -> %s is in group -> %s; calling -> %s",
            member_id,
            group_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to check if M365 user -> {} is in M365 group -> {}".format(
                member_id,
                group_id,
            ),
            show_error=show_error,
        )

        return bool(response and response.get("value"))

    # end method definition

    def get_group_owners(self, group_name: str) -> dict | None:
        """Get owners (users) of the specified group.

        Args:
            group_name (str):
                The name of the group.

        Returns:
            dict | None:
                Response of Graph REST API or None if the REST call fails.

        """

        response = self.get_group(group_name=group_name)
        group_id = self.get_result_value(response=response, key="id", index=0)
        if not group_id:
            self.logger.error(
                "M365 Group -> %s does not exist! Cannot retrieve group owners.",
                group_name,
            )
            return None

        query = {"$select": "id,displayName,mail,userPrincipalName"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/owners?" + encoded_query
        request_header = self.request_header()

        self.logger.debug(
            "Get owners of M365 group -> %s (%s); calling -> %s",
            group_name,
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get owners of M365 group -> '{}' ({})".format(
                group_name,
                group_id,
            ),
        )

    # end method definition

    def add_group_owner(self, group_id: str, owner_id: str) -> dict | None:
        """Add an owner (user) to a group.

        Args:
            group_id (str):
                The M365 GUID of the group.
            owner_id (str):
                The M365 GUID of the new member.

        Returns:
            dict | None:
                The response of the MS Graph API call or None if the call fails.

        """

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/owners/$ref"
        request_header = self.request_header()

        group_member_post_body = {
            "@odata.id": self.config()["directoryObjects"] + "/" + owner_id,
        }

        self.logger.debug(
            "Adding owner -> %s to M365 group -> %s; calling -> %s",
            owner_id,
            group_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=json.dumps(group_member_post_body),
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add owner -> {} to M365 group -> {}".format(
                owner_id,
                group_id,
            ),
        )

    # end method definition

    def purge_deleted_items(self) -> None:
        """Purge all deleted users and groups.

        Purging users and groups requires administrative rights that typically
        are not provided in Contoso example org.
        """

        request_header = self.request_header()

        request_url = self.config()["directoryUrl"] + "/deletedItems/microsoft.graph.group"
        response = requests.get(
            request_url,
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
        )
        deleted_groups = self.parse_request_response(response) or {}

        for group in deleted_groups.get("value", []):
            group_id = group["id"]
            response = self.purge_deleted_item(group_id)

        request_url = self.config()["directoryUrl"] + "/deletedItems/microsoft.graph.user"
        response = requests.get(
            request_url,
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
        )
        deleted_users = self.parse_request_response(response) or {}

        for user in deleted_users.get("value", []):
            user_id = user["id"]
            response = self.purge_deleted_item(user_id)

    # end method definition

    def purge_deleted_item(self, item_id: str) -> dict | None:
        """Purge a single deleted user or group.

        This requires elevated permissions that are typically
        not available via Graph API.

        Args:
            item_id (str):
                The M365 GUID of the item to purge.

        Returns:
            dict | None:
                Response of the MS Graph API call or None if the call fails.

        """

        request_url = self.config()["directoryUrl"] + "/deletedItems/" + item_id
        request_header = self.request_header()

        self.logger.debug(
            "Purging deleted item -> %s; calling -> %s",
            item_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to purge deleted item -> {}".format(item_id),
        )

    # end method definition

    def has_team(self, group_name: str) -> bool:
        """Check if a M365 Group has a M365 Team connected or not.

        Args:
            group_name (str):
                The name of the M365 group.

        Returns:
            bool:
                Returns True if a Team is assigned and False otherwise.

        """

        response = self.get_group(group_name=group_name)
        group_id = self.get_result_value(response=response, key="id", index=0)
        if not group_id:
            self.logger.error(
                "M365 Group -> '%s' not found! Cannot check if it has a M365 Team.",
                group_name,
            )
            return False

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/team"
        request_header = self.request_header()

        self.logger.debug(
            "Check if M365 Group -> %s has a M365 Team connected; calling -> %s",
            group_name,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to check if M365 Group -> '{}' has a M365 Team connected".format(
                group_name,
            ),
            parse_request_response=False,
            show_error=False,
        )

        if response and response.status_code == 200:  # Group has a Team assigned!
            self.logger.debug("Group -> '%s' has a M365 Team connected.", group_name)
            return True
        elif not response or response.status_code == 404:  # Group does not have a Team assigned!
            self.logger.debug("Group -> '%s' has no M365 Team connected.", group_name)
            return False

        return False

    # end method definition

    def get_team(self, name: str) -> dict | None:
        """Get a M365 Team based on its name.

        Args:
            name (str):
                The name of the M365 Team.

        Returns:
            dict | None:
                Teams data structure (dictionary) or None if the request fails.

        Example:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#teams',
                '@odata.count': 1,
                'value': [
                    {
                        'id': '951bd036-c6fc-4da4-bb80-1860f5472a2f',
                        'createdDateTime': None,
                        'displayName': 'Procurement',
                        'description': 'Procurement',
                        'internalId': None,
                        'classification': None,
                        'specialization': None,
                        'visibility': 'public',
                        'webUrl': None, ...}]}
                        'isArchived': None,
                        'isMembershipLimitedToOwners': None,
                        'memberSettings': None,
                        'guestSettings': None,
                        'messagingSettings': None,
                        ...
                    }
                ]
            }

        """

        # The M365 Teams API has an issues with ampersand characters in team names (like "Engineering & Construction")
        # So we do a work-around here to first get the Team ID via the Group endpoint of the Graph API and
        # then fetch the M365 Team via its ID (which is identical to the underlying M365 Group ID)
        response = self.get_group(group_name=name)
        team_id = self.get_result_value(response=response, key="id", index=0)
        if not team_id:
            self.logger.error(
                "Failed to get the ID of the M365 Team -> '%s' via the M365 Group API!",
                name,
            )
            return None

        request_url = self.config()["teamsUrl"] + "/" + str(team_id)

        request_header = self.request_header()

        self.logger.debug(
            "Lookup Microsoft 365 Teams with name -> '%s'; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get M365 Team -> '{}'".format(name),
        )

    # end method definition

    def add_team(self, name: str, template_name: str = "standard") -> dict | None:
        """Add M365 Team based on an existing M365 Group.

        Args:
            name (str):
                The name of the team. It is assumed that a group with the same name does already exist!
            template_name (str, optional):
                The name of the team template. "standard" is the default value.

        Returns:
            dict:
                Team information (json - empty text!) or None if the team couldn't be created
                (e.g. because it exisits already).

        """

        response = self.get_group(group_name=name)
        group_id = self.get_result_value(response=response, key="id", index=0)
        if not group_id:
            self.logger.error(
                "M365 Group -> '%s' not found! It is required for creating a corresponding M365 Team.",
                name,
            )
            return None

        response = self.get_group_owners(group_name=name)
        if response is None or "value" not in response or not response["value"]:
            self.logger.warning(
                "M365 Group -> '%s' has no owners. This is required for creating a corresponding M365 Team.",
                name,
            )
            return None

        team_post_body = {
            "template@odata.bind": "{}('{}')".format(
                self.config()["teamsTemplatesUrl"],
                template_name,
            ),
            "group@odata.bind": "{}('{}')".format(self.config()["groupsUrl"], group_id),
        }

        request_url = self.config()["teamsUrl"]
        request_header = self.request_header()

        self.logger.debug("Adding M365 Team -> '%s'; calling -> %s", name, request_url)
        self.logger.debug("M365 Team attributes -> %s", str(team_post_body))

        return self.do_request(
            url=request_url,
            method="POST",
            data=json.dumps(team_post_body),
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add M365 Team -> '{}'".format(name),
        )

    # end method definition

    def delete_team(self, team_id: str) -> dict | None:
        """Delete Microsoft 365 Team with a specific ID.

        Args:
            team_id (str):
                The ID of the Microsoft 365 Team to delete.

        Returns:
            dict | None:
                Response dictionary if the team has been deleted, False otherwise.

        """

        request_url = self.config()["groupsUrl"] + "/" + team_id

        request_header = self.request_header()

        self.logger.debug(
            "Delete Microsoft 365 Teams with ID -> %s; calling -> %s",
            team_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to delete M365 Team with ID -> {}".format(team_id),
        )

    # end method definition

    def delete_teams(self, name: str) -> bool:
        """Delete Microsoft 365 Teams with a specific name.

        Microsoft 365 allows to have multiple teams with the same name. So this method may delete
        multiple teams if the have the same name. The Graph API we use here
        is the M365 Group API as deleting the group also deletes the associated team.

        Args:
            name (str):
                The name of the Microsoft 365 Team.

        Returns:
            bool:
                True if teams have been deleted, False otherwise.

        """

        # We need a special handling of team names with single quotes:
        escaped_group_name = name.replace("'", "''")
        encoded_group_name = quote(escaped_group_name, safe="")
        request_url = self.config()["groupsUrl"] + "?$filter=displayName eq '{}'".format(encoded_group_name)

        request_header = self.request_header()

        self.logger.debug(
            "Delete all Microsoft 365 Teams with name -> '%s'; calling -> %s",
            name,
            request_url,
        )

        existing_teams = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get list of M365 Teams to delete",
        )

        if existing_teams:
            data = existing_teams.get("value")
            if data:
                counter = 0
                for team in data:
                    team_id = team.get("id")
                    response = self.delete_team(team_id)

                    if not response:
                        self.logger.error(
                            "Failed to delete M365 Team -> '%s' (%s)!",
                            name,
                            team_id,
                        )
                        continue
                    counter += 1

                self.logger.info(
                    "%s M365 Team%s with name -> '%s' %s been deleted.",
                    str(counter),
                    "s" if counter > 1 else "",
                    name,
                    "have" if counter > 1 else "has",
                )
                return True
            else:
                self.logger.info("No M365 Team with name -> '%s' found.", name)
                return False
        else:
            self.logger.error("Failed to retrieve M365 Teams with name -> '%s'!", name)
            return False

    # end method definition

    def delete_all_teams(self, exception_list: list, pattern_list: list) -> bool:
        """Delete all teams (groups) based on patterns and exceptions.

        Only delete MS Teams that are NOT on the exception list AND
        that are matching at least one of the patterns in the provided pattern list.

        This method is used for general cleanup of teams. Be aware that deleted teams
        are still listed under https://admin.microsoft.com/#/deletedgroups and it
        may take some days until M365 finally deletes them.

        Args:
            exception_list (list):
                A list of group names that should not be deleted.
            pattern_list (list):
                A list of patterns for group names to be deleted
                (regular expression).

        Returns:
            bool:
                True if teams have been deleted, False otherwise.

        """

        self.logger.info(
            "Delete existing M365 groups/teams matching delete pattern and not on exception list...",
        )

        # Get list of all existing M365 groups/teams:
        groups = self.get_groups_iterator()

        # Process all groups and check if they should be deleted:
        for group in groups:
            group_name = group.get("displayName", None)
            if not group_name:
                continue
            # Check if group is in exception list:
            if group_name in exception_list:
                self.logger.info(
                    "M365 Group name -> '%s' is on the exception list. Skipping...",
                    group_name,
                )
                continue
            # Check that at least one pattern is found that matches the group:
            for pattern in pattern_list:
                result = re.search(pattern, group_name)
                if result:
                    self.logger.info(
                        "M365 Group name -> '%s' is matching pattern -> '%s'. Deleting...",
                        group_name,
                        pattern,
                    )
                    self.delete_teams(name=group_name)
                    break
            else:
                self.logger.info(
                    "M365 Group name -> '%s' is not matching any delete pattern. Skipping...",
                    group_name,
                )
        return True

    # end method definition

    def get_team_channels(self, name: str) -> dict | None:
        """Get channels of a M365 Team based on the team name.

        Args:
            name (str):
                The name of the M365 team.

        Returns:
            dict:
                The channel data structure (dictionary) or None if the request fails.

        Example:
            {
                '@odata.context': "https://graph.microsoft.com/v1.0/$metadata#teams('951bd036-c6fc-4da4-bb80-1860f5472a2f')/channels",
                '@odata.count': 1,
                'value': [
                    {
                        'id': '19:yPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1@thread.tacv2',
                        'createdDateTime': '2023-08-11T14:11:35.986Z',
                        'displayName': 'General',
                        'description': 'Procurement',
                        'isFavoriteByDefault': None,
                        'email': None,
                        'tenantId': '417e6e3a-82e6-4aa0-9d47-a7734ca3daea',
                        'webUrl': 'https://teams.microsoft.com/l/channel/19%3AyPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1%40thread.tacv2/Procurement?groupId=951bd036-c6fc-4da4-bb80-1860f5472a2f&tenantId=417e6e3a-82e6-4aa0-9d47-a7734ca3daea&allowXTenantAccess=False',
                        'membershipType': 'standard'
                    }
                ]
            }

        """

        response = self.get_team(name=name)
        team_id = self.get_result_value(response=response, key="id", index=0)
        if not team_id:
            return None

        request_url = self.config()["teamsUrl"] + "/" + str(team_id) + "/channels"

        request_header = self.request_header()

        self.logger.debug(
            "Retrieve channels of Microsoft 365 Team -> '%s'; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Channels for M365 Team -> '{}' ({})".format(
                name,
                team_id,
            ),
        )

    # end method definition

    def get_team_channel_tabs(self, team_name: str, channel_name: str) -> dict | None:
        """Get tabs of an M365 Team channel based on the team and channel names.

        Args:
            team_name (str):
                The name of the M365 Team.
            channel_name (str):
                The name of the M365 Team channel.

        Returns:
            dict | None:
                Tabs data structure (dictionary) or None if the request fails.

        Example:
            {
                '@odata.context': "https://graph.microsoft.com/v1.0/$metadata#teams('951bd036-c6fc-4da4-bb80-1860f5472a2f')/channels('19%3AyPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1%40thread.tacv2')/tabs",
                '@odata.count': 1,
                'value': [
                    {
                        'id': '66f44e9a-0741-49a4-9500-ec82cc120115',
                        'displayName': 'Procurement',
                        'webUrl': 'https://teams.microsoft.com/l/entity/2851980b-95dc-4118-a1f5-5ae1894eaaaf/_djb2_msteams_prefix_66f44e9a-0741-49a4-9500-ec82cc120115?webUrl=https%3a%2f%2fotcs.fqdn.tld.com%2fcssupport%2fxecmoffice%2fteamsapp.html%3fnodeId%3d13178%26type%3dcontainer%26parentId%3d2000%26target%3dcontent%26csurl%3dhttps%3a%2f%2fotcs.fqdn.tld.com%2fcs%2fcs%26appId%3da168b00d-3ad9-46ac-8798-578c1961e1ed%26showBW%3dtrue%26title%3dProcurement&label=Procurement&context=%7b%0d%0a++%22canvasUrl%22%3a+%22https%3a%2f%2fotcs.fqdn.tld.com%2fcssupport%2fxecmoffice%2fteamsapp.html%3fnodeId%3d13178%26type%3dcontainer%26parentId%3d2000%26target%3dcontent%26csurl%3dhttps%3a%2f%2fotcs.fqdn.tld.com%2fcs%2fcs%26appId%3da168b00d-3ad9-46ac-8798-578c1961e1ed%22%2c%0d%0a++%22channelId%22%3a+%2219%3ayPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1%40thread.tacv2%22%2c%0d%0a++%22subEntityId%22%3a+null%0d%0a%7d&groupId=951bd036-c6fc-4da4-bb80-1860f5472a2f&tenantId=417e6e3a-82e6-4aa0-9d47-a7734ca3daea',
                        'configuration':
                        {
                            'entityId': '13178',
                            'contentUrl': 'https://otcs.fqdn.tld.com/cssupport/xecmoffice/teamsapp.html?nodeId=13178&type=container&parentId=2000&target=content&csurl=https://otcs.fqdn.tld.com/cs/cs&appId=a168b00d-3ad9-46ac-8798-578c1961e1ed',
                            'removeUrl': None,
                            'websiteUrl': 'https://otcs.fqdn.tld.com/cssupport/xecmoffice/teamsapp.html?nodeId=13178&type=container&parentId=2000&target=content&csurl=https://otcs.fqdn.tld.com/cs/cs&appId=a168b00d-3ad9-46ac-8798-578c1961e1ed&showBW=true&title=Procurement',
                            'dateAdded': '2023-08-12T08:57:35.895Z'
                        }
                    }
                ]
            }

        """

        response = self.get_team(name=team_name)
        team_id = self.get_result_value(response=response, key="id", index=0)
        if not team_id:
            return None

        # Get the channels of the M365 Team:
        response = self.get_team_channels(name=team_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            self.logger.error(
                "Cannot find Channel -> '%s' on M365 Team -> '%s'!",
                channel_name,
                team_name,
            )
            return None
        channel_id = channel["id"]

        request_url = self.config()["teamsUrl"] + "/" + str(team_id) + "/channels/" + str(channel_id) + "/tabs"

        request_header = self.request_header()

        self.logger.debug(
            "Retrieve Tabs of Microsoft 365 Teams -> %s and Channel -> %s; calling -> %s",
            team_name,
            channel_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get Tabs for M365 Team -> '{}' ({}) and Channel -> '{}' ({})".format(
                team_name,
                team_id,
                channel_name,
                channel_id,
            ),
        )

    # end method definition

    def get_teams_apps(self, filter_expression: str = "") -> dict | None:
        """Get a list of MS Teams apps in catalog that match a given filter criterium.

        Args:
            filter_expression (str, optional):
                Filter string see https://learn.microsoft.com/en-us/graph/filter-query-parameter

        Returns:
            dict | None:
                Response of the MS Graph API call or None if the call fails.

        Example:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps(appDefinitions())',
                '@odata.count': 1,
                'value': [
                    {
                        'id': '2851980b-95dc-4118-a1f5-5ae1894eaaaf',
                        'externalId': 'dd4af790-d8ff-47a0-87ad-486318272c7a',
                        'displayName': 'OpenText Extended ECM',
                        'distributionMethod': 'organization',
                        'appDefinitions@odata.context': "https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps('2851980b-95dc-4118-a1f5-5ae1894eaaaf')/appDefinitions",
                        'appDefinitions': [
                            {
                                'id': 'Mjg1MTk4MGItOTVkYy00MTE4LWExZjUtNWFlMTg5NGVhYWFmIyMyMi40IyNQdWJsaXNoZWQ=',
                                'teamsAppId': '2851980b-95dc-4118-a1f5-5ae1894eaaaf',
                                'displayName': 'OpenText Extended ECM',
                                'version': '22.4',
                                'publishingState': 'published',
                                'shortDescription': 'Add a tab for an Extended ECM business workspace.',
                                'description': 'View and interact with OpenText Extended ECM business workspaces',
                                'lastModifiedDateTime': None,
                                'createdBy': None,
                                'authorization': {
                                    'requiredPermissionSet': {...}
                                }
                            }
                        ]
                    }
                ]
            }

        """

        query = {"$expand": "AppDefinitions"}

        if filter_expression:
            query["$filter"] = filter_expression

        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["teamsAppsUrl"] + "?" + encoded_query

        if filter_expression:
            self.logger.debug(
                "Get list of MS Teams Apps using filter -> %s; calling -> %s",
                filter_expression,
                request_url,
            )
            failure_message = "Failed to get list of M365 Teams apps using filter -> {}".format(
                filter_expression,
            )
        else:
            self.logger.debug(
                "Get list of all MS Teams Apps; calling -> %s",
                request_url,
            )
            failure_message = "Failed to get list of M365 Teams apps"

        request_header = self.request_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message=failure_message,
        )

    # end method definition

    def get_teams_app(self, app_id: str) -> dict | None:
        """Get a specific MS Teams app in catalog based on the known (internal) app ID.

        Args:
            app_id (str):
                ID of the app (this is NOT the external ID but the internal ID).

        Returns:
            dict | None:
                Response of the MS Graph API call or None if the call fails.

        Examle:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps(appDefinitions())/$entity',
                'id': 'ccabe3fb-316f-40e0-a486-1659682cb8cd',
                'externalId': 'dd4af790-d8ff-47a0-87ad-486318272c7a',
                'displayName': 'Extended ECM',
                'distributionMethod': 'organization',
                'appDefinitions@odata.context': "https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps('ccabe3fb-316f-40e0-a486-1659682cb8cd')/appDefinitions",
                'appDefinitions': [
                    {
                        'id': 'Y2NhYmUzZmItMzE2Zi00MGUwLWE0ODYtMTY1OTY4MmNiOGNkIyMyNC4yLjAjI1B1Ymxpc2hlZA==',
                        'teamsAppId': 'ccabe3fb-316f-40e0-a486-1659682cb8cd',
                        'displayName': 'Extended ECM',
                        'version': '24.2.0',
                        'publishingState': 'published',
                        'shortDescription': 'Add a tab for an Extended ECM business workspace.',
                        'description': 'View and interact with OpenText Extended ECM business workspaces',
                        'lastModifiedDateTime': None,
                        'createdBy': None,
                        'authorization': {...}
                    }
                ]
            }

        """

        query = {"$expand": "AppDefinitions"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["teamsAppsUrl"] + "/" + app_id + "?" + encoded_query

        self.logger.debug(
            "Get M365 Teams App with ID -> %s; calling -> %s",
            app_id,
            request_url,
        )

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get M365 Teams app with ID -> {}".format(app_id),
        )

        return response

    # end method definition

    def get_teams_apps_of_user(
        self,
        user_id: str,
        filter_expression: str = "",
    ) -> dict | None:
        """Get a list of MS Teams apps of a user that match a given filter criterium.

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user)
            filter_expression (str, optional):
                Filter string see https://learn.microsoft.com/en-us/graph/filter-query-parameter

        Returns:
            dict | None:
                Response of the MS Graph API call or None if the call fails.

        """

        query = {"$expand": "teamsAppDefinition"}
        if filter_expression:
            query["$filter"] = filter_expression

        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["usersUrl"] + "/" + user_id + "/teamwork/installedApps?" + encoded_query

        self.logger.debug(
            "Get list of M365 Teams Apps for user -> %s using query -> %s; calling -> %s",
            user_id,
            query,
            request_url,
        )

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get M365 Teams apps for user -> {}".format(
                user_id,
            ),
        )

        return response

    # end method definition

    def get_teams_apps_of_team(
        self,
        team_id: str,
        filter_expression: str = "",
    ) -> dict | None:
        """Get a list of MS Teams apps of a M365 team that match a given filter criterium.

        Args:
            team_id (str):
                The M365 ID of the team.
            filter_expression (str, optional):
                Filter string see https://learn.microsoft.com/en-us/graph/filter-query-parameter

        Returns:
            dict | None:
                Response of the MS Graph API call or None if the call fails.

        """

        query = {"$expand": "teamsAppDefinition"}
        if filter_expression:
            query["$filter"] = filter_expression

        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["teamsUrl"] + "/" + team_id + "/installedApps?" + encoded_query

        self.logger.debug(
            "Get list of M365 Teams Apps for M365 Team -> %s using query -> %s; calling -> %s",
            team_id,
            query,
            request_url,
        )

        request_header = self.request_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get list of M365 Teams apps for M365 Team -> {}".format(
                team_id,
            ),
        )

    # end method definition

    def extract_version_from_app_manifest(self, app_path: str) -> str | None:
        """Extract the version number from the MS Teams app manifest file.

        This can be used to check if the app package includes a newer
        app version then the already installed one.

        Args:
            app_path (str):
                The file path (with directory) to the app package to extract
                the version from.

        Returns:
            str | None:
                The version number or None in case of an error.

        """

        with zipfile.ZipFile(app_path, "r") as zip_ref:
            manifest_data = zip_ref.read("manifest.json")
            manifest_json = json.loads(manifest_data)
            version = manifest_json.get("version")

            return version

    # end method definition

    def upload_teams_app(
        self,
        app_path: str,
        update_existing_app: bool = False,
        app_catalog_id: str = "",
    ) -> dict | None:
        """Upload a new app package to the catalog of MS Teams apps.

        This is not possible with client secret credentials
        but requires a token of a user authenticated with username + password.
        See https://learn.microsoft.com/en-us/graph/api/teamsapp-publish
        (permissions table on that page).

        For updates see: https://learn.microsoft.com/en-us/graph/api/teamsapp-update?view=graph-rest-1.0&tabs=http

        Args:
            app_path (str):
                The file path (with directory) to the app package to upload.
            update_existing_app (bool, optional):
                Whether or not to update an existing app with the same name.
            app_catalog_id (str, optional):
                The unique ID of the app. It is the ID the app has in
                the catalog - which is different from ID an app gets
                after installation (which is tenant specific).

        Returns:
            dict:
                Response of the MS GRAPH API REST call or None if the request fails
                The responses are different depending if it is an install or upgrade!!

        Example return for upgrades ("teamsAppId" is the "internal" ID of the app):
            {
                '@odata.context': "https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps('3f749cca-8cb0-4925-9fa0-ba7aca2014af')/appDefinitions/$entity",
                'id': 'M2Y3NDljY2EtOGNiMC00OTI1LTlmYTAtYmE3YWNhMjAxNGFmIyMyNC4yLjAjI1B1Ymxpc2hlZA==',
                'teamsAppId': '3f749cca-8cb0-4925-9fa0-ba7aca2014af',
                'displayName': 'IDEA-TE - Extended ECM 24.2.0',
                'version': '24.2.0',
                'publishingState': 'published',
                'shortDescription': 'Add a tab for an Extended ECM business workspace.',
                'description': 'View and interact with OpenText Extended ECM business workspaces',
                'lastModifiedDateTime': None,
                'createdBy': None,
                'authorization': {
                    'requiredPermissionSet': {...}
                }
            }

            Example return for new installations ("id" is the "internal" ID of the app):
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps/$entity',
                'id': '6c672afd-37fc-46c6-8365-d499aba3808b',
                'externalId': 'dd4af790-d8ff-47a0-87ad-486318272c7a',
                'displayName': 'OpenText Extended ECM',
                'distributionMethod': 'organization'
            }

        """

        if update_existing_app and not app_catalog_id:
            self.logger.error(
                "To update an existing M365 Teams app in the app catalog you need to provide the existing App catalog ID!",
            )
            return None

        if not os.path.exists(app_path):
            self.logger.error("M365 Teams app file -> %s does not exist!", app_path)
            return None

        # Ensure that the app file is a zip file
        if not app_path.endswith(".zip"):
            self.logger.error("M365 Teams app file -> %s must be a zip file!", app_path)
            return None

        request_url = self.config()["teamsAppsUrl"]
        # If we want to upgrade an existing app we add the app ID and
        # the specific endpoint:
        if update_existing_app:
            request_url += "/" + app_catalog_id + "/appDefinitions"

        # Here we need the credentials of an authenticated user!
        # (not the application credentials (client_id, client_secret))
        request_header = self.request_header_user(content_type="application/zip")

        with open(app_path, "rb") as f:
            app_data = f.read()

        with zipfile.ZipFile(app_path) as z:
            # Ensure that the app file contains a manifest.json file
            if "manifest.json" not in z.namelist():
                self.logger.error(
                    "M365 Teams app file -> '%s' does not contain a manifest.json file!",
                    app_path,
                )
                return None

        self.logger.debug(
            "Upload M365 Teams app -> '%s' to the MS Teams catalog; calling -> %s",
            app_path,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=app_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update existing M365 Teams app -> '{}' (may be because it is not a new version)".format(
                app_path,
            ),
        )

    # end method definition

    def remove_teams_app(self, app_id: str) -> None:
        """Remove MS Teams App from the app catalog.

        Args:
            app_id (str):
                The Microsoft 365 GUID of the MS Teams app.

        """

        request_url = self.config()["teamsAppsUrl"] + "/" + app_id
        # Here we need the credentials of an authenticated user!
        # (not the application credentials (client_id, client_secret))
        request_header = self.request_header_user()

        # Make the DELETE request to remove the app from the app catalog
        response = requests.delete(
            request_url,
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
        )

        # Check the status code of the response
        if response.status_code == 204:
            self.logger.debug(
                "The M365 Teams app with ID -> %s has been successfully removed from the app catalog.",
                app_id,
            )
        else:
            self.logger.error(
                "An error occurred while removing the M365 Teams app from the M365 app catalog. Status code -> %s. Error message -> %s",
                response.status_code,
                response.text,
            )

    # end method definition

    def assign_teams_app_to_user(
        self,
        user_id: str,
        app_name: str = "",
        app_internal_id: str = "",
        show_error: bool = False,
    ) -> dict | None:
        """Assign (add) a M365 Teams app to a M365 user.

        See: https://learn.microsoft.com/en-us/graph/api/userteamwork-post-installedapps?view=graph-rest-1.0&tabs=http

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).
            app_name (str, optional):
                The exact name of the app. Not needed if app_internal_id is provided.
            app_internal_id (str, optional):
                The internal ID of the app. If not provided it will be derived from app_name.
            show_error (bool, optional):
                Whether or not an error should be displayed if the user is not found.

        Returns:
            dict | None:
                The response of the MS Graph API call or None if the call fails.

        """

        if not app_internal_id and not app_name:
            self.logger.error(
                "Either the internal App ID or the App name need to be provided!",
            )
            return None

        if not app_internal_id:
            response = self.get_teams_apps(
                filter_expression="contains(displayName, '{}')".format(app_name),
            )
            app_internal_id = self.get_result_value(
                response=response,
                key="id",
                index=0,
            )
            if not app_internal_id:
                self.logger.error(
                    "M365 Teams App -> '%s' not found! Cannot assign App to user -> %s.",
                    app_name,
                    user_id,
                )
                return None

        request_url = self.config()["usersUrl"] + "/" + user_id + "/teamwork/installedApps"
        request_header = self.request_header()

        post_body = {
            "teamsApp@odata.bind": self.config()["teamsAppsUrl"] + "/" + app_internal_id,
        }

        self.logger.debug(
            "Assign M365 Teams app -> '%s' (%s) to M365 user -> %s; calling -> %s",
            app_name,
            app_internal_id,
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=post_body,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to assign M365 Teams app -> '{}' ({}) to M365 user -> {}".format(
                app_name,
                app_internal_id,
                user_id,
            ),
            warning_message="Failed to assign M365 Teams app -> '{}' ({}) to M365 user -> {} (could be the app is assigned organization-wide)".format(
                app_name,
                app_internal_id,
                user_id,
            ),
            show_error=show_error,
        )

    # end method definition

    def upgrade_teams_app_of_user(
        self,
        user_id: str,
        app_name: str,
        app_installation_id: str | None = None,
    ) -> dict | None:
        """Upgrade a MS teams app for a user.

        The call will fail if the user does not already have the app assigned.
        So this needs to be checked before calling this method.

        See: https://learn.microsoft.com/en-us/graph/api/userteamwork-teamsappinstallation-upgrade?view=graph-rest-1.0&tabs=http

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).
            app_name (str):
                The exact name of the app.
            app_installation_id (str | None, optional):
                The ID of the app installation for the user. This is neither the internal nor
                external app ID. It is specific for each user and app.

        Returns:
            dict | None:
                Response of the MS Graph API call or None if the call fails.

        """

        if not app_installation_id:
            response = self.get_teams_apps_of_user(
                user_id=user_id,
                filter_expression="contains(teamsAppDefinition/displayName, '{}')".format(
                    app_name,
                ),
            )
            # Retrieve the installation specific App ID - this is different from thew App catalalog ID!!
            app_installation_id = self.get_result_value(response=response, key="id", index=0)
        if not app_installation_id:
            self.logger.error(
                "M365 Teams app -> '%s' not found for user with ID -> %s. Cannot upgrade app for this user!",
                app_name,
                user_id,
            )
            return None

        request_url = (
            self.config()["usersUrl"] + "/" + user_id + "/teamwork/installedApps/" + app_installation_id + "/upgrade"
        )
        request_header = self.request_header()

        self.logger.debug(
            "Upgrade M365 Teams app -> '%s' (%s) of M365 user with ID -> %s; calling -> %s",
            app_name,
            app_installation_id,
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to upgrade M365 Teams app -> '{}' ({}) of M365 user -> {}".format(
                app_name,
                app_installation_id,
                user_id,
            ),
        )

    # end method definition

    def remove_teams_app_from_user(
        self,
        user_id: str,
        app_name: str,
        app_installation_id: str | None = None,
    ) -> dict | None:
        """Remove a M365 Teams app from a M365 user.

           See: https://learn.microsoft.com/en-us/graph/api/userteamwork-delete-installedapps?view=graph-rest-1.0&tabs=http

        Args:
            user_id (str):
                The M365 GUID of the user (can also be the M365 email of the user).
            app_name (str):
                The exact name of the app.
            app_installation_id (str | None):
                The installation ID of the app. Default is None.

        Returns:
            dict:
                Response of the MS Graph API call or None if the call fails.

        """

        if not app_installation_id:
            response = self.get_teams_apps_of_user(
                user_id=user_id,
                filter_expression="contains(teamsAppDefinition/displayName, '{}')".format(
                    app_name,
                ),
            )
            # Retrieve the installation specific App ID - this is different from thew App catalalog ID!!
            app_installation_id = self.get_result_value(response=response, key="id", index=0)
        if not app_installation_id:
            self.logger.error(
                "M365 Teams app -> '%s' not found for user with ID -> %s. Cannot remove app from this user!",
                app_name,
                user_id,
            )
            return None

        request_url = self.config()["usersUrl"] + "/" + user_id + "/teamwork/installedApps/" + app_installation_id
        request_header = self.request_header()

        self.logger.debug(
            "Remove M365 Teams app -> '%s' (%s) from M365 user with ID -> %s; calling -> %s",
            app_name,
            app_installation_id,
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to remove M365 Teams app -> '{}' ({}) from M365 user -> {}".format(
                app_name,
                app_installation_id,
                user_id,
            ),
        )

    # end method definition

    def assign_teams_app_to_team(self, team_id: str, app_id: str) -> dict | None:
        """Assign (add) a MS Teams app to a M365 team.

        Afterwards the app can be added as a Tab in a M365 Teams Channel).

        Args:
            team_id (str):
                The ID of the Microsoft 365 Team.
            app_id (str):
                The ID of the M365 Team App.

        Returns:
            dict | None:
                API response or None if the Graph API call fails.

        """

        request_url = self.config()["teamsUrl"] + "/" + team_id + "/installedApps"
        request_header = self.request_header()

        post_body = {
            "teamsApp@odata.bind": self.config()["teamsAppsUrl"] + "/" + app_id,
        }

        self.logger.debug(
            "Assign M365 Teams app -> '%s' (%s) to M365 Team -> %s; calling -> %s",
            self.config()["teamsAppName"],
            app_id,
            team_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=post_body,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to assign M365 Teams app -> '{}' ({}) to M365 Team -> {}".format(
                self.config()["teamsAppName"],
                app_id,
                team_id,
            ),
        )

    # end method definition

    def upgrade_teams_app_of_team(self, team_id: str, app_name: str) -> dict | None:
        """Upgrade a MS teams app for a specific team.

        The call will fail if the team does not already have the app assigned.
        So this needs to be checked before calling this method.

        THIS IS CURRENTLY NOT WORKING AS EXPECTED.

        Args:
            team_id (str):
                M365 GUID of the user (can also be the M365 email of the user).
            app_name (str):
                The exact name of the app.

        Returns:
            dict:
                The response of the MS Graph API call or None if the call fails.

        """

        response = self.get_teams_apps_of_team(
            team_id=team_id,
            filter_expression="contains(teamsAppDefinition/displayName, '{}')".format(app_name),
        )
        # Retrieve the installation specific App ID - this is different from thew App catalalog ID!!
        app_installation_id = self.get_result_value(response=response, key="id", index=0)
        if not app_installation_id:
            self.logger.error(
                "M365 Teams app -> '%s' not found for M365 Team with ID -> %s. Cannot upgrade app for this team!",
                app_name,
                team_id,
            )
            return None

        request_url = self.config()["teamsUrl"] + "/" + team_id + "/installedApps/" + app_installation_id + "/upgrade"
        request_header = self.request_header()

        self.logger.debug(
            "Upgrade app -> '%s' (%s) of M365 team with ID -> %s; calling -> %s",
            app_name,
            app_installation_id,
            team_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to upgrade M365 Teams app -> '{}' ({}) of M365 team with ID -> {}".format(
                app_name,
                app_installation_id,
                team_id,
            ),
        )

    # end method definition

    def add_teams_app_to_channel(
        self,
        team_name: str,
        channel_name: str,
        app_id: str,
        tab_name: str,
        app_url: str,
        cs_node_id: int,
    ) -> dict | None:
        """Add tab for Extended ECM app to an M365 Team channel.

        Args:
            team_name (str):
                The name of the M365 Team
            channel_name (str):
                The name of the channel.
            app_id (str):
                ID of the MS Teams Application (e.g. the Extended ECM Teams App).
            tab_name (str):
                The name of the tab.
            app_url (str):
                The web URL of the app.
            cs_node_id (int):
                The node ID of the target workspace or container in Extended ECM.

        Returns:
            dict:
                Return data structure (dictionary) or None if the request fails.

            Example return data:

        """

        response = self.get_team(name=team_name)
        team_id = self.get_result_value(response=response, key="id", index=0)
        if not team_id:
            return None

        # Get the channels of the M365 Team:
        response = self.get_team_channels(name=team_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            self.logger.error(
                "Cannot find Channel -> '%s' on M365 Team -> '%s'!",
                channel_name,
                team_name,
            )
            return None
        channel_id = channel["id"]

        request_url = self.config()["teamsUrl"] + "/" + str(team_id) + "/channels/" + str(channel_id) + "/tabs"

        request_header = self.request_header()

        # Create tab configuration payload:
        tab_config = {
            "teamsApp@odata.bind": f"https://graph.microsoft.com/v1.0/appCatalogs/teamsApps/{app_id}",
            "displayName": tab_name,
            "configuration": {
                "entityId": cs_node_id,  # Unique identifier for the tab
                "contentUrl": app_url,
                "removeUrl": "",
                "websiteUrl": app_url + "&showBW=true&title=" + tab_name,
            },
        }

        self.logger.debug(
            "Add Tab -> '%s' with App ID -> %s to Channel -> '%s' of Microsoft 365 Team -> '%s'; calling -> %s",
            tab_name,
            app_id,
            channel_name,
            team_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=tab_config,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to add Tab for M365 Team -> '{}' ({}) and Channel -> '{}' ({})".format(
                team_name,
                team_id,
                channel_name,
                channel_id,
            ),
        )

    # end method definition

    def update_teams_app_of_channel(
        self,
        team_name: str,
        channel_name: str,
        tab_name: str,
        app_url: str,
        cs_node_id: int,
    ) -> dict | None:
        """Update an existing tab for Extended ECM app in an M365 Team channel.

        Args:
            team_name (str):
                The name of the M365 Team.
            channel_name (str):
                The name of the channel.
            tab_name (str):
                The name of the tab.
            app_url (str):
                The web URL of the app.
            cs_node_id (int):
                The node ID of the target workspace or container in Content Server.

        Returns:
            dict:
                Return data structure (dictionary) or None if the request fails.

        """

        response = self.get_team(name=team_name)
        team_id = self.get_result_value(response=response, key="id", index=0)
        if not team_id:
            return None

        # Get the channels of the M365 Team:
        response = self.get_team_channels(name=team_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            self.logger.error(
                "Cannot find Channel -> '%s' for M365 Team -> '%s'!",
                channel_name,
                team_name,
            )
            return None
        channel_id = channel["id"]

        # Get the tabs of the M365 Team channel:
        response = self.get_team_channel_tabs(team_name=team_name, channel_name=channel_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the tab by name and then retrieve its ID:
        tab = next(
            (item for item in response["value"] if item["displayName"] == tab_name),
            None,
        )
        if not tab:
            self.logger.error(
                "Cannot find Tab -> '%s' on M365 Team -> '%s' (%s) and Channel -> '%s' (%s)!",
                tab_name,
                team_name,
                team_id,
                channel_name,
                channel_id,
            )
            return None
        tab_id = tab["id"]

        request_url = (
            self.config()["teamsUrl"] + "/" + str(team_id) + "/channels/" + str(channel_id) + "/tabs/" + str(tab_id)
        )

        request_header = self.request_header()

        # Create tab configuration payload:
        tab_config = {
            "configuration": {
                "entityId": cs_node_id,  # Unique identifier for the tab
                "contentUrl": app_url,
                "removeUrl": "",
                "websiteUrl": app_url + "&showBW=true&title=" + tab_name,
            },
        }

        self.logger.debug(
            "Update Tab -> '%s' (%s) of Channel -> '%s' (%s) for Microsoft 365 Teams -> '%s' (%s) with configuration -> %s; calling -> %s",
            tab_name,
            tab_id,
            channel_name,
            channel_id,
            team_name,
            team_id,
            str(tab_config),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PATCH",
            headers=request_header,
            json_data=tab_config,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update Tab -> '{}' ({}) for M365 Team -> '{}' ({}) and Channel -> '{}' ({})".format(
                tab_name,
                tab_id,
                team_name,
                team_id,
                channel_name,
                channel_id,
            ),
        )

    # end method definition

    def delete_teams_app_from_channel(
        self,
        team_name: str,
        channel_name: str,
        tab_name: str,
    ) -> bool:
        """Delete an existing tab for Extended ECM app from an M365 Team channel.

        Args:
            team_name (str):
                The name of the M365 Team.
            channel_name (str):
                The name of the channel.
            tab_name (str):
                The name of the tab.

        Returns:
            bool:
                True = success, False = Error.

        """

        response = self.get_team(name=team_name)
        team_id = self.get_result_value(response=response, key="id", index=0)
        if not team_id:
            return False

        # Get the channels of the M365 Team:
        response = self.get_team_channels(team_name)
        if not response or not response["value"] or not response["value"][0]:
            return False

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            self.logger.error(
                "Cannot find Channel -> '%s' for M365 Team -> '%s'!",
                channel_name,
                team_name,
            )
            return False
        channel_id = channel["id"]

        # Get the tabs of the M365 Team channel:
        response = self.get_team_channel_tabs(team_name=team_name, channel_name=channel_name)
        if not response or not response["value"] or not response["value"][0]:
            return False

        # Lookup the tabs by name and then retrieve their IDs (in worst case it can
        # be multiple tabs / apps with same name if former cleanups did not work):
        tab_list = [item for item in response["value"] if item["displayName"] == tab_name]
        if not tab_list:
            self.logger.error(
                "Cannot find Tab -> '%s' on M365 Team -> '%s' (%s) and Channel -> '%s' (%s)!",
                tab_name,
                team_name,
                team_id,
                channel_name,
                channel_id,
            )
            return False

        for tab in tab_list:
            tab_id = tab["id"]

            request_url = (
                self.config()["teamsUrl"] + "/" + str(team_id) + "/channels/" + str(channel_id) + "/tabs/" + str(tab_id)
            )

            request_header = self.request_header()

            self.logger.debug(
                "Delete Tab -> '%s' (%s) from Channel -> '%s' (%s) of Microsoft 365 Teams -> '%s' (%s); calling -> %s",
                tab_name,
                tab_id,
                channel_name,
                channel_id,
                team_name,
                team_id,
                request_url,
            )

            response = self.do_request(
                url=request_url,
                method="DELETE",
                headers=request_header,
                timeout=REQUEST_TIMEOUT,
                failure_message="Failed to delete Tab -> '{}' ({}) for M365 Team -> '{}' ({}) and Channel -> '{}' ({})".format(
                    tab_name,
                    tab_id,
                    team_name,
                    team_id,
                    channel_name,
                    channel_id,
                ),
                parse_request_response=False,
            )

            if response and response.ok:
                break
            return False
        # end for tab in tab_list

        return True

    # end method definition

    def add_sensitivity_label(
        self,
        name: str,
        display_name: str,
        description: str = "",
        color: str = "red",
        enabled: bool = True,
        admin_description: str = "",
        user_description: str = "",
        enable_encryption: bool = False,
        enable_marking: bool = False,
    ) -> dict | None:
        """Create a new sensitivity label in M365.

        TODO: THIS IS CURRENTLY NOT WORKING!

        Args:
            name (str):
                The name of the label.
            display_name (str):
                The display name of the label.
            description (str, optional):
                Description of the label. Defaults to "".
            color (str, optional):
                Color of the label. Defaults to "red".
            enabled (bool, optional):
                Whether this label is enabled. Defaults to True.
            admin_description (str, optional):
                Description for administrators. Defaults to "".
            user_description (str, optional):
                Description for users. Defaults to "".
            enable_encryption (bool, optional):
                Enable encryption. Defaults to False.
            enable_marking (bool, optional):
                Enable marking. Defaults to False.

        Returns:
            Request reponse or None if the request fails.

        """

        # Prepare the request body
        payload = {
            "displayName": display_name,
            "description": description,
            "isEnabled": enabled,
            "labelColor": color,
            "adminDescription": admin_description,
            "userDescription": user_description,
            "encryptContent": enable_encryption,
            "contentMarking": enable_marking,
        }

        request_url = self.config()["securityUrl"] + "/sensitivityLabels"
        request_header = self.request_header()

        self.logger.debug(
            "Create M365 sensitivity label -> '%s'; calling -> %s",
            name,
            request_url,
        )

        # Send the POST request to create the label
        response = requests.post(
            request_url,
            headers=request_header,
            data=json.dumps(payload),
            timeout=REQUEST_TIMEOUT,
        )

        # Check the response status code
        if response.status_code == 201:
            self.logger.debug("Label -> '%s' has been created successfully!", name)
            return response
        else:
            self.logger.error(
                "Failed to create the M365 label -> '%s'! Response status code -> %s",
                name,
                response.status_code,
            )
            return None

    # end method definition

    def assign_sensitivity_label_to_user(self, user_email: str, label_name: str) -> dict | None:
        """Assign a existing sensitivity label to a user.

        TODO: THIS IS CURRENTLY NOT WORKING!

        Args:
            user_email (str):
                The email address of the user (as unique identifier).
            label_name (str):
                The name of the label (need to exist).

        Returns:
            dict | None:
                Return the request response or None if the request fails.

        """

        # Set up the request body with the label name
        body = {"labelName": label_name}

        request_url = self.config()["usersUrl"] + "/" + user_email + "/assignSensitivityLabels"
        request_header = self.request_header()

        self.logger.debug(
            "Assign label -> '%s' to user -> '%s'; calling -> %s",
            label_name,
            user_email,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=body,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to assign label -> '{}' to M365 user -> '{}'".format(
                label_name,
                user_email,
            ),
        )

    # end method definition

    def upload_outlook_app(
        self,
        app_path: str,
    ) -> dict | None:
        """Upload the M365 Outlook Add-In as "Integrated" App to M365 Admin Center.

        TODO: THIS IS CURRENTLY NOT IMPLEMENTED DUE TO MISSING MS GRAPH API SUPPORT!

        https://admin.microsoft.com/#/Settings/IntegratedApps

        Args:
            app_path (str):
                Path to manifest file in local file system. Needs to be
                downloaded before.

        Returns:
            dict | None:
                Response of the MS Graph API or None if the request fails.

        """

        self.logger.debug(
            "Install Outlook Add-in from -> '%s' (NOT IMPLEMENTED)",
            app_path,
        )

        response = None

        return response

    # end method definition

    def get_app_registration(
        self,
        app_registration_name: str,
    ) -> dict | None:
        """Find an Azure App Registration based on its name.

        Args:
            app_registration_name (str):
                Name of the App Registration.

        Returns:
            dict | None:
                App Registration data or None of the request fails.

        """

        request_url = self.config()["applicationsUrl"] + "?$filter=displayName eq '{}'".format(app_registration_name)
        request_header = self.request_header()

        self.logger.debug(
            "Get Azure App Registration -> '%s'; calling -> %s",
            app_registration_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot find Azure App Registration -> '{}'".format(
                app_registration_name,
            ),
        )

    # end method definition

    def add_app_registration(
        self,
        app_registration_name: str,
        description: str = "",
        api_permissions: list | None = None,
        supported_account_type: str = "AzureADMyOrg",
    ) -> dict:
        """Add an Azure App Registration.

        Args:
            app_registration_name (str):
                The name of the App Registration.
            description (str, optional):
                The description of the app.
            api_permissions (list | None, optional):
                The API permissions.
            supported_account_type (str, optional):
                The type of account that is supposed to use
                the App Registration.

        Returns:
            dict:
                App Registration data or None of the request fails.

            Example data:
            {
                'id': 'd70bee91-3689-4239-a626-30756968e99c',
                'deletedDateTime': None,
                'appId': 'd288ba5f-9313-4b38-b4a4-d7edcce089b0',
                'applicationTemplateId': None,
                'disabledByMicrosoftStatus': None,
                'createdDateTime': '2023-09-06T21:06:05Z',
                'displayName': 'Test 1',
                'description': None,
                'groupMembershipClaims': None,
                'identifierUris': [],
                'isDeviceOnlyAuthSupported': None,
                'isFallbackPublicClient': None,
                'notes': None,
                'publisherDomain': 'M365x41497014.onmicrosoft.com',
                'signInAudience': 'AzureADMyOrg',
                ...
                'requiredResourceAccess': [
                    {
                        'resourceAppId': '00000003-0000-0ff1-ce00-000000000000',
                        'resourceAccess': [
                            {
                                'id': '741f803b-c850-494e-b5df-cde7c675a1ca',
                                'type': 'Role'
                            },
                            {
                                'id': 'c8e3537c-ec53-43b9-bed3-b2bd3617ae97',
                                'type': 'Role'
                            },
                        ]
                    },
                ]
            }

        """

        # Define the request body to create the App Registration
        app_registration_data = {
            "displayName": app_registration_name,
            "signInAudience": supported_account_type,
        }
        if api_permissions:
            app_registration_data["requiredResourceAccess"] = api_permissions
        if description:
            app_registration_data["description"] = description

        request_url = self.config()["applicationsUrl"]
        request_header = self.request_header()

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=app_registration_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot add App Registration -> '{}'".format(
                app_registration_name,
            ),
        )

    # end method definition

    def update_app_registration(
        self,
        app_registration_id: str,
        app_registration_name: str,
        api_permissions: list,
        supported_account_type: str = "AzureADMyOrg",
    ) -> dict:
        """Update an Azure App Registration.

        Args:
            app_registration_id (str):
                The ID of the existing App Registration.
            app_registration_name (str):
                The name of the App Registration.
            api_permissions (list):
                The API permissions.
            supported_account_type (str, optional):
                The type of account that is supposed to use
                the App Registration.

        Returns:
            dict:
                App Registration data or None of the request fails.

        """

        # Define the request body to create the App Registration
        app_registration_data = {
            "displayName": app_registration_name,
            "requiredResourceAccess": api_permissions,
            "signInAudience": supported_account_type,
        }

        request_url = self.config()["applicationsUrl"] + "/" + app_registration_id
        request_header = self.request_header()

        self.logger.debug(
            "Update App Registration -> '%s' (%s); calling -> %s",
            app_registration_name,
            app_registration_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PATCH",
            headers=request_header,
            json_data=app_registration_data,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot update App Registration -> '{}' ({})".format(
                app_registration_name,
                app_registration_id,
            ),
        )

    # end method definition

    def get_mail(
        self,
        user_id: str,
        sender: str,
        subject: str,
        num_emails: int | None = None,
        show_error: bool = False,
    ) -> dict | None:
        """Get email from inbox of a given user and a given sender (from).

        This requires Mail.Read Application permissions for the Azure App being used.

        Args:
            user_id (str):
                The M365 ID of the user.
            sender (str):
                The sender email address to filter for.
            subject (str):
                The subject to filter for.
            num_emails (int, optional):
                The number of matching emails to retrieve.
            show_error (bool, optional):
                Whether or not an error should be displayed if the
                user is not found.

        Returns:
            dict:
                Email or None of the request fails.

        """

        # Attention: you  can easily run in limitation of the MS Graph API. If selection + filtering
        # is too complex you can get this error: "The restriction or sort order is too complex for this operation."
        # that's why we first just do the ordering and then do the filtering on sender and subject
        # separately
        request_url = (
            self.config()["usersUrl"]
            + "/"
            + user_id
            #            + "/messages?$filter=from/emailAddress/address eq '{}' and contains(subject, '{}')&$orderby=receivedDateTime desc".format(
            + "/messages?$orderby=receivedDateTime desc"
        )
        if num_emails:
            request_url += "&$top={}".format(num_emails)

        request_header = self.request_header()

        self.logger.debug(
            "Get mails for user -> %s from -> '%s' with subject -> '%s'; calling -> %s",
            user_id,
            sender,
            subject,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot retrieve emails for M365 user -> {}".format(user_id),
            show_error=show_error,
        )

        if response and "value" in response:
            messages = response["value"]

            # Filter the messages by sender and subject in code
            filtered_messages = [
                msg
                for msg in messages
                if msg.get("from", {}).get("emailAddress", {}).get("address") == sender
                and subject in msg.get("subject", "")
            ]
            response["value"] = filtered_messages
            return response

        return None

    # end method definition

    def get_mail_body(self, user_id: str, email_id: str) -> str | None:
        """Get full email body for a given email ID.

        This requires Mail.Read Application permissions for the Azure App being used.

        Args:
            user_id (str):
                The M365 ID of the user.
            email_id (str):
                The M365 ID of the email.

        Returns:
            str | None:
                Email body or None of the request fails.

        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/messages/" + email_id + "/$value"

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get email body for M365 user -> {} and email with ID -> {}".format(
                user_id,
                email_id,
            ),
            parse_request_response=False,
        )

        if response and response.ok and response.content:
            return response.content.decode("utf-8")

        return None

    # end method definition

    def extract_url_from_message_body(
        self,
        message_body: str,
        search_pattern: str,
        multi_line: bool = False,
        multi_line_end_marker: str = "%3D",
        line_end_marker: str = "=",
        replacements: list | None = None,
    ) -> str | None:
        """Parse the email body to extract (a potentially multi-line) URL from the body.

        Args:
            message_body (str):
                Text of the Email body.
            search_pattern (str):
                Pattern that needs to be in first line of the URL. This
                makes sure it is the right URL we are looking for.
            multi_line (bool, optional):
                Is the URL spread over multiple lines?. Defaults to False.
            multi_line_end_marker (str, optional):
                If it is a multi-line URL, what marks the end
                of the URL in the last line? Defaults to "%3D".
            line_end_marker (str, optional):
                What marks the end of lines 1-(n-1)? Defaults to "=".
            replacements (list, optional):
                A list of replacements.

        Returns:
            str | None:
                The URL text that has been extracted. None in case of an error.

        """

        if not message_body:
            return None

        # Split all the lines after a CRLF:
        lines = [line.strip() for line in message_body.split("\r\n")]

        # Filter out the complete URL from the extracted URLs
        found = False

        url = ""

        for line in lines:
            if found:
                # Remove line end marker - many times a "="
                if line.endswith(line_end_marker):
                    line = line[:-1]
                for replacement in replacements:
                    line = line.replace(replacement["from"], replacement["to"])
                # We consider an empty line after we found the URL to indicate the end of the URL:
                if line == "":
                    break
                url += line
            if multi_line and line.endswith(multi_line_end_marker):
                break
            if search_pattern not in line:
                continue
            # Fine https:// in the current line:
            index = line.find("https://")
            if index == -1:
                continue
            # If there's any text in front of https in that line cut it:
            line = line[index:]
            # Remove line end marker - many times a "="
            if line.endswith(line_end_marker):
                line = line[:-1]
            for replacement in replacements:
                line = line.replace(replacement["from"], replacement["to"])
            found = True
            url += line
            if not multi_line:
                break

        return url

    # end method definition

    def delete_mail(self, user_id: str, email_id: str) -> dict | None:
        """Delete email from inbox of a given user and a given email ID.

        This requires Mail.ReadWrite Application permissions for the Azure App being used.

        Args:
            user_id (str):
                The M365 ID of the user.
            email_id (str):
                The M365 ID of the email.

        Returns:
            dict | None:
                Email or None of the request fails.

        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/messages/" + email_id

        request_header = self.request_header()

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot delete email with ID -> {} from inbox of M365 user -> {}".format(
                email_id,
                user_id,
            ),
        )

    # end method definition

    def email_verification(
        self,
        user_email: str,
        sender: str,
        subject: str,
        url_search_pattern: str,
        line_end_marker: str = "=",
        multi_line: bool = True,
        multi_line_end_marker: str = "%3D",
        replacements: list | None = None,
        max_retries: int = 6,
        use_browser_automation: bool = False,
        password: str = "",
        password_field_id: str = "",
        password_confirmation_field_id: str = "",
        password_submit_xpath: str = "",
        terms_of_service_xpath: str = "",
    ) -> bool:
        """Process email verification.

        Args:
            user_email (str):
                Email address of user recieving the verification mail.
            sender (str):
                Email sender (address)
            subject (str):
                Email subject to look for (can be substring)
            url_search_pattern (str):
                String the URL needs to contain to identify it.
            line_end_marker (str, optional):
                The character that marks line ends in the mail.
            multi_line (bool, optional):
                Whether or not this is a multi-line mail.
            multi_line_end_marker (str, optional):
                If the URL spans multiple lines this is the "end" marker for the last line.
            replacements (list, optional):
                If the URL needs some treatment these replacements can be applied.
            max_retries (int, optional):
                The number of retries in case of an error.
            use_browser_automation (bool, optional):
                If Selenium-based browser automation should be used or not. Default = False.
            password (str, optional):
                In case a password is required for browser automation. Default = "",
            password_field_id (str, optional):
                The password field name in the HTML page of a confirmation dialog. Default = "",
            password_confirmation_field_id (str, optional):
                The password confirmation field name in the HTML page of a confirmation dialog.
                Default = "".
            password_submit_xpath (str, optional):
                Default = "".
            terms_of_service_xpath (str, optional):
                Default = "".

        Returns:
            bool:
                True = Success, False = Failure.

        """

        # Determine the M365 user for the current user by
        # the email address:
        m365_user = self.get_user(user_email=user_email)
        m365_user_id = self.get_result_value(response=m365_user, key="id")
        if not m365_user_id:
            self.logger.warning("Cannot find M365 user -> %s", user_email)
            return False

        if replacements is None:
            replacements = [{"from": "=3D", "to": "="}]

        retries = 0
        while retries < max_retries:
            response = self.get_mail(
                user_id=m365_user_id,
                sender=sender,
                subject=subject,
                show_error=False,
            )
            if response and response["value"]:
                emails = response["value"]
                # potentially there may be multiple matching emails,
                # we want the most recent one (from today):
                latest_email = max(emails, key=lambda x: x["receivedDateTime"])
                # Extract just the date:
                latest_email_date = latest_email["receivedDateTime"].split("T")[0]
                # Get the current date (today):
                today_date = datetime.now(UTC).strftime("%Y-%m-%d")
                # We do a sanity check here: the verification mail should be from today,
                # otherwise we assume it is an old mail and we need to wait for the
                # new verification mail to yet arrive:
                if latest_email_date != today_date:
                    self.logger.info(
                        "Verification email not yet received (latest mail from -> %s). Waiting %s seconds...",
                        latest_email_date,
                        10 * (retries + 1),
                    )
                    time.sleep(10 * (retries + 1))
                    retries += 1
                    continue
                email_id = latest_email["id"]
                # The full email body needs to be loaded with a separate REST call:
                body_text = self.get_mail_body(user_id=m365_user_id, email_id=email_id)
                # Extract the verification URL.
                if body_text:
                    url = self.extract_url_from_message_body(
                        message_body=body_text,
                        search_pattern=url_search_pattern,
                        line_end_marker=line_end_marker,
                        multi_line=multi_line,
                        multi_line_end_marker=multi_line_end_marker,
                        replacements=replacements,
                    )
                else:
                    url = ""
                if not url:
                    self.logger.warning(
                        "Cannot find verification link in the email body!",
                    )
                    return False
                # Simulate a "click" on this URL:
                if use_browser_automation:
                    self.logger.info("Using browser automation for email verification...")
                    # Core Share needs a full browser:
                    try:
                        browser_automation_object = BrowserAutomation(
                            take_screenshots=True,
                            automation_name="email-verification",
                            logger=self.logger,
                        )
                    except Exception:
                        self.logger.error("Failed to create browser automation object. Bailing out...")
                        return False

                    self.logger.info(
                        "Open URL -> %s to verify account or email address change...",
                        url,
                    )
                    success = browser_automation_object.get_page(url=url)
                    if success:
                        user_interaction_required = False
                        self.logger.info(
                            "Successfully opened URL. Browser title is -> '%s'.",
                            browser_automation_object.get_title(),
                        )
                        if password_field_id:
                            password_field = browser_automation_object.find_elem(
                                selector=password_field_id,
                                show_error=False,
                            )
                            if password_field:
                                # The subsequent processing is only required if
                                # the returned page requests a password change:
                                user_interaction_required = True
                                self.logger.info(
                                    "Found password field on returned page - it seems email verification requests password entry!",
                                )
                                result = browser_automation_object.find_elem_and_set(
                                    selector=password_field_id,
                                    value=password,
                                    is_sensitive=True,
                                )
                                if not result:
                                    self.logger.error(
                                        "Failed to enter password in field -> '%s'!",
                                        password_field_id,
                                    )
                                    success = False
                            else:
                                self.logger.info(
                                    "No user interaction required (no password change or terms of service acceptance).",
                                )
                        if user_interaction_required and password_confirmation_field_id:
                            password_confirm_field = browser_automation_object.find_elem(
                                selector=password_confirmation_field_id,
                                show_error=False,
                            )
                            if password_confirm_field:
                                self.logger.info(
                                    "Found password confirmation field on returned page - it seems email verification requests consecutive password.",
                                )
                                result = browser_automation_object.find_elem_and_set(
                                    selector=password_confirmation_field_id,
                                    value=password,
                                    is_sensitive=True,
                                )
                                if not result:
                                    self.logger.error(
                                        "Failed to enter password in field -> '%s'!",
                                        password_confirmation_field_id,
                                    )
                                    success = False
                        if user_interaction_required and password_submit_xpath:
                            password_submit_button = browser_automation_object.find_elem(
                                selector=password_submit_xpath,
                                selector_type="xpath",
                                show_error=False,
                            )
                            if password_submit_button:
                                self.logger.info(
                                    "Submit password change dialog with button -> '%s' (found with XPath -> %s).",
                                    password_submit_button.inner_text(),
                                    password_submit_xpath,
                                )
                                result = browser_automation_object.find_elem_and_click(
                                    selector=password_submit_xpath,
                                    selector_type="xpath",
                                )
                                if not result:
                                    self.logger.error(
                                        "Failed to press submit button -> %s",
                                        password_submit_xpath,
                                    )
                                    success = False
                            # The Terms of service dialog has some weird animation
                            # which require a short wait time. It seems it is required!
                            time.sleep(1)
                            terms_accept_button = browser_automation_object.find_elem(
                                selector=terms_of_service_xpath,
                                selector_type="xpath",
                                show_error=False,
                            )
                            if terms_accept_button:
                                self.logger.info(
                                    "Accept terms of service with button -> '%s' (found with XPath -> %s).",
                                    terms_accept_button.inner_text(),
                                    terms_of_service_xpath,
                                )
                                result = browser_automation_object.find_elem_and_click(
                                    selector=terms_of_service_xpath,
                                    selector_type="xpath",
                                )
                                if not result:
                                    self.logger.error(
                                        "Failed to accept terms of service with button -> '%s'!",
                                        terms_accept_button.inner_text(),
                                    )
                                    success = False
                            else:
                                self.logger.info(
                                    "No Terms of Service acceptance required.",
                                )
                        # end if user_interaction_required and password_submit_xpath:
                    # end if success:
                # end if use_browser_automation
                else:
                    # Salesforce (other than Core Share) is OK with the simple HTTP GET request:
                    self.logger.info(
                        "Open URL -> %s to verify account or email change...",
                        url,
                    )
                    response = self._http_object.http_request(url=url, method="GET")
                    success = response and response.ok

                if success:
                    self.logger.info(
                        "Remove email from inbox of user -> %s...",
                        user_email,
                    )
                    response = self.delete_mail(user_id=m365_user_id, email_id=email_id)
                    if not response:
                        self.logger.warning(
                            "Couldn't remove the mail from the inbox of user -> %s!",
                            user_email,
                        )
                    # We have success now and can break from the while loop
                    return True
                else:
                    self.logger.error(
                        "Failed to process e-mail verification for user -> %s!",
                        user_email,
                    )
                    return False
            # end if response and response["value"]
            else:
                self.logger.info(
                    "Verification email not yet received (no mails with sender -> %s and subject -> '%s' found). Waiting %s seconds...",
                    sender,
                    subject,
                    10 * (retries + 1),
                )
                time.sleep(10 * (retries + 1))
                retries += 1
        # end while

        self.logger.warning(
            "Verification mail for user -> %s has not arrived in time.",
            user_email,
        )

        return False

    # end method definition

    def get_sharepoint_sites(
        self,
        search: str | None = None,
        filter_expression: str | None = None,
        select: str | None = None,
        limit: int = 50,
        next_page_url: str | None = None,
    ) -> dict | None:
        """Retrieve a list of SharePoint sites.

        Args:
            search (str, optional):
                A string to search for to filter the results. Default is None = no filtering.
            filter_expression (str | None, optional):
                Filter string to filter the results. Default is None = no filtering.
            select (str | None, optional):
                Fields to select. Make sure that all fields are selected that are used in filters.
                Otherwise you will get no results.
            limit (int, optional):
                The maximum number of sites to return in one call.
                Default is set to 50.
            next_page_url (str | None, optional):
                The MS Graph URL to retrieve the next page of SharePoint sites (pagination).
                This is used for the iterator get_sharepoint_sites_iterator() below.

        Returns:
            dict | None:
                A list of SharePoint sites embedded in a "value" key in the dictionary.

        Example response:
        {
            '@odata.context': 'https://graph.microsoft.com/beta/$metadata#sites',
            '@odata.nextLink': 'https://graph.microsoft.com/beta/sites?$top=50&$skiptoken=UGFnZWQ9VFJVRSZwX1RpbWVEZWxldGVkPSZwX0lEPTE5MDM4',
            'value': [
                {
                    'createdDateTime': '2025-02-11T12:11:49Z',
                    'id': 'ideatedev-my.sharepoint.com,eeed2961-91ba-46c1-abc2-159f0277130f,5aa8a98d-659d-4a52-8701-6b9a728092d8',
                    'name': 'Diane Conner',
                    'webUrl': 'https://ideatedev-my.sharepoint.com/personal/dconner_dev_idea-te_eimdemo_com',
                    'displayName': 'Diane Conner',
                    'isPersonalSite': True,
                    'siteCollection': {
                        'hostname': 'ideatedev-my.sharepoint.com'
                    },
                    'root': {}
                },
                {
                    'createdDateTime': '2025-02-06T07:44:44Z',
                    'id': 'ideatedev.sharepoint.com,570e67bc-1e69-4a62-89ea-994be9642b93,a1462b54-26f9-4a24-9660-2bc7859ce9af',
                    'name': 'SG325B - SEMI325B,ECM,PD,ExternalProcurement',
                    'webUrl': 'https://ideatedev.sharepoint.com/sites/SG325B-SEMI325BECMPDExternalProcurement698',
                    'displayName': 'SG325B - SEMI325B,ECM,PD,ExternalProcurement',
                    'isPersonalSite': False,
                    'siteCollection': {
                        'hostname': 'ideatedev.sharepoint.com'
                    },
                    'root': {}
                },
                ...
            ]
        ]

        """

        if not next_page_url:
            query = {}
            if select:
                query["$select"] = select
            if filter_expression:
                query["$filter"] = filter_expression
            if search:
                query["search"] = search
            if limit:
                query["$top"] = limit

            encoded_query = "?" + urllib.parse.urlencode(query, doseq=True) if query else ""
            request_url = self.config()["sitesUrl"] + encoded_query
        else:
            request_url = next_page_url
        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get SharePoint sites",
        )

        return response

    # end method definition

    def get_sharepoint_root_sites(self) -> dict | None:
        """Get all SharePoint root sites.

        Returns:
            dict | None:
                Dictionary that includes a list of root sites in the "value" key.

        """

        response = self.get_sharepoint_sites(
            select="siteCollection,webUrl",
            filter_expression="siteCollection/root ne null",
        )

        return response

    # end method definition

    def get_sharepoint_sites_iterator(
        self,
        search: str | None = None,
        filter_expression: str | None = None,
        select: str | None = None,
        limit: int = 50,
    ) -> iter:
        """Get an iterator object that can be used to traverse all SharePoint sites matching the filter.

        Returning a generator avoids loading a large number of nodes into memory at once. Instead you
        can iterate over the potential large list of SharePoint sites.

        Example usage:
            sites = m365_object.get_sharepoint_sites_iterator(limit=10)
            for site in sites:
                logger.info("Traversing SharePoint site -> '%s'...", site.get("name", "<undefined name>"))

        Args:
            search (str | None, optional):
                A string to search for to filter the results. Default is None = no filtering.
            filter_expression (str | None, optional):
                Filter string to filter the results. Default is None = no filtering.
            select (str | None, optional):
                Fields to select. Make sure that all fields are selected that are used in filters.
                Otherwise you will get no results.
            limit (int, optional):
                The maximum number of sites to return in one call.
                Default is set to 50.

        Returns:
            iter:
                A generator yielding one SharePoint site per iteration.
                If the REST API fails, returns no value.

        """

        next_page_url = None

        while True:
            response = self.get_sharepoint_sites(
                search=search,
                filter_expression=filter_expression,
                select=select,
                limit=limit,
                next_page_url=next_page_url,
            )
            if not response or "value" not in response:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

            # Yield users one at a time:
            yield from response["value"]

            # See if we have an additional result page.
            # If not terminate the iterator and return
            # no value.
            next_page_url = response.get("@odata.nextLink", None)
            if not next_page_url:
                # Don't return None! Plain return is what we need for iterators.
                # Natural Termination: If the generator does not yield, it behaves
                # like an empty iterable when used in a loop or converted to a list:
                return

    # end method definition

    def get_sharepoint_site(self, site_id: str) -> dict | None:
        """Retrieve a SharePoint site by its ID.

        Args:
            site_id (str):
                The ID of the SharePoint site the to retrieve.

        Returns:
            dict | None:
                The data of the SharePoint site.

        Example:
        {
            '@odata.context': 'https://graph.microsoft.com/beta/$metadata#sites/$entity',
            'createdDateTime': '2025-02-06T07:41:53.41Z',
            'description': '',
            'id': 'ideatedev.sharepoint.com,9b203cbe-27ca-45b2-944a-663cc99e5e8f,a1462b54-26f9-4a24-9660-2bc7859ce9af',
            'lastModifiedDateTime': '2025-02-10T20:37:11Z',
            'name': 'TG11-Trad.Good11PDReg.Trading795',
            'webUrl': 'https://ideatedev.sharepoint.com/sites/TG11-Trad.Good11PDReg.Trading795',
            'displayName': 'TG11 - Trad.Good 11,PD,Reg.Trading',
            'root': {},
            'siteCollection': {
                'hostname': 'ideatedev.sharepoint.com'
            }
        }

        """

        request_url = self.config()["sitesUrl"] + "/" + site_id

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get SharePoint site with ID -> '{}'".format(site_id),
        )

        return response

    # end method definition

    def get_sharepoint_site_by_name(self, site_name: str) -> dict | None:
        """Retrieve a SharePoint site by its name.

        Args:
            site_name (str):
                The name of the SharePoint site to retrieve.

        Returns:
            dict | None:
                The data of the SharePoint site.

        Example:
        {
            '@odata.context': 'https://graph.microsoft.com/beta/$metadata#sites/$entity',
            'createdDateTime': '2025-02-06T07:41:53.41Z',
            'description': '',
            'id': 'ideatedev.sharepoint.com,9b203cbe-27ca-45b2-944a-663cc99e5e8f,a1462b54-26f9-4a24-9660-2bc7859ce9af',
            'lastModifiedDateTime': '2025-02-10T20:37:11Z',
            'name': 'TG11-Trad.Good11PDReg.Trading795',
            'webUrl': 'https://ideatedev.sharepoint.com/sites/TG11-Trad.Good11PDReg.Trading795',
            'displayName': 'TG11 - Trad.Good 11,PD,Reg.Trading',
            'root': {},
            'siteCollection': {
                'hostname': 'ideatedev.sharepoint.com'
            }
        }

        """

        request_url = self.config()["sitesUrl"] + "?search={}".format(site_name)

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get SharePoint site -> '{}'".format(site_name),
        )

        # As we lookup the site by search we could have multiple results.
        # The Graph API does not do an exact match. So we check the results
        # for an exact match:
        if response:
            results = response.get("value", [])
            for result in results:
                if result["displayName"] == site_name:
                    return result

        return None

    # end method definition

    def get_sharepoint_site_for_group(self, group_id: str) -> dict:
        """Retrieve a SharePoint site for a M365 group.

        Args:
            group_id (str):
                The ID of the M365 group the site should be retrieved for.

        Returns:
            dict:
                The data of the SharePoint site.

        Example:
        {
            '@odata.context': 'https://graph.microsoft.com/beta/$metadata#sites/$entity',
            'createdDateTime': '2025-02-06T07:41:53.41Z',
            'description': '',
            'id': 'ideatedev.sharepoint.com,9b203cbe-27ca-45b2-944a-663cc99e5e8f,a1462b54-26f9-4a24-9660-2bc7859ce9af',
            'lastModifiedDateTime': '2025-02-10T20:37:11Z',
            'name': 'TG11-Trad.Good11PDReg.Trading795',
            'webUrl': 'https://ideatedev.sharepoint.com/sites/TG11-Trad.Good11PDReg.Trading795',
            'displayName': 'TG11 - Trad.Good 11,PD,Reg.Trading',
            'root': {},
            'siteCollection': {
                'hostname': 'ideatedev.sharepoint.com'
            }
        }

        """

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/sites/root"
        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get SharePoint site for group with ID -> '{}'".format(group_id),
        )

        return response

    # end method definition

    def get_sharepoint_pages(self, site_id: str) -> dict:
        """Retrieve a list of SharePoint site pages accessible to the authenticated user.

        Args:
            site_id (str):
                The ID of the SharePoint site the pages should be retrieved for.

        Returns:
            dict:
                A dictionary including the list of SharePoint pages for a given page.
                The actual list is included inside the "value" key of the dictionary.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C61c0f9cb-39d3-4c04-b60c-31576954a2ab%2Ca678aeab-68ac-46a1-bd95-28020c12de26')/pages",
            'value': [
                {
                    '@odata.type': '#microsoft.graph.sitePage',
                    '@odata.etag': '"{A546CE61-21E6-431D-B2CD-67D1F722BE5F},4"',
                    'createdDateTime': '2025-01-26T00:03:24Z',
                    'eTag': '"{A546CE61-21E6-431D-B2CD-67D1F722BE5F},4"',
                    'id': 'a546ce61-21e6-431d-b2cd-67d1f722be5f',
                    'lastModifiedDateTime': '2025-01-26T00:03:24Z',
                    'name': 'Home.aspx',
                    'webUrl': 'https://ideatedev.sharepoint.com/sites/TG11-Trad.Good11PDReg.Trading795/SitePages/Home.aspx',
                    'title': 'Home',
                    'pageLayout': 'home',
                    'promotionKind': 'page',
                    'showComments': False,
                    'showRecommendedPages': False,
                    'contentType': {
                        'id': '0x0101009D1CB255DA76424F860D91F20E6C411800813863BBF9FE6A408AE59965D98FE3DA',
                        'name': 'Site Page'
                    },
                    'createdBy': {'user': {'displayName': 'System Account'}},
                    'lastModifiedBy': {'user': {'displayName': 'Terrarium Admin', 'email': 'admin@dev.idea-te.eimdemo.com'}},
                    'parentReference': {'siteId': '61c0f9cb-39d3-4c04-b60c-31576954a2ab'},
                    'publishingState': {'level': 'published', 'versionId': '4.0'},
                    'reactions': {}
                },
                ...
            ]
        }

        """

        request_url = self.config()["sitesUrl"] + "/" + str(site_id) + "/pages"

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get pages of SharePoint site with ID -> '{}'".format(site_id),
        )

        return response

    # end method definition

    def get_sharepoint_page(self, site_id: str, page_id: str) -> dict | None:
        """Retrieve a page of a SharePoint site accessible to the authenticated user.

        Args:
            site_id (str):
                The ID of the SharePoint site the page should be get for.
            page_id (str):
                The ID of the page to be retrieved.

        Returns:
            dict | None:
                A SharePoint site page.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C9b203cbe-27ca-45b2-944a-663cc99e5e8f%2Ca1462b54-26f9-4a24-9660-2bc7859ce9af')/pages/$entity",
            '@odata.type': '#microsoft.graph.sitePage',
            '@odata.etag': '"{A546CE61-21E6-431D-B2CD-67D1F722BE5F},4"',
            'createdDateTime': '2025-01-26T00:03:24Z',
            'eTag': '"{A546CE61-21E6-431D-B2CD-67D1F722BE5F},4"',
            'id': 'a546ce61-21e6-431d-b2cd-67d1f722be5f',
            'lastModifiedDateTime': '2025-01-26T00:03:24Z',
            'name': 'Home.aspx',
            'webUrl': 'https://ideatedev.sharepoint.com/sites/TG11-Trad.Good11PDReg.Trading795/SitePages/Home.aspx',
            'title': 'Home',
            'pageLayout': 'home',
            'promotionKind': 'page',
            'showComments': False,
            'showRecommendedPages': False,
            'contentType': {
                'id': '0x0101009D1CB255DA76424F860D91F20E6C4118003CD261A156017A45BA0F28B5923AE8F6',
                'name': 'Site Page'
            },
            'createdBy': {
                'user': {...}
            },
            'lastModifiedBy': {
                'user': {...}
            },
            'parentReference': {
                'siteId': '9b203cbe-27ca-45b2-944a-663cc99e5e8f'
            },
            'publishingState': {
                'level': 'published',
                'versionId': '1.0'
            },
            'reactions': {}
        }

        """

        request_url = self.config()["sitesUrl"] + "/" + site_id + "/pages/" + page_id

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get SharePoint page -> '{}' for site -> '{}'".format(page_id, site_id),
        )

        return response

    # end method definition

    def add_sharepoint_page(self, site_id: str, page_name: str, publish: bool = True) -> dict:
        """Add a new SharePoint site page using Microsoft Graph API.

        Args:
            site_id (str):
                The ID of the SharePoint site the page should be created on.
            page_name (str):
                The name/title of the new page.
            publish (bool, optional):
                If True, the page is immediately published.

        Returns:
            dict:
                Details of the created SharePoint page or an error response.

        """

        request_url = self.config()["sitesUrl"] + "/" + site_id + "/pages"
        request_header = self.request_header()

        # Page payload for a basic site page
        payload = {
            "@odata.type": "#microsoft.graph.sitePage",
            "name": page_name + ".aspx",
            "title": page_name,
            "publishingState": {
                "level": "published",
            },
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to create SharePoint page -> '{}' in SharePoint site -> '{}'".format(
                page_name,
                site_id,
            ),
        )

        # Check if the page should be directly published:
        if response and publish:
            page_id = self.get_result_value(response=response, key="id")
            self.publish_sharepoint_page(site_id=site_id, page_id=page_id)

        return response

    # end method definition

    def publish_sharepoint_page(self, site_id: str, page_id: str) -> bool:
        """Publish a page of a SharePoint site.

        Args:
            site_id (str):
                The ID of the SharePoint site the page should be published on.
            page_id (str):
                The ID of the page to be published.

        Returns:
            bool:
                True = Success, False = Error.

        """

        request_url = (
            self.config()["sitesUrl"] + "/" + site_id + "/pages/" + page_id + "/microsoft.graph.sitePage/publish"
        )

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot publish SharePoint page -> '{}' on SharePoint site -> '{}'".format(
                page_id,
                site_id,
            ),
            parse_request_response=False,
        )

        return bool(response.ok)

    # end method definition

    def get_sharepoint_sections(
        self,
        site_id: str,
        page_id: str,
        section_type: str = "horizontalSections",
        section_id: str | int | None = None,
        show_error: bool = True,
    ) -> dict:
        """Retrieve all sections SharePoint site page.

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the sections.
            section_type (str, optional):
                "horizontalSections" (note the plural!)
                "verticalSection" (note the singular!)
            section_id (str | int | None):
                The ID of the section. Only relevant for horizontal sections.
                Simple values like 1,2,3...
                Should be None for vertical section.
            show_error (bool, optional):
                Whether or not an error should be displayed if the
                section is not found.

        Returns:
            dict:
                A dictionary including the list of SharePoint sections for a given page.
                The actual list is included inside the "value" key of the dictionary.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C61c0f9cb-39d3-4c04-b60c-31576954a2ab%2Ca678aeab-68ac-46a1-bd95-28020c12de26')/pages('ac7675ee-8891-43b9-b1b2-2d2ced8eb17e')/microsoft.graph.sitePage/canvasLayout/horizontalSections",
            'value': [
                {
                    'layout': 'fullWidth',
                    'id': '1',
                    'emphasis': 'none'
                },
                {
                    'layout': 'twoColumns',
                    'id': '2',
                    'emphasis': 'none'
                }
            ]
        }

        """

        request_url = (
            self.config()["sitesUrl"]
            + "/"
            + site_id
            + "/pages/"
            + page_id
            + "/microsoft.graph.sitePage/canvasLayout/"
            + section_type
        )

        if section_id is not None:
            request_url += "/" + str(section_id)

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            warning_message="Cannot find section{} for SharePoint page -> '{}' of SharePoint site -> '{}'".format(
                "s" if not section_id else " -> {}".format(section_id),
                page_id,
                site_id,
            ),
            failure_message="Cannot get section{} for SharePoint page -> '{}' of SharePoint site -> '{}'".format(
                "s" if not section_id else " -> {}".format(section_id),
                page_id,
                site_id,
            ),
            show_error=show_error,
        )

        return response

    # end method definition

    def get_sharepoint_section(
        self,
        site_id: str,
        page_id: str,
        section_type: str = "horizontalSections",
        section_id: int | str = 1,
        show_error: bool = True,
    ) -> dict:
        """Retrieve a section of a SharePoint site page.

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the section.
            section_type (str, optional):
                "horizontalSections" (note the plural!)
                "verticalSection" (note the singular!)
            section_id (int | str):
                The ID of the section. Only relevant for horizontal sections.
                Simple values like 1,2,3...
            show_error (bool, optional):
                Whether or not an error should be displayed if the
                section is not found.

        Returns:
            dict:
                A SharePoint site page section.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C61c0f9cb-39d3-4c04-b60c-31576954a2ab%2Ca678aeab-68ac-46a1-bd95-28020c12de26')/pages('ac7675ee-8891-43b9-b1b2-2d2ced8eb17e')/microsoft.graph.sitePage/canvasLayout/horizontalSections/$entity",
            'layout': 'fullWidth',
            'id': '1',
            'emphasis': 'none'
        }

        """

        response = self.get_sharepoint_sections(
            site_id=site_id,
            page_id=page_id,
            section_type=section_type,
            section_id=section_id,
            show_error=show_error,
        )

        return response

    # end method definition

    def add_sharepoint_section(
        self,
        site_id: str,
        page_id: str,
        section_type: str = "horizontalSections",
        section_id: int | str = 1,
        columns: str = "oneColumn",
        emphasis: str = "none",
        republish: bool = True,
    ) -> dict | None:
        """Create a specific section (horizontal or vertical) on a SharePoint page.

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the web part.
            section_type (str, optional):
                "horizontalSections" (note the plural!)
                "verticalSection" (note the singular!)
            section_id (int | str):
                The ID of the section. Only relevant for horizontal sections.
                Simple values like 1,2,3...
            columns (str, optional):
                "fullWidth"
                "oneColumn"
                "twoColumns"
                "threeColumns"
            emphasis (str, optional):
                The emphasis for the section. Possible values:
                "none" (default)
                "neutral"
                "soft"
                "strong"
            republish (bool, optional):
                If True, the page is republished to make the section active.

        Returns:
            dict:
                The horizontal or vertical section.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C61c0f9cb-39d3-4c04-b60c-31576954a2ab%2Ca678aeab-68ac-46a1-bd95-28020c12de26')/pages('ac7675ee-8891-43b9-b1b2-2d2ced8eb17e')/microsoft.graph.sitePage/canvasLayout/horizontalSections/$entity",
            'layout': 'fullWidth',
            'id': '2',
            'emphasis': 'none'
        }

        """

        request_url = (
            self.config()["sitesUrl"]
            + "/"
            + site_id
            + "/pages/"
            + page_id
            + "/microsoft.graph.sitePage/canvasLayout/"
            + section_type
        )
        request_header = self.request_header()

        # Construct the payload to update the specific property
        payload = {
            "@odata.type": "#microsoft.graph.{}".format(
                section_type.rstrip("s"),
            ),
        }
        if section_type == "horizontalSections":
            payload["layout"] = columns
            payload["emphasis"] = emphasis
            payload["id"] = str(section_id)

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to create SharePoint section of type -> '{}' ({}) on SharePoint page -> '{}' in SharePoint site -> '{}'".format(
                section_type,
                columns,
                page_id,
                site_id,
            ),
        )

        # Check if the page should be republished:
        if response and republish:
            self.publish_sharepoint_page(site_id=site_id, page_id=page_id)

        return response

    # end method definition

    def delete_sharepoint_section(
        self,
        site_id: str,
        page_id: str,
        section_type: str = "horizontalSections",
        section_id: int | str = 1,
    ) -> dict | None:
        """Delete a specific section (horizontal or vertical) on a SharePoint page.

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the web part.
            section_type (str, optional):
                "horizontalSections" (note the plural!)
                "verticalSection" (note the singular!)
            section_id (int | str):
                The ID of the section. Only relevant for horizontal sections.
                Simple values like 1,2,3...

        Returns:
            dict:
                Empty response.

        Example:
        {
            '_content': b'',
            '_content_consumed': True,
            '_next': None,
            'status_code': 204,
            'headers': {
                'Cache-Control': 'no-store, no-cache',
                'Strict-Transport-Security': 'max-age=31536000',
                'request-id': 'bd21c7fa-751c-43ca-b290-12c30f50d7e1',
                'client-request-id': 'bd21c7fa-751c-43ca-b290-12c30f50d7e1',
                'x-ms-ags-diagnostic': '{"ServerInfo":{"DataCenter":"Germany West Central","Slice":"E","Ring":"4","ScaleUnit":"004","RoleInstance":"FR2PEPF00000393"}}', 'Date': 'Fri, 14 Feb 2025 20:40:06 GMT'},
                'raw': <urllib3.response.HTTPResponse object at 0x10f210d90>,
                'url': 'https://graph.microsoft.com/beta/sites/ideatedev.sharepoint.com,61c0f9cb-39d3-4c04-b60c-31576954a2ab,a678aeab-68ac-46a1-bd95-28020c12de26/pages/ac7675ee-8891-43b9-b1b2-2d2ced8eb17e/microsoft.graph.sitePage/canvasLayout/horizontalSections/1',
                'encoding': None,
                'history': [],
                'reason': 'No Content',
                'cookies': <RequestsCookieJar[]>,
                'elapsed': datetime.timedelta(microseconds=514597),
                'request': <PreparedRequest [DELETE]>,
                'connection': <requests.adapters.HTTPAdapter object at 0x11841d700>
            }

        """

        request_url = (
            self.config()["sitesUrl"]
            + "/"
            + site_id
            + "/pages/"
            + page_id
            + "/microsoft.graph.sitePage/canvasLayout/"
            + section_type
        )

        if section_type == "horizontalSections":
            request_url += "/" + str(section_id)

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to delete SharePoint section of type -> '{}' on SharePoint page -> '{}' in Sharepoint site -> '{}', ".format(
                section_type,
                page_id,
                site_id,
            ),
        )

        return response

    # end method definition

    def get_sharepoint_webparts(
        self,
        site_id: str,
        page_id: str,
        section_type: str | None = None,
        section_id: str | int = 1,
        column_id: int | str = 1,
    ) -> dict | None:
        """Retrieve the configured webparts on a SharePoint site page.

        Can retrieve all webparts on the page or the ones in a defined
        page section (like horizontal section or vertical section).

        OpenText WebPart Type IDs:
            Content Browser: 'cecfdba4-2e82-4538-9436-dbd1c4c01a80'
            Related Workspaces: 'e24d7154-4554-4db6-a44f-d306b6b3a5d4'
            Team members of Workspace: '635a2800-8833-410d-b1f1-f209b28ea2ad'

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the web part.
            section_type (str, optional):
                "horizontalSections" (note the plural!)
                "verticalSection" (note the singular!)
                Use None if you want to retrieve all webparts on page.
            section_id (str | int | None):
                The ID of the section. Only relevant for horizontal sections.
                Simple values like 1,2,3...
                Not relevant for vertical section or if you want to retrieve
                all webparts on the page.
            column_id (int | str, optional):
                For horizontalSections the column ID has to be provided.
                Defaults to 1.


        Returns:
            dict | None:
                A dictionary including the SharePoint webparts of a given page for a given site.
                The actual list is included inside the "value" key of the dictionary.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C61c0f9cb-39d3-4c04-b60c-31576954a2ab%2Ca678aeab-68ac-46a1-bd95-28020c12de26')/pages('561c65b4-3418-4698-a4c3-7ca7f04812bb')/microsoft.graph.sitePage/webParts",
            'value': [
                {
                    '@odata.type': '#microsoft.graph.standardWebPart',
                    'id': '405b669e-3c09-45fe-822f-ff60ac7fffce',
                    'webPartType': 'c4bd7b2f-7b6e-4599-8485-16504575f590',
                    'data': {
                        'audiences': [],
                        'dataVersion': '1.5',
                        'description': 'Prominently display up to 5 pieces of content with links, images, pictures, videos, or photos in a highly visual layout.',
                        'title': 'Hero',
                        'properties': {
                            'heroLayoutThreshold': 640,
                            'carouselLayoutMaxWidth': 639,
                            'layoutCategory': 1,
                            'layout': 5,
                            'content@odata.type': '#Collection(graph.Json)',
                            'content': [
                                {
                                    'id': '20cb6611-c7cc-4ba7-91e1-65a6cb576025',
                                    'type': 'UrlLink',
                                    'color': 4,
                                    'description': '',
                                    'title': '',
                                    'showDescription': False,
                                    'showTitle': True,
                                    'alternateText': '',
                                    'imageDisplayOption': 1,
                                    'isDefaultImage': False,
                                    'showCallToAction': True,
                                    'isDefaultImageLoaded': False,
                                    'isCustomImageLoaded': False,
                                    'showFeatureText': False,
                                    'previewImage': {...}
                                },
                                {
                                    'id': '83133733-960b-4139-a73f-17ce2ca5f71c',
                                    'type': 'Image',
                                    'color': 4,
                                    'description': '',
                                    'title': '',
                                    'showDescription': False,
                                    'showTitle': True,
                                    'alternateText': '',
                                    'imageDisplayOption': 0,
                                    'isDefaultImage': False,
                                    'showCallToAction': False,
                                    'isDefaultImageLoaded': False,
                                    'isCustomImageLoaded': False,
                                    'showFeatureText': False
                                },
                                ...
                            ]
                        },
                        'serverProcessedContent': {
                            'htmlStrings': [...],
                            'searchablePlainTexts': [...],
                            'links': [...],
                            'imageSources': [...],
                            'componentDependencies': [...],
                            'customMetadata': [...]
                        }
                    }
                },
                {
                    '@odata.type': '#microsoft.graph.standardWebPart',
                    'id': 'f7bfdec9-09c5-4fb6-bc97-3ba225d35ad4',
                    'webPartType': '8c88f208-6c77-4bdb-86a0-0c47b4316588',
                    'data': {...}
                },
                {
                    '@odata.type': '#microsoft.graph.standardWebPart',
                    'id': 'f2a8650b-5ea0-4ac2-9cde-56e0fd0279b0',
                    'webPartType': 'eb95c819-ab8f-4689-bd03-0c2d65d47b1f',
                    'data': {...}
                },
                {
                    '@odata.type': '#microsoft.graph.standardWebPart',
                    'id': '418ba70b-4cf7-410a-a5fd-ea38386915ac',
                    'webPartType': 'c70391ea-0b10-4ee9-b2b4-006d3fcad0cd',
                    'data': {...}
                },
                {
                    '@odata.type': '#microsoft.graph.standardWebPart',
                    'id': '416a4c58-61fc-4166-aa19-1099fad50545',
                    'webPartType': 'f92bf067-bc19-489e-a556-7fe95f508720',
                    'data': {...}
                }
            ]
        }

        """

        request_url = self.config()["sitesUrl"] + "/" + site_id + "/pages/" + page_id + "/microsoft.graph.sitePage"
        if section_type:
            request_url += "/canvasLayout/" + section_type
        if section_type == "horizontalSections":
            request_url += "/" + str(section_id)
            request_url += "/columns/" + str(column_id)
        request_url += "/webparts"

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get webparts for page -> '{}' of SharePoint site -> '{}'".format(
                page_id,
                site_id,
            ),
        )

        return response

    # end method definition

    def get_sharepoint_webpart(self, site_id: str, page_id: str, webpart_id: str) -> dict | None:
        """Retrieve a page of a SharePoint site accessible to the authenticated user.

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the web part.
            webpart_id (str):
                The ID of the SharePoint web part to retrieve.

        Returns:
            dict | None:
                The data of the SharePoint web part.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C9b203cbe-27ca-45b2-944a-663cc99e5e8f%2Ca1462b54-26f9-4a24-9660-2bc7859ce9af')/pages('a546ce61-21e6-431d-b2cd-67d1f722be5f')/microsoft.graph.sitePage/webParts/$entity",
            '@odata.type': '#microsoft.graph.standardWebPart',
            'id': '405b669e-3c09-45fe-822f-ff60ac7fffce',
            'webPartType': 'c4bd7b2f-7b6e-4599-8485-16504575f590',
            'data': {
                'audiences': [...],
                'dataVersion': '1.5',
                'description': 'Prominently display up to 5 pieces of content with links, images, pictures, videos, or photos in a highly visual layout.',
                'title': 'Hero',
                'properties': {
                    'heroLayoutThreshold': 640,
                    'carouselLayoutMaxWidth': 639,
                    'layoutCategory': 1,
                    'layout': 5,
                    'content@odata.type': '#Collection(graph.Json)',
                    'content': [
                        {
                            'id': '20cb6611-c7cc-4ba7-91e1-65a6cb576025',
                            'type': 'UrlLink',
                            'color': 4,
                            'description': '',
                            'title': '',
                            'showDescription': False,
                            'showTitle': True,
                            'alternateText': '',
                            'imageDisplayOption': 1,
                            'isDefaultImage': False,
                            'showCallToAction': True,
                            'isDefaultImageLoaded': False,
                            'isCustomImageLoaded': False,
                            'showFeatureText': False,
                            'previewImage': {
                                '@odata.type': '#graph.Json',
                                'zoomRatio': 1,
                                'resolvedUrl': '',
                                'imageUrl': '',
                                'widthFactor': 0.5,
                                'minCanvasWidth': 1
                            }
                        },
                        {...}
                    ]
                },
                'serverProcessedContent': {...}
            }
        }

        """

        request_url = (
            self.config()["sitesUrl"]
            + "/"
            + site_id
            + "/pages/"
            + page_id
            + "/microsoft.graph.sitePage/webparts/"
            + webpart_id
        )

        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot get SharePoint webpart -> '{}' on SharePoint page -> '{}' in SharePoint site -> '{}'".format(
                webpart_id,
                page_id,
                site_id,
            ),
        )

        return response

    # end method definition

    def add_sharepoint_webpart(
        self,
        site_id: str,
        page_id: str,
        webpart_type_id: str,
        create_data: dict,
        section_type: str = "horizontalSections",
        section_id: int | str = 1,
        column_id: int | str = 1,
        republish: bool = True,
    ) -> dict | None:
        """Create a specific web part on a SharePoint page.

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the web part.
            webpart_type_id (str):
                The ID of the web part to create.
                Content Browser: 'cecfdba4-2e82-4538-9436-dbd1c4c01a80'
                Related Workspaces: 'e24d7154-4554-4db6-a44f-d306b6b3a5d4'
                Team members of Workspace: '635a2800-8833-410d-b1f1-f209b28ea2ad'
            create_data (dict):
                A dictionary with the webpart data items that will be used
                to update the "data" structure of the webpart.
            section_type (str, optional):
                "horizontalSections" (note the plural!)
                "verticalSection" (note the singular!)
            section_id (str | int):
                The ID of the section.Only relevant for horizontal sections.
                Simple values like 1,2,3...
                Defaults to 1.
            column_id (int | str, optional):
                For horizontalSections the column ID has to be provided.
                Defaults to 1.
            republish (bool, optional):
                If True, the page is republished to make the section active.

        Returns:
            dict:
                The updated web part.

        Example:
        {
            '@odata.context': "https://graph.microsoft.com/beta/$metadata#sites('ideatedev.sharepoint.com%2C61c0f9cb-39d3-4c04-b60c-31576954a2ab%2Ca678aeab-68ac-46a1-bd95-28020c12de26')/pages('ac7675ee-8891-43b9-b1b2-2d2ced8eb17e')/microsoft.graph.sitePage/canvasLayout/horizontalSections('1')/columns('1')/webparts/$entity",
            '@odata.type': '#microsoft.graph.standardWebPart',
            'id': '3df7fe9a-a1e0-4212-968c-73bd70ca3e31',
            'webPartType': 'eb95c819-ab8f-4689-bd03-0c2d65d47b1f',
            'data': {
                'audiences': [...],
                'dataVersion': '1.0',
                'title': 'Site activity',
                'properties': {'maxItems': 9},
                'serverProcessedContent': {
                    'htmlStrings': [],
                    'searchablePlainTexts': [],
                    'links': [],
                    'imageSources': []
                }
            }
        }

        """

        request_url = (
            self.config()["sitesUrl"]
            + "/"
            + site_id
            + "/pages/"
            + page_id
            + "/microsoft.graph.sitePage/canvasLayout/"
            + section_type
        )
        if section_type == "horizontalSections":
            request_url += "/" + str(section_id)
            request_url += "/columns/" + str(column_id)
        request_url += "/webparts"

        request_header = self.request_header()

        # Construct the payload to update the specific property
        payload = {
            "@odata.type": "#microsoft.graph.standardWebPart",  # likle "#microsoft.graph.standardWebPart" - this is mandatory!
            "webPartType": webpart_type_id,  # this is mandatory!
            "data": create_data,
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to create SharePoint webpart of type -> '{}' on SharePoint page -> '{}'{} in SharePoint site -> '{}', ".format(
                webpart_type_id,
                page_id,
                " (horizontal section -> {}, column -> {})".format(section_id, column_id)
                if section_type == "horizontalSections"
                else " (vertical section)",
                site_id,
            ),
        )

        # Check if the page should be republished:
        if response and republish:
            self.publish_sharepoint_page(site_id=site_id, page_id=page_id)

        return response

    # end method definition

    def update_sharepoint_webpart(
        self,
        site_id: str,
        page_id: str,
        webpart_id: str,
        update_data: dict,
        republish: bool = True,
    ) -> dict | None:
        """Update a data of a specific web part on a SharePoint page.

        Any data elements not provided for the update will remain unchanged!

        Args:
            site_id (str):
                The ID of the SharePoint site.
            page_id (str):
                The ID of the SharePoint page containing the web part.
            webpart_id (str):
                The ID of the web part to update.
            update_data (dict):
                A dictionary with the updated data items that will be used
                to update the "data" structure of the webpart.
            republish (bool, optional):
                If True, the page is republished to make the section active.

        Returns:
            dict | None:
                The updated web part. None in case of an error.

        """

        def deep_merge(source: dict, destination: dict) -> dict:
            """Recursively merges source dictionary into destination dictionary.

            If a key exists in both, the value from destination is kept unless
            both values are dictionaries, in which case they are merged recursively.

            Args:
                source (dict):
                    The dictionary with the current data values. Will be
                    used if not updated data is in update_data for the particular key.
                destination (dict):
                    The dictionary to merge into, which takes precedence.

            Returns:
                dict: The merged dictionary.

            """
            for key, value in source.items():
                if isinstance(value, dict) and key in destination and isinstance(destination[key], dict):
                    # Recursively merge dictionaries if both values are dictionaries
                    destination[key] = deep_merge(value, destination[key])
                else:
                    # If key does not exist in destination, use value from source
                    destination.setdefault(key, value)
            return destination

        # end deep_merge()

        webpart = self.get_sharepoint_webpart(site_id=site_id, page_id=page_id, webpart_id=webpart_id)
        if not webpart:
            self.logger.error(
                "Cannot find web part for site ID -> '%s', page -> '%s', webpart ID -> '%s'!",
                site_id,
                page_id,
                webpart_id,
            )
            return None
        webpart_type_id = webpart.get("webPartType")
        webpart_type_name = webpart.get("@odata.type")
        data = webpart.get("data")

        # Fill update_data with missing keys from data
        update_data = deep_merge(data, update_data)  # Merges, giving precedence to update_data

        # Construct the payload to update the specific property
        payload = {
            "@odata.type": webpart_type_name,  # likle "#microsoft.graph.standardWebPart" - this is mandatory!
            "webPartType": webpart_type_id,  # this is mandatory!
            "data": update_data,
        }

        request_url = (
            self.config()["sitesUrl"]
            + "/"
            + site_id
            + "/pages/"
            + page_id
            + "/microsoft.graph.sitePage/webparts/"
            + webpart_id
        )
        request_header = self.request_header()

        response = self.do_request(
            url=request_url,
            method="PATCH",
            json_data=payload,
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Cannot update SharePoint webpart -> '{}' on SharePoint page -> '{}' for Sharepoint site -> '{}', ".format(
                webpart_id,
                page_id,
                site_id,
            ),
        )
        # Check if the page should be republished:
        if response and republish:
            self.publish_sharepoint_page(site_id=site_id, page_id=page_id)

        return response

    # end method definition

    def follow_sharepoint_site(
        self,
        site_id: str,
        username: str | None = None,
        user_id: str | None = None,
    ) -> dict | None:
        """Let a user follow a particular SharePoint site.

        Args:
            site_id (str):
                The ID of the SharePoint site.
            username (str):
                The login name of the user. Only relevant if the user ID
                is not provided.
            user_id (str):
                The user ID. If it is not provied it will be derived from
                the username.

        Returns:
            dict:
                The Graph API response or None in case an error occured..

        Example:
        {
            '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#sites',
            'value': [
                {
                    'id': 'ideateqa.sharepoint.com,c605327f-8531-47da-8c85-9bb63845dda6,34b48533-af41-4743-8b41-185a21f0b80f',
                    'webUrl': 'https://ideateqa.sharepoint.com/sites/Procurement',
                    'displayName': 'Procurement',
                    'sharepointIds': {
                        'siteId': 'c605327f-8531-47da-8c85-9bb63845dda6',
                        'siteUrl': 'https://ideateqa.sharepoint.com/sites/Procurement',
                        'webId': '34b48533-af41-4743-8b41-185a21f0b80f'
                    },
                    'siteCollection': {
                        'hostname': 'ideateqa.sharepoint.com'
                    }
                }
            ]
        }

        """

        if not user_id and not username:
            self.logger.error("No user given to follow SharePoint site. Provide the user ID or its email address!")
            return None

        user = self.get_user(user_email=username, user_id=user_id)
        if not user_id:
            user_id = self.get_result_value(user, "id")
        if not username:
            username = self.get_result_value(user, "userPrincipalName")

        request_url = self.config()["usersUrl"] + "/" + str(user_id) + "/followedSites/add"
        request_header = self.request_header()

        # Construct the payload to update the specific property
        payload = {
            "value": [{"id": site_id}],
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=payload,
            timeout=REQUEST_TIMEOUT,
            warning_message="Failed to follow SharePoint site -> '{}' as user -> '{}'".format(
                site_id,
                username if username else user_id,
            ),
            show_error=False,
            show_warning=True,
        )

        return response

    # end method definition

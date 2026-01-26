"""OTPD Module to implement functions to read / write PowerDocs objects."""

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
from http import HTTPStatus
from importlib.metadata import version

import requests
from requests.auth import HTTPBasicAuth
from requests_toolbelt.multipart.encoder import MultipartEncoder

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otpd"

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

default_logger = logging.getLogger("pyxecm.otpd")

request_headers = {
    "accept": "application/json;charset=utf-8",
    "Connection": "keep-alive",
    "Content-Type": "application/json",
}


class OTPD:
    """Class OTPD is used to automate stettings in OpenText Extended ECM PowerDocs."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        username: str,
        password: str,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the OTPD object.

        Args:
            protocol (str):
                Either http or https.
            hostname (str):
                The hostname of the PowerDocs Server Manager to communicate with.
            port (int):
                The port number used to talk to the PowerDocs Server Manager.
            username (str):
                The admin user name of PowerDocs Server Manager.
            password (str):
                The admin password of PowerDocs Server Manager.
            logger (logging.logger):
                The logger object to use. Defaults to "default_logger".

        """

        if logger != default_logger:
            self.logger = logger.getChild("otpd")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        otpd_config = {}

        if hostname:
            otpd_config["hostname"] = hostname
        else:
            otpd_config["hostname"] = ""

        if protocol:
            otpd_config["protocol"] = protocol
        else:
            otpd_config["protocol"] = "http"

        if port:
            otpd_config["port"] = port
        else:
            otpd_config["port"] = 80

        if username:
            otpd_config["username"] = username
        else:
            otpd_config["username"] = "admin"

        if password:
            otpd_config["password"] = password
        else:
            otpd_config["password"] = ""

        otpd_base_url = protocol + "://" + otpd_config["hostname"]
        if str(port) not in ["80", "443"]:
            otpd_base_url += ":{}".format(port)
        otpd_config["baseUrl"] = otpd_base_url

        otpd_servermanager_url = otpd_base_url + "/ServerManager"
        otpd_config["serverManagerUrl"] = otpd_servermanager_url

        otpd_rest_url = otpd_servermanager_url + "/api"
        otpd_config["restUrl"] = otpd_rest_url

        otpd_config["settingsUrl"] = otpd_rest_url + "/v1/settings"

        otpd_config["importDatabaseUrl"] = otpd_servermanager_url + "/servlet/import"

        self._config = otpd_config
        self._jsessionid = None

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """

        return self._config

    # end method definition

    def credentials(self) -> dict:
        """Get credentials (username + password).

        Returns:
            dict: dictionary with username and password

        """
        return {
            "username": self.config()["username"],
            "password": self.config()["password"],
        }

    # end method definition

    def set_credentials(self, username: str = "admin", password: str = "") -> None:
        """Set the credentials for PowerDocs for the based on user name and password.

        Args:
            username (str, optional):
                The username. Defaults to "admin".
            password (str, optional):
                The password of the user. Defaults to "".

        """

        self.config()["username"] = username
        self.config()["password"] = password

    # end method definition

    def hostname(self) -> str:
        """Return the hostname of PowerDocs (e.g. "otpd").

        Returns:
            string: hostname

        """

        return self.config()["hostname"]

    # end method definition

    def set_hostname(self, hostname: str) -> None:
        """Set the hostname of PowerDocs.

        Args:
            hostname (str):
                The new hostname.

        """

        self.config()["hostname"] = hostname

    # end method definition

    def parse_request_response(
        self,
        response_object: object,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Convert the request response to a dict in a safe way that handles exceptions.

        Args:
            response_object (object):
                Reponse object delivered by the request call.
            additional_error_message (str, optional):
                If provided, print a custom error message.
            show_error (bool, optional):
                If True, log an error, if False log a warning.

        Returns:
            dict | None:
                A python dict object or None in case of an error.

        """

        if not response_object:
            return None

        try:
            dict_object = json.loads(response_object.text)
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

    # This method is currently not used and not working...
    # It cannot handle the Request - ServerManager returns an
    # error stating that JavaScript is not enabled...
    def authenticate(self, revalidate: bool = False) -> dict:
        """Authenticate at PowerDocs and retrieve session ID.

        Args:
            revalidate (bool):
                Determine, if a re-athentication is enforced
                (e.g. if session has timed out with 401 error).

        Returns:
            dict:
                Cookie information of None in case of an error.
                Also stores cookie information in self._cookie

        """

        # Already authenticated and session still valid?
        if self._jsessionid and not revalidate:
            return self._jsessionid

        auth_url = (
            self.config()["serverManagerUrl"]
            + "/j_security_check?j_username="
            + self.config()["username"]
            + "&j_password="
            + self.config()["password"]
        )
        payload = {}
        payload["settingname"] = "LocalOtdsUrl"
        payload["settingvalue"] = "http://otds/otdsws"

        request_url = self.config()["settingsUrl"]

        # Fetching session id will be three step process:
        # Step1: intiate a dummy request to tomcat
        # Step2: fetch session id from the response,
        #        and hit j_security_check with proper authentication
        # Step3: get session id from the response, add to self.
        #        It can be used for other transactions
        session = requests.Session()
        self.logger.debug(
            "Initiating dummy rest call to Tomcat to get initial session ID.",
        )
        response = session.put(request_url, json=payload)
        self.logger.info(response.text)
        if response.ok:
            self.logger.debug(
                "Url to authenticate Tomcat for Session id -> %s",
                auth_url,
            )
            session_response = session.post(auth_url)
            if session_response.ok:
                self.logger.debug(
                    "Response for -> %s is -> %s",
                    auth_url,
                    str(session_response),
                )
                session_dict = session.cookies.get_dict()
                self.logger.debug(
                    "Session id to perform Rest API calls to Tomcat -> %s",
                    session_dict["JSESSIONID"],
                )
                # store session ID an write it into the global request_headers variable:
                self._jsessionid = session_dict["JSESSIONID"]
                request_headers["Cookie"] = "JSESSIONID=" + self._jsessionid
                return session_response
            else:
                self.logger.error(
                    "Fetching session id from -> %s failed! Response -> %s",
                    auth_url,
                    session_response.text,
                )
                return None
        else:
            self.logger.error(
                "Fetching session id from -> %s failed! Response -> %s",
                request_url,
                response.text,
            )
        return None

    # end method definition

    def import_database(self, file_path: str) -> dict | None:
        """Import PowerDocs database backup from a zip file.

        Args:
            file_path (str):
                The path to the database file to import.

        Returns:
            dict | None:
                The request response or None in case of an error.

        """

        if not file_path or not os.path.isfile(file_path):
            self.logger.error(
                "Cannot import PowerDocs database from non-existent file -> %s",
                file_path,
            )
            return None

        try:
            # Extract the filename
            file_name = os.path.basename(file_path)

            # Open the file safely
            with open(file_path, "rb") as file:
                file_tuple = (file_name, file, "application/zip")

                # Prepare the multipart encoder
                multipart = MultipartEncoder(
                    fields={"name": file_name, "zipfile": file_tuple},
                )

                # Retrieve the request URL
                request_url = self.config().get("otpdImportDatabaseUrl")

                if not request_url:
                    self.logger.error("Import database URL is not configured.")
                    return None

                self.logger.info(
                    "Importing PowerDocs database backup from -> %s; calling -> %s",
                    file_path,
                    request_url,
                )

                # Send the request
                response = requests.post(
                    url=request_url,
                    data=multipart,
                    headers={"content-type": multipart.content_type},
                    timeout=60,
                )

                # Handle the response
                if response.ok:
                    self.logger.info("Database backup imported successfully.")
                    return response.json()
                else:
                    self.logger.error(
                        "Failed to import PowerDocs database backup from -> %s into -> %s; error -> %s",
                        file_path,
                        request_url,
                        response.text,
                    )
                    return None

        except FileNotFoundError:
            self.logger.error("File -> '%s' not found!", file_path)
        except requests.RequestException:
            self.logger.error("HTTP request to -> '%s' failed", request_url)
        except Exception:
            self.logger.error("An unexpected error occurred!")

        return None

    # end method definition

    def apply_setting(
        self,
        setting_name: str,
        setting_value: str,
        tenant_name: str = "",
    ) -> dict | None:
        """Apply a setting to the PowerDocs Server Manager.

        Args:
            setting_name (str):
                The name of the setting.
            setting_value (str):
                The new value of the setting.
            tenant_name (str):
                The name of the PowerDocs tenant.
                The tenant name is optional as some settings are not tenant-specific!

        Returns:
            dict | None:
                Request response or None if the REST call fails.

        """

        settings_put_body = {
            "settingname": setting_name,
            "settingvalue": setting_value,
        }

        if tenant_name:
            settings_put_body["tenantName"] = tenant_name

        request_url = self.config()["settingsUrl"]

        self.logger.debug(
            "Update PowerDocs setting -> '%s' with value -> '%s'%s; calling -> %s",
            setting_name,
            setting_value,
            " (tenant -> '%s')" if tenant_name else "",
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=settings_put_body,
                headers=request_headers,
                auth=HTTPBasicAuth(
                    self.config()["username"],
                    self.config()["password"],
                ),
                verify=False,  # for localhost deployments this will fail otherwis e# noqa: S501
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            if response.status_code == 401 and retries == 0:
                self.logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            else:
                self.logger.error(
                    "Failed to update PowerDocs setting -> '%s' with value -> '%s'%s; error -> %s",
                    setting_name,
                    setting_value,
                    " (tenant -> '%s')" if tenant_name else "",
                    response.text,
                )
                return None

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
            timeout (int | None, optional):
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
            headers = REQUEST_HEADERS

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
                )

                if response.ok:
                    if success_message:
                        self.logger.info(success_message)
                    if parse_request_response:
                        return self.parse_request_response(response)
                    else:
                        return response
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
                        "Connection error. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
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
                "Retrying REST API %s call -> %s... (retry = %s",
                method,
                url,
                str(retries),
            )
        # end while True

    # end method definition

    def generate_document(self, payload: str) -> dict | None:
        """Generate a PowerDocs document based on the provided XML payload.

        Args:
            payload (str):
                The XML payload to generate the document.

        Returns:
            dict | None:
                The request response or None in case of an error.

        """

        if not payload:
            self.logger.error("Cannot generate PowerDocs document from empty payload!")
            return None

        url = self.config()["baseUrl"] + "/c4ApplicationServer/rest/document"

        body = {"documentgeneration": payload}

        response = self.do_request(
            url=url,
            method="POST",
            headers=REQUEST_FORM_HEADERS,
            data=body,
            show_error=True,
            failure_message="Failed to generate PowerDocs document",
            parse_request_response=False,
        )

        return response

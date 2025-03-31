"""OTPD Module to implement functions to read / write PowerDocs objects."""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import os

import requests
from requests.auth import HTTPBasicAuth
from requests_toolbelt.multipart.encoder import MultipartEncoder

default_logger = logging.getLogger("pyxecm.otpd")

request_headers = {
    "accept": "application/json;charset=utf-8",
    "Connection": "keep-alive",
    "Content-Type": "application/json",
}


class OTPD:
    """Class OTPD is used to automate stettings in OpenText Extended ECM PowerDocs."""

    logger: logging.Logger = default_logger

    _config = None
    _jsessionid = None

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
        otpd_base_url += "/ServerManager"
        otpd_config["baseUrl"] = otpd_base_url

        otpd_rest_url = otpd_base_url + "/api"
        otpd_config["restUrl"] = otpd_rest_url

        otpd_config["settingsUrl"] = otpd_rest_url + "/v1/settings"

        otpd_config["importDatabaseUrl"] = otpd_base_url + "/servlet/import"

        self._config = otpd_config

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

    def base_url(self) -> str:
        """Return the base URL of PowerDocs.

        Returns:
            string:
                The base URL.

        """

        return self.config()["baseUrl"]

    # end method definition

    def rest_url(self) -> str:
        """Return the REST URL of PowerDocs.

        Returns:
            string:
                The REST URL.

        """

        return self.config()["restUrl"]

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
            self.base_url()
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

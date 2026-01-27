"""OTAC Module to implement functions to apply Archive Center settings."""

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
from importlib.metadata import version

import requests
from suds import WebFault
from suds.client import Client

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otac"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_FORM_HEADERS = {
    "User-Agent": USER_AGENT,
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_JSON_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/json",
}

REQUEST_TIMEOUT = 60.0

default_logger = logging.getLogger(MODULE_NAME)


class OTAC:
    """Class OTAC is used to automate stettings in OpenText Archive Center."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        ds_username: str,
        ds_password: str,
        admin_username: str,
        admin_password: str,
        otds_ticket: str | None = None,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the OTAC object.

        Args:
            protocol (str):
                Either http or https.
            hostname (str):
                The hostname of the Archive Center  to communicate with.
            port (int):
                The port number used to talk to the Archive Center .
            ds_username (str):
                The admin user name of Archive Center (dsadmin).
            ds_password (str):
                The admin password of Archive Center (dsadmin).
            admin_username (str):
                The admin user name of Archive Center (otadmin@otds.admin).
            admin_password (str):
                The admin password of Archive Center (otadmin@otds.admin).
            otds_ticket (str, optional):
                Existing OTDS authentication ticket.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otac")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        otac_config = {}

        if hostname:
            otac_config["hostname"] = hostname
        else:
            otac_config["hostname"] = ""

        if protocol:
            otac_config["protocol"] = protocol
        else:
            otac_config["protocol"] = "http"

        if port:
            otac_config["port"] = port
        else:
            otac_config["port"] = 80

        if ds_username:
            otac_config["ds_username"] = ds_username
        else:
            otac_config["ds_username"] = "dsadmin"

        if ds_password:
            otac_config["ds_password"] = ds_password
        else:
            otac_config["ds_password"] = ""

        if admin_username:
            otac_config["admin_username"] = admin_username
        else:
            otac_config["admin_username"] = "admin"

        if admin_password:
            otac_config["admin_password"] = admin_password
        else:
            otac_config["admin_password"] = ""

        otac_base_url = protocol + "://" + otac_config["hostname"]
        if str(port) not in ["80", "443"]:
            otac_base_url += ":{}".format(port)
        otac_exec_url = otac_base_url + "/archive/admin/exec"
        otac_config["execUrl"] = otac_exec_url
        otac_config["baseUrl"] = otac_base_url
        otac_config["restUrl"] = otac_base_url + "/ot-admin/rest"
        otac_config["certUrl"] = otac_config["restUrl"] + "/keystore/cert/status"
        otac_config["authenticationUrl"] = otac_config["restUrl"] + "/auth/users/login"

        self._config = otac_config
        self._otac_ticket = otds_ticket
        self._soap_token: str = ""

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """
        return self._config

    # end method definition

    def hostname(self) -> str:
        """Return the Archive Center hostname.

        Returns:
            str: Archive Center hostname

        """
        return self.config()["hostname"]

    # end method definition

    def set_hostname(self, hostname: str) -> None:
        """Set the Archive Center hostname.

        Args:
            hostname (str):
                The new Archive Center hostname.

        """
        self.config()["hostname"] = hostname

    # end method definition

    def credentials(self) -> dict:
        """Get credentials (username + password).

        Returns:
            dict: dictionary with username and password

        """
        return {
            "username": self.config()["admin_username"],
            "password": self.config()["admin_password"],
        }

    # end method definition

    def set_credentials(
        self,
        ds_username: str = "",
        ds_password: str = "",
        admin_username: str = "",
        admin_password: str = "",
    ) -> None:
        """Set the credentials for Archive Center for the "ds" and "admin" users.

        Args:
            ds_username (str, optional): non-default user name of the "ds" user. Defaults to "".
            ds_password (str, optional): non-default password of the "ds" user. Defaults to "".
            admin_username (str, optional): non-default user name of the "admin" user. Defaults to "".
            admin_password (str, optional): non-default password of the "admin" user. Defaults to "".

        """
        if ds_username:
            self.config()["ds_username"] = ds_username
        else:
            self.config()["ds_username"] = "dsadmin"

        if ds_password:
            self.config()["ds_password"] = ds_password
        else:
            self.config()["ds_password"] = ""

        if admin_username:
            self.config()["admin_username"] = admin_username
        else:
            self.config()["admin_username"] = "admin"

        if admin_password:
            self.config()["admin_password"] = admin_password
        else:
            self.config()["admin_password"] = ""

    # end method definition

    def base_url(self) -> str:
        """Return the Archive Center base URL.

        Returns:
            str: Archive Center base URL

        """

        return self.config()["baseUrl"]

    # end method definition

    def exec_url(self) -> str:
        """Return the Archive Center URL to execute commands.

        Returns:
            str: Archive Center exec URL

        """
        return self.config()["execUrl"]

    # end method definition

    def request_form_header(self) -> dict:
        """Deliver the FORM request header used for the SOAP calls.

        Consists of Token + Form Headers (see global variable)

        Args:
            None.

        Return:
            dict:
                The request header for forms content type that includes the authorization token.

        """

        # create union of two dicts: cookie and headers
        # (with Python 3.9 this would be easier with the "|" operator)
        request_header = {}
        request_header.update("token" + self._otac_ticket)
        request_header.update(REQUEST_FORM_HEADERS)

        return request_header

    # end method definition

    def request_json_header(self) -> dict:
        """Deliver the JSON request header used for the CRUD REST API calls.

        Consists of Cookie + JSON Headers (see global variable)

        Args:
            None.

        Return:
            dict:
                The request header for JSON content type that includes the authorization token.

        """

        if not self._otac_ticket:
            self.authenticate(revalidate=True)

        # create union of two dicts: cookie and headers
        # (with Python 3.9 this would be easier with the "|" operator)
        request_header = {}
        if self._otac_ticket:
            request_header["Authorization"] = "token " + self._otac_ticket
        request_header.update(REQUEST_JSON_HEADERS)

        return request_header

    # end method definition

    def parse_request_response(
        self,
        response_object: object,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Convert the text property of a request response object to a dictionary.

        This is done in a safe way that also handles exceptions.

        Args:
            response_object (object):
                The reponse object delivered by the request call.
            additional_error_message (str):
                To print a custom error message.
            show_error (bool):
                If True, log an error, if False log a warning.

        Returns:
            dict:
                The response or None in case of an error.

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
                self.logger.debug(message)
            return None
        else:
            return dict_object

    # end method definition

    def authenticate(self, revalidate: bool = False) -> dict | None:
        """Authenticate at Archive Center and retrieve Ticket.

        Args:
            revalidate (bool, optional):
                Determins if a re-athentication is enforced
                (e.g. if session has timed out with 401 error).
                By default we use the OTDS ticket (if exists) for the authentication with OTCS.
                This switch allows the forced usage of username / password for the authentication.

        Returns:
            dict | None:
                Cookie information of None in case of an error.
                Also stores cookie information in self._cookie

        """

        # Already authenticated and session still valid?
        if self._otac_ticket and not revalidate:
            self.logger.debug(
                "Session still valid - return existing ticket -> %s",
                str(self._otac_ticket),
            )
            return self._otac_ticket

        otac_ticket = None

        request_url = self.config()["authenticationUrl"]
        # Check if previous authentication was not successful.
        # Then we do the normal username + password authentication:
        self.logger.debug(
            "Requesting OTAC ticket with username and password; calling -> %s",
            request_url,
        )

        response = None
        try:
            response = requests.post(
                url=request_url,
                data=json.dumps(
                    self.credentials(),
                ),  # this includes username + password
                headers=REQUEST_JSON_HEADERS,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exception:
            self.logger.warning(
                "Unable to connect to -> %s; error -> %s",
                request_url,
                str(exception),
            )
            self.logger.warning("OTAC service may not be ready yet.")
            return None

        if response.ok:
            authenticate_list = self.parse_request_response(
                response_object=response,
                additional_error_message="This can be normal during restart",
                show_error=False,
            )
            if not authenticate_list:
                return None
            else:
                authenticate_dict = authenticate_list[1]
                otac_ticket = authenticate_dict["TOKEN"]
                self.logger.debug("Ticket -> %s", otac_ticket)
        else:
            self.logger.error(
                "Failed to request an OTAC ticket; error -> %s",
                response.text,
            )
            return None

        # Store authentication ticket:
        self._otac_ticket = otac_ticket

        return self._otac_ticket

    # end method definition

    def authenticate_soap(self) -> str:
        """Authenticate via SOAP with admin User.

        Args:
            None

        Returns:
            str:
                The string with the SOAP token.

        """

        url = self.base_url() + "/archive/services/Authentication?wsdl"
        client = Client(url)
        self._soap_token = client.service.Authenticate(
            username=self.config()["admin_username"],
            password=self.config()["admin_password"],
        )

        return self._soap_token

    # end method definition

    def exec_command(self, command: str) -> dict:
        """Execute a command on Archive Center.

        Args:
            command (str):
                The command to execute.

        Returns:
            dict:
                The response of the HTTP request.

        """

        payload = {
            "command": command,
            "user": self.config()["ds_username"],
            "passwd": self.config()["ds_password"],
        }

        request_url = self.exec_url()
        self.logger.info(
            "Execute command -> %s on Archive Center (user -> %s); calling -> %s",
            command,
            payload["user"],
            request_url,
        )
        response = requests.post(
            url=request_url,
            data=payload,
            headers=REQUEST_FORM_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
        if not response.ok:
            self.logger.error(
                "Failed to execute command -> %s on Archive Center; error -> %s",
                command,
                response.text.replace("\n", " "),  # avoid multi-line log entries
            )

        return response

    # end method definition

    def put_cert(
        self,
        auth_id: str,
        logical_archive: str,
        cert_path: str,
        permissions: str = "rcud",
    ) -> dict | None:
        """Put Certificate on Archive Center via SOAP Call.

        Args:
            auth_id (str):
                ID of Certification
            logical_archive (str):
                The Archive ID.
            cert_path (str):
                The path to local certificate file (base64 encoded).
            permissions (str, optional):
                Permissions of the certificate.
                Defaults to "rcud" (read-create-update-delete).

        Returns:
            Response or None if the request fails.

        """

        # Check if the photo file exists
        if not os.path.isfile(cert_path):
            self.logger.error("Certificate file -> '%s' not found!", cert_path)
            return None

        with open(file=cert_path, encoding="utf-8") as cert_file:
            cert_content = cert_file.read().strip()

        # Check that we have the pem certificate file - this is what OTAC expects.
        # If the file content is base64 encoded we will decode it
        if "BEGIN CERTIFICATE" in cert_content:
            self.logger.debug(
                "Certificate file -> '%s' is not base64 encoded",
                cert_path,
            )
        elif "BEGIN CERTIFICATE" in base64.b64decode(
            cert_content,
            validate=True,
        ).decode("utf-8"):
            self.logger.debug("Certificate file -> '%s' is base64 encoded", cert_path)
            cert_content = base64.b64decode(cert_content, validate=True).decode("utf-8")
        else:
            self.logger.error(
                "Certificate file -> '%s' is not in the right format",
                cert_path,
            )
            return None

        request_url = (
            self.base_url()
            + "/archive?putCert&pVersion=0046&authId="
            + auth_id
            + "&contRep="
            + logical_archive
            + "&permissions="
            + permissions
        )
        self.logger.debug(
            "Putting certificate -> '%s' on Archive -> '%s'; calling -> %s",
            cert_path,
            logical_archive,
            request_url,
        )
        response = requests.put(
            url=request_url,
            data=cert_content,
            headers=REQUEST_FORM_HEADERS,
            timeout=REQUEST_TIMEOUT,
        )

        if not response.ok:
            message = response.text.split(
                '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN',
            )[0]
            self.logger.error(
                "Failed to put certificate -> '%s' on Archive -> '%s'; error -> %s",
                cert_path,
                logical_archive,
                message,
            )

        return response

    # end method definition

    def enable_cert(
        self,
        auth_id: str,
        logical_archive: str,
        enable: bool = True,
    ) -> bool:
        """Enable Certitificate on Archive Center via SOAP call.

        Args:
            auth_id (str):
                The authorization ID.
            logical_archive (str):
                The logical archive.
            enable (bool, optional):
                Enable or Disable certificate. Defaults to True.

        Returns:
            True if certificate has been activated, False if an error has occured.

        """

        if not self._soap_token:
            self.authenticate_soap()

        if enable:
            enabled: int = 1
        else:
            enabled: int = 0

        url = self.base_url() + "/ot-admin/services/ArchiveAdministration?wsdl"
        client = Client(url)

        token_header = client.factory.create("ns0:OTAuthentication")
        token_header.AuthenticationToken = self._soap_token
        client.set_options(soapheaders=token_header)

        try:
            response = client.service.invokeCommand(
                command="SetCertificateFlags",
                parameters=[
                    {"key": "CERT_TYPE", "data": "@{}".format(logical_archive)},
                    {"key": "CERT_NAME", "data": auth_id},
                    {"key": "CERT_FLAGS", "data": enabled},
                ],
            )
            # With SOAP, no response is a good response!
            if not response:
                self.logger.debug("Archive Center certificate has been activated.")
                return True
            elif response.code == 500:
                self.logger.error(
                    "Failed to activate Archive Center certificate for Client -> %s on Archive -> '%s'!",
                    auth_id,
                    logical_archive,
                )
                return False

        except WebFault:
            self.logger.error(
                "Failed to execute SetCertificateFlags for Client -> %s on Archive -> '%s'",
                auth_id,
                logical_archive,
            )
            return False

    # end method definition

    def enable_certificate(
        self,
        cert_name: str,
        cert_type: str,
        logical_archive: str | None = None,
    ) -> dict | None:
        """Enable a certificate via the new REST API (replacing the old SOAP interface).

        Args:
            cert_name (str):
                The name of the certificate.
            cert_type (str):
                The type of the certificate.
            logical_archive (str, optional):
                Logical archive name. If empty it is a global certificate
                for all logical archives in Archive Center.

        Returns:
            dict | None:
                REST response or None if the request fails

        Example:
            {
                'IDNO': '3',
                'CERT_NAME': 'SP_otcs-admin-0',
                'IMPORT_TIMESTAMP': '1714092017',
                'CERT_TYPE': 'ARC',
                'ASSIGNED_ARCHIVE': None,
                'FINGER_PRINT': 'B9F5 AF66 7CE6 C613 2B3C CAEE 96B6 4F79 97BB 5470 ',
                'ENABLED': True,
                'CERTIFICATE': '...',
                'PRIVILEGES': {'read': True, 'create': True, 'update': True, 'delete': True}
            }

        """

        request_url = self.config()["certUrl"] + "?cert_name=" + cert_name + "&cert_type=" + cert_type
        if logical_archive:
            request_url += "&assigned_archive=" + logical_archive

        request_header = self.request_json_header()

        payload = {"ENABLED": True}

        self.logger.debug(
            "Enabling certificate -> '%s' of type -> '%s' to Archive Center; calling -> %s",
            cert_name,
            cert_type,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                headers=request_header,
                data=json.dumps(payload),
                timeout=REQUEST_TIMEOUT,
            )
            if response.ok:
                self.logger.debug(
                    "Certificate -> '%s' has been enabled on Archive Center keystore",
                    cert_name,
                )
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                self.logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            else:
                self.logger.error(
                    "Failed to enable certificate -> '%s' in Archive Center; status -> %s; error -> %s",
                    cert_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

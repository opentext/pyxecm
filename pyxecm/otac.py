"""
OTAC Module to implement functions to apply Archive Center settings

Class: OTAC
Methods:

__init__ : class initializer
config : returns config data set
hostname: returns the Archive Center hostname
set_hostname: sets the Archive Center hostname
credentials: Get credentials (username + password)
set_credentials: Set the credentials for Archive Center for the "ds" and "admin" users
base_url: Returns the Archive Center base URL
exec_url: Returns the Archive Center URL to execute commands
request_form_header: Deliver the FORM request header used for the SOAP calls.
request_json_header: Deliver the JSON request header used for the CRUD REST API calls.
parse_request_response: Converts the text property of a request response object to a 
                        Python dict in a safe way that also handles exceptions.
authenticate: Authenticates at Archive Center and retrieve Ticket
authenticate_soap: Authenticate via SOAP with admin User
exec_command: exec a command on Archive Center
put_cert: put Certificate on Archive Center
enable_cert: enables Certitificate on Archive Center via SOAP
enable_certificate: Enable a certificate via the new REST API
                    (replacing the old SOAP interface)
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import base64
import json
import requests

from suds.client import Client
from suds import WebFault

logger = logging.getLogger("pyxecm.otac")

REQUEST_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}

REQUEST_JSON_HEADERS = {
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/json",
}

REQUEST_TIMEOUT = 60

class OTAC:
    """Used to automate stettings in OpenText Archive Center."""

    _config = None
    _soap_token: str = ""
    _otac_ticket = None

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
    ):
        """Initialize the OTAC object

        Args:
            protocol (str): Either http or https.
            hostname (str): The hostname of the Archive Center  to communicate with.
            port (int): The port number used to talk to the Archive Center .
            ds_username (str): The admin user name of Archive Center (dsadmin).
            ds_password (str): The admin password of Archive Center (dsadmin).
            admin_username (str): The admin user name of Archive Center (otadmin@otds.admin).
            admin_password (str): The admin password of Archive Center (otadmin@otds.admin).
        """

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

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    def hostname(self) -> str:
        """Returns the Archive Center hostname

        Returns:
            str: Archive Center hostname
        """
        return self.config()["hostname"]

    def set_hostname(self, hostname: str):
        """Sets the Archive Center hostname

        Args:
            hostname (str): new Archive Center hostname
        """
        self.config()["hostname"] = hostname

    def credentials(self) -> dict:
        """Get credentials (username + password)

        Returns:
            dict: dictionary with username and password
        """
        return {
            "username": self.config()["admin_username"],
            "password": self.config()["admin_password"],
        }

    def set_credentials(
        self,
        ds_username: str = "",
        ds_password: str = "",
        admin_username: str = "",
        admin_password: str = "",
    ):
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

    def base_url(self) -> str:
        """Returns the Archive Center base URL

        Returns:
            str: Archive Center base URL
        """
        return self.config()["baseUrl"]

    def exec_url(self) -> str:
        """Returns the Archive Center URL to execute commands

        Returns:
            str: Archive Center exec URL
        """
        return self.config()["execUrl"]

    def request_form_header(self) -> dict:
        """Deliver the FORM request header used for the SOAP calls.
           Consists of Token + Form Headers (see global variable)

        Args:
            None.
        Return:
            dict: request header values
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
            dict: request header values
        """

        if not self._otac_ticket:
            self.authenticate(revalidate=True)

        # create union of two dicts: cookie and headers
        # (with Python 3.9 this would be easier with the "|" operator)
        request_header = {}
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
        """Converts the text property of a request response object to a
           Python dict in a safe way that also handles exceptions.
        Args:
            response_object (object): this is reponse object delivered by the request call
            additional_error_message (str): print a custom error message
            show_error (bool): if True log an error, if False log a warning

        Returns:
            dict: response or None in case of an error
        """

        if not response_object:
            return None

        try:
            dict_object = json.loads(response_object.text)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSon. {}; error -> {}".format(
                    additional_error_message, exception
                )
            else:
                message = "Cannot decode response as JSon; error -> {}".format(
                    exception
                )
            if show_error:
                logger.error(message)
            else:
                logger.debug(message)
            return None
        else:
            return dict_object

    # end method definition

    def authenticate(self, revalidate: bool = False) -> dict | None:
        """Authenticates at Archive Center and retrieve Ticket.

        Args:
            revalidate (bool, optional): determinse if a re-athentication is enforced
                                         (e.g. if session has timed out with 401 error)
                                         By default we use the OTDS ticket (if exists) for the authentication with OTCS.
                                         This switch allows the forced usage of username / password for the authentication.
        Returns:
            dict: Cookie information of None in case of an error.
                  Also stores cookie information in self._cookie
        """

        # Already authenticated and session still valid?
        if self._otac_ticket and not revalidate:
            logger.debug(
                "Session still valid - return existing ticket -> %s",
                str(self._otac_ticket),
            )
            return self._otac_ticket

        otac_ticket = None

        request_url = self.config()["authenticationUrl"]
        # Check if previous authentication was not successful.
        # Then we do the normal username + password authentication:
        logger.debug(
            "Requesting OTAC ticket with User/Password; calling -> %s",
            request_url,
        )

        response = None
        try:
            response = requests.post(
                url=request_url,
                data=json.dumps(
                    self.credentials()
                ),  # this includes username + password
                headers=REQUEST_JSON_HEADERS,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exception:
            logger.warning(
                "Unable to connect to -> %s; error -> %s",
                request_url,
                exception.strerror,
            )
            logger.warning("OTAC service may not be ready yet.")
            return None

        if response.ok:
            authenticate_list = self.parse_request_response(
                response, "This can be normal during restart", False
            )
            if not authenticate_list:
                return None
            else:
                authenticate_dict = authenticate_list[1]
                otac_ticket = authenticate_dict["TOKEN"]
                logger.debug("Ticket -> %s", otac_ticket)
        else:
            logger.error("Failed to request an OTAC ticket; error -> %s", response.text)
            return None

        # Store authentication ticket:
        self._otac_ticket = otac_ticket

        return self._otac_ticket

    # end method definition

    def authenticate_soap(self) -> str:
        """Authenticate via SOAP with admin User

        Args:
            None
        Returns:
            string: soap_token
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
        """Execute a command on Archive Center

        Args:
            command (str): command to execute
        Returns:
            dict: Response of the HTTP request.
        """

        payload = {
            "command": command,
            "user": self.config()["ds_username"],
            "passwd": self.config()["ds_password"],
        }

        request_url = self.exec_url()
        logger.info(
            "Execute command -> %s on Archive Center (user -> %s); calling -> %s",
            command,
            payload["user"],
            request_url,
        )
        response = requests.post(
            url=request_url, data=payload, headers=REQUEST_FORM_HEADERS, timeout=None
        )
        if not response.ok:
            logger.error(
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
    ):
        """Put Certificate on Archive Center via SOAP Call

        Args:
            auth_id (str): ID of Certification
            logical_archive (str): Archive ID
            cert_path (str): local path to certificate (base64)
            permissions (str, optional): Permissions of the certificate.
                                         Defaults to "rcud" (read-create-update-delete).
        Returns:
            response or None if the request fails
        """

        # Check if the photo file exists
        if not os.path.isfile(cert_path):
            logger.error("Certificate file -> '%s' not found!", cert_path)
            return None

        with open(file=cert_path, mode="r", encoding="utf-8") as cert_file:
            cert_content = cert_file.read().strip()

        # Check that we have the pem certificate file - this is what OTAC expects.
        # If the file content is base64 encoded we will decode it
        if "BEGIN CERTIFICATE" in cert_content:
            logger.debug("Certificate file -> '%s' is not base64 encoded", cert_path)
        elif "BEGIN CERTIFICATE" in base64.b64decode(
            cert_content, validate=True
        ).decode("utf-8"):
            logger.debug("Certificate file -> '%s' is base64 encoded", cert_path)
            cert_content = base64.b64decode(cert_content, validate=True).decode("utf-8")
        else:
            logger.error(
                "Certificate file -> '%s' is not in the right format", cert_path
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
        logger.debug(
            "Putting certificate -> '%s' on Archive -> '%s'; calling -> %s",
            cert_path,
            logical_archive,
            request_url,
        )
        response = requests.put(
            url=request_url,
            data=cert_content,
            headers=REQUEST_FORM_HEADERS,
            timeout=None,
        )

        if not response.ok:
            message = response.text.split(
                '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN'
            )[0]
            logger.error(
                "Failed to put certificate -> '%s' on Archive -> '%s'; error -> %s",
                cert_path,
                logical_archive,
                message,
            )

        return response

    # end method definition

    def enable_cert(
        self, auth_id: str, logical_archive: str, enable: bool = True
    ) -> bool:
        """Enables Certitificate on Archive Center via SOAP call

        Args:
            auth_id (str): Client ID
            logical_archive (str): Archive ID
            enable (bool, optional): Enable or Disable certificate. Defaults to True.
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
                logger.debug("Archive Center certificate has been activated.")
                return True
            elif response.code == 500:
                logger.error(
                    "Failed to activate Archive Center certificate for Client -> %s on Archive -> '%s'!",
                    auth_id,
                    logical_archive,
                )
                return False

        except WebFault as exception:
            logger.error(
                "Failed to execute SetCertificateFlags for Client -> %s on Archive -> '%s'; error -> %s",
                auth_id,
                logical_archive,
                exception,
            )
            return False

    # end method definition

    def enable_certificate(
        self, cert_name: str, cert_type: str, logical_archive: str | None = None
    ) -> dict | None:
        """Enable a certificate via the new REST API (replacing the old SOAP interface)

        Args:
            cert_name (str): Name of the certificate
            cert_type (str): Type of the certificate
            logical_archive (str, optional): Logical archive name. If empty it is a global certificate
                                             for all logical archives in Archive Center.

        Returns:
            dict | None: REST response or None if the request fails

            Example response:
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

        request_url = (
            self.config()["certUrl"]
            + "?cert_name="
            + cert_name
            + "&cert_type="
            + cert_type
        )
        if logical_archive:
            request_url += "&assigned_archive=" + logical_archive

        request_header = self.request_json_header()

        payload = {"ENABLED": True}

        logger.debug(
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
                logger.debug(
                    "Certificate -> '%s' has been enabled on Archive Center keystore",
                    cert_name,
                )
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate(revalidate=True)
                retries += 1
            else:
                logger.error(
                    "Failed to enable certificate -> '%s' in Archive Center; status -> %s; error -> %s",
                    cert_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

"""
OTAC Module to implement functions to apply Archive Center settings

Class: OTAC
Methods:

__init__ : class initializer
config : returns config data set
hostname: returns the Archive Center hostname
set_hostname: sets the Archive Center hostname
exec_command: exec a command on Archive Center
put_cert: put Certificate on Archive Center
enable_cert: enables Certitificate on Archive Center

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2023, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
import os
import base64
import requests

from suds.client import Client
from suds import WebFault

logger = logging.getLogger("pyxecm.otac")

requestHeaders = {"Content-Type": "application/x-www-form-urlencoded"}


class OTAC:
    """Used to automate stettings in OpenText Archive Center."""

    _config = None
    _soap_token: str = ""

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        ds_username: str,
        ds_password: str,
        admin_username: str,
        admin_password: str,
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

        self._config = otac_config

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
        """Returns the Archive Center URL to execute commandss

        Returns:
            str: Archive Center exec URL
        """
        return self.config()["execUrl"]

    def _soap_login(self):
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

    def exec_command(self, command: str):
        """Execute a command on Archive Center

        Args:
            command (str): command to execute
        Returns:
            _type_: _description_
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
            url=request_url, data=payload, headers=requestHeaders, timeout=None
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
        """Put Certificate on Archive Center

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
            logger.error("Certificate file -> %s not found!", cert_path)
            return None

        with open(file=cert_path, mode="r", encoding="utf-8") as cert_file:
            cert_content = cert_file.read().strip()

        # Check that we have the pem certificate file - this is what OTAC expects.
        # If the file content is base64 encoded we will decode it
        if "BEGIN CERTIFICATE" in cert_content:
            logger.info("Certificate file -> %s is not base64 encoded", cert_path)
        elif "BEGIN CERTIFICATE" in base64.b64decode(
            cert_content, validate=True
        ).decode("utf-8"):
            logger.info("Certificate file -> %s is base64 encoded", cert_path)
            cert_content = base64.b64decode(cert_content, validate=True).decode("utf-8")
        else:
            logger.error("Certificate file -> %s is not in the right format", cert_path)
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
        logger.info(
            "Putting certificate -> %s on Archive -> %s; calling -> %s",
            cert_path,
            logical_archive,
            request_url,
        )
        response = requests.put(
            url=request_url, data=cert_content, headers=requestHeaders, timeout=None
        )

        if not response.ok:
            message = response.text.split(
                '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN'
            )[0]
            logger.error(
                "Failed to put certificate -> %s on Archive -> %s; error -> %s",
                cert_path,
                logical_archive,
                message,
            )

        return response

    # end method definition

    def enable_cert(self, auth_id: str, logical_archive: str, enable: bool = True):
        """Enables Certitificate on Archive Center

        Args:
            auth_id (str): Client ID
            logical_archive (str): Archive ID
            enable (bool, optional): Enable or Disable certificate. Defaults to True.
        Returns:
            response or None if request fails.
        """

        if not self._soap_token:
            self._soap_login()

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
            return response

        except WebFault as exception:
            logger.error(
                "Failed to execute SetCertificateFlags for Client -> %s on Archive -> %s; error -> %s",
                auth_id,
                logical_archive,
                exception,
            )
            return None

    # end method definition

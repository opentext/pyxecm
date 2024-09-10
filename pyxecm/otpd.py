"""
OTPD Module to implement functions to read / write PowerDocs objects

Class: OTPD
Methods:

__init__ : class initializer
config : returns config data set
credentials: Get credentials (username and password)
set_credentials: Set new credentials
hostname: Get the configured PowerDocs hostname
set_hostname: Set the hostname of PowerDocs
base_url : Get PowerDocs base URL
rest_url : Get PowerDocs REST base URL

parse_request_response: Converts the text property of a request
                        response object to a Python dict in a safe way

authenticate : Authenticates at PowerDocs and retrieve OTCS Ticket.

import_database: imports the PowerDocs database from a zip file
apply_setting: apply a setting to a PowerDocs tenant

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import requests
from requests.auth import HTTPBasicAuth
from requests_toolbelt.multipart.encoder import MultipartEncoder

logger = logging.getLogger("pyxecm.otpd")

requestHeaders = {
    "accept": "application/json;charset=utf-8",
    "Connection": "keep-alive",
    "Content-Type": "application/json",
}


class OTPD:
    """Used to automate stettings in OpenText Extended ECM PowerDocs."""

    _config = None
    _jsessionid = None

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        username: str,
        password: str,
    ):
        """Initialize the OTPD object

        Args:
            protocol (str): Either http or https.
            hostname (str): The hostname of the PowerDocs Server Manager to communicate with.
            port (int): The port number used to talk to the PowerDocs Server Manager.
            username (str): The admin user name of PowerDocs Server Manager.
            password (str): The admin password of PowerDocs Server Manager.
        """

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

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    def credentials(self) -> dict:
        """Get credentials (username + password)

        Returns:
            dict: dictionary with username and password
        """
        return {
            "username": self.config()["username"],
            "password": self.config()["password"],
        }

    def set_credentials(self, username: str = "admin", password: str = ""):
        """Set the credentials for PowerDocs for the based on user name and password.

        Args:
            username (str, optional): Username. Defaults to "admin".
            password (str, optional): Password of the user. Defaults to "".
        """
        self.config()["username"] = username
        self.config()["password"] = password

    def hostname(self) -> str:
        """Returns the hostname of PowerDocs (e.g. "otpd")

        Returns:
            string: hostname
        """
        return self.config()["hostname"]

    def set_hostname(self, hostname: str):
        """Sets the hostname of PowerDocs

        Args:
            hostname (str): new hostname
        """
        self.config()["hostname"] = hostname

    def base_url(self):
        """Returns the base URL of PowerDocs

        Returns:
            string: base URL
        """
        return self.config()["baseUrl"]

    def rest_url(self):
        """Returns the REST URL of PowerDocs

        Returns:
            string: REST URL
        """
        return self.config()["restUrl"]

    def parse_request_response(
        self,
        response_object: object,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Converts the request response to a Python dict in a safe way
           that also handles exceptions.

        Args:
            response_object (object): this is reponse object delivered by the request call
            additional_error_message (str): print a custom error message
            show_error (bool): if True log an error, if False log a warning
        Returns:
            dict: a python dict object or None in case of an error
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
                logger.warning(message)
            return None
        else:
            return dict_object

    # end method definition

    # This method is currently not used and not working...
    # It cannot handle the Request - ServerManager returns an
    # error stating that JavaScript is not enabled...
    def authenticate(self, revalidate: bool = False) -> dict:
        """Authenticates at PowerDocs and retrieve session ID.

        Args:
            revalidate (bool): determinse if a re-athentication is enforced
                               (e.g. if session has timed out with 401 error)
        Returns:
            dict: Cookie information of None in case of an error.
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

        ##Fetching session id will be three step process
        # Step1: intiate a dummy request to tomcat
        # Step2: fetch session id from the response, and hit j_security_check with proper authentication
        # Step3: get session id from the response, add to self. It can be used for other transactions
        session = requests.Session()
        logger.debug("Initiating dummy rest call to Tomcat to get initial session id")
        response = session.put(request_url, json=payload)
        logger.info(response.text)
        if response.ok:
            logger.debug("Url to authenticate Tomcat for Session id -> %s", auth_url)
            session_response = session.post(auth_url)
            if session_response.ok:
                logger.debug(
                    "Response for -> %s is -> %s", auth_url, str(session_response)
                )
                session_dict = session.cookies.get_dict()
                logger.debug(
                    "Session id to perform Rest API calls to Tomcat -> %s",
                    session_dict["JSESSIONID"],
                )
                # store session ID an write it into the global requestHeaders variable:
                self._jsessionid = session_dict["JSESSIONID"]
                requestHeaders["Cookie"] = "JSESSIONID=" + self._jsessionid
                return session_response
            else:
                logger.error(
                    "Fetching session id from -> %s failed with j_security_check. Response -> %s",
                    auth_url,
                    session_response.text,
                )
                return None
        else:
            logger.error(
                "Fetching session id from -> %s failed. Response -> %s",
                request_url,
                response.text,
            )
            return None

    # end method definition

    def import_database(self, filename: str):
        """Import PowerDocs database backup from a zip file"""

        file = filename.split("/")[-1]
        file_tup = (file, open(filename, "rb"), "application/zip")

        # fields attribute is set according to the other party's interface description
        m = MultipartEncoder(fields={"name": file, "zipfile": file_tup})

        request_url = self.config()["otpdImportDatabaseUrl"]

        logger.info(
            "Importing PowerDocs database backup -> %s, into PowerDocs ServerManager on -> %s",
            filename,
            request_url,
        )
        response = requests.post(
            request_url, data=m, headers={"content-type": m.content_type}, timeout=60
        )

        if response.ok:
            return response
        else:
            logger.error(
                "Failed to import PowerDocs database backup -> %s into -> %s; error -> %s",
                filename,
                request_url,
                response.text,
            )
            return None

    # end method definition

    def apply_setting(
        self, setting_name: str, setting_value: str, tenant_name: str = ""
    ) -> dict | None:
        """Appy a setting to the PowerDocs Server Manager

        Args:
            setting_name (str): name of the setting
            setting_value (str): new value of the setting
            tenant_name (str): name of the PowerDocs tenant - this is optional as some settings are not tenant-specific!
        Return:
            dict: Request response or None if the REST call fails.
        """

        settingsPutBody = {
            "settingname": setting_name,
            "settingvalue": setting_value,
        }

        if tenant_name:
            settingsPutBody["tenantName"] = tenant_name

        request_url = self.config()["settingsUrl"]

        logger.debug(
            "Update PowerDocs setting -> %s with value -> %s (tenant -> %s); calling -> %s",
            setting_name,
            setting_value,
            tenant_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=settingsPutBody,
                headers=requestHeaders,
                auth=HTTPBasicAuth(
                    self.config()["username"], self.config()["password"]
                ),
                verify=False,  # for localhost deployments this will fail otherwise
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.debug("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update PowerDocs setting -> %s with value -> %s (tenant -> %s); error -> %s",
                    setting_name,
                    setting_value,
                    tenant_name,
                    response.text,
                )
                return None

    # end method definition

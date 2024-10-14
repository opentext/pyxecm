"""
AVTS stands for Aviator Search and is an OpenText offering for LLMM-based search across multiple repositories

Class: AVTS
Methods:
__init__: class initializer
request_header: Returns the request header used for Application calls.
do_request: Call an Aviator Search REST API in a safe way
parse_request_response: Converts the request response (JSon) to a Python list in a safe way
authenticate: Authenticate at Search Aviator via oAuth authentication
repo_create_extended_ecm: Create a new repository to crawl in Aviator Search
start_crawling: Start crawling of a repository
stop_crawling: Stop the crawling of a repository
get_repo_list: Get a list of all repositories
get_repo_by_name: Get a repository by name
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import time
import os
import base64

import requests

logger = logging.getLogger("pyxecm.customizer.avts")

REQUEST_HEADERS = {"Accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60
REQUEST_RETRY_DELAY = 20
REQUEST_MAX_RETRIES = 2


class AVTS(object):
    """Used to configure and interact with Aviator Search"""

    _config: dict
    _session = None

    def __init__(
        self,
        otds_url: str,
        client_id: str,
        client_secret: str,
        base_url: str,
        username: str,
        password: str,
    ):
        """Initialize the AVTS object

        Args:
            otds_url (str): URL of the OTDS Server used by Aviator Search
            client_id (str): Client ID for the Aviator Search oAuth client
            client_secret (str): Client Secret for the Aviator Search oAuth client
            base_url (str): Aviator Search base URL
            username (str): User with administrative permissions in Aviator Search
            password (str): Password of the user with administrative permissions in Aviator Search
        """

        avts_config = {}

        # Store the credentials and parameters in a config dictionary:
        avts_config["otdsUrl"] = otds_url
        avts_config["clientId"] = client_id
        avts_config["clientSecret"] = client_secret
        avts_config["baseUrl"] = base_url
        avts_config["username"] = username
        avts_config["password"] = password

        avts_config["tokenUrl"] = avts_config["otdsUrl"] + "/otdsws/oauth2/token"
        avts_config["repoUrl"] = (
            avts_config["baseUrl"] + "/aviator-gateway/avts-api/admin/v1/repo"
        )

        self._config = avts_config
        self._accesstoken = None

        self._session = requests.Session()

    # end method definition

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    # end method definition

    def request_header(self, content_type: str = "") -> dict:
        """Returns the request header used for Application calls.
           Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional): custom content type for the request
        Return:
            dict: request header values
        """

        request_header = {}

        request_header = REQUEST_HEADERS

        if content_type:
            request_header["Content-Type"] = content_type

        if self._accesstoken is not None:
            request_header["Authorization"] = f"Bearer {self._accesstoken}"

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
        timeout: int | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
    ) -> dict | None:
        """Call an Aviator Search REST API in a safe way

        Args:
            url (str): URL to send the request to.
            method (str, optional): HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional): Request Headers. Defaults to None.
            json (dict | None, optional): Request payload. Defaults to None.
            files (dict | None, optional): Dictionary of {"name": file-tuple} for multipart encoding upload.
                                           file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (int | None, optional): Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional): Whether or not an error should be logged in case of a failed REST call.
                                         If False, then only a warning is logged. Defaults to True.
            failure_message (str, optional): Specific error message. Defaults to "".
            max_retries (int, optional): How many retries on Connection errors? Default is REQUEST_MAX_RETRIES.
            retry_forever (bool, optional): Eventually wait forever - without timeout. Defaults to False.

        Returns:
            dict | None: Response of Aviator Search REST API or None in case of an error.
        """

        retries = 0
        while True:
            try:
                response = self._session.request(
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
                        logger.debug(success_message)
                    return self.parse_request_response(response)
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    logger.debug("Session has expired - try to re-authenticate...")
                    self.authenticate()
                    retries += 1
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    if content_type == "text/html":
                        response_text = "HTML content (see debug log)"
                    else:
                        response_text = response.text

                    if show_error:
                        logger.error(
                            "%s; status -> %s; error -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )
                    else:
                        logger.warning(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )

                    if content_type == "text/html":
                        logger.debug(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response.text,
                        )

                    return None
            except requests.exceptions.Timeout:
                if retries <= max_retries:
                    logger.warning(
                        "Request timed out. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    logger.error(
                        "%s; timeout error",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                    else:
                        return None
            except requests.exceptions.ConnectionError:
                if retries <= max_retries:
                    logger.warning(
                        "Connection error. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    logger.error(
                        "%s; connection error",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                        logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                        time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                    else:
                        return None

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> list | None:
        """Converts the request response (JSon) to a Python list in a safe way
           that also handles exceptions. It first tries to load the response.text
           via json.loads() that produces a dict output. Only if response.text is
           not set or is empty it just converts the response_object to a dict using
           the vars() built-in method.

        Args:
            response_object (object): this is reponse object delivered by the request call
            additional_error_message (str, optional): use a more specific error message
                                                      in case of an error
            show_error (bool): True: write an error to the log file
                               False: write a warning to the log file
        Returns:
            list: response information or None in case of an error
        """

        if not response_object:
            return None

        try:
            if response_object.text:
                list_object = json.loads(response_object.text)
            else:
                list_object = vars(response_object)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSON. {}; error -> {}".format(
                    additional_error_message, exception
                )
            else:
                message = "Cannot decode response as JSON; error -> {}".format(
                    exception
                )
            if show_error:
                logger.error(message)
            else:
                logger.warning(message)
            return None
        else:
            return list_object

    # end method definition

    def authenticate(self) -> str | None:
        """Authenticate at Search Aviator via oAuth authentication."""

        if not self._session:
            self._session = requests.Session()

        self._session.headers.update(self.request_header())

        request_url = self.config()["tokenUrl"]
        request_header = {
            "Authorization": "Bearer ",
            "content-type": "application/x-www-form-urlencoded",
        }
        request_payload = {
            "client_id": self.config()["clientId"],
            "grant_type": "password",
            "client_secret": self.config()["clientSecret"],
            "username": self.config()["username"],
            "password": self.config()["password"],
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=request_payload,
            timeout=None,
            failure_message=f"Failed to authenticate to OTDS with username -> {self.config()['username']} and client_id -> {self.config()['clientId']}",
        )

        if response is not None:
            self._accesstoken = response.get("access_token", None)

        return response

    # end method definition

    def repo_create_extended_ecm(
        self,
        name: str,
        username: str,
        password: str,
        otcs_url: str,
        otcs_api_url: str,
        node_id: int,
        version: str = "24.3.0",
    ) -> dict | None:
        """Create a new repository to crawl in Aviator Search

        Args:
            id (str): ID of the repository
            name (str): socName of the repository
            username (str): Username to use for crawling
            password (str): Password of the user used for crawling
            otcs_url (str): Base URL of Content Server e.g. https://otcs.base-url.tld/cs/cs
            node_id (int): Root Node ID for crawling

        Returns:
            dict | None: Parsed response object from the API or None in case of an error
        """

        payload = {
            "id": "xECM",
            "name": name,
            "metadataFields": ["NODE"],
            "socName": "xECM",
            "params": [
                {
                    "id": "OpenTextApiUrl",
                    "label": "xECM API URL",
                    "ctlType": "text",
                    "required": True,
                    "value": otcs_api_url,
                },
                {
                    "id": "Username",
                    "label": "xECM username",
                    "ctlType": "text",
                    "required": True,
                    "value": username,
                },
                {
                    "id": "Password",
                    "label": "xECM Password",
                    "ctlType": "password",
                    "required": True,
                    "value": password,
                },
                {
                    "id": "RootNodeId",
                    "label": "Root Node ID",
                    "ctlType": "text",
                    "required": True,
                    "value": node_id,
                },
                {
                    "id": "sourceLink",
                    "label": "Source Link( ex:https://<xECM host>/cs/cs/app/nodes/${NODE}/metadata )",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": otcs_url + "/app/nodes/${NODE}/metadata",
                    "visible": True,
                },
            ],
            "idolConfig": {
                "view": {
                    "name": "ViewOpenText",
                    "type": "idol.nifi.connector.ViewOpenText",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-opentext",
                    "version": version,
                },
                "crawler": {
                    "name": "GetOpenText",
                    "type": "idol.nifi.connector.GetOpenText",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-opentext",
                    "version": version,
                },
                "omniGroup": {
                    "name": "GetOpenTextGroups",
                    "type": "idol.nifi.connector.GetOpenTextGroups",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-opentext",
                    "version": version,
                },
            },
            "idolProperties": {
                "view": {
                    "Password": "${Password}",
                    "Username": "${UserName}",
                    "OpenTextApiUrl": "${OpenTextApiUrl}",
                },
                "crawler": {
                    "Password": "${Password}",
                    "Username": "${UserName}",
                    "RootNodeId": "${RootNodeId}",
                    "META:SOURCE": "OPENTEXT",
                    "MappedSecurity": "true",
                    "OpenTextApiUrl": "${OpenTextApiUrl}",
                },
                "omniGroup": {
                    "Password": "${Password}",
                    "Username": "${UserName}",
                    "OpenTextApiUrl": "${OpenTextApiUrl}",
                    "OpenTextApiPageSize": "10",
                },
            },
        }

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        return self.do_request(
            url=request_url,
            method="POST",
            json_data=payload,
            headers=request_header,
            timeout=None,
            failure_message="Failed to create repository -> '{}' ({})".format(
                name, node_id
            ),
        )

    # end method definition

    def repo_create_msteams(
        self,
        name: str,
        client_id: str,
        tenant_id: str,
        certificate_file: str,
        certificate_password: int,
        index_attachments: bool = True,
        index_call_recordings: bool = True,
        index_message_replies: bool = True,
        index_user_chats: bool = True,
        oauth2_site_name: str = "AVTS",
        oauth2_sites_file: str = "",
        version: str = "24.3.0",
    ) -> dict | None:
        """Create a new repository to crawl in Aviator Search

        Args:
            id (str): ID of the repository
            name (str): socName of the repository
            #todo: add more params

        Returns:
            dict | None: Parsed response object from the API or None in case of an error
        """

        if os.path.isfile(certificate_file):
            # Open the file in binary mode
            with open(certificate_file, "rb") as file:
                # Read the content of the file
                certificate_file_content = file.read()
                # Convert the bytes to a base64 string
                certificate_file_content_base64 = base64.b64encode(
                    certificate_file_content
                ).decode("utf-8")

        payload = {
            "id": "MSTeams",
            "socName": "Microsoft Teams",
            "authType": "OAUTH",
            "name": name,
            "params": [
                {
                    "id": "OAuth2SiteName",
                    "label": "OAuth2 Site Name",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "AVTS",
                    "value": "AVTS",
                    "visible": False,
                },
                {
                    "id": "OAuth2SitesFile",
                    "label": "OAuth2 Sites File",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": False,
                },
                {
                    "id": "sourceLink",
                    "label": "Source Link",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "",
                    "visible": True,
                },
                {
                    "id": "clientID",
                    "label": "Client ID",
                    "ctlType": "text",
                    "description": "Microsoft Entra client ID",
                    "required": True,
                    "defaultValue": "",
                    "value": client_id,
                    "visible": True,
                },
                {
                    "id": "tenant",
                    "label": "Tenant ID",
                    "ctlType": "text",
                    "description": "Microsoft Entra tenant ID",
                    "required": True,
                    "defaultValue": "",
                    "value": tenant_id,
                    "visible": True,
                },
                {
                    "id": "IndexAttachments",
                    "label": "Index Attachments",
                    "ctlType": "boolean",
                    "description": "Specifies whether to index attachments",
                    "required": False,
                    "defaultValue": "true",
                    "value": str(index_attachments).lower(),
                    "visible": True,
                },
                {
                    "id": "IndexCallRecordings",
                    "label": "Index Call Recordings",
                    "ctlType": "boolean",
                    "description": "Specifies whether to index call recordings",
                    "required": False,
                    "defaultValue": "true",
                    "value": str(index_call_recordings).lower(),
                    "visible": True,
                },
                {
                    "id": "IndexMessageReplies",
                    "label": "Index Message Replies",
                    "ctlType": "boolean",
                    "description": "Specifies whether to index replies to messages",
                    "required": False,
                    "defaultValue": "true",
                    "value": str(index_message_replies).lower(),
                    "visible": True,
                },
                {
                    "id": "IndexUserChats",
                    "label": "Index User Chats",
                    "ctlType": "boolean",
                    "description": "Specifies whether to synchronize one-to-one and group messages for each user",
                    "required": False,
                    "defaultValue": "true",
                    "value": str(index_user_chats).lower(),
                    "visible": True,
                },
                {
                    "id": "certificateFile",
                    "label": "Certificate File",
                    "ctlType": "file",
                    "description": 'Please upload a valid "*.pfx" certificate file',
                    "required": True,
                    "defaultValue": "",
                    "value": "C:\\fakepath\\certificate.pfx",
                    "visible": True,
                    "fileDatabase64": f"data:application/x-pkcs12;base64,{certificate_file_content_base64}",
                },
                {
                    "id": "certificateFilePassword",
                    "label": "Certificate File Password",
                    "ctlType": "password",
                    "required": True,
                    "defaultValue": "",
                    "value": certificate_password,
                    "visible": True,
                },
            ],
            "idolConfig": {
                "view": {
                    "name": "ViewMicrosoftTeams",
                    "type": "idol.nifi.connector.ViewMicrosoftTeams",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-officeteams",
                    "version": version,
                },
                "crawler": {
                    "name": "GetMicrosoftTeams",
                    "type": "idol.nifi.connector.GetMicrosoftTeams",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-officeteams",
                    "version": version,
                },
            },
            "idolProperties": {
                "view": {
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "IndexCallRecordings": "true",
                },
                "crawler": {
                    "META:SOURCE": "MSTeams",
                    "IndexUserChats": "${IndexUserChats}",
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "IndexAttachments": "${IndexAttachments}",
                    "IndexCallRecordings": "${IndexCallRecordings}",
                    "IndexMessageReplies": "${IndexMessageReplies}",
                },
            },
            "authRedirect": "",
            "metadataFields": [],
        }

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=payload,
            headers=request_header,
            timeout=None,
            failure_message="Failed to create repository -> '{}'".format(name),
        )

        if response is None:
            return None

        self.repo_admin_consent(response["id"])

        return response

    # end method definition

    def repo_create_sharepoint(
        self,
        name: str,
        client_id: str,
        tenant_id: str,
        certificate_file: str,
        certificate_password: int,
        sharepoint_url: str,
        sharepoint_url_type: str,
        sharepoint_mysite_url: str,
        sharepoint_admin_url: str,
        index_user_profiles: bool = True,
        oauth2_site_name: str = "AVTS",
        oauth2_sites_file: str = "",
        version: str = "24.3.0",
    ) -> dict | None:
        """Create a new repository to crawl in Aviator Search

        Args:
            id (str): ID of the repository
            name (str): socName of the repository
            #todo: add more params

        Returns:
            dict | None: Parsed response object from the API or None in case of an error
        """

        if os.path.isfile(certificate_file):
            # Open the file in binary mode
            with open(certificate_file, "rb") as file:
                # Read the content of the file
                certificate_file_content = file.read()
                # Convert the bytes to a base64 string
                certificate_file_content_base64 = base64.b64encode(
                    certificate_file_content
                ).decode("utf-8")

        payload = {
            "id": "SharePoint",
            "socName": "SharePoint Online",
            "authType": "OAUTH",
            "name": name,
            "params": [
                {
                    "id": "OAuth2SiteName",
                    "label": "OAuth2 Site Name",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "AVTS",
                    "value": oauth2_site_name,
                    "visible": False,
                },
                {
                    "id": "OAuth2SitesFile",
                    "label": "OAuth2 Sites File",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "",
                    "value": oauth2_sites_file,
                    "visible": False,
                },
                {
                    "id": "sourceLink",
                    "label": "Source Link",
                    "ctlType": "text",
                    "description": "Example: https://<sharepoint host>${FILEDIRREF}/Forms/AllItems.aspx?id=${FILEREF}&parent=${FILEDIRREF}",
                    "required": False,
                    "defaultValue": "",
                    "visible": True,
                    "value": sharepoint_url
                    + "${FILEDIRREF}/Forms/AllItems.aspx?id=${FILEREF}&parent=${FILEDIRREF}",
                },
                {
                    "id": "clientID",
                    "label": "Client ID",
                    "ctlType": "text",
                    "description": "Microsoft Entra client ID",
                    "required": True,
                    "defaultValue": "",
                    "value": client_id,
                    "visible": True,
                },
                {
                    "id": "tenant",
                    "label": "Tenant ID",
                    "ctlType": "text",
                    "description": "Microsoft Entra tenant ID",
                    "required": True,
                    "defaultValue": "",
                    "value": tenant_id,
                    "visible": True,
                },
                {
                    "id": "sharePointUrl",
                    "label": "SharePoint URL",
                    "ctlType": "text",
                    "description": 'The URL to start synchronizing from. Specify a URL that matches "SharePoint URL type"',
                    "required": True,
                    "defaultValue": "",
                    "value": sharepoint_url + "/",
                    "visible": True,
                },
                {
                    "id": "sharePointAdminUrl",
                    "label": "SharePoint Admin URL",
                    "ctlType": "text",
                    "description": "The URL of the admin site collection, for retrieving user profiles from SharePoint Online",
                    "required": True,
                    "defaultValue": "",
                    "value": sharepoint_admin_url,
                    "visible": True,
                },
                {
                    "id": "sharePointMySiteUrl",
                    "label": "SharePoint MySite URL",
                    "ctlType": "text",
                    "description": "The URL of the MySites site collection, for retrieving user profiles from SharePoint Online",
                    "required": True,
                    "defaultValue": "",
                    "value": sharepoint_mysite_url,
                    "visible": True,
                },
                {
                    "id": "sharePointOnline",
                    "label": "SharePoint Online",
                    "ctlType": "boolean",
                    "description": "Specifies whether to retrieve data from SharePoint Online. To retrieve data from a SharePoint Online dedicated server set this to false",
                    "required": False,
                    "defaultValue": "true",
                    "value": "true",
                    "visible": False,
                },
                {
                    "id": "MappedWebApplicationPolicies",
                    "label": "Mapped Web Application Policies",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "false",
                    "value": "false",
                    "visible": False,
                },
                {
                    "id": "TenantAdminSitesIncludeTypes",
                    "label": "Tenant Admin Sites IncludeTypes",
                    "ctlType": "text",
                    "description": "This parameter helps to filter the results to include only specific types of sites",
                    "required": False,
                    "defaultValue": "all",
                    "value": "all",
                    "visible": False,
                },
                {
                    "id": "URLType",
                    "label": "SharePoint URL Type",
                    "ctlType": "select",
                    "description": 'The type of URL specified by "Sharepoint URL"',
                    "required": True,
                    "defaultValue": "",
                    "value": "SiteCollection",
                    "visible": True,
                    "acceptedValues": [
                        "WebApplication",
                        "SiteCollection",
                        "PersonalSiteCollection",
                        "TenantAdmin",
                    ],
                },
                {
                    "id": "IndexUserProfiles",
                    "label": "Index User Profiles",
                    "ctlType": "boolean",
                    "description": "Specifies whether to index information from user profiles",
                    "required": True,
                    "defaultValue": "false",
                    "value": str(index_user_profiles).lower(),
                    "visible": True,
                },
                {
                    "id": "certificateFile",
                    "label": "Certificate File",
                    "ctlType": "file",
                    "description": 'Please upload a valid "*.pfx" certificate file',
                    "required": True,
                    "defaultValue": "",
                    "value": "C:\\fakepath\\certificate.pfx",
                    "visible": True,
                    "fileDatabase64": f"data:application/x-pkcs12;base64,{certificate_file_content_base64}",
                },
                {
                    "id": "certificateFilePassword",
                    "label": "Certificate File Password",
                    "ctlType": "password",
                    "required": True,
                    "defaultValue": "",
                    "value": certificate_password,
                    "visible": True,
                },
            ],
            "idolConfig": {
                "view": {
                    "name": "ViewSharePointOData",
                    "type": "idol.nifi.connector.ViewSharePointOData",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-sharepointodata",
                    "version": version,
                },
                "crawler": {
                    "name": "GetSharePointOData",
                    "type": "idol.nifi.connector.GetSharePointOData",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-sharepointodata",
                    "version": version,
                },
            },
            "idolProperties": {
                "view": {
                    "SharepointUrl": "${sharePointUrl}",
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "SharepointOnline": "${sharePointOnline}",
                    "SharepointUrlType": "${URLType}",
                    "SharepointAdminUrl": "${sharePointAdminUrl}",
                    "SharepointMySiteUrl": "${sharePointMySiteUrl}",
                    "MappedWebApplicationPolicies": "${MappedWebApplicationPolicies}",
                },
                "crawler": {
                    "META:SOURCE": "SharePoint",
                    "SharepointUrl": "${sharePointUrl}",
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "SharepointOnline": "${sharePointOnline}",
                    "IndexUserProfiles": "${IndexUserProfiles}",
                    "SharepointUrlType": "${URLType}",
                    "SharepointAdminUrl": "${sharePointAdminUrl}",
                    "SharepointMySiteUrl": "${sharePointMySiteUrl}",
                    "MappedWebApplicationPolicies": "${MappedWebApplicationPolicies}",
                    "TenantAdminSitesIncludeTypes": "${TenantAdminSitesIncludeTypes}",
                },
            },
            "authRedirect": "",
            "metadataFields": ["FILEREF", "FILEDIRREF"],
        }

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=payload,
            headers=request_header,
            timeout=None,
            failure_message="Failed to create repository -> '{}'".format(name),
        )

        if response is None:
            return None

        self.repo_admin_consent(response["id"])

        return response

    # end method definition

    def repo_admin_consent(self, repo_id: str) -> dict | None:
        """Send admin consent information for a repository

        Args:
            repo_id (str): id of the repository

        Returns:
            dict | None: Parsed response object from the API or None in case of an error
        """

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        request_url = (
            self.config()["repoUrl"] + "/" + repo_id + "/authorize?admin_consent=true"
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to set admin_consent for repository -> '{}'".format(
                repo_id
            ),
        )

    # end method definition

    def start_crawling(self, repo_name: str) -> list | None:
        """Start crawling of a repository

        Args:
            repo_name (str): name of the repository
        Returns:
            list | None: Parsed response object from the API or None in case of an error
        """

        logger.info("Start crawling repository -> %s", repo_name)

        repo = self.get_repo_by_name(name=repo_name)
        if repo is None:
            return None

        request_header = self.request_header()
        request_url = self.config()["repoUrl"] + "/start/" + repo.get("repoId")

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=None,
            failure_message="Failed to start crawling repository -> '{}'".format(
                repo_name
            ),
        )

    # end method definition

    def stop_crawling(self, repo_name: str) -> list | None:
        """Stop the crawling of a repository

        Args:
            repo_name (str): name of the repository
        Returns:
            list | None: Parsed response object from the API or None in case of an error
        """

        repo = self.get_repo_by_name(name=repo_name)
        if repo is None:
            return None

        request_header = self.request_header()
        request_url = self.config()["repoUrl"] + "/stop/" + repo.get("repoId")

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=None,
            failure_message="Failed to stop crawling repository -> '{}'".format(
                repo_name
            ),
        )

    # end method definition

    def get_repo_list(self) -> list | None:
        """Get a list of all repositories

        Returns:
            list | None: Parsed response object from the API listing all repositories or None in case of an error
        """

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get list of repositories to crawl.",
        )

    # end method definition

    def get_repo_by_name(self, name: str) -> dict | None:
        """Get a repository by name

        Args:
            name (str): name of the repository
        Returns:
            dict | None: ID of a repostiory by name or None in case of an error
        """

        repo_list = self.get_repo_list()

        if repo_list is None:
            return None

        return next(
            (repo for repo in repo_list if repo.get("repoName", "") == name),
            None,
        )

    # end method definition

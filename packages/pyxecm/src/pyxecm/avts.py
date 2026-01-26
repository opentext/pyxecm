"""AVTS stands for Aviator Search and is an OpenText offering for LLMM-based search across multiple repositories."""

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
import time
from importlib.metadata import version

import requests

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".avts"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_HEADERS = {"User-Agent": USER_AGENT, "accept": "application/json", "Content-Type": "application/json"}

REQUEST_TIMEOUT = 60.0
REQUEST_RETRY_DELAY = 20.0
REQUEST_MAX_RETRIES = 2

default_logger = logging.getLogger(MODULE_NAME)


class AVTS:
    """Configure and interact with Aviator Search REST API."""

    # Only class variables or class-wide constants should be defined here:

    logger: logging.Logger = default_logger

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: str,
        username: str,
        password: str,
        otds_url: str,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the Aviator Search (AVTS) object.

        Args:
            client_id (str):
                The client ID for the Aviator Search oAuth client.
            client_secret (str):
                The client secret for the Aviator Search oAuth client.
            base_url (str):
                The Aviator Search base URL.
            username (str):
                User with administrative permissions in Aviator Search.
            password (str):
                Password of the user with administrative permissions in Aviator Search.
            otds_url (str):
                The URL of the OTDS Server used by Aviator Search.
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("avts")
            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        avts_config = {}

        # Store the credentials and parameters in a config dictionary:
        avts_config["clientId"] = client_id
        avts_config["clientSecret"] = client_secret
        avts_config["baseUrl"] = base_url
        avts_config["username"] = username
        avts_config["password"] = password
        avts_config["otdsUrl"] = otds_url

        avts_config["tokenUrl"] = avts_config["otdsUrl"] + "/otdsws/oauth2/token"
        avts_config["repoUrl"] = avts_config["baseUrl"] + "/aviator-gateway/avts-api/admin/v1/repo"
        avts_config["questionsUrl"] = avts_config["baseUrl"] + "/aviator-gateway/avts-api/search/v1/questions"

        self._config = avts_config
        self._accesstoken = None

        self._session = requests.Session()

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: Configuration dictionary

        """

        return self._config

    # end method definition

    def request_header(self, content_type: str = "") -> dict:
        """Return the request header used for Application calls.

        Consists of Bearer access token and Content Type

        Args:
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
        data: dict | list | None = None,
        json_data: dict | None = None,
        files: dict | None = None,
        timeout: float | None = REQUEST_TIMEOUT,
        show_error: bool = True,
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
    ) -> dict | None:
        """Call an Aviator Search REST API in a safe way.

        Args:
            url (str):
                URL to send the request to.
            method (str, optional):
                HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional):
                Request headers. Defaults to None.
            data (dict | None, optional):
                Request payload. Defaults to None.
            json_data (dict | None, optional):
                Request payload for the JSON parameter. Defaults to None.
            files (dict | None, optional):
                Dictionary of {"name": file-tuple} for multipart encoding upload.
                The file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple
                ("filename", fileobj, "content_type").
            timeout (float | None, optional):
                Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            max_retries (int, optional):
                Number of retries on connection errors. Defaults to REQUEST_MAX_RETRIES.
            retry_forever (bool, optional):
                Whether to wait forever without timeout. Defaults to False.

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
                        self.logger.debug(success_message)
                    return self.parse_request_response(response)
                elif (
                    response.status_code == 500
                    and "Cannot modify configuration" in response.text
                    and "while the Processor is running" in response.text
                ):
                    self.logger.warning("Another operation is already running. Waiting 5 seconds to retry...")
                    time.sleep(5)
                    retries += 1
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    self.logger.info("Session has expired - try to re-authenticate...")
                    self.authenticate()
                    retries += 1
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    response_text = "HTML content (see debug log)" if content_type == "text/html" else response.text

                    if show_error:
                        self.logger.error(
                            "%s; status -> %s; error -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )
                    else:
                        self.logger.warning(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
                            response_text,
                        )

                    if content_type == "text/html":
                        self.logger.debug(
                            "%s; status -> %s; warning -> %s",
                            failure_message,
                            response.status_code,
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

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> list | None:
        """Convert the request response (JSon) to a Python list in a safe way that also handles exceptions.

        It first tries to load the response.text
        via json.loads() that produces a dict output. Only if response.text is
        not set or is empty it just converts the response_object to a dict using
        the vars() built-in method.

        Args:
            response_object (requests.Response):
                This is reponse object delivered by the request call.
            additional_error_message (str, optional):
                Use a more specific error message in case of an error.
            show_error (bool, optional):
                If True, write an error to the log file.
                If False, write a warning to the log file.

        Returns:
            list | None:
                The response information or None in case of an error.

        """

        if not response_object:
            return None

        try:
            list_object = json.loads(response_object.text) if response_object.text else vars(response_object)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSON. {}; error -> {}".format(
                    additional_error_message,
                    exception,
                )
            else:
                message = "Cannot decode response as JSON; error -> {}".format(
                    exception,
                )
            if show_error:
                self.logger.error(message)
            else:
                self.logger.warning(message)
            return None
        else:
            return list_object

    # end method definition

    def authenticate(self) -> str | None:
        """Authenticate at Aviator Search via OAuth.

        Returns:
            str | None:
                The access token or None in case of an error.

        """

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
            "client_secret": self.config()["clientSecret"],
            "grant_type": "password",
            "username": self.config()["username"],
            "password": self.config()["password"],
            "scope": "otds:roles",
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=request_payload,
            timeout=None,
            failure_message="Failed to authenticate to OTDS with username -> '{}' and client_id -> {}".format(
                self.config()["username"],
                self.config()["clientId"],
            ),
        )

        if response is not None:
            self._accesstoken = response.get("access_token", None)
        else:
            self._accesstoken = None

        return self._accesstoken

    # end method definition

    def create_extended_ecm_repo(
        self,
        name: str,
        username: str,
        password: str,
        otcs_url: str,
        otcs_api_url: str,
        node_id: int,
    ) -> dict | None:
        """Create a new Extended ECM repository to crawl with Aviator Search.

        Args:
            name (str):
                The name of the repository.
            username (str):
                Username to use for crawling.
            password (str):
                Password of the user used for crawling.
            otcs_url (str):
                Base URL of Content Server e.g. https://otcs.base-url.tld/cs/cs
            otcs_api_url (str):
                The REST API URL of Content Server.
            node_id (int):
                Root Node ID for crawling

        Returns:
            dict | None:
                Parsed response object from the API or None in case of an error

        """

        payload = {
            "authType": "Basic",
            "params": [
                {
                    "id": "OpenTextApiUrl",
                    "label": "Service URL",
                    "ctlType": "text",
                    "description": "OpenText Content Management API URL",
                    "required": True,
                    "defaultValue": "localhost",
                    "visible": True,
                    "editable": False,
                    "value": otcs_api_url,
                },
                {
                    "id": "Username",
                    "label": "Username",
                    "ctlType": "text",
                    "description": "OpenText Content Management Username",
                    "required": True,
                    "defaultValue": "",
                    "visible": True,
                    "editable": True,
                    "value": username,
                },
                {
                    "id": "Password",
                    "label": "Password",
                    "ctlType": "password",
                    "description": "OpenText Content Management password",
                    "required": True,
                    "defaultValue": "",
                    "visible": True,
                    "editable": True,
                    "value": password,
                },
                {
                    "id": "sourceLink",
                    "label": "Source Link",
                    "ctlType": "text",
                    "description": "Example: <OpenText Content Management API URL>/app/nodes/${NODE}/metadata",
                    "required": False,
                    "defaultValue": otcs_url + "/app/nodes/${NODE}/metadata",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "RootNodeIds",
                    "label": "Root Node ID's",
                    "ctlType": "text",
                    "description": "List of nodes to be crawled(comma seperated)",
                    "required": True,
                    "defaultValue": "",
                    "visible": True,
                    "editable": False,
                    "value": "2000",
                },
                {
                    "id": "proxy",
                    "label": "Proxy Service",
                    "ctlType": "boolean",
                    "description": "",
                    "required": False,
                    "defaultValue": "false",
                    "value": "false",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "proxyScheme",
                    "label": "Proxy Scheme",
                    "ctlType": "select",
                    "description": "",
                    "required": False,
                    "defaultValue": "HTTP",
                    "value": "HTTP",
                    "visible": True,
                    "acceptedValues": ["HTTP", "HTTPS", "SOCKS5"],
                    "editable": True,
                },
                {
                    "id": "proxyHost",
                    "label": "Proxy Host",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "proxyPort",
                    "label": "Proxy Port",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "ProxyConfigService",
                    "label": "Proxy Config Service",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": False,
                    "editable": True,
                },
            ],
            "config": {
                "type": "nifi",
                "id": "xECM",
                "crawlConfig": {
                    "name": "GetOpenText",
                    "type": "idol.nifi.connector.GetOpenText",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-opentext",
                    "version": "25.1.0-nifi1",
                },
                "viewConfig": {
                    "name": "ViewOpenText",
                    "type": "idol.nifi.connector.ViewOpenText",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-opentext",
                    "version": "25.1.0-nifi1",
                },
                "omniConfig": {
                    "name": "GetOpenTextGroups",
                    "type": "idol.nifi.connector.GetOpenTextGroups",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-opentext",
                    "version": "25.1.0-nifi1",
                    "repoName": "ECM",
                },
                "crawlProps": {
                    "Password": "${Password}",
                    "Username": "${UserName}",
                    "META:SOURCE": "OPENTEXT",
                    "RootNodeIds": "${RootNodeIds}",
                    "MappedSecurity": "true",
                    "OpenTextApiUrl": "${OpenTextApiUrl}",
                    "ProxyConfigService": "${ProxyConfigService}",
                },
                "viewProps": {
                    "Password": "${Password}",
                    "Username": "${UserName}",
                    "OpenTextApiUrl": "${OpenTextApiUrl}",
                    "ProxyConfigService": "${ProxyConfigService}",
                },
                "omniProps": {
                    "Password": "${Password}",
                    "Username": "${UserName}",
                    "OpenTextApiUrl": "${OpenTextApiUrl}",
                    "ProxyConfigService": "${ProxyConfigService}",
                    "OpenTextApiPageSize": "10",
                },
                "metadataFields": ["NODE"],
            },
            "name": name,
            "id": "xECM",
            "sourceId": "xECM",
        }

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        response = self.do_request(
            url=request_url,
            method="POST",
            json_data=payload,
            headers=request_header,
            timeout=None,
            failure_message="Failed to create repository -> '{}' ({})".format(
                name,
                node_id,
            ),
            show_error=False,
        )

        if response is None:
            self.logger.error("Failed to create repository -> %s (%s)!", name, node_id)

        return response

    # end method definition

    def create_msteams_repo(
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
    ) -> dict | None:
        """Create a new Microsoft Teams repository to crawl with Aviator Search.

        Args:
            name (str):
                The name of the repository.
            client_id (str):
                The M365 client ID.
            tenant_id (str):
                The M365 tenant ID.
            certificate_file (str):
                The path to the certificate file.
            certificate_password (str):
                The password for the certificate.
            index_attachments (bool, optional):
                Whether or not to index / crawl attachments.
            index_call_recordings (bool, optional):
                Whether or not to index / crawl meeting recordings.
            index_message_replies (bool, optional):
                Whether or not to index / crawl message replies.
            index_user_chats (bool, optional):
                Whether or not to index / crawl user chats.

        Returns:
            dict | None:
                Parsed response object from the API or None in case of an error

        """

        certificate_file_content_base64 = self.get_certificate_file_content_base64(
            certificate_file,
        )

        payload = {
            "authType": "OAUTH",
            "params": [
                {
                    "id": "OAuth2SiteName",
                    "label": "OAuth2 Site Name",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "AVTS",
                    "value": "AVTS",
                    "visible": False,
                    "editable": True,
                },
                {
                    "id": "OAuth2SitesFile",
                    "label": "OAuth2 Sites File",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": False,
                    "editable": True,
                },
                {
                    "id": "sourceLink",
                    "label": "Source Link",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "",
                    "visible": True,
                    "editable": True,
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
                    "editable": True,
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
                    "editable": False,
                },
                {
                    "id": "IndexAttachments",
                    "label": "Index Attachments",
                    "ctlType": "boolean",
                    "description": "Specifies whether to index attachments",
                    "required": False,
                    "defaultValue": "true",
                    "value": "true",
                    "visible": str(index_attachments).lower(),
                    "editable": True,
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
                    "editable": True,
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
                    "editable": True,
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
                    "editable": True,
                },
                {
                    "id": "certificateFile",
                    "label": "Certificate File",
                    "ctlType": "file",
                    "description": 'Please upload a valid "*.pfx" certificate file',
                    "required": True,
                    "defaultValue": "",
                    "value": "C:\\fakepath\\certificate 1 3 (1).pfx",
                    "visible": True,
                    "editable": True,
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
                    "editable": True,
                },
                {
                    "id": "proxy",
                    "label": "Proxy Service",
                    "ctlType": "boolean",
                    "description": "",
                    "required": False,
                    "defaultValue": "false",
                    "value": "false",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "proxyScheme",
                    "label": "Proxy Scheme",
                    "ctlType": "select",
                    "description": "",
                    "required": False,
                    "defaultValue": "HTTP",
                    "value": "HTTP",
                    "visible": True,
                    "acceptedValues": [
                        "HTTP",
                        "HTTPS",
                        "SOCKS5",
                    ],
                    "editable": True,
                },
                {
                    "id": "proxyHost",
                    "label": "Proxy Host",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "proxyPort",
                    "label": "Proxy Port",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "ProxyConfigService",
                    "label": "Proxy Config Service",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": False,
                    "editable": True,
                },
            ],
            "config": {
                "type": "nifi",
                "id": "MSTeams",
                "crawlConfig": {
                    "name": "GetMicrosoftTeams",
                    "type": "idol.nifi.connector.GetMicrosoftTeams",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-officeteams",
                    "version": "25.1.0-nifi1",
                },
                "viewConfig": {
                    "name": "ViewMicrosoftTeams",
                    "type": "idol.nifi.connector.ViewMicrosoftTeams",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-officeteams",
                    "version": "25.1.0-nifi1",
                },
                "omniConfig": {
                    "name": "GetMicrosoftTeamsGroups",
                    "type": "idol.nifi.connector.GetMicrosoftTeamsGroups",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-officeteams",
                    "version": "25.1.0-nifi1",
                    "repoName": "OneDrive",
                },
                "crawlProps": {
                    "META:SOURCE": "Microsoft Teams",
                    "IndexUserChats": "${IndexUserChats}",
                    "MappedSecurity": "true",
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "IndexAttachments": "${IndexAttachments}",
                    "ProxyConfigService": "${ProxyConfigService}",
                    "IndexCallRecordings": "${IndexCallRecordings}",
                    "IndexMessageReplies": "${IndexMessageReplies}",
                    "ChatMessageGroupingSection": "chat",
                    "ChannelMessageGroupingSection": "channel",
                    "[chat]MessageGroupingInterval": "24 hour",
                    "[chat]MessageGroupingStrategy": "Interval",
                    "[channel]MessageGroupingInterval": "24 hour",
                    "[channel]MessageGroupingStrategy": "Interval",
                },
                "viewProps": {
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "ProxyConfigService": "${ProxyConfigService}",
                },
                "omniProps": {
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "ProxyConfigService": "${ProxyConfigService}",
                },
                "metadataFields": [],
            },
            "name": name,
            "id": "MSTeams",
            "sourceId": "MSTeams",
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
            show_error=False,
        )

        if response is None:
            self.logger.error("Failed to create repository -> '%s'", name)
            return None

        self.repo_admin_consent(response["id"])

        return response

    # end method definition

    def create_sharepoint_repo(
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
    ) -> dict | None:
        """Create a new Microsoft SharePoint repository to crawl with Aviator Search.

        Args:
            name (str):
                The name of the repository.
            client_id (str):
                The M365 client ID.
            tenant_id (str):
                The M365 tenant ID.
            certificate_file (str):
                TODO: _description_
            certificate_password (int):
                TODO: _description_
            sharepoint_url (str):
                The SharePoint URL.
            sharepoint_url_type (str):
                The SharePoint URL type.
            sharepoint_mysite_url (str):
                The SharePoint MySite URL.
            sharepoint_admin_url (str):
                The SharePoint administration URL.
            index_user_profiles (bool, optional):
                TODO: _description_. Defaults to True.
            oauth2_site_name (str, optional):
                TODO: _description_. Defaults to "AVTS".
            oauth2_sites_file (str, optional):
                TODO: _description_. Defaults to "".

        Returns:
            dict | None:
                Parsed response object from the API or None in case of an error

        """

        certificate_file_content_base64 = self.get_certificate_file_content_base64(
            certificate_file,
        )

        payload = {
            "authType": "OAUTH",
            "params": [
                {
                    "id": "OAuth2SiteName",
                    "label": "OAuth2 Site Name",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "AVTS",
                    "value": oauth2_site_name,
                    "visible": False,
                    "editable": True,
                },
                {
                    "id": "OAuth2SitesFile",
                    "label": "OAuth2 Sites File",
                    "ctlType": "text",
                    "required": False,
                    "defaultValue": "",
                    "value": oauth2_sites_file,
                    "visible": False,
                    "editable": True,
                },
                {
                    "id": "sourceLink",
                    "label": "Source Link",
                    "ctlType": "text",
                    "description": "Example: https://<sharepoint host>${FILEDIRREF}/Forms/AllItems.aspx?id=${FILEREF}&parent=${FILEDIRREF}",
                    "required": False,
                    "defaultValue": "",
                    "visible": True,
                    "editable": True,
                    "value": sharepoint_url + "${FILEDIRREF}/Forms/AllItems.aspx?id=${FILEREF}&parent=${FILEDIRREF}",
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
                    "editable": True,
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
                    "editable": True,
                },
                {
                    "id": "sharePointUrl",
                    "label": "SharePoint URL",
                    "ctlType": "text",
                    "description": 'The URL to start synchronizing from. Specify a URL that matches "SharePoint URL type"',
                    "required": True,
                    "defaultValue": "",
                    "value": sharepoint_mysite_url,
                    "visible": True,
                    "editable": False,
                },
                {
                    "id": "MappedWebApplicationPolicies",
                    "label": "Mapped Web Application Policies",
                    "ctlType": "boolean",
                    "required": False,
                    "defaultValue": "false",
                    "value": "false",
                    "visible": True,
                    "editable": False,
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
                    "editable": False,
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
                    "editable": False,
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
                    "editable": False,
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
                    "editable": False,
                },
                {
                    "id": "URLType",
                    "label": "SharePoint URL Type",
                    "ctlType": "select",
                    "description": 'The type of URL specified by "Sharepoint URL"',
                    "required": True,
                    "defaultValue": "",
                    "value": sharepoint_url_type,
                    "visible": True,
                    "acceptedValues": [
                        "WebApplication",
                        "SiteCollection",
                        "PersonalSiteCollection",
                        "TenantAdmin",
                    ],
                    "editable": False,
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
                    "editable": True,
                },
                {
                    "id": "certificateFile",
                    "label": "Certificate File",
                    "ctlType": "file",
                    "description": 'Please upload a valid "*.pfx" certificate file',
                    "required": True,
                    "defaultValue": "",
                    "value": "C:\\fakepath\\certificate 1 3 (1).pfx",
                    "visible": True,
                    "editable": True,
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
                    "editable": True,
                },
                {
                    "id": "proxy",
                    "label": "Proxy Service",
                    "ctlType": "boolean",
                    "description": "",
                    "required": False,
                    "defaultValue": "false",
                    "value": "false",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "proxyScheme",
                    "label": "Proxy Scheme",
                    "ctlType": "select",
                    "description": "",
                    "required": False,
                    "defaultValue": "HTTP",
                    "value": "HTTP",
                    "visible": True,
                    "acceptedValues": [
                        "HTTP",
                        "HTTPS",
                        "SOCKS5",
                    ],
                    "editable": True,
                },
                {
                    "id": "proxyHost",
                    "label": "Proxy Host",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "proxyPort",
                    "label": "Proxy Port",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": True,
                    "editable": True,
                },
                {
                    "id": "ProxyConfigService",
                    "label": "Proxy Config Service",
                    "ctlType": "text",
                    "description": "",
                    "required": False,
                    "defaultValue": "",
                    "value": "",
                    "visible": False,
                    "editable": True,
                },
            ],
            "config": {
                "type": "nifi",
                "id": "SharePoint",
                "crawlConfig": {
                    "name": "GetSharePointOData",
                    "type": "idol.nifi.connector.GetSharePointOData",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-sharepointodata",
                    "version": "25.1.0-nifi1",
                },
                "viewConfig": {
                    "name": "ViewSharePointOData",
                    "type": "idol.nifi.connector.ViewSharePointOData",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-sharepointodata",
                    "version": "25.1.0-nifi1",
                },
                "omniConfig": {
                    "name": "GetSharePointGroupsOData",
                    "type": "idol.nifi.connector.GetSharePointGroupsOData",
                    "group": "idol.nifi.connector",
                    "artifact": "idol-nifi-connector-sharepointodata",
                    "version": "25.1.0-nifi1",
                    "repoName": "SharePoint",
                },
                "crawlProps": {
                    "META:SOURCE": "SharePoint Online",
                    "SharepointUrl": "${sharePointUrl}",
                    "MappedSecurity": "true",
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "SharepointOnline": "${sharePointOnline}",
                    "IndexUserProfiles": "${IndexUserProfiles}",
                    "SharepointUrlType": "${URLType}",
                    "ProxyConfigService": "${ProxyConfigService}",
                    "SharepointAdminUrl": "${sharePointAdminUrl}",
                    "SharepointMySiteUrl": "${sharePointMySiteUrl}",
                    "RetrieveUserDetailsAs": "Title",
                    "MappedWebApplicationPolicies": "${MappedWebApplicationPolicies}",
                    "TenantAdminSitesIncludeTypes": "${TenantAdminSitesIncludeTypes}",
                },
                "viewProps": {
                    "SharepointUrl": "${sharePointUrl}",
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "SharepointOnline": "${sharePointOnline}",
                    "SharepointUrlType": "${URLType}",
                    "ProxyConfigService": "${ProxyConfigService}",
                    "SharepointAdminUrl": "${sharePointAdminUrl}",
                    "SharepointMySiteUrl": "${sharePointMySiteUrl}",
                    "MappedWebApplicationPolicies": "${MappedWebApplicationPolicies}",
                },
                "omniProps": {
                    "SharepointUrl": "${sharePointUrl}",
                    "Oauth2SiteName": "${OAuth2SiteName}",
                    "Oauth2SitesFile": "${OAuth2SitesFile}",
                    "SharepointOnline": "true",
                    "SharepointUrlType": "${URLType}",
                    "ProxyConfigService": "${ProxyConfigService}",
                    "SharepointAdminUrl": "${sharePointAdminUrl}",
                    "SharepointMySiteUrl": "${sharePointMySiteUrl}",
                    "MappedWebApplicationPolicies": "false",
                    "TenantAdminSitesIncludeTypes": "${TenantAdminSitesIncludeTypes}",
                },
                "metadataFields": [
                    "FILEREF",
                    "FILEDIRREF",
                ],
            },
            "name": name,
            "id": "SharePoint",
            "sourceId": "SharePoint",
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
            show_error=False,
        )

        if response is None:
            self.logger.error("Failed to create repository -> '%s'!", name)
            return None

        self.repo_admin_consent(response["id"])

        return response

    # end method definition

    def repo_admin_consent(self, repo_id: str) -> dict | None:
        """Send admin consent information for a repository.

        Args:
            repo_id (str):
                The ID of the repository.

        Returns:
            dict | None:
                Parsed response object from the API or None in case of an error

        """

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        request_url = self.config()["repoUrl"] + "/" + repo_id + "/authorize?admin_consent=true"

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to set admin_consent for repository -> '{}'".format(
                repo_id,
            ),
        )

    # end method definition

    def start_crawling(self, repo_name: str) -> list | None:
        """Start crawling of a repository.

        Args:
            repo_name (str):
                The name of the repository.

        Returns:
            list | None:
                Parsed response object from the API or None in case of an error

        """

        self.logger.info("Start crawling repository -> '%s'...", repo_name)

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
            failure_message="Failed to start crawling repository -> '{}'!".format(
                repo_name,
            ),
        )

    # end method definition

    def stop_crawling(self, repo_name: str) -> dict | None:
        """Stop the crawling of a repository.

        Args:
            repo_name (str):
                The name of the repository.

        Returns:
            dict | None:
                Parsed response object from the API or None in case of an error

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
            failure_message="Failed to stop crawling repository -> '{}'!".format(
                repo_name,
            ),
        )

    # end method definition

    def get_repo_list(self) -> list | None:
        """Get a list of all repositories.

        Returns:
            list | None:
                Parsed response object from the API listing all repositories or None in case of an error.

        """

        request_header = self.request_header()
        request_url = self.config()["repoUrl"]

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get list of repositories to crawl",
        )

    # end method definition

    def get_repo_by_name(self, name: str) -> dict | None:
        """Get a repository by name.

        Args:
            name (str):
                The name of the repository.

        Returns:
            dict | None:
                ID of a repostiory by name or None in case of an error

        """

        repo_list = self.get_repo_list()

        if repo_list is None:
            return None

        return next(
            (repo for repo in repo_list if repo.get("repoName", "") == name),
            None,
        )

    # end method definition

    def get_certificate_file_content_base64(self, filepath: str) -> str | None:
        """Return the certificate as a base64 string.

        In Kubernetes deploymnets the certificate is already mounted base64 encoded.

        Args:
            filepath (str):
                The path to the certificate file.

        Returns:
            str | None:
                Base64 encoded certificate file content.

        """

        if not os.path.isfile(filepath):
            return None

        file_ext = os.path.splitext(filepath)[1].lower()

        if self.running_in_kubernetes_pod() and file_ext == ".pfx":
            # Return file directly as already base64 encoded
            self.logger.warning(
                "Detected a binary pfx file in Kubernetes environment, expecting it to be already base64 encoded",
            )
            with open(filepath, encoding="UTF-8") as file:
                return file.read().strip()

        else:
            # Return file as base64 encoded
            with open(filepath, "rb") as file:
                # Read the content of the file
                file_content = file.read()
                # Convert the bytes to a base64 string
                return base64.b64encode(file_content).decode("utf-8")

    # end method definition

    def running_in_kubernetes_pod(self) -> bool:
        """Check if the application is running inside a Kubernetes pod.

        This function determines whether the process is running in a Kubernetes
        environment by checking for the presence of the `KUBERNETES_SERVICE_HOST`
        and `KUBERNETES_SERVICE_PORT` environment variables.

        Returns:
            bool:
                True if running inside a Kubernetes pod, False otherwise.

        """

        return bool(os.getenv("KUBERNETES_SERVICE_HOST") and os.getenv("KUBERNETES_SERVICE_PORT"))

    # end method definition

    def set_questions(self, questions: list) -> list | None:
        """Get a list of all repositories.

        Args:
            questions (list):
                List of proposed questions.

        Returns:
            list | None:
                Parsed response object from the API listing all repositories or None in case of an error.

        """

        request_header = self.request_header()
        request_url = self.config()["questionsUrl"]

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=json.dumps(questions),
            timeout=None,
            failure_message="Failed to set list of questions to ask",
        )

    # end method definition

"""OTCS Module to implement functions to read / write Content Server objects.

This includes Users, Groups, Nodes, Workspaces, Business Administration,
System Administration, ...

The documentation for the used REST APIs can be found here:
    - [https://developer.opentext.com](https://developer.opentext.com/ce/products/extended-ecm)
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import asyncio
import json
import logging
import mimetypes
import os
import platform
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from datetime import datetime, timezone
from functools import cache
from http import HTTPStatus
from importlib.metadata import version

import requests
import websockets

from pyxecm.helper import XML, Data

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otcs"

PYTHON_VERSION = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
OS_INFO = f"{platform.system()} {platform.release()}"
ARCH_INFO = platform.machine()
REQUESTS_VERSION = requests.__version__

USER_AGENT = (
    f"{APP_NAME}/{APP_VERSION} ({MODULE_NAME}/{APP_VERSION}; "
    f"Python/{PYTHON_VERSION}; {OS_INFO}; {ARCH_INFO}; Requests/{REQUESTS_VERSION})"
)

REQUEST_JSON_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/json",
}

REQUEST_FORM_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_DOWNLOAD_HEADERS = {
    "User-Agent": USER_AGENT,
    "accept": "application/octet-stream",
    "Content-Type": "application/json",
}

REQUEST_TIMEOUT = 60
REQUEST_RETRY_DELAY = 20
REQUEST_MAX_RETRIES = 2

default_logger = logging.getLogger(MODULE_NAME)

try:
    import magic

    magic_installed = True
except ModuleNotFoundError:
    default_logger.debug(
        "Module magic is not installed. Customizer will not use advanced mime type detection for uploads.",
    )
    magic_installed = False


class OTCS:
    """Used to automate stettings in OpenText Extended ECM."""

    logger: logging.Logger = default_logger

    VOLUME_TYPE_BOT_CONFIGURATION = 898
    VOLUME_TYPE_BUSINESS_WORKSPACES = 862
    VOLUME_TYPE_CATEGORIES_VOLUME = 133
    VOLUME_TYPE_CLASSIFICATION_VOLUME = 198
    VOLUME_TYPE_CONTENT_SERVER_DOCUMENT_TEMPLATES = 20541
    VOLUME_TYPE_ENTERPRISE_WORKSPACE = 141
    VOLUME_TYPE_EXTENDED_ECM = 882
    VOLUME_TYPE_FACETS_VOLUME = 901
    VOLUME_TYPE_O365_OFFICE_ONLINE_VOLUME = 1296
    VOLUME_TYPE_PERSONAL_WORKSPACE = 142
    VOLUME_TYPE_PERSPECTIVES = 908
    VOLUME_TYPE_PERSPECTIVE_ASSETS = 954
    VOLUME_TYPE_PHYSICAL_OBJECTS_WORKSPACE = 413
    VOLUME_TYPE_RECORDS_MANAGEMENT = 550
    VOLUME_TYPE_SUPPORT_ASSET_VOLUME = 1309
    VOLUME_TYPE_TRANSPORT_WAREHOUSE = 525
    VOLUME_TYPE_TRANSPORT_WAREHOUSE_WORKBENCH = 528
    VOLUME_TYPE_TRANSPORT_WAREHOUSE_PACKAGE = 531

    ITEM_TYPE_BUSINESS_WORKSPACE = 848
    ITEM_TYPE_CATEGORY = 131
    ITEM_TYPE_CHANNEL = 207
    ITEM_TYPE_CLASSIFICATION_TREE = 196
    ITEM_TYPE_CLASSIFICATION = 199
    ITEM_TYPE_COLLECTION = 298
    ITEM_TYPE_COMPOUND_DOCUMENT = 136
    ITEM_TYPE_DOCUMENT = 144
    ITEM_TYPE_DISCUSSION = 215
    ITEM_TYPE_EMAIL_FOLDER = 751
    ITEM_TYPE_FACETS_VOLUME = 901
    ITEM_TYPE_FOLDER = 0
    ITEM_TYPE_FORUM = 123469
    ITEM_TYPE_GENERATION = 2
    ITEM_TYPE_HOLD = 833
    ITEM_TYPE_NEWS = 208
    ITEM_TYPE_PROJECT = 202
    ITEM_TYPE_SHORTCUT = 1
    ITEM_TYPE_POLL = 218
    ITEM_TYPE_RELATED_WORKSPACE = 854
    ITEM_TYPE_REPLY = 134
    ITEM_TYPE_SCHEDULED_BOT = 872
    ITEM_TYPE_SEARCH_QUERY = 258
    ITEM_TYPE_TASK = 206
    ITEM_TYPE_TASK_GROUP = 205
    ITEM_TYPE_TASK_LIST = 204
    ITEM_TYPE_TASK_MILESTONE = 212
    ITEM_TYPE_TOPIC = 130
    ITEM_TYPE_TRANSPORT_PACKAGE = 531
    ITEM_TYPE_URL = 140
    ITEM_TYPE_VIRTUAL_FOLDER = 899
    ITEM_TYPE_WEBREPORT = 30303
    ITEM_TYPE_WIKI = 5573
    ITEM_TYPE_WIKI_PAGE = 5574
    ITEM_TYPE_WORKBENCH = 528
    ITEM_TYPE_WORKFLOW_MAP = 128
    ITEM_TYPE_WORKFLOW_STATUS = 190

    _config: dict
    _otcs_ticket = None
    _otds_ticket = None
    _data: Data = None
    _thread_number = 3
    _download_dir = ""
    _use_numeric_category_identifier: bool = True

    # Handle concurrent HTTP requests that may run into 401 errors and
    # re-authentication at the same time:
    _authentication_lock = threading.Lock()
    _authentication_condition = threading.Condition(_authentication_lock)
    _authentication_semaphore = threading.Semaphore(
        1,
    )  # only 1 thread should handle the re-authentication
    _session_lock = threading.Lock()

    @classmethod
    def date_is_newer(cls, date_old: str, date_new: str) -> bool:
        """Compare two dates, typically create or modification dates.

        Args:
            date_old (str):
                The date that is considered older.
            date_new (str):
                The date that is considered newer.

        Returns:
            bool: True if date_new is indeed newer as date_old, False otherwise

        """

        if not date_old or not date_new:
            return True

        # Define the date formats
        format1 = "%Y-%m-%dT%H:%M:%SZ"  # Format: "YYYY-MM-DDTHH:MM:SSZ"
        format2 = "%Y-%m-%d %H:%M:%S"  # Format: "YYY-MM-DD HH:MM:SS"
        format3 = "%Y-%m-%dT%H:%M:%S"  # Format: "YYY-MM-DDTHH:MM:SS"
        format4 = "%Y-%m-%d"  # Format: "YYY-MM-DD"

        # Parse the dates
        try:
            if "T" in date_old and "Z" in date_old:
                old_date = datetime.strptime(date_old, format1).replace(
                    tzinfo=timezone.utc,
                )
            elif " " in date_old:
                old_date = datetime.strptime(date_old, format2).replace(
                    tzinfo=timezone.utc,
                )
            elif "T" in date_old:
                old_date = datetime.strptime(date_old, format3).replace(
                    tzinfo=timezone.utc,
                )
            else:
                old_date = datetime.strptime(date_old, format4).replace(
                    tzinfo=timezone.utc,
                )
        except ValueError:
            return True

        try:
            if "T" in date_new and "Z" in date_new:
                new_date = datetime.strptime(date_new, format1).replace(
                    tzinfo=timezone.utc,
                )
            elif " " in date_new:
                new_date = datetime.strptime(date_new, format2).replace(
                    tzinfo=timezone.utc,
                )
            elif "T" in date_new:
                new_date = datetime.strptime(date_new, format3).replace(
                    tzinfo=timezone.utc,
                )
            else:
                new_date = datetime.strptime(date_new, format4).replace(
                    tzinfo=timezone.utc,
                )
        except ValueError:
            return True

        # Compare the dates
        return new_date > old_date

    # end method definition

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        public_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        user_partition: str = "Content Server Members",
        resource_name: str = "cs",
        default_license: str = "X3",
        otds_ticket: str | None = None,
        base_path: str = "/cs/cs",
        thread_number: int = 3,
        download_dir: str | None = None,
        feme_uri: str | None = None,
        use_numeric_category_identifier: bool = True,
        logger: logging.Logger = default_logger,
    ) -> None:
        """Initialize the OTCS object.

        Args:
            protocol (str):
                Either http or https.
            hostname (str):
                The hostname of Extended ECM server to communicate with.
            port (int):
                The port number used to talk to the Extended ECM server.
            public_url (str, optional):
                The public (external) URL of OTCS.
            username (str, optional):
                The admin user name of OTCS. Optional if otds_ticket is provided.
            password (str, optional):
                The admin password of OTCS. Optional if otds_ticket is provided.
            user_partition (str, optional):
                The name of the OTDS partition for OTCS users.
                Default is "Content Server Members".
            resource_name (str, optional):
                The name of the OTDS resource for OTCS. Dault is "cs".
            default_license (str, optional):
                The name of the default user license. Default is "X3".
            otds_ticket (str, optional):
                The authentication ticket of OTDS.
            base_path (str, optional):
                The base path segment of the Content Server URL.
                This typically is /cs/cs on a Linux deployment or /cs/cs.exe
                on a Windows deployment.
            thread_number (int, optional):
                The number of threads for parallel processing for data loads.
            download_dir (str | None, optional):
                The filesystem directory to download the OTCS documents to.
                If None, a default location is constructed automatically.
            feme_uri (str, optional):
                URI of the FEME tool (used with Content Aviator)
            use_numeric_category_identifier (bool, optional):
                Parameter for load_items. Determines if the category ID is used
                in the column name of the data frame (True) or a normalized
                category name (False).
            logger (logging.Logger, optional):
                The logging object to use for all log messages. Defaults to default_logger.

        """

        if logger != default_logger:
            self.logger = logger.getChild("otcs")

            for logfilter in logger.filters:
                self.logger.addFilter(logfilter)

        if not download_dir:
            download_dir = os.path.join(tempfile.gettempdir(), "contentserver")

        # Initialize otcs_config as an empty dictionary
        otcs_config = {}

        if hostname:
            otcs_config["hostname"] = hostname
        else:
            otcs_config["hostname"] = "otcs-admin-0"

        if protocol:
            otcs_config["protocol"] = protocol
        else:
            otcs_config["protocol"] = "http"

        if port:
            otcs_config["port"] = port
        else:
            otcs_config["port"] = 8080

        otcs_config["publicUrl"] = public_url

        if username:
            otcs_config["username"] = username
        else:
            otcs_config["username"] = "admin"

        if password:
            otcs_config["password"] = password
        else:
            otcs_config["password"] = ""

        if user_partition:
            otcs_config["partition"] = user_partition
        else:
            otcs_config["partition"] = ""

        if resource_name:
            otcs_config["resource"] = resource_name
        else:
            otcs_config["resource"] = ""

        if default_license:
            otcs_config["license"] = default_license
        else:
            otcs_config["license"] = ""

        otcs_config["feme_uri"] = feme_uri

        otcs_base_url = protocol + "://" + otcs_config["hostname"]
        if str(port) not in ["80", "443"]:
            otcs_base_url += ":{}".format(port)
        otcs_config["baseUrl"] = otcs_base_url
        otcs_support_url = otcs_base_url + "/cssupport"
        otcs_config["supportUrl"] = otcs_support_url

        if public_url is None:
            public_url = otcs_base_url

        otcs_public_support_url = public_url + "/cssupport"
        otcs_config["supportPublicUrl"] = otcs_public_support_url

        otcs_config["configuredUrl"] = otcs_support_url + "/csconfigured"

        otcs_url = otcs_base_url + base_path
        otcs_config["csUrl"] = otcs_url
        otcs_public_url = public_url + base_path
        otcs_config["csPublicUrl"] = otcs_public_url

        otcs_rest_url = otcs_url + "/api"
        otcs_config["restUrl"] = otcs_rest_url

        otcs_config["isReady"] = otcs_rest_url + "/v1/ping"
        otcs_config["authenticationUrl"] = otcs_rest_url + "/v1/auth"
        otcs_config["serverInfoUrl"] = otcs_rest_url + "/v1/serverinfo"
        otcs_config["membersUrl"] = otcs_rest_url + "/v1/members"
        otcs_config["membersUrlv2"] = otcs_rest_url + "/v2/members"
        otcs_config["nodesUrl"] = otcs_rest_url + "/v1/nodes"
        otcs_config["nodesUrlv2"] = otcs_rest_url + "/v2/nodes"
        otcs_config["privileges"] = otcs_rest_url + "/v2/server/privileges"
        otcs_config["doctemplatesUrl"] = otcs_rest_url + "/v2/doctemplates"
        otcs_config["nicknameUrl"] = otcs_rest_url + "/v2/nicknames"
        otcs_config["importSettingsUrl"] = otcs_rest_url + "/v2/import/settings/admin"
        otcs_config["searchUrl"] = otcs_rest_url + "/v2/search"
        otcs_config["volumeUrl"] = otcs_rest_url + "/v2/volumes"
        otcs_config["externalSystemUrl"] = otcs_rest_url + "/v2/externalsystems"
        otcs_config["businessObjectsUrl"] = otcs_rest_url + "/v2/businessobjects"
        otcs_config["businessObjectTypesUrl"] = otcs_rest_url + "/v2/businessobjecttypes"
        otcs_config["businessObjectsSearchUrl"] = otcs_rest_url + "/v2/forms/businessobjects/search"
        otcs_config["businessWorkspaceTypesUrl"] = otcs_rest_url + "/v2/businessworkspacetypes"
        otcs_config["businessworkspacecreateform"] = otcs_rest_url + "/v2/forms/businessworkspaces/create"
        otcs_config["businessWorkspacesUrl"] = otcs_rest_url + "/v2/businessworkspaces"
        otcs_config["uniqueNamesUrl"] = otcs_rest_url + "/v2/uniquenames"
        otcs_config["favoritesUrl"] = otcs_rest_url + "/v2/members/favorites"
        otcs_config["webReportsUrl"] = otcs_rest_url + "/v1/webreports"
        otcs_config["csApplicationsUrl"] = otcs_rest_url + "/v2/csapplications"
        otcs_config["xEngProjectTemplateUrl"] = otcs_rest_url + "/v2/xengcrt/projecttemplate"
        otcs_config["rsisUrl"] = otcs_rest_url + "/v2/rsis"
        otcs_config["rsiSchedulesUrl"] = otcs_rest_url + "/v2/rsischedules"
        otcs_config["recordsManagementUrl"] = otcs_rest_url + "/v1/recordsmanagement"
        otcs_config["recordsManagementUrlv2"] = otcs_rest_url + "/v2/recordsmanagement"
        otcs_config["userSecurityUrl"] = otcs_rest_url + "/v2/members/usersecurity"
        otcs_config["physicalObjectsUrl"] = otcs_rest_url + "/v1/physicalobjects"
        otcs_config["securityClearancesUrl"] = otcs_rest_url + "/v1/securityclearances"
        otcs_config["holdsUrl"] = otcs_rest_url + "/v1/holds"
        otcs_config["holdsUrlv2"] = otcs_rest_url + "/v2/holds"
        otcs_config["validationUrl"] = otcs_rest_url + "/v1/validation/nodes/names"
        otcs_config["aiUrl"] = otcs_rest_url + "/v2/ai/nodes"
        otcs_config["recycleBinUrl"] = otcs_rest_url + "/v2/volumes/recyclebin"
        otcs_config["processUrl"] = otcs_rest_url + "/v2/processes"
        otcs_config["workflowUrl"] = otcs_rest_url + "/v2/workflows"
        otcs_config["docWorkflowUrl"] = otcs_rest_url + "/v2/docworkflows"
        otcs_config["draftProcessUrl"] = otcs_rest_url + "/v2/draftprocesses"
        otcs_config["categoryFormUrl"] = otcs_rest_url + "/v1/forms/nodes/categories"
        otcs_config["nodesFormUrl"] = otcs_rest_url + "/v1/forms/nodes"
        otcs_config["draftProcessFormUrl"] = otcs_rest_url + "/v1/forms/draftprocesses"
        otcs_config["processTaskUrl"] = otcs_rest_url + "/v1/forms/processes/tasks/update"

        self._config = otcs_config
        self._otds_ticket = otds_ticket
        self._data = Data(logger=self.logger)
        self._thread_number = thread_number
        self._download_dir = download_dir
        self._semaphore = threading.BoundedSemaphore(value=thread_number)
        self._last_session_renewal = 0
        self._use_numeric_category_identifier = use_numeric_category_identifier

    # end method definition

    def config(self) -> dict:
        """Return the configuration dictionary.

        Returns:
            dict: The configuration dictionary with all settings.

        """
        return self._config

    # end method definition

    def cookie(self) -> dict | None:
        """Return the login cookie of Content Server.

        This is set by the authenticate() method

        Returns:
            dict | None:
                The OTCS cookie or None if no authentication has happened yet
                or the ticket got invalidated.

        """

        if self._otcs_ticket:
            return {"otcsticket": self._otcs_ticket, "LLCookie": self._otcs_ticket}

        return None

    # end method definition

    def otcs_ticket(self) -> str | None:
        """Return the OTCS ticket.

        Returns:
            str | None:
                The OTCS ticket (which may be None).

        """

        return self._otcs_ticket

    # end method definition

    def set_otcs_ticket(self, ticket: str) -> None:
        """Set the OTCS ticket.

        Args:
            ticket (str):
                The new OTCS ticket.

        """

        self._otcs_ticket = ticket

    # end method definition

    def set_otds_ticket(self, ticket: str) -> None:
        """Set the OTDS ticket.

        Args:
            ticket (str):
                The new OTDS ticket.

        """

        self._otds_ticket = ticket

    # end method definition

    def credentials(self) -> dict:
        """Get credentials (username + password).

        Returns:
            dict:
                A dictionary with username and password.

        """

        return {
            "username": self.config()["username"],
            "password": self.config()["password"],
        }

    # end method definition

    def set_credentials(self, username: str = "admin", password: str = "") -> None:
        """Set the credentials for Extended ECM based on username and password.

        Args:
            username (str, optional):
                Username. Defaults to "admin".
            password (str, optional):
                Password of the user. Defaults to "".

        """

        self.config()["username"] = username
        self.config()["password"] = password

    # end method definition

    def hostname(self) -> str:
        """Return the hostname of Content Server (e.g. "otcs").

        Returns:
            str:
                The hostname of Content Server.

        """

        return self.config()["hostname"]

    # end method definition

    def set_hostname(self, hostname: str) -> None:
        """Set the hostname of Content Server.

        Args:
            hostname (str):
                The new hostname.

        """

        self.config()["hostname"] = hostname

    # end method definition

    def base_url(self) -> str:
        """Return the base URL of Content Server.

        Returns:
            str:
                The base URL of Content Server.

        """

        return self.config()["baseUrl"]

    # end method definition

    def cs_url(self) -> str:
        """Return the Content Server URL.

        Returns:
            str:
                The Content Server URL.

        """

        return self.config()["csUrl"]

    # end method definition

    def cs_public_url(self) -> str:
        """Return the public (external) Content Server URL (incl. base_path /cs/cs).

        Returns:
            str:
                The public URL of Content Server.

        """

        return self.config()["csPublicUrl"]

    # end method definition

    def cs_support_url(self) -> str:
        """Return the Content Server Support URL.

        Returns:
            str:
                The Content Server Support URL.

        """

        return self.config()["supportUrl"]

    # end method definition

    def cs_support_public_url(self) -> str:
        """Return the Content Server Public Support URL.

        Returns:
            str:
                The Content Server Public Support URL.

        """

        return self.config()["supportPublicUrl"]

    # end method definition

    def rest_url(self) -> str:
        """Return the REST URL of Content Server.

        Returns:
            str:
                The Content Server REST URL.

        """

        return self.config()["restUrl"]

    # end method definition

    def get_data(self) -> Data:
        """Get the Data object that holds all loaded Content Server items (see method load_items()).

        Returns:
            Data:
                The data object with all processed Content Server items.

        """

        return self._data

    # end method definition

    def request_form_header(self) -> dict:
        """Deliver the request header used for the CRUD REST API calls.

        Consists of Cookie + Form Headers (see global variable).

        Args:
            None.

        Returns:
            dict:
                The request header values.

        """

        request_header = {}
        request_header.update(REQUEST_FORM_HEADERS)

        return request_header

    # end method definition

    def request_json_header(self) -> dict:
        """Deliver the request header for REST calls that require content type application/json.

        Consists of Cookie + Json Headers (see global variable).

        Args:
            None.

        Returns:
            dict:
                The request header values for content type JSON.

        """

        request_header = {}
        request_header.update(REQUEST_JSON_HEADERS)

        return request_header

    # end method definition

    def request_download_header(self) -> dict:
        """Deliver the request header used for the CRUD REST API calls.

        Consists Form Headers (see global variable).

        Args:
            None.

        Returns:
            dict:
                Request header values.

        """

        request_header = {}
        request_header.update(REQUEST_DOWNLOAD_HEADERS)

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
        show_warning: bool = False,
        warning_message: str = "",
        failure_message: str = "",
        success_message: str = "",
        max_retries: int = REQUEST_MAX_RETRIES,
        retry_forever: bool = False,
        parse_request_response: bool = True,
        stream: bool = False,
    ) -> dict | None:
        """Call an OTCS REST API in a safe way.

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
            timeout (int | None, optional):
                Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional):
                Whether or not an error should be logged in case of a failed REST call.
                If False, then only a warning is logged. Defaults to True.
            show_warning (bool, optional):
                Whether or not an warning should be logged in case of a
                failed REST call.
                If False, then only a warning is logged. Defaults to True.
            warning_message (str, optional):
                Specific warning message. Defaults to "".
                If not given, the error_message will be used.
            failure_message (str, optional):
                Specific error message. Defaults to "".
            success_message (str, optional):
                Specific success message. Defaults to "".
            max_retries (int, optional):
                Number of retries on connection errors. Defaults to REQUEST_MAX_RETRIES.
            retry_forever (bool, optional):
                Whether to wait forever without timeout. Defaults to False.
            parse_request_response (bool, optional):
                Whether the response text should be interpreted as JSON and loaded
                into a dictionary. Defaults to True.
            stream (bool, optional):
                Enable stream for response content (e.g. for downloading large files).

        Returns:
            dict | None:
                Response of Content Server REST API or None in case of an error.

        """

        # In case of an expired session we reauthenticate and
        # try 1 more time. Session expiration should not happen
        # twice in a row:
        retries = 0

        while True:
            try:
                # We protect this with a lock to not read
                # a cookie that is in process of being renewed
                # by another thread:
                with self._session_lock:
                    # IMPORTANT: this needs to be a copy - dicts are mutable and
                    # we need to preserve the old value to detect in reauthenticate()
                    # if the cookie has been renewed already or not:
                    request_cookie = self.cookie().copy()
                    headers.update(request_cookie)
                response = requests.request(
                    method=method,
                    url=url,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    cookies=request_cookie,
                    timeout=timeout,
                    stream=stream,
                )

                if response.ok:
                    if success_message:
                        self.logger.info(success_message)
                    if parse_request_response and not stream:
                        return self.parse_request_response(response_object=response)
                    else:
                        return response
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries <= max_retries:
                    # Try to reauthenticate:
                    self.logger.info(
                        "Reauthentication at -> '%s' required.",
                        url,
                    )
                    self.reauthenticate(request_cookie=request_cookie, thread_safe=True)
                    retries += 1
                    self.logger.info("Reauthentication complete.")
                    self.logger.debug(
                        "Old cookie -> %s",
                        str(request_cookie),
                    )
                    self.logger.debug(
                        "New cookie -> %s",
                        str(self.cookie()),
                    )
                elif response.status_code == 500 and "already exists" in response.text:
                    self.logger.warning(
                        (
                            warning_message
                            + " (it already exists); details -> {}".format(
                                response.text,
                            )
                            if warning_message
                            else failure_message
                            + " (it already exists); details -> {}".format(
                                response.text,
                            )
                        ),
                    )
                    if parse_request_response:
                        return self.parse_request_response(response_object=response)
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
                    else:
                        self.logger.debug(
                            "Status -> %s/%s; debug -> %s",
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response_text,
                        )

                    if content_type == "text/html":
                        self.logger.debug(
                            "%s; status -> %s/%s; debug output -> %s",
                            failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response.text,
                        )

                    return None
            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
            ):
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
                        "%s; connection error",
                        failure_message,
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries
                        # we let it wait forever:
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                        time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                    else:
                        return None
            # end try
            self.logger.debug(
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
        """Convert the text property of a request response object to a Python dict safely.

        Handles exceptions to prevent fatal errors caused by corrupt responses,
        such as those produced by Content Server during restarts or resource limits.
        This method logs errors or warnings and bails out gracefully if an issue occurs.

        Args:
            response_object (object):
                The response object delivered by the request call.
            additional_error_message (str):
                Custom error message to include in logs.
            show_error (bool):
                If True, logs an error. If False, logs a warning.

        Returns:
            dict | None:
                Parsed response as a dictionary, or None in case of an error.

        """

        if not response_object:
            return None

        if not response_object.text:
            self.logger.warning("Response text is empty. Cannot decode response.")
            return None

        try:
            dict_object = json.loads(response_object.text)
        except json.JSONDecodeError as exception:
            if additional_error_message:
                message = "Cannot decode response as JSon. {}; response object -> {}; error -> {}".format(
                    additional_error_message,
                    response_object,
                    exception,
                )
            else:
                message = "Cannot decode response as JSon; response object -> {}; error -> {}".format(
                    response_object,
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

    def lookup_result_value(
        self,
        response: dict,
        key: str,
        value: str,
        return_key: str,
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

        Returns:
            str | None:
                The value of the property specified by "return_key" if found,
                or None if the lookup fails.

        """

        if not response:
            return None
        if "results" not in response:
            return None

        results = response["results"]
        # check if results is a list or a dict (both is possible -
        # dependent on the actual REST API):
        if isinstance(results, dict):
            # result is a dict - we don't need index value:
            data = results["data"]
            if isinstance(data, dict):
                # data is a dict - we don't need index value:
                properties = data["properties"]
                if key in properties and properties[key] == value and return_key in properties:
                    return properties[return_key]
                else:
                    return None
            elif isinstance(data, list):
                # data is a list - this has typically just one item, so we use 0 as index
                for item in data:
                    properties = item["properties"]
                    if key in properties and properties[key] == value and return_key in properties:
                        return properties[return_key]
                return None
            else:
                self.logger.error(
                    "Data needs to be a list or dict but it is -> %s",
                    str(type(data)),
                )
                return None
        elif isinstance(results, list):
            # result is a list - we need index value
            for result in results:
                data = result["data"]
                if isinstance(data, dict):
                    # data is a dict - we don't need index value:
                    properties = data["properties"]
                    if key in properties and properties[key] == value and return_key in properties:
                        return properties[return_key]
                elif isinstance(data, list):
                    # data is a list we iterate through the list and try to find the key:
                    for item in data:
                        properties = item["properties"]
                        if key in properties and properties[key] == value and return_key in properties:
                            return properties[return_key]
                else:
                    self.logger.error(
                        "Data needs to be a list or dict but it is of type -> %s",
                        str(type(data)),
                    )
                    return None
            return None
        else:
            self.logger.error(
                "Result needs to be a list or dict but it is of type -> %s",
                str(type(results)),
            )
            return None

    # end method definition

    def exist_result_item(
        self,
        response: dict,
        key: str,
        value: str,
        property_name: str = "properties",
    ) -> bool:
        """Check existence of key / value pair in the response properties of an Content Server REST API call.

        Args:
            response (dict):
                REST response from an OTCS REST Call.
            key (str):
                The property name (key).
            value (str):
                The value to find in the item with the matching key.
            property_name (str, optional):
                The name of the substructure that includes the values.

        Returns:
            bool: True if the value was found, False otherwise

        """

        if not response:
            return False
        if "results" not in response:
            return False

        results = response["results"]
        # check if results is a list or a dict (both is possible - dependent on the actual REST API):
        if isinstance(results, dict):
            # result is a dict - we don't need index value:
            if "data" not in results:
                return False
            data = results["data"]
            if isinstance(data, dict):
                # data is a dict - we don't need index value:
                if property_name and property_name not in data:
                    self.logger.error(
                        "There's no dictionary -> '%s' in data -> %s",
                        property_name,
                        data,
                    )
                    return False
                properties = data[property_name]
                if isinstance(properties, dict):
                    if key in properties:
                        return properties[key] == value
                    else:
                        return False
                elif isinstance(properties, list):
                    # Properties is a list we iterate through the list
                    # and try to find the key. If we find it we return True. Otherwise False.
                    return any(key in item and item[key] == value for item in properties)
                else:
                    self.logger.error(
                        "Properties needs to be a list or dict but it is -> %s",
                        str(type(properties)),
                    )
                    return False
            elif isinstance(data, list):
                # data is a list
                for item in data:
                    if property_name and property_name not in item:
                        self.logger.error(
                            "There's no dictionary -> '%s' in the data list item -> %s",
                            property_name,
                            item,
                        )
                        continue
                    # if properties if passed as empty string then we assume that
                    # the key fields are directly in the item dictionary. This is
                    # the case e.g. with the V2 Proxy APIs
                    properties = item[property_name] if property_name else item
                    if key in properties and properties[key] == value:
                        return True
                return False
            else:
                self.logger.error(
                    "Data needs to be a list or dict but it is -> %s",
                    str(type(data)),
                )
                return False
        elif isinstance(results, list):
            # result is a list - we need index value
            for result in results:
                if "data" not in result:
                    continue
                data = result["data"]
                if isinstance(data, dict):
                    # data is a dict - we don't need index value:
                    properties = data[property_name]
                    if key in properties and properties[key] == value:
                        return True
                elif isinstance(data, list):
                    # data is a list we iterate through the list and try to find the key:
                    for item in data:
                        properties = item[property_name]
                        if key in properties and properties[key] == value:
                            return True
                else:
                    self.logger.error(
                        "Data needs to be a list or dict but it is -> %s",
                        str(type(data)),
                    )
                    return False
            return False
        else:
            self.logger.error(
                "Result needs to be a list or dict but it is -> %s",
                str(type(results)),
            )
            return False

    # end method definition

    def get_result_value(
        self,
        response: dict,
        key: str,
        index: int = 0,
        property_name: str = "properties",
        show_error: bool = True,
    ) -> str | None:
        """Read an item value from the REST API response.

        This method handles the most common response structures delivered by the
        V2 REST API of Extended ECM. For more details, refer to the documentation at
        developer.opentext.com.

        Args:
            response (dict):
                REST API response object.
            key (str):
                Key to find (e.g., "id", "name").
            index (int, optional):
                Index to use if a list of results is delivered (1st element has index 0).
                Defaults to 0.
            property_name (str, optional):
                Name of the sub-dictionary holding the actual values.
                Defaults to "properties".
            show_error (bool, optional):
                Whether an error or just a warning should be logged.

        Returns:
            str:
                Value of the item with the given key, or None if no value is found.

        """

        # First do some sanity checks:
        if not response:
            self.logger.debug("Empty response - no results found!")
            return None

        # To support also iterators that yield from results,
        # we wrap a single data element into a results list
        # to make the following code work like for direct REST responses:
        if "data" in response:
            response = {"results": [response]}

        if "results" not in response:
            if show_error:
                self.logger.error("No 'results' key in REST response - returning None")
            return None

        results = response["results"]
        if not results:
            self.logger.debug("No results found!")
            return None

        # check if results is a list or a dict (both is possible - dependent on the actual REST API):
        if isinstance(results, dict):
            # result is a dict - we don't need index value

            # this is a special treatment for the businessworkspaces REST API - it returns
            # for "Create business workspace" the ID directly in the results dict (without data substructure)
            if key in results:
                return results[key]
            data = results["data"]
            if isinstance(data, dict):
                # data is a dict - we don't need index value:
                properties = data[property_name]
            elif isinstance(data, list):
                # data is a list - this has typically just one item, so we use 0 as index
                properties = data[0][property_name]
            else:
                self.logger.error(
                    "Data needs to be a list or dict but it is -> %s",
                    str(type(data)),
                )
                return None
            # For nearly all OTCS REST Calls properties is a dict:
            if isinstance(properties, dict):
                if key not in properties:
                    if show_error:
                        self.logger.error(
                            "Key -> '%s' is not in result properties!",
                            key,
                        )
                    return None
                return properties[key]
            # but there are some strange ones that have other names for
            # properties and may use a list - see e.g. /v2/holds
            elif isinstance(properties, list):
                if index > len(properties) - 1:
                    self.logger.error(
                        "Illegal Index -> %s given. List has only -> %s elements!",
                        str(index),
                        str(len(properties)),
                    )
                    return None
                return properties[index][key]
            else:
                self.logger.error(
                    "Properties needs to be a list or dict but it is -> %s",
                    str(type(properties)),
                )
                return None
        elif isinstance(results, list):
            # result is a list - we need a valid index:
            if index > len(results) - 1:
                self.logger.error(
                    "Illegal Index -> %s given. List has only -> %s elements!",
                    str(index),
                    str(len(results)),
                )
                return None
            data = results[index]["data"]
            if isinstance(data, dict):
                # data is a dict - we don't need index value:
                properties = data[property_name]
            elif isinstance(data, list):
                # data is a list - this has typically just one item, so we use 0 as index
                properties = data[0][property_name]
            else:
                self.logger.error(
                    "Data needs to be a list or dict but it is -> %s",
                    str(type(data)),
                )
                return None
            if key not in properties:
                if show_error:
                    self.logger.error("Key -> '%s' is not in result properties!", key)
                return None
            return properties[key]
        else:
            self.logger.error(
                "Result needs to be a list or dict but it is -> %s",
                str(type(results)),
            )
            return None

    # end method definition

    def get_result_values(
        self,
        response: dict,
        key: str,
        property_name: str = "properties",
        data_name: str = "data",
    ) -> list | None:
        """Read an item value from the REST API response.

        This method handles the most common response structures delivered by the
        V2 REST API of Extended ECM. For more details, refer to the documentation at
        developer.opentext.com.

        Args:
            response (dict):
                REST API response object.
            key (str):
                Key to find (e.g., "id", "name").
            property_name (str, optional):
                Name of the sub-dictionary holding the actual values.
                Defaults to "properties".
            data_name (str, optional):
                Name of the sub-dictionary holding the data.
                Defaults to "data".

        Returns:
            list | None:
                Value list of the item with the given key, or None if no value is found.

        """

        # First do some sanity checks:
        if not response:
            self.logger.debug("Empty REST response - returning None")
            return None
        if "results" not in response:
            self.logger.error("No 'results' key in REST response - returning None")
            return None

        results = response["results"]
        if not results:
            self.logger.debug("No results found!")
            return None

        # check if results is a list or a dict
        # (both is possible - dependent on the actual REST API):
        if isinstance(results, dict):
            # result is a dict - we don't need index value

            # this is a special treatment for the businessworkspaces REST API -
            # it returns for "Create business workspace" the ID directly in the
            # results dict (without data substructure)
            if key in results:
                return [results[key]]
            data = results[data_name]
            if isinstance(data, dict):
                # data is a dict - we don't need index value:
                properties = data[property_name]
            elif isinstance(data, list):
                # data is a list - this has typically just one item, so we use 0 as index
                if property_name:
                    properties = data[0][property_name]
                else:
                    properties = data
                    self.logger.debug(
                        "Response does not have properties structure. Using data structure directly.",
                    )
            else:
                self.logger.error(
                    "Data needs to be a list or dict but it is -> %s",
                    str(type(data)),
                )
                return None
            # For nearly all OTCS REST Calls properties is a dict:
            if isinstance(properties, dict):
                if key not in properties:
                    self.logger.error("Key -> '%s' is not in result properties!", key)
                    return None
                return [properties[key]]
            # but there are some strange ones that have other names for
            # properties and may use a list - see e.g. /v2/holds
            elif isinstance(properties, list):
                return [item[key] for item in properties]
            else:
                self.logger.error(
                    "Properties needs to be a list or dict but it is -> %s",
                    str(type(properties)),
                )
                return None
        # end if isinstance(results, dict)
        elif isinstance(results, list):
            return [item[data_name][property_name][key] for item in results]
        else:
            self.logger.error(
                "Result needs to be a list or dict but it is of type -> %s",
                str(type(results)),
            )
            return None

    # end method definition

    def is_configured(self) -> bool:
        """Check if the Content Server pod is configured to receive requests.

        Args:
            None.

        Returns:
            bool:
                True if OTCS is configured. False if OTCS is not yet configured.

        """

        request_url = self.config()["configuredUrl"]

        self.logger.debug("Trying to retrieve OTCS URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=REQUEST_JSON_HEADERS,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exception:
            self.logger.debug(
                "Unable to connect to -> %s; warning -> %s",
                request_url,
                str(exception),
            )
            return False

        if not response.ok:
            self.logger.debug(
                "Unable to connect to -> %s; status -> %s; warning -> %s",
                request_url,
                response.status_code,
                response.text,
            )
            return False

        return True

    # end method definition

    def is_ready(self) -> bool:
        """Check if the Content Server pod is ready to receive requests.

        Args:
            None.

        Returns:
            bool: True if pod is ready. False if pod is not yet ready.

        """

        request_url = self.config()["isReady"]

        self.logger.debug("Trying to retrieve OTCS URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=REQUEST_JSON_HEADERS,
                timeout=2,
            )
        except requests.exceptions.RequestException as exception:
            self.logger.debug(
                "Unable to connect to -> %s; warning -> %s",
                request_url,
                str(exception),
            )
            return False

        if response.status_code != 200:
            self.logger.debug(
                "Unable to connect to -> %s; status -> %s; warning -> %s",
                request_url,
                response.status_code,
                response.text,
            )
            return False

        return True

    # end method definition

    def invalidate_authentication_ticket(self) -> None:
        """If a 401 HTTP error occurs we may want to invalidate the login ticket."""

        self._otcs_ticket = None

    # end method definition

    def authenticate(
        self,
        revalidate: bool = False,
        wait_for_ready: bool = True,
    ) -> dict | None:
        """Authenticate with Content Server and retrieves an OTCS ticket.

        Args:
            revalidate (bool, optional):
                Determines if re-authentication is enforced (e.g., if the session
                has timed out with a 401 error). By default, the OTDS ticket
                (if available) is used for authentication with OTCS. This flag
                forces the use of a username and password for authentication.
            wait_for_ready (bool, optional):
                Specifies whether to wait for the OTCS service to be "ready".
                Defaults to True. Set to False if you want authentication to fail fast.

        Returns:
            dict | None:
                Cookie information, or None in case of an error.
                Also stores Ticket information in self._otcs_ticket.

        """

        # Already authenticated and session still valid?
        if self._otcs_ticket and not revalidate:
            self.logger.debug(
                "Session still valid - return existing cookie -> %s",
                str(self.cookie()),
            )
            return self.cookie()

        # Clear the ticket:
        otcs_ticket = None

        if wait_for_ready:
            self.logger.info("Check if OTCS is ready...")
            while not self.is_ready():
                self.logger.debug(
                    "OTCS is not ready to receive requests yet. Waiting additional 30 seconds...",
                )
                time.sleep(30)

        request_url = self.config()["authenticationUrl"]

        if self._otds_ticket and not revalidate:
            self.logger.debug(
                "Requesting OTCS ticket with existing OTDS ticket; calling -> %s",
                request_url,
            )
            request_header = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "OTDSTicket": self._otds_ticket,
            }

            try:
                response = requests.get(
                    url=request_url,
                    headers=request_header,
                    timeout=10,
                )
                if response.ok:
                    # read the ticket from the response header:
                    otcs_ticket = response.headers.get("OTCSTicket")

            except requests.exceptions.RequestException as exception:
                self.logger.warning(
                    "Unable to connect to -> %s; error -> %s",
                    request_url,
                    str(exception),
                )

        # Check if previous authentication was not successful.
        # Then we do the normal username + password authentication:
        if not otcs_ticket:
            self.logger.debug(
                "Requesting OTCS ticket with user/password; calling -> %s",
                request_url,
            )

            response = None
            try:
                response = requests.post(
                    url=request_url,
                    data=self.credentials(),  # this includes username + password
                    headers=REQUEST_FORM_HEADERS,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.exceptions.RequestException as exception:
                self.logger.warning(
                    "Unable to connect to -> %s; error -> %s",
                    request_url,
                    str(exception),
                )
                self.logger.warning("OTCS service may not be ready yet.")
                return None

            if response.ok:
                authenticate_dict = self.parse_request_response(
                    response_object=response,
                    additional_error_message="This can be normal during restart",
                    show_error=False,
                )
                if not authenticate_dict:
                    return None
                else:
                    otcs_ticket = authenticate_dict["ticket"]
                    self.logger.debug("Ticket -> %s", otcs_ticket)
            else:
                self.logger.error(
                    "Failed to request an OTCS ticket; error -> %s",
                    response.text,
                )
                return None

        # Store authentication ticket:
        self._otcs_ticket = otcs_ticket

        self.logger.debug("Cookie after authentication -> %s", str(self.cookie()))

        return self.cookie()

    # end method definition

    def reauthenticate(
        self,
        request_cookie: dict,
        thread_safe: bool = True,
    ) -> dict | None:
        """Re-authenticates after a session timeout.

        This implementation supports thread-safe reauthentication, ensuring that
        multiple threads do not attempt to reauthenticate simultaneously.

        Args:
            request_cookie (dict):
                The cookie used in the REST API call that produced the 401 HTTP error,
                triggering the re-authentication. It is compared with the current cookie
                to check whether another thread has already reauthenticated and updated
                the cookie.
            thread_safe (bool, optional):
                Specifies whether to use a thread-safe implementation.
                Defaults to True.

        Returns:
            dict | None:
                Cookie information returned by authenticate(), or None in case of failure.

        """

        if not thread_safe:
            return self.authenticate(revalidate=True)

        # Lock access to session for thread-safe reads
        with self._session_lock:
            # Check if the cookie used for the REST call is still the current cookie:
            if request_cookie != self.cookie():
                # Another thread has already re-authenticated; skip re-authentication
                self.logger.debug(
                    "Session has already been renewed with new cookie. Skip re-authentication and return new cookie -> %s",
                    str(self.cookie()),
                )
                # return the new cookie:
                return self.cookie()
            else:
                # No other thread has re-authenticatedyes.
                # This thread will try to get the re-authentication role:
                self.logger.debug(
                    "Session has still the old cookie used for the REST call -> %s",
                    request_cookie,
                )

        # If the session is invalid, try to acquire the semaphore and renew it
        if self._authentication_semaphore.acquire(blocking=False):
            # Renew the session (only one thread gets here)
            self.logger.debug(
                "Session has expired - need to renew old request cookie -> %s",
                str(request_cookie),
            )

            try:
                # The 'with' automatically acquires and releases the lock on 'authentication_condition'
                with self._authentication_condition:
                    self.logger.debug(
                        "Current thread got the authentication condition...",
                    )
                    # We use the _session_lock to prevent race conditions
                    # while reading / writing the self._otcs_ticket (which is modified
                    # by the authenticate() method):
                    with self._session_lock:
                        self.logger.debug(
                            "Current thread got the session lock and tries to re-authenticate to get new cookie",
                        )
                        try:
                            self.authenticate(revalidate=True)
                            self.logger.debug(
                                "Session renewal successful, new cookie -> %s",
                                str(self.cookie()),
                            )
                            time.sleep(REQUEST_RETRY_DELAY)
                        except Exception:
                            self.logger.error(
                                "Reauthentication failed!",
                            )
                            raise
                    self.logger.debug("Lift session lock and notify waiting threads...")
                    # Notify all waiting threads that session is renewed:
                    self._authentication_condition.notify_all()
                    self.logger.debug("All waiting threads have been notified.")
            finally:
                # Ensure the semaphore is released even if an error occurs
                self._authentication_semaphore.release()
                self.logger.debug("Semaphore released after session renewal.")
            self.logger.debug(
                "Session renewing thread continues with retry of request...",
            )
        # end if self._authentication_semaphore.acquire(blocking=False)
        else:
            # Other threads wait for session renewal to complete
            self.logger.debug(
                "Session has expired but another thread is working on renewal - current thread waiting for re-authentication...",
            )

            with self._authentication_condition:
                self.logger.debug("Waiting thread got the authentication condition...")
                # IMPORTANT: Don't do a session lock here. This can produce a deadlock.
                # Reason: self._authentication_condition.wait() does not release the self._session_lock
                # but just the self._authentication_condition lock.

                # Check if session is not yet renewed (still has the old cookie used for the request)
                while request_cookie == self.cookie():
                    # This code is very unlikely to be executed as
                    # _authentication_condition and _session_lock protect
                    # the else clause from running in parallel to the if clause.
                    self.logger.debug("Thread is waiting for session renewal now...")
                    # Wait for notification that the session is renewed:
                    self._authentication_condition.wait()
                    self.logger.debug(
                        "Thread received notification, session renewal complete.",
                    )
                self.logger.debug(
                    "Waiting thread got the new cookie -> %s.",
                    str(self.cookie()),
                )
            self.logger.debug(
                "Waiting thread released the authentication condition and continues with retry of request...",
            )

        return self.cookie()

    # end method definition

    def get_server_info(self) -> dict | None:
        """Retrieve Content Server information.

        Fetches detailed server information, including mobile support, server
        settings, session configurations, and viewer details.

        Returns:
            dict | None:
                Server information as a dictionary, or None if the call fails.

        Example:
            ```json
            {
                'mobile': {
                    'cs_viewer_support': False,
                    'offline_use': True
                },
                'server': {
                    'advanced_versioning': True,
                    'character_encoding': 1,
                    'current_date': '2023-09-05T17:09:41',
                    'current_locale_suffix': '_en_US',
                    'domain_access_enabled': False,
                    'enhanced_advanced_versioning': False,
                    'force_download_for_mime_types': [...],
                    'language_code': 'USA',
                    'languages': [...],
                    'metadata_languages': [...],
                    'url': 'https://otcs.dev.idea-te.eimdemo.com/cs/cs',
                    'version': '23.3'
                },
                'sessions': {
                    'enabled': True,
                    'expire_after_last_login': False,
                    'expire_after_last_request': True,
                    'logout_url': '?func=ll.DoLogout&secureRequestToken=<token>',
                    'session_inactivity': 7020000,
                    'session_reaction_time': 180000,
                    'session_timeout': 7200000
                },
                'viewer': {
                    'content_suite': {...}
                }
            }
            ```

        """

        request_url = self.config()["serverInfoUrl"]
        request_header = self.request_form_header()  # self.cookie()

        self.logger.debug(
            "Retrieve Content Server information; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve Content Server information",
        )

    # end method definition

    def get_server_version(self) -> str | None:
        """Get Content Server version.

        Args:
            None

        Returns:
            str | None:
                Server version number like "24.4". Returns None in case of an error.

        """

        response = self.get_server_info()
        if not response:
            return None

        server_info = response.get("server")
        if not server_info:
            return None

        return server_info.get("version")

    # end method definition

    def apply_config(self, xml_file_path: str) -> dict | None:
        """Apply Content Server administration settings from XML file.

        Args:
            xml_file_path (str): name + path of the XML settings file

        Returns:
            dict | None:
                Import response or None if the import fails.
                The field response["results"]["data"]["restart"] indicates if the settings
                require a restart of the OTCS services.

        """

        filename = os.path.basename(xml_file_path)

        if not os.path.exists(xml_file_path):
            self.logger.error(
                "The admin settings file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(xml_file_path),
            )
            return None

        request_url = self.config()["importSettingsUrl"]
        request_header = self.cookie()

        self.logger.debug(
            "Applying admin settings from file -> '%s'; calling -> %s",
            xml_file_path,
            request_url,
        )

        with open(xml_file_path, encoding="utf-8") as xml_file:
            llconfig_file = {
                "file": (filename, xml_file, "text/xml"),
            }

            return self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                files=llconfig_file,
                timeout=None,
                success_message="Admin settings in file -> '{}' have been applied".format(
                    xml_file_path,
                ),
                failure_message="Failed to import settings file -> '{}'".format(
                    xml_file_path,
                ),
            )

    # end method definition

    @cache
    def get_user(self, name: str, show_error: bool = False) -> dict | None:
        """Look up an Content Server user based on the login name.

        Args:
            name (str):
                Name of the user (login).
            show_error (bool, optional):
                If True, treat as an error if the user is not found. Defaults to False.

        Returns:
            dict | None:
                User information as a dictionary, or None if the user is not found.

        Example:
            ```json
            {
                'collection': {
                    'paging': {...},
                    'sorting': {...}
                },
                'links': {
                    'data': {...}
                },
                'results': [
                    {
                        'data': {
                            'birth_date': None,
                            'business_email': 'pramos@M365x61936377.onmicrosoft.com',
                            'business_fax': None,
                            'business_phone': None,
                            'cell_phone': None,
                            'deleted': False,
                            'display_language': None,
                            'first_name': 'Peter',
                            'gender': None,
                            'group_id': 8006,
                            'home_address_1': None,
                            'home_address_2': None,
                            'home_fax': None,
                            'home_phone': None,
                            'id': 8123,
                            'initials': None,
                            'last_name': 'Ramos',
                            'middle_name': None,
                            'name': 'pramos',
                            'name_formatted': 'Peter Ramos',
                            'photo_id': 13981,
                            'photo_url': 'api/v1/members/8123/photo?v=13981.1',
                            'type': 0,
                            'type_name': 'User'
                        }
                    }
                ]
            }
            ```

            To access the (login) name of the first user found, use
            `["results"][0]["data"]["properties"]["name"]`.
            Alternatively, use the method `get_result_value(response, "name", 0)`.

        """

        # Add query parameters (these are NOT passed via JSon body!)
        # type = 0 ==> User
        query = {"where_type": 0, "where_name": name}
        encoded_query = urllib.parse.urlencode(query=query, doseq=True)
        request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get user with login name -> '%s'; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get user with login -> '{}'".format(name),
            warning_message="Couldn't find user with login -> '{}'".format(name),
            show_error=show_error,
        )

    # end method definition

    def add_user(
        self,
        name: str,
        password: str,
        first_name: str,
        last_name: str,
        email: str,
        title: str,
        base_group: int,
        privileges: list | None = None,
        user_type: int = 0,
    ) -> dict | None:
        """Add Content Server user.

        Args:
            name (str): login name of the user
            password (str): password of the user
            first_name (str): first name of the user
            last_name (str): last name of the user
            email (str): email address of the user
            title (str): title of the user
            base_group (int): base group id of the user (e.g. department)
            privileges (list, optional):
                Possible values are Login, Public Access, Content Manager,
                Modify Users, Modify Groups, User Admin Rights,
                Grant Discovery, System Admin Rights
            user_type (int, optional): id of user_type 0-User, 17-ServiceUser, ...

        Returns:
            dict | None:
                User information or None if the user couldn't be created
                (e.g. because it exisits already).

        """

        if privileges is None:
            privileges = ["Login", "Public Access"]

        user_post_body = {
            "type": user_type,
            "name": name,
            "password": password,
            "first_name": first_name,
            "last_name": last_name,
            "business_email": email,
            "title": title,
            "group_id": base_group,
            "privilege_login": ("Login" in privileges),
            "privilege_public_access": ("Public Access" in privileges),
            "privilege_content_manager": ("Content Manager" in privileges),
            "privilege_modify_users": ("Modify Users" in privileges),
            "privilege_modify_groups": ("Modify Groups" in privileges),
            "privilege_user_admin_rights": ("User Admin Rights" in privileges),
            "privilege_grant_discovery": ("Grant Discovery" in privileges),
            "privilege_system_admin_rights": ("System Admin Rights" in privileges),
        }

        request_url = self.config()["membersUrlv2"]
        request_header = self.request_form_header()

        self.logger.debug("Add user -> '%s'; calling -> %s", name, request_url)

        # Clear user cache
        self.get_user.cache_clear()

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=user_post_body,
            timeout=None,
            failure_message="Failed to add user -> '{}'".format(name),
        )

    # end method definition

    def search_user(self, value: str, field: str = "where_name") -> dict | None:
        """Find a user based on search criteria.

        Args:
            value (str):
                Field value to search for.
            field (str):
                User field to search with (e.g. "where_name", "where_first_name", "where_last_name").

        Returns:
            dict | None:
                User information as a dictionary, or None if the user could not be found
                (e.g., because it doesn't exist).

        Example:
            ```json
            {
                'collection': {
                    'paging': {...},
                    'sorting': {...}
                },
                'links': {
                    'data': {...}
                },
                'results': [
                    {
                        'data': {
                            'properties': {
                                'birth_date': None,
                                'business_email': 'dfoxhoven@M365x61936377.onmicrosoft.com',
                                'business_fax': None,
                                'business_phone': None,
                                'cell_phone': None,
                                'deleted': False,
                                'display_language': None,
                                'first_name': 'Deke',
                                'gender': None,
                                'group_id': 8005,
                                'home_address_1': None,
                                'home_address_2': None,
                                'home_fax': None,
                                'home_phone': None,
                                'id': 8562,
                                'initials': 'DF',
                                'last_name': 'Foxhoven',
                                'middle_name': None,
                                'name': 'dfoxhoven',
                                'name_formatted': 'Deke Foxhoven',
                                ...
                            }
                        }
                    }
                ]
            }
            ```

        """

        request_url = self.config()["membersUrlv2"] + "?" + field + "=" + value
        request_header = self.request_form_header()

        self.logger.debug(
            "Searching user by field -> %s, value -> %s; calling -> %s",
            field,
            value,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Cannot find user with field -> {}, value -> {}".format(
                field,
                value,
            ),
        )

    # end method definition

    def update_user(self, user_id: int, field: str, value: str) -> dict | None:
        """Update a defined field for a user.

        Args:
            user_id (int): ID of the user
            value (str): field value
            field (str): user field

        Returns:
            dict | None:
                User information or None if the user couldn't be updated (e.g. because it doesn't exist).

        """

        user_put_body = {field: value}

        request_url = self.config()["membersUrlv2"] + "/" + str(user_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Updating user with ID -> %s, field -> %s, value -> %s; calling -> %s",
            str(user_id),
            field,
            value,
            request_url,
        )
        self.logger.debug("User Attributes -> %s", str(user_put_body))

        # Clear user cache
        self.get_user.cache_clear()

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=user_put_body,
            timeout=None,
            failure_message="Failed to update user with ID -> {}".format(user_id),
        )

    # end method definition

    def get_user_profile(self) -> dict | None:
        """Update a defined field for a user profile.

        IMPORTANT: this method needs to be called by the authenticated user

        Args:
            None

        Returns:
            dict | None:
                User information or None if the user couldn't be updated
                (e.g. because it doesn't exist).

        """

        request_url = self.config()["membersUrlv2"] + "/preferences"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get profile (settings) for current user; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get profile of current user",
        )

    # end method definition

    def update_user_profile(
        self,
        field: str,
        value: str,
        config_section: str = "SmartUI",
    ) -> dict | None:
        """Update a defined field for a user profile.

        IMPORTANT: This method must be called by the authenticated user.

        Args:
            field (str):
                The user profile field to be updated.
            value (str):
                The new value for the specified field.
            config_section (str, optional):
                The name of the config section. Possible values include:
                - SmartUI
                - General
                - Colors
                - ContentIntelligence
                - Discussion
                - Follow Up
                - Template Workspaces
                - Workflow
                - XECMGOVSettings
                - CommunitySettings
                - RecMan
                - PhysObj
                Defaults to "SmartUI".

        Returns:
            dict | None:
                User information as a dictionary, or None if the user could not be updated
                (e.g., because the user does not exist).

        """

        user_profile_put_body = {config_section: {field: value}}

        request_url = self.config()["membersUrlv2"] + "/preferences"
        request_header = self.request_form_header()

        self.logger.debug(
            "Updating profile for current user, field -> %s, value -> %s; calling -> %s",
            field,
            value,
            request_url,
        )
        self.logger.debug("User Attributes -> %s", str(user_profile_put_body))

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data={"body": json.dumps(user_profile_put_body)},
            timeout=None,
            failure_message="Failed to update profile of current user",
        )

    # end method definition

    def update_user_photo(self, user_id: int, photo_id: int) -> dict | None:
        """Update a user with a profile photo (which must be an existing node).

        Args:
            user_id (int): The ID of the user.
            photo_id (int): The node ID of the photo.

        Returns:
            dict | None: Node information or None if photo node is not found.

        """

        update_user_put_body = {"photo_id": photo_id}

        request_url = self.config()["membersUrl"] + "/" + str(user_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Update user ID -> %s with photo ID -> %s; calling -> %s",
            user_id,
            photo_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=update_user_put_body,
            timeout=None,
            failure_message="Failed to update user with ID -> {}".format(user_id),
        )

    # end method definition

    def is_proxy(self, user_name: str) -> bool:
        """Check if a user is defined as proxy of the current user.

        This method differentiates between the old (xGov) based
        implementation and the new Extended ECM platform one
        that was introduced with version 23.4.

        Args:
            user_name (str): user to test (login name)

        Returns:
            bool: True is user is proxy of current user. False if not.

        """

        version_number = self.get_server_version()
        # Split the version number by dot
        parts = version_number.split(".")
        # Take the first two parts and join them back with a dot
        stripped_version = ".".join(parts[:2])

        try:
            version_number = float(stripped_version)
        except ValueError:
            version_number = 99.99  # Set to version 99.99 for "main"

        if version_number >= 23.4:
            response = self.get_user_proxies(use_v2=True)
            return self.exist_result_item(
                response=response,
                key="name",
                value=user_name,
                property_name="",
            )
        else:
            response = self.get_user_proxies(use_v2=False)
            if not response or "proxies" not in response:
                return False
            proxies = response["proxies"]

            return any(proxy["name"] == user_name for proxy in proxies)

    # end method definition

    def get_user_proxies(self, use_v2: bool = False) -> dict | None:
        """Get list of user proxies.

        This method needs to be called as the user the proxy is acting for.

        Args:
            use_v2 (bool):
                Whether or not to use the newer V2 version of this API.
                Default is False (i.e. using the V1 version).

        Returns:
            dict | None:
                Node information or None if REST request fails.

        """

        request_url = self.config()["membersUrlv2"] + "/proxies" if use_v2 else self.config()["membersUrl"] + "/proxies"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get proxy users for current user; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get proxy users for current user",
        )

    # end method definition

    def add_user_proxy(
        self,
        proxy_user_id: int,
        from_date: str | None = None,
        to_date: str | None = None,
    ) -> dict | None:
        """Add a user as a proxy to the current user.

        IMPORTANT: This method must be called as the user the proxy is acting for.
        Optionally, this method can be provided with a time span during which the
        proxy should be active.
        This method differentiates between the old (xGov) implementation and the new
        Extended ECM platform, which was introduced with version 23.4.

        Example payload for a proxy user (ID: 19340) without a time span:
        {
            "id": 2545,
            "from_date": None,
            "to_date": None
        }

        Example payload for a proxy user (ID: 19340) with a time span:
        {
            "id": 2545,
            "from_date": "2023-03-15",
            "to_date": "2023-03-31"
        }

        Args:
            proxy_user_id (int):
                The ID of the proxy user.
            from_date (str, optional):
                The start date for the proxy (format: YYYY-MM-DD).
                Defaults to None.
            to_date (str, optional):
                The end date for the proxy (format: YYYY-MM-DD).
                Defaults to None.

        Returns:
            dict | None:
                Request response as a dictionary, or None if the call fails.

        """

        version_number = self.get_server_version()
        # Split the version number by dot
        parts = version_number.split(".")
        # Take the first two parts and join them back with a dot
        stripped_version = ".".join(parts[:2])
        version_number = float(stripped_version)

        # for versions older than 23.4 we need to use
        # the legacy Extended ECM for Government Proxy
        # implementation:
        if version_number >= 23.4:
            post_dict = {}
            post_dict["id"] = proxy_user_id
            post_dict["from_date"] = from_date
            post_dict["to_date"] = to_date
            post_data = {"body": json.dumps(post_dict)}
            request_url = self.config()["membersUrlv2"] + "/proxies"
            self.logger.debug(
                "Assign proxy user with ID -> %s to current user; calling -> %s",
                proxy_user_id,
                request_url,
            )
        else:
            post_dict = {}
            if from_date and to_date:
                post_dict["from_date"] = from_date
                post_dict["to_date"] = to_date
            post_dict = {str(proxy_user_id): post_dict}
            post_data = {"add_proxy": json.dumps(post_dict)}
            request_url = self.config()["membersUrl"] + "/proxies"
            self.logger.debug(
                "Assign proxy user with ID -> %s to current user (legacy xGov); calling -> %s",
                proxy_user_id,
                request_url,
            )

        request_header = self.request_form_header()

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=post_data,
            timeout=None,
            failure_message="Failed to assign proxy user with ID -> {} to current user".format(
                proxy_user_id,
            ),
        )

    # end method definition

    def add_favorite(self, node_id: int) -> dict | None:
        """Add a favorite for the current (authenticated) user.

        Args:
            node_id (int):
                The ID of the node that should become a favorite.

        Returns:
            dict | None:
                Request response or None if the favorite creation request has failed.

        """

        request_url = self.config()["favoritesUrl"] + "/" + str(node_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Adding favorite for node ID -> %s; calling -> %s",
            node_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=None,
            failure_message="Failed to add favorite for node ID -> {}".format(node_id),
        )

    # end method definition

    def add_favorite_tab(self, tab_name: str, order: int) -> dict | None:
        """Add a favorite tab for the current (authenticated) user.

        Args:
            tab_name (str):
                The name of the new tab.
            order (int):
                The ordering position of the new tab.

        Returns:
            dict | None:
                Request response or None if the favorite tab creation request has failed.

        """

        favorite_tab_post_body = {"name": tab_name, "order": str(order)}

        request_url = self.config()["favoritesUrl"] + "/tabs"
        request_header = self.request_form_header()

        self.logger.debug(
            "Adding favorite tab -> %s; calling -> %s",
            tab_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=favorite_tab_post_body,
            timeout=None,
            failure_message="Failed to add favorite tab -> {}".format(tab_name),
        )

    # end method definition

    def get_group(self, name: str, show_error: bool = False) -> dict | None:
        """Look up a Content Server group.

        Args:
            name (str):
                The name of the group to look up.
            show_error (bool, optional):
                If True, treats the absence of the group as an error. Defaults to False.

        Returns:
            dict | None:
                Group information as a dictionary, or None if the group is not found.
                The returned information has the following structure:
                {
                    "data": [
                        {
                            "id": 0,
                            "name": "string",
                            ...
                        }
                    ]
                }

                To access the ID of the first group found, use ["data"][0]["id"].

        """

        # Add query parameters (these are NOT passed via JSon body!)
        # type = 1 ==> Group
        query = {"where_type": 1, "where_name": name}
        encoded_query = urllib.parse.urlencode(query=query, doseq=True)
        request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get group with name -> '%s'; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get group -> '{}'".format(name),
            warning_message="Group -> '{}' does not yet exist".format(name),
            show_error=show_error,
        )

    # end method definition

    def add_group(self, name: str) -> dict | None:
        """Add Content Server group.

        Args:
            name (str):
                The name of the group.

        Returns:
            dict | None:
                Group information or None if the group couldn't be created (e.g. because it exisits already).

        """

        group_post_body = {"type": 1, "name": name}

        request_url = self.config()["membersUrlv2"]
        request_header = self.request_form_header()

        self.logger.debug("Adding group -> '%s'; calling -> %s", name, request_url)
        self.logger.debug("Group Attributes -> %s", str(group_post_body))

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=group_post_body,
            timeout=None,
            failure_message="Failed to add group -> '{}'".format(name),
        )

    # end method definition

    def get_group_members(
        self,
        group: int,
        member_type: int,
        where_name: str | None = None,
        where_first_name: str | None = None,
        where_last_name: str | None = None,
        where_business_email: str | None = None,
        limit: int = 100,
        page: int = 1,
    ) -> dict | None:
        """Get Content Server group members.

        Args:
            group (int):
                The ID of the group.
            member_type (int):
                Type of members to retrieve. Possible values:
                0 = users
                1 = groups
            where_name (str | None, optional):
                Filters the results, returning the members where the login name matches the specified string.
            where_first_name (str | None, optional):
                Filters the results, returning the members where the first name matches the specified string.
            where_last_name (str | None, optional):
                Filters the results, returning the members where the last name matches the specified string.
            where_business_email (str | None, optional):
                Filters the results, returning the members where the business email address matches the specified string.
            limit (int, optional):
                The maximum number of results per page (internal default is 25)
            page (int, optional):
                The page number to retrieve.

        Returns:
            dict | None:
                Group members or None if the group members couldn't be found.

        """

        query = {}
        query["where_type"] = str(member_type)
        if limit:
            query["limit"] = limit
        if page:
            query["page"] = page
        if where_name:
            query["where_name"] = where_name
        if where_first_name:
            query["where_first_name"] = where_first_name
        if where_last_name:
            query["where_last_name"] = where_last_name
        if where_business_email:
            query["where_business_email"] = where_business_email

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        # default limit is 25 which may not be enough for groups with many members
        # where_type = 1 makes sure we just get groups and not users
        request_url = self.config()["membersUrlv2"] + "/" + str(group) + "/members?{}".format(encoded_query)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get members of group with ID -> %s; calling -> %s",
            str(group),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get members of group with ID -> {}".format(
                group,
            ),
        )

    # end method definition

    def get_group_members_iterator(
        self,
        group: int,
        member_type: int,
        where_name: str | None = None,
        where_first_name: str | None = None,
        where_last_name: str | None = None,
        where_business_email: str | None = None,
        page_size: int = 100,
    ) -> iter:
        """Get an iterator object that can be used to traverse group members.

        Filters can be applied that are given by the "where" parameters.

        Using a generator avoids loading a large number of nodes into memory at once.
        Instead you can iterate over the potential large list of related workspaces.

        Example usage:
            ```python
            members = otcs_object.get_group_members_iterator(group=1001, member_type=0, page_size=10)
            for member in group_members:
                logger.info("Traversing member -> %s (%s)", member["name"], member["id"])
            ```

        Args:
            group (int):
                The ID of the group.
            member_type (int):
                Type of members to retrieve. Possible values:
                0 = users
                1 = groups
            where_name (str | None, optional):
                Filters the results, returning the members where the login name
                matches the specified string.
            where_first_name (str | None, optional):
                Filters the results, returning the members where the first name
                matches the specified string.
            where_last_name (str | None, optional):
                Filters the results, returning the members where the last name
                matches the specified string.
            where_business_email (str | None, optional):
                Filters the results, returning the members where the business email
                address matches the specified string.
            page_size (int, optional):
                The maximum number of results per page (internal default is 25). For this
                iterator it is basically the chunk size.

        Returns:
            iter:
                A generator yielding one member per iteration for the given group.
                If the REST API fails, returns no value.

        """

        # First we probe how many members we have:
        response = self.get_group_members(
            group=group,
            member_type=member_type,
            where_name=where_name,
            where_first_name=where_first_name,
            where_last_name=where_last_name,
            where_business_email=where_business_email,
            limit=1,
            page=1,
        )
        if not response or "results" not in response:
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        number_of_members = response["collection"]["paging"]["total_count"]
        if not number_of_members:
            self.logger.warning(
                "Group with ID -> %s does not have members! Cannot iterate over members.",
                str(group),
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        # If the group has many members we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (number_of_members + page_size - 1) // page_size

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.get_group_members(
                group=group,
                member_type=member_type,
                where_name=where_name,
                where_first_name=where_first_name,
                where_last_name=where_last_name,
                where_business_email=where_business_email,
                limit=page_size,
                page=page,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve members for group with ID -> %d (page -> %d)",
                    group,
                    page,
                )
                return

            # Yield nodes one at a time:
            yield from response["results"]

        # end for page in range(1, total_pages + 1)

    # end method definition

    def add_group_member(self, member_id: int, group_id: int) -> dict | None:
        """Add a user or group to a target group.

        Args:
            member_id (int):
                The ID of the user or group to add.
            group_id (int):
                The ID of the target group the member should be added to.

        Returns:
            dict | None:
                Response or None if adding a the member fails.

        """

        group_member_post_body = {"member_id": member_id}

        request_url = self.config()["membersUrlv2"] + "/" + str(group_id) + "/members"
        request_header = self.request_form_header()

        self.logger.debug(
            "Adding member with ID -> %s to group with ID -> %s; calling -> %s",
            str(member_id),
            str(group_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=group_member_post_body,
            timeout=None,
            failure_message="Failed to add member with ID -> {} to group with ID -> {}".format(
                member_id,
                group_id,
            ),
        )

    # end method definition

    def update_privilege(self, privilege_id: str, restricted: bool) -> dict | None:
        """Update a usage privilege.

        Args:
            privilege_id (str):
                The object_type (for an Object Privilege) or usage_id (for a Usage Privilege) value of the privilege.
            restricted (bool):
                update the restricted propertiy of a usage privilege

        Returns:
            dict | None:
                The id of the update privilege.

        Example:
            ```json
            {
                "id": 123
            }
            ```

        """
        request_header = self.request_form_header()

        request_url = self.config()["privileges"]

        request_body = {
            "privilege_id": privilege_id,
            "action": "restrict" if restricted else "unrestrict",
        }

        response = self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=request_body,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to update privilege {}".format(privilege_id),
        )

        if response:
            self.logger.debug("Invalidating cache for usage and object privileges")
            self.get_object_privileges.cache_clear()
            self.get_usage_privileges.cache_clear()

            return response["results"]["data"]

        return None

    # end method definition

    @cache
    def get_usage_privileges(self) -> list[dict] | None:
        """Get list of all usage privileges defined in the system.

        The returned values are cached, as they will not change for the lifetime of the system.

        Returns:
            list:
                The complete list of usage privileges.

        Example:
            [
                {
                    'deleted': False,
                    'id': None,
                    'name': "Share Item with OpenText Core ({'ContentSharing',1})",
                    'object_icon': None,
                    'object_name': None,
                    'object_type': None,
                    'restricted': False,
                    'type': 4,
                    'type_name': 'Privilege',
                    'usage_id': "{'ContentSharing',1}",
                    'usage_name': 'Share Item with OpenText Core',
                    'usage_type': 'ContentSharing',
                    'usage_type_name': 'Content Sharing Operation'
                },
                ...
            ]

        """
        request_header = self.request_form_header()

        request_url = self.config()["privileges"] + "/usage"

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get system usage privileges.",
        )

        if response:
            return response["results"]["data"]

        return None

    # end method definition

    def get_usage_privilege(
        self,
        usage_id: str | None = None,
        usage_name: str | None = None,
        update_cache: bool = False,
    ) -> dict | None:
        """Get the usage privilege either based on ID or based on a name.

        The returned values are cached, as they will not change for the lifetime of the system.

        Args:
            usage_id (str | None, optional):
                The usage privilege ID. Needs to be provided if usage_name is None.
            usage_name (str | None, optional):
                The name of the usage privilege. Needs to be provided if usage_id is None.
            update_cache (bool, optional):
                Use the cached state of usage privileges if available.
                Dewfault is False.

        Returns:
            dict:
                The privilege data.

        Example:
            ```json
            {
                'deleted': False,
                'id': 2498,
                'name': 'Create items in Supplier exchange. ({12002,12002})',
                'object_icon': None,
                'object_name': None,
                'object_type': None,
                'restricted': True,
                'type': 4,
                'type_name': 'Privilege',
                'usage_id': '{12002,12002}',
                'usage_name': 'Create items in Supplier exchange.',
                'usage_type': '12002',
                'usage_type_name': 'Supplier exchange'
            }
            ```

        """

        if not usage_id and not usage_name:
            self.logger.error("Get privilege failed - either usage_id or usage_name need to be specified")
            return None

        if update_cache:
            self.logger.debug("Clearing cache for usage privileges.")
            self.get_usage_privileges.cache_clear()

        all_privileges = self.get_usage_privileges()

        if usage_id:
            result = next(
                (priv for priv in all_privileges if priv.get("usage_id", "") == usage_id),
                None,
            )
            if result:
                return result

        if usage_name:
            result = next(
                (priv for priv in all_privileges if priv.get("usage_name", "") == usage_name),
                None,
            )

        if result:
            return result

        return None

    # end method definition

    def assign_usage_privilege(self, usage_privilege: str, member_id: int, auto_restrict: bool = True) -> dict | None:
        """Assign a usage privilege to a user or group.

        Args:
            usage_privilege (str):
                The name of the usage privilege to assign.
            member_id (int):
                The ID of user or group that the privilege should be given to.
            auto_restrict (bool, optional):
                automatically restrict the usage privilege, if it is unrestricted

        Returns:
            dict | None:
                The privilege data / response.

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/members/2393/members',
                            'method': 'POST',
                            'name': ''
                        }
                    }
                },
                'results': {}
            }
            ```

        """

        # Provide the provided argument as ID and Name to find the privilege
        privilege = self.get_usage_privilege(usage_id=usage_privilege, usage_name=usage_privilege)

        if not privilege:
            self.logger.warning(
                "Privilege -> '%s' could not be found. Cannot assign privilege to member -> %s.",
                usage_privilege,
                member_id,
            )

            return None

        privilege_id = privilege.get("id", None) if privilege else None

        # Check if identified privilege is restricted - if not restrict it and set ID from response
        if auto_restrict and privilege_id is None and privilege["restricted"] is False:
            result = self.update_privilege(privilege_id=privilege["usage_id"], restricted=True)
            if result:
                privilege_id = result.get(
                    "id",
                    None,
                )

        if privilege_id:
            self.logger.info(
                "Assigning member with ID -> %s to usage privilege -> '%s' (%s)",
                member_id,
                usage_privilege,
                privilege_id,
            )
            return self.add_group_member(member_id=member_id, group_id=privilege_id)

        self.logger.warning(
            "Cannot add member with ID -> %s to usage privilege -> '%s'. Usage is likely unrestricted.",
            member_id,
            usage_privilege,
        )
        return None

    # end method definition

    @cache
    def get_object_privileges(self) -> list[dict] | None:
        """Get list of all usage privileges defined in the system.

        The returned values are cached, as they will not change for the lifetime of the system.

        Returns:
            list:
                The complete list of usage privileges.

        Example:
            [
                {
                "deleted": false,
                "id": 2010,
                "name": "Custom View (146)",
                "object_icon": "/cssupport/webdoc/customview.gif",
                "object_name": "Custom View",
                "object_type": 146,
                "restricted": true,
                "type": 4,
                "type_name": "Privilege",
                "usage_id": null,
                "usage_name": null,
                "usage_type": null,
                "usage_type_name": null
                },
                ...
            ]

        """
        request_header = self.request_form_header()

        request_url = self.config()["privileges"] + "/object"

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=REQUEST_TIMEOUT,
            failure_message="Failed to get system usage privileges.",
        )

        if response:
            return response["results"]["data"]

        return None

    # end method definition

    def get_object_privilege(
        self,
        object_type: int,
        update_cache: bool = False,
    ) -> dict | None:
        """Get the usage privilege either based on ID or based on a name.

        The returned values are cached, as they will not change for the lifetime of the system.

        Args:
            object_type (int):
                The object type ID of the object to be fetched
            update_cache (bool, optional):
                Use the cached state of usage privileges if available.
                Dewfault is False.

        Returns:
            dict:
                The privilege data.

        Example:
            ```json
            {
                "deleted": false,
                "id": 2010,
                "name": "Custom View (146)",
                "object_icon": "/cssupport/webdoc/customview.gif",
                "object_name": "Custom View",
                "object_type": 146,
                "restricted": true,
                "type": 4,
                "type_name": "Privilege",
                "usage_id": null,
                "usage_name": null,
                "usage_type": null,
                "usage_type_name": null
            }
            ```

        """

        if update_cache:
            self.logger.debug("Clearing cache for usage privileges.")
            self.get_object_privileges.cache_clear()

        all_privileges = self.get_object_privileges()

        return next(
            (priv for priv in all_privileges if priv.get("object_type", "") == object_type),
            None,
        )

    # end method definition

    def assign_object_privilege(self, object_type: str, member_id: int, auto_restrict: bool = True) -> dict | None:
        """Assign a usage privilege to a user or group.

        Args:
            object_type (str):
                The ID of the object type to the member_id should be added to.
            member_id (int):
                The ID of user or group that the privilege should be given to.
            auto_restrict (bool, optional):
                automatically restrict the usage privilege, if it is unrestricted

        Returns:
            dict | None:
                The privilege data / response.

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/members/2393/members',
                            'method': 'POST',
                            'name': ''
                        }
                    }
                },
                'results': {}
            }
            ```

        """

        # Provide the provided argument as ID and Name to find the privilege
        privilege = self.get_object_privilege(object_type=object_type)

        if not privilege:
            self.logger.warning(
                "Object Type privilege -> '%s' could not be found. Cannot assign privilege to member -> %s.",
                object_type,
                member_id,
            )

            return None

        privilege_id = privilege.get("id", None) if privilege else None

        # Check if identified privilege is restricted - if not restrict it and set ID from response
        if auto_restrict and privilege_id is None and privilege["restricted"] is False:
            result = self.update_privilege(privilege_id=object_type, restricted=True)
            if result:
                privilege_id = result.get(
                    "id",
                    None,
                )

        if privilege_id:
            self.logger.info(
                "Assigning member with ID -> %s to object privilege -> '%s' (%s)",
                member_id,
                object_type,
                privilege_id,
            )
            return self.add_group_member(member_id=member_id, group_id=privilege_id)

        self.logger.warning(
            "Cannot add member with ID -> %s to object privilege -> '%s'. Object Type is likely unrestricted.",
            member_id,
            object_type,
        )
        return None

    # end method definition

    def get_node(
        self,
        node_id: int,
        fields: (str | list) = "properties",  # per default we just get the most important information
        metadata: bool = False,
        timeout: int = REQUEST_TIMEOUT,
    ) -> dict | None:
        """Get a node based on the node ID.

        Args:
            node_id (int):
                The ID of the node to retrieve.
            fields (str | list, optional):
                Which fields to retrieve. This can have a significant impact on performance.
                Possible fields include:
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "categories"
                - "versions" (can be further restricted by specifying ".element(0)"
                  to retrieve only the latest version)
                - "permissions" (can be further restricted by specifying ".limit(5)"
                  to retrieve only the first 5 permissions)

                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".
            metadata (bool, optional):
                If True, returns metadata (data type, field length, min/max values, etc.)
                about the data.
                The metadata will be returned under `results.metadata`, `metadata_map`,
                and `metadata_order`.
                Defaults to False.
            timeout (int, optional):
                Timeout for the request in seconds. Defaults to `REQUEST_TIMEOUT`.

        Returns:
            dict | None:
                Node information as a dictionary, or None if no node with the
                given ID is found.

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/nodes/576204?fields=properties',
                            'method': 'GET',
                            'name': ''
                        }
                    }
                },
                'results': {
                    'data': {
                        'properties': {
                            'advanced_versioning': None,
                            'container': True,
                            'container_size': 0,
                            'create_date': '2025-01-19T06:57:04Z',
                            'create_user_id': 1000,
                            'description':
                            'Test Description',
                            'description_multilingual': {...},
                            'external_create_date': '2025-01-18T12:33:27',
                            'external_identity': '',
                            'external_identity_type': '',
                            'external_modify_date':
                            '2025-01-19T14:57:01',
                            'external_source': '',
                            'favorite': False,
                            'hidden': False,
                            'icon': '/cssupport/webdoc/folder.gif',
                            'icon_large': '/cssupport/webdoc/folder_large.gif',
                            'id': 576204,
                            'mime_type': None,
                            'modify_date': '2025-01-19T06:57:04Z',
                            'modify_user_id': 1000,
                            'name': 'Test',
                            'name_multilingual': {'ar': '', 'de': '', 'en': 'Test', 'es': '', 'fr': '', 'it': '', 'iw': '', 'ja': '', 'nl': ''},
                            'owner': 'Admin',
                            'owner_group_id': 999,
                            'owner_user_id': 1000,
                            'parent_id': 2004,
                            'permissions_model':
                            'advanced',
                            'reserved': False,
                            'reserved_date': None,
                            'reserved_shared_collaboration': False,
                            'reserved_user_id': 0,
                            'size': 0,
                            'size_formatted': '0 Items',
                            'status': None,
                            'type': 0,
                            'type_name': 'Folder',
                            'versionable': False,
                            'versions_control_advanced': False,
                            'volume_id': -2004
                        }
                    }
                }
            }
            ```

        """

        query = {}
        if fields:
            query["fields"] = fields

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "?{}".format(encoded_query)

        if metadata:
            request_url += "&metadata"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get node with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=timeout,
            failure_message="Failed to get node with ID -> {}".format(node_id),
        )

    # end method definition

    def get_node_by_parent_and_name(
        self,
        parent_id: int,
        name: str,
        fields: str | list = "properties",
        show_error: bool = False,
        exact_match: bool = True,
    ) -> dict | None:
        """Get a node based on the parent ID and name.

        This method queries using "where_name", and the result is returned as a list.

        Args:
            parent_id (int):
                The ID of the parent node.
            name (str):
                The name of the node to retrieve.
            fields (str | list, optional):
                Which fields to retrieve.
                This can have a significant impact on performance.
                Possible fields include:
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "categories"
                - "versions" (can be further restricted by specifying ".element(0)" to
                  retrieve only the latest version)
                - "permissions" (can be further restricted by specifying ".limit(5)" to
                  retrieve only the first 5 permissions)

                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".
            show_error (bool, optional):
                If True, the function treats the absence of the node as an error.
                Defaults to False.
            exact_match (bool, optional):
                If True, only an exact match of the node name is considered.
                Defaults to True.

        Returns:
            dict | None:
                Node information as a dictionary, or None if no node with the given name
                is found under the specified parent.
                To access the node ID, use:
                `response["results"][0]["data"]["properties"]["id"]`.

        """

        # Add query parameters (these are NOT passed via request body!)
        query = {"where_name": name, "limit": 100}
        if fields:
            query["fields"] = fields
        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["nodesUrlv2"] + "/" + str(parent_id) + "/nodes?{}".format(encoded_query)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get node with name -> '%s' and parent ID -> %s; calling -> %s",
            name,
            str(parent_id),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            warning_message="Node with name -> '{}' and parent ID -> {} does not exist".format(
                name,
                parent_id,
            ),
            failure_message="Failed to get node with name -> '{}' and parent ID -> {}".format(
                name,
                parent_id,
            ),
            show_error=show_error,
        )

        # Filter results for exact matches only
        if response and exact_match:
            results = response.get("results", [])
            filtered_results = next(
                (node for node in results if node.get("data", {}).get("properties", {}).get("name") == name),
                None,
            )

            response["results"] = [] if filtered_results is None else [filtered_results]

        return response

    # end method definition

    def get_node_by_workspace_and_path(
        self,
        workspace_id: int,
        path: list,
        create_path: bool = False,
        show_error: bool = False,
    ) -> dict | None:
        """Get a node based on the workspace ID (= node ID) and path (list of folder names).

        Args:
            workspace_id (int): node ID of the workspace
            path (list):
                A list of container items (top down).
                The last item is name of to be retrieved item.
                If path is empty the node of the volume is returned.
            create_path (bool):
                Whether or not missing folders in the path should be created.
            show_error (bool, optional):
                If True, treat as error if node is not found.

        Returns:
            dict | None:
                Node information or None if no node with this path is found.

        """

        parent_item_id = workspace_id

        # in case the path is an empty list
        # we will have the node of the workspace:
        node = self.get_node(parent_item_id)

        for path_element in path:
            node = self.get_node_by_parent_and_name(parent_item_id, path_element)
            current_item_id = self.get_result_value(response=node, key="id")
            if not current_item_id:
                if create_path:
                    # create missing path element:
                    response = self.create_item(
                        parent_id=parent_item_id,
                        item_type=self.ITEM_TYPE_FOLDER,
                        item_name=path_element,
                        show_error=False,
                    )
                    # We may have a race condition here -
                    # another thread may have created the folder in parallel:
                    if not response:
                        self.logger.warning(
                            "Cannot create folder -> '%s' in workspace with ID -> %s (path -> %s), it may already exist (race condition). Try to get it...",
                            path_element,
                            workspace_id,
                            str(path),
                        )
                        response = self.get_node_by_parent_and_name(
                            parent_id=parent_item_id,
                            name=path_element,
                            show_error=True,
                        )
                        if not response:
                            if show_error:
                                self.logger.error(
                                    "Cannot create path element -> %s!",
                                    path_element,
                                )
                            else:
                                self.logger.debug(
                                    "Cannot create path element -> %s.",
                                    path_element,
                                )
                            return None
                    # now we set current item ID to the new response:
                    current_item_id = self.get_result_value(response=response, key="id")
                    node = response
                # end if create_path
                else:
                    if show_error:
                        self.logger.error(
                            "Cannot find path element -> '%s'!",
                            path_element,
                        )
                    else:
                        self.logger.debug(
                            "Cannot find path element -> '%s'",
                            path_element,
                        )
                    return None
            self.logger.debug(
                "Traversing path element -> '%s' (%s)",
                path_element,
                str(current_item_id),
            )
            parent_item_id = current_item_id

        return node

    # end method definition

    def get_node_by_volume_and_path(
        self,
        volume_type: int,
        path: list | None = None,
        create_path: bool = False,
        show_error: bool = False,
    ) -> dict | None:
        """Get a node based on the volume and path (list of container items).

        Args:
            volume_type (int): Volume type ID (default is 141 = Enterprise Workspace)
                "Records Management"                = 550
                "Content Server Document Templates" = 20541
                "O365 Office Online Volume"         = 1296
                "Categories Volume"                 = 133
                "Perspectives"                      = 908
                "Perspective Assets"                = 954
                "Facets Volume"                     = 901
                "Transport Warehouse"               = 525
                "Transport Warehouse Workbench"     = 528
                "Transport Warehouse Package"       = 531
                "Event Action Center Configuration" = 898
                "Classification Volume"             = 198
                "Support Asset Volume"              = 1309
                "Physical Objects Workspace"        = 413
                "Extended ECM"                      = 882
                "Enterprise Workspace"              = 141
                "Personal Workspace"                = 142
                "Business Workspaces"               = 862
            path (list):
                A list of container items (top down),
                last item is name of to be retrieved item.
                If path is empty the node of the volume is returned.
            create_path (bool):
                if path elements are missing: should they be created?
            show_error (bool, optional):
                If True, treat as error if node is not found.

        Returns:
            dict | None:
                Node information or None if no node with this path is found.

        """

        # If path is not given we use empty list to make
        # the for loop below working in this case as well:
        if path is None:
            path = []

        # Preparation: get volume IDs for Transport Warehouse
        # (root volume and Transport Packages)
        response = self.get_volume(volume_type)
        if not response:
            self.logger.error("Volume type -> %s not found!", str(volume_type))
            return None

        volume_id = self.get_result_value(response=response, key="id")
        self.logger.debug(
            "Volume type -> %s has node ID -> %s",
            str(volume_type),
            str(volume_id),
        )

        current_item_id = volume_id

        # in case the path is an empty list
        # we will have the node of the volume:
        node = self.get_node(current_item_id)

        for path_element in path:
            node = self.get_node_by_parent_and_name(current_item_id, path_element)
            path_item_id = self.get_result_value(response=node, key="id")
            if not path_item_id and create_path:
                node = self.create_item(
                    parent_id=current_item_id,
                    item_type=self.ITEM_TYPE_FOLDER
                    if volume_type != self.VOLUME_TYPE_CLASSIFICATION_VOLUME
                    else self.ITEM_TYPE_CLASSIFICATION
                    if current_item_id != volume_id
                    else self.ITEM_TYPE_CLASSIFICATION_TREE,
                    item_name=path_element,
                )
                path_item_id = self.get_result_value(response=node, key="id")
            if not path_item_id:
                if show_error:
                    self.logger.error(
                        "Cannot find path element -> '%s' in container with ID -> %s!",
                        path_element,
                        str(current_item_id),
                    )
                else:
                    self.logger.debug(
                        "Cannot find path element -> '%s' in container with ID -> %s.",
                        path_element,
                        str(current_item_id),
                    )
                return None
            current_item_id = path_item_id
            self.logger.debug(
                "Traversing path element with ID -> %s",
                str(current_item_id),
            )

        return node

    # end method definition

    def get_node_from_nickname(
        self,
        nickname: str,
        show_error: bool = False,
    ) -> dict | None:
        """Get a node based on the nickname.

        Args:
            nickname (str): The nickname of the node.
            show_error (bool): If True, treat as error if node is not found.

        Returns:
            dict | None:
                Node information or None if no node with this nickname is found.

        """

        request_url = self.config()["nicknameUrl"] + "/" + nickname + "/nodes"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get node with nickname -> '%s'; calling -> %s",
            nickname,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            warning_message="Node with nickname -> '{}' does not exist".format(
                nickname,
            ),
            failure_message="Failed to get node with nickname -> '{}'".format(nickname),
            show_error=show_error,
        )

    # end method definition

    def set_node_nickname(
        self,
        node_id: int,
        nickname: str,
        show_error: bool = False,
    ) -> dict | None:
        """Assign a nickname to an Extended ECM node (e.g. workspace).

        Some naming conventions for the nickname are automatically applied:
        - replace "-" with "_"
        - replace ":" with "_"
        - replace "/" with "_"
        - replace "&" with "_"
        - replace " " with "_"
        - replace "___" with "_"

        Args:
            node_id (int):
                The ID of the node to assign a nickname for.
            nickname (str):
                The to be assigned nickname of the node.
            show_error (bool, optional):
                If True, treat as error if node is not found.

        Returns:
            dict | None:
                Node information or None if nickname icouldn't be set.

        """

        if not nickname:
            return None

        nickname = nickname.replace("-", "_")
        nickname = nickname.replace(":", "_")
        nickname = nickname.replace("/", "_")
        nickname = nickname.replace("&", "_")
        nickname = nickname.replace(" ", "_")
        nickname = nickname.replace("___", "_")

        nickname_put_body = {"nickname": nickname}

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/nicknames"
        request_header = self.request_form_header()

        self.logger.debug(
            "Assign nickname -> '%s' to node with ID -> %s; calling -> %s",
            nickname,
            node_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=nickname_put_body,
            timeout=None,
            warning_message="Cannot assign nickname -> '{}' to node ID -> {}. Maybe the nickname is already in use or the node does not exist.".format(
                nickname,
                node_id,
            ),
            failure_message="Failed to assign nickname -> '{}' to node ID -> {}".format(
                nickname,
                node_id,
            ),
            show_error=show_error,
        )

    # end method definition

    def get_subnodes(
        self,
        parent_node_id: int,
        filter_node_types: int = -2,
        filter_name: str = "",
        show_hidden: bool = False,
        limit: int = 100,
        page: int = 1,
        fields: (str | list) = "properties",  # per default we just get the most important information
        metadata: bool = False,
    ) -> dict | None:
        """Get the subnodes of a given parent node ID.

        Args:
            parent_node_id (int):
                The ID of the parent node.
            filter_node_types (int, optional):
                Type of nodes to filter by. Possible values:
                -1: Get all containers
                -2: Get all searchable objects (default)
                -3: Get all non-containers
            filter_name (str, optional):
                Filter nodes by name. Defaults to no filter.
            show_hidden (bool, optional):
                Whether to list hidden items. Defaults to False.
            limit (int, optional):
                The maximum number of results to return. Defaults to 100.
            page (int, optional):
                The page of results to retrieve. Defaults to 1 (first page).
            fields (str | list, optional):
                Which fields to retrieve.
                This can have a significant impact on performance.
                Possible fields include:
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "categories"
                - "versions" (can be further restricted by specifying ".element(0)"
                  to retrieve only the latest version)
                - "permissions" (can be further restricted by specifying ".limit(5)"
                  to retrieve only the first 5 permissions)
                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".
            metadata (bool, optional):
                Whether to return metadata (data type, field length, min/max values, etc.)
                about the data.
                Metadata will be returned under `results.metadata`, `metadata_map`,
                or `metadata_order`.

        Returns:
            dict | None:
                Subnode information as a dictionary, or None if no nodes with
                the given parent ID are found.
                Example response:
                {
                    "results": [
                        {
                            "data": [
                                {
                                    "columns": [
                                        {
                                            "data_type": 0,
                                            "key": "string",
                                            "name": "string",
                                            "sort_key": "string"
                                        }
                                    ],
                                    "properties": [
                                        {
                                            "advanced_versioning": true,
                                            "container": true,
                                            "container_size": 0,
                                            "create_date": "string",
                                            "create_user_id": 0,
                                            "description": "string",
                                            "description_multilingual": {
                                                "en": "string",
                                                "de": "string"
                                            },
                                            "external_create_date": "2019-08-24",
                                            "external_identity": "string",
                                            "external_identity_type": "string",
                                            "external_modify_date": "2019-08-24",
                                            "external_source": "string",
                                            "favorite": true,
                                            "guid": "string",
                                            "hidden": true,
                                            "icon": "string",
                                            "icon_large": "string",
                                            "id": 0,
                                            "modify_date": "2019-08-24",
                                            "modify_user_id": 0,
                                            "name": "string",
                                            "name_multilingual": {
                                                "en": "string",
                                                "de": "string"
                                            },
                                            "owner": "string",
                                            "owner_group_id": 0,
                                            "owner_user_id": 0,
                                            "parent_id": 0,
                                            "reserved": true,
                                            "reserved_date": "string",
                                            "reserved_user_id": 0,
                                            "status": 0,
                                            "type": 0,
                                            "type_name": "string",
                                            "versionable": true,
                                            "versions_control_advanced": true,
                                            "volume_id": 0
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }

        """

        # Add query parameters (these are NOT passed via JSon body!)
        query = {
            "where_type": filter_node_types,
            "limit": limit,
        }
        if filter_name:
            query["where_name"] = filter_name
        if show_hidden:
            query["show_hidden"] = show_hidden
        if page > 1:
            query["page"] = page
        if fields:
            query["fields"] = fields

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["nodesUrlv2"] + "/" + str(parent_node_id) + "/nodes" + "?{}".format(encoded_query)

        if metadata:
            request_url += "&metadata"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get subnodes of parent node with ID -> %s (page -> %d, item limit -> %d); calling -> %s",
            str(parent_node_id),
            page,
            limit,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get subnodes for parent node with ID -> {}".format(
                parent_node_id,
            ),
        )

    # end method definition

    def get_subnodes_iterator(
        self,
        parent_node_id: int,
        filter_node_types: int = -2,
        filter_name: str = "",
        show_hidden: bool = False,
        fields: (str | list) = "properties",  # per default we just get the most important information
        metadata: bool = False,
        page_size: int = 25,
    ) -> iter:
        """Get an iterator object that can be used to traverse subnodes.

        Filters can be applied that are given by the "filter" parameters.

        Using a generator avoids loading a large number of nodes into memory at once.
        Instead you can iterate over the potential large list of subnodes.

        Example usage:
            ```python
            nodes = otcs_object.get_subnodes_iterator(parent_node_id=15838)
            for node in nodes:
                logger.info("Node name -> '%s'", node["data"]["properties"]["name"])
            ```

        Args:
            parent_node_id (int):
                The ID of the parent node (typically a folder or workspace).
            filter_node_types (int, optional):
                The type of nodes to filter by. Possible values:
                -1: Get all containers
                -2: Get all searchable objects (default)
                -3: Get all non-containers
            filter_name (str, optional):
                Filter nodes by name. Defaults to no filter.
            show_hidden (bool, optional):
                Whether to list hidden items. Defaults to False.
            fields (str | list, optional):
                Which fields to retrieve. This can have a significant impact
                on performance.
                Possible fields include:
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "categories"
                - "versions" (can be further restricted by specifying ".element(0)" to
                  retrieve only the latest version)
                - "permissions" (can be further restricted by specifying ".limit(5)" to
                  retrieve only the first 5 permissions)
                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".
            metadata (bool, optional):
                Whether to return metadata (data type, field length, min/max values,...)
                about the data.
                Metadata will be returned under `results.metadata`, `metadata_map`,
                or `metadata_order`.
            page_size (int, optional):
                The number of subnodes that are requested per page.
                For the iterator this is basically the chunk size.

        Returns:
            iter:
                A generator yielding one node per iteration under the parent.
                If the REST API fails, returns no value.

                Example return value:
                {
                    'data': {
                        'properties': {
                            'advanced_versioning': False,
                            'container': False,
                            'container_size': 0,
                            'create_date': '2005-10-06T23:07:40Z',
                            'create_user_id': 17984548,
                            'description': 'LL4DM and RM',
                            'description_multilingual': {'en_US': 'LL4DM and RM'},
                            'external_create_date': None,
                            'external_identity': '',
                            'external_identity_type': '',
                            'external_modify_date': None,
                            'external_source': '',
                            'favorite': False,
                            'hidden': False,
                            'icon': '/img/webdoc/appword.gif',
                            'icon_large': '/img/webdoc/appword_large.gif',
                            'id': 22794834,
                            'mime_type': 'application/msword',
                            'modify_date': '2011-08-18T19:52:22Z',
                            'modify_user_id': 13527115,
                            'name': ' Proposal Executive Summary - 2005 - Document Management',
                            'name_multilingual': {'en_US': ' Proposal Executive Summary - 2005 - Document Management'},
                            'owner': 'Cheri M',
                            'owner_group_id': 2284384,
                            'owner_user_id': 39242242,
                            'parent_id': 37596275,
                            'permissions_model': 'advanced',
                            'preferred_rendition_type': [''],
                            'reserved': False,
                            'reserved_date': None,
                            'reserved_shared_collaboration': False,
                            'reserved_user_id': 0,
                            'size': 409088,
                            'size_formatted': '400 KB',
                            'status': None,
                            'type': 144,
                            'type_name': 'Document',
                            'versionable': True,
                            'versions_control_advanced': False,
                            'volume_id': -2001,
                        }
                    }
                }

        """

        response = self.get_node(node_id=parent_node_id)
        container_size = self.get_result_value(response=response, key="size")
        if not container_size:
            self.logger.debug(
                "Container with parent node ID -> %s is empty! Cannot iterate sub items.",
                str(parent_node_id),
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        # If the container has many items we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (container_size + page_size - 1) // page_size

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.get_subnodes(
                parent_node_id=parent_node_id,
                filter_node_types=filter_node_types,
                filter_name=filter_name,
                show_hidden=show_hidden,
                limit=page_size,
                page=page,
                fields=fields,
                metadata=metadata,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve sub nodes for parent node ID -> %d (page -> %d)",
                    parent_node_id,
                    page,
                )
                return None

            # Yield nodes one at a time
            yield from response["results"]

        # end for page in range(1, total_pages + 1)

    # end method definition

    def lookup_node(
        self,
        parent_node_id: int,
        category: str,
        attribute: str,
        value: str,
        attribute_set: str | None = None,
    ) -> dict | None:
        """Lookup the node under a parent node that has a specified value in a category attribute.

        Args:
            parent_node_id (int):
                The node ID of the parent (typically folder or workspace).
            category (str):
                The name of the category.
            attribute (str):
                The name of the attribute that includes the value to match with
            value (str):
                The lookup value that is matched agains the node attribute value.
            attribute_set (str, optional):
                The name of the attribute set

        Returns:
            dict | None:
                Node wrapped in dictionary with "results" key or None if the REST API fails.

        """

        # get_subnodes_iterator() returns a python generator that we use for iterating over all nodes
        # in an efficient way avoiding to retrieve all nodes at once (which could be a large number):
        for node in self.get_subnodes_iterator(
            parent_node_id=parent_node_id,
            fields=["properties", "categories"],
            metadata=True,
        ):
            node_name = self.get_result_value(node, "name")
            node_id = self.get_result_value(node, "id")
            schema = node["metadata"]["categories"]
            # Get the the matching category. For this we check that the name
            # of the first dictionary (representing the category itself) has
            # the requested name:
            category_schema = next(
                (cat_elem for cat_elem in schema if next(iter(cat_elem.values()), {}).get("name") == category),
                None,
            )
            if not category_schema:
                self.logger.debug(
                    "Node -> '%s' (%s) does not have category -> '%s'. Cannot lookup -> '%s'. Skipping...",
                    node_name,
                    node_id,
                    category,
                    value,
                )
                continue
            category_key = next(iter(category_schema))

            attribute_schema = next(
                (cat_elem for cat_elem in category_schema.values() if cat_elem.get("name") == attribute),
                None,
            )
            if not attribute_schema:
                self.logger.debug(
                    "Node -> '%s' (%s) does not have attribute -> '%s'. Skipping...",
                    node_name,
                    node_id,
                    attribute,
                )
                continue
            attribute_key = attribute_schema["key"]
            attribute_id = attribute_key.rsplit("_", 1)[-1]

            if attribute_set:
                set_schema = next(
                    (
                        cat_elem
                        for cat_elem in category_schema.values()
                        if cat_elem.get("name") == attribute_set and cat_elem.get("persona") == "set"
                    ),
                    None,
                )
                if not set_schema:
                    self.logger.debug(
                        "Node -> '%s' (%s) does not have attribute set -> '%s'. Skipping...",
                        node_name,
                        node_id,
                        attribute_set,
                    )
                    continue
                set_key = set_schema["key"]
            else:
                set_schema = None
                set_key = None

            prefix = set_key + "_" if set_key else category_key + "_"

            data = node["data"]["categories"]
            for cat_data in data:
                if set_key:
                    for i in range(1, int(set_schema["multi_value_length_max"])):
                        key = prefix + str(i) + "_" + attribute_id
                        attribute_value = cat_data.get(key)
                        if not attribute_value:
                            break
                        if isinstance(attribute_value, list):
                            if value in attribute_value:
                                # Create a "results" dict that is compatible with normal REST calls
                                # to not break get_result_value() method that may be called on the result:
                                return {"results": node}
                        elif value == attribute_value:
                            # Create a results dict that is compatible with normal REST calls
                            # to not break get_result_value() method that may be called on the result:
                            return {"results": node}
                else:
                    key = prefix + attribute_id
                    attribute_value = cat_data.get(key)
                    if not attribute_value:
                        break
                    if isinstance(attribute_value, list):
                        if value in attribute_value:
                            # Create a "results" dict that is compatible with normal REST calls
                            # to not break get_result_value() method that may be called on the result:
                            return {"results": node}
                    elif value == attribute_value:
                        # Create a results dict that is compatible with normal REST calls
                        # to not break get_result_value() method that may be called on the result:
                        return {"results": node}
            # end for cat_data, cat_schema in zip(data, schema)
        # end for node in nodes

        self.logger.debug(
            "Couldn't find a node with the value -> '%s' in the attribute -> '%s' of category -> '%s' in parent with node ID -> %s.",
            value,
            attribute,
            category,
            parent_node_id,
        )

        return {"results": []}

    # end method definition

    def lookup_node_old(
        self,
        parent_node_id: int,
        category: str,
        attribute: str,
        value: str,
    ) -> dict | None:
        """Lookup the node under a parent node that has a specified value in a category attribute.

        Args:
            parent_node_id (int):
                The node ID of the parent (typically folder or workspace).
            category (str):
                The name of the category.
            attribute (str):
                The name of the attribute that includes the value to match with
            value (str):
                The lookup value that is matched agains the node attribute value.

        Returns:
            dict | None:
                Node wrapped in dictionary with "results" key or None if the REST API fails.

        """

        # get_subnodes_iterator() returns a python generator that we use for iterating over all nodes
        # in an efficient way avoiding to retrieve all nodes at once (which could be a large number):
        for node in self.get_subnodes_iterator(
            parent_node_id=parent_node_id,
            fields=["properties", "categories"],
            metadata=True,
        ):
            schema = node["metadata"]["categories"]
            data = node["data"]["categories"]
            for cat_data, cat_schema in zip(data, schema, strict=False):
                data_values = list(cat_data.values())
                schema_values = list(cat_schema.values())
                # Schema has one additional element (the first one) representing
                # the category object itself. This includes the name. We need
                # to remove (pop) it from the schema list to make sure the schema list
                # and the data list have the same number of items. Otherwise
                # the following for loop with zip() would not properly align the
                # two lists:
                category_name = schema_values.pop(0)["name"]
                # Set attributes (standing for the set itself, not it's contained attributes)
                # are only in the schema values, not in the data values. We need to remove
                # them as well to avoid mis-alignment:
                schema_values = [schema_value for schema_value in schema_values if schema_value.get("persona") != "set"]
                if category_name == category:
                    for attr_data, attr_schema in zip(
                        data_values,
                        schema_values,
                        strict=False,
                    ):
                        attr_name = attr_schema["name"]
                        if attr_name == attribute:
                            if isinstance(attr_data, list):
                                if value in attr_data:
                                    # Create a "results" dict that is compatible with normal REST calls
                                    # to not break get_result_value() method that may be called on the result:
                                    return {"results": node}
                            elif value == attr_data:
                                # Create a results dict that is compatible with normal REST calls
                                # to not break get_result_value() method that may be called on the result:
                                return {"results": node}
                    # we can break here and continue with the next node
                    # as we had the right category but did not find the matching value
                    break
            # end for cat_data, cat_schema in zip(data, schema)
        # end for node in nodes

        self.logger.debug(
            "Couldn't find a node with the value -> '%s' in the attribute -> '%s' of category -> '%s' in parent with node ID -> %s.",
            value,
            attribute,
            category,
            parent_node_id,
        )

        return None

    # end method definition

    def lookup_node_by_regex(
        self,
        parent_node_id: int,
        regex_list: list,
    ) -> dict | None:
        """Lookup the node under a parent node that has a name that matches on of the given regular expressions.

        Args:
            parent_node_id (int):
                The node ID of the parent (typically folder or workspace).
            regex_list (list):
                A list of regular expression the item name should match.

        Returns:
            dict | None:
                Node wrapped in dictionary with "results" key or None if the REST API fails.

        """

        # get_subnodes_iterator() returns a python generator that we use for iterating
        # over all nodes in an efficient way avoiding to retrieve all nodes at once
        # (which could be a large number):
        for node in self.get_subnodes_iterator(
            parent_node_id=parent_node_id,
            fields=["properties"],
            metadata=False,
        ):
            node_name = node["data"]["properties"]["name"]
            # Check if the node name matches any of the given regular expressions:
            for regex in regex_list:
                if re.match(regex, node_name):
                    self.logger.debug(
                        "Node with name -> '%s' under parent with ID -> %s matches regular expression -> %s",
                        node_name,
                        parent_node_id,
                        regex,
                    )
                    return {"results": node}
            # end for regex in regex_list
        # end for node in self.get_subnodes_iterator()

        self.logger.warning(
            "Couldn't find a node under parent with node ID -> %s that has a name matching any of these regular expressions -> %s",
            parent_node_id,
            str(regex_list),
        )

        return None

    # end method definition

    def get_node_columns(self, node_id: int) -> dict | None:
        """Get custom columns configured / enabled for a node.

        Args:
            node_id (int):
                The ID of the Node.

        Returns:
            dict | None:
                Information of the Node columns or None if the request fails.

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'results': {
                    'columns_to_display': {
                        'global_columns': ['Type', 'Name', 'Size', 'Modified'],
                        'inherited_columns': [
                            {
                                'id': 6270,
                                'name': 'Title',
                                'locked': False,
                                'default': False,
                                'has_permission': True,
                                'location_id': 6271,
                                'displayed': False,
                                'location_name': 'Knowledge Base Articles'
                            },
                            {
                                'id': 13076,
                                'name': 'Published Date',
                                'locked': False,
                                'default': False,
                                'has_permission': True,
                                'location_id': 6271,
                                'displayed': False,
                                'location_name': 'Knowledge Base Articles'
                            },
                            {
                                'id': 6248,
                                'name': 'Valid To Date',
                                'locked': False,
                                'default': False,
                                'has_permission': True,
                                'location_id': 6271,
                                'displayed': False,
                                'location_name': 'Knowledge Base Articles'
                            },
                            ...
                        ],
                        'local_columns': {
                            'available_columns': [
                                {
                                    'id': 13072,
                                    'name': 'Application',
                                    'default': False
                                },
                                {
                                    'id': 6288,
                                    'name': 'Approved Usage',
                                    'default': False
                                },
                                {
                                    'id': 6262,
                                    'name': 'Business Function',
                                    'default': False
                                },
                                ...
                            ],
                            'displayed_columns': [...]
                        }
                    },
                    'columns_to_sort': {
                        'inherited_sort': {
                            'column_id': None,
                            'column_name': None,
                            'sort_direction': None
                        },
                        'local_sort': {
                            'local_sort_column': [
                                {
                                    'value': 13072,
                                    'name': 'Application',
                                    'selected': False
                                },
                                {
                                    'value': 6288,
                                    'name': 'Approved Usage',
                                    'selected': False
                                },
                                ...
                            ],
                            'local_sort_order': [...]
                        }
                    }
                }
            }
            ```

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/columns"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get columns for node with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get columns for node with ID -> {}".format(
                node_id,
            ),
        )

    # end method definition

    def get_node_actions(
        self,
        node_id: int | list,
        filter_actions: list | None = None,
    ) -> dict | None:
        """Get allowed actions for a node.

        Args:
            node_id (int | list):
                ID(s) of the Node(s). This can either be int (= single node)
                or a list of nodes.
            filter_actions (list, optional):
                Optional list of actions to filter for, e.g. "delete", "copy",
                "permissions", "makefavorite", "open", "collect", "audit", ...

        Returns:
            dict | None:
                Information of the Node actions or None if the request fails.
                "results" is a dictionary with Node IDs as keys, and three
                sub-sictionaries "data", "map", and "order.

        Example:
            ```json
            {
                'links': {'data': {...}},
                'results': {
                    '173301412': {
                        'data': {
                            'AddRMClassifications': {
                                'body': '{
                                    "displayPrompt":false,
                                    "enabled":false,
                                    "inheritfrom":false,
                                    "managed":true
                                }',
                                'content_type': 'application/x-www-form-urlencoded',
                                'form_href': '',
                                'href': '/api/v2/nodes/164878074/rmclassifications',
                                'method': 'POST',
                                'name': 'Add RM Classification'
                            },
                            'audit': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '/api/v2/nodes/164878074/audit?limit=1000',
                                'method': 'GET',
                                'name': 'Audit'
                            },
                            'BrowseClassifiedItems': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '/api/v2/nodes/164878074/nodes',
                                'method': 'GET',
                                'name': 'Browse classified items'
                            },
                            'BrowseRecManContainer': {
                                'body': '',
                                'content_type': 'application/x-www-form-urlencoded',
                                'form_href': '',
                                'href': '',
                                'method': '',
                                'name': ''
                            },
                            'collect': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '/api/v2/nodes/164878074',
                                'method': 'PUT',
                                'name': 'Collect'
                            },
                            'copy': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '/api/v2/nodes',
                                'method': 'POST',
                                'name': 'Copy'
                            },
                            'makefavorite': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '/api/v2/members/favorites/164878074',
                                'method': 'POST',
                                'name': 'Add to Favorites'
                            },
                            'more': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '',
                                'method': '',
                                'name': '...'
                            },
                            'open': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '/api/v2/nodes/164878074/nodes',
                                'method': 'GET',
                                'name': 'Open'
                            },
                            'permissions': {
                                'body': '',
                                'content_type': '',
                                'form_href': '',
                                'href': '',
                                'method': '',
                                'name': 'Permissions'
                            },
                            ...
                        'map': {...},
                        'order': [...]
                    }
                }
            ```

        """

        if isinstance(node_id, list):
            actions_post_body = {"ids": node_id, "actions": filter_actions}
        else:
            actions_post_body = {"ids": [node_id], "actions": filter_actions}

        request_url = self.config()["nodesUrlv2"] + "/actions"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get actions for node(s) with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=actions_post_body,
            timeout=None,
            failure_message="Failed to get actions for node with ID -> {}".format(
                node_id,
            ),
        )

    # end method definition

    def rename_node(
        self,
        node_id: int,
        name: str,
        description: str,
        name_multilingual: dict | None = None,
        description_multilingual: dict | None = None,
    ) -> dict | None:
        """Change the name and description of a node.

        Args:
            node_id (int):
                ID of the node. You can use the get_volume() function below to
                to the node id for a volume.
            name (str): New name of the node.
            description (str): New description of the node.
            name_multilingual (dict, optional): multi-lingual node names
            description_multilingual (dict, optional): multi-lingual description

        Returns:
            dict | None: Request response or None if the renaming fails.

        """

        rename_node_put_body = {"name": name, "description": description}

        if name_multilingual:
            rename_node_put_body["name_multilingual"] = name_multilingual
        if description_multilingual:
            rename_node_put_body["description_multilingual"] = description_multilingual

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Rename node with ID -> %s to -> '%s'; calling -> %s",
            str(node_id),
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data={"body": json.dumps(rename_node_put_body)},
            timeout=None,
            failure_message="Failed to rename node with ID -> {} to -> '{}'".format(
                node_id,
                name,
            ),
        )

    # end method definition

    def delete_node(self, node_id: int, purge: bool = False) -> dict | None:
        """Delete an existing node.

        Args:
            node_id (int):
                The ID of the node to be deleted.
            purge (bool, optional):
                If True, immediately purge the item from the recycle bin.

        Returns:
            dict | None:
                The response of the REST call; None in case of a failure.

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/nodes/576093',
                            'method': 'DELETE',
                            'name': ''
                        }
                    }
                },
                'results': {}
            }
            ```

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Delete node with ID -> %s%s; calling -> %s",
            str(node_id),
            " (with immediate purging from recycle bin)" if purge else "",
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=None,
            failure_message="Failed to delete node with ID -> {}".format(node_id),
        )

        # Do we want to immediately purge it from the Recycle Bin?
        if response and purge:
            self.purge_node(node_id)

        return response

    # end method definition

    def purge_node(self, node_id: int | list) -> dict | None:
        """Purge an item in the recycle bin (final destruction).

        Args:
            node_id (int | list):
                ID(s) of the node(s) to be finally deleted.

        """

        request_url = self.config()["recycleBinUrl"] + "/nodes/purge"
        request_header = self.request_form_header()

        # Make it a list if it is not yet a list:
        purge_data = {"ids": node_id} if isinstance(node_id, list) else {"ids": [node_id]}

        self.logger.debug(
            "Purge node(s) with ID(s) -> %s from recycle bin; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=purge_data,
            timeout=None,
            failure_message="Failed to purge node with ID -> {} from the recycle bin".format(
                node_id,
            ),
        )

    # end method definition

    def restore_node(self, node_id: int | list) -> dict | None:
        """Restore an item from the recycle bin (undo deletion).

        Args:
            node_id (int | list):
                ID(s) of the node(s) to be restored.

        Results:
            dict | None:
                Dictionary include key 'success' with the successful restored IDs.

        Example:
            ```json
            {
                'failure': {
                    'errors': {}, 'ids': [...]
                },
                'success': {
                    'ids': [...]
                }
            }
            ```

        """

        request_url = self.config()["recycleBinUrl"] + "/nodes/restore"
        request_header = self.request_form_header()

        restore_data = {"ids": node_id} if isinstance(node_id, list) else {"ids": [node_id]}

        self.logger.debug(
            "Restore node(s) with ID(s) -> %s from recycle bin; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=restore_data,
            timeout=None,
            failure_message="Failed to restore node(s) with ID(s) -> {} from the recycle bin".format(
                node_id,
            ),
        )

    # end method definition

    def get_volumes(self) -> dict | None:
        """Get all Volumes.

        Args:
            None

        Returns:
            dict | None:
                Volume Details or None if an error occured.

        Exmaple:
            {
                'links': {
                    'data': {...}
                },
                'results': [
                    {
                        'data': {
                            'properties': {
                                'advanced_versioning': None,
                                'container': True,
                                'container_size': 16,
                                'create_date': '2023-05-07T23:18:50Z',
                                'create_user_id': 1000,
                                'description': '',
                                'description_multilingual': {'de': '', 'en': '', 'fr': '', 'it': '', 'ja': ''},
                                'external_create_date': None,
                                'external_identity': '',
                                'external_identity_type': '',
                                'external_modify_date': None,
                                'external_source': '',
                                'favorite': False,
                                'hidden': False,
                                ...
                                'id': 2000,
                                ...
                                'name': 'Enterprise',
                                'name_multilingual': {'de': '', 'en': 'Enterprise', 'fr': '', 'it': '', 'ja': ''},
                                ...
                                'parent_id': -1,
                                'type': 141,
                                'volume_id': -2000,
                                ...
                            }
                            ...
                        }
                    },
                    ...
                ]
            }
            Usage:
            ["results"][0]["data"]["properties"]["id"] is the node ID of the volume.

        """

        request_url = self.config()["volumeUrl"]
        request_header = self.request_form_header()

        self.logger.debug("Get all volumes; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get volumes",
        )

    # end method definition

    @cache
    def get_volume(
        self,
        volume_type: int,
        timeout: int = REQUEST_TIMEOUT,
    ) -> dict | None:
        """Get Volume information based on the volume type ID.

        Args:
            volume_type (int): ID of the volume type
            timeout (int, optional): timeout for the request in seconds

        Returns:
            dict | None: Volume Details or None if volume is not found.

        Example:
            ["results"]["data"]["properties"]["id"] is the node ID of the volume.

        """

        request_url = self.config()["volumeUrl"] + "/" + str(volume_type)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get volume type -> %s; calling -> %s",
            str(volume_type),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=timeout,
            failure_message="Failed to get volume of type -> {}".format(volume_type),
        )

    # end method definition

    def check_node_name(self, parent_id: int, node_name: str) -> dict | None:
        """Check if a node with a given name already exists under a specified parent node.

        Args:
            parent_id (int):
                The ID of the parent node (location).
            node_name (str):
                The name of the node to check for existence.

        Returns:
            dict | None:
                If `response["results"]` contains an element,
                the node with the given name exists.
                If `response["results"]` is empty, the node does not exist.
                Returns None in case of an error.

        Example:
            ```json
            {
                'results': [
                    {
                        'name': 'opentext-image-fi-dana-gas-en.jpg',
                        'id': 87221
                    }
                ]
            }
            ```

        """

        request_url = self.config()["validationUrl"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Check if node with name -> '%s' can be created in parent with ID -> %s; calling -> %s",
            node_name,
            str(parent_id),
            request_url,
        )

        check_node_name_post_data = {"parent_id": parent_id, "names": [node_name]}

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(check_node_name_post_data)},
            timeout=None,
            failure_message="Failed to check if node name -> '{}' can be created in parent with ID -> {}".format(
                node_name,
                parent_id,
            ),
        )

    # end method definition

    def upload_file_to_volume(
        self,
        volume_type: int,
        path_or_url: str,
        file_name: str,
        mime_type: str | None = None,
    ) -> dict | None:
        """Fetch a file from a URL or local filesystem and upload it to a Content Server volume.

        Args:
            volume_type (int):
                The type (ID) of the volume.
            path_or_url (str):
                The URL or path to file to upload.
            file_name (str):
                The name of the file.
            mime_type (str | None, optional):
                The mime type of the file (e.g., 'application/pdf').
                If the mime type is not provided the method tries to "guess"
                the mime type.

        Returns:
            dict | None: Upload response or None if the upload fails.

        """

        if not file_name:
            self.logger.error("Missing file name! Cannot upload file.")
            return None

        # Make sure we don't have leading or trailing whitespace:
        file_name = file_name.strip()

        if path_or_url.startswith("http"):
            # Download file from remote location specified by the packageUrl
            # this must be a public place without authentication:
            self.logger.debug("Download file from URL -> %s", path_or_url)

            try:
                package = requests.get(url=path_or_url, timeout=1200)
                package.raise_for_status()
            except requests.exceptions.HTTPError as http_error:
                self.logger.error("HTTP error requesting -> %s; error -> %s", path_or_url, str(http_error))
                return None
            except requests.exceptions.ConnectionError:
                self.logger.error("Connection error requesting -> %s", path_or_url)
                return None
            except requests.exceptions.Timeout:
                self.logger.error("Timeout error requesting -> %s", path_or_url)
                return None
            except requests.exceptions.RequestException:
                self.logger.error("Request error requesting -> %s", path_or_url)
                return None

            self.logger.debug(
                "Successfully downloaded file from URL -> '%s'; status code -> %s",
                path_or_url,
                package.status_code,
            )
            file_content = package.content

        elif os.path.exists(path_or_url):
            self.logger.debug("Uploading local file -> '%s'", path_or_url)
            file_content = open(file=path_or_url, mode="rb")  # noqa: SIM115

        else:
            self.logger.warning("Cannot access file -> '%s'", path_or_url)
            return None

        upload_post_data = {"type": str(volume_type), "name": file_name}

        if not mime_type:
            mime_type, _ = mimetypes.guess_type(path_or_url)

        if not mime_type and magic_installed:
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(path_or_url)
            except Exception:
                self.logger.error(
                    "Unknown mime type for document -> '%s' for upload to volume -> %s",
                    file_name,
                    str(volume_type),
                )

        upload_post_files = [("file", (f"{file_name}", file_content, mime_type))]

        request_url = self.config()["nodesUrlv2"]

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Upload package -> '%s' with mime type -> '%s'; calling -> %s",
            file_name,
            mime_type,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=upload_post_data,
            files=upload_post_files,
            timeout=None,
            failure_message="Failed to upload file -> '{}' to volume of type -> {}".format(
                path_or_url,
                volume_type,
            ),
        )

    # end method definition

    def flatten_categories_dict(self, categories_dict: dict) -> dict:
        """Return flattened categories dict.

        This is a helper method.

        V2 of the nodes REST enpoint of OTCS requires a flat list of attributes
        (other than V1). So we need to flatten the structure. If category_data
        is already in a flat V2 structure it will remain unchanged.

        See: https://developer.opentext.com/ce/products/extended-ecm/apis/content-server-25-1-0#nodes/createNode2

        Args:
            categories_dict (dict):
                A (potentially nested) category / attribute structure.

        Returns:
            dict:
                A flattened structure where all attributes of all categories
                are in one dictionary.

        """

        items = {}

        def recurse(current_dict: dict) -> dict:
            for k, v in current_dict.items():
                # Attribute 1 stands for the category itself
                # and we don't want to modify it:
                if isinstance(v, dict) and not k.endswith("_1"):
                    recurse(v)  # Recurse into the nested dictionary
                else:
                    items[k] = v

        # end def recurse()

        recurse(categories_dict)

        return items

    # end method definition

    def upload_file_to_parent(
        self,
        parent_id: int,
        file_url: str,
        file_name: str | None = None,
        mime_type: str | None = None,
        category_data: dict | None = None,
        classifications: list | None = None,
        description: str = "",
        external_modify_date: str | None = None,
        external_create_date: str | None = None,
        extract_zip: bool = False,
        show_error: bool = True,
    ) -> dict | None:
        """Fetch a file from a URL or local filesystem and uploads it to a OTCS parent.

        The parent should be a container item such as a folder or business workspace.

        Args:
            parent_id (int):
                The ID of the parent (folder) to upload the file to.
            file_url (str):
                The URL to download the file from, or a local file path.
            file_name (str):
                The name of the file being uploaded.
            mime_type (str | None, optional):
                The mime type of the file (e.g., 'application/pdf').
                If the mime type is not provided the method tries to "guess" the mime type.
            category_data (dict | None, optional):
                Metadata or category data associated with the file. Example format:
                {
                    "12508": {
                        "12508_2": "Draft",         # Text drop-down
                        "12508_3": 8559,            # User ID
                        "12508_4": "2023-05-10",    # Date
                        "12508_6": 7357,            # User ID
                        "12508_7": "2023-05-11",    # Date
                        "12508_5": True,            # Checkbox / Bool
                        "12508_8": "EN",            # Text drop-down
                        "12508_9": "MS Word",       # Text drop-down
                    }
                }
            classifications (list):
                List of classification item IDs to apply to the new item.
            description (str, optional):
                A description of the document.
            external_create_date (str, optional):
                The date the file was created in the source system, in format 'YYYY-MM-DD'.
            external_modify_date (str, optional):
                The date the file was last modified in the source system, in format 'YYYY-MM-DD'.
            extract_zip (bool, optional):
                If True, automatically extract ZIP files and upload extracted directory. If False,
                upload the unchanged Zip file.
            show_error (bool, optional):
                If True, treats the upload failure as an error. If False, no error is shown (useful if the file already exists).

        Returns:
            dict | None:
                The response from the upload operation or None if the upload fails.

        """

        if not file_name:
            # if path_or_url does not end with a "/"
            # we may get the missing file name from there:
            file_name = os.path.basename(file_url)

        if not file_name:
            self.logger.error("Missing file name! Cannot upload file.")
            return None

        # Make sure we don't have leading or trailing whitespace:
        file_name = file_name.strip()

        if file_url.startswith("http"):
            # Download file from remote location specified by the file_url parameter
            # this must be a public place without authentication:
            self.logger.debug("Download file from URL -> %s", file_url)

            try:
                response = requests.get(url=file_url, timeout=1200)
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                self.logger.error("HTTP error with -> %s", file_url)
                return None
            except requests.exceptions.ConnectionError:
                self.logger.error("Connection error with -> %s", file_url)
                return None
            except requests.exceptions.Timeout:
                self.logger.error("Timeout error with -> %s", file_url)
                return None
            except requests.exceptions.RequestException:
                self.logger.error("Request error with -> %s", file_url)
                return None

            self.logger.debug(
                "Successfully downloaded file -> %s; status code -> %s",
                file_url,
                response.status_code,
            )
            file_content = response.content

        # If path_or_url specifies a directory or a zip file we want to extract
        # it and then defer the upload to upload_directory_to_parent()

        elif os.path.exists(file_url) and (
            ((file_url.endswith(".zip") or mime_type == "application/x-zip-compressed") and extract_zip)
            or os.path.isdir(file_url)
        ):
            return self.upload_directory_to_parent(
                parent_id=parent_id,
                file_path=file_url,
            )

        elif os.path.exists(file_url):
            self.logger.debug("Uploading local file -> %s", file_url)
            file_content = open(file=file_url, mode="rb")  # noqa: SIM115

        else:
            self.logger.warning("Cannot access file -> '%s'", file_url)
            return None

        upload_post_data = {
            "type": str(self.ITEM_TYPE_DOCUMENT),
            "name": file_name,
            "parent_id": str(parent_id),
            "roles": {},
        }

        if external_create_date:
            upload_post_data["external_create_date"] = external_create_date
        if external_modify_date:
            upload_post_data["external_modify_date"] = external_modify_date

        if description:
            upload_post_data["description"] = description

        if category_data:
            upload_post_data["roles"]["categories"] = self.flatten_categories_dict(category_data)

        if classifications:
            upload_post_data["roles"]["classifications"] = {
                "create_id": [],
                "id": classifications,
            }

        if not mime_type:
            mime_type, _ = mimetypes.guess_type(file_url)

        if not mime_type and magic_installed:
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(file_url)
            except Exception:
                self.logger.error(
                    "Unknown mime type for upload of document -> '%s' to parent ID -> %s",
                    file_name,
                    str(parent_id),
                )

        upload_post_files = [("file", (f"{file_name}", file_content, mime_type))]

        request_url = self.config()["nodesUrlv2"]

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly fwhen the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Upload file -> '%s' with mime type -> '%s' to parent with ID -> %s; calling -> %s",
            file_name,
            mime_type,
            str(parent_id),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(upload_post_data)},
            files=upload_post_files,
            timeout=None,
            warning_message="Cannot upload file -> '{}' from -> '{}' to parent with ID -> {}".format(
                file_name,
                file_url,
                parent_id,
            ),
            failure_message="Failed to upload file -> '{}' from -> '{}' to parent with ID -> {}".format(
                file_name,
                file_url,
                parent_id,
            ),
            show_error=show_error,
            show_warning=not show_error,
        )

        return response

    # end method definition

    def upload_directory_to_parent(self, parent_id: int, file_path: str) -> dict | None:
        """Upload a directory or an uncompressed zip file to Content Server.

        IMPORTANT: if the path ends in a file then we assume it is a ZIP file!

        Args:
            parent_id (int):
                ID of the parent in Content Server.
            file_path (str):
                File system path to the directory or zip file.

        Returns:
            dict | None:
                Deliver the response of the first item created (wether this is a file oder folder)
                to make uploading a folder or zip behave like uploading a single document.

        """

        # Unzip if the path is ending in a file (then we assume it is a zip file)
        if os.path.isfile(file_path):
            try:
                # If the ".zip" file extension is missing we add
                # it and rename the file to avoid conflicts with
                # extracted zips that may have a top level directory
                # with the same name:
                if not file_path.endswith(".zip"):
                    os.rename(file_path, file_path + ".zip")
                    file_path = file_path + ".zip"
                with zipfile.ZipFile(file_path, "r") as zip_ref:
                    extract_path = file_path[:-4]  # Remove .zip extension
                    self.logger.debug(
                        "Extracting zip file -> '%s' into -> '%s'",
                        file_path,
                        extract_path,
                    )
                    zip_ref.extractall(extract_path)
                    file_path = extract_path
            except zipfile.BadZipFile:
                self.logger.error(
                    "Failed to extract zip file -> '%s'",
                    file_path,
                )
                return None
            except OSError:
                self.logger.error(
                    "OS error occurred while trying to extract zip file -> '%s'",
                    file_path,
                )
                return None
        # end os.path.isfile(file_path)
        else:
            # In this case we don't have a ZIP file but an existing directory.
            # Make sure to set this to None to not delete it after we are finished.
            # We only want to clean things up that this method has created on the fly.
            extract_path = None

        # first_response captures the response of the first item created.
        # This can be a folder or a single document. This is what we want to
        # return at the end as the calling method still sees this as a "single file".
        first_response = None

        # Traverse the directory
        parent_id_map = {file_path: parent_id}
        for root, dirs, files in os.walk(file_path):
            current_parent_id = parent_id_map[root]

            # 1. Traverse directory items to create corresponding
            #    folders in OTCS and update parent ID map
            for dir_name in dirs:
                response = self.get_node_by_parent_and_name(
                    parent_id=current_parent_id,
                    name=dir_name,
                )
                if not response or not response["results"]:
                    response = self.create_item(
                        parent_id=current_parent_id,
                        item_type=self.ITEM_TYPE_FOLDER,
                        item_name=dir_name,
                        show_error=False,
                    )
                    created = True
                else:
                    created = False
                new_parent_id = self.get_result_value(response=response, key="id")
                if new_parent_id:
                    self.logger.debug(
                        "%s folder -> '%s' in parent folder with ID -> %s. Resulting ID -> %s",
                        "Created" if created else "Found existing",
                        dir_name,
                        str(current_parent_id),
                        str(new_parent_id),
                    )
                    parent_id_map[os.path.join(root, dir_name)] = new_parent_id
                    # Remember the first item created
                    if not first_response:
                        first_response = response.copy()
            # end for dir_name in dirs:

            # 2. Traverse files in the current directory and
            #    upload the files into the OTCS folder:
            for file_name in files:
                full_file_path = os.path.join(root, file_name)
                if full_file_path.endswith(".zip"):
                    # Recursive call for zip files in zip files:
                    response = self.upload_directory_to_parent(
                        parent_id=current_parent_id,
                        file_path=full_file_path,
                    )
                    if response and not first_response:
                        first_response = response.copy()
                    continue
                response = self.get_node_by_parent_and_name(
                    parent_id=current_parent_id,
                    name=file_name,
                )
                if not response or not response["results"]:
                    response = self.upload_file_to_parent(
                        parent_id=current_parent_id,
                        file_url=full_file_path,
                        file_name=file_name,
                    )
                else:
                    existing_document_id = self.get_result_value(
                        response=response,
                        key="id",
                    )
                    response = self.add_document_version(
                        node_id=existing_document_id,
                        file_url=full_file_path,
                        file_name=file_name,
                    )
                if response and not first_response:
                    first_response = response.copy()
            # end for file_name in files:
        # end for root, dirs, files in os.walk(...)

        # Cleanup: remove extracted directory:
        if extract_path and os.path.exists(extract_path) and os.path.isdir(extract_path):
            self.logger.debug(
                "Delete temporary directory -> '%s' created from ZIP file...",
                extract_path,
            )
            try:
                shutil.rmtree(extract_path)
            except FileNotFoundError:
                self.logger.error(
                    "Directory -> '%s' not found!",
                    extract_path,
                )
            except PermissionError:
                self.logger.error(
                    "No permission to delete directory -> '%s'!",
                    extract_path,
                )
            except OSError:
                self.logger.error(
                    "OS error while trying to delete directory -> '%s'!",
                    extract_path,
                )

        return first_response

    # end method definition

    def add_document_version(
        self,
        node_id: int,
        file_url: str,
        file_name: str,
        mime_type: str | None = None,
        description: str = "",
    ) -> dict | None:
        """Fetch file from URL or local filesystem and upload it as a document version.

        Args:
            node_id (int):
                The ID of the document to add add version to.
            file_url (str):
                URL to download file from or the local file path.
            file_name (str):
                The name of the file.
            mime_type (str | None, optional):
                The mime type of the file (e.g., 'application/pdf').
                If the mime type is not provided the method tries to "guess" the mime type.
            description (str, optional):
                The description of the version (default = no description).

        Returns:
            dict | None:
                Add version response or None if the upload fails.

        """

        # Desciption of a version cannot be longer than 255 characters in OTCS:
        if description and len(description) > 255:
            description = description[:255]

        if file_url.startswith("http"):
            # Download file from remote location specified by the file_url parameter
            # this must be a public place without authentication:
            self.logger.debug("Download file from URL -> %s", file_url)

            try:
                response = requests.get(
                    url=file_url,
                    timeout=None,
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError:
                self.logger.error("HTTP error with -> %s", file_url)
                return None
            except requests.exceptions.ConnectionError:
                self.logger.error("Connection error with -> %s", file_url)
                return None
            except requests.exceptions.Timeout:
                self.logger.error("Timeout error with -> %s", file_url)
                return None
            except requests.exceptions.RequestException:
                self.logger.error("Request error -> %s", file_url)
                return None

            self.logger.debug(
                "Successfully downloaded file -> %s; status code -> %s",
                file_url,
                response.status_code,
            )
            file_content = response.content

        elif os.path.exists(file_url):
            self.logger.debug("Upload local file -> '%s'", file_url)
            file_content = open(file=file_url, mode="rb")  # noqa: SIM115

        else:
            self.logger.warning("Cannot access file -> '%s'", file_url)
            return None

        upload_post_data = {"description": description}

        if not mime_type:
            mime_type, _ = mimetypes.guess_type(file_url)

        if not mime_type and magic_installed:
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(file_url)
            except Exception:
                self.logger.error(
                    "Unknown mime type for new version of document -> '%s' (%s)",
                    file_name,
                    str(node_id),
                )

        upload_post_files = [("file", (f"{file_name}", file_content, mime_type))]

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is
        # provided.cSo we just put the cookie in the header and trust the request
        # library to add the Content-Type = multipart/form-data:
        request_header = self.cookie()

        self.logger.debug(
            "Upload file -> '%s' with mime type -> '%s' as new version to document node with ID -> %s; calling -> %s",
            file_name,
            mime_type,
            node_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=upload_post_data,
            files=upload_post_files,
            timeout=None,
            failure_message="Failed to add file -> '{}' as new version to document with ID -> {}".format(
                file_url,
                node_id,
            ),
        )

    # end method definition

    def get_latest_document_version(self, node_id: int) -> dict | None:
        """Get latest version of a document node based on the node ID.

        Args:
            node_id (int):
                The ID of the document node to get the latest from.

        Returns:
            dict | None:
                The Node information or None if no node with this ID is found.

        """

        request_url = self.config()["nodesUrl"] + "/" + str(node_id) + "/versions/latest"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get latest version of document with node ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get latest version of document with node ID -> {}".format(
                str(node_id),
            ),
        )

    # end method definition

    def get_document_content(
        self,
        node_id: int,
        version_number: str = "",
        parse_request_response: bool = False,
    ) -> bytes | dict | None:
        """Get document content from Content Server.

        Args:
            node_id (int):
                The node ID of the document to download.
            version_number (str, optional):
                The version of the document to download. If an empty string (""),
                the latest version is downloaded. Default is "".
            parse_request_response (bool, optional):
                If True, the content is interpreted as JSON and delivered as a dictionary.
                If False, raw content is returned as bytes. Default is False.

        Returns:
            bytes | dict | None:
                The content of the document as bytes if no error occurs,
                or a dictionary if `parse_request_response` is True and the content is parsed as JSON.
                Returns None if an error occurs.

        """

        if not version_number:
            response = self.get_latest_document_version(node_id)
            if not response:
                self.logger.error(
                    "Cannot get latest version of document with ID -> %s",
                    str(node_id),
                )
            version_number = response["data"]["version_number"]

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions/" + str(version_number) + "/content"
        request_header = self.request_download_header()

        self.logger.debug(
            "Get document with node ID -> %s and version -> %s; calling -> %s",
            str(node_id),
            str(version_number),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to download document with node ID -> {}".format(
                node_id,
            ),
            parse_request_response=parse_request_response,
        )

        if parse_request_response:
            # In this case response.content has been interpreted as JSON
            # and delivered as a Python dict (or None in case of an error):
            return response

        if response is not None:
            # In this case the unparsed content is delivered as bytes:
            return response.content

        return None

    # end method definition

    def get_json_document(
        self,
        node_id: int,
        version_number: str = "",
    ) -> list | dict | None:
        """Get document content from Extended ECM and read content as JSON.

        Args:
            node_id (int): The node ID of the document to download
            version_number (str, optional): The version of the document to download.
                                            If version = "" then download the latest
                                            version.

        Returns:
            list | dict | None: Content of the file or None in case of an error.

        """

        return self.get_document_content(
            node_id=node_id,
            version_number=version_number,
            parse_request_response=True,
        )

    # end method definition

    def download_document(
        self,
        node_id: int,
        file_path: str,
        version_number: str = "",
    ) -> bool:
        """Download a document from Extended ECM to local file system.

        Args:
            node_id (int):
                The node ID of the document to download
            file_path (str):
                The local file path (directory).
            version_number (str, optional):
                The version of the document to download.
                If version = "" then download the latest version.

        Returns:
            bool:
                True if the document has been download to the specified file.
                False otherwise.

        """

        if not version_number:
            response = self.get_latest_document_version(node_id)
            if not response:
                self.logger.error(
                    "Cannot get latest version of document with ID -> %s",
                    str(node_id),
                )
                return False
            version_number = response["data"]["version_number"]

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions/" + str(version_number) + "/content"
        request_header = self.request_download_header()

        self.logger.debug(
            "Download document with node ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to download document with node ID -> {}".format(
                node_id,
            ),
            parse_request_response=False,
            stream=True,  # as we may download large documents we better enable streaming here
        )

        if response is None:
            return False

        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            self.logger.info(
                "Download directory -> '%s' does not exist, creating it.",
                directory,
            )
            os.makedirs(directory)

        try:
            with open(file_path, "wb") as download_file:
                for chunk in response.iter_content(chunk_size=1024):
                    download_file.write(chunk)
        except Exception:
            self.logger.error(
                "Error while writing content to file -> %s",
                file_path,
            )
            return False

        return True

    # end method definition

    def download_config_file(
        self,
        otcs_url_suffix: str,
        file_path: str,
        search: str = "",
        replace: str = "",
    ) -> bool:
        """Download a config file from a given OTCS URL.

        This is NOT for downloading documents from within the OTCS repository
        but for configuration files such as app packages for MS Teams.

        Args:
            otcs_url_suffix (str):
                OTCS URL suffix starting typically starting
                with /cs/cs?func=, e.g. /cs/cs?func=officegroups.DownloadTeamsPackage
            file_path (str):
                The local path to save the file (direcotry + filename).
            search (str, optional):
                An optional string to search for a replacement.
            replace (str, optional):
                An optional replacement string.

        Returns:
            bool:
                True if the download succeeds, False otherwise.

        """

        request_url = self.config()["baseUrl"] + otcs_url_suffix
        request_header = self.request_download_header()

        self.logger.debug("Download config file from URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError:
            self.logger.error("HTTP error with -> %s", request_url)
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error("Connection error with -> %s", request_url)
            return False
        except requests.exceptions.Timeout:
            self.logger.error("Timeout error with -> %s", request_url)
            return False
        except requests.exceptions.RequestException:
            self.logger.error("Request error with -> %s", request_url)
            return False

        content = response.content

        if search:
            self.logger.debug(
                "Search for all occurances of '%s' in the config file and replace them with '%s'",
                search,
                replace,
            )
            content = content.replace(search.encode("utf-8"), replace.encode("utf-8"))

        # Open file in write binary mode
        with open(file=file_path, mode="wb") as file:
            # Write the content to the file
            file.write(content)

        self.logger.debug(
            "Successfully downloaded config file -> %s to -> '%s'; status code -> %s",
            request_url,
            file_path,
            response.status_code,
        )

        return True

    # end method definition

    def search(
        self,
        search_term: str,
        look_for: str = "complexQuery",
        modifier: str = "",
        slice_id: int = 0,
        query_id: int = 0,
        template_id: int = 0,
        limit: int = 100,
        page: int = 1,
    ) -> dict | None:
        """Search for a search term using Content Server Search.

        Args:
            search_term (str):
                The search term to query, e.g., "test or OTSubType: 189".
            look_for (str, optional):
                Defines the search method. Possible values are:
                - 'allwords': search for all words
                - 'anywords': search for any words
                - 'exactphrase': search for an exact phrase
                - 'complexquery': search for a complex query
                Default is 'complexquery'.
            modifier (str, optional):
                Defines a modifier for the search. Possible values are:
                - 'synonymsof'
                - 'relatedto'
                - 'soundslike'
                - 'wordbeginswith'
                - 'wordendswith'
                If not specified or any value other than these options is given,
                it is ignored.
            slice_id (int, optional):
                The ID of an existing search slice.
            query_id (int, optional):
                The ID of a saved search query.
            template_id (int, optional):
                The ID of a saved search template.
            limit (int, optional):
                The maximum number of results to return. Default is 100.
            page (int, optional):
                The page number of the search results. Default is 1 (first page).

        Returns:
            dict | None:
                The search response as a dictionary if successful,
                or None if the search fails.

        Example:
            ```json
            {
                'collection': {
                    'paging': {
                        limit': 100,
                        'links': {
                            'next': {...}
                        },
                        'page': 1,
                        'page_total': 50,
                        'range_max': 100,
                        'range_min': 1,
                        'result_header_string': 'Results 1 to 100 of 4945 sorted by Relevance',
                        'total_count': 4945
                    },
                    'searching': {
                        'cache_id': 507204350,
                        'regions_metadata': {
                            'OTCreatedBy': {...},
                            'OTLocation': {...},
                            'OTMIMEType': {...},
                            'OTName': {...},
                            'OTObjectDate': {...},
                            'OTObjectSize': {...}
                        },
                        'regions_order': [
                            'OTMIMEType', 'OTName', 'OTObjectDate',
                            'OTObjectSize', 'OTLocation', 'OTCreatedBy'
                        ],
                        'result_title': 'Search results: Extended ECM'
                    },
                    'sorting': {
                        'links': {
                            'asc_OTObjectDate': {...},
                            'asc_OTObjectSize': {...},
                            'asc_XENGCRTRevisionIndicator': {...},
                            'asc_XENGCRTRevisionNumber': {...},
                            'asc_XENGCRTRevisionStatus': {...},
                            'asc_XENGCRTSourceWorkspace': {...},
                            'asc_XENGSFMState': {...},
                            'asc_XENGSFMStateFlow': {...},
                            'desc_OTObjectDate': {...},
                            'desc_OTObjectSize': {...},
                            'desc_XENGCRTRevisionIndicator': {...},
                            'desc_XENGCRTRevisionNumber': {...},
                            'desc_XENGCRTRevisionStatus': {...},
                            'desc_XENGCRTSourceWorkspace': {...},
                            'desc_XENGSFMState': {...},
                            'desc_XENGSFMStateFlow': {...},
                            'relevance': {...}
                        },
                        'sort': ['relevance']
                    }
                },
                'links': {
                    'data': {...}
                },
                'results': [
                    {
                        'data': {
                            'properties': {
                                'advanced_versioning': False,
                                'container': False,
                                'container_size': 0,
                                'create_date': '2025-01-16T20:14:14Z',
                                'create_user_id': 1000,
                                'description': 'Configure features of the Extended ECM Platform module.',
                                'description_multilingual': {'ar': '', 'de': '', 'en': 'Configure features of the Extended ECM Platform module.', ...},
                                'external_create_date': None,
                                'external_identity': '',
                                'external_identity_type': '',
                                'external_modify_date': None,
                                'external_source': '',
                                'favorite': False,
                                'hidden': False,
                                'icon': '/cssupport/webdoc/apppdf.gif',
                                'icon_large': '/cssupport/webdoc/apppdf_large.gif',
                                'id': 42708,
                                'mime_type': 'application/pdf',
                                'modify_date': '2025-01-16T20:14:16Z',
                                'modify_user_id': 1000,
                                'name': 'Extended ECM - Extended ECM Platform',
                                'name_multilingual': {'ar': '', 'de': '', 'en': 'Extended ECM - Extended ECM Platform',...},
                                'owner': 'Admin',
                                'owner_group_id': 999,
                                'owner_user_id': 1000,
                                'parent_id': 28375,
                                'permissions_model': 'advanced',
                                'preferred_rendition_type': [''],
                                'reserved': False,
                                'reserved_date': None,
                                'reserved_shared_collaboration': False,
                                'reserved_user_id': 0,
                                'short_summary': 'Important Administrators need Business Administration Business Workspaces and...',
                                'size': 894283,
                                'size_formatted': '874 KB',
                                'status': None,
                                'summary': 'Important Administrators need Business Administration Business Workspaces and...',
                                'type': 144,
                                'type_name': 'Document',
                                'versionable': True,
                                'versions_control_advanced': False,
                                'volume_id': 28368
                            },
                            'regions': {
                                'OTCreatedBy': 1000,
                                'OTCreatedBy_formatted': 'Admin',
                                'OTLocation': '2000 6471 6473 10318 -10318 10324 28368 -28368 28375 42708',
                                'OTLocation_expand': {...},
                                'OTLocation_formatted': 'User Guides',
                                'OTLocation_path': [...],
                                'OTMIMEType': 'application/pdf',
                                'OTMIMEType_formatted': 'Document',
                                'OTName': 'Extended ECM - Extended ECM Platform',
                                'OTName_expand': {...},
                                'OTObjectDate': '20250116',
                                'OTObjectDate_formatted': '2025-01-16',
                                'OTObjectSize': 894283,
                                'OTObjectSize_formatted': '874 KB'
                            },
                            'versions': {
                                'create_date': '2025-01-16T20:14:15Z',
                                'description': None,
                                'file_create_date': '2025-01-16T20:14:13Z',
                                'file_modify_date': '2025-01-16T20:14:13Z',
                                'file_name': 'Extended ECM - Extended ECM Platform',
                                'file_size': 894283,
                                'file_type': '',
                                'id': 42708,
                                'locked': False,
                                'locked_date': None,
                                'locked_user_id': None,
                                'mime_type': 'application/pdf',
                                'modify_date': '2025-01-16T20:14:15Z',
                                'name': 'Extended ECM - Extended ECM Platform',
                                'owner_id': 1000,
                                'provider_id': 42708,
                                'version_id': 42708,
                                'version_number': 1,
                                'version_number_major': 0,
                                ...
                            }
                        },
                        'links': {
                            'ancestors': [{...}, {...}, {...}, {...}, {...}, {...}, {...}],
                            'ancestors_nodes': [{...}, {...}, {...}, {...}, {...}, {...}, {...}],
                            'parent': {
                                'href': 'api/v1/nodes/28375',
                                'name': 'User Guides'
                            },
                            'parent_nodes': {
                                'href': 'api/v1/nodes/28375/nodes',
                                'name': 'User Guides'
                            }
                        },
                        'search_result_metadata': {
                            'current_version': True,
                            'object_href': None,
                            'object_id': 'DataId=42708&Version=1',
                            'result_type': '264',
                            'source_id': '2275',
                            'version_type': None
                        }
                    }
                ]
            }
            ```

        """

        search_post_body = {
            "where": search_term,
            "lookfor": look_for,
            "page": page,
            "limit": limit,
        }

        if modifier:
            search_post_body["modifier"] = modifier
        if slice_id > 0:
            search_post_body["slice_id"] = slice_id
        if query_id > 0:
            search_post_body["query_id"] = query_id
        if template_id > 0:
            search_post_body["template_id"] = template_id

        request_url = self.config()["searchUrl"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Search for term -> '%s'; calling -> %s",
            search_term,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=search_post_body,
            timeout=None,
            failure_message="Failed to search for term -> '{}'".format(search_term),
        )

    # end method definition

    def search_iterator(
        self,
        search_term: str,
        look_for: str = "complexQuery",
        modifier: str = "",
        slice_id: int = 0,
        query_id: int = 0,
        template_id: int = 0,
        page_size: int = 100,
    ) -> iter:
        """Get an iterator object to traverse all search results for a given search.

        Using a generator avoids loading a large number of nodes into memory at once.
        Instead you can iterate over the potential large list of search results.

        Example usage:
            ```python
            search_results = otcs_object.search_iterator(...)
            for result in search_results:
                logger.info("Found search result -> '%s'", node["data"]["properties"]["name"])
            ```

        Args:
            search_term (str):
                The search term to query, e.g., "test or OTSubType: 189".
            look_for (str, optional):
                Defines the search method. Possible values are:
                - 'allwords': search for all words
                - 'anywords': search for any words
                - 'exactphrase': search for an exact phrase
                - 'complexquery': search for a complex query
                Default is 'complexquery'.
            modifier (str, optional):
                Defines a modifier for the search. Possible values are:
                - 'synonymsof', 'relatedto', 'soundslike', 'wordbeginswith', 'wordendswith'.
                If not specified or any value other than these options is given, it is ignored.
            slice_id (int, optional):
                The ID of an existing search slice.
            query_id (int, optional):
                The ID of a saved search query.
            template_id (int, optional):
                The ID of a saved search template.
            page_size (int, optional):
                The maximum number of results to return. Default is 100.
                For the iterator this ois basically the chunk size.

        Returns:
            dict | None:
                The search response as a dictionary if successful, or None if the search fails.

        """

        # First we probe how many items we have:
        response = self.search(
            search_term=search_term,
            look_for=look_for,
            modifier=modifier,
            slice_id=slice_id,
            query_id=query_id,
            template_id=template_id,
            limit=1,
            page=1,
        )
        if not response or "results" not in response:
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        number_of_results = response["collection"]["paging"]["total_count"]
        if not number_of_results:
            self.logger.warning(
                "Search -> '%s' does not have results! Cannot iterate over results.",
                str(search_term),
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        # If the container has many items we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (number_of_results + page_size - 1) // page_size

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.search(
                search_term=search_term,
                look_for=look_for,
                modifier=modifier,
                slice_id=slice_id,
                query_id=query_id,
                template_id=template_id,
                limit=page_size,
                page=page,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve search results for search term -> '%s' (page -> %d)",
                    search_term,
                    page,
                )
                return

            # Yield nodes one at a time
            yield from response["results"]

        # end for page in range(1, total_pages + 1)

    # end method definition

    def get_external_system_connection(
        self,
        connection_name: str,
        show_error: bool = False,
    ) -> dict | None:
        """Get Extended ECM external system connection (e.g. SAP, Salesforce, SuccessFactors).

        Args:
            connection_name (str): Name of the connection
            show_error (bool, optional): If True, treat as error if connection is not found.

        Returns:
            dict | None: External system Details or None if the REST call fails.

        """
        # Encode special characters in connection_name
        connection_name = connection_name.replace("\\", "0xF0A6").replace("/", "0xF0A7")
        request_url = self.config()["externalSystemUrl"] + "/" + connection_name + "/config"
        request_header = self.cookie()

        self.logger.debug(
            "Get external system connection -> %s; calling -> %s",
            connection_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            warning_message="External system connection -> '{}' does not yet exist".format(
                connection_name,
            ),
            failure_message="Failed to get external system connection -> '{}'".format(
                connection_name,
            ),
            show_error=show_error,
        )

    # end method definition

    def add_external_system_connection(
        self,
        connection_name: str,
        connection_type: str,
        as_url: str,
        base_url: str,
        username: str,
        password: str,
        authentication_method: str = "BASIC",  # either BASIC or OAUTH
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> dict | None:
        """Add an external system connection (e.g. SAP, Salesforce, SuccessFactors).

        Args:
            connection_name (str):
                The name of the connection.
            connection_type (str):
                The type of the connection (HTTP, SF, SFInstance)
            as_url (str):
                The application URL of the external system.
            base_url (str):
                The base URL of the external system.
            username (str):
                The username (used for BASIC authentication)
            password (str):
                The password (used for BASIC authentication)
            authentication_method (str, optional):
                Either BASIC (using username and password) or OAUTH.
            client_id (str, optional):
                The OAUTH Client ID (only required if authenticationMethod = OAUTH).
            client_secret (str, optional):
                OAUTH Client Secret (only required if authenticationMethod = OAUTH).

        Returns:
            dict | None: External system Details or None if the REST call fails.

        """

        external_system_post_body = {
            "external_system_name": connection_name,
            "conn_type": connection_type,
            "asurl": as_url,
            "baseurl": base_url,
            "username": username,
            "password": password,
        }

        if authentication_method == "OAUTH" and client_id and client_secret:
            external_system_post_body["authentication_method"] = str(
                authentication_method,
            )
            external_system_post_body["client_id"] = str(client_id)
            external_system_post_body["client_secret"] = str(client_secret)

        request_url = self.config()["externalSystemUrl"]
        request_header = self.cookie()

        self.logger.debug(
            "Create external system connection -> '%s' of type -> '%s' with URL -> %s; calling -> %s",
            connection_name,
            connection_type,
            as_url,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=external_system_post_body,
            timeout=None,
            failure_message="Failed to create external system connection -> '{}'".format(
                connection_name,
            ),
        )

    # end method definition

    def create_transport_workbench(self, workbench_name: str) -> dict | None:
        """Create a Workbench in the Transport Volume.

        Args:
            workbench_name (str):
                The name of the workbench to be created.

        Returns:
            dict | None:
                Create response or None if the creation fails.

        """

        create_worbench_post_data = {
            "type": str(self.ITEM_TYPE_WORKBENCH),
            "name": workbench_name,
        }

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Create transport workbench -> '%s'; calling -> %s",
            workbench_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_worbench_post_data,
            timeout=None,
            failure_message="Failed to create transport workbench -> {}".format(
                workbench_name,
            ),
        )

    # end method definition

    def unpack_transport_package(
        self,
        package_id: int,
        workbench_id: int,
    ) -> dict | None:
        """Unpack an existing Transport Package into an existing Workbench.

        Args:
            package_id (int):
                The ID of package to be unpacked.
            workbench_id (int):
                The ID of target workbench.

        Returns:
            dict | None:
                Unpack response or None if the unpacking fails.

        """

        unpack_package_post_data = {"workbench_id": workbench_id}

        request_url = self.config()["nodesUrlv2"] + "/" + str(package_id) + "/unpack"
        request_header = self.request_form_header()

        self.logger.debug(
            "Unpack transport package with ID -> %s into workbench with ID -> %s; calling -> %s",
            str(package_id),
            str(workbench_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=unpack_package_post_data,
            timeout=None,
            failure_message="Failed to unpack package with ID -> {} to workbench with ID -> {}".format(
                package_id,
                workbench_id,
            ),
        )

    # end method definition

    def deploy_workbench(self, workbench_id: int) -> dict | None:
        """Deploy an existing Workbench.

        Args:
            workbench_id (int):
                The ID of the workbench to be deployed.

        Returns:
            dict | None:
                The deploy response or None if the deployment fails.

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(workbench_id) + "/deploy"
        request_header = self.request_form_header()

        self.logger.debug(
            "Deploy workbench with ID -> %s; calling -> %s",
            str(workbench_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=None,
            failure_message="Failed to deploy workbench with ID -> {}".format(
                workbench_id,
            ),
        )

    # end method definition

    def deploy_transport(
        self,
        package_url: str,
        package_name: str,
        package_description: str = "",
        replacements: list | None = None,
        extractions: list | None = None,
    ) -> dict | None:
        """Deploy a transport.

        This uses subfunctions to upload, unpackage and deploy the transport,
        and creates the required workbench.

        Args:
            package_url (str):
                URL to download the transport package.
            package_name (str):
                Name of the transport package ZIP file.
            package_description (str, optional):
                Description of the transport package. Default is an empty string.
            replacements (list of dicts, optional):
                List of replacement values to be applied to all XML files in the transport.
                Each dictionary must contain:
                - 'placeholder': text to replace
                - 'value': text to replace with
            extractions (list of dicts, optional):
                List of XML subtrees to extract from each XML file in the transport.
                Each dictionary must contain:
                - 'xpath': defining the subtree to extract
                - 'enabled': True if the extraction is active

        Returns:
            dict | None:
                Deploy response as a dictionary if successful, or None if the deployment fails.

        """

        if replacements is None:
            replacements = []
        if extractions is None:
            extractions = []

        # Preparation: get volume IDs for Transport Warehouse (root volume and Transport Packages)
        response = self.get_volume(volume_type=self.VOLUME_TYPE_TRANSPORT_WAREHOUSE)
        transport_root_volume_id = self.get_result_value(response=response, key="id")
        if not transport_root_volume_id:
            self.logger.error("Failed to retrieve transport root volume")
            return None
        self.logger.debug(
            "Transport root volume ID -> %s",
            str(transport_root_volume_id),
        )

        response = self.get_node_by_parent_and_name(
            parent_id=transport_root_volume_id,
            name="Transport Packages",
        )
        transport_package_volume_id = self.get_result_value(response=response, key="id")
        if not transport_package_volume_id:
            self.logger.error("Failed to retrieve transport package volume")
            return None
        self.logger.debug(
            "Transport package volume ID -> %s",
            str(transport_package_volume_id),
        )

        # Step 1: Upload Transport Package
        self.logger.debug(
            "Check if transport package -> '%s' already exists...",
            package_name,
        )
        response = self.get_node_by_parent_and_name(
            parent_id=transport_package_volume_id,
            name=package_name,
        )
        package_id = self.get_result_value(response=response, key="id")
        if package_id:
            self.logger.debug(
                "Transport package -> '%s' does already exist; existing package ID -> %s",
                package_name,
                str(package_id),
            )
        else:
            self.logger.debug(
                "Transport package -> '%s' does not yet exist, loading from -> %s",
                package_name,
                package_url,
            )
            # If we have string replacements configured execute them now:
            if replacements:
                self.logger.debug(
                    "Transport -> '%s' has replacements -> %s",
                    package_name,
                    str(replacements),
                )
                self.replace_transport_placeholders(
                    zip_file_path=package_url,
                    replacements=replacements,
                )
            else:
                self.logger.debug(
                    "Transport -> '%s' has no replacements!",
                    package_name,
                )
            # If we have data extractions configured execute them now:
            if extractions:
                self.logger.debug(
                    "Transport -> '%s' has extractions -> %s",
                    package_name,
                    str(extractions),
                )
                self.extract_transport_data(
                    zip_file_path=package_url,
                    extractions=extractions,
                )
            else:
                self.logger.debug("Transport -> '%s' has no extractions!", package_name)

            # Upload package to Transport Warehouse:
            response = self.upload_file_to_volume(
                volume_type=self.VOLUME_TYPE_TRANSPORT_WAREHOUSE_PACKAGE,
                path_or_url=package_url,
                file_name=package_name,
                mime_type="application/zip",
            )
            package_id = self.get_result_value(response=response, key="id")
            if not package_id:
                self.logger.error(
                    "Failed to upload transport package -> %s",
                    package_url,
                )
                return None
            self.logger.debug(
                "Successfully uploaded transport package -> '%s'; new package ID -> %s",
                package_name,
                str(package_id),
            )

        # Step 2: Create Transport Workbench (if not yet exist)
        workbench_name = package_name.split(".")[0]
        self.logger.debug(
            "Check if workbench -> '%s' is already deployed...",
            workbench_name,
        )
        # check if the package name has the suffix "(deployed)" - this indicates it is already
        # successfully deployed (see renaming at the end of this method)
        response = self.get_node_by_parent_and_name(
            parent_id=transport_root_volume_id,
            name=workbench_name + " (deployed)",
        )
        workbench_id = self.get_result_value(response=response, key="id")
        if workbench_id:
            self.logger.debug(
                "Workbench -> '%s' has already been deployed successfully; existing workbench ID -> %s; skipping transport",
                workbench_name,
                str(workbench_id),
            )
            # we return and skip this transport...
            return response
        else:
            self.logger.debug(
                "Check if workbench -> '%s' already exists...",
                workbench_name,
            )
            response = self.get_node_by_parent_and_name(
                parent_id=transport_root_volume_id,
                name=workbench_name,
            )
            workbench_id = self.get_result_value(response=response, key="id")
            if workbench_id:
                self.logger.debug(
                    "Workbench -> '%s' does already exist but is not successfully deployed; existing workbench ID -> %s",
                    workbench_name,
                    str(workbench_id),
                )
            else:
                response = self.create_transport_workbench(
                    workbench_name=workbench_name,
                )
                workbench_id = self.get_result_value(response=response, key="id")
                if not workbench_id:
                    self.logger.error(
                        "Failed to create workbench -> '%s'",
                        workbench_name,
                    )
                    return None
                self.logger.debug(
                    "Successfully created workbench -> '%s'; new workbench ID -> %s",
                    workbench_name,
                    str(workbench_id),
                )

        # Step 3: Unpack Transport Package to Workbench
        self.logger.debug(
            "Unpack transport package -> '%s' (%s) to workbench -> '%s' (%s)",
            package_name,
            str(package_id),
            workbench_name,
            str(workbench_id),
        )
        response = self.unpack_transport_package(
            package_id=package_id,
            workbench_id=workbench_id,
        )
        if not response:
            self.logger.error(
                "Failed to unpack the transport package -> '%s'",
                package_name,
            )
            return None
        self.logger.debug(
            "Successfully unpackaged to workbench -> '%s' (%s)",
            workbench_name,
            str(workbench_id),
        )

        # Step 4: Deploy Workbench
        self.logger.debug(
            "Deploy workbench -> '%s' (%s)",
            workbench_name,
            str(workbench_id),
        )
        response = self.deploy_workbench(workbench_id=workbench_id)
        if not response:
            self.logger.error("Failed to deploy workbench -> '%s'", workbench_name)
            return None

        self.logger.debug(
            "Successfully deployed workbench -> '%s' (%s)",
            workbench_name,
            str(workbench_id),
        )
        self.rename_node(
            node_id=workbench_id,
            name=workbench_name + " (deployed)",
            description=package_description,
        )

        return response

    # end method definition

    def replace_transport_placeholders(
        self,
        zip_file_path: str,
        replacements: list,
    ) -> bool:
        """Search and replace strings in the XML files of the transport package.

        Args:
            zip_file_path (str): Path to transport zip file.
            replacements (list of dicts):
                List of replacement values; dict needs to have two values:
                - placeholder: The text to replace.
                - value: The replacement text.

        Returns:
            bool: True = success, False = error.

        """

        if not os.path.isfile(zip_file_path):
            self.logger.error("Zip file -> '%s' not found.", zip_file_path)
            return False

        # Extract the zip file to a temporary directory
        zip_file_folder = os.path.splitext(zip_file_path)[0]
        with zipfile.ZipFile(zip_file_path, "r") as zfile:
            zfile.extractall(zip_file_folder)

        modified = False

        # Replace search pattern with replace string in all XML files
        # in the directory and its subdirectories:
        for replacement in replacements:
            if "value" not in replacement:
                self.logger.error(
                    "Replacement needs a value but it is not specified. Skipping...",
                )
                continue
            # Check if the replacement is explicitly disabled:
            if not replacement.get("enabled", True):
                self.logger.debug(
                    "Replacement for transport -> '%s' is disabled. Skipping...",
                    zip_file_path,
                )
                continue
            # there are two types of replacements:
            # 1. XPath - more elegant and powerful
            # 2. Search & Replace - basically treat the XML file like a
            #    text file and do a search & replace
            if "xpath" in replacement:
                self.logger.debug(
                    "Using xpath -> %s to narrow down the replacement",
                    replacement["xpath"],
                )
                if "setting" in replacement:
                    self.logger.debug(
                        "Looking up setting -> %s in XML element",
                        replacement["setting"],
                    )
                if "assoc_elem" in replacement:
                    self.logger.debug(
                        "Looking up assoc element -> %s in XML element",
                        replacement["assoc_elem"],
                    )
            else:  # we have a simple "search & replace" replacement
                if "placeholder" not in replacement:
                    self.logger.error(
                        "Replacement without an xpath needs a placeholder value but it is not specified. Skipping...",
                    )
                    continue
                if replacement.get("placeholder") == replacement["value"]:
                    self.logger.debug(
                        "Placeholder and replacement are identical -> %s. Skipping...",
                        replacement["value"],
                    )
                    continue
                self.logger.debug(
                    "Replace -> %s with -> %s in Transport package -> %s",
                    replacement["placeholder"],
                    replacement["value"],
                    zip_file_folder,
                )

            found = XML.replace_in_xml_files(
                zip_file_folder,
                replacement.get("placeholder"),
                replacement["value"],
                replacement.get("xpath"),
                replacement.get("setting"),
                replacement.get("assoc_elem"),
                logger=self.logger.getChild("xml"),
            )
            if found:
                self.logger.debug(
                    "Replacement -> %s has been completed successfully for Transport package -> %s",
                    replacement,
                    zip_file_folder,
                )
                modified = True
            else:
                self.logger.warning(
                    "Replacement -> %s not found in Transport package -> %s",
                    replacement,
                    zip_file_folder,
                )

        if not modified:
            self.logger.warning(
                "None of the specified replacements have been found in Transport package -> %s. No need to create a new transport package.",
                zip_file_folder,
            )
            return False

        # Create the new zip file and add all files from the directory to it
        new_zip_file_path = os.path.dirname(zip_file_path) + "/new_" + os.path.basename(zip_file_path)
        self.logger.debug(
            "Content of transport -> '%s' has been modified - repacking to new zip file -> %s",
            zip_file_folder,
            new_zip_file_path,
        )
        with zipfile.ZipFile(new_zip_file_path, "w", zipfile.ZIP_DEFLATED) as zip_ref:
            for subdir, _, files in os.walk(
                zip_file_folder,
            ):  # 2nd parameter is not used, thus using _ instead of dirs
                for file in files:
                    file_path = os.path.join(subdir, file)
                    rel_path = os.path.relpath(file_path, zip_file_folder)
                    zip_ref.write(file_path, arcname=rel_path)

        # Close the new zip file and delete the temporary directory
        zip_ref.close()
        old_zip_file_path = os.path.dirname(zip_file_path) + "/old_" + os.path.basename(zip_file_path)
        self.logger.debug(
            "Rename orginal transport zip file -> '%s' to -> '%s'",
            zip_file_path,
            old_zip_file_path,
        )
        os.rename(zip_file_path, old_zip_file_path)
        self.logger.debug(
            "Rename new transport zip file -> '%s' to -> '%s'",
            new_zip_file_path,
            zip_file_path,
        )
        os.rename(new_zip_file_path, zip_file_path)

        # Return success
        return True

    # end method definition

    def extract_transport_data(self, zip_file_path: str, extractions: list) -> bool:
        """Search and extract XML data from the transport package.

        Args:
            zip_file_path (str): Path to transport zip file.
            extractions (list of dicts):
                List of extraction values; dict needs to have two values:
                - xpath: structure to find
                - enabed (optional): if the extraction is active

        Returns:
            bool:
                True if successful, False otherwise.

            THIS METHOD MODIFIES EXTRACTIONS BY ADDING A NEW KEY "data"
            TO EACH EXTRACTION ELEMENT!!

        """

        if not os.path.isfile(zip_file_path):
            self.logger.error("Zip file -> '%s' not found.", zip_file_path)
            return False

        # Extract the zip file to a temporary directory
        zip_file_folder = os.path.splitext(zip_file_path)[0]
        with zipfile.ZipFile(zip_file_path, "r") as zfile:
            zfile.extractall(zip_file_folder)

        # Extract data from all XML files in the directory and its subdirectories
        for extraction in extractions:
            if "xpath" not in extraction:
                self.logger.error(
                    "Extraction needs an XPath but it is not specified. Skipping...",
                )
                continue
            # Check if the extraction is explicitly disabled:
            if not extraction.get("enabled", True):
                self.logger.debug(
                    "Extraction for transport -> '%s' is disabled. Skipping...",
                    zip_file_path,
                )
                continue

            xpath = extraction["xpath"]
            self.logger.debug(
                "Using xpath -> %s to extract the data",
                xpath,
            )

            # This delivers a list of strings containing the extracted data:
            extracted_data = XML.extract_from_xml_files(
                directory=zip_file_folder,
                xpath=xpath,
                logger=self.logger.getChild("xml"),
            )
            if extracted_data:
                self.logger.debug(
                    "Extraction with XPath -> %s has been successfully completed for Transport package -> %s",
                    xpath,
                    zip_file_folder,
                )
                # Add the extracted elements to the extraction data structure (dict).
                extraction["data"] = extracted_data
            else:
                self.logger.warning(
                    "Extraction with XPath -> %s has not delivered any data for Transport package -> %s",
                    xpath,
                    zip_file_folder,
                )
                extraction["data"] = []

        # Return the path to the new zip file
        return True

    # end method definition

    def get_business_object_types(self) -> dict | None:
        """Get information for all configured business object types.

        Args:
            None

        Returns:
            dict | None:
                Workspace Types information (for all external systems)
                or None if the request fails.

        """

        request_url = self.config()["businessObjectTypesUrl"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Get all business object types; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get business object types",
        )

    # end method definition

    def get_business_object_type(
        self,
        external_system_id: str,
        type_name: str,
        expand_workspace_type: bool = True,
        expand_external_system: bool = True,
    ) -> dict | None:
        """Get business object type information.

        Unfortunately this REST API is pretty much limited.
        It does not return Field names of external system properties
        and also does not return property groups defined.

        Args:
            external_system_id (str):
                External system Id (such as "TM6")
            type_name (str):
                Type name of the business object (such as "SAP Customer")
            expand_workspace_type (bool, optional):
                If True, deliver additional information for the workspace type.
            expand_external_system (bool, optional):
                If True, deliver additional information for the external system.

        Returns:
            dict | None:
                Business Object Type information or None if the request fails.

        Example:
            ```json
            {
                'businessProperties': [
                    {
                        'attributeID': '14012_29',
                        'categoryID': '14012',
                        'name': 'Name',
                        'type': 'String'
                    },
                    {
                        'attributeID': '14012_28',
                        'categoryID': '14012',
                        'name': 'Customer Number',
                        'type': 'String'
                    }
                ]
                'bwsinfo': {'id': None},
                'cadxref_doc_info': {'has_relation': False},
                'categories': [],
                'claimed_doc_info': {'is_claimed': False},
                'columns': [{...}, {...}, {...}, {...}],
                'doctemplates_info': {'isInDocTemplateVolTree': False},
                'followups': [],
                'nicknames': {'nickname': '16568'},
                'properties': {
                    'advanced_versioning': None,
                    'container': False,
                    'container_size': 0,
                    'create_date': '2017-11-23T16:43:34Z',
                    'create_user_id': 1000,
                    'description': '',
                    'description_multilingual': {...},
                    'external_create_date': None,
                    'external_identity': '',
                    ...
                },
                'rmiconsdata': {
                    'class_id': 0,
                    'official': 0,
                    'show_classify': False,
                    'show_hold': False,
                    'show_hold_tab': False,
                    'show_label_tab': True,
                    'show_official': False,
                    'show_xref': False,
                    'show_xref_tab': False
                },
                'sestatus_doc_info': {'is_se_document': False, 'sync_tooltip': ''},
                'sharing_info': {'is_shared': False, 'sync_state': -1},
                'showmainruleicon': False,
                ...
            }
            ```

        """

        query = {
            "expand_ext_system": expand_external_system,
            "expand_wksp_type": expand_workspace_type,
        }

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        encoded_type_name = type_name.replace("/", "%2F")

        request_url = (
            self.config()["externalSystemUrl"]
            + "/"
            + external_system_id
            + "/botypes/"
            + encoded_type_name
            + "?{}".format(encoded_query)
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Get business object type -> '%s' for external system -> %s; calling -> %s",
            type_name,
            external_system_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get business object type -> '{}' for external system -> {}".format(
                type_name,
                external_system_id,
            ),
        )

    # end method definition

    def get_business_objects(
        self,
        external_system_id: str,
        type_name: str,
        where_clauses: dict | None = None,
        limit: int | None = None,
        page: int | None = None,
    ) -> dict | None:
        """Get all business objects for an external system and a business object type.

        Args:
            external_system_id (str):
                External system ID (such as "TM6")
            type_name (str):
                Type name of the business object (such as "SAP Customer").
            where_clauses (dict | None, optional):
                Filter the results based on one or multiple where clauses.
                TODO: NAME CONVENTION FOR THE FIELDS
            limit (int, optional):
                The maximum number of result items.
            page (int, optional):
                The page number for a chunked result list.

        Returns:
            dict | None:
                Business Object information (for all results) or None if the request fails.

        Example:
            ```json
            {
                'links': {'data': {...}},
                'paging': {'limit': 500, 'page': 1, 'page_total': 1, 'range_max': 15, 'range_min': 1, 'total_count': 15},
                'results': {
                    'column_descriptions': [
                        {
                            'fieldLabel': 'AccountDetail.AccountID',
                            'fieldName': 'Account.ID',
                            'keyField': 'X',
                            'length': 18,
                            'position': 4
                        },
                        {
                            'fieldLabel': 'AccountName',
                            'fieldName': 'Account.Name',
                            'keyField': ' ',
                            'length': 255,
                            'position': 2
                        },
                        {
                            'fieldLabel': 'AccountNumber',
                            'fieldName': 'Account.AccountNumber',
                            'keyField': ' ',
                            'length': 40,
                            'position': 3
                        },
                        ...
                    ]
                    'max_rows_exceeded': False,
                    'result_rows': [
                        {
                            'AccountDetail.AccountID': '001Dn00000w0bCQIAY',
                            'AccountDetail.AccountName': 'Jet Stream Inc.',
                            'AccountDetail.AccountNumber': '1234567',
                            'AccountDetail.AccountOwner': 'Nick Wheeler',
                            'AccountDetail.AnnualRevenue': '$900001',
                            'AccountDetail.Description': '',
                            'AccountDetail.Employees': '',
                            'AccountDetail.Industry': 'Biotechnology',
                            'AccountDetail.ParentAccount': '',
                            ...
                        },
                        ...
                    ]
                }
            }
            ```

        """

        query = {
            "ext_system_id": external_system_id,
            "bo_type": type_name,
        }
        if limit:
            query["limit"] = limit
        if page:
            query["page"] = page
        if where_clauses:
            query.update(
                {("where_" + key): value for key, value in where_clauses.items()},
            )

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["businessObjectsUrl"] + "?{}".format(encoded_query)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get all business objects of type -> '%s' from external system -> %s; calling -> %s",
            type_name,
            external_system_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get business objects of type -> '{}' from external system -> {}".format(
                type_name,
                external_system_id,
            ),
        )

    # end method definition

    def get_business_objects_search(
        self,
        external_system_id: str,
        type_name: str,
    ) -> dict | None:
        """Get business object type information.

        Unfortunately this REST API is pretty much limited. It does not return
        Field names of external system properties and also does not return property
        groups defined.

        Args:
            external_system_id (str):
                The External system ID (such as "TM6").
            type_name (str):
                Type name of the business object (such as "SAP Customer").

        Returns:
            dict | None:
                Business Object Search Form or None if the request fails.

        """

        query = {
            "ext_system_id": external_system_id,
            "bo_type": type_name,
        }

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["businessObjectsSearchUrl"] + "?{}".format(
            encoded_query,
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Get search form for business object type -> '%s' and external system -> %s; calling -> %s",
            type_name,
            external_system_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get search form for business object type -> '{}' and external system -> {}".format(
                type_name,
                external_system_id,
            ),
        )

    # end method definition

    def get_workspace_types(
        self,
        expand_workspace_info: bool = True,
        expand_templates: bool = True,
    ) -> dict | None:
        """Get all workspace types configured in Extended ECM.

        This REST API is very limited. It does not return all workspace type properties
        you can see in Extended ECM admin page.

        Args:
            expand_workspace_info (bool, optional):
                Controls if the workspace info is returned as well
            expand_templates (bool, optional):
                Controls if the list of workspace templates
                per workspace type is returned as well

        Returns:
            dict | None:
                Workspace Types or None if the request fails.

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'results': [
                    {
                        'data': {
                            'properties': {
                                'rm_enabled': False,
                                'templates': [
                                    {
                                        'id': 14471,
                                        'name': 'Campaign',
                                        'subtype': 848
                                    },
                                    ...
                                ],
                                'wksp_type_id': 35,
                                'wksp_type_name': 'Campaign'
                            },
                            'wksp_info': {
                                'wksp_type_icon': '/appimg/ot_bws/icons/13147%2Esvg?v=161108_84584'
                            }
                        }
                    }
                ]
            }
            ```

        """

        request_url = self.config()["businessWorkspaceTypesUrl"]
        if expand_templates:
            request_url += "?expand_templates=true"
        else:
            request_url += "?expand_templates=false"
        if expand_workspace_info:
            request_url += "&expand_wksp_info=true"
        else:
            request_url += "&expand_wksp_info=false"

        request_header = self.request_form_header()

        self.logger.debug("Get workspace types; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workspace types",
        )

    # end method definition

    def get_workspace_create_form(
        self,
        template_id: int,
        external_system_id: str | None = None,
        bo_type: str | None = None,
        bo_id: str | None = None,
        parent_id: int | None = None,
    ) -> dict | None:
        """Get the Workspace create form.

        Args:
            template_id (int):
                The ID of the workspace template.
            external_system_id (str, optional):
                Identifier of the external system (None if no external system).
            bo_type (str, optional):
                Business object type (should be None if no external system connected).
            bo_id (str, optional):
                Business object identifier / key (None if no external system).
            parent_id (int, optional):
                Parent ID of the workspaces. Needs only be specified in special
                cases where workspace location cannot be derived from workspace
                type definition, e.g. sub-workspace

        Returns:
            dict | None:
                Workspace Create Form data or None if the request fails.

        """

        request_url = self.config()["businessworkspacecreateform"] + "?template_id={}".format(template_id)
        # Is a parent ID specifified? Then we need to add it to the request URL
        if parent_id is not None:
            request_url += "&parent_id={}".format(parent_id)
        # Is this workspace connected to a business application / external system?
        if external_system_id and bo_type and bo_id:
            request_url += "&ext_system_id={}".format(external_system_id)
            request_url += "&bo_type={}".format(bo_type)
            request_url += "&bo_id={}".format(bo_id)
            self.logger.debug(
                "Include business object connection -> (%s, %s, %s) in workspace create form...",
                external_system_id,
                bo_type,
                bo_id,
            )
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace create form for workspace template ID -> %s; calling -> %s",
            str(template_id),
            request_url,
        )

        if parent_id:
            failure_message = "Failed to get workspace create form for template -> {} and parent ID -> {}".format(
                template_id,
                parent_id,
            )
        else:
            failure_message = (
                "Failed to get workspace create form for template -> {} (called without parent ID)".format(
                    template_id,
                )
            )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message=failure_message,
        )

    # end method definition

    def get_workspace(self, node_id: int) -> dict | None:
        """Get a workspace based on the node ID.

        Args:
            node_id (int):
                The node ID of the workspace to retrieve.

        Returns:
            dict | None:
                Workspace node information or None if no node with this ID is found.

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'meta_data': {
                    'properties': {...}
                },
                'paging': {
                    'limit': 500,
                    'page': 1,
                    'page_total': 1,
                    'range_max': 1,
                    'range_min': 1,
                    'total_count': 1
                },
                'results': [
                    {
                        'actions': {...},
                        'data': {
                            'business_properties': {
                                'business_object_id': '000004000240',
                                'business_object_type': 'BUS2007',
                                'business_object_type_id': 18,
                                'business_object_type_name': 'Maintenance Order',
                                'business_object_type_name_multilingual': {...},
                                'display_url': "https://fiori.qa.idea-te.eimdemo.com:8443/sap/bc/ui2/flp#MaintenanceOrder-displayXecmFactSheet&//C_ObjPgMaintOrder('000004000240')",
                                'external_system_id': 'TM6',
                                'external_system_name': 'TM6',
                                'has_default_display': True,
                                'has_default_search': True,
                                'isEarly': False,
                                'workspace_type_id': 42,
                                'workspace_type_name': 'Maintenance Order',
                                'workspace_type_name_multilingual': {},
                                ...
                            }
                            'properties': {
                                'volume_id': -2000,
                                'id': 36780,
                                'parent_id': 13567,
                                'owner_user_id': 7240,
                                'name': '4600000044 - C.E.B. New York Inc.',
                                'type': 848,
                                'description': '',
                                'create_date': '2023-09-02T11:07:06',
                                'create_user_id': 7240,
                                'create_user_id': 7240,
                                'modify_date': '2023-09-02T11:07:11',
                                'modify_user_id': 7240,
                                'reserved': False,
                                'reserved_user_id': 0,
                                'reserved_date': None,
                                'order': None,
                                'icon': '/cssupport/otsapxecm/wksp_contract_vendor.png',
                                'hidden': False,
                                'mime_type': None,
                                'original_id': 0,
                                'wnf_wksp_type_id': 16,
                                'wnf_wksp_template_id': 15615,
                                'size_formatted': '7 Items',
                                'type_name': 'Business Workspace',
                                'container': True,
                                'size': 7,
                                ...
                            }
                            'wksp_info':
                            {
                                'wksp_type_icon': '/appimg/ot_bws/icons/16634%2Esvg?v=161194_13949'
                            }
                        },
                        'metadata': {...},
                        'metadata_order': {
                            'categories': ['16878']
                        }
                    }
                ],
                'wksp_info': {
                    'wksp_type_icon': None
                }
                'workspace_references': [
                    {
                        'business_object_id': '000004000240',
                        'business_object_type': 'BUS2007',
                        'business_object_type_id': 18,
                        'external_system_id': 'TM6',
                        'has_default_display': True,
                        'has_default_search': True,
                        'workspace_type_id': 42
                    }
                ]
            }
            ```

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(node_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workspace with ID -> {}".format(node_id),
        )

    # end method definition

    def get_workspace_instances(
        self,
        type_name: str | None = None,
        type_id: int | None = None,
        expanded_view: bool = True,
        page: int | None = None,
        limit: int | None = None,
    ) -> dict | None:
        """Get all workspace instances of a given type.

        This is a convenience wrapper method for get_workspace_by_type_and_name()

        The workspace type must be provided either as the type ID or the type name.
        If both, the type name and type ID are provided the type name takes preference
        and the type ID is ignored. This may not be what you want.

        Args:
            type_name (str, optional):
                The name of the workspace type. CAREFUL: the REST API seems to apply
                a "starts with" filter, e.g. if you have two workspace types called
                "Product" and "Product Version" then workspaces instances of both types
                are returned if you provide "Product" for type_name !
                Preferrable use type_id if you can!
            type_id (int, optional):
                The ID of the workspace_type.
            expanded_view (bool, optional):
                If False, then just search in recently accessed business workspace
                for this name and type.
                If True, (this is the default) then search in all
                workspaces for this name and type.
            limit (int | None, optional):
                The maximum number of workspace instances that should be delivered
                in one page.
                The default is None, in this case the internal OTCS limit
                seems to be 500.
            page (int | None, optional):
                The page to be returned (if more workspace instances exist
                than given by the page limit).
                The default is None.

        Returns:
            dict | None:
                Workspace information or None if the workspace is not found.

        """

        # Omitting the name lets it return all instances of the type:
        return self.get_workspace_by_type_and_name(
            type_name=type_name,
            type_id=type_id,
            name="",
            expanded_view=expanded_view,
            page=page,
            limit=limit,
        )

    # end method definition

    def get_workspace_instances_iterator(
        self,
        type_name: str | None = None,
        type_id: int | None = None,
        expanded_view: bool = True,
        page_size: int = 100,
    ) -> iter:
        """Get an iterator object to traverse all workspace instances of a workspace type.

        Returning a generator avoids loading a large number of workspace instances
        at once. Instead you can iterate over the potential large list of subnodes.

        Example usage:
            ```python
            workspace_instances = otcs_object.get_workspace_instances_iterator(type_id=2)
            for workspace in workspace_instances:
                workspace = workspace.get("data").get("properties")
                logger.info("Traversing workspace instance -> %s (%s)", workspace["name"], workspace["id"])
            ```

        Args:
            type_name (str, optional):
                The name of the workspace type. CAREFUL: the REST API seems to apply
                a "starts with" filter, e.g. if you have two workspace types called
                "Product" and "Product Version" then workspaces instances of both types
                are returned if you provide "Product" for type_name !
                Preferrable use type_id if you can!
            type_id (int, optional):
                The ID of the workspace_type.
            expanded_view (bool, optional):
                If False, then just search in recently accessed business workspace
                for this name and type.
                If True, (this is the default) then search in all workspaces for this name and type.
            page_size (int | None, optional):
                The maximum number of workspace instances that should be delivered in one page.
                The default is None, in this case the internal OTCS limit seems to be 500.

        Returns:
            iter:
                A generator yielding one workspace instance per iteration.
                If the REST API fails, returns no value.

        """

        # Send a minimum "probe" to determine the total number of instances:
        response = self.get_workspace_by_type_and_name(
            type_name=type_name,
            type_id=type_id,
            name="",
            expanded_view=expanded_view,
            page=1,
            limit=1,
        )
        if not response or "results" not in response:
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        number_of_instances = response["paging"]["total_count"]
        if not number_of_instances:
            self.logger.warning(
                "Workspace type -> %s does not have instances! Cannot iterate over instances.",
                type_name if type_name else str(type_id),
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        # If the group has many members we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (number_of_instances + page_size - 1) // page_size

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.get_workspace_by_type_and_name(
                type_name=type_name,
                type_id=type_id,
                name="",
                expanded_view=expanded_view,
                page=page,
                limit=page_size,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve workspace instances for workspace type -> %s (page -> %d)",
                    type_name if type_name else str(type_id),
                    page,
                )
                return

            # Yield nodes one at a time
            yield from response["results"]

        # end for page in range(1, total_pages + 1)

    # end method definition

    def get_workspace_by_type_and_name(
        self,
        type_name: str = "",
        type_id: int | None = None,
        name: str = "",
        expanded_view: bool = True,
        page: int | None = None,
        limit: int | None = None,
        timeout: int = REQUEST_TIMEOUT,
    ) -> dict | None:
        """Lookup workspaces based on workspace type and workspace name.

        There can be multiple workspaces in the result. This depends on
        the provided combination of workspace type and workspace name.
        The workspace name is optional. The workspace type must be provided
        either as the type ID or the type name.

        Args:
            type_name (str, optional):
                The name of the workspace type.
            type_id (int, optional):
                The ID of the workspace_type.
            name (str, optional):
                Name of the workspace, if "" then deliver all instances
                of the given workspace type. If the name is provided
                the prefixes 'contains_' and 'startswith_' are supported
                like 'contains_Test' to find workspace that have 'Test'
                in their name.
            expanded_view (bool, optional):
                If False, then just search in recently
                accessed business workspace for this name and type.
                If True (this is the default), then search in all
                workspaces for this name and type.
            limit (int | None, optional):
                The maximum number of workspace instances that should be delivered in one page.
                The default is None, in this case the internal OTCS limit seems to be 500.
            page (int | None, optional):
                The page to be returned (if more workspace instances exist than given by the page limit).
                The default is None.
            timeout (int, optional):
                Specific timeout for the request in seconds. The default is the standard
                timeout value REQUEST_TIMEOUT used by the OTCS module.

        Returns:
            dict | None:
                Workspace information or None if the workspace is not found.

        Example:
            ```json
            {
                'links': {'data': {...}},
                'paging': {
                    'actions': {
                        'next': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/businessworkspaces?expanded_view=True&where_workspace_type_name=Product&page=2&limit=10',
                            'method': 'GET',
                            'name': ''
                        }
                    },
                    limit': 10,
                    'page': 1,
                    'page_total': 81,
                    'range_max': 10,
                    'range_min': 1,
                    'total_count': 806
                },
                'results': [
                    {
                        'actions': {
                            'data': {
                                'open': {...}
                            },
                            'map': {
                                'default_action': 'open'
                            },
                            'order': ['open']
                        },
                        'data': {
                            'properties': {
                                'volume_id': -2000,
                                'id': 8291,
                                'parent_id': 6129,
                                'owner_user_id': 1000,
                                'name': 'ArcSight Enterprise Security Manager',
                                'type': 848,
                                'description': 'OpenText™ ArcSight™ Enterprise Security Manager (ESM) is a powerful, adaptable SIEM...',
                                'create_date': '2025-01-05T18:00:37',
                                'create_user_id': 1000,
                                'modify_date': '2025-01-05T18:00:44',
                                'modify_user_id': 1000,
                                'reserved': False,
                                'reserved_user_id': 0,
                                'reserved_date': None,
                                'order': None,
                                'icon': '/cssupport/otsapxecm/wksp_material.png',
                                'hidden': False,
                                'mime_type': None,
                                'original_id': 0,
                                ...
                            }
                        }
                    },
                    {
                        'actions': {...},
                        'data': {...}
                    },
                    ...
                ],
                'wksp_info': {'wksp_type_icon': None}
            }
            ```

        """

        if not type_name and not type_id:
            self.logger.error(
                "No workspace type specified - neither by type name nor type ID. Cannot lookup workspace(s)!",
            )
            return None

        # Add query parameters (these are NOT passed via JSon body!)
        query = {
            "expanded_view": expanded_view,
        }
        if type_name:
            query["where_workspace_type_name"] = type_name
        if type_id:
            query["where_workspace_type_id"] = type_id
        if name:
            query["where_name"] = name
        if page and limit:
            query["page"] = page
            query["limit"] = limit

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["businessWorkspacesUrl"] + "?{}".format(
            encoded_query,
        )
        request_header = self.request_form_header()

        if name:
            if type_name:
                self.logger.debug(
                    "Get workspace with name -> '%s' and type -> '%s'; calling -> %s",
                    name,
                    type_name,
                    request_url,
                )
                failure_message = "Failed to get workspace with name -> '{}' and type -> '{}'".format(
                    name,
                    type_name,
                )
            else:
                self.logger.debug(
                    "Get workspace with name -> '%s' and type ID -> '%s'; calling -> %s",
                    name,
                    str(type_id),
                    request_url,
                )
                failure_message = "Failed to get workspace with name -> '{}' and type ID -> '{}'".format(
                    name,
                    type_id,
                )
        elif type_name:
            self.logger.debug(
                "Get all workspace instances of type -> '%s'; calling -> %s",
                type_name,
                request_url,
            )
            failure_message = "Failed to get all workspace instances of type -> '{}'".format(
                type_name,
            )
        else:
            self.logger.debug(
                "Get all workspace instances with type ID -> %s; calling -> %s",
                str(type_id),
                request_url,
            )
            failure_message = "Failed to get all workspace instances with type ID -> {}".format(
                type_id,
            )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=timeout,
            failure_message=failure_message,
        )

    # end method definition

    def get_workspace_type_location(
        self,
        type_name: str = "",
        type_id: int | None = None,
    ) -> int | None:
        """Determine the folder in which the workspace instances of a given type reside.

        Either the type ID or the type name need to be provided. NOTE: workspace types
        may not always have a default location for all its instances. In such case
        `parent_id` may just be the folder of the first delivered workspace instance.

        Args:
            type_name (str, optional):
                The name of the workspace type. Defaults to "".
            type_id (int, optional):
                The ID of the workspace type. Defaults to None.

        Returns:
            int | None:
                The node ID of the parent folder.

        """

        # It seems there's no other way to get the workspace location configured for a
        # workspace type other then getting an example workspace of this type and see
        # what the parent is. The REST API used for get_workspace_types() does not
        # deliver this information :-(
        # TODO: this implementation has the bad limitation that the parent cannot
        # be determined if no workspace instance exists! This should be
        # reviewed once we have an REST API for Workspace Types.
        response = self.get_workspace_by_type_and_name(
            type_name=type_name,
            type_id=type_id,
            page=1,
            limit=1,
        )

        return self.get_result_value(response=response, key="parent_id")

    # end method definition

    def get_workspace_by_business_object(
        self,
        external_system_name: str,
        business_object_type: str,
        business_object_id: str,
        return_workspace_metadata: bool = False,
        show_error: bool = False,
    ) -> dict | None:
        """Get a workspace based on the business object of an external system.

        Args:
            external_system_name (str):
                The name of the external system connection.
            business_object_type (str):
                Type of the Business object, e.g. KNA1 for SAP customers
            business_object_id (str):
                ID of the business object in the external system
            return_workspace_metadata (bool, optional):
                Whether or not workspace metadata (categories) should be returned.
                Default is False.
            show_error (bool, optional):
                Treat as error if node is not found. Default is False.

        Returns:
            dict | None:
                Workspace node information or None if no node with this ID is found.

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'meta_data': {
                    'properties': {...}
                },
                'paging': {
                    'limit': 500,
                    'page': 1,
                    'page_total': 1,
                    'range_max': 1,
                    'range_min': 1,
                    'total_count': 1
                },
                'results': [
                    {
                        'actions': {...},
                        'data': {
                            'properties': {
                                'volume_id': -2000,
                                'id': 36780,
                                'parent_id': 13567,
                                'owner_user_id': 7240,
                                'name': '4600000044 - C.E.B. New York Inc.',
                                'type': 848,
                                'description': '',
                                'create_date': '2023-09-02T11:07:06',
                                'create_user_id': 7240,
                                'create_user_id': 7240,
                                'modify_date': '2023-09-02T11:07:11',
                                'modify_user_id': 7240,
                                'reserved': False,
                                'reserved_user_id': 0,
                                'reserved_date': None,
                                'order': None,
                                'icon': '/cssupport/otsapxecm/wksp_contract_vendor.png',
                                'hidden': False,
                                'mime_type': None,
                                'original_id': 0,
                                'wnf_wksp_type_id': 16,
                                'wnf_wksp_template_id': 15615,
                                'size_formatted': '7 Items',
                                'type_name': 'Business Workspace',
                                'container': True,
                                'size': 7,
                                ...
                            }
                        },
                        'metadata': {...},
                        'metadata_order': {...}
                    }
                ],
                'wksp_info': {
                    'wksp_type_icon': None
                }
            }
            ```

        """

        request_url = (
            self.config()["externalSystemUrl"]
            + "/"
            + external_system_name
            + "/botypes/"
            + business_object_type
            + "/boids/"
            + business_object_id
        )
        if return_workspace_metadata:
            request_url += "?metadata"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace via external system -> '%s' (Business Object Type -> '%s'; Business Object ID -> %s); calling -> %s",
            external_system_name,
            business_object_type,
            business_object_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            warning_message="Cannot get workspace via external system -> '{}', Business Object Type -> '{}', and Business Object ID -> {}. It does not exist.".format(
                external_system_name,
                business_object_type,
                business_object_id,
            ),
            failure_message="Failed to get workspace via external system -> '{}', Business Object Type -> '{}', and Business Object ID -> {}".format(
                external_system_name,
                business_object_type,
                business_object_id,
            ),
            show_error=show_error,
        )

    # end method definition

    def set_workspace_reference(
        self,
        workspace_id: int,
        external_system_id: str | None = None,
        bo_type: str | None = None,
        bo_id: str | None = None,
        show_error: bool = True,
    ) -> dict | None:
        """Set reference of workspace to a business object in an external system.

        Args:
            workspace_id (int):
                The ID of the workspace.
            external_system_id (str, optional):
                Identifier of the external system (None if no external system).
            bo_type (str, optional):
                Business object type (None if no external system)
            bo_id (str, optional):
                Business object identifier / key (None if no external system)
            show_error (bool, optional):
                Log an error if workspace cration fails. Otherwise log a warning.

        Returns:
            Request response or None in case of an error.

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(workspace_id) + "/workspacereferences"
        request_header = self.request_form_header()

        if not external_system_id or not bo_type or not bo_id:
            self.logger.error(
                "Cannot update workspace reference - required Business Object information is missing!",
            )
            return None

        self.logger.debug(
            "Update workspace reference of workspace ID -> %s with business object connection -> (%s, %s, %s); calling -> %s",
            str(workspace_id),
            external_system_id,
            bo_type,
            bo_id,
            request_url,
        )

        workspace_put_data = {
            "ext_system_id": external_system_id,
            "bo_type": bo_type,
            "bo_id": bo_id,
        }

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=workspace_put_data,
            timeout=None,
            warning_message="Cannot update reference for workspace ID -> {} with business object connection -> ({}, {}, {})".format(
                workspace_id,
                external_system_id,
                bo_type,
                bo_id,
            ),
            failure_message="Failed to update reference for workspace ID -> {} with business object connection -> ({}, {}, {})".format(
                workspace_id,
                external_system_id,
                bo_type,
                bo_id,
            ),
            show_error=show_error,
        )

    # end method definition

    def create_workspace(
        self,
        workspace_template_id: int,
        workspace_name: str,
        workspace_description: str,
        workspace_type: int,
        category_data: dict | None = None,
        classifications: list | None = None,
        external_system_id: str | None = None,
        bo_type: str | None = None,
        bo_id: str | None = None,
        parent_id: int | None = None,
        ibo_workspace_id: int | None = None,
        external_modify_date: str | None = None,
        external_create_date: str | None = None,
        show_error: bool = True,
    ) -> dict | None:
        """Create a new business workspace.

        This method creates a new workspace based on the provided
        template and type, with optional category data and business object details.
        It also supports linking to external systems and specifying metadata such as
        creation and modification dates.

        Args:
            workspace_template_id (int):
                The ID of the workspace template to be used.
            workspace_name (str):
                The name of the new workspace.
            workspace_description (str):
                A description of the new workspace.
            workspace_type (int):
                Type ID of the workspace, indicating its category or function.
            category_data (dict, optional):
                Category and attribute data for the workspace.
            classifications (list):
                List of classification item IDs to apply to the new item.
            external_system_id (str, optional):
                External system identifier if linking the workspace to an external system.
            bo_type (str, optional):
                Business object type, used if linking to an external system.
            bo_id (str, optional):
                Business object identifier or key, used if linking to an external system.
            parent_id (int, optional):
                ID of the parent workspace, required in special cases such as
                sub-workspaces or location ambiguity.
            ibo_workspace_id (int, optional):
                ID of an existing workspace that is already linked to an external system.
                Allows connecting multiple business objects (IBO).
            external_create_date (str, optional):
                Date of creation in the external system (format: YYYY-MM-DD).
            external_modify_date (str, optional):
                Date of last modification in the external system (format: YYYY-MM-DD).
            show_error (bool, optional):
                If True, log an error if workspace creation fails.
                If False, log a warning instead.

        Returns:
            dict | None:
                The Workspace creation data or `None` if the request fails.

        Notes:
            If `parent_id` is not provided, the workspace will be created based
            on the workspace type definition.
            This method supports external system integration by linking workspaces
            to business objects (BO) or IBO (Identical Business Objects).

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/businessworkspaces',
                            'method': 'POST',
                            'name': ''
                        }
                    }
                },
                'results': {
                    'direct_open': True,
                    'id': 224082,
                    'sub_folder_id': 0
                }
            }
            ```

        """

        create_workspace_post_data = {
            "template_id": str(workspace_template_id),
            "name": workspace_name,
            "description": workspace_description,
            "wksp_type_id": str(workspace_type),
            "type": str(self.ITEM_TYPE_BUSINESS_WORKSPACE),
            "roles": {},  # category_data,
        }

        if category_data:
            create_workspace_post_data["roles"]["categories"] = category_data
        if external_create_date:
            create_workspace_post_data["external_create_date"] = external_create_date
        if external_modify_date:
            create_workspace_post_data["external_modify_date"] = external_modify_date

        # Is this workspace connected to a business application / external system?
        if external_system_id and bo_type and bo_id:
            create_workspace_post_data["ext_system_id"] = external_system_id
            create_workspace_post_data["bo_type"] = bo_type
            create_workspace_post_data["bo_id"] = bo_id
            self.logger.debug(
                "Use business object connection -> (%s, %s, %s) for workspace -> '%s'",
                external_system_id,
                bo_type,
                bo_id,
                workspace_name,
            )
            if ibo_workspace_id:
                self.logger.debug(
                    "This is a subsequent call to create a cross-application workspace (IBO)",
                )
                create_workspace_post_data["ibo_workspace_id"] = ibo_workspace_id

        # If workspace creation location cannot be derived from the workspace type
        # there may be an optional parent parameter passed to this method. This can
        # also be the case if workspaces are nested into each other:
        if parent_id is not None:
            create_workspace_post_data["parent_id"] = parent_id
            self.logger.debug(
                "Use specified location -> %s for workspace -> '%s'",
                str(parent_id),
                workspace_name,
            )
        else:
            self.logger.debug(
                "Location of workspace -> '%s' will automatically be determined via workspace type -> '%s'",
                workspace_name,
                str(workspace_type),
            )

        request_url = self.config()["businessWorkspacesUrl"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Create workspace -> '%s' with type -> '%s' from template -> %s with payload -> %s; calling -> %s",
            workspace_name,
            str(workspace_type),
            str(workspace_template_id),
            str(create_workspace_post_data),
            request_url,
        )

        # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
        # See https://developer.opentext.com/apis/14ba85a7-4693-48d3-8c93-9214c663edd2/4403207c-40f1-476a-b794-fdb563e37e1f/07229613-7ef4-4519-8b8a-47eaff639d42#operation/createBusinessWorkspace
        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(create_workspace_post_data)},
            timeout=None,
            warning_message="Failed to create workspace -> '{}' from template with ID -> {}".format(
                workspace_name,
                workspace_template_id,
            ),
            failure_message="Failed to create workspace -> '{}' from template with ID -> {}".format(
                workspace_name,
                workspace_template_id,
            ),
            show_error=show_error,
            show_warning=(not show_error),
        )

        node_id = self.get_result_value(response=response, key="id")

        if node_id and classifications:
            self.assign_classifications(node_id=node_id, classifications=classifications)

        return response

    # end method definition

    def update_workspace(
        self,
        workspace_id: int,
        workspace_name: str | None = None,
        workspace_description: str | None = None,
        category_data: dict | None = None,
        external_system_id: str | None = None,
        bo_type: str | None = None,
        bo_id: str | None = None,
        external_modify_date: str | None = None,
        external_create_date: str | None = None,
        show_error: bool = True,
    ) -> bool:
        """Update an existing business workspace.

        This is a wrapper method to update a combination of workspace name / description,
        workspace reference, and workspace metadata

        Args:
            workspace_id (int):
                The ID of the workspace.
            workspace_name (str):
                New Name of the workspace (renaming).
                Default is None (no renaming).
            workspace_description (str):
                New Description of the workspace.
                Default is None (description is not changed).
            category_data (dict):
                Category and attribute data.
                Default is None (attributes remain unchanged).
            external_system_id (str, optional):
                Identifier of the external system (None if no external system)
            bo_type (str, optional):
                Business object type (None if no external system)
            bo_id (str, optional):
                Business object identifier / key (None if no external system)
            external_create_date (str, optional):
                Date of creation in the external system
                (format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS).
            external_modify_date (str, optional):
                Date of last modification in the external system
                (format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS).
            show_error (bool, optional):
                If True, log an error if workspace cration fails.
                Otherwise log a warning.

        Returns:
            bool:
                True = success, False if the request fails.

        """

        # Should we connect this workspace to a business application / external system?
        if external_system_id and bo_type and bo_id:
            response = self.set_workspace_reference(
                workspace_id=workspace_id,
                external_system_id=external_system_id,
                bo_type=bo_type,
                bo_id=bo_id,
                show_error=show_error,
            )
            if not response:
                return False

        # Should we change the name and/or the description or the
        # category data of this workspace?
        if workspace_name or workspace_description or category_data:
            response = self.update_item(
                node_id=workspace_id,
                item_name=workspace_name,
                item_description=workspace_description,
                category_data=category_data,
                external_create_date=external_create_date,
                external_modify_date=external_modify_date,
            )
            if not response:
                return False

        return True

    # end method definition

    def create_workspace_relationship(
        self,
        workspace_id: int,
        related_workspace_id: int,
        relationship_type: str = "child",
        show_error: bool = True,
    ) -> dict | None:
        """Create a relationship between two workspaces.

        Args:
            workspace_id (int):
                The ID of the workspace.
            related_workspace_id (int):
                The ID of the related workspace.
            relationship_type (str, optional):
                Can be "parent" or "child" - "child" is default if not provided.
            show_error (bool, optional):
                If True, log an error if relationship cration fails.
                Otherwise log a warning.

        Returns:
            dict | None:
                Workspace Relationship data (json) or None if the request fails.

        """

        create_workspace_relationship_post_data = {
            "rel_bw_id": str(related_workspace_id),
            "rel_type": relationship_type,
        }

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/relateditems".format(workspace_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Create workspace relationship between -> %s and -> %s; calling -> %s",
            str(workspace_id),
            str(related_workspace_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_workspace_relationship_post_data,
            timeout=None,
            warning_message="Cannot create workspace relationship between -> {} and -> {}. It may already exist.".format(
                workspace_id,
                related_workspace_id,
            ),
            failure_message="Failed to create workspace relationship between -> {} and -> {}".format(
                workspace_id,
                related_workspace_id,
            ),
            show_error=show_error,
        )

    # end method definition

    def get_workspace_relationships(
        self,
        workspace_id: int,
        relationship_type: str | list | None = None,
        related_workspace_name: str | None = None,
        related_workspace_type_id: int | list | None = None,
        limit: int | None = None,
        page: int | None = None,
        fields: (str | list) = "properties",  # per default we just get the most important information
    ) -> dict | None:
        """Get the Workspace relationships to other workspaces.

        Optionally, filter criterias can be provided
        such as the related workspace name (starts with) or
        the related workspace TYPE ids (one or multiple)

        Args:
            workspace_id (int):
                The ID of the workspace.
            relationship_type (str):
                Either "parent" or "child" (or None = unspecified which is the default).
            related_workspace_name (str, optional):
                Filter for a certain workspace name in the related items.
            related_workspace_type_id (int | list | None):
                ID of related workspace type (or list of IDs)
            limit (int | None, optional):
                The maximum number of related workspaces that should be
                delivered in one page.
                The default is None, in this case the internal OTCS limit
                seems to be 500.
            page (int | None, optional):
                The page to be returned (if more relationships exist than given
                by the page limit).
                The default is None.
            fields (str | list, optional):
                Which fields to retrieve. This can have a significant
                impact on performance.
                Possible fields include:
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "categories"
                - "versions" (can be further restricted by specifying ".element(0)" to
                  retrieve only the latest version)
                - "permissions" (can be further restricted by specifying ".limit(5)" to
                  retrieve only the first 5 permissions)
                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".

        Returns:
            dict | None:
                Workspace relationships or None if the request fails.

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'paging': {
                    'actions': {...},
                    'limit': 100,
                    'page': 1,
                    'page_total': 22,
                    'range_max': 100,
                    'range_min': 1,
                    'total_count': 2146
                },
                'results': [
                    {
                        'actions': {
                            'data': {
                                'deleterelateditem': {
                                    'body': '',
                                    'content_type': '',
                                    'form_href': '',
                                    'href': '/api/v2/businessworkspaces/8919/relateditems/150514?rel_type=Child',
                                    'method': 'DELETE',
                                    'name': 'Remove related item'
                                },
                                'open': {
                                    'body': '',
                                    'content_type': '',
                                    'form_href': '',
                                    'href': '/api/v2/nodes/150514/nodes',
                                    'method': 'GET',
                                    'name': 'Open'
                                }
                            },
                            'map': {
                                'default_action': 'open',
                                'more': [...]
                            },
                            'order': [
                                'open',
                                'deleterelateditem'
                            ]
                        },
                        'data': {
                            'properties': {
                                'volume_id': -2000,
                                'id': 150514,
                                'parent_id': 6304,
                                'owner_user_id': 1000,
                                'name': 'KB0800036',
                                'type': 848,
                                'description':
                                'Vendor Invoice Management for SAP Solutions - Business Rule (BR) 418 triggered incorrectly',
                                'create_date': '2025-01-14T13:15:13',
                                'create_user_id': 1000,
                                'modify_date': '2025-01-14T13:15:27',
                                'modify_user_id': 1000,
                                'reserved': False,
                                'reserved_user_id': 0,
                                'reserved_date': None,
                                'order': None,
                                'icon': '/cssupport/casebasic/casetype_06.gif',
                                'hidden': False,
                                'mime_type': None,
                                'original_id': 0,
                                'wnd_comments': None,
                                'wnd_modifiedby': 1000,
                                'wnf_att_7cx_2': None,
                                'wnf_att_7cx_3': None,
                                'wnf_att_7cx_4': None,
                                'wnf_att_7cx_5': None,
                                ...
                        }
                    }
                ],
                'wksp_info': {
                    'wksp_type_icon': '/appimg/ot_bws/icons/6127%2Esvg?v=161528_84074'
                }
            }
            ```

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(workspace_id) + "/relateditems"

        query = {}

        if relationship_type:
            if isinstance(relationship_type, str):
                query["where_relationtype"] = relationship_type
            elif isinstance(relationship_type, list):
                query["where_rel_types"] = relationship_type
            else:
                self.logger.error(
                    "Illegal relationship type for related workspace type!",
                )
                return None

        if related_workspace_name:
            query["where_name"] = related_workspace_name

        if related_workspace_type_id:
            if isinstance(related_workspace_type_id, int):
                query["where_workspace_type_id"] = related_workspace_type_id
            elif isinstance(related_workspace_type_id, list):
                query["where_workspace_type_ids"] = related_workspace_type_id
            else:
                self.logger.error("Illegal data type for related workspace type!")
                return None

        query["page"] = page if page is not None else 1
        if limit is not None:
            query["limit"] = limit
        if fields:
            query["fields"] = fields

        encoded_query = urllib.parse.urlencode(query=query, doseq=False)
        request_url += "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get related workspaces for workspace with ID -> %s; calling -> %s",
            str(workspace_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get related workspaces of workspace with ID -> {}".format(
                workspace_id,
            ),
        )

    # end method definition

    def get_workspace_relationships_iterator(
        self,
        workspace_id: int,
        relationship_type: str | list | None = None,
        related_workspace_name: str | None = None,
        related_workspace_type_id: int | list | None = None,
        fields: (str | list) = "properties",  # per default we just get the most important information
        page_size: int = 100,
    ) -> iter:
        """Get an iterator object to traverse all related workspaces for a workspace.

        Filter criterias can be provided by the parameters.

        Using a generator avoids loading a large number of nodes into memory at once.
        Instead you can iterate over the potential large list of related workspaces.

        Example usage:
            ```python
            related_workspaces = otcs_object.get_workspace_relationships_iterator(workspace_id=15838)
            for workspace in related_workspaces:
                workspace = workspace.get("data").get("properties")
                logger.info("Related workspace name -> '%s'", workspace["name"])
            ```

        Args:
            workspace_id (int):
                The ID of the workspace.
            relationship_type (str):
                Either "parent" or "child" (or None = unspecified which is the default).
            related_workspace_name (str, optional):
                Filter for a certain workspace name in the related items.
            related_workspace_type_id (int | list | None):
                ID of related workspace type (or list of IDs)
            fields (str | list, optional):
                Which fields to retrieve. This can have a significant
                impact on performance.
                Possible fields include:
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "categories"
                - "versions" (can be further restricted by specifying ".element(0)" to
                  retrieve only the latest version)
                - "permissions" (can be further restricted by specifying ".limit(5)" to
                  retrieve only the first 5 permissions)
                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".
            page_size (int, optional):
                The maximum number of related workspaces that should be delivered
                in one page.
                The default is None, in this case the internal OTCS limit seems
                to be 500.
                This is basically the chunk size for the iterator.

        Returns:
            iter:
                A generator yielding one node per iteration under the parent.
                If the REST API fails, returns no value.

        """

        # First we probe how many items we have:
        response = self.get_workspace_relationships(
            workspace_id=workspace_id,
            relationship_type=relationship_type,
            related_workspace_name=related_workspace_name,
            related_workspace_type_id=related_workspace_type_id,
            limit=1,
            page=1,
            fields=fields,
        )
        if not response or "results" not in response:
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        number_of_related_workspaces = response["paging"]["total_count"]
        if not number_of_related_workspaces:
            self.logger.warning(
                "Workspace with node ID -> %s does not have related workspaces! Cannot iterate over related workspaces.",
                str(workspace_id),
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        # If the container has many items we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (number_of_related_workspaces + page_size - 1) // page_size

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.get_workspace_relationships(
                workspace_id=workspace_id,
                relationship_type=relationship_type,
                related_workspace_name=related_workspace_name,
                related_workspace_type_id=related_workspace_type_id,
                limit=page_size,
                page=page,
                fields=fields,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve related workspaces for workspace with node ID -> %d (page -> %d)",
                    workspace_id,
                    page,
                )
                return

            # Yield nodes one at a time
            yield from response["results"]

        # end for page in range(1, total_pages + 1)

    # end method definition

    def delete_workspace_relationship(
        self,
        workspace_id: int,
        related_workspace_id: int,
        relationship_type: str = "child",
        show_error: bool = True,
    ) -> dict | None:
        """Delete a relationship between two workspaces.

        Args:
            workspace_id (int):
                The ID of the workspace.
            related_workspace_id (int):
                The ID of the related workspace.
            relationship_type (str, optional):
                Can be "parent" or "child" - "child" is default if not provided.
            show_error (bool, optional):
                If True, log an error if relationship cration fails.
                Otherwise log a warning.

        Returns:
            dict | None:
                Workspace Relationship data (json) or None if the request fails.

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/relateditems/{}?rel_type={}".format(
            workspace_id,
            related_workspace_id,
            relationship_type,
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Delete workspace relationship between -> %s and -> %s; calling -> %s",
            str(workspace_id),
            str(related_workspace_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=None,
            warning_message="Cannot delete workspace relationship between -> {} and -> {}. It may already exist.".format(
                workspace_id,
                related_workspace_id,
            ),
            failure_message="Failed to delete workspace relationship between -> {} and -> {}".format(
                workspace_id,
                related_workspace_id,
            ),
            show_error=show_error,
        )

    # end method definition

    def delete_workspace_relationships(
        self,
        workspace_id: int,
        relationship_type: str = "child",
        related_workspace_name: str | None = None,
        related_workspace_type_id: int | list | None = None,
    ) -> bool:
        """Delete all relationships of a given workspace to related workspaces.

        Optionally, filter criterias can be provided such as the related workspace name
        (starts with) or the related workspace TYPE ids (one or multiple)

        Args:
            workspace_id (int):
                The ID of the workspace.
            relationship_type (str, optional):
                Either "parent" or "child". "child" is the default.
            related_workspace_name (str, optional):
                Filter for a certain workspace name in the related items.
            related_workspace_type_id (int | list | None):
                ID of related workspace type (or list of IDs)

        Returns:
            dict | None:
                Workspace relationships or None if the request fails.

        """

        # Get an iterator for all matching workspace relationships:
        related_workspaces = self.get_workspace_relationships_iterator(
            workspace_id=workspace_id,
            relationship_type=relationship_type,
            related_workspace_name=related_workspace_name,
            related_workspace_type_id=related_workspace_type_id,
        )

        # Iterate over all matching workspace relationships:
        for workspace in related_workspaces:
            related_workspace = workspace.get("data").get("properties")
            related_workspace_id = related_workspace["id"]
            response = self.delete_workspace_relationship(
                workspace_id=workspace_id,
                related_workspace_id=related_workspace_id,
                relationship_type=relationship_type,
            )
            if not response:
                self.logger.error(
                    "Failed to delete %s relationship between workspace ID -> %s and related workspace ID -> %s",
                    relationship_type,
                    workspace_id,
                    related_workspace_id,
                )
                return False

        return True

    # end method definition

    def get_workspace_roles(self, workspace_id: int) -> dict | None:
        """Get the Workspace roles.

        Args:
            workspace_id (int): ID of the workspace template or workspace

        Returns:
            dict | None: Workspace Roles data or None if the request fails.

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(workspace_id) + "/roles"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace roles of workspace with ID -> %s; calling -> %s",
            str(workspace_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get roles of workspace with ID -> {}".format(
                workspace_id,
            ),
        )

    # end method definition

    def get_workspace_members(self, workspace_id: int, role_id: int) -> dict | None:
        """Get the Workspace members of a given role.

        Args:
            workspace_id (int): ID of the workspace template
            role_id (int): ID of the role

        Returns:
            dict | None: Workspace member data or None if the request fails.

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace members for workspace ID -> %s and role ID -> %s; calling -> %s",
            str(workspace_id),
            str(role_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workspace members",
        )

    # end method definition

    def add_workspace_member(
        self,
        workspace_id: int,
        role_id: int,
        member_id: int,
        show_warning: bool = True,
    ) -> dict | None:
        """Add member to a workspace role. Check that the user/group is not yet a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            member_id (int): User ID or Group ID
            show_warning (bool, optional): If True logs a warning if member is already in role

        Returns:
            dict | None: Workspace Role Membership or None if the request fails.

        """

        self.logger.debug(
            "Check if user/group with ID -> %s is already in role with ID -> %s of workspace with ID -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
        )

        workspace_members = self.get_workspace_members(
            workspace_id=workspace_id,
            role_id=role_id,
        )

        if self.exist_result_item(
            response=workspace_members,
            key="id",
            value=member_id,
        ):
            if show_warning:
                self.logger.warning(
                    "User/group with ID -> %s is already a member of role with ID -> %s of workspace with ID -> %s",
                    str(member_id),
                    str(role_id),
                    str(workspace_id),
                )
            return workspace_members

        add_workspace_member_post_data = {"id": str(member_id)}

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Add user/group with ID -> %s to role with ID -> %s of workspace with ID -> %s; calling -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=add_workspace_member_post_data,
            timeout=None,
            failure_message="Failed to add user/group with ID -> {} to role with ID -> {} of workspace with ID -> {}".format(
                member_id,
                role_id,
                workspace_id,
            ),
        )

    # end method definition

    def remove_workspace_member(
        self,
        workspace_id: int,
        role_id: int,
        member_id: int,
        show_warning: bool = True,
    ) -> dict | None:
        """Remove a member from a workspace role. Check that the user is currently a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            member_id (int): User or Group Id
            show_warning (bool, optional): If True logs a warning if member is not in role

        Returns:
            dict | None: Workspace Role Membership or None if the request fails.

        """

        self.logger.debug(
            "Check if user/group with ID -> %s is in role with ID -> %s of workspace with ID -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
        )

        workspace_members = self.get_workspace_members(
            workspace_id=workspace_id,
            role_id=role_id,
        )

        if not self.exist_result_item(
            response=workspace_members,
            key="id",
            value=member_id,
        ):
            if show_warning:
                self.logger.warning(
                    "User/group with ID -> %s is not a member of role with ID -> %s of workspace with ID -> %s",
                    str(member_id),
                    str(role_id),
                    str(workspace_id),
                )
            return None

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}/members/{}".format(
            workspace_id,
            role_id,
            member_id,
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Removing user/group with ID -> %s from role with ID -> %s of workspace with ID -> %s; calling -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            timeout=None,
            failure_message="Failed to remove user/group with ID -> {} from role with ID -> {} of workspace with ID -> {}".format(
                member_id,
                role_id,
                workspace_id,
            ),
        )

    # end method definition

    def remove_workspace_members(
        self,
        workspace_id: int,
        role_id: int,
        show_warning: bool = True,
    ) -> bool:
        """Remove all members from a workspace role. Check that the user is currently a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            show_warning (bool, optional): If True, logs a warning if member is not in role

        Returns:
            bool: True if success or False if the request fails.

        """

        workspace_members = self.get_workspace_members(
            workspace_id=workspace_id,
            role_id=role_id,
        )

        # Get the list of existing workspace_member ids:
        workspace_member_ids = self.get_result_values(
            response=workspace_members,
            key="id",
        )
        if not workspace_member_ids:
            return False

        for workspace_member_id in workspace_member_ids:
            self.remove_workspace_member(
                workspace_id=workspace_id,
                role_id=role_id,
                member_id=workspace_member_id,
                show_warning=show_warning,
            )

        return True

    # end method definition

    def assign_workspace_permissions(
        self,
        workspace_id: int,
        role_id: int,
        permissions: list,
        apply_to: int = 2,
    ) -> dict | None:
        """Update the permissions for a specific role within a workspace.

        This method assigns specified permissions to a role for a given workspace. It also allows
        specifying whether to apply these permissions to the item itself, its sub-items, or both.

        Args:
            workspace_id (int): ID of the workspace for which the role permissions are being assigned.
            role_id (int): ID of the role to which the permissions will be assigned.
            permissions (list of str): List of permissions to assign to the role. Valid permissions include:
                - "see"               : View the workspace
                - "see_contents"      : View contents of the workspace
                - "modify"            : Modify the workspace
                - "edit_attributes"   : Edit attributes of the workspace
                - "add_items"         : Add items to the workspace
                - "reserve"           : Reserve the workspace
                - "add_major_version" : Add major versions to the workspace
                - "delete_versions"   : Delete versions of the workspace
                - "delete"            : Delete the workspace
                - "edit_permissions"  : Modify permissions for the workspace
            apply_to (int, optional): Specifies the scope of permission assignment. Possible values:
                - 0 = Apply to this item only
                - 1 = Apply to sub-items only
                - 2 = Apply to this item and its sub-items (default)
                - 3 = Apply to this item and its immediate sub-items

        Returns:
            dict | None: Updated workspace role membership details or `None` if the request fails.

        Notes:
            - If `apply_to` is set to `2`, both the workspace and its sub-items will inherit the updated permissions.
            - If `permissions` contains any invalid values, the method may fail or ignore the invalid entries.

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}".format(
            workspace_id,
            role_id,
        )

        request_header = self.request_form_header()

        self.logger.debug(
            "Updating Permissions of role with ID -> %s of workspace with ID -> %s with permissions -> %s; calling -> %s",
            str(role_id),
            str(workspace_id),
            str(permissions),
            request_url,
        )

        permission_put_data = {
            "permissions": permissions,
            "apply_to": apply_to,
        }

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data={"body": json.dumps(permission_put_data)},
            timeout=None,
            failure_message="Failed to update permissions for role with ID -> {} of workspace with ID -> {}".format(
                role_id,
                workspace_id,
            ),
        )

    # end method definition

    def update_workspace_icon(
        self,
        workspace_id: int,
        file_path: str,
        file_mimetype: str = "image/*",
    ) -> dict | None:
        """Update a workspace with a with a new icon (which is uploaded).

        Args:
            workspace_id (int): ID of the workspace
            file_path (str): path + filename of icon file
            file_mimetype (str, optional): mimetype of the image

        Returns:
            dict | None: Node information or None if REST call fails.

        """

        if not os.path.exists(file_path):
            self.logger.error("Workspace icon file does not exist -> %s", file_path)
            return None

        update_workspace_icon_post_body = {
            "file_content_type": file_mimetype,
            "file_filename": os.path.basename(file_path),
        }

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(workspace_id) + "/icons"

        request_header = self.cookie()

        self.logger.debug(
            "Update icon for workspace ID -> %s with icon file -> %s; calling -> %s",
            str(workspace_id),
            file_path,
            request_url,
        )

        with open(file_path, "rb") as icon_file:
            upload_workspace_icon_post_files = [
                (
                    "file",
                    (
                        os.path.basename(file_path),
                        icon_file,
                        file_mimetype,
                    ),
                ),
            ]

            return self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data=update_workspace_icon_post_body,
                files=upload_workspace_icon_post_files,
                timeout=None,
                failure_message="Failed to update workspace ID -> {} with new icon -> '{}'".format(
                    workspace_id,
                    file_path,
                ),
            )

    # end method definition

    def get_unique_names(self, names: list, subtype: int | None = None) -> dict | None:
        """Get definition information for Unique Names.

        Args:
            names (list): list of unique names to lookup.
            subtype (int): filter unique names for those pointing to a specific subtype

        Returns:
            dict | None: Unique name definition information or None if REST call fails.

        Example:
            ```json
            {
                'links': {'data': {...}},
                'results': [
                    {
                        'NodeId': 13653,
                        'NodeName': 'Functional Location',
                        'UniqueName': 'ot_templ_func_location'
                    },
                    {
                        'NodeId': 2424,
                        'NodeName': 'Content Server Document Templates',
                        'UniqueName': 'Document Templates'
                    }
                ]
            }
            ```

        """

        if not names:
            self.logger.error("Missing unique names!")
            return None

        # Add query parameters (these are NOT passed via JSon body!)
        query = {}
        if names:
            query["where_names"] = "{" + ",".join(names) + "}"
        if subtype:
            query["where_subtype"] = subtype

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["uniqueNamesUrl"] + "?{}".format(encoded_query)
        request_header = self.request_form_header()

        if subtype:
            self.logger.debug(
                "Get unique names -> %s of subtype -> %s; calling -> %s",
                str(names),
                str(subtype),
                request_url,
            )
            warning_message = "Failed to get unique names -> {} of subtype -> {}".format(
                names,
                subtype,
            )
        else:
            self.logger.debug(
                "Get unique names -> %s; calling -> %s",
                str(names),
                request_url,
            )
            warning_message = "Failed to get unique names -> {}".format(names)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            warning_message=warning_message,
            show_error=False,
        )

    # end method definition

    def create_item(
        self,
        parent_id: int,
        item_type: int,
        item_name: str,
        item_description: str = "",
        url: str = "",
        original_id: int = 0,
        category_data: dict | None = None,
        classifications: list | None = None,
        body: bool = True,
        show_error: bool = True,
        **kwargs: dict,
    ) -> dict | None:
        """Create a Content Server item.

        This REST call is somewhat limited. It cannot set featured item or hidden item.
        It does also not accept owner group information.

        Args:
            parent_id (int):
                The node ID of the parent.
            item_type (int):
                The type of the item (e.g. 0 = folder, 140 = URL).
                See ITEM_TYPE_* definitions on top of this class.
            item_name (str):
                The name of the item.
            item_description (str, optional):
                The description of the item.
            url (str, optional):
                Address of the URL item (if it is an URL item type).
            original_id (int, optional):
                Node ID of the original (referenced) item.
                Required if a shortcut item is created.
            category_data (dict | None, optional):
                New category and attributes values.
            classifications (list):
                List of classification item IDs to apply to the new item.
            body (bool):
                Should the payload be put in an body tag. Most V2 REST API methods
                do require this but some not (like Scheduled Bots)
            show_error (bool, optional):
                Log an error if item cration fails. Otherwise log a warning.
            **kwargs (dict):
                Add additional attributes to the body of the POST request

        Returns:
            dict | None:
                Request response of the create item call or None if the REST call has failed.

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/nodes',
                            'method': 'POST',
                            'name': ''
                        }
                    }
                },
                'results': {
                    'data': {
                        'properties': {
                            'advanced_versioning': None,
                            'container': True,
                            'container_size': 0,
                            'create_date': '2025-01-19T06:04:29Z',
                            'create_user_id': 1000,
                            'description': 'Test Description',
                            'description_multilingual': {...},
                            'external_create_date': None,
                            'external_identity': '',
                            'external_identity_type': '',
                            'external_modify_date': None,
                            'external_source': '',
                            'favorite': False,
                            'hidden': False,
                            'icon': '/cssupport/webdoc/folder.gif',
                            'icon_large': '/cssupport/webdoc/folder_large.gif',
                            'id': 576313,
                            'mime_type': None,
                            'modify_date': '2025-01-19T06:04:29Z',
                            'modify_user_id': 1000,
                            'name': 'Test',
                            'name_multilingual': {'ar': '', 'de': '', 'en': 'Test', 'es': '', 'fr': '', 'it': '', 'iw': '', 'ja': '', 'nl': ''},
                            'owner': 'Admin',
                            'owner_group_id': 999,
                            'owner_user_id': 1000,
                            'parent_id': 2004,
                            'permissions_model': 'advanced',
                            'reserved': False,
                            'reserved_date': None,
                            'reserved_shared_collaboration': False,
                            'reserved_user_id': 0,
                            'size': 0,
                            'size_formatted': '0 Items',
                            'status': None,
                            'type': 0,
                            'type_name': 'Folder',
                            'versionable': False,
                            'versions_control_advanced': False,
                            'volume_id': -2004
                        }
                    }
                }
            }
            ```

        """

        create_item_post_data = {
            "parent_id": parent_id,
            "type": str(item_type),
            "name": item_name,
            "description": item_description,
            "roles": {},
        }

        # Ability to add undefined arguments
        create_item_post_data.update(kwargs.items())

        if category_data:
            create_item_post_data["roles"]["categories"] = self.flatten_categories_dict(category_data)

        if classifications:
            create_item_post_data["roles"]["classifications"] = {
                "create_id": [],
                "id": classifications,
            }

        if url:
            create_item_post_data["url"] = url
        if original_id > 0:
            create_item_post_data["original_id"] = original_id

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Create item -> '%s' (type -> %s) under parent with ID -> %s; calling -> %s",
            item_name,
            str(item_type),
            str(parent_id),
            request_url,
        )

        # This REST API needs a special treatment: we encapsulate the payload
        # as JSON into a "body" tag.
        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(create_item_post_data)} if body else create_item_post_data,
            timeout=None,
            warning_message="Cannot create item -> '{}'".format(item_name),
            failure_message="Failed to create item -> '{}'".format(item_name),
            show_error=show_error,
        )

    # end method definition

    def update_item(
        self,
        node_id: int,
        parent_id: int | None = None,
        item_name: str | None = None,
        item_description: str | None = None,
        url: str = "",
        category_data: dict | None = None,
        classifications: list | None = None,
        body: bool = True,
        **kwargs: dict | None,
    ) -> dict | None:
        """Update a Content Server item (parent, name, description, metadata).

        Changing the parent ID is a move operation. If parent ID = 0 or None the item will not be moved.
        The category data is updated via a separate REST call if category data is provided.
        For URL items the new URL can be provided.

        Args:
            node_id (int):
                The ID of the node.
            parent_id (int | None, optional):
                The node ID of the new parent (in case of a move operation).
            item_name (str | None, optional):
                The new name of the item.
            item_description (str | None, optional):
                The new description of the item.
            url (str, optional):
                Address of the URL item (if it is an URL item type).
            category_data (dict | None, optional):
                New category and attributes values.
            classifications (list):
                List of classification item IDs to apply to the new item.
            body (bool):
                Should the payload be put in an body tag. Most V2 REST API methods
                do require this but some not (like Scheduled Bots)
            **kwargs (dict):
                Add additional attributes to the body of the POST request

        Returns:
            dict | None:
                Response of the update item request or None if the REST call has failed.

        """

        update_item_put_data = {}

        # Ability to add undefined arguments
        update_item_put_data.update(kwargs)

        if item_name:
            # this is a rename operation
            update_item_put_data["name"] = item_name
        if item_description:
            # this is a change description operation
            update_item_put_data["description"] = item_description
        if parent_id:
            # this is a move operation
            update_item_put_data["parent_id"] = parent_id
        if url:
            # if the item is a URL item
            update_item_put_data["url"] = url

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)

        request_header = self.request_form_header()

        if update_item_put_data:
            self.logger.debug(
                "Update item %s with new data -> %s; calling -> %s",
                "-> '{}' ({})".format(item_name, node_id) if item_name else "with ID -> {}".format(node_id),
                str(update_item_put_data),
                request_url,
            )

            response = self.do_request(
                url=request_url,
                method="PUT",
                headers=request_header,
                data={"body": json.dumps(update_item_put_data)} if body else update_item_put_data,
                timeout=None,
                failure_message="Failed to update item -> '{}' ({})".format(
                    item_name,
                    node_id,
                ),
            )
        else:
            response = None

        # As category data and classifications cannot be added to the REST call above
        # we use seperate methods to set the values for each category separately and classifiions
        # See: https://developer.opentext.com/ce/products/extended-ecm/documentation/content-server-rest-api-implementation-notes/7
        if category_data:
            for category in category_data:
                self.logger.debug(
                    "Update item %s, category ID -> %s with new category data -> %s",
                    "-> '{}' ({})".format(item_name, node_id) if item_name else "with ID -> {}".format(node_id),
                    str(category),
                    str(category_data[category]),
                )
                response = self.set_category_values(
                    node_id=node_id,
                    category_id=category,
                    category_data=self.flatten_categories_dict(category_data[category]),
                )

        if classifications:
            self.assign_classifications(node_id=node_id, classifications=classifications)

        return response

    # end method definition

    def get_node_create_form(
        self,
        parent_id: int,
        subtype: int = ITEM_TYPE_DOCUMENT,
        category_ids: int | list[int] | None = None,
    ) -> dict | None:
        """Get the node create form.

        Args:
            parent_id (int):
                The node the category should be applied to.
            subtype (int):
                The subtype of the new node. Default is document.
            category_ids (int | list[int]):
                The ID of the category or a list of category IDs.

        Returns:
            dict | None:
                Workspace Create Form data or None if the request fails.

        """

        request_header = self.request_form_header()

        if isinstance(category_ids, int):
            category_ids = [category_ids]

        self.logger.debug(
            "Get create form for parent ID  -> %s and category IDs -> %s",
            str(parent_id),
            str(category_ids),
        )

        request_url = self.config()["nodesFormUrl"] + "/create?parent_id={}&type={}".format(parent_id, subtype)

        for cat_id in category_ids:
            request_url += "&category_id={}".format(cat_id)

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Cannot get create form for parent ID -> {} and category IDs -> {}".format(
                parent_id,
                category_ids,
            ),
        )

        return response

    # end method definition

    def set_system_attributes(
        self,
        node_id: int,
        system_attributes: dict,
    ) -> dict | None:
        """Change custom system attributes of a node.

        These are NOT the normal node attributres like name or create date! In a standard
        OTCS deployment these are NOT used.

        Args:
            node_id (int):
                The ID of the node to set system attributes for.
            system_attributes (dict):
                A dictionary with key / value pairs to be set.

        Returns:
            dict | None:
                Node information or None in case of an error.

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/systemattributes"
        request_header = self.request_form_header()

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=system_attributes,
            failure_message="Failed to update system attributes of item -> '{}' with values -> %s".format(
                node_id,
            ),
        )

    # end method definition

    def get_document_templates(self, parent_id: int) -> dict | None:
        """Get all document templates for a given target location.

        Args:
            parent_id (int):
                TRhe node ID of target location (e.g. a folder)

        Returns:
            dict | None:
                Response of the REST call (converted to a Python dictionary) or None
                if the call fails.

        Example:
            ```json
            {
                'results': [
                    {
                        'container': False,
                        'hasTemplates': False,
                        'name': 'Document',
                        'subtype': 144,
                        'templates': [
                            {
                                'description_multilingual': {...},
                                'id': 16817,
                                'isDPWizardAvailable': False,
                                'mime_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                'name': 'Innovate Procurement Contract Template 2022.docx',
                                'name_multilingual': {...},
                                'size': 144365,
                                'sizeformatted': '141 KB',
                                'type': 144
                            },
                            {
                                ...
                            }
                        ]
                    }
                ]
            }
            ```

        """

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(parent_id)
            + "/doctemplates?subtypes={}&sidepanel_subtypes={}".format(
                self.ITEM_TYPE_DOCUMENT,
                self.ITEM_TYPE_DOCUMENT,
            )
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Get document templates for target location -> %s (parent ID); calling -> %s",
            str(parent_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get document templates for parent folder with ID -> {}".format(
                parent_id,
            ),
        )

    # end method definition

    def create_document_from_template(
        self,
        template_id: int,
        parent_id: int,
        classification_id: int,
        category_data: dict | None,
        doc_name: str,
        doc_description: str = "",
    ) -> dict | None:
        """Create a document based on a document template.

        Args:
            template_id (int):
                The node ID of the document template.
            parent_id (int):
                The node ID of the target location (parent).
            classification_id (int):
                The node ID of the classification.
            category_data (dict):
                The metadata / category data.
                Example: category ID = 12508
                {
                    "12508": {
                        "12508_2": "Draft",         # Text drop-down
                        "12508_3": 8559,            # user ID
                        "12508_4": "2023-05-10",    # date
                        "12508_6": 7357,            # user ID
                        "12508_7": "2023-05-11",    # date
                        "12508_5": True,            # checkbox / bool
                        "12508_8": "EN",            # text drop-down
                        "12508_9": "MS Word",       # text drop-down
                    }
                }
            doc_name (str):
                The name of the item to create.
            doc_description (str, optional):
                The description of the item to create.

        Returns:
            dict | None:
                Response of the REST call (converted to a Python dictionary) or
                None if the calls fails.

        """

        create_document_post_data = {
            "template_id": template_id,
            "parent_id": parent_id,
            "name": doc_name,
            "description": doc_description,
            "type": self.ITEM_TYPE_DOCUMENT,
            "roles": {
                "categories": category_data,
                "classifications": {"create_id": [classification_id], "id": []},
            },
        }

        request_url = self.config()["doctemplatesUrl"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Create document -> '%s' from template with ID -> %s in target location with ID -> %s with classification ID -> %s; calling -> %s",
            doc_name,
            str(template_id),
            str(parent_id),
            str(classification_id),
            request_url,
        )

        # This REST API needs a special treatment:
        # we have to encapsulate the payload as JSON into a "body" tag.
        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            # this seems to only work with a "body" tag and is different
            # form the documentation on developer.opentext.com
            data={"body": json.dumps(create_document_post_data)},
            timeout=None,
            failure_message="Failed to create document -> '{}'".format(doc_name),
        )

    # end method definition

    def create_wiki(
        self,
        parent_id: int,
        name: str,
        description: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Create a Content Server wiki.

        Args:
            parent_id (int):
                The node ID of the parent.
            name (str):
                The name of the wiki item
            description (str, optional):
                The description of the wiki item
            show_error (bool, optional):
                Log an error if item cration fails. Otherwise log a warning.

        Returns:
            dict | None:
                Request response of the create item call or
                None if the REST call has failed.

        """

        create_wiki_post_data = {
            "parent_id": parent_id,
            "type": self.ITEM_TYPE_WIKI,
            "name": name,
            "description": description,
        }

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Create wiki -> '%s' under parent with ID -> %s; calling -> %s",
            name,
            str(parent_id),
            request_url,
        )

        # This REST API needs a special treatment:
        # we encapsulate the payload as JSON into a "body" tag.
        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(create_wiki_post_data)},
            timeout=None,
            warning_message="Cannot create wiki -> '{}'".format(name),
            failure_message="Failed to create wiki -> '{}'".format(name),
            show_error=show_error,
        )

    # end method definition

    def create_wiki_page(
        self,
        wiki_id: int,
        name: str,
        content: str = "",
        description: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Create an Extended ECM wiki page.

        Args:
            wiki_id (int):
                The node ID of the wiki.
            name (str):
                The name of the wiki page.
            content (str, optional):
                The content of the page (typically HTML).
            description (str, optional):
                The description for the wiki page item.
            show_error (bool, optional):
                Log an error if item cration fails. Otherwise log a warning.

        Returns:
            dict | None:
                Request response of the create wiki page call or
                None if the REST call has failed.

        """

        create_wiki_page_post_data = {
            "parent_id": wiki_id,
            "type": self.ITEM_TYPE_WIKI_PAGE,
            "name": name,
            "description": description,
            "TextField": content,
        }

        request_url = self.config()["nodesUrl"]
        # Header needs to just include the cookie:
        request_header = self.cookie()

        self.logger.debug(
            "Create wiki page -> '%s' in wiki with ID -> %s; calling -> %s",
            name,
            str(wiki_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_wiki_page_post_data,
            timeout=None,
            warning_message="Cannot create wiki page -> '{}'".format(name),
            failure_message="Failed to create wiki page -> '{}'".format(name),
            show_error=show_error,
        )

    # end method definition

    def get_web_report_parameters(self, nickname: str) -> list | None:
        """Retrieve parameters of a Web Report in Extended ECM.

        These parameters are defined on the Web Report node (Properties -> Parameters).

        Args:
            nickname (str):
                The nickname of the Web Report node.

        Returns:
            list[dict] | None:
                A list of dictionaries, where each dictionary describes a parameter.
                The structure of each dictionary is as follows:
                    {
                        "type": str,
                        "parm_name": str,
                        "display_text": str,
                        "prompt": bool,
                        "prompt_order": int,
                        "default_value": Any,
                        "description": str,
                        "mandatory": bool
                    }
                Returns None if the REST call fails.

        """

        request_url = self.config()["webReportsUrl"] + "/" + nickname + "/parameters"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get parameters of Web Report with nickname -> '%s'; calling -> %s",
            nickname,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get parameters of Web Report with nickname -> '{}'".format(
                nickname,
            ),
        )

        if response and "data" in response:
            return response["data"]

        return None

    # end method definition

    def run_web_report(
        self,
        nickname: str,
        web_report_parameters: dict | None = None,
    ) -> dict | None:
        """Run a Web Report that is identified by its nick name.

        Args:
            nickname (str): nickname of the Web Reports node.
            web_report_parameters (dict, optional): Parameters of the Web Report (names + value pairs)

        Returns:
            dict | None: Response of the run Web Report request or None if the Web Report execution has failed.

        """

        # Avoid linter warning W0102:
        if web_report_parameters is None:
            web_report_parameters = {}

        request_url = self.config()["webReportsUrl"] + "/" + nickname
        request_header = self.request_form_header()

        self.logger.debug(
            "Running Web Report with nickname -> %s; calling -> %s",
            nickname,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=web_report_parameters,
            timeout=None,
            failure_message="Failed to run web report with nickname -> '{}'".format(
                nickname,
            ),
        )

    # end method definition

    def install_cs_application(self, application_name: str) -> dict | None:
        """Install a CS Application (based on WebReports).

        Args:
            application_name (str):
                The name of the application (e.g. OTPOReports, OTRMReports, OTRMSecReports).

        Returns:
            dict | None:
                Response or None if the installation of the CS Application has failed.

        """

        install_cs_application_post_data = {"appName": application_name}

        request_url = self.config()["csApplicationsUrl"] + "/install"
        request_header = self.request_form_header()

        self.logger.debug(
            "Install CS Application -> '%s'; calling -> %s",
            application_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=install_cs_application_post_data,
            timeout=None,
            failure_message="Failed to install CS Application -> '{}'".format(
                application_name,
            ),
        )

    # end method definition

    def assign_item_to_user_group(
        self,
        node_id: int,
        subject: str,
        instruction: str,
        assignees: list,
    ) -> dict | None:
        """Assign an Content Server item to users and groups.

        This is a function used by Extended ECM for Government.

        Args:
            node_id (int):
                The node ID of the Extended ECM item (e.g. a workspace or a document)
            subject (str):
                The title / subject of the assignment.
            instruction (str):
                A more detailed description or instructions for the assignment.
            assignees (list):
                The list of IDs of users or groups.

        Returns:
            dict | None:
                Response of the request or None if the assignment has failed.

        """

        assignment_post_data = {
            "subject": subject,
            "instruction": instruction,
            "assignees": assignees,
        }

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/xgovassignments"

        request_header = self.request_form_header()

        self.logger.debug(
            "Assign item with ID -> %s to assignees -> %s (subject -> '%s'); calling -> %s",
            str(node_id),
            str(assignees),
            subject,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"add_assignment": json.dumps(assignment_post_data)},
            timeout=None,
            failure_message="Failed to assign item with ID -> {} to assignees -> {} (subject -> '{}')".format(
                node_id,
                assignees,
                subject,
            ),
        )

    # end method definition

    def convert_permission_string_to_permission_value(self, permissions: list) -> int:
        """Convert a list of permission names (strongs) to a bit-mask.

        Args:
            permissions (list):
                List of permission names - see conversion variable below.

        Returns:
            int:
                The bit-encoded permission value.

        """

        conversion = {
            "see": 130,  # Bits 2 and 8
            "see_contents": 36865,  # Bit 17
            "modify": 65536,  # Bit 18
            "edit_attributes": 131072,  # Bit 19
            "add_items": 4,  # Bit 3
            "reserve": 8192,  # Bit 14
            "add_major_version": 4194304,  # Bit 23
            "delete_versions": 16384,  # Bit 15
            "delete": 8,  # Bit 4
            "edit_permissions": 16,  # Bit 5
        }

        permission_value = 0

        for permission in permissions:
            if not conversion.get(permission):
                self.logger.error("Illegal permission value -> %s", str(permission))
                return 0
            permission_value += conversion[permission]

        return permission_value

    # end method definition

    def convert_permission_value_to_permission_string(
        self,
        permission_value: int,
    ) -> list:
        """Convert a bit-encoded permission value to a list of permission names (strings).

        Args:
            permission_value (int):
                A bit-encoded permission value.

        Returns:
            list:
                A list of permission names.

        """

        conversion = {
            "see": 130,  # Bits 2 and 8
            "see_contents": 36865,  # Bit 17
            "modify": 65536,  # Bit 18
            "edit_attributes": 131072,  # Bit 19
            "add_items": 4,  # Bit 3
            "reserve": 8192,  # Bit 14
            "add_major_version": 4194304,  # Bit 23
            "delete_versions": 16384,  # Bit 15
            "delete": 8,  # Bit 4
            "edit_permissions": 16,  # Bit 5
        }

        permissions = []

        for key, value in conversion.items():
            if permission_value & value:  # binary and
                permissions.append(key)

        return permissions

    # end method definition

    def assign_permission(
        self,
        node_id: int,
        assignee_type: str,
        assignee: int,
        permissions: list,
        apply_to: int = 0,
    ) -> dict | None:
        """Assign permissions to a user or group for an Extended ECM item.

        This method allows you to assign specified permissions to a user or group for a given
        Content Server item (node). The permissions can be applied to the item itself, its sub-items,
        or both.

        Args:
            node_id (int): The ID of the Extended ECM item (node) to which permissions are being assigned.
            assignee_type (str): The type of assignee. This can be one of the following:
                - "owner": Permissions are assigned to the owner.
                - "group": Permissions are assigned to the owner group.
                - "public": Permissions are assigned to the public (all users).
                - "custom": Permissions are assigned to a specific user or group (specified by `assignee`).
            assignee (int):
                The ID of the user or group (referred to as "right ID").
                If `assignee` is 0 and `assignee_type` is "owner" or "group",
                the owner or group will not be changed.
            permissions (list of str): A list of permissions to assign to the assignee. Valid permissions include:
                - "see"               : View the item
                - "see_contents"      : View the contents of the item
                - "modify"            : Modify the item
                - "edit_attributes"   : Edit the attributes of the item
                - "add_items"         : Add items to the item
                - "reserve"           : Reserve the item
                - "add_major_version" : Add major versions to the item
                - "delete_versions"   : Delete versions of the item
                - "delete"            : Delete the item
                - "edit_permissions"  : Modify permissions for the item
            apply_to (int, optional): The scope of the permission assignment. Possible values:
                - 0 = Apply to this item only (default)
                - 1 = Apply to sub-items only
                - 2 = Apply to this item and its sub-items
                - 3 = Apply to this item and its immediate sub-items

        Returns:
            dict | None:
                The response of the permission assignment request, or None if the operation fails.

        Notes:
            - If `assignee_type` is "custom", `assignee` must refer to a valid user or group ID.
            - The method modifies the permissions of the specified assignee for the specified ECM item.

        """

        if not assignee_type or assignee_type not in [
            "owner",
            "group",
            "public",
            "custom",
        ]:
            self.logger.error(
                "Missing or wrong assignee type. Needs to be owner, group, public or custom!",
            )
            return None
        if assignee_type == "custom" and not assignee:
            self.logger.error("Missing permission assignee!")
            return None

        permission_post_data = {
            "permissions": permissions,
            "apply_to": apply_to,
        }

        # Assignees can be specified for owner and group and must be specified for custom:
        #
        if assignee:
            permission_post_data["right_id"] = assignee

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/permissions/" + assignee_type

        request_header = self.request_form_header()

        self.logger.debug(
            "Assign permissions -> %s to item with ID -> %s; assignee type -> '%s'; calling -> %s",
            str(permissions),
            str(node_id),
            assignee_type,
            request_url,
        )

        if assignee_type == "custom":
            # Custom also has a REST POST - we prefer this one as to
            # also allows to add a new assigned permission (user or group):
            return self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data={"body": json.dumps(permission_post_data)},
                timeout=None,
                failure_message="Failed to assign custom permissions -> {} to item with ID -> {}".format(
                    permissions,
                    node_id,
                ),
            )
        else:
            # Owner, Owner Group and Public require REST PUT:
            return self.do_request(
                url=request_url,
                method="PUT",
                headers=request_header,
                data={"body": json.dumps(permission_post_data)},
                timeout=None,
                failure_message="Failed to assign stadard permissions -> {} to item with ID -> {}".format(
                    permissions,
                    node_id,
                ),
            )

    # end method definition

    def get_node_categories(self, node_id: int, metadata: bool = True) -> dict | None:
        """Get categories assigned to a node.

        Args:
            node_id (int):
                The ID of the node to get the categories for.
            metadata (bool, optional):
                If True, expand the attribute definitions of the category. Default is True.

        Returns:
            dict | None:
                Category response or None if the call to the REST API fails.

        Example:
            [
                {
                    'data': {
                        'categories': {
                            '16878_25': 'Customer',
                            '16878_28': '50031',
                            '16878_29': 'Global Trade AG',
                            '16878_30': 'Gutleutstraße 53',
                            '16878_31': 'Germany',
                            '16878_32': '60329',
                            '16878_33': ['1000'],
                            '16878_34': 'Frankfurt',
                            '16878_37': ['Retail'],
                            '16878_38': '0000050031',
                            '16878_39_1_40': '0000001096',
                            '16878_39_1_41': 'Heinz Hart',
                            '16878_39_1_42': 'Purchasing',
                            '16878_39_1_43': 'Purchasing Manager',
                            '16878_39_1_44': '+49695325410',
                            '16878_39_1_45': '+49695325499',
                            '16878_39_1_46': 'Heinz.Hart@GlobalTrade.com',
                            '16878_39_1_47': 'B',
                            '16878_39_1_48': '4',
                            ...
                        }
                    },
                    'metadata': {
                        '16878': {
                            'allow_undefined': False,
                            'bulk_shared': False,
                            'default_value': None,
                            'description': None,
                            'hidden': False,
                            'key': '16878',
                            'key_value_pairs': False,
                            'multi_value': False,
                            'multi_value_length_default': 1,
                            'multi_value_length_fixed': True,
                            'multi_value_length_max': 1,
                            'multi_value_max_length': None,
                            'multi_value_min_length': None,
                            'multi_value_unique': False,
                            'name': 'Customer',
                            'next_id': 83,
                            'persona': 'category',
                            'read_only': True,
                            'required': False,
                            ...
                        },
                        '16878_25': {
                            'allow_undefined': False,
                            'bulk_shared': False,
                            'default_value': None,
                            'description': None,
                            'hidden': False,
                            'key': '16878_25',
                            'key_value_pairs': False,
                            'max_length': None,
                            'min_length': None,
                            'multi_select': False,
                            'multi_value': False,
                            'multi_value_length_default': 1,
                            'multi_value_length_fixed': True,
                            'multi_value_length_max': 1,
                            'multi_value_max_length': None,
                            'multi_value_min_length': None,
                            'multi_value_unique': False,
                            'multiline': False,
                            'multilingual': False,
                            ...
                        },
                        '16878_28': {
                            'allow_undefined': False,
                            'bulk_shared': False,
                            'default_value': None,
                            'description': None,
                            'hidden': False,
                            'key': '16878_28',
                            'key_value_pairs': False,
                            'max_length': 10,
                            'min_length': None,
                            'multi_select': False,
                            'multi_value': False,
                            'multi_value_length_default': 1,
                            'multi_value_length_fixed': True,
                            'multi_value_length_max': 1,
                            'multi_value_max_length': None,
                            'multi_value_min_length': None,
                            'multi_value_unique': False,
                            'multiline': False,
                            'multilingual': False,
                            ...
                        },
                        ...
                    }
                    'metadata_map': {
                        'categories': {'16878': ['16878_2', '16878_3', '16878_4', '16878_5', '16878_6', '16878_7', '16878_8']}
                    }
                    'metadata_order': {
                        'categories': ['16878']
                    }
                }
            ]

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories"
        if metadata:
            request_url += "?metadata"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get categories of node with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get categories for node ID -> {}".format(
                str(node_id),
            ),
        )

    # end method definition

    def get_node_category(
        self,
        node_id: int,
        category_id: int,
        metadata: bool = True,
    ) -> dict | None:
        """Get a specific category assigned to a node.

        Args:
            node_id (int):
                The ID of the node to get the categories for.
            category_id (int):
                The node ID of the category definition (in category volume).
            metadata (bool, optional):
                Expanded information with the attribute definitions of the category. Default is True.

        Returns:
            dict | None:
                REST esponse with category data or None if the call to the REST API fails.

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories/" + str(category_id)
        if metadata:
            request_url += "?metadata"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get category with ID -> %s on node with ID -> %s; calling -> %s",
            str(category_id),
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get category with ID -> {} for node ID -> {}".format(
                category_id,
                node_id,
            ),
        )

    # end method definition

    def get_node_category_ids(
        self,
        node_id: int,
        node_categories: dict | None = None,
    ) -> list:
        """Get list of all category definition IDs that are assigned to the node.

        Args:
            node_id (int):
                The ID of the node to get the categories for.
            node_categories (dict | None, optional):
                If the calling method has already used get_node_categories()
                to get the category data structure of the node we can pass the response
                of get_node_categories() with this parameter to optimize performance and
                avoid recalculation. It is optional, and if it is not provided, category
                data is determined with get_node_categories() inside this method.

        Returns:
            list:
                The list of category IDs (all categories assigned to the node).

        """

        # Check if the categories have NOT been provided by the calling method.
        # In this case we determine it here:
        if node_categories is None:
            node_categories = self.get_node_categories(node_id=node_id)

        if not node_categories or not node_categories.get("results", None):
            return []

        category_id_list = []

        for category in node_categories["results"]:
            category_id_list += [int(i) for i in category["metadata_order"]["categories"]]

        return category_id_list

    # end method definition

    def get_node_category_names(
        self,
        node_id: int,
        node_categories: dict | None = None,
    ) -> list | None:
        """Get list of all category names that are assigned to the node.

        Args:
            node_id (int):
                The ID of the node to get the categories for.
            node_categories (dict | None, optional):
                If the calling method has already used get_node_categories()
                to get the category data structure of the node we can pass the response
                of get_node_categories() with this parameter to optimize performance and
                avoid recalculation. It is optional, and if it is not provided, category
                data is determined with get_node_categories() inside this method.

        Returns:
            list | None:
                List of category names (all categories assigned to the node).

        """

        # Check if the node categories have NOT been provided by the calling method.
        # In this case we determine it here:
        if node_categories is None:
            node_categories = self.get_node_categories(node_id=node_id, metadata=True)

        if not node_categories or not node_categories.get("results", None):
            return None

        # List comprehension to extract category names safely
        return [
            next(iter(category["metadata"]["categories"].values()), {}).get("name")
            for category in node_categories["results"]
        ]

    # end method definition

    def get_node_category_definition(
        self,
        node_id: int,
        category_name: str,
        node_categories: dict | None = None,
    ) -> tuple[int, dict]:
        """Get category definition (category id and attribute names, IDs and types).

        This is a convenience method that wraps the the complex return value
        of get_node_categories() in an easier to parse structure.

        Args:
            node_id (int):
                The node to read the category definition from
                (e.g. a workspace template or a document template or a target folder).
                This should NOT be the category definition object!
            category_name (str):
                The name of the category to get the definition for.
            node_categories (dict | None, optional):
                If the calling method has already used get_node_categories()
                to get the category data structure of the node we can pass the response
                of get_node_categories() with this parameter to optimize performance and
                avoid recalculation. It is optional, and if it is not provided, category
                data is determined with get_node_categories() inside this method.

        Returns:
            int:
                The category ID
            dict:
                The dict keys are the attribute names.
                The dict values are sub-dictionaries with the id and type of the attribute.
                For set attributes the key is constructed as <set name>:<attribute name>.
                Set attributes also incluide an additional value "set_id".

        Example:
            ```json
            {
                'Status': {'id': '16892_25', 'type': 'String'},
                'Customer Number': {'id': '16892_28', 'type': 'String'},
                'Name': {'id': '16892_29', 'type': 'String'},
                'Street': {'id': '16892_30', 'type': 'String'},
                'Country': {'id': '16892_31', 'type': 'String'},
                'Postal code': {'id': '16892_32', 'type': 'String'},
                'Sales organisation': {'id': '16892_33', 'type': 'String'},
                'City': {'id': '16892_34', 'type': 'String'},
                'Industry': {'id': '16892_37', 'type': 'String'},
                'Object Key': {'id': '16892_38', 'type': 'String'},
                'Contacts': {'id': '16892_39', 'type': 'set'},
                'Contacts:BP No': {'id': '16892_39_x_40', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Name': {'id': '16892_39_x_41', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Department': {'id': '16892_39_x_42', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Function': {'id': '16892_39_x_43', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Phone': {'id': '16892_39_x_44', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Fax': {'id': '16892_39_x_45', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Email': {'id': '16892_39_x_46', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Building': {'id': '16892_39_x_47', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Floor': {'id': '16892_39_x_48', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Room': {'id': '16892_39_x_49', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Comments': {'id': '16892_39_x_50', 'type': 'String', 'set_id': '16892_39'},
                'Contacts:Valid from': {'id': '16892_39_x_51', 'type': 'Date', 'set_id': '16892_39'},
                'Contacts:Valid to': {'id': '16892_39_x_52', 'type': 'Date', 'set_id': '16892_39'},
                'Sales Areas': {'id': '16892_53', 'type': 'set'},
                'Sales Areas:Sales Organisation': {'id': '16892_53_x_54', 'type': 'String', 'set_id': '16892_53'},
                'Sales Areas:Distribution Channel': {'id': '16892_53_x_55', 'type': 'String', 'set_id': '16892_53'},
                'Sales Areas:Division': {'id': '16892_53_x_56', 'type': 'String', 'set_id': '16892_53'},
                'Rating': {'id': '16892_57', 'type': 'set'},
                'Rating:Credit Standing': {'id': '16892_57_x_58', 'type': 'String', 'set_id': '16892_57'},
                'Rating:Date': {'id': '16892_57_x_59', 'type': 'Date', 'set_id': '16892_57'},
                'Rating:Status': {'id': '16892_57_x_60', 'type': 'String', 'set_id': '16892_57'},
                'Rating:add. Information': {'id': '16892_57_x_61', 'type': 'String', 'set_id': '16892_57'},
                'Rating:Institute': {'id': '16892_57_x_62', 'type': 'String', 'set_id': '16892_57'},
                'Rating:Rating': {'id': '16892_57_x_63', 'type': 'String', 'set_id': '16892_57'},
                'Locations': {'id': '16892_75', 'type': 'set'},
                'Locations:Type': {'id': '16892_75_x_76', 'type': 'String', 'set_id': '16892_75'},
                'Locations:Street': {'id': '16892_75_x_77', 'type': 'String', 'set_id': '16892_75'},
                'Locations:City': {'id': '16892_75_x_78', 'type': 'String', 'set_id': '16892_75'},
                'Locations:Country': {'id': '16892_75_x_79', 'type': 'String', 'set_id': '16892_75'},
                'Locations:Postal code': {'id': '16892_75_x_80', 'type': 'String', 'set_id': '16892_75'},
                'Locations:Valid from': {'id': '16892_75_x_81', 'type': 'Date', 'set_id': '16892_75'},
                'Locations:Valid to': {'id': '16892_75_x_82', 'type': 'Date', 'set_id': '16892_75'}
            }
            ```

        """

        attribute_definitions = {}

        # Check if the categories have NOT been provided by the calling method.
        # In this case we determine it here:
        if node_categories is None:
            node_categories = self.get_node_categories(node_id=node_id, metadata=True)

        if not node_categories or not node_categories.get("results", None):
            return -1, {}

        for category in node_categories["results"]:
            # get all metadata IDs
            keys = category["metadata"]["categories"].keys()
            # There's one without an underscore - that's the ID of the category itself:
            cat_id = next((key for key in keys if "_" not in key), -1)
            cat_name = category["metadata"]["categories"][cat_id]["name"]
            # Check we have the category we are looking for:
            if cat_name != category_name:
                # Wrong category - not matching - skip this category and go to the next.
                continue
            # Initial state: we are not inside a set:
            set_name = None
            set_id = None
            for att_id in category["metadata"]["categories"]:
                if "_" not in att_id:
                    # We skip the element representing the category itself:
                    continue
                att_name = category["metadata"]["categories"][att_id]["name"]
                att_persona = category["metadata"]["categories"][att_id]["persona"]
                # Attribute types can be "String", "Date", ...
                # For the set attribute the type_name is "Assoc"
                att_type = category["metadata"]["categories"][att_id]["type_name"]
                # Persona can be either "set" or "categoryattribute".
                # If the persona is "set" we store the set information:
                if att_persona == "set":
                    # We save the set name and ID for the attributes that follow:
                    set_name = att_name
                    set_id = att_id
                if "_x_" in att_id:  # this is not true for the set attribute itself
                    # set_name and set_id are still set to the name of the proceeding
                    # for-loop iteration!
                    if not set_name:
                        self.logger.warning(
                            "Unexpected case - set name is None but we have a set attribute -> '%s' (%s). Skipping...",
                            att_name,
                            att_id,
                        )
                        continue
                    attribute_definitions[set_name + ":" + att_name] = {
                        "id": att_id,
                        "type": att_type,
                        "set_id": set_id,
                    }
                else:
                    attribute_definitions[att_name] = {
                        "id": att_id,
                        "type": att_type,
                    }
                    # As also the set attribute itself does not have an "_x_"
                    # we need to avoid resetting the set information right
                    # after it was set above:
                    if att_persona != "set" and set_name:
                        set_name = None
                        set_id = None

            return cat_id, attribute_definitions

        return -1, {}

    # end method definition

    def assign_category(
        self,
        node_id: int,
        category_id: list,
        inheritance: bool | None = False,
        apply_to_sub_items: bool = False,
        apply_action: str = "add_upgrade",
        add_version: bool = False,
        clear_existing_categories: bool = False,
    ) -> bool:
        """Assign a category to a Content Server node.

        Optionally turn on inheritance and apply category to sub-items
        (if node_id is a container / folder / workspace).
        If the category is already assigned to the node this method will
        throw an error.

        Args:
            node_id (int): node ID to apply the category to
            category_id (list): ID of the category definition object
            inheritance (bool | None):
                If True, turn on inheritance for the category
                (this makes only sense if the node is a container like a folder or workspace).
                For documents or other non-container-item you should pass None to avoid errors.
            apply_to_sub_items (bool, optional):
                If True, the category is applied to the item and all its sub-items.
                If False, the category is only applied to the item itself.
            apply_action (str, optional):
                A category action to apply. Supported values are "add", "add_upgrade", "upgrade",
                "replace", "delete", "none". The default is "add_upgrade".
            add_version (bool, optional):
                True, if a document version should be added for the category change (default = False).
            clear_existing_categories (bool, optional):
                Defines, whether or not existing (other) categories should be removed (default = False).

        Returns:
            bool:
                True = success, False = error

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories"
        request_header = self.request_form_header()

        #
        # 1. Assign Category to Node if not yet assigned:
        #

        existing_category_ids = self.get_node_category_ids(node_id=node_id)
        if not existing_category_ids or category_id not in existing_category_ids:
            self.logger.debug(
                "Category with ID -> %s is not yet assigned to node ID -> %s. Assigning it now...",
                str(category_id),
                str(node_id),
            )
            category_post_data = {
                "category_id": category_id,
            }

            self.logger.debug(
                "Assign category with ID -> %s to item with ID -> %s; calling -> %s",
                str(category_id),
                str(node_id),
                request_url,
            )

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data=category_post_data,
                timeout=None,
                failure_message="Failed to assign category with ID -> {} to node with ID -> {}".format(
                    category_id,
                    node_id,
                ),
                parse_request_response=False,
            )

            if not response or not response.ok:
                return False

        #
        # 2. Set Inheritance
        #

        # We only set the inheritance if it is given as True or False.
        # If we got None we don't mess with inheritance at all to
        # avoid issues with non-container items:
        if inheritance is not None:
            response = self.set_category_inheritance(
                node_id=node_id,
                category_id=category_id,
                enable=inheritance,
            )
            if not response:
                return False

        #
        # 3. Apply to sub-items
        #

        if apply_to_sub_items:
            request_url_apply_sub_items = request_url + "/apply"

            category_post_data = {
                "categories": [{"id": category_id, "action": apply_action}],
                "add_version": add_version,
                "clear_existing_categories": clear_existing_categories,
            }

            # we need to wrap the body of this POST call into a "body"
            # tag. This is documented worngly on developer.opentext.com
            response = self.do_request(
                url=request_url_apply_sub_items,
                method="POST",
                headers=request_header,
                data={"body": json.dumps(category_post_data)},
                timeout=None,
                failure_message="Failed to apply category with ID -> {} to sub-items of node with ID -> {}".format(
                    category_id,
                    node_id,
                ),
                parse_request_response=False,
            )

            if not response or not response.ok:
                return False

        return True

    # end method definition

    def get_category_value_by_name(
        self,
        node_id: int,
        category_name: str,
        attribute_name: str,
        set_name: str | None = None,
        set_row: int = 1,
        cat_definitions: dict | None = None,
        node_categories: dict | None = None,
    ) -> str | list | None:
        """Lookup the value of an attribute if names of category, set, and attribute are known.

        Args:
            node_id (int):
                The ID of the node the category is assigned to.
            category_name (str):
                The name of the category.
            attribute_name (str):
                The name of the attribute.
            set_name (str | None, optional):
                The name of the set. Defaults to None.
            set_row (int, optional):
                Index of the row (first row = 1!). Defaults to 1.
            cat_definitions (dict | None, optional):
                This is for performance optimization to avoid repeatedly calculation the
                definition dictionary of the same node. Optional. Default is None
                (in default case we calculate the category definition inside the method).
            node_categories (dict | None, optional):
                If the calling method has already used get_node_categories()
                to get the category data structure of the node we can pass the response
                of get_node_categories() with this parameter to optimize performance and
                avoid recalculation. It is optional, and if it is not provided, category
                data is determined with get_node_categories() inside this method.

        Returns:
            str | list | None:
                The value of the attribute. If it is a multi-value attribute a list will be returned.

        """

        if cat_definitions is None:
            (_, cat_definitions) = self.get_node_category_definition(
                node_id=node_id,
                category_name=category_name,
            )

        if not cat_definitions:
            self.logger.warning(
                "No categories are assigned to node with ID -> %s",
                str(node_id),
            )
            return None

        lookup = set_name + ":" + attribute_name if set_name else attribute_name

        if lookup not in cat_definitions:
            self.logger.error("Cannot find attribute -> '%s' in category -> '%s'")

        # Get the definition of the attribute:
        att_def = cat_definitions[lookup]

        att_id = att_def["id"]
        if "_x_" in att_id:
            att_id = att_id.replace("_x_", "_" + str(set_row) + "_")

        # Check if the categories have NOT been provided by the calling method.
        # In this case we determine it here:
        if node_categories is None:
            node_categories = self.get_node_categories(node_id=node_id, metadata=False)

        if not node_categories or not node_categories.get("results", None):
            return []

        value = None

        for category in node_categories["results"]:
            if att_id in category["data"]["categories"]:
                value = category["data"]["categories"][att_id]
                break

        return value

    # end method definition

    def get_category_value(
        self,
        node_id: int,
        category_id: int,
        attribute_id: int,
        set_id: int | None = None,
        set_row: int = 1,
    ) -> str | list | None:
        """Lookup the value of an attribute if IDs of category, set, and attribute are known.

        If you only have the names use get_category_value_by_name() instead!

        Args:
            node_id (int):
                The Node ID the category is assigned to.
            category_id (int):
                The node ID of the category definition item.
            attribute_id (int):
                The ID of the attribute (the pure ID without underscores).
            set_id (int, optional):
                The ID of the set. Defaults to None.
            set_row (int, optional):
                Index of the row (first row = 1!). Defaults to 1.

        Returns:
            str | list | None:
                The value of the attribute. If it is a multi-value attribute a list will be returned.

        """

        if set_id and set_row:
            att_id = str(category_id) + "_" + str(set_id) + "_" + str(set_row) + "_" + str(attribute_id)
        elif set_id:
            att_id = str(category_id) + "_" + str(set_id) + "_" + str(attribute_id)
        else:
            att_id = str(category_id) + "_" + str(attribute_id)

        response = self.get_node_categories(node_id=node_id, metadata=False)
        categories = response["results"]

        value = None

        for category in categories:
            if att_id in category["data"]["categories"]:
                value = category["data"]["categories"][att_id]
                break

        return value

    # end method definition

    def set_category_value(
        self,
        node_id: int,
        value: str | int | list,
        category_id: int,
        attribute_id: int,
        set_id: int = 0,
        set_row: int = 1,
    ) -> dict | None:
        """Set a value to a specific attribute in a category.

        Categories and have sets (groupings), multi-line sets (matrix),
        and multi-value attributes (list of values). This method supports all variants.

        Args:
            node_id (int):
                The ID of the node.
            value (multi-typed):
                The value to be set - can be string or list of strings
                (for multi-value attributes)
            category_id (int):
                The ID of the category definition item.
            attribute_id (int):
                The ID of the attribute. This should not include the category ID
                nor an underscore but the plain attribute ID like '10'.
            set_id (int, optional):
                The ID of the set. Defaults to 0.
            set_row (int, optional):
                The row inside the set. Defaults to 1.

        Returns:
            dict | None:
                REST API response or None if the call fails

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories/" + str(category_id)
        request_header = self.request_form_header()

        if set_id:
            self.logger.debug(
                "Assign value -> '%s' to category with ID -> %s, set ID -> %s, row -> %s, attribute ID -> %s on node with ID -> %s; calling -> %s",
                str(value),
                str(category_id),
                str(set_id),
                str(set_row),
                str(attribute_id),
                str(node_id),
                request_url,
            )
            category_put_data = {
                "category_id": category_id,
                "{}_{}_{}_{}".format(category_id, set_id, set_row, attribute_id): value,
            }
            failure_message = "Failed to set value -> '{}' for category with ID -> {}, set ID -> {}, set row -> {}, attribute ID -> {} on node ID -> {}".format(
                value,
                category_id,
                set_id,
                set_row,
                attribute_id,
                node_id,
            )
        else:
            self.logger.debug(
                "Assign value -> '%s' to category ID -> %s, attribute ID -> %s on node with ID -> %s; calling -> %s",
                str(value),
                str(category_id),
                str(attribute_id),
                str(node_id),
                request_url,
            )
            category_put_data = {
                "category_id": category_id,
                "{}_{}".format(category_id, attribute_id): value,
            }
            failure_message = (
                "Failed to set value -> '{}' for category with ID -> {}, attribute ID -> {} on node ID -> {}".format(
                    value,
                    category_id,
                    attribute_id,
                    node_id,
                )
            )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=category_put_data,
            timeout=None,
            failure_message=failure_message,
        )

    # end method definition

    def set_category_values(
        self,
        node_id: int,
        category_id: int,
        category_data: dict,
        inheritance: bool | None = False,
    ) -> dict | None:
        """Set values of a category.

        Categories can have sets (groupings), multi-line sets (matrix), and
        multi-value attributes (list of values). This method supports all variants.

        Args:
            node_id (int):
                The ID of the node.
            category_id (int):
                The node ID of the category definition item.
            category_data (dict):
                Dictionary with category attributes and values that should be set.
            inheritance (bool | None):
                If True, turn on inheritance for the category
                (this makes only sense if the node is a container like a folder or workspace).
                For documents or other non-container-item you should pass None to avoid errors.

        Returns:
            dict | None:
                REST API response or None if the call fails

        """

        def set_category_values_sub(show_error: bool = False) -> None | dict:
            return self.do_request(
                url=request_url,
                method="PUT",
                headers=request_header,
                data=category_data,
                timeout=None,
                failure_message="Failed to set values -> {} for category with ID -> {}, on node ID -> {}".format(
                    category_data,
                    category_id,
                    node_id,
                ),
                warning_message="Couldn't set values -> {} for category with ID -> {}, on node ID -> {}".format(
                    category_data,
                    category_id,
                    node_id,
                ),
                show_error=show_error,
                show_warning=not show_error,
            )

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories/" + str(category_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Set values -> %s for category ID -> %s on node -> %s...",
            category_data,
            category_id,
            node_id,
        )

        response = set_category_values_sub(show_error=False)

        if not response:
            self.logger.debug("Failed to set category values, trying to assign category to node first.")

            if self.assign_category(node_id=node_id, category_id=category_id, inheritance=inheritance):
                response = set_category_values_sub(show_error=True)

        return response

    # end method definition

    def set_category_inheritance(
        self,
        node_id: int,
        category_id: int,
        enable: bool = True,
    ) -> dict | None:
        """Set category inheritance of a container item (e.g. a folder or workspace) to sub-items.

        Args:
            node_id (int):
                The node ID of the container item.
            category_id (int):
                The node ID of the category definition item.
            enable (bool):
                Whether the inheritance should be enabled (True) or disabled (False).

        Returns:
            dict | None:
                Response of the request or None in case of an error.

        """

        request_url = (
            self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories/" + str(category_id) + "/inheritance"
        )
        request_header = self.request_form_header()

        if enable:
            self.logger.debug(
                "Enable category inheritance for node with ID -> %s and category ID -> %s; calling -> %s",
                str(node_id),
                str(category_id),
                request_url,
            )
            return self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                timeout=None,
                failure_message="Failed to enable categories inheritance for node ID -> {} and category ID -> {}".format(
                    node_id,
                    category_id,
                ),
            )
        else:
            self.logger.debug(
                "Disable category inheritance of node with ID -> %s and category ID -> %s; calling -> %s",
                str(node_id),
                str(category_id),
                request_url,
            )
            return self.do_request(
                url=request_url,
                method="DELETE",
                headers=request_header,
                timeout=None,
                failure_message="Failed to disable categories inheritance for node ID -> {} and category ID -> {}".format(
                    node_id,
                    category_id,
                ),
            )

    # end method definition

    def collection_operation(
        self,
        collection_id: int,
        node_ids: list | int,
        operation: str = "add",
    ) -> dict | None:
        """Apply a collection operation (add or remove) to a list of node(s).

        Args:
            collection_id (int):
                The node ID of the colection.
            node_ids (list | int):
                The ID of the node to add or remove from the collection.
            operation (str, optional):
                Operation to apply.
                Use "add" to add a node to the collection
                and use "remove" to remove an existing node from a collection.
                Defaults to "add".

        Returns:
            dict | None:
                Response of the request or None in case of an error.

        """

        if operation not in ["add", "remove"]:
            self.logger.error("Illegal collection operation -> '%s'!")
            return None

        request_url = self.config()["nodesUrlv2"] + "/" + str(collection_id) + "/collection"
        request_header = self.request_form_header()

        # Make it a list if it is not yet:
        if isinstance(node_ids, int):
            node_ids = [node_ids]

        collection_put_data = {"ids": node_ids, "operation": operation}

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=collection_put_data,
            timeout=None,
            failure_message="Failed to {} nodes with IDs -> {} to collection with ID -> {}".format(
                operation,
                node_ids,
                collection_id,
            ),
        )

    # end method definition

    def add_node_to_collection(
        self,
        collection_id: int,
        node_ids: int | list,
    ) -> dict | None:
        """Add node(s) to a collection.

        Args:
            collection_id (int):
                The node ID of the colection.
            node_ids (int | list):
                The ID(s) of the node(s) to add to the collection.

        Returns:
            dict | None:
                Response of the request or None in case of an error.

        """

        return self.collection_operation(
            collection_id=collection_id,
            node_ids=node_ids,
            operation="add",
        )

    # end method definition

    def remove_node_from_collection(
        self,
        collection_id: int,
        node_ids: int | list,
    ) -> dict | None:
        """Remove node(s) from a collection.

        Args:
            collection_id (int):
                The node ID of the colection.
            node_ids (int):
                The ID(s) of the node(s) to remove from the collection.

        Returns:
            dict | None:
                Response of the request or None in case of an error.

        """

        return self.collection_operation(
            collection_id=collection_id,
            node_ids=node_ids,
            operation="remove",
        )

    # end method definition

    def get_node_classifications(self, node_id: int) -> dict | None:
        """Assign one or multiple classifications to a Content Server item.

        Args:
            node_id (int):
                The node ID of the Content Server item to assign classifications to.

        Returns:
            dict | None:
                Repose of the request or None in case of an error:

        Example:
            ```json
            {
                'bCanApplyClass': True,
                'bCanRemoveClass': True,
                'canModify': True,
                'classVolumeID': 2048,
                'data': [
                    {
                        'id': 219555,
                        'name': 'Aviator Search',
                        'type': 199,
                        'selectable': True,
                        'management_type': 'manual',
                        'score': None,
                        'inherit_flag': True,
                        'classvolumeid': None,
                        'parent_managed': None,
                        'cell_metadata': {
                            'data': {...},
                            'definitions': {...}
                        },
                        'menu': None
                    },
                    ...
                ],
                'definitions': {
                    'classvolumeid': {
                        'allow_undefined': False,
                        'bulk_shared': False,
                        'default_value': None,
                        'description': None,
                        'hidden': False,
                        'key': 'classvolumeid',
                        'key_value_pairs': False,
                        'max_value': None,
                        'min_value': None,
                        'multi_value': False,
                        'multi_value_max_length': None,
                        'multi_value_min_length': None,
                        'multi_value_unique': False,
                        'name': 'Classification Volume ID',
                        'persona': '',
                        'read_only': False,
                        'required': False,
                        'type': 2,
                        'type_name': 'Integer',
                        'valid_values': [],
                        'valid_values_name': []
                    },
                    'id': {
                        'allow_undefined': False,
                        'bulk_shared': False,
                        'default_value': None,
                        'description': None,
                        'hidden': False,
                        'key': 'id',
                        'key_value_pairs': False,
                        'max_value': None,
                        'min_value': None,
                        'multi_value': True,
                        'multi_value_max_length': None,
                        'multi_value_min_length': None,
                        'multi_value_unique': False,
                        'name': 'Classification',
                        'persona': 'node',
                        'read_only': False,
                        'required': False,
                        'type': 2,
                        'type_name': 'Integer',
                        'valid_values': [],
                        'valid_values_name': []
                    },
                    'inherit_flag': {...},
                    'management_type': {...},
                    'name': {...},
                    'parent_managed': {...},
                    'score': {...},
                    'selectable': {...},
                    'type': {...}
                },
                'definitions_map': {
                    'name': ['menu']
                },
                'definitions_order': ['name']
            }
            ```

        """

        request_url = self.config()["nodesUrl"] + "/" + str(node_id) + "/classifications"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get classifications of node with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get classifications of node ID -> {}".format(
                node_id,
            ),
        )

    # end method definition

    def assign_classifications(
        self,
        node_id: int,
        classifications: list,
        apply_to_sub_items: bool = False,
        remove_existing: bool = False,
    ) -> dict | None:
        """Assign one or multiple classifications to a Content Server item.

        The method supports the removal of existing classification
        and the addition of new classifications. This can be controlled
        by the parametes given.

        Args:
            node_id (int):
                The node ID of the Content Server item to assign classifications to.
            classifications (list):
                List of classification item IDs.
            apply_to_sub_items (bool, optional):
                If True, the classification is applied to the item and all
                its sub-items.
                If False, the classification is only applied to the item itself.
            remove_existing (bool):
                If True, existing classifications will be remove and the node
                only gets the classification provided in the `classification` parameter.
                If False, the provided classifications will be added in addition to the
                existing ones.

        Returns:
            dict | None:
                Response of the request or None if the assignment of the classification has failed.

        """

        # If we want to preserve the existing classifications we need to retrieve them first
        # and the create a "super-set" of the existing and new classifications:
        if not remove_existing:
            existing_classifications = self.get_node_classifications(node_id=node_id)
            if existing_classifications and existing_classifications["data"]:
                existing_classification_ids = [
                    classification["id"] for classification in existing_classifications["data"]
                ]
            else:
                existing_classification_ids = []

        if existing_classification_ids:
            # Make sure we don't have redundant IDs by temporarily convert lists to sets,
            # then merge the sets and then convert back to list:
            classifications = list(set(classifications) | set(existing_classification_ids))

        classification_post_data = {
            "class_id": classifications,  # classification_list,
            "apply_to_sub_items": apply_to_sub_items,
            "inherit_flag": False,
        }

        request_url = self.config()["nodesUrl"] + "/" + str(node_id) + "/classifications"

        request_header = self.request_form_header()

        self.logger.debug(
            "Assign classifications with IDs -> %s to item with ID -> %s; calling -> %s",
            str(classifications),
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(classification_post_data)},
            timeout=None,
            failure_message="Failed to assign classifications with IDs -> {} to item with ID -> {}".format(
                classifications,
                node_id,
            ),
        )

    # end method definition

    def assign_rm_classification(
        self,
        node_id: int,
        rm_classification: int,
        apply_to_sub_items: bool = False,
    ) -> dict | None:
        """Assign a RM classification to a Content Server item.

        Args:
            node_id (int):
                The node ID of the Content Server item.
            rm_classification (int):
                The Records Management classification ID.
            apply_to_sub_items (bool, optional):
                If True, the RM classification is applied to
                the item and all its sub-items.
                If False the RM classification is only applied to the item itself.

        Returns:
            dict | None:
                Response of the request or None if the assignment of the RM classification has failed.

        """

        rm_classification_post_data = {
            "class_id": rm_classification,
            "apply_to_sub_items": apply_to_sub_items,
        }

        request_url = self.config()["nodesUrl"] + "/" + str(node_id) + "/rmclassifications"

        request_header = self.request_form_header()

        self.logger.debug(
            "Assign RM classifications with ID -> %s to item with ID -> %s; calling -> %s",
            str(rm_classification),
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(rm_classification_post_data)},
            timeout=None,
            failure_message="Failed to assign RM classifications with ID -> {} to item with ID -> {}".format(
                rm_classification,
                node_id,
            ),
        )

    # end method definition

    def register_workspace_template(self, node_id: int) -> dict | None:
        """Register a workspace template as project template for Extended ECM for Engineering.

        Args:
            node_id (int):
                The node ID of the Extended ECM workspace template.

        Returns:
            dict | None:
                Response of request or None if the registration of the workspace template has failed.

        """

        registration_post_data = {"ids": "{{ {} }}".format(node_id)}

        request_url = self.config()["xEngProjectTemplateUrl"]

        request_header = self.request_form_header()

        self.logger.debug(
            "Register workspace template with ID -> %s for Extended ECM for Engineering; calling -> %s",
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=registration_post_data,
            timeout=None,
            failure_message="Failed to register Workspace Template with ID -> {} for Extended ECM for Engineering".format(
                node_id,
            ),
        )

    # end method definition

    def get_records_management_rsis(self, limit: int = 100) -> list | None:
        """Get all Records management RSIs togther with their RSI Schedules.

        Args:
            limit (int, optional):
                The maximum number of elements to return (default = 100).

        Returns:
            list | None:
                The list of Records Management RSIs or None if the request fails.

        Example:
            [
                {
                    "RSIID": 0,
                    "RSI": "string",
                    "Title": "string",
                    "Subject": "string",
                    "Description": "string",
                    "CreateDate": "string",
                    "RSIStatus": "string",
                    "StatusDate": "string",
                    "DiscontFlag": 0,
                    "DiscontDate": "string",
                    "DiscontComment": "string",
                    "Active": 0,
                    "DispControl": 0,
                    "RSIScheduleID": 0,
                    "RetStage": "string",
                    "RecordType": 0,
                    "EventType": 0,
                    "RSIRuleCode": "string",
                    "DateToUse": "string",
                    "YearEndMonth": 0,
                    "YearEndDay": 0,
                    "RetYears": 0,
                    "RetMonths": 0,
                    "RetDays": 0,
                    "RetIntervals": 0,
                    "EventRuleDate": "string",
                    "EventRule": "string",
                    "EventComment": "string",
                    "StageAction": "string",
                    "FixedRet": 0,
                    "ActionCode": "string",
                    "ActionDescription": "string",
                    "Disposition": "string",
                    "ApprovalFlag": 0,
                    "MaximumRet": 0,
                    "ObjectType": "LIV"
                }, ...
            ]

        """

        request_url = self.config()["rsisUrl"] + "?limit=" + str(limit)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get list of Records Management RSIs; calling -> %s",
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get list of Records Management RSIs",
        )

        if response and "results" in response and response["results"]:
            return response["results"]["data"]["rsis"]

        return None

    # end method definition

    def get_records_management_codes(self) -> dict | None:
        """Get Records Management Codes.

        These are the most basic data types of the Records Management configuration
        and required to create RSIs and other higher-level Records Management configurations.

        Args:
            None

        Returns:
            dict | None:
                The RM codes or None if the request fails.

        """

        request_url = self.config()["recordsManagementUrlv2"] + "/rmcodes"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get list of Records Management codes; calling -> %s",
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get list of Records Management codes",
        )

        if response and "results" in response and response["results"]:
            return response["results"]["data"]

        return None

    # end method definition

    # This is not yet working. REST API endpoint seems not to be in 22.4. Retest with 23.1
    def update_records_management_codes(self, rm_codes: dict) -> dict | None:
        """Update Records Management Codes.

        These are the most basic data types of the Records Management configuration
        and required to create RSIs and other higher-level Records Management configurations.

        THIS METHOD IS CURRENTLY NOT WORKING!

        Args:
            rm_codes (dict):
                The Codes to be updated.

        Returns:
            dict | None:
                RSI data or None if the request fails.

        """

        update_rm_codes_post_data = {}

        request_url = self.config()["recordsManagementUrl"] + "/rmcodes"
        request_header = self.request_form_header()

        self.logger.debug(
            "Update Records Management codes -> %s; calling -> %s",
            str(rm_codes),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=update_rm_codes_post_data,
            timeout=None,
            failure_message="Failed to update Records Management codes with -> {}".format(
                rm_codes,
            ),
        )

        if response and "results" in response and response["results"]:
            return response["results"]["data"]

        return None

    # end method definition

    def create_records_management_rsi(
        self,
        name: str,
        status: str,
        status_date: str,
        description: str,
        subject: str,
        title: str,
        dispcontrol: bool,
    ) -> dict | None:
        """Create a new Records Management RSI.

        Args:
            name (str):
                The name of the RSI.
            status (str):
                The status of the RSI.
            status_date (str):
                The status date of the RSI in YYYY-MM-DDTHH:mm:ss format.
            description (str):
                The description of the RSI.
            subject (str):
                The subject of the RSI.
            title (str):
                The title of the RSI.
            dispcontrol (bool):
                The disposition control of the RSI.

        Returns:
            dict | None:
                RSI data or None if the request fails.

        """

        if status_date == "":
            now = datetime.now(timezone.utc)
            status_date = now.strftime("%Y-%m-%dT%H:%M:%S")

        create_rsi_post_data = {
            "name": name,
            "status": status,
            "statusDate": status_date,
            "description": description,
            "subject": subject,
            "title": title,
            "dispcontrol": dispcontrol,
        }

        request_url = self.config()["rsiSchedulesUrl"]

        request_header = self.request_form_header()

        self.logger.debug(
            "Create Records Management RSI -> %s; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_rsi_post_data,
            timeout=None,
            failure_message="Failed to create Records Management RSI -> '{}'".format(
                name,
            ),
        )

    # end method definition

    def create_records_management_rsi_schedule(
        self,
        rsi_id: int,
        stage: str,
        event_type: int = 1,
        object_type: str = "LIV",
        rule_code: str = "",
        rule_comment: str = "",
        date_to_use: int = 91,
        retention_years: int = 0,
        retention_months: int = 0,
        retention_days: int = 0,
        category_id: int = 0,
        attribute_id: int = 0,
        year_end_month: int = 12,
        year_end_day: int = 31,
        retention_intervals: int = 1,
        fixed_retention: bool = True,
        maximum_retention: bool = True,
        fixed_date: str = "",
        event_condition: str = "",
        disposition: str = "",
        action_code: int = 0,
        description: str = "",
        new_status: str = "",
        min_num_versions_to_keep: int = 1,
        purge_superseded: bool = False,
        purge_majors: bool = False,
        mark_official_rendition: bool = False,
    ) -> dict | None:
        """Create a new Records Management RSI Schedule for an existing RSI.

        Args:
            rsi_id (int):
                The ID of an existing RSI the schedule should be created for.
            stage (str):
                The retention stage - this is the key parameter to define multiple stages
                (stages are basically schedules).
            event_type (int):
                The type of the event. Possible values:
                1 Calculated Date,
                2 Calendar Calculation,
                3 Event Based,
                4 Fixed Date,
                5 Permanent
            object_type (str):
                The object type of the event. Either "LIV" - Classified Objects (default) or "LRM" - RM Classifications
            rule_code (str, optional):
                The rule code - this value must be defined upfront.
            rule_comment (str, optional):
                The comment for the rule.
            date_to_use (int, optional):
                Defines which date to use. Possible values:
                91 Create Date,
                92 Reserved Data,
                93 Modification Date,
                94 Status Date,
                95 Records Date
            retention_years (int, optional):
                Years to wait before disposition.
            retention_months (int, optional):
                Months to wait before disposition.
            retention_days (int, optional):
                Days to wait before disposition.
            category_id (int, optional):
                The ID of the category.
            attribute_id (int, optional):
                The ID of the category attribute.
            year_end_month (int, optional):
                The month the year ends (default = 12).
            year_end_day (int, optional):
                The day the year ends (default = 31).
            retention_intervals (int, optional):
                The retention intervals.
            fixed_retention (bool, optional):
                True, if a fixed retention should be used. False otherwise.
            maximum_retention (bool,optional): maximumRetention
            fixed_date(str, optional):
                The format for fixed dates. Default is YYYY-MM-DDTHH:mm:ss
            event_condition (str, optional): eventCondition
            disposition (str, optional): disposition
            action_code (int, optional):
                0 None,
                1 Change Status,
                7 Close,
                8 Finalize Record,
                9 Mark Official,
                10 Export,
                11 Update Storage Provider,
                12 Delete Electronic Format,
                15 Purge Versions,
                16 Make Rendition,
                32 Destroy
            description (str, optional):
                The description of the RSI schedule.
            new_status (str, optional):
                The new status.
            min_num_versions_to_keep (int, optional):
                The minimum document versions to keep. Default is 1.
            purge_superseded (bool, optional):
                True, if superseded items should be purged. Default is False.
            purge_majors (bool, optional):
                True, if major document versions should be purged. Default is False.
            mark_official_rendition (bool, optional):
                True, if a rendition should be created with mark official. Default is False.

        Returns:
            dict | None: RSI Schedule data or None if the request fails.

        """

        create_rsi_schedule_post_data = {
            "objectType": object_type,
            "stage": stage,
            "eventType": event_type,
            "ruleCode": rule_code,
            "ruleComment": rule_comment,
            "dateToUse": date_to_use,
            "retentionYears": retention_years,
            "retentionMonths": retention_months,
            "retentionDays": retention_days,
            "categoryId": category_id,
            "attributeId": attribute_id,
            "yearEndMonth": year_end_month,
            "yearEndDay": year_end_day,
            "retentionIntervals": retention_intervals,
            "fixedRetention": fixed_retention,
            "maximumRetention": maximum_retention,
            "fixedDate": fixed_date,
            "eventCondition": event_condition,
            "disposition": disposition,
            "actionCode": action_code,
            "description": description,
            "newStatus": new_status,
            "minNumVersionsToKeep": min_num_versions_to_keep,
            "purgeSuperseded": purge_superseded,
            "purgeMajors": purge_majors,
            "markOfficialRendition": mark_official_rendition,
        }

        request_url = self.config()["rsiSchedulesUrl"] + "/" + str(rsi_id) + "/stages"

        request_header = self.request_form_header()

        self.logger.debug(
            "Create Records Management RSI Schedule -> %s for RSI -> %s; calling -> %s",
            stage,
            str(rsi_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_rsi_schedule_post_data,
            timeout=None,
            failure_message="Failed to create Records Management RSI Schedule -> '{}' for RSI -> {}".format(
                stage,
                rsi_id,
            ),
        )

    # end method definition

    def create_records_management_hold(
        self,
        hold_type: str,
        name: str,
        comment: str,
        alternate_id: str = "",
        parent_id: int = 0,
        date_applied: str = "",
        date_to_remove: str = "",
    ) -> dict | None:
        """Create a new Records Management Hold.

        Args:
            hold_type (str):
                The type of the hold.
            name (str):
                The name of the RSI.
            comment (str):
                A comment.
            alternate_id (str, optional):
                An alternate hold ID.
            parent_id (int, optional):
                ID of the parent node.
                If parent_id is 0 the item will be created right under "Hold Management" (top level item)
            date_applied (str, optional):
                The create date of the Hold in this format: YYYY-MM-DDTHH:mm:ss
            date_to_remove (str, optional):
                The suspend date of the Hold in this format: YYYY-MM-DDTHH:mm:ss

        Returns:
            dict | None:
                Hold data or None if the request fails. The dict structure is this: {'holdID': <ID>}

        """

        if date_applied == "":
            now = datetime.now(timezone.utc)
            date_applied = now.strftime("%Y-%m-%dT%H:%M:%S")

        create_hold_post_data = {
            "type": hold_type,
            "name": name,
            "comment": comment,
            "date_applied": date_applied,
            "date_to_remove": date_to_remove,
            "alternate_id": alternate_id,
        }

        if parent_id > 0:
            create_hold_post_data["parent_id"] = parent_id

        request_url = self.config()["holdsUrl"]

        request_header = self.request_form_header()

        self.logger.debug(
            "Create Records Management Hold -> %s; calling -> %s",
            name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_hold_post_data,
            timeout=None,
            failure_message="Failed to create Records Management Hold -> '{}'".format(
                name,
            ),
        )

    # end method definition

    def get_records_management_holds(self) -> dict | None:
        """Get a list of all Records Management holds in the system.

        Even though there are folders in the holds management area in RM these
        are not real folders - they cannot be retrieved with get_node_by_parent_and_name()
        thus we need this method to get them all.

        Args:
            None

        Returns:
            dict | None:
                Response with list of holds. None in case of an error.

        Example:
            ```json
            {
                "results": {
                    "data": {
                        "holds": [
                            {
                                "HoldID": 0,
                                "HoldName": "string",
                                "ActiveHold": 0,
                                "OBJECT": 0,
                                "ApplyPatron": "string",
                                "DateApplied": "string",
                                "HoldComment": "string",
                                "HoldType": "string",
                                "DateToRemove": "string",
                                "DateRemoved": "string",
                                "RemovalPatron": "string",
                                "RemovalComment": "string",
                                "EditDate": "string",
                                "EditPatron": "string",
                                "AlternateHoldID": 0,
                                "ParentID": 0
                            }
                        ]
                    }
                }
            }
            ```

        """

        request_url = self.config()["holdsUrlv2"]

        request_header = self.request_form_header()

        self.logger.debug(
            "Get list of Records Management Holds; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get list of Records Management Holds",
        )

    # end method definition

    def import_records_management_settings(self, file_path: str) -> bool:
        """Import Records Management settings from a local file.

        Args:
            file_path (str):
                The path + filename of config file in local filesystem.

        Returns:
            bool: True, if the REST call succeeds or False otherwise.

        """

        request_url = self.config()["recordsManagementUrl"] + "/importSettings"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Importing Records Management settings from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            self.logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False

        with open(file=file_path, encoding="utf-8") as settings_file:
            settings_post_file = {
                "file": (filename, settings_file, "text/xml"),
            }

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                files=settings_post_file,
                timeout=None,
                failure_message="Failed to import Records Management settings from file -> '{}'".format(
                    file_path,
                ),
                parse_request_response=False,
            )

        return bool(response and response.ok)

    # end method definition

    def import_records_management_codes(
        self,
        file_path: str,
        update_existing_codes: bool = True,
    ) -> bool:
        """Import RM Codes from a file that is uploaded from the local filesystem.

        Args:
            file_path (str):
                The path + filename of settings file in the filesystem.
            update_existing_codes (bool, optional):
                Flag that controls whether existing table maintenance codes
                should be updated.

        Returns:
            bool:
                True, if if the REST call succeeds, or False otherwise.

        """

        request_url = self.config()["recordsManagementUrl"] + "/importCodes"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Importing Records Management codes from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        codes_post_data = {"updateExistingCodes": update_existing_codes}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            self.logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False

        with open(file=file_path, encoding="utf-8") as codes_file:
            codes_post_file = {
                "file": (filename, codes_file, "text/xml"),
            }

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data=codes_post_data,
                files=codes_post_file,
                timeout=None,
                failure_message="Failed to import Records Management codes from file -> '{}'".format(
                    file_path,
                ),
                parse_request_response=False,
            )

        return bool(response and response.ok)

    # end method definition

    def import_records_management_rsis(
        self,
        file_path: str,
        update_existing_rsis: bool = True,
        delete_schedules: bool = False,
    ) -> bool:
        """Import RM RSIs from a config file that is uploaded from the local filesystem.

        Args:
            file_path (str):
                The path + filename of config file in the filesystem.
            update_existing_rsis (bool, optional):
                whether or not existing RSIs should be updated (or ignored).
            delete_schedules (bool, optional):
                Whether existing RSI Schedules should be deleted.

        Returns:
            bool:
                True, if if the REST call succeeds, or False otherwise.

        """

        request_url = self.config()["recordsManagementUrl"] + "/importRSIs"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Importing Records Management RSIs from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        rsis_post_data = {
            "updateExistingRSIs": update_existing_rsis,
            "deleteSchedules": delete_schedules,
        }

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            self.logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False

        with open(file=file_path, encoding="utf-8") as rsis_file:
            rsis_post_file = {
                "file": (filename, rsis_file, "text/xml"),
            }

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data=rsis_post_data,
                files=rsis_post_file,
                timeout=None,
                failure_message="Failed to import Records Management RSIs from file -> '{}'".format(
                    file_path,
                ),
                parse_request_response=False,
            )

        return bool(response and response.ok)

    # end method definition

    def import_physical_objects_settings(self, file_path: str) -> bool:
        """Import Physical Objects settings from a config file from the local filesystem.

        Args:
            file_path (str):
                The path + filename of config file in local filesystem.

        Returns:
            bool:
                True if if the REST call succeeds, or False otherwise.

        """

        request_url = self.config()["physicalObjectsUrl"] + "/importSettings"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Importing Physical Objects Settings from server file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            self.logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False

        with open(file=file_path, encoding="utf-8") as settings_file:
            settings_post_file = {
                "file": (filename, settings_file, "text/xml"),
            }

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                files=settings_post_file,
                timeout=None,
                failure_message="Failed to import Physical Objects settings from file -> '{}'".format(
                    file_path,
                ),
                parse_request_response=False,
            )

        return bool(response and response.ok)

    # end method definition

    def import_physical_objects_codes(
        self,
        file_path: str,
        update_existing_codes: bool = True,
    ) -> bool:
        """Import Physical Objects codes from a config file in the local filesystem.

        Args:
            file_path (str):
                The path + filename of config file in the local filesystem.
            update_existing_codes (bool):
                Whether or not existing codes should be updated (default = True).

        Returns:
            bool:
                True, if if the REST call succeeds, or False otherwise.

        """

        request_url = self.config()["physicalObjectsUrl"] + "/importCodes"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data:
        request_header = self.cookie()

        self.logger.debug(
            "Importing Physical Objects codes from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        codes_post_data = {"updateExistingCodes": update_existing_codes}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            self.logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False

        with open(file=file_path, encoding="utf-8") as codes_file:
            codes_post_file = {
                "file": (filename, codes_file, "text/xml"),
            }

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data=codes_post_data,
                files=codes_post_file,
                timeout=None,
                failure_message="Failed to import Physical Objects codes from file -> '{}'".format(
                    file_path,
                ),
                parse_request_response=False,
            )

        return bool(response and response.ok)

    # end method definition

    def import_physical_objects_locators(self, file_path: str) -> bool:
        """Import Physical Objects locators from a config file in the local filesystem.

        Args:
            file_path (str):
                The path + filename of config file in the local filesystem.

        Returns:
            bool:
                True, if if the REST call succeeds, or False otherwise.

        """

        request_url = self.config()["physicalObjectsUrl"] + "/importLocators"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Importing Physical Objects Locators from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            self.logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False

        with open(file=file_path, encoding="utf-8") as locators_file:
            locators_post_file = {
                "file": (filename, locators_file, "text/xml"),
            }

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                files=locators_post_file,
                timeout=None,
                failure_message="Failed to import Physical Objects locators from file -> '{}'".format(
                    file_path,
                ),
                parse_request_response=False,
            )

        return bool(response and response.ok)

    # end method definition

    def import_security_clearance_codes(
        self,
        file_path: str,
        include_users: bool = False,
    ) -> bool:
        """Import Security Clearance codes from a config file in the local filesystem.

        Args:
            file_path (str):
                The path + filename of config file in local filesystem.
            include_users (bool):
                Defines if users should be included or not.

        Returns:
            bool:
                True, if if the REST call succeeds, or False otherwise.

        """

        request_url = self.config()["securityClearancesUrl"] + "/importCodes"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Importing Security Clearance Codes from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        codes_post_data = {"includeusers": include_users}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            self.logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False

        with open(file=file_path, encoding="utf-8") as codes_file:
            codes_post_file = {
                "file": (filename, codes_file, "text/xml"),
            }

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data=codes_post_data,
                files=codes_post_file,
                timeout=None,
                failure_message="Failed to import Security Clearance codes from file -> '{}'".format(
                    file_path,
                ),
                parse_request_response=False,
            )

        return bool(response and response.ok)

    # end method definition

    def assign_user_security_clearance(
        self,
        user_id: int,
        security_clearance: int,
    ) -> dict | None:
        """Assign a Security Clearance level to a Content Server user.

        Args:
            user_id (int):
                The ID of the user.
            security_clearance (int):
                The security clearance level to be set for the user.

        Returns:
            dict | None:
                REST response or None if the REST call fails.

        """

        assign_user_security_clearance_post_data = {
            "securityLevel": security_clearance,
        }

        request_url = self.config()["userSecurityUrl"] + "/{}/securityclearancelevel".format(user_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Assign security clearance -> %s to user with ID -> %s; calling -> %s",
            str(security_clearance),
            str(user_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=assign_user_security_clearance_post_data,
            timeout=None,
            failure_message="Failed to assign security clearance -> {} to user with ID -> {}".format(
                security_clearance,
                user_id,
            ),
        )

    # end method definition

    def assign_user_supplemental_markings(
        self,
        user_id: int,
        supplemental_markings: list,
    ) -> dict | None:
        """Assign a list of Supplemental Markings to a Content Server user.

        Args:
            user_id (int):
                The ID of the user.
            supplemental_markings (list of strings):
                A list of Supplemental Markings to be set for the user.

        Returns:
            dict | None:
                REST response or None if the REST call fails.

        """

        assign_user_supplemental_markings_post_data = {
            "suppMarks": supplemental_markings,
        }

        request_url = self.config()["userSecurityUrl"] + "/{}/supplementalmarkings".format(user_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Assign supplemental markings -> %s to user with ID -> %s; calling -> %s",
            str(supplemental_markings),
            str(user_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=assign_user_supplemental_markings_post_data,
            timeout=None,
            failure_message="Failed to assign supplemental markings -> {} to user with ID -> {}".format(
                supplemental_markings,
                user_id,
            ),
        )

    # end method definition

    def get_workflow_definition(self, workflow_id: int) -> dict | None:
        """Get the workflow definition.

        Args:
            workflow_id (int): The node ID of the workflow definition item (map).

        Returns:
            dict | None: The workflow definition data. None in case of an error.

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'results': {
                    'definition': {
                        'data_packages': [
                            {
                                'data': {},
                                'description': None,
                                'sub_type': 2,
                                'type': 1
                            },
                            {
                                'data': {
                                    'data': {
                                        'data': {
                                            '25397_10': None,
                                            '25397_11': False,
                                            '25397_8': None,
                                            '25397_9': None
                                        },
                                        'definitions': {
                                            '25397': {...},
                                            '25397_10': {
                                                'allow_undefined': False,
                                                'bulk_shared': False,
                                                'default_value': None,
                                                'description': None,
                                                'hidden': False,
                                                'include_time': False,
                                                'key': '25397_10',
                                                'key_value_pairs': False,
                                                'multi_value': False,
                                                'multi_value_length_default': 1,
                                                'multi_value_length_fixed': True,
                                                'multi_value_length_max': 1,
                                                'multi_value_max_length': None,
                                                'multi_value_min_length': None,
                                                'multi_value_unique': False,
                                                'name': 'Approval Date',
                                                'persona': '',
                                                'read_only': False,
                                                'required': False,
                                                'type': -7,
                                                'type_llattribute': -7,
                                                'type_name': 'Date',
                                                'valid_values': [],
                                                'valid_values_name': []
                                            },
                                            '25397_11': {...},
                                            '25397_8': {...},
                                            '25397_9': {...}
                                        },
                                        'definitions_map': {
                                            '25397': [...]
                                        },
                                        'definitions_order': ['25397']
                                    },
                                    'definitions': {...},
                                    'definitions_map': {...},
                                    'definitions_order': [...]
                                },
                                'description': 'Please fill in all required attributes.',
                                'sub_type': 3,
                                'type': 1
                            },
                            {...},
                            {...}
                        ],
                        'tasks': [
                            {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}
                        ],
                        'workflow_id': 25397,
                        'workflow_roles': []
                    }
                }
            }
            ```

        """

        request_url = self.config()["workflowUrl"] + "/" + str(workflow_id) + "/definition"
        request_header = self.request_form_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get definition of workflow with ID -> {}".format(
                workflow_id,
            ),
        )

    # end method definition

    def get_workflow_attributes(
        self,
        workflow_id: int,
        form_prefix: str = "WorkflowForm",
    ) -> dict | None:
        """Get workflow attribute definition.

        It returns a dictionary to allow looking up attribute IDs based on the attribute names.

        Args:
            workflow_id (int):
                The node ID of the workflow.
            form_prefix (str, optional):
                The prefix string used for form attributes.
                Defaults to "WorkflowForm".

        Returns:
            dict | None:
                The dictionary keys are the attribute names. The dictionary values are the attribute IDs.
                None in case an error occurs.

        Example:
            ```json
            {
                'Approval Date': {
                    'id': '25397_10',
                    'type': 'Date'
                    'form_id': 'WorkflowForm_10'
                },
                'Official': {
                    'id': '25397_11',
                    'type': 'Boolean'
                    'form_id': 'WorkflowForm_11'
                },
                'Approver': {
                    'id': '25397_8',
                    'type': 'Integer'
                    'form_id': 'WorkflowForm_8'
                },
                'Status': {
                    'id': '25397_9',
                    'type': 'String'
                    'form_id': 'WorkflowForm_9'
                }
            }
            ```

        """

        response = self.get_workflow_definition(workflow_id=workflow_id)

        if not response or "results" not in response:
            return None

        results = response["results"]
        if "definition" not in results:
            self.logger.error(
                "Workflow definition is missing 'results' data structure!",
            )
            return None

        # we just need the definition part of the workflow definition:
        definition = results["definition"]

        # in particular we want to lookup a specific data package
        # that includes the attribute definitions:
        if "data_packages" not in definition:
            self.logger.error("Workflow definition does not have data packages!")
            return None

        # Initialize the result dictionary:
        result = {}

        for data_package in definition["data_packages"]:
            data = data_package.get("data", None)
            if data and "definitions" in data:
                # We found the right data package with the attribute definitions!
                attribute_definitions = data["definitions"]
                for key, value in attribute_definitions.items():
                    attribute_type = value.get("type_name", None)
                    # the assoc represents the whole data structure
                    # and is not a single attribute - we skip it:
                    if attribute_type == "Assoc":
                        continue
                    # We construct the dict in a way that allows
                    # to lookup attribute IDs based on attribute names.
                    # we also add a key with the 'form_prefix' as the
                    # draft process needs it in that syntax.
                    form_id = form_prefix + "_" + key.split("_")[1]
                    result[value.get("name")] = {
                        "id": key,
                        "type": attribute_type,
                        "form_id": form_id,
                    }

        return result

    # end method definition

    def get_document_workflows(self, node_id: int, parent_id: int) -> list:
        """Get a list of available workflows for a document ID and a parent ID.

        Args:
            node_id (int): node ID of the document
            parent_id (int): node ID of the parent

        Returns:
            list: list of available workflows

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'results': {
                    'data': [
                        {
                            'DataID': 25397,
                            'Name': 'Contract Approval Workflow',
                            'WorkflowType': 100
                        },
                        {
                            'DataID': 25442,
                            'Name': 'Contract Approval Workflow (2 steps)',
                            'WorkflowType': 100
                        },
                        ...
                    ],
                    'fError': '',
                    'fErrorDetail': '',
                    'statusMsg': None}
                }
            }
            ```

        """

        request_url = self.config()["docWorkflowUrl"] + "?doc_id={}&parent_id={}".format(node_id, parent_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workflows for node ID -> %s and parent ID -> %s; calling -> %s",
            str(node_id),
            str(parent_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workflows for node ID -> {} and parent ID -> {}".format(
                node_id,
                parent_id,
            ),
        )

    # end method definition

    def get_workflows_by_kind_and_status(
        self,
        kind: str | None = None,
        status: str | list | None = None,
        sort: str | None = None,
    ) -> list | None:
        """Get a list of workflows with a defined kind and status.

        IMPORTANT: This method is personlalized, you
        need to call it with the user these workflows are related / assigned to.

        Args:
            kind (str | None, optional):
                Possible values: "Managed", "Initiated", "Both". Defaults to None.
            status (str | None, optional):
                The workflow status. Possible values are "ontime", "workflowlate", "stopped",
                "completed". Defaults to None (=all).
            sort (str | None, optional):
                Sorting order, like "name asc", "name desc", "data_initiated asc", "status_key desc".
                Defaults to None.

        Returns:
            list | None:
                The list of matching workflows or None if the request fails.

        Example:
            ```json
            {
                "links": {
                    "data": {
                        "self": {
                            "body": "",
                            "content_type": "",
                            "href": "/api/v2/workflows/status",
                            "method": "GET",
                            "name": ""
                        }
                    }
                },
                "results": [
                    {
                        "data": {
                            "wfstatus": {
                                "assignee": [
                                    {
                                        "userId": 15665,
                                        "loginName": "dfoxhoven",
                                        "firstName": "Deke",
                                        "lastName": "Foxhoven",
                                        "emailAddress": "dfoxhoven@dev.idea-te.eimdemo.com",
                                        "phone": ""
                                    }
                                ],
                                "assignee_count": 1,
                                "comments_on": true,
                                "current_assignee": "Deke Foxhoven",
                                "date_initiated": "2024-09-27T15:50:47",
                                "due_date": "",
                                "parallel_steps": [
                                    {
                                        "process_id": 160580,
                                        "subprocess_id": 160580,
                                        "task_id": 1,
                                        "task_name": "Approver",
                                        "task_due_date": "",
                                        "task_start_date": "2024-09-27T15:51:13",
                                        "task_status": "ontime",
                                        "task_assignees": {
                                            "assignee": [
                                                {
                                                    "userId": 15665,
                                                    "loginName": "dfoxhoven",
                                                    "firstName": "Deke",
                                                    "lastName": "Foxhoven",
                                                    "emailAddress": "dfoxhoven@dev.idea-te.eimdemo.com",
                                                    "phone": ""
                                                }
                                            ],
                                            "assigneeCount": 1,
                                            "currentAssignee": "Deke Foxhoven"
                                        }
                                    }
                                ],
                                "process_id": 160580,
                                "status_key": "ontime",
                                "step_name": "Approver",
                                "steps_count": 1,
                                "subprocess_id": 160580,
                                "task_id": 1,
                                "wf_name": "Contract Approval Workflow (1 step)"
                            }
                        },
                        "definitions": {
                            "wfstatus": {
                                "assignee": {
                                    "allow_undefined": false,
                                    "bulk_shared": false,
                                    "default_value": null,
                                    "description": null,
                                    "hidden": false,
                                    "key": "assignee",
                                    "max_value": null,
                                    "min_value": null,
                                    "multi_value": false,
                                    "name": "Assigned to",
                                    "persona": "",
                                    "read_only": true,
                                    "required": false,
                                    "type": 2,
                                    "type_name": "Integer",
                                    "valid_values": [],
                                    "valid_values_name": []
                                },
                                "date_initiated": {
                                    "allow_undefined": false,
                                    "bulk_shared": false,
                                    "default_value": null,
                                    "description": null,
                                    "hidden": false,
                                    "include_time": true,
                                    "key": "date_initiated",
                                    "multi_value": false,
                                    "name": "Start Date",
                                    "persona": "",
                                    "read_only": true,
                                    "required": false,
                                    "type": -7,
                                    "type_name": "Date",
                                    "valid_values": [],
                                    "valid_values_name": []
                                },
                                "due_date": {
                                    "allow_undefined": false,
                                    "bulk_shared": false,
                                    "default_value": null,
                                    "description": null,
                                    "hidden": false,
                                    "include_time": true,
                                    "key": "due_date",
                                    "multi_value": false,
                                    "name": "Step Due Date",
                                    "persona": "",
                                    "read_only": true,
                                    "required": false,
                                    "type": -7,
                                    "type_name": "Date",
                                    "valid_values": [],
                                    "valid_values_name": []
                                },
                                "status_key": {
                                    "allow_undefined": false,
                                    "bulk_shared": false,
                                    "default_value": null,
                                    "description": null,
                                    "hidden": false,
                                    "key": "status_key",
                                    "max_length": null,
                                    "min_length": null,
                                    "multi_value": false,
                                    "multiline": false,
                                    "multilingual": false,
                                    "name": "Status",
                                    "password": false,
                                    "persona": "",
                                    "read_only": true,
                                    "regex": "",
                                    "required": false,
                                    "type": -1,
                                    "type_name": "String",
                                    "valid_values": [],
                                    "valid_values_name": []
                                },
                                "step_name": {
                                    "allow_undefined": false,
                                    "bulk_shared": false,
                                    "default_value": null,
                                    "description": null,
                                    "hidden": false,
                                    "key": "step_name",
                                    "max_length": null,
                                    "min_length": null,
                                    "multi_value": false,
                                    "multiline": false,
                                    "multilingual": true,
                                    "name": "Current Step",
                                    "password": false,
                                    "persona": "",
                                    "read_only": true,
                                    "regex": "",
                                    "required": false,
                                    "type": -1,
                                    "type_name": "String",
                                    "valid_values": [],
                                    "valid_values_name": []
                                },
                                "wf_name": {
                                    "allow_undefined": false,
                                    "bulk_shared": false,
                                    "default_value": null,
                                    "description": null,
                                    "hidden": false,
                                    "key": "wf_name",
                                    "max_length": null,
                                    "min_length": null,
                                    "multi_value": false,
                                    "multiline": false,
                                    "multilingual": true,
                                    "name": "Workflow",
                                    "password": false,
                                    "persona": "",
                                    "read_only": true,
                                    "regex": "",
                                    "required": false,
                                    "type": -1,
                                    "type_name": "String",
                                    "valid_values": [],
                                    "valid_values_name": []
                                }
                            }
                        },
                        "definitions_map": {
                            "wfstatus": {}
                        },
                        "definitions_order": {
                            "wfstatus": [
                                "status_key",
                                "due_date",
                                "wf_name",
                                "step_name",
                                "assignee",
                                "date_initiated"
                            ]
                        },
                        "permissions": {
                            "Archive": true,
                            "ChangeAttr": true,
                            "ChangeRoute": true,
                            "Delete": true,
                            "ManagerPerms": true,
                            "SeeDetail": true,
                            "Stop": true,
                            "Suspend": true
                        }
                    }
                ]
            }
            ```

        """

        query = {}
        if kind:
            query["kind"] = kind
        if status:
            query["wstatus"] = status
        if sort:
            query["sort"] = sort
        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["workflowUrl"] + "/status?{}".format(encoded_query)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workflows of kind -> '%s' and status -> '%s'; calling -> %s",
            kind,
            str(status),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workflows of kind -> {} and status -> {}".format(
                kind,
                str(status),
            ),
        )

    # end method definition

    def get_workflow_status(self, process_id: int) -> dict | None:
        """Get the status (task list) of a workflow instance (process).

        Args:
            process_id (int):
                The ID of the process (worflow instance).

        Returns:
            dict | None:
                Task list of the workflow instance or None if the request fails.

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/workflows/status/processes/159324',
                            'method': 'GET',
                            'name': ''
                        }
                    }
                },
                'results': {
                    'attachments': {'attachment_folder_id': 159311},
                    'data_packages': [
                        {
                            'TYPE': 1,
                            'SUBTYPE': 1,
                            'USERDATA': 159311,
                            'DESCRIPTION': ''
                        },
                        {
                            'TYPE': 1,
                            'SUBTYPE': 2,
                            'USERDATA': 159314,
                            'DESCRIPTION': ''
                        },
                        {
                            'TYPE': 1,
                            'SUBTYPE': 3,
                            'USERDATA': {...},
                            'DESCRIPTION': 'Please fill in all required attributes.'
                        }
                    ],
                    'permissions': {
                        'Archive': True,
                        'ChangeAttr': True,
                        'ChangeRoute': True,
                        'Delete': True,
                        'ManagerPerms': True,
                        'SeeDetail': True,
                        'Stop': True,
                        'Suspend': True
                    },
                    'step_list': {
                        'completed': [],
                        'current': [
                            {
                                'process_id': 159314,
                                'subprocess_id': 159314,
                                'task_id': 10,
                                'task_name': 'set Item Status = pending approval',
                                'task_due_date': '',
                                'task_start_date': '2024-10-03T15:21:23',
                                'task_status': 'ontime',
                                'task_assignees': {
                                    'assignee': [
                                        {
                                            'userId': 1000,
                                            'loginName': 'Admin',
                                            'firstName': '',
                                            'lastName': '',
                                            'emailAddress': '',
                                            'phone': ''
                                        }
                                    ],
                                    'assigneeCount': 1,
                                    'currentAssignee': ' '
                                }
                            }
                        ],
                        'next': []
                    },
                    'wf_details': {
                        'date_initiated': '2024-10-03T15:21:23',
                        'due_date': '',
                        'initiator': {
                            'firstName': 'Paul',
                            'lastName': 'Williams',
                            'loginName': 'pwilliams',
                            'userId': 15235
                        },
                        'status': 'ontime',
                        'wf_name': 'Test without due date',
                        'work_workID': 159314
                    }
                }
            }
            ```

        """

        request_url = self.config()["workflowUrl"] + "/status/processes/{}".format(
            process_id,
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workflow status (task list) of process ID -> %s; calling -> %s",
            str(process_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workflow status for process ID -> {}".format(
                process_id,
            ),
        )

    # end method definition

    def create_draft_process(self, workflow_id: int, documents: list) -> dict | None:
        """Initiate a draft process. This is the first step to start a process (workflow instance).

        Args:
            workflow_id (int):
                The node ID of the workflow map.
            documents (list):
                The node IDs of the attachmewnt documents.

        Returns:
            dict | None:
                Task list of the workflow instance or None if the request fails.

        Example:
            ```json
            {
                'links': {
                    'data': {...}
                },
                'results': {
                    'draftprocess_id': 157555,
                    'workflow_type': '1_1'}
                }
            }
            ```

        """

        draft_process_body_post_data = {
            "workflow_id": workflow_id,
            "doc_ids": documents,
        }

        request_url = self.config()["draftProcessUrl"]
        request_header = self.request_form_header()

        self.logger.debug(
            "Create a draft process for workflow with ID -> %s and body -> %s; calling -> %s",
            str(workflow_id),
            str(draft_process_body_post_data),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(draft_process_body_post_data)},
            timeout=None,
            failure_message="Failed to create draft process from workflow with ID -> {}".format(
                workflow_id,
            ),
        )

    # end method definition

    def get_draft_process(self, draftprocess_id: int) -> dict | None:
        r"""Get draft process data.

        Args:
            draftprocess_id (int):
                The ID of an existing draft process.

        Returns:
            dict | None:
                The details for a draft process. Delivers None in case of an error.

        Example:
            ```json
            {
                'data': {
                    'actions': [
                        {
                            'key': 'Initiate',
                            'label': 'Start'
                        }
                    ],
                    'attachment_centric_default_mode': 'properties',
                    'attachments_on': True,
                    'authentication': False,
                    'comments_on': True,
                    'data_packages': [...],
                    'enableTopAlignedLabel': True,
                    'instructions': 'Please pick the Approver (type-ahead search)\n\n',
                    'process_id': 158037,
                    'task': {...},
                    'title': 'Contract Approval Workflow (1 step)',
                    'workflow_type': '1_1'
                },
                'forms': [
                    {...}
                ]
            }
            ```

        """

        request_url = self.config()["draftProcessFormUrl"] + "/update" + "?draftprocess_id=" + str(draftprocess_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get draft process with ID -> %s; calling -> %s",
            str(draftprocess_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get draft process with ID -> {}".format(
                draftprocess_id,
            ),
        )

    # end method definition

    def update_draft_process(
        self,
        draftprocess_id: int,
        title: str = "",
        due_date: str = "",
        values: dict | None = None,
    ) -> dict | None:
        """Update a draft process with values.

        These can either be given via dedicated parameters
        like title and due_date or with a generic value dictionary.

        Args:
            draftprocess_id (int):
                The ID of the draft process that has been created before with create_draft_process().
            title (str):
                The title of the process.
            due_date (str, optional):
                The due date for the process. Defaults to "".
            values (dict | None, optional):
                The values for workflow attributes. Defaults to None.

        Returns:
            dict | None:
                Response of the REST API or None in case of an error.

        """

        request_url = self.config()["draftProcessUrl"] + "/" + str(draftprocess_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Update draft process with ID -> %s with these values -> %s; calling -> %s",
            str(draftprocess_id),
            str(values),
            request_url,
        )

        if not values:
            values = {}

        if title:
            values["WorkflowForm_Title"] = title
        if due_date:
            values["WorkflowForm_WorkflowDueDate"] = due_date

        update_draft_process_body_put_data = {
            "action": "formUpdate",
            "values": values,
        }

        # this call needs a "body" tag around the
        # actual payload - otherwise it will return just "None"
        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data={"body": json.dumps(update_draft_process_body_put_data)},
            timeout=None,
            failure_message="Failed to update draft process with ID -> {} with these values -> {}".format(
                draftprocess_id,
                values,
            ),
        )

    # end method definition

    def initiate_draft_process(
        self,
        draftprocess_id: int,
        comment: str = "",
    ) -> dict | None:
        """Initiate a process (workflow instance) from a draft process.

        Args:
            draftprocess_id (int):
                The ID of the draft process that has been created before with create_draft_process()
            title (str):
                The title of the process.
            comment (str, optional):
                The comment of the process. Defaults to "".
            due_date (str, optional):
                The due date for the process. Defaults to "" (= no due date).
            values (dict | None, optional):
                The values for workflow attributes. Defaults to None (all attributes remain empty).

        Returns:
            dict | None:
                Response of the REST API or None in case of an error.

        Example:
            ```json
            {
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/draftprocesses/158037',
                            'method': 'PUT',
                            'name': ''
                        }
                    }
                },
                'results': {
                    'custom_message': 'Contract Approval Workflow was initiated successfully.',
                    'process_id': 165496,
                    'WorkID': None,
                    'WRID': None
                }
            }
            ```

        """

        request_url = self.config()["draftProcessUrl"] + "/" + str(draftprocess_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Initiate a process (workflow instance) from a draft process with ID -> %s; calling -> %s",
            str(draftprocess_id),
            request_url,
        )

        initiate_process_body_put_data = {
            "action": "Initiate",
            "comment": comment,
        }

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data={"body": json.dumps(initiate_process_body_put_data)},
            timeout=None,
            failure_message="Failed to initiate draft process with ID -> {}".format(
                draftprocess_id,
            ),
        )

    # end method definition

    def get_process_task(
        self,
        process_id: int,
        subprocess_id: int | None = None,
        task_id: int = 1,
    ) -> dict | None:
        r"""Get the task information of a workflow assignment.

        This method must be called with the user authenticated
        that has the task in ts inbox.

        Args:
            process_id (int):
                The process ID of the workflow instance.
            subprocess_id (int | None, optional):
                The subprocess ID. Defaults to None (= process_id).
            task_id (int, optional):
                The task ID. Defaults to 1.

        Returns:
            dict | None: Response of REST API call. None in case an error occured.

        Example:
            ```json
            {
                'data': {
                    'actions': [
                        {
                            'key': 'Delegate',
                            'label': 'Forward'
                        }
                    ],
                    'attachments_on': True,
                    'authentication': False,
                    'comments_on': True,
                    'custom_actions': [
                        {
                            'key': 'Approve',
                            'label': 'Approve'
                        },
                        {
                            'key': 'Reject',
                            'label': 'Reject'
                        }
                    ],
                    'data_packages': [
                        {
                            'data': {
                                'attachment_folder_id': 115292
                            },
                            'sub_type': 1,
                            'type': 1
                        }
                    ],
                    'instructions': 'Paul Williams has sent this contract to you for review.',
                    'message': None,
                    'process_id': 115295,
                    'subprocess_id': 115295,
                    'task': {...},
                    'task_id': 1,
                    'title': 'Approver'
                },
                'forms': [
                    {...}
                ]
            }
            ```

        """

        if subprocess_id is None:
            subprocess_id = process_id

        request_url = (
            self.config()["processTaskUrl"]
            + "?process_id="
            + str(process_id)
            + "&subprocess_id="
            + str(subprocess_id)
            + "&task_id="
            + str(task_id)
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Get a process (workflow instance) task for process with ID -> %s; calling -> %s",
            str(process_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get task for process with ID -> {}".format(
                process_id,
            ),
        )

    # end method definition

    def update_process_task(
        self,
        process_id: int,
        subprocess_id: int | None = None,
        task_id: int = 1,
        values: dict | None = None,
        action: str = "formUpdate",
        custom_action: str = "",
        comment: str = "",
    ) -> dict | None:
        """Update a process with values in a task.

        This method needs to be called with the user that has the task in its inbox
        (My ToDo - Workflows). It can update the task data (formUpdate)
        and/or send on the task to the next workflow step (action or custom_action).

        TODO: this method is currently untested.

        Args:
            process_id (int):
                The ID of the draft process that has been created before with create_draft_process().
            subprocess_id (int):
                The ID of the subprocess.
            task_id (int, optional):
                The ID of the task. Default is 1.
            values (dict | None, optional):
                The values for workflow attributes. Defaults to None.
                It is only used if action = "formUpdate".
            action (str, optional):
                The name of the action to process. The default is "formUpdate".
            custom_action (str, optional):
                Here we can have custom actions like "Approve" or "Reject".
                If "custom_action" is not None then the "action" parameter is ignored.
            comment (str, optional):
                The comment given with the action.

        Returns:
            dict | None:
                Response of the REST API or None in case of an error.

        """

        if not action and not custom_action:
            self.logger.error(
                "Either 'action' or 'custom_action' is required for updating a process task!",
            )
            return None

        if subprocess_id is None:
            subprocess_id = process_id

        request_url = (
            self.config()["processUrl"]
            + "/"
            + str(process_id)
            + "/subprocesses/"
            + str(subprocess_id)
            + "/tasks/"
            + str(task_id)
        )
        request_header = self.request_form_header()

        if values:
            self.logger.debug(
                "Update task with ID -> %s of process with ID -> %s with these values -> %s; calling -> %s",
                str(task_id),
                str(process_id),
                str(values),
                request_url,
            )

        if not values:
            values = {}

        if not custom_action:
            update_process_task_body_put_data = {
                "action": action,
            }
            if action == "formUpdate":
                update_process_task_body_put_data["values"] = values
            self.logger.debug(
                "Execute action -> '%s' for process with ID -> %s",
                action,
                str(process_id),
            )
        else:  # we have a custom action:
            update_process_task_body_put_data = {
                "custom_action": custom_action,
            }
            self.logger.debug(
                "Execute custom action -> '%s' for process with ID -> %s",
                custom_action,
                str(process_id),
            )
        if comment:
            update_process_task_body_put_data["comment"] = comment

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data={"body": json.dumps(update_process_task_body_put_data)},
            timeout=None,
            failure_message="Failed to update task with ID -> {} of process with ID -> {} with these values -> {}".format(
                task_id,
                process_id,
                values,
            ),
        )

    # end method definition

    def check_workspace_aviator(
        self,
        workspace_id: int,
    ) -> bool:
        """Check if Content Aviator is enabled for a workspace.

        Args:
            workspace_id (int):
                The node ID of the workspace to enable for Content Aviator.

        Returns:
            bool:
                True, if Content Aviator is enabled, False otherwise.

        """

        response = self.get_node_actions(
            node_id=workspace_id,
            filter_actions=["disableai", "enableai"],
        )
        result_data = self.get_result_value(
            response=response,
            key=str(workspace_id),
        )
        if result_data and "data" in result_data:
            data = result_data["data"]
            if "disableai" in data:
                self.logger.debug(
                    "Aviator is enabled for workspace with ID -> %s",
                    str(workspace_id),
                )
                return True
            elif "enableai" in data:
                self.logger.debug(
                    "Aviator is disabled for workspace with ID -> %s",
                    str(workspace_id),
                )

        return False

    # end method definition

    def update_workspace_aviator(
        self,
        workspace_id: int,
        status: bool,
    ) -> dict | None:
        """Enable or disable the Content Aviator for a workspace.

        Args:
            workspace_id (int):
                The node ID of the workspace
            status (bool):
                True = enable, False = disable Content Aviator for this workspace.

        Returns:
            dict | None: REST response or None if the REST call fails.

        """

        aviator_status_put_data = {
            "enabled": status,
        }

        request_url = self.config()["aiUrl"] + "/{}".format(workspace_id)
        request_header = self.request_form_header()

        if status is True:
            self.logger.debug(
                "Enable Content Aviator for workspace with ID -> %s; calling -> %s",
                str(workspace_id),
                request_url,
            )
        else:
            self.logger.debug(
                "Disable Content Aviator for workspace with ID -> %s; calling -> %s",
                str(workspace_id),
                request_url,
            )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=aviator_status_put_data,
            timeout=None,
            failure_message="Failed to change status for Content Aviator on workspace with ID -> {}".format(
                workspace_id,
            ),
        )

    # end method definition

    def volume_translator(
        self,
        current_node_id: int,
        translator: object,
        languages: list,
        simulate: bool = False,
    ) -> None:
        """Experimental code to translate the item names and descriptions in a hierarchy.

        The actual translation is done by a tranlator object. This recursive method just
        traverses the hierarchy and calls the translate() method of the translator object.

        Args:
            current_node_id (int):
                The current node ID to translate.
            translator (object):
                This object needs to be created based on the "Translator" class
                and passed to this method.
            languages (list):
                A list of target languages to translate into.
            simulate (bool, optional):
                If True, do not really rename but just traverse and log info.
                The default is False.

        """

        # Get current node based on the ID:
        current_node = self.get_node(current_node_id)
        current_node_id = self.get_result_value(response=current_node, key="id")

        name = self.get_result_value(response=current_node, key="name")
        description = self.get_result_value(response=current_node, key="description")
        names_multilingual = self.get_result_value(
            response=current_node,
            key="name_multilingual",
        )
        descriptions_multilingual = self.get_result_value(
            response=current_node,
            key="description_multilingual",
        )

        for language in languages:
            if language == "en":
                continue
            # Does the language not exist as metadata language or is it
            # already translated? Then we skip this language:
            if language in names_multilingual and names_multilingual["en"] and not names_multilingual[language]:
                names_multilingual[language] = translator.translate(
                    "en",
                    language,
                    names_multilingual["en"],
                )
                self.logger.debug(
                    "Translate name of node -> %s from -> '%s' (%s) to -> '%s' (%s)",
                    current_node_id,
                    name,
                    "en",
                    names_multilingual[language],
                    language,
                )
            if (
                language in descriptions_multilingual
                and descriptions_multilingual["en"]
                and not descriptions_multilingual[language]
            ):
                descriptions_multilingual[language] = translator.translate(
                    "en",
                    language,
                    descriptions_multilingual["en"],
                )
                self.logger.debug(
                    "Translate description of node -> %s from -> '%s' (%s) to -> '%s' (%s)",
                    current_node_id,
                    descriptions_multilingual["en"],
                    "en",
                    descriptions_multilingual[language],
                    language,
                )

        # Rename node multi-lingual:
        if not simulate:
            self.rename_node(
                node_id=current_node_id,
                name=name,
                description=description,
                name_multilingual=names_multilingual,
                description_multilingual=descriptions_multilingual,
            )

        # Get children nodes of the current node:
        results = self.get_subnodes(parent_node_id=current_node_id, limit=200)["results"]

        # Recursive call of all subnodes:
        for result in results:
            self.volume_translator(
                current_node_id=result["data"]["properties"]["id"],
                translator=translator,
                languages=languages,
            )

    # end method definition

    def download_document_multi_threading(
        self,
        node_id: int,
        file_path: str,
        extract_after_download: bool = False,
    ) -> None:
        """Multi-threading variant of download_document().

        Args:
            node_id (int):
                Node ID of the document to download.
            file_path (str):
                File system path - location to download to.
            extract_after_download (bool):
                Extract the downloaded file recusively to a folder
                with same name as the document.

        """

        # Aquire and release thread semaphore to limit parallel API executions
        # to not overload source system:
        with self._semaphore:
            self.download_document(node_id=node_id, file_path=file_path)

        if extract_after_download and os.path.isfile(file_path):
            self.logger.debug("Extracting Zip file -> %s", file_path)

            file_with_ext = file_path + ".zip"
            try:
                # Rename the node to ID.zip to extract it to
                # the same name, remove zip if present:
                if os.path.isfile(file_with_ext):
                    os.remove(file_with_ext)
                os.rename(file_path, file_with_ext)
            except OSError:
                self.logger.error(
                    "Failed to rename file -> '%s' to '%s'!",
                    file_path,
                    file_with_ext,
                )
                return

            try:
                with zipfile.ZipFile(file_with_ext, "r") as zfile:
                    zfile.extractall(file_path)
                    os.remove(file_with_ext)

                self.logger.debug(
                    "File successfully extracted, extracting nested items -> %s",
                    file_path,
                )

            except Exception:
                self.logger.error(
                    "Failed to unzip node (%s) -> %s",
                    node_id,
                    file_path,
                )

            for root, _, files in os.walk(file_path):
                for filename in files:
                    if filename.endswith(".zip"):
                        file_spec = os.path.join(root, filename)
                        try:
                            with zipfile.ZipFile(file_spec, "r") as zip_file:
                                self.logger.debug(
                                    "Extracting nested ZIP archive -> %s",
                                    filename,
                                )
                                zip_file.extractall(os.path.join(root, filename[:-4]))
                        except Exception:
                            self.logger.error(
                                "Failed to unzip nested ZIP file -> '%s'!",
                                filename,
                            )

    # end method definition

    def apply_filter(
        self,
        node: dict,
        node_categories: dict | None = None,
        current_depth: int = 0,
        filter_depth: int | None = None,
        filter_subtypes: list | None = None,
        filter_category: str | None = None,
        filter_attributes: dict | list | None = None,
    ) -> bool:
        """Check all defined filters for the given node.

        All filters are applied additive, i.e. the given node must comply
        with _all_ filters to pass the test.

        Args:
            node (dict):
                The current OTCS Node to test the filters for.
            node_categories (dict | None, optional):
                If the calling method has already used get_node_categories()
                to get the category data structure of the node we can pass the response
                of get_node_categories() with this parameter to optimize performance and
                avoid recalculation. It is optional, and if it is not provided, category
                data is determined with get_node_categories() inside this method.
            current_depth (int, optional):
                The current depth of the traversal. Used for the depth_filter.
            filter_depth (int | None, optional):
                Additive filter criterium for path depth.
                Defaults to None = filter not active.
            filter_subtypes (list | None, optional):
                Additive filter criterium for item type.
                Defaults to None = filter not active.
            filter_category (str | None, optional):
                Additive filter criterium for existence of a category on the node.
                The value of filter_category is the name of the category
                the node must have assigned.
                Defaults to None = filter not active.
            filter_attributes (dict | list | None, optional):
                Additive filter for attribute values on the node.
                The dictionary has multiple keys:
                * category (str, optional): The name of the category
                * set (str, optional): The name of the set.
                * attribute (str, mandatory): The name of the attribute.
                * row (int, optional): The row in a multi-row set.
                * value (any, mandatory): The value of the attribute.
                Defaults to None = filter not active.
                {
                    "category": <cat_name>
                    "set": <set_name>
                    "row": <num>
                    "value": [...] | "..."
                }

        Returns:
            bool:
                Only for nodes that comply with ALL provided filters True is returned.
                Otherwise False.

        """

        if not node or "type" not in node or "id" not in node:
            self.logger.error("Illegal node - cannot apply filter!")
            return False

        if filter_subtypes and node["type"] not in filter_subtypes:
            self.logger.debug(
                "Node type -> '%s' is not in filter node types -> %s. Node -> '%s' failed filter test.",
                node["type"],
                filter_subtypes,
                node["name"],
            )
            return False

        if filter_depth is not None and filter_depth != current_depth:
            self.logger.debug(
                "Node is in depth -> %s which is different from filter depth -> %s. Node -> '%s' failed filter test.",
                current_depth,
                filter_depth,
                node["name"],
            )
            return False

        if filter_category:
            # Check if the categories have NOT been provided by the calling method.
            # In this case we determine it here:
            if node_categories is None:
                # We pre-calculated the node categories to avoid doing this
                # multiple times in the methodes get_node_category_names(),
                # get_node_category_definitions() and get_category_value() below:
                node_categories = self.get_node_categories(
                    node_id=node["id"],
                    metadata=True,
                )
            # We determine all category names of the current node
            # to test the category filter:
            category_names = self.get_node_category_names(
                node_id=node["id"],
                node_categories=node_categories,
            )
            if not category_names or filter_category not in category_names:
                if not category_names:
                    self.logger.debug(
                        "Node -> '%s' (%s) failed filter test. It does not have filter category -> '%s'.",
                        node["name"],
                        node["id"],
                        filter_category,
                    )
                else:
                    self.logger.debug(
                        "Node -> '%s' (%s) failed filter test. Its categories -> %s do not include filter category -> '%s'.",
                        node["name"],
                        node["id"],
                        category_names,
                        filter_category,
                    )
                return False
            if filter_attributes:
                if isinstance(filter_attributes, dict):
                    filter_attributes = [filter_attributes]
                # We try to optimize performance here by precalculating
                # the category definition outside the for loop below
                # This will work only if the attribute filters don't have
                # their own category specified in the payload:
                (_, cat_definitions) = self.get_node_category_definition(
                    node_id=node["id"],
                    category_name=filter_category,
                    node_categories=node_categories,
                )

                for filter_attribute in filter_attributes:
                    # Check if the category name is explicitly defined inside the
                    # attribute filter payload, otherwise we reuse the category name
                    # from the category filter above:
                    filter_category_name = filter_attribute.get(
                        "category",
                        filter_category,
                    )
                    if not filter_category_name:
                        self.logger.error(
                            "Attribute filter -> %s is missing the category name!",
                            str(filter_attribute),
                        )
                        continue
                    filter_set_name = filter_attribute.get("set", None)
                    filter_attribute_name = filter_attribute.get("attribute", None)
                    if not filter_attribute_name:
                        self.logger.error(
                            "Attribute filter -> %s is missing attribute name!",
                            str(filter_attribute),
                        )
                        continue
                    filter_row = filter_attribute.get("row", None)
                    filter_value = filter_attribute.get("value", None)
                    # We pass in the category definitions if the attribute filter
                    # does not have a different category name specified in the payload:
                    actual_value = self.get_category_value_by_name(
                        node_id=node["id"],
                        category_name=filter_category_name,
                        set_name=filter_set_name,
                        attribute_name=filter_attribute_name,
                        set_row=filter_row,
                        cat_definitions=cat_definitions if filter_category_name == filter_category else None,
                        node_categories=node_categories,
                    )
                    # Both actual value and filter value can be strings or list of strings.
                    # So we need to handle a couple of cases here:

                    # Case 1: the actual value is not set (empty field). In this case the item cannot comply with the filter:
                    if actual_value is None:
                        self.logger.debug(
                            "Node -> '%s' (%s) failed filter test. Its node attribute value for attribute -> '%s' is empty and thus not matching any of the filter values -> %s.",
                            node["name"],
                            node["id"],
                            filter_attribute_name,
                            str(filter_value),
                        )
                        return False
                    # Case 2: Data source delivers a list and filter value is a scalar value (int, str, float)
                    elif isinstance(actual_value, list) and isinstance(
                        filter_value,
                        (str, int, float),
                    ):
                        if filter_value not in actual_value:
                            self.logger.debug(
                                "Node -> '%s' (%s) failed filter test. Its filter value -> '%s' is not included in node attribute values -> %s for attribute -> '%s'.",
                                node["name"],
                                node["id"],
                                str(filter_value),
                                str(actual_value),
                                filter_attribute_name,
                            )
                            return False
                    # Case 3: Data source delivers a scalar value and filter value is a list
                    elif isinstance(actual_value, (str, int, float)) and isinstance(
                        filter_value,
                        list,
                    ):
                        if actual_value not in filter_value:
                            self.logger.debug(
                                "Node -> '%s' (%s) failed filter test. Its filter values -> %s do not include the node attribute value -> '%s' for attribute -> '%s'.",
                                node["name"],
                                node["id"],
                                str(filter_value),
                                str(actual_value),
                                filter_attribute_name,
                            )
                            return False
                    # Case 4: Both, filter and actual value are lists:
                    elif isinstance(actual_value, list) and isinstance(
                        filter_value,
                        list,
                    ):
                        # check if there's an non-empty intersetion set of both lists:
                        if not set(actual_value) & set(filter_value):
                            self.logger.debug(
                                "Node -> '%s' (%s) failed filter test. Its filter values -> %s do not intersect with node attribute values -> %s for attribute -> '%s'.",
                                node["name"],
                                node["id"],
                                str(filter_value),
                                str(actual_value),
                                filter_attribute_name,
                            )
                            return False
                    # Case 5: Both, filter and actual value are scalar:
                    elif isinstance(actual_value, (str, int, float)) and isinstance(
                        filter_value,
                        (str, int, float),
                    ):
                        if actual_value != filter_value:
                            self.logger.debug(
                                "Node -> '%s' (%s) failed filter test. Its filter value -> '%s' is not equal to node attribute value -> '%s'.",
                                node["name"],
                                node["id"],
                                str(filter_value),
                                str(actual_value),
                            )
                            return False
                    else:
                        return False

        return True

    # end method definition

    def add_attribute_columns(self, row: dict, categories: dict, prefix: str) -> bool:
        """Add attributes for all categories to the row dictionary.

        The resulting row will be added by the calling load_items() method
        to a Data Frame.

        Args:
            row (dict):
                The row data to extend with keys for each attribute.
            categories (dict):
                The categories of the node.
            prefix (str):
                The prefix string. Either "workspace_" or "item_" to
                differentiate attributes on workspace level and attributes
                on item (document) level.

        Returns:
            bool:
                True = succeess, False = error.

        """

        if not categories or "results" not in categories:
            return False

        for category in categories["results"]:
            if "data" not in category or "categories" not in category["data"]:
                continue
            attributes = category["data"]["categories"]
            metadata = category["metadata"]["categories"]
            category_item = metadata.pop(first_key) if (first_key := next(iter(metadata), None)) else None
            category_name = category_item.get("name")
            # Replace non-aphanumeric characters in the name with underscores
            # but avoid having multiple underscores following each other:
            category_name = re.sub(r"[^a-z0-9]+", "_", category_name.lower())
            for key in attributes:
                value = attributes[key]
                if self._use_numeric_category_identifier:  # this value is set be the class initializer
                    column_header = prefix + key
                else:
                    # Construct the final coolumn name by replacing the leading <cat_num>_ with the
                    # normalized name of the category.
                    column_header = prefix + re.sub(r"^[^_]+_", category_name + "_", key)
                row[column_header] = value

        return True

    # end method definition

    def load_items(
        self,
        node_id: int,
        folder_path: list | None = None,
        current_depth: int = 0,
        workspace_type: int | None = None,
        workspace_id: int | None = None,
        workspace_name: str | None = None,
        workspace_description: str | None = None,
        filter_workspace_depth: int | None = None,
        filter_workspace_subtypes: list | None = None,
        filter_workspace_category: str | None = None,
        filter_workspace_attributes: dict | list | None = None,
        filter_item_depth: int | None = None,
        filter_item_subtypes: list | None = None,
        filter_item_category: str | None = None,
        filter_item_attributes: dict | list | None = None,
        filter_item_in_workspace: bool = True,
        exclude_node_ids: list | None = None,
        workspace_metadata: bool = True,
        item_metadata: bool = True,
        download_documents: bool = True,
        skip_existing_downloads: bool = True,
        extract_zip: bool = False,
    ) -> bool:
        """Create a Pandas Data Frame by traversing a given Content Server hierarchy.

        This method collects workspace and document items.

        Args:
            node_id (int):
                The currrent Node ID (in recursive processing).
                Initially this is the starting node (root of the traversal).
            folder_path (str, optional):
                The current path from the starting node to the current node
                (in recursive processing). Defaults to None.
            current_depth (int):
                The current depth in the tree that is traversed.
            workspace_type (int | None, optional):
                The type of the workspace (if already found in the hierarchy).
                It is used for writing it in the data row of processed sub-items.
                Defaults to None.
            workspace_id (int | None, optional):
                The ID of the workspace (if already found in the hierarchy).
                It is used for writing it in the data row of processed sub-items.
                Defaults to None.
            workspace_name (str | None, optional):
                The name of the workspace (if already found in the hierarchy).
                It is used for writing it in the data row of processed sub-items.
                Defaults to None.
            workspace_description (str | None, optional):
                The description of the workspace (if already found in the hierarchy).
                It is used for writing it in the data row of processed sub-items.
                Defaults to None.
            filter_workspace_depth (int | None, optional):
                Additive filter criterium for workspace path depth.
                Defaults to None = filter not active.
            filter_workspace_subtypes (list | None, optional):
                Additive filter criterium for workspace type.
                Defaults to None = filter not active.
            filter_workspace_category (str | None, optional):
                Additive filter criterium for workspace category.
                Defaults to None = filter not active.
            filter_workspace_attributes (dict | list, optional):
                Additive filter criterium for workspace attribute values.
                Defaults to None = filter not active
            filter_item_depth (int | None, optional):
                Additive filter criterium for item path depth.
                Defaults to None = filter not active.
            filter_item_subtypes (list | None, optional):
                Additive filter criterium for item types.
                Defaults to None = filter not active.
            filter_item_category (str | None, optional):
                Additive filter criterium for item category.
                Defaults to None = filter not active.
            filter_item_attributes (dict | list, optional):
                Additive filter criterium for item attribute values.
                Defaults to None = filter not active.
            filter_item_in_workspace (bool, optional):
                Defines if item filters should be applied to
                items inside workspaces as well. If False,
                then items inside workspaces are always included.
            exclude_node_ids (list, optional):
                List of node IDs to exclude from traversal.
            workspace_metadata (bool, optional):
                If True, include workspace metadata.
            item_metadata (bool, optional):
                if True, include item metadata.
            download_documents (bool, optional):
                Whether or not documents should be downloaded.
            skip_existing_downloads (bool, optional):
                If True, reuse already existing downloads in the file system.
            extract_zip (bool, optional):
                If True, documents that are downloaded with mime-type
                "application/x-zip-compressed" will be extracted recursively.

        Returns:
            bool: True = success, False = Error

        """

        if folder_path is None:
            folder_path = []  # required for list concatenation below

        # Create folder if it does not exist
        if not os.path.exists(self._download_dir):
            os.makedirs(self._download_dir)

        # Aquire and Release threading semaphore to limit parallel executions
        # to not overload the source Content Server system:
        with self._semaphore:
            subnodes = self.get_subnodes_iterator(parent_node_id=node_id, page_size=100)

        # Initialize traversal threads:
        traversal_threads = []

        for subnode in subnodes:
            subnode = subnode.get("data").get("properties")

            if exclude_node_ids is not None and (subnode["id"] in exclude_node_ids):
                self.logger.info(
                    "Node with ID -> %s and name -> '%s' is in exclusion list. Skip traversal of this node.",
                    subnode["id"],
                    subnode["name"],
                )
                continue
            # Initiaze download threads for this subnode:
            download_threads = []

            match subnode["type"]:
                case self.ITEM_TYPE_FOLDER | self.ITEM_TYPE_BUSINESS_WORKSPACE:  # folder or workspace
                    # First we check if we have not found a workspace already during the traversal:
                    if not workspace_id:
                        # We try to avoid calculating the node categories more than once
                        # by doing it here and use it for filtering _and_ for
                        # data frame columns. We only need the category metadata if we
                        # have category/attribute filters:
                        if workspace_metadata or filter_workspace_category or filter_workspace_attributes:
                            categories = self.get_node_categories(
                                node_id=subnode["id"],
                                metadata=(
                                    filter_workspace_category is not None
                                    or filter_workspace_attributes is not None
                                    or not self._use_numeric_category_identifier
                                ),
                            )
                        else:
                            categories = None

                        # Second we apply the defined filters to the current node to see
                        # if it is a node that we want to interpret as a workspace.
                        # Only "workspaces" that comply with ALL provided filters are
                        # considered and written into the data frame:
                        found_workspace = self.apply_filter(
                            node=subnode,
                            node_categories=categories,
                            current_depth=current_depth,
                            filter_depth=filter_workspace_depth,
                            filter_subtypes=filter_workspace_subtypes,
                            filter_category=filter_workspace_category,
                            filter_attributes=filter_workspace_attributes,
                        )
                    else:
                        self.logger.debug(
                            "Found folder or workspace -> '%s' (%s) inside workspace with ID -> %s. So this container cannot be a workspace.",
                            subnode["name"],
                            subnode["id"],
                            workspace_id,
                        )
                        # otherwise the current node cannot be a workspace as we are
                        # already in a workspace!
                        # For future improvements we could look at supporting
                        # sub-workspaces:
                        found_workspace = False

                    if found_workspace:
                        self.logger.info(
                            "Found workspace -> '%s' (%s) in depth -> %s. Adding to Data Frame...",
                            subnode["name"],
                            subnode["id"],
                            current_depth,
                        )
                        # DON'T change workspace_id here!
                        # This would break the for loop logic!

                        #
                        # Construct a dictionary 'row' that we will add
                        # to the resulting data frame:
                        #
                        row = {}
                        row["workspace_type"] = subnode["type"]
                        row["workspace_id"] = subnode["id"]
                        row["workspace_name"] = subnode["name"]
                        row["workspace_description"] = subnode["description"]
                        row["workspace_outer_path"] = folder_path
                        # If we want (and have) metadata then add it as columns:
                        if workspace_metadata and categories and categories.get("results", None):
                            # Add columns for workspace node categories have been determined above.
                            self.add_attribute_columns(row=row, categories=categories, prefix="workspace_cat_")

                        # Now we add the article to the Pandas Data Frame in the Data class:
                        with self._data.lock():
                            self._data.append(row)
                        subfolder = []  # now we switch to workspace inner path
                    # end if found_workspace:
                    else:  # we treat the current folder / workspace just as a container
                        self.logger.info(
                            "Node -> '%s' (%s) in depth -> %s is NOT a workspace as the filter criteria were not met. Keep traversing...",
                            subnode["name"],
                            subnode["id"],
                            current_depth,
                        )
                        subfolder = folder_path + [subnode["name"]]

                    # Recursive call to start threads for sub-items:
                    thread = threading.Thread(
                        target=self.load_items,
                        args=(
                            subnode["id"],  # node_id
                            subfolder,  # folder_path
                            current_depth + 1,  # current_depth
                            (
                                workspace_type  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["type"]
                            ),  # workspace_type = subtype of the node we identified as a workspace
                            (
                                workspace_id  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["id"]
                            ),  # workspace_id = ID of the node we identified as a workspace
                            (
                                workspace_name  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["name"]
                            ),  # workspace_name
                            (
                                workspace_description  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["description"]
                            ),  # workspace_description
                            filter_workspace_depth,
                            filter_workspace_subtypes,
                            filter_workspace_category,
                            filter_workspace_attributes,
                            filter_item_depth,
                            filter_item_subtypes,
                            filter_item_category,
                            filter_item_attributes,
                            filter_item_in_workspace,
                            exclude_node_ids,
                            workspace_metadata,
                            item_metadata,
                            download_documents,
                            skip_existing_downloads,
                            extract_zip,
                        ),
                        name="traverse_node_{}".format(subnode["id"]),
                    )
                    thread.start()
                    traversal_threads.append(thread)

                case self.ITEM_TYPE_SHORTCUT:  # shortcuts
                    pass

                case self.ITEM_TYPE_RELATED_WORKSPACE:  # Related Workspaces - we don't want to run into loops!
                    pass

                case self.ITEM_TYPE_EMAIL_FOLDER:  # E-Mail folders
                    pass

                case self.ITEM_TYPE_FORUM:  # Forum
                    pass

                case self.ITEM_TYPE_DOCUMENT | self.ITEM_TYPE_URL:  # document or URL
                    # We try to avoid calculating the node categories more than once
                    # by doing it here and use it for filtering _and_ for data frame columns.
                    # We only need the category metadata if we have category/attribute filters:
                    if item_metadata or filter_item_category or filter_item_attributes:
                        categories = self.get_node_categories(
                            node_id=subnode["id"],
                            metadata=(
                                filter_item_category is not None
                                or filter_item_attributes is not None
                                or not self._use_numeric_category_identifier
                            ),
                        )
                    else:
                        categories = None

                    # If filter_item_in_workspace is false, then documents
                    # inside workspaces are included in the data frame unconditionally!
                    if not workspace_id or filter_item_in_workspace:
                        # We apply the defined filters to the current node. Only "documents"
                        # that comply with ALL provided filters are considered and written into the data frame
                        found_item = self.apply_filter(
                            node=subnode,
                            node_categories=categories,
                            current_depth=current_depth,
                            filter_depth=filter_item_depth,
                            filter_subtypes=filter_item_subtypes,
                            filter_category=filter_item_category,
                            filter_attributes=filter_item_attributes,
                        )
                    else:
                        found_item = True

                    if not found_item:
                        continue

                    # We use the node ID as the filename to avoid any
                    # issues with too long or not valid file names.
                    # As the Pandas DataFrame has all information
                    # this is easy to resolve at upload time.
                    file_path = "{}/{}".format(self._download_dir, subnode["id"])

                    # We only consider documents that are inside the defined "workspaces":
                    if workspace_id:
                        self.logger.debug(
                            "Found %s item -> '%s' (%s) in depth -> %s inside workspace -> '%s' (%s).",
                            "document" if subnode["type"] == self.ITEM_TYPE_DOCUMENT else "URL",
                            subnode["name"],
                            subnode["id"],
                            current_depth,
                            workspace_name,
                            workspace_id,
                        )
                    else:
                        self.logger.debug(
                            "Found %s item -> '%s' (%s) in depth -> %s outside of workspace.",
                            "document" if subnode["type"] == self.ITEM_TYPE_DOCUMENT else "URL",
                            subnode["name"],
                            subnode["id"],
                            current_depth,
                        )

                    if subnode["type"] == self.ITEM_TYPE_DOCUMENT:
                        # We download only if not downloaded before or if downloaded
                        # before but forced to re-download:
                        if download_documents and (not os.path.exists(file_path) or not skip_existing_downloads):
                            #
                            # Start anasynchronous Download Thread:
                            #
                            self.logger.debug(
                                "Downloading file -> '%s'...",
                                file_path,
                            )

                            extract_after_download = (
                                subnode["mime_type"] == "application/x-zip-compressed" and extract_zip
                            )
                            thread = threading.Thread(
                                target=self.download_document_multi_threading,
                                args=(subnode["id"], file_path, extract_after_download),
                                name="download_document_node_{}".format(subnode["id"]),
                            )
                            thread.start()
                            download_threads.append(thread)
                        else:
                            self.logger.debug(
                                "File -> %s has been downloaded before or download is not requested. Skipping download...",
                                file_path,
                            )
                    # end if document

                    #
                    # Construct a dictionary 'row' that we will add
                    # to the resulting data frame:
                    #
                    row = {}
                    # First we include some key workspace data to associate
                    # the item with the workspace:
                    row["workspace_type"] = workspace_type
                    row["workspace_id"] = workspace_id
                    row["workspace_name"] = workspace_name
                    row["workspace_description"] = workspace_description
                    row["item_id"] = str(subnode["id"])
                    row["item_type"] = subnode["type"]
                    row["item_name"] = subnode["name"]
                    row["item_description"] = subnode["description"]
                    row["item_path"] = folder_path
                    # Document specific data:
                    row["item_download_name"] = str(subnode["id"]) if subnode["type"] == self.ITEM_TYPE_DOCUMENT else ""
                    row["item_mime_type"] = subnode["mime_type"] if subnode["type"] == self.ITEM_TYPE_DOCUMENT else ""
                    # URL specific data:
                    row["item_url"] = subnode["url"] if subnode["type"] == self.ITEM_TYPE_URL else ""
                    if item_metadata and categories and categories["results"]:
                        # Add columns for workspace node categories have been determined above.
                        self.add_attribute_columns(row=row, categories=categories, prefix="item_cat_")

                    # Now we add the row to the Pandas Data Frame in the Data class:
                    self.logger.info(
                        "Adding %s -> '%s' (%s) to data frame...",
                        "document" if subnode["type"] == self.ITEM_TYPE_DOCUMENT else "URL",
                        row["item_name"],
                        row["item_id"],
                    )
                    with self._data.lock():
                        self._data.append(row)
                case _:
                    self.logger.warning(
                        "Don't know what to do with item -> '%s' (%s) of type -> %s",
                        subnode["name"],
                        subnode["id"],
                        subnode["type"],
                    )

            # Wait for all download threads to complete:
            for thread in download_threads:
                thread.join()

        # Wait for all traversal threads to complete:
        for thread in traversal_threads:
            thread.join()

        return True

    # end method definition

    def feme_embedd_metadata(
        self,
        node_id: int,
        node: dict | None = None,
        crawl: bool = False,
        wait_for_completion: bool = True,
        message_override: dict | None = None,
        timeout: float = 30.0,
        document_metadata: bool = False,
        images: bool = False,
        image_prompt: str = "",
        workspace_metadata: bool = True,
        remove_existing: bool = False,
    ) -> None:
        """Run FEME metadata embedding on provided node for Content Aviator.

        Args:
            node_id (int):
                The Node ID to start embedding for.
            node (dict | None, optional):
                If the caller already has the node data it can be passed with this parameter.
            crawl (bool, optional):
                Defines if the task is a "crawl" (vs. and "index"). Defaults to False (= "index").
            wait_for_completion (bool, optional):
                Defines if the method waits for the completion of the embedding. Defaults to True.
            message_override (dict | None, optional):
                Overwrite specific message details. Defaults to None.
            timeout (float):
                Time in seconds to wait until the WebSocket times out. Defaults to 10.0.
            document_metadata (bool, optional):
                Defines whether or not to embed document metadata.
            images (bool, optional):
                Defines whether or not to embed images.
            image_prompt (str, optional):
                The prompt for the LLM to extract information from images.
                If empty ("") a default prompt will be used.
            workspace_metadata (bool, optional):
                Defines whether or not to embed workspace metadata.
            remove_existing (bool, optional):
                Defines whether or not existing embeddings should be removed.

        """

        async def _inner(
            uri: str,
            node: dict,
            crawl: bool,
            wait_for_completion: bool,
            message_override: dict | None,
            timeout: float,
            document_metadata: bool = False,
            images: bool = False,
            image_prompt: str = "",
            workspace_metadata: bool = True,
            remove_existing: bool = False,
        ) -> None:
            self.logger.debug("Open WebSocket connection to -> %s", uri)
            async with websockets.connect(uri) as websocket:
                # Define if one node (index), or all childs should be processed (crawl)
                task = "crawl" if crawl else "index"

                message = {
                    "task": task,  # either "index" or "crawl". "crawl" means traversing OTCS workspaces and folders.
                    "nodes": [node],  # the list of (root) node IDs to process
                    "documents": document_metadata,  # process metadata of documents
                    "workspaces": workspace_metadata,  # process metadata of workspaces
                    "images": images,  # enable image processing via LLM (Gemini) - just content of images
                    "binaries": False,  # enable processing of document content (TXT, PDF, ...). CSAI does this automatically. Should be False.
                    "upload": not remove_existing,  # add or replace embedding. Should be True except for removal of embeddings.
                    "remove": remove_existing,  # If True remove embedding for the given node. Either "upload" or "remove" must be True (only).
                    "imagePrompt": image_prompt  # Custom image prompt.
                    if image_prompt
                    else "Extract all information from the picture, please.",
                    "maxRelations": 0,  # Crawl related workspaces. 0 = turned off. Otherwise number of related workspaces to process.
                }
                if message_override:
                    message.update(message_override)
                self.logger.debug(
                    "Start FEME on -> %s (%s), type -> %s, crawl -> %s, wait for completion -> %s, workspaces -> %s, documents -> %s, images -> %s",
                    node["name"],
                    node["id"],
                    node["type"],
                    crawl,
                    wait_for_completion,
                    workspace_metadata,
                    document_metadata,
                    images,
                )
                self.logger.debug("Sending WebSocket message -> %s", message)
                await websocket.send(message=json.dumps(message))

                # Continuously listen for messages
                while wait_for_completion:
                    try:
                        response = await asyncio.wait_for(
                            fut=websocket.recv(),
                            timeout=timeout,
                        )
                    except TimeoutError:
                        self.logger.error(
                            "Timeout Error during FEME WebSocket connection, WebSocket did not receive a message in time (%ss)",
                            timeout,
                        )
                        break

                    self.logger.debug("Received WebSocket response -> %s", response)
                    response = json.loads(response)

                    if response.get("name", None) == "processed":
                        self.logger.debug(
                            "FEME processed -> %s (%s), subtype -> %s",
                            response["node"].get("name", ""),
                            response["node"].get("id", ""),
                            response["node"].get("type", ""),
                        )

                    if response.get("name", None) == "done":
                        self.logger.debug(
                            "FEME processed -> %s (%s), subtype -> %s, and received completed message via WebSocket, close connection.",
                            response["nodes"][0].get("name", ""),
                            response["nodes"][0].get("id", ""),
                            response["nodes"][0].get("type", ""),
                        )
                        break

                    if response.get("name", None) == "crawled":
                        self.logger.debug(
                            "Received completed message via WebSocket, close connection. Processed -> %s, Failed -> %s",
                            response["statistics"].get("processed", ""),
                            response["statistics"].get("failed", ""),
                        )
                        break

        # end async def _inner()

        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop=event_loop)

        # Is this method called without the node data?
        # Then we get it with the node_id:
        if not node:
            node = self.get_node(node_id=node_id)
        if not node:
            self.logger.error(
                "Cannot get node with ID -> %s, skipping FEME embedding!",
                node_id,
            )
            return
        try:
            node_data = node["results"]["data"]["properties"]
        except json.JSONDecodeError:
            self.logger.error(
                "Cannot decode data for node with ID -> %s, skipping FEME embedding.",
                node_id,
            )
            return

        uri = self._config["feme_uri"]
        task = _inner(
            uri=uri,
            node=node_data,
            crawl=crawl,
            wait_for_completion=wait_for_completion,
            message_override=message_override,
            timeout=timeout,
            document_metadata=document_metadata,
            images=images,
            image_prompt=image_prompt,
            workspace_metadata=workspace_metadata,
            remove_existing=remove_existing,
        )

        try:
            event_loop.run_until_complete(task)
        except websockets.exceptions.ConnectionClosed:  # :
            self.logger.error("WebSocket connection was closed!")

        except TimeoutError:
            self.logger.error(
                "Timeout error during FEME WebSocket connection, WebSocket did not receive a message in time (%ss)",
                timeout,
            )

        except Exception:
            self.logger.error("Error during FEME WebSocket connection!")

        event_loop.close()

    # end method definition

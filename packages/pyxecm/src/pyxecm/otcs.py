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
import hashlib
import html
import io
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
import warnings
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from functools import cache
from http import HTTPStatus
from importlib.metadata import version
from queue import Empty, LifoQueue, Queue

import requests
import websockets
from opentelemetry import trace

from pyxecm.helper import XML, Data

tracer = trace.get_tracer(__name__)

APP_NAME = "pyxecm"
APP_VERSION = version("pyxecm")
MODULE_NAME = APP_NAME + ".otcs"
OTEL_TRACING_ATTRIBUTES = {"class": "otcs"}

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

REQUEST_TIMEOUT = 60.0
REQUEST_RETRY_DELAY = 30.0
REQUEST_MAX_RETRIES = 4


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
    """Used to automate settings in OpenText Content Management."""

    # Only class variables or class-wide constants should be defined here:

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
    ITEM_TYPE_CATEGORY_FOLDER = 132
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

    CONTAINER_ITEM_TYPES = [
        ITEM_TYPE_FOLDER,
        ITEM_TYPE_BUSINESS_WORKSPACE,
        ITEM_TYPE_COMPOUND_DOCUMENT,
        ITEM_TYPE_CLASSIFICATION,
        ITEM_TYPE_CATEGORY_FOLDER,
        VOLUME_TYPE_ENTERPRISE_WORKSPACE,
        VOLUME_TYPE_CLASSIFICATION_VOLUME,
        VOLUME_TYPE_CONTENT_SERVER_DOCUMENT_TEMPLATES,
        VOLUME_TYPE_CATEGORIES_VOLUME,
    ]

    ITEM_TYPE_LOOKUP = {
        "Business Workspace": ITEM_TYPE_BUSINESS_WORKSPACE,
        "Collection": ITEM_TYPE_COLLECTION,
        "Compound Document": ITEM_TYPE_COMPOUND_DOCUMENT,
        "Category": ITEM_TYPE_CATEGORY,
        "Category Folder": ITEM_TYPE_CATEGORY_FOLDER,
        "Classification": ITEM_TYPE_CLASSIFICATION,
        "Classification Tree": ITEM_TYPE_CLASSIFICATION_TREE,
        "Document": ITEM_TYPE_DOCUMENT,
        "Folder": ITEM_TYPE_FOLDER,
        "Generation": ITEM_TYPE_GENERATION,
        "Project": ITEM_TYPE_PROJECT,
        "Related Workspace": ITEM_TYPE_RELATED_WORKSPACE,
        "Search Query": ITEM_TYPE_SEARCH_QUERY,
        "Shortcut": ITEM_TYPE_SHORTCUT,
        "Task List": ITEM_TYPE_TASK_LIST,
        "Task Group": ITEM_TYPE_TASK_GROUP,
        "Task": ITEM_TYPE_TASK,
        "URL": ITEM_TYPE_URL,
        "Virtual Folder": ITEM_TYPE_VIRTUAL_FOLDER,
        "Wiki": ITEM_TYPE_WIKI,
        "Wiki Page": ITEM_TYPE_WIKI_PAGE,
        "Workflow Map": ITEM_TYPE_WORKFLOW_MAP,
        "Workflow Status": ITEM_TYPE_WORKFLOW_STATUS,
    }

    PERMISSION_TYPES = [
        "see",
        "see_contents",
        "modify",
        "edit_attributes",
        "add_items",
        "reserve",
        "add_major_version",
        "delete_versions",
        "delete",
        "edit_permissions",
    ]
    PERMISSION_ASSIGNEE_TYPES = [
        "owner",
        "group",
        "public",
        "custom",
    ]

    # The maximum length of an item name in OTCS:
    MAX_ITEM_NAME_LENGTH = 248

    # Definitions for the workspace type ontology:
    ONTOLOGY_TEMP_DIRECTORY = "ontology"
    ONTOLOGY_FILE_NAME = "ontology.json"
    ONTOLOGY_NICK_NAME = "ontology"

    @classmethod
    def cleanse_item_name(cls, item_name: str, max_length: int | None = None) -> str:
        """Cleanse the given name of an OTCS item.

        Control for forbidden characters and check the item name length.

        Args:
            item_name (str):
                The item name to cleanse.
            max_length (int, optional):
                A specific maximum length for custom cases.
                If not provided we will use the default OTCS.MAX_ITEM_NAME_LENGTH.

        Returns:
            str:
                The cleansed item name.

        """

        # If no custom max length is given we use the default:
        if max_length is None:
            max_length = OTCS.MAX_ITEM_NAME_LENGTH

        # Item names for sure are not allowed to have ":":
        item_name = item_name.replace(":", "")
        # Item names for sure should not have leading or trailing spaces:
        item_name = item_name.strip()
        # Truncate the item name to 248 characters which is the maximum
        # allowed length in Content Server
        if len(item_name) > max_length:
            item_name = item_name[:max_length]

        return item_name

    # end method definition

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
                    tzinfo=UTC,
                )
            elif " " in date_old:
                old_date = datetime.strptime(date_old, format2).replace(
                    tzinfo=UTC,
                )
            elif "T" in date_old:
                old_date = datetime.strptime(date_old, format3).replace(
                    tzinfo=UTC,
                )
            else:
                old_date = datetime.strptime(date_old, format4).replace(
                    tzinfo=UTC,
                )
        except ValueError:
            return True

        try:
            if "T" in date_new and "Z" in date_new:
                new_date = datetime.strptime(date_new, format1).replace(
                    tzinfo=UTC,
                )
            elif " " in date_new:
                new_date = datetime.strptime(date_new, format2).replace(
                    tzinfo=UTC,
                )
            elif "T" in date_new:
                new_date = datetime.strptime(date_new, format3).replace(
                    tzinfo=UTC,
                )
            else:
                new_date = datetime.strptime(date_new, format4).replace(
                    tzinfo=UTC,
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
        resource_id: str = "",
        default_license: str = "X3",
        otds_ticket: str | None = None,
        otds_token: str | None = None,
        base_path: str = "/cs/cs",
        support_path: str = "/cssupport",
        thread_number: int = 3,
        download_dir: str | None = None,
        feme_uri: str | None = None,
        use_numeric_category_identifier: bool = True,
        workspace_ontology: dict[tuple[str, str, str], list[str]] | None = None,
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
                The name of the OTDS resource for OTCS. Default is "cs".
            resource_id (str, optional):
                The ID of the OTDS resource for OTCS. Default is "".
            default_license (str, optional):
                The name of the default user license. Default is "X3".
            otds_ticket (str, optional):
                The authentication ticket of OTDS.
            otds_token (str, optional):
                The authentication token of OTDS.
            base_path (str, optional):
                The base path segment of the Content Server URL.
                This typically is /cs/cs on a Linux deployment or /cs/cs.exe
                on a Windows deployment.
            support_path (str, optional):
                The support path of the Content Server. This is typically
                /cssupport on a Linux deployment. This is also the default.
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
            workspace_ontology (dict[tuple[str, str, str], list[str]]):
                A dictionary mapping (source_type, target_type, rel_type) tuples
                to a list of semantic relationship names. source_type and target_type
                are workspace type names from OTCS. rel_type is either "parent" or "child".
                It abstracts the graph structure at the type level.
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

        otcs_config["hostname"] = hostname or "otcs-admin-0"
        otcs_config["protocol"] = protocol or "http"
        otcs_config["port"] = port or 8080
        otcs_config["publicUrl"] = public_url
        otcs_config["username"] = username or "admin"
        otcs_config["password"] = password or ""
        otcs_config["partition"] = user_partition or ""
        otcs_config["resource"] = resource_name or ""
        otcs_config["resourceId"] = resource_id or None
        otcs_config["license"] = default_license or ""

        otcs_config["femeUri"] = feme_uri

        otcs_base_url = protocol + "://" + otcs_config["hostname"]
        if str(port) not in ["80", "443"]:
            otcs_base_url += ":{}".format(port)
        otcs_config["baseUrl"] = otcs_base_url
        otcs_support_url = otcs_base_url + support_path
        otcs_config["supportUrl"] = otcs_support_url

        if public_url is None:
            public_url = otcs_base_url

        otcs_public_support_url = public_url + support_path
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
        otcs_config["businessWorkspaceTypesUrl"] = otcs_rest_url + "/v1/businessworkspacetypes"
        otcs_config["businessWorkspaceTypesUrlv2"] = otcs_rest_url + "/v2/businessworkspacetypes"
        otcs_config["businessworkspacecreateform"] = otcs_rest_url + "/v2/forms/businessworkspaces/create"
        otcs_config["businessWorkspacesUrl"] = otcs_rest_url + "/v2/businessworkspaces"
        otcs_config["uniqueNamesUrl"] = otcs_rest_url + "/v2/uniquenames"
        otcs_config["favoritesUrl"] = otcs_rest_url + "/v2/members/favorites"
        otcs_config["reservedNodesUrl"] = otcs_rest_url + "/v2/members/reserved"
        otcs_config["recentlyAccessedUrl"] = otcs_rest_url + "/v2/members/accessed"
        otcs_config["memberofUrl"] = otcs_rest_url + "/v2/members/memberof"
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
        otcs_config["aiUrl"] = otcs_rest_url + "/v2/ai"
        otcs_config["aiNodesUrl"] = otcs_config["aiUrl"] + "/nodes"
        otcs_config["aiChatUrl"] = otcs_config["aiUrl"] + "/chat"
        otcs_config["aiContextUrl"] = otcs_config["aiUrl"] + "/context"
        otcs_config["recycleBinUrl"] = otcs_rest_url + "/v2/volumes/recyclebin"
        otcs_config["processUrl"] = otcs_rest_url + "/v2/processes"
        otcs_config["workflowUrl"] = otcs_rest_url + "/v2/workflows"
        otcs_config["docWorkflowUrl"] = otcs_rest_url + "/v2/docworkflows"
        otcs_config["draftProcessUrl"] = otcs_rest_url + "/v2/draftprocesses"
        otcs_config["categoryFormUrl"] = otcs_rest_url + "/v1/forms/nodes/categories"
        otcs_config["nodesFormUrl"] = otcs_rest_url + "/v1/forms/nodes"
        otcs_config["draftProcessFormUrl"] = otcs_rest_url + "/v1/forms/draftprocesses"
        otcs_config["processTaskUrl"] = otcs_rest_url + "/v1/forms/processes/tasks/update"
        otcs_config["docGenUrl"] = otcs_url + "?func=xecmpfdocgen"
        otcs_config["facetsUrl"] = otcs_rest_url + "/v2/facets"
        otcs_config["facetBrowseUrl"] = otcs_rest_url + "/v3/app/container"

        self._config = otcs_config
        self._otcs_ticket = None  # will be set by authenticate()
        self._otds_ticket = otds_ticket
        self._otds_token = otds_token
        self._data = Data(logger=self.logger)
        self._thread_number = thread_number
        self._download_dir = download_dir
        self._semaphore = threading.BoundedSemaphore(value=thread_number)
        self._last_session_renewal = 0
        self._use_numeric_category_identifier: bool = use_numeric_category_identifier
        self._executor = ThreadPoolExecutor(max_workers=thread_number)
        self._workspace_type_lookup: dict = {}
        self._workspace_type_names = []
        self._workspace_ontology = workspace_ontology

        # Handle concurrent HTTP requests that may run into 401 errors and
        # re-authentication at the same time:
        self._authentication_lock = threading.Lock()
        self._authentication_condition = threading.Condition(self._authentication_lock)
        self._authentication_semaphore = threading.Semaphore(
            1,
        )  # only 1 thread should handle the re-authentication
        self._session_lock = threading.Lock()

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

    def otcs_ticket_hashed(self) -> str | None:
        """Return the hashed OTCS ticket.

        Returns:
            str | None:
                The hashed OTCS ticket (which may be None).

        """

        if not self._otcs_ticket:
            return None

        # Encode the input string before hashing
        encoded_string = self._otcs_ticket.encode("utf-8")

        # Create a new SHA-512 hash object
        sha512 = hashlib.sha512()

        # Update the hash object with the input string
        sha512.update(encoded_string)

        # Get the hexadecimal representation of the hash
        hashed_output = sha512.hexdigest()

        return hashed_output

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

    def set_otds_token(self, token: str) -> None:
        """Set the OTDS token.

        Args:
            token (str):
                The new OTDS token.

        """

        self._otds_token = token

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
                The (login) name of the user. Defaults to "admin".
            password (str, optional):
                The password of the user. Defaults to "".

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

    def partition_name(self) -> str:
        """Return the OTDS user partition for Content Server.

        Returns:
            str:
                The Content Server OTDS user partition.

        """

        return self.config()["partition"]

    # end method definition

    def resource_name(self) -> str:
        """Return the OTDS resource name of Content Server.

        Returns:
            str:
                The Content Server OTDS resource name.

        """

        return self.config()["resource"]

    # end method definition

    def resource_id(self) -> str:
        """Return the OTDS resource ID of Content Server.

        Returns:
            str:
                The Content Server OTDS resource ID.

        """

        return self.config()["resourceId"]

    # end method definition

    def set_resource_id(self, resource_id: str) -> None:
        """Set the OTDS resource ID of Content Server.

        Args:
            resource_id (str):
                The Content Server OTDS resource ID.

        """

        self.config()["resourceId"] = resource_id

    # end method definition

    def get_data(self) -> Data:
        """Get the Data object that holds all loaded Content Server items (see method load_items()).

        Returns:
            Data:
                The data object with all processed Content Server items.

        """

        return self._data

    # end method definition

    def clear_data(self) -> Data:
        """Reset the data object to an empty data frame.

        Returns:
            Data:
                Newly initialized data object.

        """

        self._data = Data(logger=self.logger)

        return self._data

    # end method definition

    def lookup_workspace_type_name(self, workspace_type_id: int) -> str | None:
        """Lookup the workspace type name based on the workspace type ID.

        This structure is built up during traversal. Using it in other contexts
        may find it uninitialized.

        Args:
            workspace_type_id (int):
                The ID of the workspace type.

        Returns:
            str | None:
                The name of the workspace type.

        """

        if not self._workspace_type_lookup or workspace_type_id not in self._workspace_type_lookup:
            return None

        return self._workspace_type_lookup.get(workspace_type_id)["name"]

    # end method definition

    def get_workspace_ontology(self, force_reload: bool = False) -> dict[tuple[str, str, str], list[str]] | None:
        """Get the relationship model for workspace types (ontology).

        TODO: currently we cannot derive it from the workspace type definitions
        as this information is not managed in OTCS - this will change with 26.2.

        Returns:
            dict[tuple[str, str, str], list[str]] | None:
                Workspace ontology or None in case it is not provided via
                the class __init__ method or not found as a JSON file in admin
                Personal Workspace.

        """

        if force_reload:
            self.load_workspace_ontology()
            return self._workspace_ontology

        # If the ontology is not yet initialized, we try to load
        # it from a JSON file in the perosnal workspace of the admin user:
        if self._workspace_ontology or self.load_workspace_ontology():
            return self._workspace_ontology

        return None

    # end method definition

    def save_workspace_ontology(self) -> bool:
        """Save the workspace ontology as JSON file into Admin's personal workspace.

        Returns:
            bool:
                True = Success
                False = Failure

        """

        if not self._workspace_ontology:
            self.logger.error("The workspace ontology is empty! Cannot save it.")
            return False

        #
        # 1. Dump the ontology data structure into a file in local file system:
        #
        download_dir = os.path.join(tempfile.gettempdir(), self.ONTOLOGY_TEMP_DIRECTORY)
        file_path = os.path.join(download_dir, self.ONTOLOGY_FILE_NAME)
        with open(file_path, "w", encoding="utf-8") as ontology_file:
            json.dump(self._workspace_ontology, ontology_file, indent=2)
            self.logger.info(
                "Workspace ontology -> '%s' has been saved to JSON file -> %s", self.ONTOLOGY_FILE_NAME, file_path
            )

        #
        # 2. Upload the local ontology JSON file to the admin workspace:
        #
        response = self._otcs.get_node_by_volume_and_path(
            volume_type=self._otcs.VOLUME_TYPE_PERSONAL_WORKSPACE,
        )  # write to Personal Workspace of Admin (with Volume Type ID = 142)
        target_folder_id = self._otcs.get_result_value(response=response, key="id")
        if not target_folder_id:
            target_folder_id = 2004  # use Personal Workspace of Admin as fallback

        # Check if the ontology file has been uploaded before.
        # This can happen if we re-run the OTCS pod or having multiple pods.
        # In this case we add a version to the existing document:
        response = self._otcs.get_node_by_parent_and_name(
            parent_id=int(target_folder_id),
            name=self.ONTOLOGY_FILE_NAME,
            show_error=False,
        )
        target_document_id = self._otcs.get_result_value(response=response, key="id")
        if target_document_id:
            response = self._otcs.add_document_version(
                node_id=int(target_document_id),
                file_url=file_path,
                file_name=self.ONTOLOGY_FILE_NAME,
                mime_type="application/json",
                description="Updated ontology file -> '{}' in admin workspace.".format(self.ONTOLOGY_FILE_NAME),
            )
        else:
            response = self._otcs.upload_file_to_parent(
                file_url=file_path,
                file_name=self.ONTOLOGY_FILE_NAME,
                mime_type="application/json",
                parent_id=int(target_folder_id),
                description="Workspace type ontology. Shows relationships between different workspace types in the system.",
            )

        if response:
            self.logger.info(
                "Ontology file -> '%s' has been written to Personal Workspace of admin user.",
                self.ONTOLOGY_FILE_NAME,
            )
            return True

        self.logger.error(
            "Failed to write ontology file -> '%s' to Personal Workspace of admin user!",
            self.ONTOLOGY_FILE_NAME,
        )

        return False

    # end method definition

    def load_workspace_ontology(self) -> bool:
        """Load the workspace ontology from a JSON file in the Admin personal workspace.

        Returns:
            bool:
                True = Success
                False = Failure

        """

        # First, try to find the ontology file via a nickname. If not found fall back
        # top a file in the Admin personal workspaces. If still not found return False:
        response = self.get_node_from_nickname(nickname=self.ONTOLOGY_NICK_NAME)
        if not response:
            # If the file with the ontology nickname is not found we
            # try to find the file in the Personal Workspace of the current user.
            response = self.get_node_by_volume_and_path(
                volume_type=self.VOLUME_TYPE_PERSONAL_WORKSPACE,
            )  # write to Personal Workspace of Admin (with Volume Type ID = 142)
            folder_id = self.get_result_value(response=response, key="id")
            if not folder_id:
                folder_id = 2004  # use Personal Workspace of Admin as fallback

            # Check if the ontology file is in the Personal Workspace of the admin user.
            response = self.get_node_by_parent_and_name(
                parent_id=int(folder_id),
                name=self.ONTOLOGY_FILE_NAME,
                show_error=False,
            )
        document_id = self.get_result_value(response=response, key="id")
        if not document_id:
            self.logger.warning("Ontology file not found - cannot load the ontology.")
            return False

        json_content = self.get_json_document(node_id=int(document_id))
        if not json_content:
            self.logger.error(
                "Cannot load ontology from JSON document -> %s (%s)", self.ONTOLOGY_FILE_NAME, document_id
            )
            return False

        try:
            self._workspace_ontology = json.loads(json_content)
        except json.JSONDecodeError as json_error:
            self.logger.error(
                "Invalid JSON input in document -> %s (%s); error -> %s",
                self.ONTOLOGY_FILE_NAME,
                document_id,
                json_error,
            )
            return False

        self.logger.info(
            "Ontology file -> '%s' has been loaded from document with ID -> %s.", self.ONTOLOGY_FILE_NAME, document_id
        )
        return True

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
        parse_error_response: bool = False,
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
            parse_error_response (bool, optional):
                Whether the error response text should be interpreted as JSON and loaded. Defaults to False.

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
                    if not self.cookie():
                        self.logger.error("Cannot call -> %s - user is not authenticatd!", url)
                        return None
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
                        # There are cases where OTCS returns response.ok (200) but
                        # because of restart or scaling of pods the response text is not
                        # valid JSON. So parse_request_response() may raise an ConnectionError exception that
                        # is handled in the exception block below (with waiting for readiness and retry logic)
                        parsed_response = self.parse_request_response(response_object=response)
                        return parsed_response
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
                    if parse_error_response:
                        return self.parse_error_response(response_object=response)
                    elif parse_request_response:
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
                    if parse_error_response:
                        return self.parse_error_response(response_object=response)
                    else:
                        return None
            # end try:
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
            # end except Timeout
            except requests.exceptions.ConnectionError as connection_error:
                if retries <= max_retries:
                    self.logger.warning(
                        "Cannot connect to OTCS at -> %s; error -> %s! Retrying in %d seconds... %d/%d",
                        url,
                        str(connection_error),
                        REQUEST_RETRY_DELAY,
                        retries,
                        max_retries,
                    )
                    retries += 1

                    # The connection error could have been caused by a restart of the OTCS pod or services.
                    # So we better check if OTCS is ready to receive requests again before retrying:
                    while not self.is_ready():
                        self.logger.warning(
                            "Content Server is not ready to receive requests. Waiting for state change in %d seconds...",
                            REQUEST_RETRY_DELAY,
                        )
                        time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying

                else:
                    self.logger.error(
                        "%s; connection error -> %s",
                        failure_message,
                        str(connection_error),
                    )
                    if retry_forever:
                        # If it fails after REQUEST_MAX_RETRIES retries
                        # we let it wait forever:
                        self.logger.warning("Turn timeouts off and wait forever...")
                        timeout = None
                        time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                    else:
                        return None
            # end except connection error
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
            show_error (bool, optional):
                If True, logs an error / raises an exception. If False, logs a warning.

        Returns:
            dict | None:
                Parsed response as a dictionary, or None in case of an error.

        Raises:
            requests.exceptions.ConnectionError:
                If the response cannot be decoded as JSON.

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
                # Raise ConnectionError instead of returning None
                raise requests.exceptions.ConnectionError(message) from exception
            self.logger.warning(message)
            return None
        # end try-except block

        return dict_object

    # end method definition

    def parse_error_response(
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
            show_error (bool, optional):
                If True, logs an error / raises an exception. If False, logs a warning.

        Returns:
            dict | None:
                Parsed response as a dictionary, or None in case of an error.

        Raises:
            requests.exceptions.ConnectionError:
                If the response cannot be decoded as JSON.

        """

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
                # Raise ConnectionError instead of returning None
                raise requests.exceptions.ConnectionError(message) from exception
            self.logger.warning(message)
            return None
        # end try-except block

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

        if not response or "results" not in response:
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
            bool:
                True if the value was found, False otherwise

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
        response: dict | None,
        key: str,
        index: int = 0,
        property_name: str = "properties",
        show_error: bool = True,
    ) -> str | None:
        """Read an item value from the REST API response.

        This method handles the most common response structures delivered by the
        V2 REST API of OTCS. For more details, refer to the documentation at
        developer.opentext.com.

        Args:
            response (dict | None):
                REST API response object. None is also handled.
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
            str | None:
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
                properties = data.get(property_name)
            elif isinstance(data, list):
                # data is a list - this has typically just one item, so we use 0 as index
                properties = data[0].get(property_name)
            else:
                self.logger.error(
                    "Data needs to be a list or dict but it is -> %s",
                    str(type(data)),
                )
                return None
            if not properties:
                self.logger.error(
                    "No properties found in data -> %s",
                    str(data),
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
        """Read all values with a given key from the REST API response.

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

    def get_result_values_iterator(
        self,
        response: dict,
        property_name: str = "properties",
        data_name: str = "data",
    ) -> iter:
        """Get an iterator object that can be used to traverse through OTCS responses.

        This method handles the most common response structures delivered by the
        V2 REST API of Extended ECM. For more details, refer to the documentation at
        developer.opentext.com.

        Args:
            response (dict):
                REST API response object.
            property_name (str, optional):
                Name of the sub-dictionary holding the actual values.
                Defaults to "properties".
            data_name (str, optional):
                Name of the sub-dictionary holding the data.
                Defaults to "data".

        Returns:
            iter:
                Iterator object for iterating through the values.

        """

        # First do some sanity checks:
        if not response or "results" not in response:
            return

        # It is important to use (...) and not [...] here to create a generator
        # that yields the values one by one. This is more memory efficient
        # than creating a list with all values at once.
        # This is especially important for large result sets.
        yield from (
            item[data_name][property_name] if property_name else item[data_name]
            for item in response["results"]
            if isinstance(item.get(data_name), dict) and (not property_name or property_name in item[data_name])
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="is_configured")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="is_ready")
    def is_ready(self) -> bool:
        """Check if the Content Server pod is ready to receive requests.

        Args:
            None.

        Returns:
            bool: True if pod is ready. False if pod is not yet ready.

        """

        request_url = self.config()["isReady"]  # /v1/ping endpoint

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

        parsed_response = self.parse_request_response(response_object=response, show_error=False)
        if not parsed_response:
            self.logger.debug("Able to connect to -> %s with status 200 but OTCS returns corrupt data. Not ready yet.")
            return False

        return True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="invalidate_authentication_ticket")
    def invalidate_authentication_ticket(self) -> None:
        """If a 401 HTTP error occurs we may want to invalidate the login ticket."""

        self._otcs_ticket = None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="otcs_authenticate")
    def authenticate(
        self,
        revalidate: bool = False,
        wait_for_ready: bool = True,
    ) -> dict | None:
        """Authenticate with Content Server and retrieves an OTCS ticket.

        This method supports 3 ways of authentication (in this order):
        1. OTDS TOKEN (if available)
        2. OTDS TICKET (if available)
        3. USERNAME + PASSWORD

        The OTDS token, OTDS ticket or username + password must be available
        in the OTCS object variables (provided in the init method of OTCS)
        for authentication to succeed.

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

        # Extend the OTEL tracing span with attributes for this method call
        current_span = trace.get_current_span()
        current_span.set_attribute("revalidate", revalidate)
        current_span.set_attribute("wait_for_ready", wait_for_ready)

        # Already authenticated and session still valid?
        if self._otcs_ticket and not revalidate:
            self.logger.debug(
                "Session still valid - return existing cookie -> %s",
                str(self.cookie()),
            )
            return self.cookie()

        if wait_for_ready:
            while not self.is_ready():
                self.logger.debug(
                    "OTCS is not ready to receive requests yet. Cannot authenticate. Waiting 30 seconds...",
                )
                time.sleep(30)

        request_url = self.config()["authenticationUrl"]

        # We try 3 ways of authentication (in this order):
        # 1. OTDS TOKEN (if available)
        # 2. OTDS TICKET (if available)
        # 3. USERNAME + PASSWORD

        if (
            not self._otds_token
            and not self._otds_ticket
            and (not self.config()["username"] or not self.config()["password"])
        ):
            self.logger.error(
                "No OTDS token, OTDS ticket or username/password available for authentication! Cannot authenticate with OTCS.",
            )
            return None

        self.logger.debug("Authenticating with OTCS at -> %s", request_url)
        self.logger.debug(
            "Using %s for authentication at OTCS...",
            "OTDS token" if self._otds_token else "OTDS ticket" if self._otds_ticket else "username/password",
        )

        # Initialize the ticket to not set:
        otcs_ticket = None

        # Try with OTDS TOKEN first (if available):
        if self._otds_token:  #  and not revalidate:
            self.logger.debug(
                "Requesting OTCS ticket with existing OTDS token; calling -> %s",
                request_url,
            )
            # Add the OTDS token to the request headers:
            request_header = REQUEST_FORM_HEADERS | {"Authorization": f"Bearer {self._otds_token}"}

            try:
                response = requests.get(
                    url=request_url,
                    headers=request_header,
                    timeout=REQUEST_TIMEOUT,
                )
                if response.ok:
                    # read the ticket from the response header:
                    otcs_ticket = response.headers.get("OTCSTicket")
                else:
                    self.logger.warning(
                        "Failed to request OTCS ticket with OTDS token; status -> %s; error -> %s",
                        response.status_code,
                        response.text,
                    )

            except requests.exceptions.RequestException as exception:
                self.logger.warning(
                    "Unable to connect to -> %s; error -> %s",
                    request_url,
                    str(exception),
                )
                return None
        # end if self._otds_token

        # Alternatively try with OTDS TICKET (if available):
        if not otcs_ticket and self._otds_ticket:  # and not revalidate:
            self.logger.debug(
                "Requesting OTCS ticket with existing OTDS ticket; calling -> %s",
                request_url,
            )
            # Add the OTDS ticket to the request headers:
            request_header = REQUEST_FORM_HEADERS | {"OTDSTicket": self._otds_ticket}

            try:
                response = requests.get(
                    url=request_url,
                    headers=request_header,
                    timeout=REQUEST_TIMEOUT,
                )
                if response.ok:
                    # read the ticket from the response header:
                    otcs_ticket = response.headers.get("OTCSTicket")
                else:
                    self.logger.warning(
                        "Failed to request OTCS ticket with OTDS ticket; status -> %s; error -> %s",
                        response.status_code,
                        response.text,
                    )

            except requests.exceptions.RequestException as exception:
                self.logger.warning(
                    "Unable to connect to -> %s; error -> %s",
                    request_url,
                    str(exception),
                )
                return None
        # end if self._otds_ticket

        # Check if previous authentication was not successful.
        # Then we try the normal username + password authentication:
        if not otcs_ticket:
            if not self.config()["username"] or not self.config()["password"]:
                # Check if basic authentication is just the "fallback" for
                # a failed OTDS based authentication (ticket or token) above:
                if self._otds_ticket or self._otds_token:
                    self.logger.warning(
                        "Cannot fallback to basic authentication at OTCS after OTDS based authentication failed as no username or password are provided."
                    )
                else:
                    self.logger.error("Missing username or password for authentication! Cannot authenticate at OTCS.")
                return None

            self.logger.debug(
                "Requesting OTCS ticket with username -> '%s' and password; calling -> %s",
                self.config()["username"],
                request_url,
            )

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
        # end if not otcs_ticket

        # Store authentication ticket:
        self._otcs_ticket = otcs_ticket

        self.logger.debug("Cookie after authentication -> %s", str(self.cookie()))

        return self.cookie()

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="reauthenticate")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_server_info")
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
        request_header = self.request_form_header()

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_server_version")
    @cache
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="apply_config")
    def apply_config(self, xml_file_path: str) -> dict | None:
        """Apply Content Server administration settings from XML file.

        Args:
            xml_file_path (str):
                The fully qualified path to the XML settings file.

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
                success_message="Admin settings in file -> '{}' have been applied.".format(
                    xml_file_path,
                ),
                failure_message="Failed to import settings file -> '{}'".format(
                    xml_file_path,
                ),
            )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_users")
    def get_users(
        self,
        where_type: int = 0,
        where_name: str | None = None,
        where_first_name: str | None = None,
        where_last_name: str | None = None,
        where_business_email: str | None = None,
        query_string: str | None = None,
        sort: str | None = None,
        limit: int = 20,
        page: int = 1,
        show_error: bool = False,
    ) -> dict | None:
        """Get a Content Server users based on different criterias.

        The criterias can be combined.

        Args:
            where_type (int, optional):
                Type ID of user:
                0 - Regular User
                17 - Service User
                Defaults to 0 -> (Regular User)
            where_name (str | None, optional):
                Name of the user (login).
            where_first_name (str | None, optional):
                First name of the user.
            where_last_name (str | None, optional):
                Last name of the user.
            where_business_email (str | None, optional):
                Business email address of the user.
            query_string (str | None, optional):
                Filters the results, returning the users with the specified query string
                in any of the following fields: log-in name, first name, last name, email address,
                and groups with the specified query string in the group name.
                NOTE: query cannot be used together with any combination of: where_name,
                where_first_name, where_last_name, where_business_email.
                The query value will be used to perform a search within the log-in name,
                first name, last name and email address properties for users and group name
                for groups to see if that value is contained within any of those properties.
                This differs from the user search that is performed in Classic UI where it
                searches for a specific property that begins with the value provided by the user.
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Format can be sort = id, sort = name, sort = first_name, sort = last_name,
                sort = group_id, sort = mailaddress. If the prefix of asc or desc is not used
                then asc will be assumed.
                Default is None.
            limit (int, optional):
                The maximum number of results per page (internal default is 10). OTCS does
                not allow values > 20 so this method adjusts values > 20 to 20.
            page (int, optional):
                The page number to retrieve.
            show_error (bool, optional):
                If True, treat as an error if the user is not found. Defaults to False.

        Returns:
            dict | None:
                User information as a dictionary, or None if the user could not be found
                (e.g., because it doesn't exist).

        Example:
            ```json
            {
                'collection': {
                    'paging': {
                        'limit': 10,
                        'page': 1,
                        'page_total': 1,
                        'range_max': 1,
                        'range_min': 1,
                        'total_count': 1
                    },
                    'sorting': {
                        'sort': [
                            {
                                'key': 'sort',
                                'value': 'asc_id'
                            }
                        ]
                    }
                },
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/members?where_first_name=Peter',
                            'method': 'GET',
                            'name': ''
                        }
                    }
                },
                'results': [
                    {
                        'data': {
                            'properties': {
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
                                'office_location': None,
                                'pager': None,
                                'personal_email': None,
                                'photo_id': 13981,
                                'photo_url': 'api/v1/members/8123/photo?v=13981.1',
                                'privilege_content_manager': False,
                                'privilege_grant_discovery': False,
                                'privilege_login': True,
                                'privilege_modify_groups': False,
                                'privilege_modify_users': False,
                                'privilege_public_access': True,
                                'privilege_system_admin_rights': False,
                                'privilege_user_admin_rights': False,
                                'time_zone': -1,
                                'title': 'Maintenance Planner',
                                'type': 0,
                                'type_name': 'User'
                            }
                        }
                    }
                ]
            }
            ```

            To access the (login) name of the first user found, use
            `["results"][0]["data"]["properties"]["name"]`.
            Alternatively, use the method `get_result_value(response, "name", 0)`.

        """

        # Add query parameters (embedded in the URL)
        # Using type = 0 for OTCS groups or type = 17 for service user:
        query = {}
        filter_string = " type -> 'service user'" if where_type == 17 else ""
        query["where_type"] = where_type
        if where_name:
            query["where_name"] = where_name
            filter_string += " login name -> '{}'".format(where_name) if where_name else ""
        if where_first_name:
            query["where_first_name"] = where_first_name
            filter_string += " first name -> '{}'".format(where_first_name) if where_first_name else ""
        if where_last_name:
            query["where_last_name"] = where_last_name
            filter_string += " last name -> '{}'".format(where_last_name) if where_last_name else ""
        if where_business_email:
            query["where_business_email"] = where_business_email
            filter_string += " business email -> '{}'".format(where_business_email) if where_business_email else ""
        if query_string:
            query["query"] = query_string
            filter_string += " query -> '{}'".format(query_string) if where_business_email else ""
        if sort:
            query["sort"] = sort
        if limit:
            if limit > 20:
                self.logger.warning(
                    "Page limit for user query cannot be larger than 20. Adjusting from %d to 20.", limit
                )
                limit = 20
            query["limit"] = limit
        if page:
            query["page"] = page
        encoded_query = urllib.parse.urlencode(query=query, doseq=True)
        request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get users%s; calling -> %s",
            " with{}".format(filter_string) if filter_string else "",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get users{}".format(" with{}".format(filter_string) if filter_string else ""),
            warning_message="Couldn't find users{}".format(" with{}".format(filter_string) if filter_string else ""),
            show_error=show_error,
        )

    # end method definition

    def get_users_iterator(
        self,
        where_type: int = 0,
        where_name: str | None = None,
        where_first_name: str | None = None,
        where_last_name: str | None = None,
        where_business_email: str | None = None,
        query_string: str | None = None,
        sort: str | None = None,
        limit: int = 20,
    ) -> iter:
        """Get an iterator object that can be used to traverse OTCS users.

        Filters can be applied that are given by the "where" and "query" parameters.

        Using a generator avoids loading a large users into memory at once.
        Instead you can iterate over the potential large list of users.

        Example usage:
            ```python
            users = otcs_object.get_users_iterator(where_type=0, limit=10)
            for user in users:
                logger.info(
                    "Traversing user -> '%s' (%s)",
                    otcs_object.get_result_value(response=user, key="name"),
                    otcs_object.get_result_value(response=user, key="id"),
                )
            ```

        Args:
            where_type (int, optional):
                Type ID of user:
                0 - Regular User
                17 - Service User
                Defaults to 0 -> (Regular User)
            where_name (str | None, optional):
                Name of the user (login).
            where_first_name (str | None, optional):
                First name of the user.
            where_last_name (str | None, optional):
                Last name of the user.
            where_business_email (str | None, optional):
                Business email address of the user.
            query_string (str | None, optional):
                Filters the results, returning the users with the specified query string
                in any of the following fields: log-in name, first name, last name, email address,
                and groups with the specified query string in the group name.
                NOTE: query cannot be used together with any combination of: where_name,
                where_first_name, where_last_name, where_business_email.
                The query value will be used to perform a search within the log-in name,
                first name, last name and email address properties for users and group name
                for groups to see if that value is contained within any of those properties.
                This differs from the user search that is performed in Classic UI where it
                searches for a specific property that begins with the value provided by the user.
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Format can be sort = id, sort = name, sort = first_name, sort = last_name,
                sort = group_id, sort = mailaddress. If the prefix of asc or desc is not used
                then asc will be assumed.
                Default is None.
            limit (int, optional):
                The maximum number of results per page (internal default is 10). OTCS does
                not allow values > 20 so this method adjusts values > 20 to 20.

        Returns:
            iter:
                A generator yielding one user per iteration.
                If the REST API fails, returns no value.

        """

        # First we probe how many members we have:
        response = self.get_users(
            where_type=where_type,
            where_name=where_name,
            where_first_name=where_first_name,
            where_last_name=where_last_name,
            where_business_email=where_business_email,
            query_string=query_string,
            limit=1,
            page=1,
        )
        if not response or "results" not in response:
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        number_of_users = response["collection"]["paging"]["total_count"]
        if not number_of_users:
            self.logger.debug(
                "No users found! Cannot iterate over users.",
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        # If the group has many members we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (number_of_users + limit - 1) // limit

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.get_users(
                where_type=where_type,
                where_name=where_name,
                where_first_name=where_first_name,
                where_last_name=where_last_name,
                where_business_email=where_business_email,
                query_string=query_string,
                sort=sort,
                limit=limit,
                page=page,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve users (page -> %d)",
                    page,
                )
                return

            # Yield nodes one at a time:
            yield from response["results"]

        # end for page in range(1, total_pages + 1)

    # end method definition

    @cache
    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_user")
    def get_user(
        self, name: str | None = None, user_id: int | None = None, user_type: int = 0, show_error: bool = False
    ) -> dict | None:
        """Get a Content Server user based on the login name and type.

        Args:
            name (str | None, optional):
                Name of the user (login). If empty or None, this parameter is ignored and
                the 'user_id' parameter is used to retrieve the user.
            user_id (int | None, optional):
                ID of the user to retrieve. If provided, this parameter takes precedence
                over the 'name' parameter.
            user_type (int, optional):
                Type ID of user:
                0 - Regular User
                17 - Service User
                Defaults to 0 -> (Regular User)

            show_error (bool, optional):
                If True, treat as an error if the user is not found. Defaults to False.

        Returns:
            dict | None:
                User information as a dictionary, or None if the user could not be found
                (e.g., because it doesn't exist).

        Example:
            ```json
            {
                'collection': {
                    'paging': {
                        'limit': 10,
                        'page': 1,
                        'page_total': 1,
                        'range_max': 1,
                        'range_min': 1,
                        'total_count': 1
                    },
                    'sorting': {
                        'sort': [
                            {
                                'key': 'sort',
                                'value': 'asc_id'
                            }
                        ]
                    }
                },
                'links': {
                    'data': {
                        'self': {
                            'body': '',
                            'content_type': '',
                            'href': '/api/v2/members?where_first_name=Peter',
                            'method': 'GET',
                            'name': ''
                        }
                    }
                },
                'results': [
                    {
                        'data': {
                            'properties': {
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
                                'office_location': None,
                                'pager': None,
                                'personal_email': None,
                                'photo_id': 13981,
                                'photo_url': 'api/v1/members/8123/photo?v=13981.1',
                                'privilege_content_manager': False,
                                'privilege_grant_discovery': False,
                                'privilege_login': True,
                                'privilege_modify_groups': False,
                                'privilege_modify_users': False,
                                'privilege_public_access': True,
                                'privilege_system_admin_rights': False,
                                'privilege_user_admin_rights': False,
                                'time_zone': -1,
                                'title': 'Maintenance Planner',
                                'type': 0,
                                'type_name': 'User'
                            }
                        }
                    }
                ]
            }
            ```

            To access the (login) name of the first user found, use
            `["results"][0]["data"]["properties"]["name"]`.
            Alternatively, use the method `get_result_value(response, "name", 0)`.

        """

        if user_id is None and name is None:
            self.logger.error("No user name or ID provided. Cannot find user!")
            return None

        if user_id is None:
            # Add query parameters (embedded in the URL)
            # Using type = 0 for OTCS groups or type = 17 for service user:
            query = {"where_type": user_type, "where_name": name}
            encoded_query = urllib.parse.urlencode(query=query, doseq=True)
            request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)
        else:
            request_url = self.config()["membersUrlv2"] + "/" + str(user_id)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get user with %s%s; calling -> %s",
            "login name -> '{}'".format(name) if name is not None else "user ID -> '{}'".format(user_id),
            ", type -> 'service user'" if user_type == 17 else "",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get user with {} and type -> {}".format(
                "login name -> '{}'".format(name) if name is not None else "user ID -> {}".format(user_id),
                user_type,
            ),
            warning_message="Couldn't find user with {} and type -> {}".format(
                "login name -> '{}'".format(name) if name is not None else "user ID -> {}".format(user_id),
                user_type,
            ),
            show_error=show_error,
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="search_user")
    def search_user(
        self,
        value: str,
        field: str = "where_name",
        fields: dict | None = None,
        query_string: str | None = None,
        limit: int = 20,
        page: int = 1,
    ) -> dict | None:
        """Find a user based on search criteria.

        This method is just a wrapper for get_users() for more simple use cases.
        We mainly keep it for backwards compatibility.

        Args:
            value (str):
                Field value to search for.
            field (str):
                User field to search with (e.g. "where_type", "where_name",
                "where_first_name", "where_last_name", "where_business_email", "query").
            fields (dict | None, optional):
                If multiple fields should be combined provide them with this dict. E.g.:
                {
                    "where_first_name": "Peter",
                    "where_last_name": "Parker",
                    "where_business_email": "abc@example.com"
                }
            query_string (str | None, optional):
                If you want to search for a query string in the user properties,
                use the "query" field. This will search for the query string in the
                log-in name, first name, last name, and email address properties for users,
                and group name for groups to see if that value is contained within any of those properties.
                NOTE: query cannot be used together with any combination of: where_name, where_first_name,
                where_last_name, where_business_email.
            limit (int, optional):
                The maximum number of results per page (internal default is 10). OTCS does
                not allow values > 20 so this method adjusts values > 20 to 20.
            page (int, optional):
                The page number to retrieve.

        Returns:
            dict | None:
                User information as a dictionary, or None if the user could not be found
                (e.g., because it doesn't exist).

        """

        return self.get_users(
            where_type=0,  # Regular User
            where_name=value
            if field == "where_name"
            else fields.get("where_name")
            if fields
            else fields.get("where_name") or None,
            where_first_name=value
            if field == "where_first_name"
            else fields.get("where_first_name")
            if fields
            else None,
            where_last_name=value if field == "where_last_name" else fields.get("where_last_name") if fields else None,
            where_business_email=value
            if field == "where_business_email"
            else fields.get("where_business_email")
            if fields
            else None,
            query_string=query_string,
            sort=None,
            limit=limit,
            page=page,
            show_error=False,
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_current_user")
    def get_current_user(self) -> dict | None:
        """Get the current authenticated user.

        Returns:
            dict | None:
                Information for the current (authenticated) user.

        """

        request_url = self.config()["authenticationUrl"]

        request_header = self.request_form_header()

        self.logger.debug(
            "Get current user; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get current user",
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_user")
    def add_user(
        self,
        name: str,
        password: str,
        first_name: str,
        last_name: str,
        email: str,
        title: str,
        base_group: int,
        phone: str = "",
        privileges: list | None = None,
        user_type: int = 0,
    ) -> dict | None:
        """Add Content Server user.

        Args:
            name (str):
                The login name of the user.
            password (str):
                The password of the user.
            first_name (str):
                The first name of the user.
            last_name (str):
                The last name of the user.
            email (str):
                The email address of the user.
            title (str):
                The title of the user.
            base_group (int):
                The base group id of the user (e.g. department)
            phone (str, optional):
                The business phone number of the user.
            privileges (list | None, optional):
                Possible values are Login, Public Access, Content Manager,
                Modify Users, Modify Groups, User Admin Rights,
                Grant Discovery, System Admin Rights
            user_type (int, optional):
                The ID of the user type. 0 = regular user, 17 = service user.

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
            "business_phone": phone,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_user")
    def update_user(self, user_id: int, field: str, value: str) -> dict | None:
        """Update a defined field for a user.

        Args:
            user_id (int):
                The ID of the user to update.
            field (str):
                The user data field to update.
            value (str):
                The new value for user data field.

        Returns:
            dict | None:
                User information or None if the user couldn't be updated (e.g. because it doesn't exist).

        """

        user_put_body = {field: value}

        request_url = self.config()["membersUrlv2"] + "/" + str(user_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Updating user with ID -> %d, field -> %s, value -> %s; calling -> %s",
            user_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_user_profile")
    def get_user_profile(self) -> dict | None:
        """Get the user profile.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_user_profile")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_user_photo")
    def get_user_photo(self, user_id: int) -> dict | None:
        """Get the profile photo of a user.

        Args:
            user_id (int):
                The ID of the user.

        Returns:
            dict | None:
                Node information or None if photo node is not found.

        """

        request_url = self.config()["membersUrl"] + "/" + str(user_id) + "/photo"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get photo of user ID -> %d; calling -> %s",
            user_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get photo of user with ID -> {}".format(user_id),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_user_photo")
    def update_user_photo(self, user_id: int, photo_id: int) -> dict | None:
        """Update a user with a profile photo (which must be an existing node).

        Args:
            user_id (int):
                The ID of the user.
            photo_id (int):
                The node ID of the photo.

        Returns:
            dict | None:
                Node information or None if photo node is not found.

        """

        update_user_put_body = {"photo_id": photo_id}

        request_url = self.config()["membersUrl"] + "/" + str(user_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Update user ID -> %d with photo ID -> %d; calling -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="is_proxy")
    def is_proxy(self, user_name: str) -> bool:
        """Check if a user is defined as proxy of the current user.

        This method differentiates between the old (xGov) based
        implementation and the new Extended ECM platform one
        that was introduced with version 23.4.

        Args:
            user_name (str):
                The user to test (login name) for proxy.

        Returns:
            bool:
                True is user is proxy of current user. False if not.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_user_proxies")
    def get_user_proxies(self, use_v2: bool = False) -> dict | None:
        """Get list of user proxies for the current user.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_user_proxy")
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
                "Assign proxy user with ID -> %d to current user; calling -> %s",
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
                "Assign proxy user with ID -> %d to current user (legacy xGov); calling -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_favorites")
    def get_user_favorites(
        self,
        where_name: str | None = None,
        expand: str | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
        sort: str | None = None,
        limit: int = 20,
        page: int = 1,
    ) -> dict | None:
        """Get the favorites for the current (authenticated) user.

        Args:
            where_name (str | None = None):
                Name of the user (login).
            expand (str | None = None):
                Resolve individual fields (e.g. expand=properties{id,parent_id}&expand=versions{file_name})
                or entire sections (eg. expand=properties) that contain known identifiers (nodes, members, etc.).
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
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Format can be sort = name, sort = order, sort = tab_id. If the prefix of asc or desc is not used
                then asc will be assumed.
                Default is None.
            limit (int, optional):
                The maximum number of results per page.
            page (int, optional):
                The page number to retrieve.

        Returns:
            dict | None:
                Request response or None if the favorite request has failed.

        """

        # Add query parameters (embedded in the URL)
        query = {}
        if where_name:
            query["where_name"] = where_name
        if expand:
            query["expand"] = expand
        if fields:
            query["fields"] = fields
        if metadata:
            query["expand"] = expand
        if sort:
            query["sort"] = sort
        if limit:
            query["limit"] = limit
        if page:
            query["page"] = page

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["favoritesUrl"] + "?" + encoded_query
        if metadata:
            request_url += "&metadata"
        request_header = self.request_form_header()

        self.logger.debug(
            "Getting favorites for current user; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get favorites for current user",
        )

    # end method definition

    def add_favorite(self, node_id: int) -> dict | None:
        """Add a favorite for the current (authenticated) user.

        Deprecated: use add_user_favorite() instead.
        """

        warnings.warn(
            message="Method add_favorite() is deprecated, use add_user_favorite() instead.",
            category=DeprecationWarning,
            stacklevel=2,
        )
        return self.add_user_favorite(node_id=node_id)

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_favorite")
    def add_user_favorite(self, node_id: int) -> dict | None:
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
            "Adding favorite for node ID -> %d; calling -> %s",
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
        """Add a favorite for the current (authenticated) user.

        Deprecated: use add_user_favorite_tab() instead.
        """

        warnings.warn(
            message="Method add_favorite_tab() is deprecated, use add_user_favorite_tab() instead.",
            category=DeprecationWarning,
            stacklevel=2,
        )
        return self.add_user_favorite_tab(tab_name=tab_name, order=order)

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_favorite_tab")
    def add_user_favorite_tab(self, tab_name: str, order: int) -> dict | None:
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
            "Adding favorite tab -> '%s'; calling -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_user_recently_accessed")
    def get_user_recently_accessed(
        self,
        where_name: str | None = None,
        where_type: list[int] | None = None,
        where_parent_id: int | None = None,
        expand: str | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
        sort: str | None = None,
        limit: int = 20,
        page: int = 1,
    ) -> dict | None:
        """Get the recently accessed items for the current (authenticated) user.

        Args:
            where_name (str | None = None):
                Name of the user (login).
            where_type (list[int] | None = None):
                List of node types to filter the results by.
                (144 for document, 749 for email and so on)
            where_parent_id (int | None = None):
                Filter results by parent node ID.
            expand (str | None = None):
                Resolve individual fields (e.g. expand=properties{id,parent_id}&expand=versions{file_name})
                or entire sections (eg. expand=properties) that contain known identifiers (nodes, members, etc.).
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
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Format can be sort = name, sort = order, sort = tab_id. If the prefix of asc or desc is not used
                then asc will be assumed.
                Default is None.
            limit (int, optional):
                The maximum number of results per page.
            page (int, optional):
                The page number to retrieve.

        Returns:
            dict | None:
                Request response or None if the favorite request has failed.

        """

        # Add query parameters (embedded in the URL)
        query = {}
        if where_name:
            query["where_name"] = where_name
        if where_type:
            query["where_type"] = where_type
        if where_parent_id:
            query["where_parent_id"] = where_parent_id
        if expand:
            query["expand"] = expand
        if fields:
            query["fields"] = fields
        if metadata:
            query["expand"] = expand
        if sort:
            query["sort"] = sort
        if limit:
            query["limit"] = limit
        if page:
            query["page"] = page

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["recentlyAccessedUrl"] + "?" + encoded_query
        if metadata:
            request_url += "&metadata"
        request_header = self.request_form_header()

        self.logger.debug(
            "Getting recently accessed items for current user; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get recently accessed items for current user",
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_user_reserved_nodes")
    def get_user_reserved_nodes(
        self,
        where_name: str | None = None,
        expand: str | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
        sort: str | None = None,
        limit: int = 20,
        page: int = 1,
    ) -> dict | None:
        """Get the reserved nodes for the current (authenticated) user.

        Args:
            where_name (str | None = None):
                Name of the user (login).
            expand (str | None = None):
                Resolve individual fields (e.g. expand=properties{id,parent_id}&expand=versions{file_name})
                or entire sections (eg. expand=properties) that contain known identifiers (nodes, members, etc.).
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
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Format can be sort = name, sort = order, sort = tab_id. If the prefix of asc or desc is not used
                then asc will be assumed.
                Default is None.
            limit (int, optional):
                The maximum number of results per page.
            page (int, optional):
                The page number to retrieve.

        Returns:
            dict | None:
                Request response or None if the favorite request has failed.

        """

        # Add query parameters (embedded in the URL)
        query = {}
        if where_name:
            query["where_name"] = where_name
        if expand:
            query["expand"] = expand
        if fields:
            query["fields"] = fields
        if metadata:
            query["expand"] = expand
        if sort:
            query["sort"] = sort
        if limit:
            query["limit"] = limit
        if page:
            query["page"] = page

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["reservedNodesUrl"] + "?" + encoded_query
        if metadata:
            request_url += "&metadata"
        request_header = self.request_form_header()

        self.logger.debug(
            "Getting reserved nodes for current user; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get reserved nodes for current user",
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_favorites")
    def get_user_memberof(
        self,
        expand: str | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
        limit: int = 20,
        page: int = 1,
    ) -> dict | None:
        """Get the groups the current (authenticated) user is a member of.

        Args:
            expand (str | None = None):
                Resolve individual fields (e.g. expand=properties{id,parent_id}&expand=versions{file_name})
                or entire sections (eg. expand=properties) that contain known identifiers (nodes, members, etc.).
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
            limit (int, optional):
                The maximum number of results per page.
            page (int, optional):
                The page number to retrieve.

        Returns:
            dict | None:
                Request response or None if the favorite request has failed.

        Example:
        {
            'links': {
                'data': {
                    'self': {
                        'body': '',
                        'content_type': '',
                        'href': '/api/v2/members/memberof?fields=properties&limit=20&page=1',
                        'method': 'GET',
                        'name': ''
                    }
                }
            },
            'results': [
                {
                    'data': {
                        'properties': {
                            'deleted': False,
                            'id': 19935,
                            'initials': 'I',
                            'leader_id': None,
                            'name': 'Innovate',
                            'name_formatted': 'Innovate',
                            'type': 1,
                            'type_name': 'Group'
                        }
                    }
                },
                ...
            ]
        }

        """

        # Add query parameters (embedded in the URL)
        query = {}
        if expand:
            query["expand"] = expand
        if fields:
            query["fields"] = fields
        if metadata:
            query["expand"] = expand
        if limit:
            query["limit"] = limit
        if page:
            query["page"] = page

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["memberofUrl"] + "?" + encoded_query
        if metadata:
            request_url += "&metadata"
        request_header = self.request_form_header()

        self.logger.debug(
            "Getting groups the current user is a member of; calling -> %s",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get groups the current user is a member of",
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_groups")
    def get_groups(
        self,
        where_name: str | None = None,
        sort: str | None = None,
        limit: int = 20,
        page: int = 1,
        show_error: bool = False,
    ) -> dict | None:
        """Get a list of Content Server groups.

        Args:
            where_name (str | None, optional):
                The name of the group to look up.
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Format can be sort = id, sort = name, sort = group_id.
                If the prefix of asc or desc is not used then asc will be assumed.
                Default is None.
            limit (int, optional):
                The maximum number of results per page (internal default is 10). OTCS does
                not allow values > 20 so this method adjusts values > 20 to 20.
            page (int, optional):
                The page number to retrieve.
            show_error (bool, optional):
                If True, treats the absence of the group as an error. Defaults to False.

        Returns:
            dict | None:
                Group information as a dictionary, or None if the group is not found.

        Example:
            ```json
                {
                    'collection': {
                        'paging': {
                            'limit': 10,
                            'page': 1,
                            'page_total': 1,
                            'range_max': 1,
                            'range_min': 1,
                            'total_count': 1
                        },
                        'sorting': {
                            'sort': [
                                {
                                    'key': 'sort',
                                    'value': 'asc_id'
                                }
                            ]
                        }
                    },
                    'links': {
                        'data': {
                            'self': {
                                'body': '',
                                'content_type': '',
                                'href': '/api/v2/members?where_name=Procurement&where_type=1',
                                'method': 'GET',
                                'name': ''
                            }
                        }
                    },
                    'results': [
                        {
                            'data': {
                                'properties': {
                                    'deleted': False,
                                    'id': 17649,
                                    'initials': 'P',
                                    'leader_id': None,
                                    'name': 'Procurement',
                                    'name_formatted': 'Procurement',
                                    'type': 1,
                                    'type_name': 'Group'
                                }
                            }
                        }
                    ]
                }
            ```

            To access the ID of the first group found, use ["results"][0]["data"]["properties"]["id"].
            Or use the method get_result_value(response, key="id")

        """

        # Add query parameters (embedded in the URL)
        # Using type = 1 for OTCS groups:
        query = {"where_type": 1}
        if where_name:
            query["where_name"] = where_name
        if sort:
            query["sort"] = sort
        if limit:
            if limit > 20:
                self.logger.warning(
                    "Page limit for group query cannot be larger than 20. Adjusting from %d to 20.", limit
                )
                limit = 20
            query["limit"] = limit
        if page:
            query["page"] = page
        encoded_query = urllib.parse.urlencode(query=query, doseq=True)
        request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get groups%s; calling -> %s",
            " with name -> '{}'".format(where_name) if where_name else "",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get groups{}".format(
                " with name -> '{}'".format(where_name) if where_name else ""
            ),
            warning_message="Groups{} do not yet exist!".format(
                " with name -> '{}'".format(where_name) if where_name else ""
            ),
            show_error=show_error,
        )

    # end method definition

    def get_groups_iterator(
        self,
        where_name: str | None = None,
        sort: str | None = None,
        limit: int = 20,
    ) -> iter:
        """Get an iterator object that can be used to traverse OTCS groups.

        Filters can be applied that are given by the "where" and "query" parameters.

        Using a generator avoids loading a large number of groups into memory at once.
        Instead you can iterate over the potential large list of groups.

        Example usage:
            ```python
            groups = otcs_object.get_groups_iterator(limit=10)
            for group in groups:
                logger.info(
                    "Traversing group -> '%s' (%s)",
                    otcs_object.get_result_value(response=group, key="name"),
                    otcs_object.get_result_value(response=group, key="id"),
                )
            ```

        Args:
            where_name (str | None, optional):
                Name of the user (login).
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name ).
                Format can be sort = id, sort = name, sort = group_id.
                If the prefix of asc or desc is not used then asc will be assumed.
                Default is None.
            limit (int, optional):
                The maximum number of results per page (internal default is 10). OTCS does
                not allow values > 20 so this method adjusts values > 20 to 20.

        Returns:
            iter:
                A generator yielding one group per iteration.
                If the REST API fails, returns no value.

        """

        # First we probe how many members we have:
        response = self.get_groups(
            where_name=where_name,
            limit=1,
            page=1,
        )
        if not response or "results" not in response:
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        number_of_users = response["collection"]["paging"]["total_count"]
        if not number_of_users:
            self.logger.debug(
                "No groups found! Cannot iterate over groups.",
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        # If the group has many members we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (number_of_users + limit - 1) // limit

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.get_groups(
                where_name=where_name,
                sort=sort,
                limit=limit,
                page=page,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve groups (page -> %d)",
                    page,
                )
                return

            # Yield nodes one at a time:
            yield from response["results"]

        # end for page in range(1, total_pages + 1)

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_group")
    def get_group(self, name: str | None = None, group_id: int | None = None, show_error: bool = False) -> dict | None:
        """Get the Content Server group with a given name.

        Args:
            name (str | None, optiopnal):
                The name of the group to look up.
            group_id (int | None, optional):
                The ID of the group to look up. If provided, this will be used to find
                the group instead of the name.
                Defaults to None.
            show_error (bool, optional):
                If True, treats the absence of the group as an error. Defaults to False.

        Returns:
            dict | None:
                Group information as a dictionary, or None if the group is not found.

        Example:
            ```json
                {
                    'collection': {
                        'paging': {
                            'limit': 10,
                            'page': 1,
                            'page_total': 1,
                            'range_max': 1,
                            'range_min': 1,
                            'total_count': 1
                        },
                        'sorting': {
                            'sort': [
                                {
                                    'key': 'sort',
                                    'value': 'asc_id'
                                }
                            ]
                        }
                    },
                    'links': {
                        'data': {
                            'self': {
                                'body': '',
                                'content_type': '',
                                'href': '/api/v2/members?where_name=Procurement&where_type=1',
                                'method': 'GET',
                                'name': ''
                            }
                        }
                    },
                    'results': [
                        {
                            'data': {
                                'properties': {
                                    'deleted': False,
                                    'id': 17649,
                                    'initials': 'P',
                                    'leader_id': None,
                                    'name': 'Procurement',
                                    'name_formatted': 'Procurement',
                                    'type': 1,
                                    'type_name': 'Group'
                                }
                            }
                        }
                    ]
                }
            ```

            To access the ID of the first group found, use ["results"][0]["data"]["properties"]["id"].
            Or use the method get_result_value(response, key="id")

        """

        if group_id is None and name is None:
            self.logger.error("No group name or ID provided. Cannot find group!")
            return None

        if group_id is None:
            # Add query parameters (embedded in the URL)
            # Using type = 1 for OTCS groups:
            query = {"where_type": 1}
            query["where_name"] = name
            encoded_query = urllib.parse.urlencode(query=query, doseq=True)
            request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)
        else:
            # If a group ID is provided, we use the direct URL to that group:
            request_url = self.config()["membersUrlv2"] + "/" + str(group_id)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get group with%s; calling -> %s",
            " name -> '{}'".format(name) if name else "ID -> {}".format(group_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get group -> '{}'".format(name if name else group_id),
            warning_message="Group -> '{}' does not yet exist".format(name if name else group_id),
            show_error=show_error,
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_group")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_group_members")
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
        if where_name:
            query["where_name"] = where_name
        if where_first_name:
            query["where_first_name"] = where_first_name
        if where_last_name:
            query["where_last_name"] = where_last_name
        if where_business_email:
            query["where_business_email"] = where_business_email
        if limit:
            query["limit"] = limit
        if page:
            query["page"] = page
        encoded_query = urllib.parse.urlencode(query=query, doseq=True)
        request_url = self.config()["membersUrlv2"] + "/" + str(group) + "/members?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get members of group with ID -> %d; calling -> %s",
            group,
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

        Using a generator avoids loading a large number of group members into memory at once.
        Instead you can iterate over the potential large list of group members.

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
            self.logger.debug(
                "Group with ID -> %d does not have members! Cannot iterate over members.",
                group,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_group_member")
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
            "Adding member with ID -> %d to group with ID -> %d; calling -> %s",
            member_id,
            group_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_privilege")
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
    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_usage_privileges")
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
            failure_message="Failed to get system usage privileges",
        )

        if response:
            return response["results"]["data"]

        return None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_usage_privilege")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_usage_privilege")
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
                "Assigning member with ID -> %d to usage privilege -> '%s' (%s)",
                member_id,
                usage_privilege,
                privilege_id,
            )
            return self.add_group_member(member_id=member_id, group_id=privilege_id)

        self.logger.warning(
            "Cannot add member with ID -> %d to usage privilege -> '%s'. Usage is likely unrestricted.",
            member_id,
            usage_privilege,
        )
        return None

    # end method definition

    @cache
    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_object_privileges")
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
            failure_message="Failed to get system usage privileges",
        )

        if response:
            return response["results"]["data"]

        return None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_object_privilege")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_object_privilege")
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
                "Assigning member with ID -> %d to object privilege -> '%s' (%s)",
                member_id,
                object_type,
                privilege_id,
            )
            return self.add_group_member(member_id=member_id, group_id=privilege_id)

        self.logger.warning(
            "Cannot add member with ID -> %d to object privilege -> '%s'. Object Type is likely unrestricted.",
            member_id,
            object_type,
        )
        return None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node")
    def get_node(
        self,
        node_id: int,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
        timeout: float = REQUEST_TIMEOUT,
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
            timeout (float, optional):
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

        # Extend the OTEL span with custom attributes
        current_span = trace.get_current_span()
        current_span.set_attribute("node_id", node_id)
        current_span.set_attribute("fields", fields)
        current_span.set_attribute("metadata", metadata)
        current_span.set_attribute("timeout", timeout)

        query = {}
        if fields:
            query["fields"] = fields

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "?{}".format(encoded_query)
        if metadata:
            request_url += "&metadata"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get node with ID -> %d; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_by_parent_and_name")
    def get_node_by_parent_and_name(
        self,
        parent_id: int,
        name: str,
        fields: str | list = "properties",
        metadata: bool = False,
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
            metadata (bool, optional):
                If True, returns metadata (data type, field length, min/max values, etc.)
                about the data.
                The metadata will be returned under `results.metadata`, `metadata_map`,
                and `metadata_order`.
                Defaults to False.
            show_error (bool, optional):
                If True, the function treats the absence of the node as an error.
                Defaults to False.
            exact_match (bool, optional):
                If True, the results are filtered for an exact match of the node name.
                Defaults to True. If fields do not include the 'name' property the matching is skipped.

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
        if metadata:
            request_url += "&metadata"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get node with name -> '%s' and parent ID -> %d; calling -> %s",
            name,
            parent_id,
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

        # Filter results for exact matches only if applicable
        results = response.get("results", []) if response else []

        # Filter results for exact matches only
        if results and exact_match:
            has_name_property = any("name" in node.get("data", {}).get("properties", {}) for node in results)
            # Check if any node has the 'name' key in properties
            # (depending on the 'fields' parameter, the 'name' property may be excluded, e.g. fields="properties{id}")
            if has_name_property:
                filtered_results = next(
                    (node for node in results if node.get("data", {}).get("properties", {}).get("name") == name),
                    None,
                )
                response["results"] = [] if filtered_results is None else [filtered_results]
            else:
                self.logger.warning(
                    "Exact match requested for node -> '%s' and parent ID -> %d, but 'name' key is missing in result properties -> '%s'. Skipping filtering.",
                    name,
                    parent_id,
                    fields,
                )

        return response

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_by_workspace_and_path")
    def get_node_by_workspace_and_path(
        self,
        workspace_id: int,
        path: list,
        create_path: bool = False,
        fields: str | list = "properties",
        metadata: bool = False,
        show_error: bool = False,
    ) -> dict | None:
        """Get a node based on the workspace ID (= node ID) and path (list of folder names).

        Args:
            workspace_id (int):
                The node ID of the workspace.
            path (list):
                A list of container items (top down).
                The last item is name of to be retrieved item.
                If path is empty the node of the volume is returned.
            create_path (bool, optional):
                Whether or not missing folders in the path should be created.
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
            metadata (bool, optional):
                If True, returns metadata (data type, field length, min/max values, etc.)
                about the data.
                The metadata will be returned under `results.metadata`, `metadata_map`,
                and `metadata_order`.
                Defaults to False.
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

        parent_item_id = workspace_id

        # In case the path is an empty list we will have the node of the volume:
        # Only deliver the full set of requested fields if this node is the final result, i.e.
        # if path is empty:
        node = self.get_node(
            node_id=parent_item_id,
            fields=fields if not path else "properties{id,name}",
            metadata=metadata if not path else False,
        )

        for i, path_element in enumerate(path):
            # We only deliver the full set of fields for the last path element:
            if i == len(path) - 1:
                node = self.get_node_by_parent_and_name(
                    parent_id=parent_item_id, name=path_element, fields=fields, metadata=metadata
                )
            # For intermediate path elements we use the minimum set of fields (ID)
            # to allow traversal of the path (IMPORTANT: turn-off exact_match if name property is excluded):
            else:
                node = self.get_node_by_parent_and_name(
                    parent_id=parent_item_id, name=path_element, fields="properties{id}", exact_match=False
                )
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
                            "Cannot create folder -> '%s' in workspace with ID -> %d (path -> %s), it may already exist (race condition). Try to get it...",
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
            parent_item_id = current_item_id
            self.logger.debug(
                "Traversing path element -> '%s' (%s)",
                path_element,
                str(current_item_id),
            )

        return node

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_by_volume_and_path")
    def get_node_by_volume_and_path(
        self,
        volume_type: int,
        path: list | None = None,
        create_path: bool = False,
        fields: str | list = "properties",
        metadata: bool = False,
        show_error: bool = False,
    ) -> dict | None:
        """Get a node based on the volume and path (list of container items).

        Args:
            volume_type (int):
                Volume type ID (default is 141 = Enterprise Workspace)
                See OTCS class declaration for a list of available types.
            path (list, optional):
                A list of container items (top down),
                last item is name of to be retrieved item.
                If path is empty the node of the volume is returned.
            create_path (bool, optional):
                if path elements are missing: should they be created?
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
            metadata (bool, optional):
                If True, returns metadata (data type, field length, min/max values, etc.)
                about the data.
                The metadata will be returned under `results.metadata`, `metadata_map`,
                and `metadata_order`.
                Defaults to False.
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
            "Volume type -> %s has node ID -> %d",
            str(volume_type),
            volume_id,
        )

        current_item_id = volume_id

        # In case the path is an empty list we will have the node of the volume:
        # Only deliver the full set of requested fields if this node is the final result, i.e.
        # if path is empty:
        node = self.get_node(
            node_id=current_item_id,
            fields=fields if not path else "properties{id,name}",
            metadata=metadata if not path else False,
        )

        for i, path_element in enumerate(path):
            # We only deliver the full set of fields for the last path element:
            if i == len(path) - 1:
                node = self.get_node_by_parent_and_name(
                    parent_id=current_item_id, name=path_element, fields=fields, metadata=metadata
                )
            # For intermediate path elements we use the minimum set of fields (ID)
            # to allow traversal of the path (IMPORTANT: turn-off exact_match if name property is excluded):
            else:
                node = self.get_node_by_parent_and_name(
                    parent_id=current_item_id, name=path_element, fields="properties{id}", exact_match=False
                )
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
                        "Cannot find path element -> '%s' in container with ID -> %d!",
                        path_element,
                        current_item_id,
                    )
                else:
                    self.logger.debug(
                        "Cannot find path element -> '%s' in container with ID -> %d.",
                        path_element,
                        current_item_id,
                    )
                return None
            current_item_id = path_item_id
            self.logger.debug(
                "Traversing path element -> '%s' (%s)",
                path_element,
                str(current_item_id),
            )

        return node

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_from_nickname")
    def get_node_from_nickname(
        self,
        nickname: str,
        show_error: bool = False,
    ) -> dict | None:
        """Get a node based on the nickname.

        Args:
            nickname (str):
                The nickname of the node.
            show_error (bool, optional):
                If True, treat as error if node is not found.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="set_node_nickname")
    def set_node_nickname(
        self,
        node_id: int,
        nickname: str,
        show_error: bool = False,
    ) -> dict | None:
        """Assign a nickname to an OTCS node (e.g. workspace).

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
            "Assign nickname -> '%s' to node with ID -> %d; calling -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_subnodes")
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
                The maximum number of results to return (page size). Defaults to 100.
            page (int, optional):
                The page of results to retrieve (page number). Defaults to 1 (first page).
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
            "Get subnodes of parent node with ID -> %d (page -> %d, item limit -> %d); calling -> %s",
            parent_node_id,
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

        response = self.get_node(node_id=parent_node_id, fields="properties{size}")
        container_size = self.get_result_value(response=response, key="size")
        if not container_size:
            self.logger.debug(
                "Container with parent node ID -> %d is empty! Cannot iterate sub items.",
                parent_node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_nodes_by_parent_and_filters")
    def get_nodes_by_parent_and_filters(
        self,
        parent_id: int,
        name: str | None = None,
        facet_values: dict[int, int | str | list[int | str]] | None = None,
        sort: str | None = None,
        page_size: int = 100,
        page: int = 1,
    ) -> dict | None:
        """Get the nodes under a given parent node ID with defined facet values.

        NOTE: This is a V3 REST API that may not be aviable in older OTCS versions!

        Args:
            parent_id (int):
                The ID of the parent node.
            name (str | None, optional):
                The name of the node to retrieve. Can also be a substring.
            facet_values (dict[int, int | str | list[int | str]] | None, optional):
                Each dictionary item has:
                * Key: facet ID (int)
                * Value: filter value (int or str or list). If a list is given,
                  multiple values are OR'ed together using a | (pipe).
                Defaults to None (no facet filtering). Multiple facet_values are AND'ed together.
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Default is None.
            page_size (int, optional):
                The maximum number of results to return (page size). Defaults to 100.
            page (int, optional):
                The page of results to retrieve (page number). Defaults to 1 (first page).

        Returns:
            dict | None:
                Subnode information as a dictionary, or None if no nodes with
                the given parent ID and facet filters are found.

        """

        # Add query parameters (these are NOT passed via JSon body!)
        query = {}
        if name:
            query["where_name"] = name
        if facet_values:
            where_facet = []
            for k, v in facet_values.items():
                # Edge case: empty list []: ignore this facet filter and continue:
                if not v:
                    continue
                # Join list values with pipe (this is a facet OR operation). Scalar values are used as string:
                value = "|".join(str(item) for item in v) if isinstance(v, list) else str(v)
                where_facet.append("{}:{}".format(k, value))
            if where_facet:
                query["where_facet"] = where_facet
        if sort:
            query["sort"] = sort
        if page > 1:
            query["page"] = page
        if page_size > 0:
            query["page_size"] = page_size

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["facetBrowseUrl"] + "/" + str(parent_id) + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get nodes of parent with ID -> %d%s%s (page -> %d, item limit -> %d); calling -> %s",
            parent_id,
            " and name -> '{}'".format(name) if name else "",
            " and facet values -> {}".format(facet_values) if facet_values else "",
            page,
            page_size,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get nodes for parent with ID -> {}".format(
                parent_id,
            ),
        )

    # end method definition

    def get_nodes_by_parent_and_filters_iterator(
        self,
        parent_id: int,
        name: str | None = None,
        facet_values: dict[int, str] | None = None,
        sort: str | None = None,
        result_field: str = "contents",
        page_size: int = 100,
    ) -> iter:
        """Get an iterator object that can be used to traverse the filtered nodes.

        NOTE: This is a V3 REST API that may not be aviable in older OTCS versions!

        Using a generator avoids loading a large number of nodes into memory at once.
        Instead you can iterate over the potential large list of filtered nodes.

        Args:
            parent_id (int):
                The ID of the parent node.
            name (str | None, optional):
                The name of the node to retrieve. Can also be a substring.
            facet_values (dict[int, str] | None, optional):
                Each dictionary item has:
                * Key: facet ID (int)
                * Value: filter value (str)
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Default is None.
            result_field (str, optional):
                This V3 REST API delivers multiple substructures for the matching nodes:
            page_size (int, optional):
                The maximum number of results to return (page size). Defaults to 100.

        Example usage:
            ```python
            nodes = otcs_object.get_nodes_by_parent_and_filters_iterator(parent_node_id=15838, facet_filters={...})
            for node in nodes:
                logger.info("Node name -> '%s'", node["name"])
            ```

        Example iterator value:
        {
            'container': True,
            'create_date': '2025-11-22T04:35:43Z',
            'create_user_id': 28282,
            'data': {
                'actions': {...},
                'annotations': {...},
                'boattachinfo': {...},
                'bwsinfo': {...},
                'cadxref_doc_info': {...},
                'claimed_doc_info': {...},
                'rmiconsdata': {...},
                'sestatus_doc_info': {...},
                'sharing_info': {...},
                'signedout_doc_info': {...},
                'transmittal_data': {},
                'xeng_tag_info': {...}
            },
            'description': '',
            'favorite': False,
            'hidden': False,
            'icon': '/cssupport/otsapxecm/wksp_contract_vendor.png',
            'icon_large': '/cssupport/otsapxecm/wksp_contract_vendor_large.png',
            'id': 80524,
            'image_url': '/appimg/ot_bws/icons/35671%2Esvg?v=161841_20331',
            'mime_type': None,
            'modify_date': '2025-11-22T04:35:49Z',
            'name': '4500000007 - C.E.B. Berlin SE',
            'openable': True,
            'owner_user_id': 28282,
            'parent_id': 34897,
            'permissions_model': 'advanced',
            'reserved': False,
            'reserved_user_id': None,
            'rm_enabled': True,
            'size': 12,
            'size_formatted': '12 Items',
            'type': 848,
            'type_name': 'Business Workspace',
            'wksp_type_name': 'Purchase Order',
            'wnf_att_xf3_4': '2016-02-01T00:00:00',
            'wnf_att_xf3_5': 'C.E.B. Berlin SE',
            'wnf_att_xf3_c': 'Berlin',
            'wnf_att_xf3_d': 'Germany',
            'wnf_att_xf3_f': 'Innovate Germany',
            'wnf_att_xf3_g': 'Group Mgt.',
            'wnf_att_xf3_k': '785.57',
            'wnf_att_xf3_l': 'EUR',
            'wnf_att_xf3_p': 'R-9010; R-9020; R-9030; R-9040; R-9050'
        }

        """

        # Get the first page of items:
        response = self.get_nodes_by_parent_and_filters(
            parent_id=parent_id,
            name=name,
            facet_values=facet_values,
            sort=sort,
            page=1,
            page_size=page_size,
        )

        if not response or not response["results"]:
            return

        total_pages = response["results"]["paging"]["page_total"]

        # Yield nodes one at a time
        yield from response["results"][result_field]

        for page in range(2, total_pages):
            # Get the next page of sub node items:
            response = self.get_nodes_by_parent_and_filters(
                parent_id=parent_id,
                name=name,
                facet_values=facet_values,
                sort=sort,
                page=page,
                page_size=page_size,
            )

            # Yield nodes one at a time
            yield from response["results"][result_field]

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="lookup_node")
    def lookup_nodes(
        self,
        parent_node_id: int,
        category: str,
        attribute: str,
        value: str,
        attribute_set: str | None = None,
        substring: bool = False,
        fields: str | list | None = None,
        page_size: int = 25,
        stop_at_first_match: bool = False,
    ) -> dict | None:
        """Lookup nodes under a parent node that have a specified value in a category attribute.

        Args:
            parent_node_id (int):
                The node ID of the parent (typically folder or workspace).
            category (str):
                The name of the category.
            attribute (str):
                The name of the attribute that includes the value to match with.
            value (str):
                The lookup value that is matched against the node attribute value.
            attribute_set (str | None, optional):
                The name of the attribute set
            substring (bool, optional):
                Whether to match the value as a substring (True) or exact (False). Defaults to exact match.
            fields (str | list | None, optional):
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
                Defaults to None which is internally set to ["properties", "categories"].
            page_size (int, optional):
                The number of subnodes that are requested per request.
                For the lookup nodes this is basically the chunk size.
            stop_at_first_match (bool, optional):
                Whether to stop the lookup at the first match found. Defaults to False.
                This can improve performance if only one match is needed.

        Returns:
            dict | None:
                Node(s) wrapped in dictionary with "results" key or None if the REST API fails.

        """

        # Create a "results" dict that is compatible with normal REST calls
        # to not break get_result_value() method that may be called on the result:
        results = {"results": []}

        if fields is None:
            fields = ["properties", "categories"]

        # get_subnodes_iterator() returns a python generator that we use for iterating over all nodes
        # in an efficient way avoiding to retrieve all nodes at once (which could be a large number):
        for node in self.get_subnodes_iterator(
            parent_node_id=parent_node_id, fields=fields, metadata=True, page_size=page_size
        ):
            #
            # 1: Get the category and attribute schemas for the requested category name and attribute name:
            #

            node_name = self.get_result_value(node, "name")
            node_id = self.get_result_value(node, "id")
            category_schemas = node["metadata"]["categories"]
            # Get the the matching category. For this we check that the name
            # of the first dictionary (representing the category itself) has
            # the requested name:
            category_schema = next(
                (
                    cat_elem
                    for cat_elem in category_schemas
                    if next(iter(cat_elem.values()), {}).get("name") == category
                ),
                None,
            )
            if not category_schema:
                self.logger.debug(
                    "Node -> '%s' (%s) does not have category -> '%s'. Cannot lookup value -> '%s'. Skipping...",
                    node_name,
                    node_id,
                    category,
                    value,
                )
                continue

            # The first entry is the category itself:
            category_key = next(iter(category_schema))

            # There can be multiple attributes with the same name in a category
            # if the category has sets:
            attribute_keys = [
                cat_elem["key"] for cat_elem in category_schema.values() if cat_elem.get("name") == attribute
            ]
            if not attribute_keys:
                self.logger.debug(
                    "Node -> '%s' (%s) does not have attribute -> '%s'. Skipping...",
                    node_name,
                    node_id,
                    attribute,
                )
                continue

            if attribute_set:  # is the attribute_set parameter provided?
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
                set_max_len = int(set_schema["multi_value_length_max"])
            else:  # no attribute set value provided via the attribute_set parameter:
                set_schema = None
                set_key = None
                set_max_len = None

            # Calculate the prefix for the attribute key(s):
            prefix = set_key + "_" if set_key else category_key + "_"

            #
            # 2: Now we have the attribute keys to retrieve the attribute value(s)
            #    from the node data to compare with the lookup value:
            #

            # category_data is a list which each element representing the data of a different category:
            category_data = node["data"]["categories"]
            node_matched = False

            # Traverse the attribute keys for the attributes with the matching attribute name:
            for attribute_key in attribute_keys:
                # The lookup does not include a set name but this attribute key
                # belongs to a set attribute - so we can skip it:
                if not set_key and "_x_" in attribute_key:
                    continue

                # Split the attribute key once (1) at the first underscore from the right.
                # rsplit delivers a list and [-1] delivers the last list item:
                attribute_id = attribute_key.rsplit("_", 1)[-1]

                # Loop over all category data entries to find the attribute value(s):
                for cat_data in category_data:
                    if set_key:
                        for i in range(1, set_max_len):
                            # Construct the full key for the attribute value:
                            key = prefix + str(i) + "_" + attribute_id
                            if key not in cat_data:
                                # if the set row does not exist we can break:
                                break
                            attribute_value = cat_data.get(key)
                            # Is it a multi-value attribute (i.e. a list of values)?
                            if isinstance(attribute_value, list):
                                if value in attribute_value:
                                    node_matched = True
                                    break
                            elif (substring and value in attribute_value) or (
                                not substring and value == attribute_value
                            ):
                                node_matched = True
                                break
                    # end if set_key
                    else:
                        key = prefix + attribute_id
                        attribute_value = cat_data.get(key)
                        if not attribute_value:
                            continue
                        # Is it a multi-value attribute (i.e. a list of values)?
                        if isinstance(attribute_value, list):
                            if value in attribute_value:
                                node_matched = True
                        # If not a multi-value attribute, check for equality:
                        elif (substring and value in attribute_value) or (not substring and value == attribute_value):
                            node_matched = True
                    if node_matched:
                        break
                    # end if set_key ... else
                # end for cat_data in data:
                if node_matched:
                    break
            # end for attribute_key in attribute_keys:

            if node_matched:
                results["results"].append(node)
                if stop_at_first_match:
                    break
        # end for node in self.get_subnodes_iterator()

        if not results["results"]:
            self.logger.debug(
                "Couldn't find a node with the value -> '%s' in the attribute -> '%s' of category -> '%s' in parent with node ID -> %d.",
                value,
                attribute,
                category,
                parent_node_id,
            )

        return results if results["results"] else None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="lookup_node_by_regex")
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
                        "Node with name -> '%s' under parent with ID -> %d matches regular expression -> %s",
                        node_name,
                        parent_node_id,
                        regex,
                    )
                    return {"results": node}
            # end for regex in regex_list
        # end for node in self.get_subnodes_iterator()

        self.logger.warning(
            "Couldn't find a node under parent with node ID -> %d that has a name matching any of these regular expressions -> %s",
            parent_node_id,
            str(regex_list),
        )

        return None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_columns")
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
            "Get columns for node with ID -> %d; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_facets")
    def get_node_facets(
        self, node_id: int, facet_values: dict[int, str] | None = None, facet_values_limit: int | None = None
    ) -> dict | None:
        """Get facets configured / enabled for a node.

        Args:
            node_id (int):
                The ID of the Node.
            facet_values (str, optional):
                The current position in the facet tree (optional). Used
                to determine remaining facet values if facets are already selected.
                Specify selected facets using the following syntax:
                '{facet id}:{value1}|{value2}|...' e.g. &where_facet=2101:331&where_facet=2100:23|9|17|20
            facet_values_limit (int | None 0 None):
                The maximum number of facet values to retrieve per facet.

        Returns:
            dict | None:
                Information of the Node facets or None if the request fails.

        Example:
        {
            'links': {
                'data': {
                    'self': {
                        'body': '',
                        'content_type': '',
                        'href': '/api/v2/facets/30607',
                        'method': 'GET',
                        'name': ''
                    }
                }
            },
            'results': {
                'data': {
                    'facets': {
                        '2330': {
                            'display_count': True,
                            'id': 2330,
                            'name': 'Owner',
                            'show_text_in_more': True,
                            'total_displayable': 2
                        },
                        '29853': {
                            'display_count': True,
                            'id': 29853,
                            'name': 'PO - Vendor',
                            'show_text_in_more': True,
                            'total_displayable': 35
                        },
                        '30136': {
                            'display_count': True,
                            'id': 30136,
                            'name': 'PO - Material',
                            'show_text_in_more': True,
                            'total_displayable': 26
                        },
                        '30556': {
                            'display_count': True,
                            'id': 30556,
                            'name': 'PO - Purchasing Organization',
                            'show_text_in_more': True,
                            'total_displayable': 7
                        }
                    },
                    'values': {
                        'available': [
                            {
                                '30136': [
                                    {
                                        'count': 1317,
                                        'name': 'Fingerprint Scanner Pro Sense X-I',
                                        'percentage': 85.4639844256976,
                                        'value': 'Fingerprint Scanner Pro Sense X-I'
                                    },
                                    ...
                                ]
                            },
                            {
                                '30556': [...]
                            },
                            {
                                '29853': [...]
                            },
                            {
                                '2330': [...]
                            }
                        ],
                        'selected': [...]
                    }
                }
            }
        }

        """

        # Add query parameters (these are NOT passed via JSon body!)
        query = {}
        if facet_values_limit:
            query["top_values_limit"] = facet_values_limit
        if facet_values:
            query["where_facet"] = ["{}:{}".format(k, v) for k, v in facet_values.items()]

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["facetsUrl"] + "/" + str(node_id) + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get facets for node with ID -> %d%s; calling -> %s",
            node_id,
            " and preselected facets -> {}".format(facet_values) if facet_values else "",
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get facets for node with ID -> {}".format(
                node_id,
            ),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_actions")
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
            "Get actions for node(s) with ID -> %d; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="rename_node")
    def rename_node(
        self,
        node_id: int,
        name: str,
        description: str | None = None,
        name_multilingual: dict | None = None,
        description_multilingual: dict | None = None,
        parse_error_response: bool | None = False,
    ) -> dict | None:
        """Change the name and description of a node.

        Args:
            node_id (int):
                ID of the node. You can use the get_volume() function below to
                to the node id for a volume.
            name (str):
                New name of the node.
            description (str | None, optional):
                New description of the node.
            name_multilingual (dict | None, optional):
                The multi-lingual node names.
            description_multilingual (dict | None, optional):
                The multi-lingual descriptions.
            parse_error_response (bool | None, optional):
                Whether to parse the request response or not. Defaults to False.

        Returns:
            dict | None:
                Request response or None if the renaming fails.

        """

        rename_node_put_body = {"name": name}

        if description:
            rename_node_put_body["description"] = description
        if name_multilingual:
            rename_node_put_body["name_multilingual"] = name_multilingual
        if description_multilingual:
            rename_node_put_body["description_multilingual"] = description_multilingual

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Rename node with ID -> %d to -> '%s'; calling -> %s",
            node_id,
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
            parse_error_response=parse_error_response,
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="delete_node")
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
            "Delete node with ID -> %d%s; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="purge_node")
    def purge_node(self, node_id: int | list) -> dict | None:
        """Purge an item in the recycle bin (final destruction).

        Args:
            node_id (int | list):
                ID(s) of the node(s) to be finally deleted.

        Returns:
            dict | None:
                The response of the REST call; None in case of a failure.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="restore_node")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_audit")
    def get_node_audit(
        self,
        node_id: int,
        filter_event_type: int | None = None,
        filter_user_id: int | None = None,
        filter_date_start: str | None = None,
        filter_date_end: str | None = None,
        limit: int = 100,
        page: int = 1,
        sort: str = "desc_audit_date",
    ) -> dict | None:
        """Get the audit information for a given node ID.

        Args:
            node_id (int):
                The ID of the node to get the audit for.
            filter_event_type (int | None, optional):
                Type of audit events to filter by. Possible values:
                - 9 : Permission Changed
                - 10 : Attribute Value Changed
                - 92 : Create from Copy
                - 264 : Classification Applied
                - 301 : Deployed from Warehouse
                - 416 : XML Import
                - 6000 : Content Sharing - Shared with external system
                - 6014 : Content Sharing - Share Coordinator changed
                - ...
            filter_user_id (int, optional):
                Filter audit events by user ID. Defaults to no filter.
                The date should be provided in YYYY-MM-DD notation. Time
                is not considered (only days)
            filter_date_start (str | None, optional):
                Filter audit events by start date. Defaults to no filter.
                The date should be provided in YYYY-MM-DD notation. Time
                is not considered (only days)
            filter_date_end (str | None, optional):
                Filter audit events by end date. Defaults to no filter.
            limit (int, optional):
                The maximum number of results to return. Defaults to 100.
            page (int, optional):
                The page of results to retrieve. Defaults to 1 (first page).
            sort (str, optional):
                Sort order of audit results. Format can be sort=desc_audit_date or sort=asc_audit_date.
                Results are sorted in descending order by default.

        Returns:
            dict | None:
                Subnode information as a dictionary, or None if no nodes with
                the given parent ID are found.

        Example:
                {
                    'collection': {
                        'paging': {
                            'limit': 100,
                            'page': 1,
                            'page_total': 1,
                            'range_max': 23,
                            'range_min': 1,
                            'total_count': 23
                        },
                        'sorting': {
                            'sort': [
                                {
                                    'key': 'sort',
                                    'value': 'desc_audit_date'
                                }
                            ]
                        }
                    },
                    'links': {
                        'data': {
                            'self': {
                                'body': '',
                                'content_type': '',
                                'href': '/api/v2/nodes/29572/audit?fields=properties&limit=100&sort=desc_audit_date',
                                'method': 'GET',
                                'name': ''
                            }
                        }
                    },
                    'results': {
                        'data': {
                            'audit': [
                                {
                                    'id': 29572,
                                    'event_type': 6000,
                                    'audit_date': '2025-05-23T10:20:56Z',
                                    'user_id': 8306,
                                    'agent_id': None,
                                    'audit_language_code': None,
                                    'target_user_id': None,
                                    'audit_name': 'Shared with Microsoft Teams Content Sharing Provider'
                                },
                                ...
                            ],
                            'audit_event_types': [
                                {
                                    'id': 92,
                                    'name': 'Create from Copy'
                                },
                                {
                                    'id': 6014,
                                    'name': 'Content Sharing - Share Coordinators Changed'
                                },
                                {
                                    'id': 301,
                                    'name': 'Deployed from Warehouse'
                                },
                                ...
                            ]
                        }
                    }
                }

        """

        # Add query parameters (these are NOT passed via JSon body!)
        query = {"limit": limit, "sort": sort}
        if filter_event_type:
            query["where_type"] = filter_event_type
        if filter_user_id:
            query["where_user_id"] = filter_user_id
        if filter_date_start:
            query["where_audit_date_start"] = filter_date_start
        if filter_date_end:
            query["where_audit_date_end"] = filter_date_end
        if page > 1:
            query["page"] = page

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/audit" + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        self.logger.debug(
            "Get audit of node with ID -> %d (page -> %d, item limit -> %d); calling -> %s",
            node_id,
            page,
            limit,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get audit for node with ID -> {}".format(
                node_id,
            ),
        )

    # end method definition

    def get_node_audit_iterator(
        self,
        node_id: int,
        filter_event_type: int | None = None,
        filter_user_id: int | None = None,
        filter_date_start: str | None = None,
        filter_date_end: str | None = None,
        page_size: int = 25,
        sort: str = "desc_audit_date",
    ) -> iter:
        """Get an iterator object that can be used to traverse subnodes.

        Filters can be applied that are given by the "filter" parameters.

        Using a generator avoids loading a large number of nodes into memory at once.
        Instead you can iterate over the potential large list of subnodes.

        Example usage:
            ```python
            audit_entries = otcs_object.get_node_audit_iterator(node_id=15838)
            for audit_entry in audit_entries:
                logger.info("Audit entry -> '%s'", ...)
            ```

        Args:
            node_id (int):
                The ID of the node to get the audit for.
            filter_event_type (int, optional):
                Type of audit events to filter by. Possible values:
                - 9 : Permission Changed
                - 10 : Attribute Value Changed
                - 92 : Create from Copy
                - 264 : Classification Applied
                - 301 : Deployed from Warehouse
                - 416 : XML Import
                - 6000 : Content Sharing - Shared with external system
                - 6014 : Content Sharing - Share Coordinator changed
                - ...
            filter_user_id (int, optional):
                Filter audit events by user ID. Defaults to no filter.
                The date should be provided in YYYY-MM-DD notation. Time
                is not considered (only days)
            filter_date_start (str, optional):
                Filter audit events by start date. Defaults to no filter.
                The date should be provided in YYYY-MM-DD notation. Time
                is not considered (only days)
            filter_date_end (str, optional):
                Filter audit events by end date. Defaults to no filter.
            page_size (int, optional):
                The number of subnodes that are requested per page.
                For the iterator this is basically the chunk size.
            sort (str, optional):
                Sort order of audit results. Format can be sort=desc_audit_date or sort=asc_audit_date.
                Results are sorted in descending order by default.

        Returns:
            iter:
                A generator yielding one node per iteration under the parent.
                If the REST API fails, returns no value.

        """

        response = self.get_node_audit(
            node_id=node_id,
            filter_event_type=filter_event_type,
            filter_user_id=filter_user_id,
            filter_date_start=filter_date_start,
            filter_date_end=filter_date_end,
        )
        if (
            not response
            or "collection" not in response
            or "paging" not in response["collection"]
            or not response["collection"]["paging"].get("total_count")
        ):
            self.logger.debug(
                "Item with node ID -> %d has no audit information! Cannot iterate audit.",
                node_id,
            )
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        audit_size = response["collection"]["paging"]["total_count"]

        # If the container has many items we need to go through all pages
        # Adding page_size - 1 ensures that any remainder from the division is
        # accounted for, effectively rounding up. Integer division (//) performs floor division,
        # giving the desired number of pages:
        total_pages = (audit_size + page_size - 1) // page_size

        for page in range(1, total_pages + 1):
            # Get the next page of sub node items:
            response = self.get_node_audit(
                node_id=node_id,
                filter_event_type=filter_event_type,
                filter_user_id=filter_user_id,
                filter_date_start=filter_date_start,
                filter_date_end=filter_date_end,
                limit=page_size,
                page=page,
                sort=sort,
            )
            if not response or not response.get("results", None):
                self.logger.warning(
                    "Failed to retrieve audit for node ID -> %d (page -> %d)",
                    node_id,
                    page,
                )
                return None

            # Yield nodes one at a time
            yield from (
                item["data"]["audit"]
                for item in response["results"]
                if isinstance(item.get("data"), dict) and "audit" in item["data"]
            )

        # end for page in range(1, total_pages + 1)

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_volumes")
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
    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_volume")
    def get_volume(
        self,
        volume_type: int,
        timeout: float = REQUEST_TIMEOUT,
    ) -> dict | None:
        """Get Volume information based on the volume type ID.

        Args:
            volume_type (int):
                The ID of the volume type.
            timeout (float | None, optional):
                The timeout for the request in seconds.

        Returns:
            dict | None:
                Volume details or None if volume is not found.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="check_node_name")
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
            "Check if node with name -> '%s' can be created in parent with ID -> %d; calling -> %s",
            node_name,
            parent_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="upload_file_to_volume")
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
                package = requests.get(url=path_or_url, headers=self.request_download_header(), timeout=1200)
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="flatten_categories_dict")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="upload_file_to_parent")
    def upload_file_to_parent(
        self,
        parent_id: int,
        file_url: str | None = None,
        file_name: str | None = None,
        mime_type: str | None = None,
        file_content: str | bytes | None = None,
        encoding: str = "utf-8",
        category_data: dict | None = None,
        classifications: list | None = None,
        description: str = "",
        external_modify_date: str | None = None,
        external_create_date: str | None = None,
        extract_zip: bool = False,
        replace_existing: bool = False,
        show_error: bool = True,
    ) -> dict | None:
        """Fetch a file from a URL or local filesystem and uploads it to a OTCS parent.

        The parent should be a container item such as a folder or business workspace.

        The file data can be provided in one of three ways:
        1. Via a public URL (file_url starting with "http")
        2. Via a local filesystem path (file_url pointing to an existing file or directory)
        3. Via in-memory content using the file_content parameter (str or bytes)

        Args:
            parent_id (int):
                The ID of the parent (folder) to upload the file to.
            file_url (str | None, optional):
                The URL to download the file from, or a local file path.
            file_name (str | None, optional):
                The name of the file being uploaded.
            mime_type (str | None, optional):
                The mime type of the file (e.g., 'application/pdf').
                If the mime type is not provided the method tries to "guess" the mime type.
            file_content (str | bytes | None):
                The file content provided directly in memory. If a string is provided,
                it will be encoded using the specified encoding.
            encoding (str, optional):
                The encoding used when file_content is a string (default: "utf-8").
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
            classifications (list | None, optional):
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
            replace_existing (bool, optional):
                If True, replaces an existing file with the same name in the target folder. If False,
                the upload will fail if a file with the same name already exists.
            show_error (bool, optional):
                If True, treats the upload failure as an error. If False, no error is shown (useful if the file already exists).

        Returns:
            dict | None:
                The response from the upload operation or None if the upload fails.

        """

        # Validate mutually exclusive inputs:
        if file_content is not None and file_url is not None:
            self.logger.error("Provide either file URL or file content for uploading files, not both.")
            return None
        if file_content is None and file_url is None:
            self.logger.error("Provide either file URL or file content for uploading files.")
            return None

        # Handle in-memory file content:
        if file_content is not None:
            if not file_name:
                self.logger.error("Missing file name! Cannot upload in-memory file without a file name.")
                return None

            # Make sure we don't have leading or trailing whitespace:
            file_name = file_name.strip()

            if isinstance(file_content, str):
                # Encode text content to bytes using the provided encoding
                file_bytes = file_content.encode(encoding)
                if not mime_type:
                    mime_type = "text/plain"
            elif isinstance(file_content, bytes):
                file_bytes = file_content
            else:
                self.logger.error("File content must be of type str or bytes! Cannot upload file.")
                return None

            # Use an in-memory byte stream instead of a filesystem file
            file_content = io.BytesIO(file_bytes)

        # Handle file provided via URL or local filesystem
        else:
            if not file_url:
                self.logger.error("Missing file URL! Cannot upload file.")
                return None

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
                    response = requests.get(url=file_url, headers=self.request_download_header(), timeout=1200)
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
            # it and then defer the upload to upload_directory_to_parent():
            elif os.path.exists(file_url) and (
                ((file_url.endswith(".zip") or mime_type == "application/x-zip-compressed") and extract_zip)
                or os.path.isdir(file_url)
            ):
                return self.upload_directory_to_parent(
                    parent_id=parent_id,
                    file_path=file_url,
                    replace_existing=replace_existing,
                )

            elif os.path.exists(file_url):
                self.logger.debug("Uploading local file -> %s", file_url)
                file_content = open(file=file_url, mode="rb")  # noqa: SIM115

            else:
                self.logger.warning("Cannot access file -> '%s'", file_url)
                return None

        # Prepare upload payload:
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
            mime_type, _ = mimetypes.guess_type(file_name)

        if not mime_type and magic_installed and file_url:
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(file_url)
            except Exception:
                self.logger.error(
                    "Unknown mime type for upload of document -> '%s' to parent ID -> %d",
                    file_name,
                    parent_id,
                )

        upload_post_files = [("file", (f"{file_name}", file_content, mime_type))]

        request_url = self.config()["nodesUrlv2"]

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly when the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        self.logger.debug(
            "Upload file -> '%s' with mime type -> '%s' to parent with ID -> %d; calling -> %s",
            file_name,
            mime_type,
            parent_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="upload_directory_to_parent")
    def upload_directory_to_parent(self, parent_id: int, file_path: str, replace_existing: bool = True) -> dict | None:
        """Upload a directory or an uncompressed zip file to Content Server.

        IMPORTANT: if the path ends in a file then we assume it is a ZIP file!

        Args:
            parent_id (int):
                ID of the parent in Content Server.
            file_path (str):
                File system path to the directory or zip file.
            replace_existing (bool, optional):
                If True, existing files are replaced by uploading a new version.

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
                        "%s folder -> '%s' in parent folder with ID -> %d. Resulting ID -> %d",
                        "Created" if created else "Found existing",
                        dir_name,
                        current_parent_id,
                        new_parent_id,
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
                        replace_existing=replace_existing,
                    )
                    if response and not first_response:
                        first_response = response.copy()
                    continue
                # Check if the file already exists:
                response = self.get_node_by_parent_and_name(
                    parent_id=current_parent_id,
                    name=file_name,
                )
                if not response or not response["results"]:
                    # File does not yet exist - upload new document:
                    response = self.upload_file_to_parent(
                        parent_id=current_parent_id,
                        file_url=full_file_path,
                        file_name=file_name,
                    )
                elif replace_existing:
                    # Document does already exist - upload a new version if replace existing is requested:
                    existing_document_id = self.get_result_value(
                        response=response,
                        key="id",
                    )
                    response = self.add_document_version(
                        node_id=int(existing_document_id),
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_document_version")
    def add_document_version(
        self,
        node_id: int,
        file_url: str | None = None,
        file_name: str | None = None,
        mime_type: str | None = None,
        file_content: str | bytes | None = None,
        encoding: str = "utf-8",
        description: str = "",
    ) -> dict | None:
        """Fetch file from URL or local filesystem and upload it as a document version.

        The version data can be provided in one of three ways:
        1. Via a public URL (file_url starting with "http")
        2. Via a local filesystem path (file_url pointing to an existing file or directory)
        3. Via in-memory content using the file_content parameter (str or bytes)

        Args:
            node_id (int):
                The ID of the document to add add version to.
            file_url (str | None, optional):
                URL to download file from or the local file path.
            file_name (str | None, optional):
                The name of the file being uploaded as a new version.
            mime_type (str | None, optional):
                The mime type of the file (e.g., 'application/pdf').
                If the mime type is not provided the method tries to "guess" the mime type.
            file_content (str | bytes | None):
                The file content provided directly in memory. If a string is provided,
                it will be encoded using the specified encoding.
            encoding (str, optional):
                The encoding used when file_content is a string (default: "utf-8").
            description (str, optional):
                The description of the version (default = no description).

        Returns:
            dict | None:
                Add version response or None if the upload fails.

        """

        # Desciption of a version cannot be longer than 255 characters in OTCS:
        if description and len(description) > 255:
            description = description[:255]

        # Validate mutually exclusive inputs:
        if file_content is not None and file_url is not None:
            self.logger.error("Provide either file URL or file content for uploading files, not both.")
            return None
        if file_content is None and file_url is None:
            self.logger.error("Provide either file URL or file content for uploading files.")
            return None

        # Handle in-memory file content:
        if file_content is not None:
            if not file_name:
                self.logger.error("Missing file name! Cannot upload in-memory file without a file name.")
                return None

            # Make sure we don't have leading or trailing whitespace:
            file_name = file_name.strip()

            if isinstance(file_content, str):
                # Encode text content to bytes using the provided encoding
                file_bytes = file_content.encode(encoding)
                if not mime_type:
                    mime_type = "text/plain"
            elif isinstance(file_content, bytes):
                file_bytes = file_content
            else:
                self.logger.error("File content must be of type str or bytes! Cannot upload file.")
                return None

            # Use an in-memory byte stream instead of a filesystem file
            file_content = io.BytesIO(file_bytes)

        # Handle file provided via URL or local filesystem
        else:
            if not file_url:
                self.logger.error("Missing file URL! Cannot upload file.")
                return None

            if not file_name:
                # if path_or_url does not end with a "/"
                # we may get the missing file name from there:
                file_name = os.path.basename(file_url)

            if not file_name:
                self.logger.error("Missing file name! Cannot upload document version.")
                return None

            # Make sure we don't have leading or trailing whitespace:
            file_name = file_name.strip()

            if file_url.startswith("http"):
                # Download file from remote location specified by the file_url parameter
                # this must be a public place without authentication:
                self.logger.debug("Download file from URL -> %s", file_url)

                try:
                    response = requests.get(
                        url=file_url,
                        headers=self.request_download_header(),
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
                self.logger.debug("Upload local file -> '%s' as new version.", file_url)
                file_content = open(file=file_url, mode="rb")  # noqa: SIM115

            else:
                self.logger.warning("Cannot access file -> '%s'", file_url)
                return None

        # Prepare add version payload:
        upload_post_data = {"description": description}

        if not mime_type:
            mime_type, _ = mimetypes.guess_type(file_url)

        if not mime_type and magic_installed and file_url:
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(file_url)
            except Exception:
                self.logger.error(
                    "Unknown mime type for new version of document -> '%s' (%d)",
                    file_name,
                    node_id,
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
            "Upload file -> '%s' with mime type -> '%s' as new version to document with ID -> %d; calling -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_document_versions")
    def get_document_versions(self, node_id: str) -> list | None:
        """Get a list of the document versions of a document node.

        Args:
            node_id (str):
                Node ID of the document.

        Returns:
            list | None:
                The list of document versions.

        Example:
        {
            'links': {'data': {...}},
            'results': [
                {
                    'data': {
                        'versions': {
                            'create_date': '2025-06-07T05:29:22Z',
                            'description': '',
                            'external_create_date': None,
                            'external_identity': '',
                            'external_identity_type': '',
                            'external_modify_date': '2025-06-05T10:06:02',
                            'external_source': 'file_system',
                            'file_create_date': '2025-06-07T05:29:22Z',
                            'file_modify_date': '2025-06-05T10:06:02Z',
                            'file_name': 'OpenText-PPT-Presentation-FY25-LIGHT-FINAL.pptx',
                            'file_size': 4057237,
                            'file_type': 'pptx',
                            'has_generation': False,
                            'id': 107044,
                            'locked': False,
                            'locked_date': None,
                            'locked_user_id': None,
                            'mime_type': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                            'modify_date': '2025-06-07T05:29:22Z',
                            'name': 'OpenText-PPT-Presentation-FY25-LIGHT-FINAL.pptx',
                            'owner_id': 1000,
                            'provider_id': 103563,
                            'version_id': 103564,
                            'version_number': 2,
                            'version_number_major': 0,
                            'version_number_minor': 2,
                            'version_number_name': '2'
                        }
                    }
                }
            ]
        }

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get a list of all versions of document with node ID -> %d; calling -> %s",
            node_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get list of versions of document with node ID -> {}".format(
                str(node_id),
            ),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_document_version")
    def get_document_version(self, node_id: str, version_number: int) -> dict | None:
        """Get a particular version of a document based on the version number.

        The first version (oldest) typically has the number 1.

        Args:
            node_id (str):
                Node ID of the document.
            version_number (int):
                The version number.

        Returns:
            dict | None:
                The version data.

        Example:
        {
            'links': {'data': {...}},
            'results': {
                'data': {
                    'versions': {
                        'create_date': '2025-06-07T05:29:22Z',
                        'description': '',
                        'external_create_date': None,
                        'external_identity': '',
                        'external_identity_type': '',
                        'external_modify_date': '2025-06-05T10:06:02',
                        'external_source': 'file_system',
                        'file_create_date': '2025-06-07T05:29:22Z',
                        'file_modify_date': '2025-06-05T10:06:02Z',
                        'file_name': 'OpenText-PPT-Presentation-FY25-LIGHT-FINAL.pptx',
                        'file_size': 4057237,
                        'file_type': 'pptx',
                        'has_generation': False,
                        'id': 107044,
                        'locked': False,
                        'locked_date': None,
                        'locked_user_id': None,
                        'mime_type': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                        'modify_date': '2025-06-07T05:29:22Z',
                        'name': 'OpenText-PPT-Presentation-FY25-LIGHT-FINAL.pptx',
                        'owner_id': 1000,
                        'provider_id': 103563,
                        'version_id': 103564,
                        'version_number': 2,
                        'version_number_major': 0,
                        'version_number_minor': 2,
                        'version_number_name': '2'
                    }
                }
            }
        }

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions/" + str(version_number)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get version -> %d of document with node ID -> %d; calling -> %s",
            version_number,
            node_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get version -> {} of document with node ID -> {}".format(
                version_number,
                node_id,
            ),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_latest_document_version")
    def get_latest_document_version(self, node_id: int) -> dict | None:
        """Get latest version of a document node based on the node ID.

        Args:
            node_id (int):
                The ID of the document node to get the latest from.

        Returns:
            dict | None:
                The Node information or None if no node with this ID is found.

        """

        # This Method requires V1of the REST API!
        request_url = self.config()["nodesUrl"] + "/" + str(node_id) + "/versions/latest"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get latest version of document with node ID -> %d; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="purge_document_versions")
    def purge_document_versions(self, node_id: int, versions_to_keep: int = 1) -> dict | None:
        """Purge versions of a document based on the node ID of the document.

        Args:
            node_id (int):
                The ID of the document node to purge versions for.
            versions_to_keep (int):
                Number of versions to keep (from the newest to the oldest).
                The minimum allowed number is 1. This is also the default.
                If 1 is provided it means to keep the nerwest version only.

        Returns:
            dict | None:
                The result data or None if the request fails.

        Example:
        {
            'links': {'data': {...}},
            'results': {}
        }

        """

        # Sanity check:
        if versions_to_keep < 1:
            self.logger.error("Purging to less than 1 version is not possible. The value -> %d is not valid!")
            return None

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions"
        request_header = self.request_form_header()

        purge_delete_body = {
            "number_to_keep": versions_to_keep,
        }

        self.logger.debug(
            "Purge document versions down to the newest%s version%s of document with node ID -> %d; calling -> %s",
            " {}".format(versions_to_keep) if versions_to_keep > 1 else "",
            "s" if versions_to_keep > 1 else "",
            node_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="DELETE",
            headers=request_header,
            data=purge_delete_body,
            timeout=None,
            failure_message="Failed to purge to {} versions of document with node ID -> {}".format(
                versions_to_keep,
                str(node_id),
            ),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_document_content")
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
                    "Cannot get latest version of document with ID -> %d",
                    node_id,
                )
            version_number = response["data"]["version_number"]

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions/" + str(version_number) + "/content"
        request_header = self.request_download_header()

        self.logger.debug(
            "Get document with node ID -> %d and version -> %s; calling -> %s",
            node_id,
            str(version_number),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get content of document with node ID -> {}".format(
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_json_document")
    def get_json_document(
        self,
        node_id: int,
        version_number: str = "",
    ) -> list | dict | None:
        """Get document content from Content Server and parse content as JSON.

        Args:
            node_id (int):
                The node ID of the document to download
            version_number (str, optional):
                The version of the document to download.
                If version = "" then download the latest
                version.

        Returns:
            list | dict | None:
                Content of the file or None in case of an error.

        """

        return self.get_document_content(
            node_id=node_id,
            version_number=version_number,
            parse_request_response=True,  # try to parse as JSON
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="download_document")
    def download_document(
        self,
        node_id: int,
        file_path: str,
        version_number: str | int = "",
        chunk_size: int = 8192,
        overwrite: bool = True,
    ) -> bool:
        """Download a document (version) from OTCS to local file system.

        Args:
            node_id (int):
                The node ID of the document to download
            file_path (str):
                The local file path (directory).
            version_number (str | int, optional):
                The version of the document to download.
                If version = "" then download the latest version.
            chunk_size (int, optional):
                The chunk size to use when downloading the document in bytes.
                Default is 8192 bytes.
            overwrite (bool, optional):
                If True, overwrite the file if it already exists. If False, do not overwrite
                and return False if the file already exists.

        Returns:
            bool:
                True if the document has been download to the specified file.
                False otherwise.

        """

        if not version_number:
            # we retrieve the latest version - using V1 REST API. V2 has issues with downloading files:
            request_url = self.config()["nodesUrl"] + "/" + str(node_id) + "/content"
            self.logger.debug(
                "Download document with node ID -> %d (latest version); calling -> %s",
                node_id,
                request_url,
            )
        else:
            # we retrieve the given version - using V1 REST API. V2 has issues with downloading files:
            request_url = (
                self.config()["nodesUrl"] + "/" + str(node_id) + "/versions/" + str(version_number) + "/content"
            )
            self.logger.debug(
                "Download document with node ID -> %d and version number -> %d; calling -> %s",
                node_id,
                version_number,
                request_url,
            )
        request_header = self.request_download_header()

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

        total_size = int(response.headers["Content-Length"]) if "Content-Length" in response.headers else None

        content_encoding = response.headers.get("Content-Encoding", "").lower()
        is_compressed = content_encoding in ("gzip", "deflate", "br")

        self.logger.debug(
            "Downloading document with node ID -> %d to file -> '%s'; total size -> %s bytes; content encoding -> '%s'",
            node_id,
            file_path,
            total_size,
            content_encoding,
        )

        if os.path.exists(file_path) and not overwrite:
            self.logger.warning(
                "File -> '%s' already exists and overwrite is set to False, not downloading document.",
                file_path,
            )
            return False

        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            self.logger.debug(
                "Download directory -> '%s' does not exist, creating it.",
                directory,
            )
            os.makedirs(directory)

        bytes_downloaded = 0
        try:
            with open(file_path, "wb") as download_file:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        download_file.write(chunk)
                        bytes_downloaded += len(chunk)

        except Exception as e:
            self.logger.error(
                "Error while writing content to file -> %s after %d bytes downloaded; error -> %s",
                file_path,
                bytes_downloaded,
                str(e),
            )
            return False

        # if we have a total size and the content is not compressed
        # we can do a sanity check if the downloaded size matches
        # the expected size:
        if total_size and not is_compressed and bytes_downloaded != total_size:
            self.logger.error(
                "Downloaded size (%d bytes) does not match expected size (%d bytes) for file -> '%s'",
                bytes_downloaded,
                total_size,
                file_path,
            )
            return False

        return True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="download_config_file")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="search")
    def search(
        self,
        search_term: str,
        look_for: str = "complexQuery",
        modifier: str = "",
        within: str = "all",
        slice_id: int = 0,
        query_id: int = 0,
        template_id: int = 0,
        location_id: int | list[int] | None = None,
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
            within (str, optional):
                The scope of the search. Possible values are:
                - 'all': search in content and in metadata (default)
                - 'content': search only in document content
                - 'metadata': search only in item metadata
            slice_id (int, optional):
                The ID of an existing search slice.
            query_id (int, optional):
                The ID of a saved search query.
            template_id (int, optional):
                The ID of a saved search template.
            location_id (int | None, optional):
                The ID of a folder or workspace to start a search from here.
                None = unrestricted search (default).
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
            "within": within,
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
        if location_id is not None:
            if isinstance(location_id, int):
                search_post_body["location_id1"] = location_id
            else:
                for idx, loc_id in enumerate(location_id, start=1):
                    search_post_body["location_id" + str(idx)] = loc_id

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
        within: str = "all",
        slice_id: int = 0,
        query_id: int = 0,
        template_id: int = 0,
        location_id: int | None = None,
        page_size: int = 100,
        limit: int | None = None,
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
            within (str, optional):
                The scope of the search. Possible values are:
                - 'all': search in content and in metadata (default)
                - 'content': search only in document content
                - 'metadata': search only in item metadata
            slice_id (int, optional):
                The ID of an existing search slice.
            query_id (int, optional):
                The ID of a saved search query.
            template_id (int, optional):
                The ID of a saved search template.
            location_id (int | None, optional):
                The ID of a folder or workspace to start a search from here.
                None = unrestricted search (default).
            page_size (int, optional):
                The maximum number of results to return. Default is 100.
                For the iterator this is basically the chunk size.
            limit (int | None = None), optional):
                The maximum number of results to return in total.
                If None (default) all results are returned.
                If a number is provided only up to this number of results is returned.

        Returns:
            iter:
                The search response iterator object.

        """

        page = 1
        remaining = limit

        while True:
            effective_limit = min(page_size, remaining) if remaining is not None else page_size

            response = self.search(
                search_term=search_term,
                look_for=look_for,
                modifier=modifier,
                within=within,
                slice_id=slice_id,
                query_id=query_id,
                template_id=template_id,
                location_id=location_id,
                limit=effective_limit,
                page=page,
            )

            results = response.get("results") if response else None
            if not results:
                return  # natural iterator termination

            yield from results

            if remaining is not None:
                remaining -= len(results)
                if remaining <= 0:
                    return

            # Fewer results than requested means this was the last page
            if len(results) < effective_limit:
                return

            page += 1
        # end while True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_external_system_connection")
    def get_external_system_connection(
        self,
        connection_name: str,
        show_error: bool = False,
    ) -> dict | None:
        """Get external system connection (e.g. SAP, Salesforce, SuccessFactors).

        Args:
            connection_name (str):
                The name of the connection to an external system.
            show_error (bool, optional):
                If True, treat as error if connection is not found.

        Returns:
            dict | None:
                External system Details or None if the REST call fails.

        """
        # Encode special characters in connection_name
        connection_name = connection_name.replace("\\", "0xF0A6").replace("/", "0xF0A7")
        request_url = self.config()["externalSystemUrl"] + "/" + connection_name + "/config"
        request_header = self.cookie()

        self.logger.debug(
            "Get external system connection -> '%s'; calling -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_external_system_connection")
    def add_external_system_connection(
        self,
        connection_name: str,
        connection_type: str,
        as_url: str,
        base_url: str,
        username: str,
        password: str,
        authentication_method: str = "BASIC",
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
            client_id (str | None, optional):
                The OAUTH Client ID (only required if authenticationMethod = OAUTH).
            client_secret (str | None, optional):
                OAUTH Client Secret (only required if authenticationMethod = OAUTH).

        Returns:
            dict | None:
                External system Details or None if the REST call fails.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_transport_workbench")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="unpack_transport_package")
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
            "Unpack transport package with ID -> %d into workbench with ID -> %d; calling -> %s",
            package_id,
            workbench_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="deploy_workbench")
    def deploy_workbench(self, workbench_id: int) -> tuple[dict | None, int]:
        """Deploy an existing Workbench.

        Args:
            workbench_id (int):
                The ID of the workbench to be deployed.

        Returns:
            dict | None:
                The deploy response or None if the deployment fails.
            int:
                Error count. Should be 0 if fully successful.

        Example response:
        {
            'links': {
                'data': {
                    'self': {
                        'body': '',
                        'content_type': '',
                        'href': '/api/v2/nodes/97559/deploy',
                        'method': 'POST',
                        'name': ''
                    }
                }
            },
            'results': {
                'data': {
                    'status': {
                        'error_count': 0,
                        'errors': [...],
                        'success_count': 79,
                        'total_count': 79
                    }
                }
            }
        }

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(workbench_id) + "/deploy"
        request_header = self.request_form_header()

        self.logger.debug(
            "Deploy workbench with ID -> %d; calling -> %s",
            workbench_id,
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            timeout=None,
            failure_message="Failed to deploy workbench with ID -> {}".format(
                workbench_id,
            ),
        )

        # Transport packages canalso partly fail to deploy.
        # For such cases we determine the number of errors.
        error_count = 0

        if not response or "results" not in response:
            return (None, 0)

        try:
            error_count = response["results"]["data"]["status"]["error_count"]
            if error_count > 0:
                self.logger.error(
                    "%d error%s occoured during workbench deployment", error_count, "s" if error_count > 1 else ""
                )
            else:
                success_count = response["results"]["data"]["status"]["success_count"]
                self.logger.info(
                    "Transport successfully deployed %d workbench items.",
                    success_count,
                )

            for error in response["results"]["data"]["status"]["errors"]:
                self.logger.error(
                    "Failed to deploy workbench item -> '%s' (%s); error -> %s",
                    error["name"],
                    error["id"],
                    error["error"],
                )

        except Exception as e:
            self.logger.debug(str(e))

        return (response, error_count)

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="deploy_transport")
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
            replacements (list[dict] | None, optional):
                List of replacement values to be applied to all XML files in the transport.
                Each dictionary must contain:
                - 'placeholder': text to replace
                - 'value': text to replace with
            extractions (list[dict] | None, optional):
                List of XML subtrees to extract from each XML file in the transport.
                Each dictionary must contain:
                - 'xpath': defining the subtree to extract
                - 'enabled': True if the extraction is active

        Returns:
            dict | None:
                Deploy response as a dictionary if successful, or None if the deployment fails.

        """

        trace.get_current_span().set_attributes(
            {
                "package.url": package_url,
                "package.name": package_name,
            }
        )

        if replacements is None:
            replacements = []
        if extractions is None:
            extractions = []

        while not self.is_ready():
            self.logger.info(
                "OTCS is not ready. Cannot deploy transport -> '%s' to OTCS. Waiting 30 seconds and retry...",
                package_name,
            )
            time.sleep(30)

        # Preparation: get volume IDs for Transport Warehouse (root volume and Transport Packages)
        response = self.get_volume(volume_type=self.VOLUME_TYPE_TRANSPORT_WAREHOUSE)
        transport_root_volume_id = self.get_result_value(response=response, key="id")
        if not transport_root_volume_id:
            self.logger.error("Failed to retrieve transport root volume!")
            return None
        self.logger.debug(
            "Transport root volume ID -> %d",
            transport_root_volume_id,
        )

        response = self.get_node_by_parent_and_name(
            parent_id=transport_root_volume_id,
            name="Transport Packages",
        )
        transport_package_volume_id = self.get_result_value(response=response, key="id")
        if not transport_package_volume_id:
            self.logger.error("Failed to retrieve transport package volume!")
            return None
        self.logger.debug(
            "Transport package volume ID -> %d",
            transport_package_volume_id,
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
                "Transport package -> '%s' does already exist; existing package ID -> %d.",
                package_name,
                package_id,
            )
        else:
            self.logger.debug(
                "Transport package -> '%s' does not yet exist, loading from -> '%s'...",
                package_name,
                package_url,
            )
            # If we have string replacements configured execute them now:
            if replacements:
                self.logger.debug(
                    "Transport -> '%s' has replacements -> %s.",
                    package_name,
                    str(replacements),
                )
                self.replace_transport_placeholders(
                    zip_file_path=package_url,
                    replacements=replacements,
                )
            else:
                self.logger.debug(
                    "Transport -> '%s' has no replacements.",
                    package_name,
                )
            # If we have data extractions configured execute them now:
            if extractions:
                self.logger.debug(
                    "Transport -> '%s' has extractions -> %s.",
                    package_name,
                    str(extractions),
                )
                self.extract_transport_data(
                    zip_file_path=package_url,
                    extractions=extractions,
                )
            else:
                self.logger.debug("Transport -> '%s' has no extractions.", package_name)

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
                    "Failed to upload transport package -> '%s'!",
                    package_url,
                )
                return None
            self.logger.debug(
                "Successfully uploaded transport package -> '%s'; new package ID -> %d",
                package_name,
                package_id,
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
                "Workbench -> '%s' has already been deployed successfully; existing workbench ID -> %d; skipping transport",
                workbench_name,
                workbench_id,
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
                    "Workbench -> '%s' does already exist but is not successfully deployed; existing workbench ID -> %d.",
                    workbench_name,
                    workbench_id,
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
                    "Successfully created workbench -> '%s'; new workbench ID -> %d.",
                    workbench_name,
                    workbench_id,
                )

        # Step 3: Unpack Transport Package to Workbench
        self.logger.debug(
            "Unpack transport package -> '%s' (%d) to workbench -> '%s' (%d)...",
            package_name,
            package_id,
            workbench_name,
            workbench_id,
        )
        response = self.unpack_transport_package(
            package_id=package_id,
            workbench_id=workbench_id,
        )
        if not response:
            self.logger.error(
                "Failed to unpack the transport package -> '%s'!",
                package_name,
            )
            return None
        self.logger.debug(
            "Successfully unpackaged to workbench -> '%s' (%s).",
            workbench_name,
            str(workbench_id),
        )

        # Step 4: Deploy Workbench
        self.logger.debug(
            "Deploy workbench -> '%s' (%s)...",
            workbench_name,
            str(workbench_id),
        )
        response, errors = self.deploy_workbench(workbench_id=workbench_id)
        if not response or errors > 0:
            self.logger.error(
                "Failed to deploy workbench -> '%s' (%s)!%s",
                workbench_name,
                str(workbench_id),
                " {} error{} occured during deployment.".format(errors, "s" if errors > 1 else "")
                if errors > 0
                else "",
            )
            return None

        self.logger.debug(
            "Successfully deployed workbench -> '%s' (%s).",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="replace_transport_placeholders")
    def replace_transport_placeholders(
        self,
        zip_file_path: str,
        replacements: list,
    ) -> bool:
        """Search and replace strings in the XML files of the transport package.

        Args:
            zip_file_path (str):
                Path to transport zip file.
            replacements (list[dict]):
                List of replacement values; dict needs to have two values:
                - placeholder: The text to replace.
                - value: The replacement text.

        Returns:
            bool:
                True = success, False = error.

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
                    "Replace -> %s with -> %s in transport package -> %s",
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
                    "Replacement -> %s has been completed successfully for transport package -> '%s'.",
                    replacement,
                    zip_file_folder,
                )
                modified = True
            else:
                self.logger.warning(
                    "Replacement -> %s not found in transport package -> '%s'!",
                    replacement,
                    zip_file_folder,
                )

        if not modified:
            self.logger.warning(
                "None of the specified replacements have been found in transport package -> %s. No need to create a new transport package.",
                zip_file_folder,
            )
            return False

        # Create the new zip file and add all files from the directory to it
        new_zip_file_path = os.path.dirname(zip_file_path) + "/new_" + os.path.basename(zip_file_path)
        self.logger.debug(
            "Content of transport -> '%s' has been modified - repacking to new zip file -> '%s'...",
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
            "Rename orginal transport zip file -> '%s' to -> '%s'...",
            zip_file_path,
            old_zip_file_path,
        )
        os.rename(zip_file_path, old_zip_file_path)
        self.logger.debug(
            "Rename new transport zip file -> '%s' to -> '%s'...",
            new_zip_file_path,
            zip_file_path,
        )
        os.rename(new_zip_file_path, zip_file_path)

        # Return success
        return True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="extract_transport_data")
    def extract_transport_data(self, zip_file_path: str, extractions: list) -> bool:
        """Search and extract XML data from the transport package.

        Args:
            zip_file_path (str):
                Path to transport zip file.
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
            self.logger.error("Zip file -> '%s' not found!", zip_file_path)
            return False

        # Extract the zip file to a temporary directory
        zip_file_folder = os.path.splitext(zip_file_path)[0]
        with zipfile.ZipFile(zip_file_path, "r") as zfile:
            zfile.extractall(zip_file_folder)

        # Extract data from all XML files in the directory and its subdirectories
        for extraction in extractions:
            if "xpath" not in extraction:
                self.logger.error(
                    "Extraction needs an xpath but it is not specified! Skipping...",
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
                "Using xpath -> %s to extract the data.",
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
                    "Extraction with xpath -> %s has been successfully completed for transport package -> '%s'.",
                    xpath,
                    zip_file_folder,
                )
                # Add the extracted elements to the extraction data structure (dict).
                extraction["data"] = extracted_data
            else:
                self.logger.warning(
                    "Extraction with xpath -> %s has not delivered any data for transport package -> '%s'!",
                    xpath,
                    zip_file_folder,
                )
                extraction["data"] = []

        # Return the path to the new zip file
        return True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_business_object_types")
    def get_business_object_types(self) -> dict | None:
        """Get information for all configured business object types.

        Args:
            None

        Returns:
            dict | None:
                Business Object Types information (for all external systems)
                or None if the request fails.

        Example:
        {
            'links': {
                'data': {
                    'self': {
                        'body': '',
                        'content_type': '',
                        'href': '/api/v2/businessobjecttypes',
                        'method': 'GET',
                        'name': ''
                    }
                }
            },
            'results': [
                {
                    'data': {
                        'properties': {
                            'bo_type': 'account',
                            'bo_type_id': 54,
                            'bo_type_name': 'gw.account',
                            'ext_system_id': 'Guidewire Policy Center',
                            'is_default_Search': True,
                            'workspace_type_id': 33
                        }
                    }
                },
                ...
            ]
        }

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_business_object_types_iterator")
    def get_business_object_types_iterator(self) -> iter:
        """Get an iterator object to traverse all business object types.

        Returning a generator avoids loading a large number of workspace instances
        at once. Instead you can iterate over the potential large list of subnodes.

        Example usage:
            ```python
            business_object_types = otcs_object.get_business_object_types_iterator()
            for business_object_type in business_object_types:
                bo_type_id = otcs_object.get_result_value(response=business_object_type, key="bo_type_id")
                bo_type_name = otcs_object.get_result_value(response=business_object_type, key="bo_type_name")
                bo_type_system_id = otcs_object.get_result_value(response=business_object_type, key="ext_system_id")
                bo_type_workspace_type_id = otcs_object.get_result_value(response=business_object_type, key="workspace_type_id")
            ```

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

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get business object types",
        )

        if not response or "results" not in response:
            return

        yield from response["results"]

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_business_object_type_old")
    def get_business_object_type_old(
        self,
        external_system_id: str,
        type_name: str,
        expand_workspace_type: bool = True,
        expand_external_system: bool = True,
    ) -> dict | None:
        """Get business object type information.

        This REST API is pretty much limited.
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_business_object_type")
    def get_business_object_type(self, type_id: int) -> dict | None:
        """Get information for all configured business object types.

        This method uses an REST endpoint that was only introduced in OTCS 25.3.

        Args:
            type_id (int):
                The ID of the business object type to retrieve.

        Returns:
            dict | None:
                Workspace Types information (for all external systems)
                or None if the request fails.

        Example:
        {
            'links': {'data': {...}},
            'results': {
                'GeneralTab': {
                    'data': {
                        'properties': {
                            'fBoTypeInUse': True,
                            'fCrossAppRelationMappings': None,
                            'fDocTypeAttachment': {
                                'attachmentDeclaration': [
                                    {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...},
                                    ...
                                ],
                                'botypeAttacheValues': [],
                                'ok': True
                            },
                            'fFieldConfigs': {
                                'AUTO_KEYDEF': {
                                    'fieldLength': 32,
                                    'label': 'AUTO_KEYDEF',
                                    'readonly': False,
                                    'showAsType': 0,
                                    'value': None
                                },
                                ...
                                'WKSP_TYPE_NODE_ID': {
                                    'fieldLength': 32,
                                    'label': 'WKSP_TYPE_NODE_ID',
                                    'readonly': False,
                                    'showAsType': 1,
                                    'value': 27883
                                }
                            },
                            'fInlineWSTEnable': True,
                            'fWkspCreationConfig': {
                                'boCallbacks': [{...}, {...}, {...}],
                                'documenttypes': [],
                                'multilinguals': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}],
                                'propertyGroups': {
                                    'accountHolder': {
                                        'cat_cb_name': 'CategorySet',
                                        'cat_cb_parm': '22658',
                                        'mappings': [
                                            {
                                                'bo_prop_name': 'displayName',
                                                'att_name': 'Name'
                                            },
                                            {
                                                'bo_prop_name': 'type',
                                                'att_name': 'Type'
                                            }
                                        ],
                                        'set_name': 'Account Holder'
                                    },
                                    'accountStatus': {
                                        'cat_cb_name': 'CategorySet',
                                        'cat_cb_parm': '22658',
                                        'mappings': [{...}],
                                        'set_name': 'Account Status'
                                    },
                                    'industryCode': {...},
                                    'organizationType': {...}
                                },
                                'propertyMappings': [
                                    {
                                        'bo_prop_name': 'accountNumber',
                                        'cat_cb_name': 'CategoryAttribute',
                                        'cat_cb_parm': '22658',
                                        'set_name': None,
                                        'att_name': 'Account No'
                                    },
                                    {...}, {...}, {...}, {...}
                                ]
                            },
                            'ID_BO_TYPE': 41
                        }
                    },
                    'errMsg': '',
                    'ok': True
                },
                'S4HanaTab': {...}
            }
        }

        """

        request_url = self.config()["businessObjectTypesUrl"] + "/" + str(type_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get business object type with ID -> %d; calling -> %s",
            type_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get business object type -> {}".format(type_id),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_business_objects")
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
            limit (int | None, optional):
                The maximum number of result items.
            page (int | None, optional):
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_business_objects_search")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_types")
    def get_workspace_types(
        self,
        expand_workspace_info: bool = True,
        expand_templates: bool = True,
        show_error: bool = True,
    ) -> dict | None:
        """Get all workspace types configured in OTCS.

        This REST API is very limited. It does not return all workspace type properties
        you can see in OTCS business admin page.

        This endpoint may throw an HTTP 500 error if no workspace types are in OTCS.

        Args:
            expand_workspace_info (bool, optional):
                Controls if the workspace info is returned as well
            expand_templates (bool, optional):
                Controls if the list of workspace templates
                per workspace type is returned as well
            show_error (bool, optional):
                Controls if errors are shown to the caller. Defaults to True.
                If no workspace types are configured in OTCS the endpoint may
                return an HTTP 500 error. In such a case you may want to
                set this parameter to False to avoid error messages in the log.

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

        query = {"expand_templates": expand_templates, "expand_wksp_info": expand_workspace_info}

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["businessWorkspaceTypesUrlv2"] + "?{}".format(encoded_query)
        request_header = self.request_form_header()

        self.logger.debug("Get workspace types; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workspace types with URL -> {}".format(request_url),
            show_error=show_error,
        )

    # end method definition

    def get_workspace_types_iterator(self, expand_workspace_info: bool = True, expand_templates: bool = True) -> iter:
        """Get an iterator object to traverse all workspace types.

        Args:
            expand_workspace_info (bool, optional):
                Controls if the workspace info is returned as well
            expand_templates (bool, optional):
                Controls if the list of workspace templates
                per workspace type is returned as well
        Returns:
            iter:
                An iterator to traverse all workspace types.
        Example usage:
            ```python
            workspace_types = otcs_object.get_workspace_types_iterator()
            for workspace_type in workspace_types:
                wksp_type_id = otcs_object.get_result_value(response=workspace_type, key="wksp_type_id")
                wksp_type_name = otcs_object.get_result_value(response=workspace_type, key="wksp_type_name")
            ```

        """

        response = self.get_workspace_types(
            expand_workspace_info=expand_workspace_info, expand_templates=expand_templates
        )
        if not response or "results" not in response:
            self.logger.warning("Failed to get workspace types or no results found.")
            return

        yield from response["results"]

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_type_by_name")
    def get_workspace_type_by_name(self, type_name: str) -> dict | None:
        """Get information for a given workspace type.

        This is a convinience method. It's implementation is potentially
        inefficent as it traverse the full list of workspace types and
        finds the matching one by name comparison.

        Args:
            type_name (str):
                The name of the workspace type to retrieve.

        Returns:
            dict | None:
                Workspace Type information or None if the request fails.

        """

        workspace_types = self.get_workspace_types_iterator()
        for workspace_type in workspace_types:
            workspace_type_name = self.get_result_value(response=workspace_type, key="wksp_type_name")
            if workspace_type_name.lower() == type_name.lower():
                return workspace_type

        return None

    # end method definition

    @cache
    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_type")
    def get_workspace_type(
        self,
        type_id: int,
    ) -> dict | None:
        """Get workspace type configured in OTCS.

        This REST API is very basic. It mainly delivers the type name for the type ID.
        It is a V1 API. Thus the response cannot be processed by the get_result_value()
        method. There's also a get_workspace_type_by_name() below.

        Args:
            type_id (int):
                The workspace type ID.

        Returns:
            dict | None:
                Workspace Types or None if the request fails.

        Example:
            {
                'icon_url': '/cssupport/otsapxecm/wksp_contract_cust.png',
                'is_policies_enabled': False,
                'workspace_type': 'Sales Contract'
            }

        """

        request_url = self.config()["businessWorkspaceTypesUrl"] + "/" + str(type_id)

        request_header = self.request_form_header()

        self.logger.debug("Get workspace type with ID -> %d; calling -> %s", type_id, request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workspace type with ID -> {}".format(type_id),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_type_name")
    def get_workspace_type_name(self, type_id: int) -> str | None:
        """Get the name of a workspace type based on the provided workspace type ID.

        The name is taken from a OTCS object variable self._workspace_type_lookup if recorded there.
        If not yet derived it is determined via the REST API and then stored
        in self._workspace_type_lookup (as a lookup cache).

        Args:
            type_id (int):
                The workspace type ID.

        Returns:
            str | None:
                The name of the workspace type. Or None if the type ID
                was ot found.

        Side effects:
            Caches the workspace type name in self._workspace_type_lookup
            for future calls.

        """

        workspace_type = self._workspace_type_lookup.get(type_id)
        if workspace_type:
            return workspace_type.get("name")

        workspace_type = self.get_workspace_type(type_id=type_id)
        type_name = workspace_type.get("workspace_type")
        if type_name:
            # Update the lookup cache:
            self._workspace_type_lookup[type_id] = {"location": None, "name": type_name}
            return type_name

        return None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_type_by_name")
    def get_workspace_type_names(self, lower_case: bool = False, renew: bool = False) -> list[str] | None:
        """Get a list of all workspace type names.

        Args:
            lower_case (bool):
                Whether to return the names in lower case.
            renew (bool):
                Whether to renew the cached workspace type names.

        Returns:
            list[str] | None:
                List of workspace type names or None if the request fails.

        Side effects:
            Caches the workspace type names in self._workspace_type_names
            for future calls.

        """

        if self._workspace_type_names and not renew:
            return self._workspace_type_names

        workspace_types = self.get_workspace_types_iterator()
        workspace_type_names = [
            self.get_result_value(response=workspace_type, key="wksp_type_name") for workspace_type in workspace_types
        ]
        if lower_case:
            workspace_type_names = [name.lower() for name in workspace_type_names]

        # Update the cache:
        self._workspace_type_names = workspace_type_names

        return workspace_type_names

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_workspace_type_relations")
    def update_workspace_type_relations(
        self,
        type_id: int,
        relations: list[dict],
    ) -> dict | None:
        """Update workspace type configured in OTCS.

        Currently its main purpose is to update the onotology relations
        for a given workspace type.

        This method can only be used with OTCM 26.2 or newer!

        Args:
            type_id (int):
                The workspace type ID.
            relations (list[dict]):
                List of ontology relations to set for the workspace type.
                This is a list of dictionaries with the following structure:
                {
                    "target_wksp_type_id": int,
                    "rel_type": either "child" or "parent"
                    "predicates": list of predicate strings,
                }

        Returns:
            dict | None:
                Workspace Types or None if the request fails.

        """

        request_url = self.config()["businessWorkspaceTypesUrlv2"] + "/" + str(type_id)
        request_header = self.request_form_header()

        workspace_type_put_body = {"relations": relations}

        self.logger.debug("Update workspace type with ID -> %d; calling -> %s", type_id, request_url)

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            #            data=workspace_type_put_body,
            data={"body": json.dumps(workspace_type_put_body)},
            timeout=None,
            failure_message="Failed to update workspace type with ID -> {}".format(type_id),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_templates")
    def get_workspace_templates(
        self, type_id: int | None = None, type_name: str | None = None
    ) -> tuple[int | None, list | None]:
        """Get the workspace type with a list of workspace templates for a workspace type.

        The type can be provided either by name or ID.

        Args:
            type_id (int | None, optional):
                The type ID.
            type_name (str | None, optional):
                The type name.

        Returns:
            int | None:
                ID of the workspace type
            list | None:
                List of templates.

        """

        if not type_id and not type_name:
            self.logger.error("No workspace type ID or name provided. Cannot get workspace templates.")
            return (None, None)

        response = self.get_workspace_types(expand_workspace_info=True, expand_templates=True)
        if not response or not response.get("results"):
            return (None, None)

        workspace_types = self.get_result_values_iterator(response=response)
        for workspace_type in workspace_types:
            workspace_type_name = workspace_type.get("wksp_type_name")
            workspace_type_id = workspace_type.get("wksp_type_id")

            if (type_id and workspace_type_id == type_id) or (
                type_name and workspace_type_name.lower() == type_name.lower()
            ):
                workspace_templates = workspace_type.get("templates")
                return (workspace_type_id, workspace_templates)

        return (None, None)

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_create_form")
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
            "Get workspace create form for workspace template ID -> %d; calling -> %s",
            template_id,
            request_url,
        )

        if parent_id:
            failure_message = "Failed to get workspace create form for template -> {} and parent ID -> {}".format(
                template_id,
                parent_id,
            )
        else:
            failure_message = (
                "Failed to get workspace create form for template with ID -> {} (called without parent ID)".format(
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace")
    def get_workspace(
        self,
        node_id: int,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
    ) -> dict | None:
        """Get a workspace based on the node ID.

        Args:
            node_id (int):
                The node ID of the workspace to retrieve.
            fields (str | list, optional):
                Which fields to retrieve. This can have a significant
                impact on performance.
                Possible fields include:
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "business_properties" (all the information for the business object and the external system)
                - "categories" (the category data of the workspace item)
                - "workspace_references" (a list with the references to business objects in external systems)
                - "display_urls" (a list with the URLs to external business systems)
                - "wksp_info" (currently just the icon information of the workspace)
                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".
            metadata (bool, optional):
                Whether to return metadata (data type, field length, min/max values,...)
                about the data.
                Metadata will be returned under `results.metadata`, `metadata_map`,
                or `metadata_order`.

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
                                'business_object_id': '0000010020',
                                'business_object_type': 'LFA1',
                                'business_object_type_id': 30,
                                'business_object_type_name': 'Vendor',
                                'business_object_type_name_multilingual': {'ar': '', 'de': 'Lieferant', 'en': 'Vendor', 'es': '', 'fr': 'Fournisseur', 'it': 'Fornitore', 'iw': '', 'ja': 'ベンダー', 'nl': ''},
                                'display_url': 'https://fiori.example.com:8443/sap/bc/ui5_ui5/ui2/ushell/shells/abap/FioriLaunchpad.html?sap-client=600&sap-language=EN#Supplier-displayFactSheet?Supplier=0000010020',
                                'external_system_id': 'TE1',
                                'external_system_name': 'TE1',
                                'has_default_display': True,
                                'has_default_search': True,
                                'isEarly': False,
                                'workspace_type_id': 37,
                                'workspace_type_name': 'Vendor',
                                'workspace_type_name_multilingual': {'ar': '', 'de': 'Lieferant', 'en': 'Vendor', 'es': '', 'fr': 'Fournisseur', 'it': 'Fornitore', 'iw': '', 'ja': 'ベンダー', 'nl': ''},
                                'workspace_type_widget_icon_content': '/appimg/ot_bws/icons/24643%2Esvg?v=161696_1252'
                            }
                            'properties': {
                                'advanced_versioning': None,
                                'classification_id': 0,
                                'classification_ids': [18003],
                                'container': True,
                                'container_size': 9,
                                'create_date': '2025-06-30T01:14:59',
                                'create_user_id': 18095,
                                'description': '',
                                'description_multilingual': {'ar': '', 'de': '', 'en': '', 'es': '', 'fr': '', 'it': '', 'iw': '', 'ja': '', 'nl': ''},
                                'external_create_date': None,
                                'external_identity': '',
                                'external_identity_type': '',
                                'external_modify_date': None,
                                'external_source': '',
                                'favorite': False,
                                'guid': None,
                                'hidden': False,
                                'icon': '/cssupport/otsapxecm/wksp_vendor.png',
                                'icon_large': '/cssupport/otsapxecm/wksp_vendor_large.png',
                                'id': 28866,
                                'image_url': '/appimg/ot_bws/icons/24643%2Esvg?v=161696_1252',
                                'modify_date': '2025-06-30T01:47:35',
                                'modify_user_id': 18095,
                                'name': 'C.E.B. Berlin SE (10020)',
                                'name_multilingual': {'ar': '', 'de': '', 'en': 'C.E.B. Berlin SE (10020)', 'es': '', 'fr': '', 'it': '', 'iw': '', 'ja': '', 'nl': ''},
                                'owner_group_id': 17978,
                                'owner_user_id': 18095,
                                'parent_id': 23676,
                                'reserved': False,
                                'reserved_date': None,
                                'reserved_user_id': 0,
                                'rm_enabled': True,
                                'status': None,
                                'type': 848,
                                'type_name': 'Business Workspace',
                                'versionable': False,
                                'versions_control_advanced': False,
                                'volume_id': -2000,
                                'wksp_type_name': 'Vendor',
                                'xgov_workspace_type': ''
                            }
                            'display_urls': [
                                {
                                    'business_object_type': 'LFA1',
                                    'business_object_type_id': 30,
                                    'business_object_type_name': 'Customer',
                                    'displayUrl': '/sap/bc/gui/sap/its/webgui?~logingroup=SPACE&~transaction=%2fOTX%2fRM_WSC_START_BO+KEY%3dpc%3AS3XljqcFfD0pakDIjUKul%3bOBJTYPE%3daccount&~OkCode=ONLI',
                                    'external_system_id': 'TE1',
                                    'external_system_name': 'SAP S/4HANA'
                                }
                            ]
                            'wksp_info':
                            {
                                'wksp_type_icon': '/appimg/ot_bws/icons/16634%2Esvg?v=161194_13949'
                            }
                            'workspace_references': [
                                {
                                    'business_object_id': '0000010020',
                                    'business_object_type': 'LFA1',
                                    'business_object_type_id': 30,
                                    'external_system_id': 'TE1',
                                    'has_default_display': True,
                                    'has_default_search': True,
                                    'workspace_type_id': 37
                                }
                            ]
                        },
                        'metadata': {...},
                        'metadata_order': {
                            'categories': ['16878']
                        }
                    }
                ],
            }
            ```

        """

        query = {}
        if fields:
            query["fields"] = fields

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(node_id)
        if encoded_query:
            request_url += "?" + encoded_query
            if metadata:
                request_url += "&metadata"
        elif metadata:
            request_url += "?metadata"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace with ID -> %d; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_instances")
    def get_workspace_instances(
        self,
        type_name: str | None = None,
        type_id: int | None = None,
        name: str | None = None,
        column_query: str | None = None,
        expanded_view: bool = True,
        sort: str | None = None,
        page: int | None = None,
        limit: int | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
    ) -> dict | None:
        """Get all workspace instances of a given type.

        This is a convenience wrapper method for get_workspace_by_type_and_name()

        The workspace type must be provided either as the type ID or the type name.
        If both, the type name and type ID are provided the type name takes preference
        and the type ID is ignored. This may not be what you want.

        Args:
            type_name (str | None, optional):
                The name of the workspace type. CAREFUL: the REST API seems to apply
                a "starts with" filter, e.g. if you have two workspace types called
                "Product" and "Product Version" then workspaces instances of both types
                are returned if you provide "Product" for type_name !
                Preferrable use type_id if you can!
            type_id (int | None, optional):
                The ID of the workspace_type.
            name (str, optional):
                Name of the workspace, if None then deliver all instances
                of the given workspace type. If the name is provided
                the prefixes 'contains_' and 'startswith_' are supported
                like 'contains_Test' to find workspace that have 'Test'
                in their name.
            column_query (str | None, optional):
                Specific query for custom columns (if columns are configured
                for the folder the workspaces are in).
            expanded_view (bool, optional):
                If False, then just search in recently accessed business workspace
                for this name and type.
                If True, (this is the default) then search in all
                workspaces for this name and type.
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Default is None.
            limit (int | None, optional):
                The maximum number of workspace instances that should be delivered
                in one page.
                The default is None, in this case the internal OTCS limit
                seems to be 500.
            page (int | None, optional):
                The page to be returned (if more workspace instances exist
                than given by the page limit).
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
            metadata (bool, optional):
                Whether to return metadata (data type, field length, min/max values,...)
                about the data.
                Metadata will be returned under `results.metadata`, `metadata_map`,
                or `metadata_order`.

        Returns:
            dict | None:
                Workspace information or None if the workspace is not found.

        """

        # Omitting the name lets it return all instances of the type:
        return self.get_workspace_by_type_and_name(
            type_name=type_name,
            type_id=type_id,
            name=name,
            column_query=column_query,
            expanded_view=expanded_view,
            sort=sort,
            page=page,
            limit=limit,
            fields=fields,
            metadata=metadata,
        )

    # end method definition

    def get_workspace_instances_iterator(
        self,
        type_name: str | None = None,
        type_id: int | None = None,
        name: str | None = None,
        column_query: str | None = None,
        expanded_view: bool = True,
        sort: str | None = None,
        page_size: int = 100,
        limit: int | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
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
            name (str, optional):
                Name of the workspace, if None then deliver all instances
                of the given workspace type. If the name is provided
                the prefixes 'contains_' and 'startswith_' are supported
                like 'contains_Test' to find workspace that have 'Test'
                in their name.
            column_query (str | None, optional):
                Specific query for custom columns (if columns are configured
                for the folder the workspaces are in).
            expanded_view (bool, optional):
                If False, then just search in recently accessed business workspace
                for this name and type.
                If True, (this is the default) then search in all workspaces for this name and type.
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Default is None.
            page_size (int | None, optional):
                The maximum number of workspace instances that should be delivered in one page.
                The default is 100. If None is given then the internal OTCS limit seems to be 500.
            limit (int | None, optional):
                The maximum number of workspaces to return in total.
                If None (default) all workspaces are returned.
                If a number is provided only up to this number of results is returned.
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
            metadata (bool, optional):
                Whether to return metadata (data type, field length, min/max values,...)
                about the data.
                Metadata will be returned under `results.metadata`, `metadata_map`,
                or `metadata_order`.

        Returns:
            iter:
                A generator yielding one workspace instance per iteration.
                If the REST API fails, returns no value.

        """

        page = 1
        remaining = limit

        while True:
            effective_limit = min(page_size, remaining) if remaining is not None else page_size
            # Get the next page of sub node items:
            response = self.get_workspace_by_type_and_name(
                type_name=type_name,
                type_id=type_id,
                name=name,
                column_query=column_query,
                expanded_view=expanded_view,
                sort=sort,
                limit=effective_limit,
                page=page,
                fields=fields,
                metadata=metadata,
            )

            results = response.get("results") if response else None
            if not results:
                return  # natural iterator termination

            yield from results

            if remaining is not None:
                remaining -= len(results)
                if remaining <= 0:
                    return

            # Fewer results than requested means this was the last page
            if len(results) < effective_limit:
                return

            page += 1
        # end while True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_by_type_and_name")
    def get_workspace_by_type_and_name(
        self,
        type_name: str = "",
        type_id: int | None = None,
        name: str | None = None,
        column_query: str | None = None,
        expanded_view: bool = True,
        sort: str | None = None,
        limit: int | None = None,
        page: int | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
        timeout: float = REQUEST_TIMEOUT,
    ) -> dict | None:
        """Lookup workspaces based on workspace type and workspace name.

        There can be multiple workspaces in the result. This depends on
        the provided combination of workspace type and workspace name.
        The workspace name is optional. The workspace type must be provided
        either as the type ID or the type name.

        The REST API endpoint of this method is /v2/businessworkspaces
        This API is behaving different from normal node / workspace API.
        Especially the fields and metadata deliver a non-standard format.
        fields=categories seems to not deliver the actual category data.
        If you want category data you should use get_workspace() method instead.

        Args:
            type_name (str, optional):
                The name of the workspace type.
            type_id (int, optional):
                The ID of the workspace_type.
            name (str | None, optional):
                Name of the workspace, if None then deliver all instances
                of the given workspace type. If the name is provided
                the prefixes 'contains_' and 'startswith_' are supported
                like 'contains_Test' to find workspace that have 'Test'
                in their name.
            column_query (str | None, optional):
                Specific query for custom columns (if columns are configured
                for the folder the workspaces are in).
            expanded_view (bool, optional):
                If False, then just search in recently
                accessed business workspace for this name and type.
                If True (this is the default), then search in all
                workspaces for this name and type.
            sort (str | None, optional):
                Order by named column (Using prefixes such as sort=asc_name or sort=desc_name).
                Default is None.
            limit (int | None, optional):
                The maximum number of workspace instances that should be delivered in one page.
                The default is None, in this case the internal OTCS limit seems to be 500.
            page (int | None, optional):
                The page to be returned (if more workspace instances exist than given by the page limit).
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
            metadata (bool, optional):
                Whether to return metadata (data type, field length, min/max values,...)
                about the data.
                Metadata will be returned under `results.metadata`, `metadata_map`,
                or `metadata_order`.
                This is NOT categories & attributes!
            timeout (float, optional):
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
                                'wnf_wksp_type_id': 16,
                                'wnf_wksp_template_id': 28168
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

        # The REST API seems to not properly handle just passing the type name if expanded_view is False,
        # so we first need to resolve the type ID if only the type name is given and expanded_view is False:
        if type_name and not type_id and not expanded_view:
            response = self.get_workspace_type_by_name(type_name=type_name)
            type_id = self.get_result_value(response=response, key="wksp_type_id")
            if not type_id:
                self.logger.error("Cannot determine workspace type ID for type name -> '%s'", type_name)
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
        if column_query:
            query["where_column_query"] = column_query
        if sort:
            query["sort"] = sort
        if page and limit:
            query["page"] = page
            query["limit"] = limit
        if fields:
            query["fields"] = fields
            query["action"] = "properties-"

        encoded_query = urllib.parse.urlencode(query=query, doseq=True)

        request_url = self.config()["businessWorkspacesUrl"] + "?{}".format(
            encoded_query,
        )
        if metadata:
            request_url += "&metadata"

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
                    "Get workspace with name -> '%s' and type ID -> %d; calling -> %s",
                    name,
                    type_id,
                    request_url,
                )
                failure_message = "Failed to get workspace with name -> '{}' and type ID -> '{}'".format(
                    name,
                    type_id,
                )
        elif type_name:
            self.logger.debug(
                "Get %s workspace instances of type -> '%s'; calling -> %s",
                "all" if expanded_view else "recently accessed",
                type_name,
                request_url,
            )
            failure_message = "Failed to get {} workspace instances of type -> '{}'".format(
                "all" if expanded_view else "recently accessed",
                type_name,
            )
        else:
            self.logger.debug(
                "Get %s workspace instances with type ID -> %d; calling -> %s",
                "all" if expanded_view else "recently accessed",
                type_id,
                request_url,
            )
            failure_message = "Failed to get {} workspace instances with type ID -> {}".format(
                "all" if expanded_view else "recently accessed",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_type_location")
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
        # reviewed once we have an improved REST API for Workspace Types.
        response = self.get_workspace_by_type_and_name(
            type_name=type_name,
            type_id=type_id,
            page=1,
            limit=1,
        )

        return self.get_result_value(response=response, key="parent_id")

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_by_business_object")
    def get_workspace_by_business_object(
        self,
        external_system_name: str,
        business_object_type: str,
        business_object_id: str,
        metadata: bool = False,
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
            metadata (bool, optional):
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
        if metadata:
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="lookup_workspace")
    def lookup_workspaces(
        self,
        type_name: str,
        category: str,
        attribute: str,
        value: str,
        attribute_set: str | None = None,
        substring: bool = False,
        fields: str | list | None = None,
        page_size: int = 25,
        stop_at_first_match: bool = False,
    ) -> dict | None:
        """Lookup workspaces that have a specified value in a category attribute.

        Args:
            type_name (str):
                The name of the workspace type. This is required to determine
                the parent folder in which the workspaces of this type reside.
            category (str):
                The name of the category.
            attribute (str):
                The name of the attribute that includes the value to match with
            value (str):
                The lookup value that is matched agains the node attribute value.
            attribute_set (str | None, optional):
                The name of the attribute set. If None (default) the attribute to lookup
                is supposed to be a top-level attribute.
            substring (bool, optional):
                If True, then the value is looked up as a substring of the attribute value.
                If False (default), then the value must match the attribute value exactly.
            fields (str | list | None, optional):
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
                Defaults to None which is internal set to ["properties", "categories"].
            page_size (int, optional):
                The number of subnodes that are requested per request.
                For the lookup nodes this is basically the chunk size.
            stop_at_first_match (bool, optional):
                Whether to stop the lookup at the first match found. Defaults to False.
                This can improve performance if only one match is needed.

        Returns:
            dict | None:
                Node(s) wrapped in dictionary with "results" key or None if the REST API fails.

        """

        parent_id = self.get_workspace_type_location(type_name=type_name)
        if not parent_id:
            self.logger.error(
                "Cannot lookup workspace of type -> '%s', with category -> '%s', attribute -> '%s', and value -> '%s'. No parent ID found for this type!",
                type_name,
                category,
                attribute,
                value,
            )
            return None

        return self.lookup_nodes(
            parent_node_id=parent_id,
            category=category,
            attribute=attribute,
            value=value,
            attribute_set=attribute_set,
            substring=substring,
            fields=fields,
            page_size=page_size,
            stop_at_first_match=stop_at_first_match,
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace")
    def get_workspace_references(
        self,
        node_id: int,
    ) -> list | None:
        """Get a workspace rewferences to business objects in external systems.

        Args:
            node_id (int):
                The node ID of the workspace to retrieve.

        Returns:
            list | None:
                A List of references to business objects in external systems.

        """

        response = self.get_workspace(node_id=node_id, fields="workspace_references")

        results = response.get("results")
        if not results:
            return None
        data = results.get("data")
        if not data:
            return None

        workspace_references: list = data.get("workspace_references")

        return workspace_references

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="set_workspace_reference")
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
            external_system_id (str | None, optional):
                Identifier of the external system (None if no external system).
            bo_type (str | None, optional):
                Business object type (None if no external system)
            bo_id (str | None, optional):
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
            "Update workspace reference of workspace ID -> %d with business object connection -> (%s, %s, %s); calling -> %s",
            workspace_id,
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
            warning_message="Cannot update reference for workspace ID -> {} with business object connection -> ('{}', '{}', {})".format(
                workspace_id,
                external_system_id,
                bo_type,
                bo_id,
            ),
            failure_message="Failed to update reference for workspace ID -> {} with business object connection -> ('{}', '{}', {})".format(
                workspace_id,
                external_system_id,
                bo_type,
                bo_id,
            ),
            show_error=show_error,
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="delete_workspace_reference")
    def delete_workspace_reference(
        self,
        workspace_id: int,
        external_system_id: str | None = None,
        bo_type: str | None = None,
        bo_id: str | None = None,
        show_error: bool = True,
    ) -> dict | None:
        """Delete reference of workspace to a business object in an external system.

        Args:
            workspace_id (int):
                The ID of the workspace.
            external_system_id (str | None, optional):
                Identifier of the external system (None if no external system).
            bo_type (str | None, optional):
                Business object type (None if no external system)
            bo_id (str | None, optional):
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
            "Delete workspace reference of workspace ID -> %d with business object connection -> (%s, %s, %s); calling -> %s",
            workspace_id,
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
            method="DELETE",
            headers=request_header,
            data=workspace_put_data,
            timeout=None,
            warning_message="Cannot delete reference for workspace ID -> {} with business object connection -> ({}, {}, {})".format(
                workspace_id,
                external_system_id,
                bo_type,
                bo_id,
            ),
            failure_message="Failed to delete reference for workspace ID -> {} with business object connection -> ({}, {}, {})".format(
                workspace_id,
                external_system_id,
                bo_type,
                bo_id,
            ),
            show_error=show_error,
        )

    # end method definition

    @tracer.start_as_current_span(
        attributes=OTEL_TRACING_ATTRIBUTES, name="create_workspace", kind=trace.SpanKind.CLIENT
    )
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
            category_data (dict | None, optional):
                Category and attribute data for the workspace.
            classifications (list | None, optional):
                List of classification item IDs to apply to the new item.
            external_system_id (str | None, optional):
                External system identifier if linking the workspace to an external system.
            bo_type (str | None, optional):
                Business object type, used if linking to an external system.
            bo_id (str | None, optional):
                Business object identifier or key, used if linking to an external system.
            parent_id (int | None, optional):
                ID of the parent workspace, required in special cases such as
                sub-workspaces or location ambiguity.
            ibo_workspace_id (int | None, optional):
                ID of an existing workspace that is already linked to an external system.
                Allows connecting multiple business objects (IBO).
            external_create_date (str | None, optional):
                Date of creation in the external system (format: YYYY-MM-DD).
                None is the default.
            external_modify_date (str | None, optional):
                Date of last modification in the external system (format: YYYY-MM-DD).
                None is the default.
            show_error (bool, optional):
                If True, log an error if workspace creation fails.
                If False, log a warning instead.
                True is the default.

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
                "Use specified location with node ID -> %d for workspace -> '%s'",
                parent_id,
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
            "Create workspace -> '%s' with type -> '%s' from template ID -> %d with payload -> %s; calling -> %s",
            workspace_name,
            str(workspace_type),
            workspace_template_id,
            str(create_workspace_post_data),
            request_url,
        )
        trace.get_current_span().set_attributes(
            {
                "workspace.name": workspace_name,
                "workspace.type": workspace_type,
                "workspace.template_id": workspace_template_id,
            }
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
        if node_id:
            trace.get_current_span().set_attribute("workspace.id", node_id)

        if node_id and classifications:
            self.assign_classifications(node_id=node_id, classifications=classifications)

        return response

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_workspace")
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
            workspace_name (str | None, optional):
                New Name of the workspace (renaming).
                Default is None (no renaming).
            workspace_description (str | None, optional):
                New Description of the workspace.
                Default is None (description is not changed).
            category_data (dict | None, optional):
                Category and attribute data.
                Default is None (attributes remain unchanged).
            external_system_id (str | None, optional):
                Identifier of the external system (None if no external system)
            bo_type (str | None, optional):
                Business object type (None if no external system)
            bo_id (str | None, optional):
                Business object identifier / key (None if no external system)
            external_create_date (str | None, optional):
                Date of creation in the external system
                (format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS).
            external_modify_date (str | None, optional):
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_workspace_relationship")
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
            "Create workspace relationship between workspace ID -> %d and related workspace ID -> %d; calling -> %s",
            workspace_id,
            related_workspace_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_relationships")
    def get_workspace_relationships(
        self,
        workspace_id: int,
        relationship_type: str | list = "child",
        related_workspace_name: str | None = None,
        related_workspace_type_id: int | list | None = None,
        limit: int | None = None,
        page: int | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        metadata: bool = False,
    ) -> dict | None:
        """Get the Workspace relationships to other workspaces.

        Optionally, filter criterias can be provided
        such as the related workspace name (starts with) or
        the related workspace TYPE IDs (one or multiple)

        Args:
            workspace_id (int):
                The ID of the workspace.
            relationship_type (str | list, optional):
                Either "parent" or "child" ("child" is the default).
                If both ("child" and "parent") are requested then use a
                list like ["child", "parent"].
            related_workspace_name (str | None, optional):
                Filter for a certain workspace name in the related items.
            related_workspace_type_id (int | list | None, optional):
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
            metadata (bool, optional):
                Whether or not workspace metadata (categories) should be returned.
                Default is False.

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
                                'open': {
                                    'body': '',
                                    'content_type': '',
                                    'form_href': '',
                                    'href': '/api/v2/nodes/35710/nodes',
                                    'method': 'GET', 'name': 'Open'
                                }
                            },
                            'map': {'default_action': 'open'},
                            'order': ['open']
                        },
                        'data': {
                            'properties': {
                                'volume_id': -2000,
                                'id': 35710,
                                'parent_id': 26558,
                                'owner_user_id': 22263,
                                'name': 'B3-L7B-A8753 - Agilum S87 V53 Ampere Block 3 Line 7B',
                                'type': 848,
                                'description': '',
                                'create_date': '2025-06-29T01:19:56',
                                'create_user_id': 22263,
                                'modify_date': '2025-06-29T03:47:35',
                                'modify_user_id': 22263,
                                'reserved': False,
                                'reserved_user_id': 0,
                                'reserved_date': None,
                                'order': None,
                                'icon': '/cssupport/otsapxecm/wksp_equipment.png',
                                'hidden': False,
                                'mime_type': None,
                                'original_id': 0,
                                'wnf_wksp_type_id': 20,
                                'wnf_wksp_template_id': 29449,
                                'size_formatted': '13 Items',
                                'type_name': 'Business Workspace',
                                'container': True,
                                'size': 13,
                                'perm_see': True,
                                'perm_see_contents': True,
                                'perm_modify': True,
                                'perm_modify_attributes': True,
                                'perm_modify_permissions': True,
                                'perm_create': True,
                                'perm_delete': True,
                                'perm_delete_versions': True,
                                'perm_reserve': True,
                                'perm_add_major_version': True,
                                'favorite': False,
                                'rel_type': 'BO_Child'
                            }
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
                if any(rt not in ["parent", "child"] for rt in relationship_type):
                    self.logger.error(
                        "Illegal relationship type for related workspace type! Must be either 'parent' or 'child'. -> %s",
                        relationship_type,
                    )
                    return None
                query["where_rel_types"] = "{'" + ("','").join(relationship_type) + "'}"
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
            query["action"] = "properties-"

        encoded_query = urllib.parse.urlencode(query=query, doseq=False)
        request_url += "?{}".format(encoded_query)
        if metadata:
            request_url += "&metadata"

        request_header = self.request_form_header()

        self.logger.debug(
            "Get related workspaces for workspace with ID -> %d; calling -> %s",
            workspace_id,
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
        relationship_type: str | list = "child",
        related_workspace_name: str | None = None,
        related_workspace_type_id: int | list | None = None,
        fields: str | list = "properties",  # per default we just get the most important information
        page_size: int = 100,
        limit: int | None = None,
        metadata: bool = False,
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
            relationship_type (str | list, optional):
                Either "parent" or "child" ("child" is the default).
                If both ("child" and "parent") are requested then use a
                list like ["child", "parent"].
            related_workspace_name (str | None, optional):
                Filter for a certain workspace name in the related items.
            related_workspace_type_id (int | list | None, optional):
                ID of related workspace type (or list of IDs)
            fields (str | list, optional):
                Which fields to retrieve. This can have a significant
                impact on performance.
                Possible fields include (NOTE: "categories" is not supported in this method!!):
                - "properties" (can be further restricted by specifying sub-fields,
                  e.g., "properties{id,name,parent_id,description}")
                - "business_properties" (all the information for the business object and the external system)
                - "workspace_references" (a list with the references to business objects in external systems)
                - "wksp_info" (currently just the icon information of the workspace)
                This parameter can be a string to select one field group or a list of
                strings to select multiple field groups.
                Defaults to "properties".
            page_size (int, optional):
                The maximum number of related workspaces that should be delivered
                in one page.
                The default is None, in this case the internal OTCS limit seems
                to be 500.
                This is basically the chunk size for the iterator.
            limit (int | None = None), optional):
                The maximum number of workspaces to return in total.
                If None (default) all workspaces are returned.
                If a number is provided only up to this number of results is returned.
            metadata (bool, optional):
                Whether or not workspace metadata should be returned. These are
                the system level metadata - not the categories of the workspace!
                Default is False.

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
            metadata=metadata,
        )
        if not response or "results" not in response:
            # Don't return None! Plain return is what we need for iterators.
            # Natural Termination: If the generator does not yield, it behaves
            # like an empty iterable when used in a loop or converted to a list:
            return

        number_of_related_workspaces = response["paging"]["total_count"]
        if limit and number_of_related_workspaces > limit:
            number_of_related_workspaces = limit

        if not number_of_related_workspaces:
            self.logger.debug(
                "Workspace with node ID -> %d does not have related workspaces! Cannot iterate over related workspaces.",
                workspace_id,
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
                limit=page_size if limit is None else limit,
                page=page,
                fields=fields,
                metadata=metadata,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="delete_workspace_relationship")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="delete_workspace_relationships")
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
                    "Failed to delete %s relationship between workspace ID -> %d and related workspace ID -> %d",
                    relationship_type,
                    workspace_id,
                    related_workspace_id,
                )
                return False

        return True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_roles")
    def get_workspace_roles(self, workspace_id: int) -> dict | None:
        """Get the Workspace roles.

        Args:
            workspace_id (int):
                The ID of the workspace template or workspace.

        Returns:
            dict | None:
                Workspace Roles data or None if the request fails.

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(workspace_id) + "/roles"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace roles of workspace with ID -> %d; calling -> %s",
            workspace_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workspace_members")
    def get_workspace_members(self, workspace_id: int, role_id: int) -> dict | None:
        """Get the Workspace members of a given role.

        Args:
            workspace_id (int):
                The ID of the workspace.
            role_id (int):
                The ID of the workspace role.

        Returns:
            dict | None:
                Workspace member data or None if the request fails.

        """

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Get workspace members for workspace ID -> %d and role ID -> %d; calling -> %s",
            workspace_id,
            role_id,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get workspace members for workspace with ID -> {} and role with ID -> {}".format(
                workspace_id, role_id
            ),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_workspace_member")
    def add_workspace_member(
        self,
        workspace_id: int,
        role_id: int,
        member_id: int,
        show_warning: bool = True,
    ) -> dict | None:
        """Add member to a workspace role. Check that the user/group is not yet a member.

        Args:
            workspace_id (int):
                The ID of the workspace.
            role_id (int):
                The ID of the workspace role.
            member_id (int):
                The user ID or group ID.
            show_warning (bool, optional):
                If True logs a warning if member is already in role.

        Returns:
            dict | None:
                Workspace Role Membership or None if the request fails.

        Example:
        {
            'links': {
                'data': {
                    'self': {
                        'body': '',
                        'content_type': '',
                        'href': '/api/v2/businessworkspaces/80998/roles/81001/members',
                        'method': 'POST',
                        'name': ''
                    }
            },
            'results': {
                'data': {
                    'properties': {
                        'birth_date': None,
                        'business_email': 'lwhite@terrarium.cloud',
                        'business_fax': None,
                        'business_phone': '+1 (345) 4626-333',
                        'cell_phone': None,
                        'deleted': False,
                        'display_language': None,
                        'display_name': 'Liz White',
                        'first_name': 'Liz',
                        'gender': None,
                        'group_id': 16178,
                        'group_name': 'Executive Leadership Team',
                        'home_address_1': None,
                        'home_address_2': None,
                        'home_fax': None,
                        'home_phone': None,
                        'id': 15520,
                        'initials': 'LW',
                        'last_name': 'White',
                        ...
                    }
                }
            }
        }

        """

        self.logger.debug(
            "Check if user/group with ID -> %d is already in role with ID -> %d of workspace with ID -> %d",
            member_id,
            role_id,
            workspace_id,
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
                    "User/group with ID -> %d is already a member of role with ID -> %d of workspace with ID -> %d",
                    member_id,
                    role_id,
                    workspace_id,
                )
            return workspace_members

        add_workspace_member_post_data = {"id": str(member_id)}

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Add user/group with ID -> %d to role with ID -> %d of workspace with ID -> %d; calling -> %s",
            member_id,
            role_id,
            workspace_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="remove_workspace_member")
    def remove_workspace_member(
        self,
        workspace_id: int,
        role_id: int,
        member_id: int,
        show_warning: bool = True,
    ) -> dict | None:
        """Remove a member from a workspace role. Check that the user is currently a member.

        Args:
            workspace_id (int):
                The ID of the workspace.
            role_id (int):
                The ID of the workspace role.
            member_id (int):
                The user or Group ID.
            show_warning (bool, optional):
                If True logs a warning if member is not in role.

        Returns:
            dict | None:
                Workspace Role Membership or None if the request fails.

        """

        self.logger.debug(
            "Check if user/group with ID -> %d is in role with ID -> %d of workspace with ID -> %d",
            member_id,
            role_id,
            workspace_id,
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
                    "User/group with ID -> %d is not a member of role with ID -> %d of workspace with ID -> %d",
                    member_id,
                    role_id,
                    workspace_id,
                )
            return None

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}/members/{}".format(
            workspace_id,
            role_id,
            member_id,
        )
        request_header = self.request_form_header()

        self.logger.debug(
            "Removing user/group with ID -> %d from role with ID -> %d of workspace with ID -> %d; calling -> %s",
            member_id,
            role_id,
            workspace_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="remove_workspace_members")
    def remove_workspace_members(
        self,
        workspace_id: int,
        role_id: int,
        show_warning: bool = True,
    ) -> bool:
        """Remove all members from a workspace role. Check that the user is currently a member.

        Args:
            workspace_id (int):
                The ID of the workspace.
            role_id (int):
                The ID of the workspace role.
            show_warning (bool, optional):
                If True, logs a warning if member is not in role.

        Returns:
            bool:
                True if success or False if the request fails.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_workspace_permissions")
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
            workspace_id (int):
                The ID of the workspace for which the role permissions are being assigned.
            role_id (int):
                The ID of the role to which the permissions will be assigned.
            permissions (list):
                List of permissions to assign to the role. Valid permissions include:
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
            apply_to (int, optional):
                Specifies the scope of permission assignment. Possible values:
                - 0 = Apply to this item only
                - 1 = Apply to sub-items only
                - 2 = Apply to this item and its sub-items (default)
                - 3 = Apply to this item and its immediate sub-items

        Returns:
            dict | None:
                Updated workspace role membership details or `None` if the request fails.

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
            "Updating Permissions of role with ID -> %d of workspace with ID -> %d with permissions -> %s; calling -> %s",
            role_id,
            workspace_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_workspace_icon")
    def update_workspace_icon(
        self,
        workspace_id: int,
        file_path: str,
        file_mimetype: str = "image/*",
    ) -> dict | None:
        """Update a workspace with a with a new icon (which is uploaded).

        Args:
            workspace_id (int):
                The ID of the workspace to update the icon for.
            file_path (str):
                The path + filename of icon file.
            file_mimetype (str, optional):
                The mimetype of the image.

        Returns:
            dict | None:
                Node information or None if REST call fails.

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
            "Update icon for workspace ID -> %d with icon file -> %s; calling -> %s",
            workspace_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_unique_names")
    def get_unique_names(self, names: list, subtype: int | None = None) -> dict | None:
        """Get definition information for Unique Names.

        Args:
            names (list):
                A list of unique names to lookup.
            subtype (int | None, optional):
                A subtype ID to filter unique names to those pointing to a specific subtype.

        Returns:
            dict | None:
                Unique name definition information or None if REST call fails.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_item")
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
            "Create item -> '%s' (type -> %s) under parent with ID -> %d; calling -> %s",
            item_name,
            str(item_type),
            parent_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_item")
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
            classifications (list | None, optional):
                List of classification item IDs to apply to the new item.
            body (bool, optional):
                Should the payload be put in an body tag. Most V2 REST API methods
                do require this but some not (like Scheduled Bots)
            **kwargs (dict, optional):
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
                failure_message="Failed to update item {}".format(
                    "-> '{}' ({})".format(item_name, node_id) if item_name else "with ID -> {}".format(node_id),
                ),
            )
        else:
            response = None

        # As category data and classifications cannot be added to the REST call above
        # we use seperate methods to set the values for each category separately and classifiions
        # See: https://developer.opentext.com/ce/products/extended-ecm/documentation/content-server-rest-api-implementation-notes/7
        if category_data:
            for category_id in category_data:
                self.logger.debug(
                    "Update item %s, category ID -> %s with new category data -> %s",
                    "-> '{}' ({})".format(item_name, node_id) if item_name else "with ID -> {}".format(node_id),
                    str(category_id),
                    str(category_data[category_id]),
                )
                category = category_data[category_id]
                response = self.set_category_values(
                    node_id=node_id,
                    category_id=category_id,
                    category_data=self.flatten_categories_dict(category),
                )

        if classifications:
            self.assign_classifications(node_id=node_id, classifications=classifications)

        return response

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_create_form")
    def get_node_create_form(
        self,
        parent_id: int,
        subtype: int = ITEM_TYPE_DOCUMENT,
        category_ids: int | list[int] | None = None,
    ) -> dict | None:
        """Get the node create form.

        Args:
            parent_id (int):
                The parent node of the new node to create.
            subtype (int, optional):
                The subtype of the new node. Default is document.
            category_ids (int | list[int], optional):
                The ID of the category or a list of category IDs.

        Returns:
            dict | None:
                Node create form data or None if the request fails.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_category_update_form")
    def get_node_category_form(
        self,
        node_id: int,
        category_id: int | None = None,
        operation: str = "update",
    ) -> dict | None:
        """Get the node category update form.

        Args:
            node_id (int):
                The ID of the node to update.
            category_id (int | None, optional):
                The ID of the category to update.
            operation (str, optional):
                The operation to perform. Default is "update". Other possible value is "create".

        Returns:
            dict | None:
                Workspace Category Update Form data or None if the request fails.

        Example:
        {
            'forms': [
                {
                    'data': {
                        '20581_1': {'metadata_token': ''},
                        '20581_10': None,
                        '20581_11': None,
                        '20581_12': None,
                        '20581_13': None,
                        '20581_14': [
                            {
                                '20581_14_x_15': None,
                                '20581_14_x_16': None,
                                '20581_14_x_17': None,
                                '20581_14_x_18': None,
                                '20581_14_x_19': None,
                                '20581_14_x_20': None,
                                '20581_14_x_21': None,
                                '20581_14_x_22': None
                            }
                        ],
                        '20581_14_1': None,
                        '20581_2': None,
                        '20581_23': [
                            {
                                '20581_23_x_25': None,
                                '20581_23_x_26': None,
                                '20581_23_x_27': None,
                                '20581_23_x_28': None,
                                '20581_23_x_29': None,
                                '20581_23_x_30': None,
                                '20581_23_x_31': None,
                                '20581_23_x_32': None,
                                '20581_23_x_37': None
                            }
                        ],
                        '20581_23_1': None,
                        '20581_3': None,
                        '20581_33': {
                            '20581_33_1_34': None,
                            '20581_33_1_35': None,
                            '20581_33_1_36': None
                        },
                        '20581_4': None,
                        '20581_5': None,
                        '20581_6': None,
                        '20581_7': None,
                        '20581_8': None,
                        '20581_9': None
                    },
                    'options': {
                        'fields': {...},
                        'form': {...}
                    },
                    'schema': {
                        'properties': {
                            '20581_1': {
                                'readonly': True,
                                'required': False, 'type': 'object'},
                            '20581_2': {
                                'maxLength': 20,
                                'multilingual': None,
                                'readonly': False,
                                'required': False,
                                'title': 'Order Number',
                                'type': 'string'
                            },
                            '20581_11': {
                                'maxLength': 25,
                                'multilingual': None,
                                'readonly': False,
                                'required': False,
                                'title': 'Order Type',
                                'type': 'string'
                            },
                            ... (more fields) ...
                        },
                        'type': 'object'
                    }
                }
            ]
        }

        """

        request_header = self.request_form_header()

        # If no category ID is provided get the current category IDs of the node and take the first one.
        # TODO: we need to be more clever here if multiple categories are assigned to a node.
        if category_id is None:
            category_ids = self.get_node_category_ids(node_id=node_id)
            if not category_ids or not isinstance(category_ids, list):
                self.logger.error("Cannot get category IDs for node with ID -> %s", str(node_id))
                return None
            category_id = category_ids[0]

        self.logger.debug(
            "Get category %s form for node ID  -> %s and category ID -> %s",
            operation,
            str(node_id),
            str(category_id),
        )

        request_url = self.config()["nodesFormUrl"] + "/categories/{}?id={}&category_id={}".format(
            operation, node_id, category_id
        )

        response = self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Cannot get category {} form for node ID -> {} and category ID -> {}".format(
                operation,
                node_id,
                category_id,
            ),
        )

        return response

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="set_system_attributes")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_document_templates")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_document_from_template")
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
            category_data (dict | None):
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
            "Create document -> '%s' from template with ID -> %d in target location with ID -> %d with classification ID -> %d; calling -> %s",
            doc_name,
            template_id,
            parent_id,
            classification_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_wiki")
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
            "Create wiki -> '%s' under parent with ID -> %d; calling -> %s",
            name,
            parent_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_wiki_page")
    def create_wiki_page(
        self,
        wiki_id: int,
        name: str,
        content: str = "",
        description: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Create an OTCS wiki page.

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
            "Create wiki page -> '%s' in wiki with ID -> %d; calling -> %s",
            name,
            wiki_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_web_report_parameters")
    def get_web_report_parameters(self, nickname: str) -> list | None:
        """Retrieve parameters of a Web Report in OTCS.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="run_web_report")
    def run_web_report(
        self,
        nickname: str,
        web_report_parameters: dict | None = None,
    ) -> dict | None:
        """Run a Web Report that is identified by its nickname.

        Args:
            nickname (str):
                The nickname of the Web Reports node.
            web_report_parameters (dict, optional):
                Parameters of the Web Report (names + value pairs)

        Returns:
            dict | None:
                Response of the run Web Report request or None if the Web Report execution has failed.

        """

        # Avoid linter warning W0102:
        if web_report_parameters is None:
            web_report_parameters = {}

        request_url = self.config()["webReportsUrl"] + "/" + nickname
        request_header = self.request_form_header()

        self.logger.debug(
            "Running web report with nickname -> '%s'; calling -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="install_cs_application")
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
            "Install OTCS application -> '%s'; calling -> %s",
            application_name,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=install_cs_application_post_data,
            timeout=None,
            failure_message="Failed to install OTCS application -> '{}'".format(
                application_name,
            ),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_item_to_user_group")
    def assign_item_to_user_group(
        self,
        node_id: int,
        subject: str,
        instruction: str,
        assignees: list,
    ) -> dict | None:
        """Assign an Content Server item to users and groups.

        This is a function used by OT Content Management for Government.

        Args:
            node_id (int):
                The node ID of the OTCS item (e.g. a workspace or a document)
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
            "Assign item with ID -> %d to assignees -> %s (subject -> '%s'); calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_permission")
    def assign_permission(
        self,
        node_id: int,
        permissions: list,
        assignee_type: str,
        assignee: int = 0,
        apply_to: int = 0,
    ) -> dict | None:
        """Assign permissions to a user or group for an Content Server item.

        This method allows you to assign specified permissions to a user or group for a given
        Content Server item (node). The permissions can be applied to the item itself, its sub-items,
        or both.

        Args:
            node_id (int): The ID of the OTCS item (node) to which permissions are being assigned.
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
            assignee_type (str): The type of assignee. This can be one of the following:
                - "owner": Permissions are assigned to the owner.
                - "group": Permissions are assigned to the owner group.
                - "public": Permissions are assigned to the public (all users).
                - "custom": Permissions are assigned to a specific user or group (specified by `assignee`).
            assignee (int, optional):
                The ID of the user or group (referred to as "right ID").
                If `assignee` is 0 and `assignee_type` is "owner" or "group",
                the owner or group will not be changed.
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

        if not assignee_type or assignee_type not in OTCS.PERMISSION_ASSIGNEE_TYPES:
            self.logger.error(
                "Missing or wrong assignee type. Needs to be one of %s!", str(OTCS.PERMISSION_ASSIGNEE_TYPES)
            )
            return None
        if assignee_type == "custom" and not assignee:
            self.logger.error("Assignee type is 'custom' but permission assignee is missing!")
            return None

        if any(permission not in OTCS.PERMISSION_TYPES for permission in permissions):
            illegal_permissions = [permission for permission in permissions if permission not in OTCS.PERMISSION_TYPES]
            self.logger.error(
                "Illegal permission%s -> %s! Allowed permissions are -> %s. Cannot assign permissions to node with ID -> %d.",
                "s" if len(illegal_permissions) > 1 else "",
                str(illegal_permissions),
                str(OTCS.PERMISSION_TYPES),
                node_id,
            )
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
            "Assign permissions -> %s to item with ID -> %d; assignee type -> '%s'; apply to -> '%d'; calling -> %s",
            str(permissions),
            node_id,
            assignee_type,
            apply_to,
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
                failure_message="Failed to assign 'custom' permissions -> {} to item with ID -> {} (apply to -> {})".format(
                    permissions, node_id, apply_to
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
                failure_message="Failed to assign -> '{}' permissions -> {} to item with ID -> {} (apply to -> {})".format(
                    assignee_type, permissions, node_id, apply_to
                ),
            )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="check_user_node_permissions")
    def check_user_node_permissions(self, node_ids: list[int], user_id: int | None = None) -> dict | None:
        """Check if the current user (or a specified user) has permissions to access a given list of Content Server nodes.

        This is using the AI endpoint as this method is typically used in Aviator use cases.

        Args:
            node_ids (list[int]):
                List of node IDs to check.
            user_id (int | None, optional):
                The user ID to check permissions for. If None, the current user is used.
                This can only execurted by an administrator or Business Administrator.
                Default: None (current user)

        Returns:
            dict | None:
                REST API response or None in case of an error.

        Example:
        {
            'links': {
                'data': {
                    self': {
                        'body': '',
                        'content_type': '',
                        'href': '/api/v2/ai/nodes/permissions/check',
                        'method': 'POST',
                        'name': ''
                    }
                }
            },
            'results': {
                'ids': [...]
            }
        }

        """

        request_header = self.request_form_header()

        # Different endpoints for current user vs a specific user:
        if user_id is None:
            # Use the current user:
            request_url = self.config()["aiUrl"] + "/nodes/permissions/check"

            permission_post_data = {"ids": node_ids}

            if float(self.get_server_version()) < 25.4:
                permission_post_data["user_hash"] = self.otcs_ticket_hashed()
        else:
            # Use the specific user:
            request_url = self.config()["nodesUrlv2"] + "/permissions/check"
            permission_post_data = {"ids": node_ids, "right_id": user_id}

        self.logger.debug(
            "Check if %s has permissions to access nodes -> %s; calling -> %s",
            str(user_id) if user_id is not None else "current user",
            str(node_ids),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=permission_post_data,
            failure_message="Failed to check if {} has permissions to access nodes -> {}".format(
                "user with ID -> " + str(user_id) if user_id is not None else "current user", node_ids
            ),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_context")
    def get_node_context(self, node_ids: list[int], attributes: int = -1, environment: bool = True) -> dict | None:
        """Retrieve metadata for the IDs passed in to provide context for Aviator.

        Args:
            node_ids (list[int]):
                One or more node IDs. MUST be specified unless only wanting the environment description.
            attributes (int, optional):
                Total number (approx) of how many attributes to retrieve. Any negative number means all attributes, 0 means no attributes, positive numbers will be a limit we'll try to limit to. (Default: -1 / all attributes)
            environment (bool, optional):
                Include the environment description in the response. (Default: True)


        Returns:
            dict | None:
                REST API response or None in case of an error.

        Example:
        {
        "links": {},
        "results": {
                "node information": {},
                "user information": {},
                "environment information": "string"
            }
        }

        """

        if float(self.get_server_version()) < 25.4:
            self.logger.warning("The get_node_context method is only available for OTCS version 25.4 and higher.")
            return None

        request_url = self.config()["aiUrl"] + "/nodecontext"
        request_header = self.request_form_header()

        post_data = {
            "ids": node_ids,
            "numberofattributes": attributes,
            "environmentDescription": environment,
        }

        self.logger.debug(
            "Get node context for nodes -> %s; calling -> %s",
            node_ids,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=post_data,
            failure_message="Failed to get node context for nodes -> {}".format(node_ids),
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_categories")
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
            "Get categories of node with ID -> %d; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_category")
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
                REST response with category data or None if the call to the REST API fails.

        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories/" + str(category_id)
        if metadata:
            request_url += "?metadata"
        request_header = self.request_form_header()

        self.logger.debug(
            "Get category with ID -> %d on node with ID -> %d; calling -> %s",
            category_id,
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_category_ids")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_category_names")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_category_definition")
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

    def get_category_id_by_name(self, node_id: int, category_name: str) -> int | None:
        """Get the category ID by its name.

        Args:
            node_id (int):
                The ID of the node to get the categories for.
            category_name (str):
                The name of the category to get the ID for.

        Returns:
            int | None:
                The category ID or None if the category is not found.

        """

        response = self.get_node_categories(node_id=node_id)
        results = response["results"]
        for result in results:
            categories = result["metadata"]["categories"]
            first_key = next(iter(categories))
            if categories[first_key]["name"] == category_name:
                return first_key
        return None

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_category_as_dictionary")
    def get_node_category_as_dictionary(
        self, node_id: int, category_id: int | None = None, category_name: str | None = None
    ) -> dict | None:
        """Get a specific category assigned to a node in a streamlined Python dictionary form.

        * The whole category data of a node is embedded into a python dict.
        * Single-value / scalar attributes are key / value pairs in that dict.
        * Multi-value attributes become key / value pairs with value being a list of strings or integers.
        * Single-line sets become key /value pairs with value being a sub-dict.
        * Attribute in single-line sets become key / value pairs in the sub-dict.
        * Multi-line sets become key / value pairs with value being a list of dicts.
        * Single-value attributes in multi-line sets become key / value pairs inside the dict at the row position in the list.
        * Multi-value attributes in multi-line sets become key / value pairs inside the dict at the row position in the list
          with value being a list of strings or integers.

        See also extract_category_data() for an alternative implementation.

        Args:
            node_id (int):
                The ID of the node to get the categories for.
            category_id (int | None, optional):
                The node ID of the category definition (in category volume). If not provided,
                the category ID is determined by its name.
            category_name (str | None, optional):
                The name of the category to get the ID for.
                If category_id is not provided, the category ID is determined by its name.

        Returns:
            dict | None:
                REST response with category data or None if the call to the REST API fails.

        """

        if not category_id and not category_name:
            self.logger.error("Either category ID or category name must be provided!")
            return None

        if not category_id:
            category_id = self.get_category_id_by_name(node_id=node_id, category_name=category_name)

        response = self.get_node_category(node_id=node_id, category_id=category_id)

        data = response["results"]["data"]["categories"]
        metadata = response["results"]["metadata"]["categories"]
        category_key = next(iter(metadata))
        _ = metadata.pop(category_key)

        # Initialize the result dict:
        result = {}

        for key, attribute in metadata.items():
            is_set = attribute["persona"] == "set"
            is_multi_value = attribute["multi_value"]
            attr_name = attribute["name"]
            attr_key = attribute["key"]

            if is_set:
                set_name = attr_name
                set_multi_value = is_multi_value

            if not is_set and "x" not in attr_key:
                result[attr_name] = data[key]
                set_name = None
            elif is_set:
                # The current attribute is the set itself:
                if not is_multi_value:
                    result[attr_name] = {}
                else:
                    result[attr_name] = []
                set_name = attr_name
            elif not is_set and "x" in attr_key:
                # We are inside a set and process the set attributes:
                if not set_multi_value:
                    # A single row set:
                    attr_key = attr_key.replace("_x_", "_1_")
                    result[set_name][attr_name] = data[attr_key]
                else:
                    # Collect all the row data:
                    for index in range(1, 50):
                        attr_key_index = attr_key.replace("_x_", "_" + str(index) + "_")
                        # Do we have data for this row?
                        if attr_key_index in data:
                            if index > len(result[set_name]):
                                result[set_name].append({attr_name: data[attr_key_index]})
                            else:
                                result[set_name][index - 1][attr_name] = data[attr_key_index]
                        else:
                            # No more rows
                            break
        return result

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_category")
    def assign_category(
        self,
        node_id: int,
        category_id: list,
        inheritance: bool | None = False,
        apply_to_sub_items: bool = False,
        apply_action: str = "add_upgrade",
        add_version: bool = False,
        clear_existing_categories: bool = False,
        attribute_values: dict | None = None,
    ) -> bool:
        """Assign a category to a Content Server node.

        Optionally turn on inheritance and apply category to sub-items
        (if node_id is a container / folder / workspace).
        If the category is already assigned to the node this method will
        throw an error.
        Optionally set category attributes values.

        Args:
            node_id (int):
                The node ID to apply the category to.
            category_id (list):
                The ID of the category definition object.
            inheritance (bool | None, optional):
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
            attribute_values (dict, optional):
                Dictionary containing "attribute_id":"value" pairs, to be populated during
                the category assignment. For mandatory attributes this is required to assign the category.

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
                "Category with ID -> %d is not yet assigned to node ID -> %d. Assigning it now...",
                category_id,
                node_id,
            )
            category_post_data = {
                "category_id": category_id,
            }

            if attribute_values is not None:
                category_post_data.update(attribute_values)

            self.logger.debug(
                "Assign category with ID -> %d to item with ID -> %d; calling -> %s",
                category_id,
                node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_category_value_by_name")
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
                "No categories are assigned to node with ID -> %d",
                node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_category_value")
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
            set_id (int | None, optional):
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="set_category_value")
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
                "Assign value -> '%s' to category with ID -> %d, set ID -> %s, row -> %s, attribute ID -> %s on node with ID -> %d; calling -> %s",
                str(value),
                category_id,
                str(set_id),
                str(set_row),
                str(attribute_id),
                node_id,
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
                "Assign value -> '%s' to category ID -> %d, attribute ID -> %s on node with ID -> %d; calling -> %s",
                str(value),
                category_id,
                str(attribute_id),
                node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="set_category_values")
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
            inheritance (bool | None, optional):
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

        if not category_id:
            self.logger.error("Category ID is not specified! Cannot set category values on node with ID -> %d", node_id)
            return None

        if not category_data:
            self.logger.error(
                "No category data provided! Cannot set values for category ID -> %d on node with ID -> %d",
                int(category_id),
                int(node_id),
            )
            return None

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories/" + str(category_id)
        request_header = self.request_form_header()

        self.logger.debug(
            "Set values -> %s for category ID -> %d on node -> %d...",
            str(category_data),
            category_id,
            node_id,
        )

        response = set_category_values_sub(show_error=False)

        if not response:
            self.logger.warning("Failed to set category values, trying to assign category to node first.")

            if self.assign_category(node_id=node_id, category_id=category_id, inheritance=inheritance):
                response = set_category_values_sub(show_error=True)

        return response

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="set_category_inheritance")
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
            enable (bool, optional):
                Whether the inheritance should be enabled (True) or disabled (False).

        Returns:
            dict | None:
                Response of the request or None in case of an error.

        """

        if not category_id:
            self.logger.error(
                "Category ID is not specified! Cannot set category inheritance on node with ID -> %s", str(node_id)
            )
            return None

        request_url = (
            self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories/" + str(category_id) + "/inheritance"
        )
        request_header = self.request_form_header()

        if enable:
            self.logger.debug(
                "Enable category inheritance for node with ID -> %d and category ID -> %d; calling -> %s",
                node_id,
                category_id,
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
                "Disable category inheritance of node with ID -> %d and category ID -> %d; calling -> %s",
                node_id,
                category_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="extract_category_data")
    def extract_category_data(self, node: dict) -> dict | None:
        """Extract category information into a clean python data structure.

        * The whole category data of a node is embedded into a python dict.
        * Single-value / scalar attributes are key / value pairs in that dict.
        * Multi-value attributes become key / value pairs with value being a list of strings or integers.
        * Single-line sets become key /value pairs with value being a sub-dict.
        * Attribute in single-line sets become key / value pairs in the sub-dict.
        * Multi-line sets become key / value pairs with value being a list of dicts.
        * Single-value attributes in multi-line sets become key / value pairs inside the dict at the row position in the list.
        * Multi-value attributes in multi-line sets become key / value pairs inside the dict at the row position in the list
          with value being a list of strings or integers.

        See also get_node_category_as_dictionary() for an alternative implementation.

        Args:
            node (dict):
                The typical node response of a node get REST API call that include the "categories" fields.

        Returns:
            dict | None:
                The category data as a python data structure.

        Example:
            {
                'Customer': {
                    'Status': 'Customer',
                    'Customer Number': '50030',
                    'Name': 'CWT Frankfurt',
                    'Street': '',
                    'Country': 'Germany',
                    'Postal code': '69483',
                    'Sales organisation': [...],
                    'City': 'Frankfurt',
                    'Industry': [...],
                    'Object Key': '0000050030',
                    'Contacts': [
                        {
                            'BP No': None,
                            'Name': None,
                            'Department': None,
                            'Function': None,
                            'Phone': None,
                            'Fax': None,
                            'Email': None,
                            'Building': None,
                            'Floor': None,
                            'Room': None,
                            'Comments': None,
                            'Valid from': None,
                            'Valid to': None
                        }
                    ],
                    'Sales Areas': [
                        {
                            'Sales Organisation': None,
                            'Distribution Channel': None,
                            'Division': None
                        }
                    ],
                    'Rating': {...},
                    'Locations': [...]
                }
            }

        """

        def truncate_before_underscore(attribute_key: str, n: int) -> str:
            """Truncate the string before the nth underscore (if it exists).

            Args:
                attribute_key (str):
                    The input string.
                n (int):
                    The number of underscores before which to truncate.

            Returns:
                str:
                    The truncated string.

            """

            parts = attribute_key.split("_")
            if len(parts) > n:
                return "_".join(parts[:n])
            return attribute_key  # return original if there are fewer than n underscores

        def replace_row_number_with_x(attribute_key: str) -> str:
            """Replace the actual row number with the "x" placeholder.

            Required to find the schema entry for the data entry.

            Args:
                attribute_key (str):
                    The set attribute key value for a multi-line set.

            Returns:
                str:
                    The attribute key in the schema (which has "..._x_...").

            """

            parts = attribute_key.split("_")
            if len(parts) >= 4:
                parts[2] = "x"  # replace the third part (0-based index)
                return "_".join(parts)
            return attribute_key  # return unchanged if format is unexpected

        def get_row_number(attribute_key: str) -> int:
            """Extract the third underscore-separated part of the string as the row number.

            Args:
                attribute_key (str):
                    The input string.

            Returns:
                int:
                    The third number in the attribute key which is the row number,
                    or 1 if not present or not numeric.

            """
            parts = attribute_key.split("_")
            if len(parts) >= 3 and parts[2].isdigit():
                return int(parts[2])
            return 1

        # Start of main method body:

        if not node:
            self.logger.error("Cannot extract category data. No node data provided!")
            return None

        if "results" not in node:
            # Support also iterators that have resolved the "results" already.
            # In this case we wrap it in a "rsults" dict to make it look like
            # a full response:
            if "data" in node:
                node = {"results": node}
            else:
                return None

        # Some OTCS REST APIs may return a list of nodes in "results".
        # We only support processing a single node here:
        if isinstance(node["results"], list):
            if len(node["results"]) > 1:
                self.logger.warning("Response includes a node list. Extracting category data for the first node!")
            node["results"] = node["results"][0]

        if "metadata" not in node["results"]:
            self.logger.error("Cannot extract category data. Method was called without the '&metadata' parameter!")
            return None

        #
        # 1. Process the Category & Attribute Schemas
        #
        metadata = node["results"]["metadata"]
        if "categories" not in metadata:
            self.logger.error(
                "Cannot extract category data. No category data found in node response! Use 'categories' value for 'fields' parameter in the node call!"
            )
            return None
        category_schemas = metadata["categories"]

        result_dict = {}
        current_dict = result_dict
        set_lookup = {}
        category_lookup = {}
        attribute_lookup = {}

        # Some REST API return categories in different format. We adjust
        # it on the fly here:
        if isinstance(category_schemas, list):
            new_schema = {}
            for category_schema in category_schemas:
                first_key = next(iter(category_schema))
                new_schema[first_key] = category_schema
            category_schemas = new_schema

        try:
            for category_key, category_schema in category_schemas.items():
                for attribute_key, attribute_schema in category_schema.items():
                    attribute_name = attribute_schema["name"]
                    attribute_type = attribute_schema["type_name"]
                    attribute_multi_value = attribute_schema["multi_value"]
                    persona = attribute_schema["persona"]
                    self.logger.debug(
                        "Processing %sattribute -> '%s' (%s) of type -> '%s'",
                        "set " if persona == "set" else "",
                        attribute_name,
                        attribute_key,
                        attribute_type,
                    )
                    if persona == "category":
                        category_name = attribute_name
                        result_dict[category_name] = {}
                        current_dict = result_dict[category_name]
                        category_lookup[category_key] = current_dict
                    elif persona == "set" and not attribute_multi_value:
                        result_dict[category_name][attribute_name] = {}
                        current_dict = result_dict[category_name][attribute_name]
                        set_lookup[truncate_before_underscore(attribute_key, 2)] = current_dict
                    elif persona == "set" and attribute_multi_value:
                        result_dict[category_name][attribute_name] = []
                        result_dict[category_name][attribute_name].append({})
                        set_lookup[truncate_before_underscore(attribute_key, 2)] = result_dict[category_name][
                            attribute_name
                        ]
                        # We use first list item to "park" the row template:
                        current_dict = result_dict[category_name][attribute_name][0]
                    else:
                        attribute_lookup[attribute_key] = attribute_name
                        if attribute_key.count("_") > 1:
                            set_dict = set_lookup.get(truncate_before_underscore(attribute_key, 2))
                            if isinstance(set_dict, list):
                                set_dict = set_dict[0]
                            if set_dict != current_dict:
                                current_dict = set_dict
                        elif current_dict != result_dict[category_name]:
                            # We jump back to top-level attributes:
                            current_dict = result_dict[category_name]
                        match attribute_type:
                            case "String":
                                if attribute_multi_value:
                                    current_dict[attribute_name] = []
                                else:
                                    current_dict[attribute_name] = ""
                            case "Integer":
                                if attribute_multi_value:
                                    current_dict[attribute_name] = []
                                else:
                                    current_dict[attribute_name] = None
                            case "Date":
                                if attribute_multi_value:
                                    current_dict[attribute_name] = []
                                else:
                                    current_dict[attribute_name] = None
                            case "Boolean":
                                if attribute_multi_value:
                                    current_dict[attribute_name] = []
                                else:
                                    current_dict[attribute_name] = False
                            case _:
                                self.logger.error("Type -> '%s' not handled yet!", attribute_type)
                        # end match attribute_type
                    # end if persona == "category":
                # end for attribute_key, attribute_schema in category_schema.items():
            # end for category_key, category_schema in category_schemas.items():
        except Exception as e:
            self.logger.error("Something went wrong with getting the data schema! Error -> %s", str(e))
            return None

        #
        # 2. Process the Category & Attribute Data
        #
        category_datas = node["results"]["data"]["categories"]

        if isinstance(category_datas, list):
            new_data = {}
            for category_data in category_datas:
                first_key = next(iter(category_data))
                new_data[first_key] = category_data
            category_datas = new_data

        try:
            for category_data in category_datas.values():
                for attribute_key, value in category_data.items():
                    if attribute_key.endswith("_multilingual"):
                        continue  # We skip multilingual data entries
                    attribute_name = attribute_lookup[replace_row_number_with_x(attribute_key=attribute_key)]
                    self.logger.debug(
                        "Add value -> '%s' to %sattribute -> '%s' (%s)",
                        value,
                        "set " if attribute_key.count("_") > 1 else "",
                        attribute_name,
                        attribute_key,
                    )
                    # Is it data for a set attribute?
                    # Adjust the current_dict to the right place the value should be added:
                    if attribute_key.count("_") > 1:
                        set_data = set_lookup[truncate_before_underscore(attribute_key=attribute_key, n=2)]
                        if isinstance(set_data, dict):
                            self.logger.debug("Taget dict is single-line set attribute.")
                            current_dict = set_data
                        elif isinstance(set_data, list):
                            row_number = get_row_number(attribute_key=attribute_key)
                            self.logger.debug("Target dict is row %d of multi-line set attribute.", row_number)
                            if row_number > len(set_data):
                                self.logger.debug("Add rows up to %d of multi-line set attribute...", row_number)
                                for _ in range(row_number - len(set_data)):
                                    set_data.append(dict.fromkeys(set_data[0], ""))
                            current_dict = set_data[row_number - 1]
                        else:
                            self.logger.error("Unsupported set data structure -> %s!", str(set_data))
                            continue
                    else:
                        # If it is not a set attribute we reset current_dict to the top-level attributes
                        # of the category:
                        current_dict = category_lookup[truncate_before_underscore(attribute_key=attribute_key, n=1)]
                    current_dict[attribute_name] = value if value is not None else ""
                # end for attribute_key, value in category_data.items():
            # end for for category_data in category_datas.values():
        except Exception as e:
            self.logger.error("Something went wrong while filling the data! Error -> %s", str(e))
            return None

        return result_dict

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="collection_operation")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_node_to_collection")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="remove_node_from_collection")
    def remove_node_from_collection(
        self,
        collection_id: int,
        node_ids: int | list,
    ) -> dict | None:
        """Remove node(s) from a collection.

        Args:
            collection_id (int):
                The node ID of the colection.
            node_ids (int | list):
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_node_classifications")
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
            "Get classifications of node with ID -> %d; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(
        attributes=OTEL_TRACING_ATTRIBUTES, name="createassign_classifications_document_from_template"
    )
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
            remove_existing (bool, optional):
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
            "Assign classifications with IDs -> %s to item with ID -> %d; calling -> %s",
            str(classifications),
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_rm_classification")
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
            "Assign RM classifications with ID -> %d to item with ID -> %d; calling -> %s",
            rm_classification,
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="register_workspace_template")
    def register_workspace_template(self, node_id: int) -> dict | None:
        """Register a workspace template as project template for Extended ECM for Engineering.

        Args:
            node_id (int):
                The node ID of the Business Workspace template.

        Returns:
            dict | None:
                Response of request or None if the registration of the workspace template has failed.

        """

        registration_post_data = {"ids": "{{ {} }}".format(node_id)}

        request_url = self.config()["xEngProjectTemplateUrl"]

        request_header = self.request_form_header()

        self.logger.debug(
            "Register workspace template with ID -> %d for Extended ECM for Engineering; calling -> %s",
            node_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_records_management_rsis")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_records_management_codes")
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
    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_records_management_codes")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_records_management_rsi")
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
            now = datetime.now(UTC)
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_records_management_rsi_schedule")
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
            event_type (int, optional):
                The type of the event. Possible values:
                1 Calculated Date,
                2 Calendar Calculation,
                3 Event Based,
                4 Fixed Date,
                5 Permanent
            object_type (str, optional):
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_records_management_hold")
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
            now = datetime.now(UTC)
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_records_management_holds")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="import_records_management_settings")
    def import_records_management_settings(self, file_path: str) -> bool:
        """Import Records Management settings from a local file.

        Args:
            file_path (str):
                The path + filename of config file in local filesystem.

        Returns:
            bool:
                True, if the REST call succeeds or False otherwise.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="import_records_management_codes")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="import_records_management_rsis")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="import_physical_objects_settings")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="import_physical_objects_codes")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="import_physical_objects_locators")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="import_security_clearance_codes")
    def import_security_clearance_codes(
        self,
        file_path: str,
        include_users: bool = False,
    ) -> bool:
        """Import Security Clearance codes from a config file in the local filesystem.

        Args:
            file_path (str):
                The path + filename of config file in local filesystem.
            include_users (bool, optional):
                Defines if users should be included or not. Default is False.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_user_security_clearance")
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
            "Assign security clearance -> %d to user with ID -> %d; calling -> %s",
            security_clearance,
            user_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="assign_user_supplemental_markings")
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
            "Assign supplemental markings -> %s to user with ID -> %d; calling -> %s",
            str(supplemental_markings),
            user_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workflow_definition")
    def get_workflow_definition(self, workflow_id: int) -> dict | None:
        """Get the workflow definition.

        Args:
            workflow_id (int):
                The node ID of the workflow definition item (map).

        Returns:
            dict | None:
                The workflow definition data. None in case of an error.

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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workflow_attributes")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_document_workflows")
    def get_document_workflows(self, node_id: int, parent_id: int) -> list:
        """Get a list of available workflows for a document ID and a parent ID.

        Args:
            node_id (int):
                The node ID of the document.
            parent_id (int):
                The node ID of the parent.

        Returns:
            list:
                The list of available workflows.

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
            "Get workflows for node ID -> %d and parent ID -> %d; calling -> %s",
            node_id,
            parent_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workflows_by_kind_and_status")
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_workflow_status")
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
            "Get workflow status (task list) of process ID -> %d; calling -> %s",
            process_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="create_draft_process")
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
            "Create a draft process for workflow with ID -> %d and body -> %s; calling -> %s",
            workflow_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_draft_process")
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
            "Get draft process with ID -> %d; calling -> %s",
            draftprocess_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_draft_process")
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
            title (str, optional):
                The title of the process. Default is "".
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
            "Update draft process with ID -> %d with these values -> %s; calling -> %s",
            draftprocess_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="initiate_draft_process")
    def initiate_draft_process(self, draftprocess_id: int) -> dict | None:
        """Initiate a process (workflow instance) from a draft process.

        Args:
            draftprocess_id (int):
                The ID of the draft process that has been created before with create_draft_process()

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
            "Initiate a process (workflow instance) from a draft process with ID -> %d; calling -> %s",
            draftprocess_id,
            request_url,
        )

        initiate_process_body_put_data = {
            "action": "Initiate",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_process_task")
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
            dict | None:
                Response of REST API call. None in case an error occured.

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

        # If no sub-process ID is given, use the process ID:
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
            "Get a process (workflow instance) task for process with ID -> %d; calling -> %s",
            process_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_process_task")
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
                "Update task with ID -> %d of process with ID -> %d with these values -> %s; calling -> %s",
                task_id,
                process_id,
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
                "Execute action -> '%s' for process with ID -> %d",
                action,
                process_id,
            )
        else:  # we have a custom action:
            update_process_task_body_put_data = {
                "custom_action": custom_action,
            }
            self.logger.debug(
                "Execute custom action -> '%s' for process with ID -> %d",
                custom_action,
                process_id,
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="check_workspace_aviator")
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
                    "Aviator is enabled for workspace with ID -> %d",
                    workspace_id,
                )
                return True
            elif "enableai" in data:
                self.logger.debug(
                    "Aviator is disabled for workspace with ID -> %d",
                    workspace_id,
                )

        return False

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="update_workspace_aviator")
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

        request_url = self.config()["aiNodesUrl"] + "/{}".format(workspace_id)
        request_header = self.request_form_header()

        if status is True:
            self.logger.debug(
                "Enable Content Aviator for workspace with ID -> %d; calling -> %s",
                workspace_id,
                request_url,
            )
        else:
            self.logger.debug(
                "Disable Content Aviator for workspace with ID -> %d; calling -> %s",
                workspace_id,
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

    def aviator_chat(
        self,
        context: str | None,
        messages: list[dict],
        where: list[dict] | None = None,
        inline_citation: bool = True,
        parse_request_response: bool = True,
    ) -> dict | requests.Response | None:
        """Process a chat interaction with Content Aviator.

        Args:
            context (str | None):
                Context for the current conversation. This includes the text chunks
                provided by the RAG pipeline.
            messages (list[dict]):
                List of messages from conversation history.
                Format example:
                [
                    {
                        "author": "user", "content": "Summarize this workspace, please."
                    },
                    {
                        "author": "ai", "content": "..."
                    }
                ]
            where (list):
                Metadata name/value pairs for the query.
                Could be used to specify workspaces, documents, or other criteria in the future.
                Values need to match those passed as metadata to the embeddings API.
                Format example:
                [
                    {"workspaceID":"38673"},
                    {"documentID":"38458"},
                ]
            inline_citation (bool, optional):
                Whether or not inline citations should be used in the response. Default is True.
            parse_request_response (bool, optional):
                Whether or not the response should be parsed and returned as a dictionary.
                If False, the raw requests.Response object is returned. Default is

        Returns:
            dict:
                Conversation status

        Example:
        {
            'result': 'I am unable to provide the three main regulations for fuel, as the documents contain various articles and specifications related to fuel, but do not explicitly identify which three are the "main" ones.',
            'references': [
                {
                    'chunks': [
                        {
                            'citation': None,
                            'content': ['16. 1 Basic principles 16.'],
                            'distance': 0.262610273676197,
                            'source': 'Similarity'
                        }
                    ],
                    'distance': 0.262610273676197,
                    'metadata': {
                        'content': {
                            'chunks': ['16. 1 Basic principles 16.'],
                            'source': 'Similarity'
                        },
                        'documentID': '39004',
                        'workspaceID': '38673'
                    }
                },
                {
                    'chunks': [
                        {
                            'citation': None,
                            'content': ['16. 1.'],
                            'distance': 0.284182507756566,
                            'source': 'Similarity'
                        }
                    ],
                    'distance': 0.284182507756566,
                    'metadata': {
                        'content': {
                            'chunks': ['16. 1.'],
                            'source': 'Similarity'
                        },
                        'documentID': '38123',
                        'workspaceID': '38673'
                    }
                }
            ],
            'context': 'Tool "get_context" called with arguments {"query":"Tell me about the calibration equipment"} and returned:',
            'queryMetadata': {
                'originalQuery': 'Tell me about the calibration equipment',
                'usedQuery': 'Tell me about the calibration equipment'
            }
        }

        """

        request_url = self.config()["aiChatUrl"]
        request_header = self.request_json_header()

        chat_data = {}
        if where:
            chat_data["where"] = where

        chat_data["context"] = context
        chat_data["messages"] = messages
        # "synonyms": self.config()["synonyms"],
        chat_data["inlineCitation"] = inline_citation

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            json_data=chat_data,
            timeout=None,
            failure_message="Failed to chat with Content Aviator",
            parse_request_response=parse_request_response,
        )

    # end method definition

    def aviator_context(
        self, query: str, threshold: float = 0.5, limit: int = 10, data: list | None = None
    ) -> dict | None:
        """Get context based on the query text from Aviator's vector database.

        Results are text-chunks and they will be permission-checked for the authenticated user.

        Args:
            query (str):
                The query text to search for similar text chunks.
            threshold (float, optional):
                Similarity threshold between 0 and 1. Default is 0.5.
            limit (int, optional):
                Maximum number of results to return. Default is 10.
            data (list | None, optional):
                Additional data to pass to the embeddings API. Defaults to None.
                This can include metadata for filtering the results.

        Returns:
            dict | None:
                The response from the embeddings API or None if the request fails.

        """

        request_url = self.config()["aiContextUrl"]
        request_header = self.request_form_header()

        if not query:
            self.logger.error("Query text is required for getting context from Content Aviator!")
            return None

        context_post_body = {
            "query": query,
            "threshold": threshold,
            "limit": limit,
        }
        if data:
            context_post_body["data"] = data
        else:
            context_post_body["data"] = []

        self.logger.debug(
            "Get context from Content Aviator for query -> '%s' (threshold: %f, limit: %d); calling -> %s",
            query,
            threshold,
            limit,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            #            data={"body": json.dumps(context_post_body)},
            data=context_post_body,
            timeout=None,
            failure_message="Failed to retrieve context from Content Aviator",
        )

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="traverse_node")
    def traverse_node(
        self,
        node: dict | int,
        executables: list[callable],
        current_depth: int = 0,
        **kwargs: dict,
    ) -> dict | None:
        """Recursively traverse the node an its subnodes.

        This method is preferred for CPU intensive traversals.

        Args:
            node (dict | int):
                The node datastructure (like in a V2 REST Call response)
            executables (list[callable]):
                A list of methods to call for each traversed node. The node
                and a optional dictionary of keyword arguments (kwargs)
                are passed. The executables are called BEFORE the subnodes
                are traversed. The executables should return a boolean result.
                If the result is False, then the execution of the executables
                list is stopped.
            current_depth (int, optional):
                The recursion depth - distance in hierarchy from the root note
                traverse_node() was INITIALLY called from.
            kwargs:
                Additional keyword arguments for the executables.

        Returns:
            dict | None:
                The number of processed and traversed nodes. Format:
                {
                    "processed": int,
                    "traversed": int,
                }

        """

        processed = 0
        traversed = 0

        # Initialze the traverse flag. If True, container
        # subnodes will be processed. If executables exist
        # than at least one executable has to indicate that
        # further traversal is required:
        traverse = not (executables)

        if isinstance(node, dict):
            node_id = self.get_result_value(response=node, key="id")
        elif isinstance(node, int):
            node_id = node
            node = self.get_node(node_id=node_id)
        else:
            self.logger.error("Illegal type of node object. Expect 'int' or 'dict'!")
            return None

        # Run executables:
        for executable in executables or []:
            result_success, result_traverse = executable(node=node, current_depth=current_depth, **kwargs)
            if result_traverse:
                traverse = True
            if not result_success:
                break
        else:
            # else case is processed only if NO break occured in the for loop
            # If all executables have been successful than the node counts as processed:
            processed += 1

        node_type = self.get_result_value(response=node, key="type")

        # We only traverse the subtnodes if the current node is a container type
        # and the executables have all been executed successfully:
        if traverse and node_type in self.CONTAINER_ITEM_TYPES:
            # Get children nodes of the current node:
            subnodes = self.get_subnodes_iterator(parent_node_id=node_id, page_size=200)

            # Recursive call of all subnodes:
            for subnode in subnodes:
                subnode_id = self.get_result_value(response=subnode, key="id")
                subnode_name = self.get_result_value(response=subnode, key="name")
                subnode_type_name = self.get_result_value(response=subnode, key="type_name")
                self.logger.debug("Traversing %s node -> '%s' (%s)", subnode_type_name, subnode_name, subnode_id)
                # Recursive call for current subnode:
                result = self.traverse_node(
                    node=subnode,
                    executables=executables,
                    current_depth=current_depth + 1,
                    **kwargs,
                )
                processed += result.get("processed", 0)
                traversed += result.get("traversed", 0)
            traversed += 1

        return {"processed": processed, "traversed": traversed}

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="traverse_node_parallel")
    def traverse_node_parallel(
        self,
        node: dict | int,
        executables: list[callable],
        workers: int = 3,
        workers_name: str = "TraverseNodeWorker",
        strategy: str = "BFS",
        timeout: float = 1.0,
        **kwargs: dict,
    ) -> dict:
        """Traverse nodes using a queue and thread pool (BFS-style).

        This method is preferred for I/O or API intensive traversals.

        Args:
            node (dict | int):
                Root node to start traversal. It can be a node or a node ID.
            executables (list[callable]):
                Callables to execute per node.
            workers (int, optional):
                Number of parallel workers.
            workers_name (str, optional):
                Name prefix for worker threads.
            strategy (str, optional):
                Either "DFS" for Depth First Search, or "BFS" for Breadth First Search.
                "BFS" is the default.
            timeout (float, optional):
                Wait time for the queue to have items:
            kwargs (dict):
                Additional arguments for executables.

        Returns:
            dict:
                Stats with processed and traversed counters. Format:
                {
                    "processed": int,
                    "traversed": int,
                }

        """

        results = {"processed": 0, "traversed": 0}
        lock = threading.Lock()
        if strategy == "BFS":
            task_queue = Queue()
        elif strategy == "DFS":
            task_queue = LifoQueue()

        # Enqueue initial nodes at depth 0:
        node_id = self.get_result_value(response=node, key="id") if isinstance(node, dict) else node
        subnodes = self.get_subnodes_iterator(parent_node_id=node_id, page_size=100)
        for subnode in subnodes:
            # Each queue element needs its own copy of traversal data:
            traversal_data = {
                "folder_path": [],
                "workspace_id": None,
                "workspace_type": None,
                "workspace_name": None,
                "workspace_description": None,
                "current_depth": 0,
            }
            task_queue.put((subnode, 0, traversal_data))

        def traverse_node_worker() -> None:
            """Work on a shared queue.

            Loops over these steps:
            1. Get node from queue
            2. Execute all executables for that node
            3. If node is a container and executables indicate to traverse,
               then enqueue all subnodes

            Returns:
                None

            """

            thread_name = threading.current_thread().name

            while True:
                # Initialze the traverse flag. If True, container
                # subnodes will be processed. If executables exist
                # than at least one executable has to return that
                # further traversal is required:
                traverse = not (executables)

                try:
                    node, current_depth, traversal_data = task_queue.get(timeout=timeout)
                except Empty:
                    self.logger.debug("[%s] No (more) nodes to process - finishing...", thread_name)
                    return  # Queue is empty - worker is done

                try:
                    # Fetch node dictionary if just an ID was passed as parameter:
                    if isinstance(node, int):
                        node = self.get_node(node_id=node)

                    node_id = self.get_result_value(response=node, key="id")
                    node_name = self.get_result_value(response=node, key="name")
                    node_type = self.get_result_value(response=node, key="type")

                    self.logger.debug(
                        "[%s] Traversing node -> '%s' (%s) at depth %d", thread_name, node_name, node_id, current_depth
                    )

                    # Run all executables
                    for executable in executables or []:
                        # The executables are functions or method from outside this class.
                        # They need to return a tuple of two boolean values:
                        # (result_success, result_traverse)
                        # result_success indicates if the executable was successful (True)
                        # or not (False). If False, the execution of the executables list
                        # is stopped.
                        # result_traverse indicates if the traversal should continue
                        # into subnodes (True) or not (False).
                        # If at least one executable returns result_traverse = True,
                        # then the traversal into subnodes will be done (if the node is a container).
                        # As this code is from outside this class, we better catch exceptions:
                        try:
                            result_success, result_traverse = executable(
                                node=node,
                                current_depth=current_depth,
                                traversal_data=traversal_data,
                                **kwargs,
                            )
                            if result_traverse:
                                traverse = True
                            if not result_success:
                                break
                        except Exception as e:
                            self.logger.error(
                                "Failed to run executable on node -> '%s' (%s), error -> %s", node_name, node_id, str(e)
                            )
                    else:
                        with lock:
                            results["processed"] += 1

                    # We only traverse the subtnodes if the current node is a container type
                    # and at least one executables (if they any) indicate to require further traversal:
                    if traverse and node_type in self.CONTAINER_ITEM_TYPES:
                        subnodes = self.get_subnodes_iterator(parent_node_id=node_id, page_size=100)
                        for subnode in subnodes:
                            sub_traversal_data = {
                                **traversal_data,
                                "folder_path": traversal_data["folder_path"] + [node_name],
                                "current_depth": current_depth + 1,
                            }
                            # Put all subnodes into the queue for further processing:
                            task_queue.put((subnode, current_depth + 1, sub_traversal_data))

                        with lock:
                            results["traversed"] += 1

                finally:
                    # Guarantee task_done() is called even if exceptions occur:
                    task_queue.task_done()
            # end while True

        # end method traverse_node_worker()

        # Start thread pool with limited concurrency
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=workers_name) as executor:
            for i in range(workers):
                self.logger.debug("Starting worker -> %d...", i)
                executor.submit(traverse_node_worker)

            # Wait for all tasks to complete
            task_queue.join()

        return results

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="translate_node")
    def translate_node(self, node: dict | int, **kwargs: dict) -> bool:
        """Translate a node.

        The actual translation is done by a tranlator object. This recursive method just
        traverses the hierarchy and calls the translate() method of the translator object.

        Args:
            node (dict | int):
                The current node to translate. This can be the node data structure or just
                the node ID. If it is just the ID the actual node will be fetched.
            kwargs (dict):
                Keyword parameters. The methods expects the follwoing keyword parameters:
                * simulate (bool):
                    If True, do not really rename but just traverse and log info.
                * translator (object):
                    This object needs to be created based on the "Translator" class
                    and passed to this method.
                * languages (list):
                    A list of target languages to translate into.

        Returns:
            bool:
                True for success, False for error.

        """

        translator = kwargs.get("translator")
        languages = kwargs.get("languages", [])
        simulate = kwargs.get("simulate", False)

        if not translator:
            self.logger.error("Missing 'translator' parameter (object)!")
            return False
        if not languages:
            self.logger.error("Missing or empty 'languages' parameter (list)!")
            return False

        if isinstance(node, dict):
            current_node_id = self.get_result_value(response=node, key="id")
        else:
            current_node_id = node
            node = self.get_node(node_id=current_node_id)

        name = self.get_result_value(response=node, key="name")
        description = self.get_result_value(response=node, key="description")
        names_multilingual = self.get_result_value(
            response=node,
            key="name_multilingual",
        )
        descriptions_multilingual = self.get_result_value(
            response=node,
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
                self.logger.info(
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
                self.logger.info(
                    "Translate description of node -> %s from -> '%s' (%s) to -> '%s' (%s)",
                    current_node_id,
                    descriptions_multilingual["en"],
                    "en",
                    descriptions_multilingual[language],
                    language,
                )

        # Rename node multi-lingual:
        if not simulate:
            response = self.rename_node(
                node_id=current_node_id,
                name=name,
                description=description,
                name_multilingual=names_multilingual,
                description_multilingual=descriptions_multilingual,
            )
            if not response:
                return False

        return True

    # end method definition

    def _check_filter(
        self,
        workspace_type_name: str,
        workspace_type_id: int,
        workspace_type_exclusions: str | list | None = None,
        workspace_type_inclusions: str | list | None = None,
    ) -> bool:
        """Check the workspace type filters.

        We pass both, the workspace type name and workspace type ID as
        we don't know (and don't want to assume) if the filter lists include
        type names or type ID. So we check both.

        There's an exclusion and an inclusion list. The exclusion list
        is checked first. if a workspace type is excluded this has preference
        over inclusions.

        Args:
            workspace_type_name (str):
                The name of the workspace type.
            workspace_type_id (int):
                The ID of the workspace type.
            workspace_type_exclusions (str | list | None):
                List of workspace types to exclude. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly excluded is included.
                None = filter is not active.
            workspace_type_inclusions (str | list | None):
                List of workspace types to include. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly included is excluded.
                None = filter is not active.

        Returns:
            bool:
                True = workspace type should be processed.
                False = workspace type should not be processed.

        """

        #
        # 1. Check Exclusions (either on type name or type ID basis):
        #
        if workspace_type_exclusions and (
            workspace_type_name in workspace_type_exclusions or workspace_type_id in workspace_type_exclusions
        ):
            return False

        #
        # 2. Check Inclusions - only if some exist (either on type name or type ID basis):
        #
        include = (
            not workspace_type_inclusions  # if no inclusion list is given all types will be included!
            or workspace_type_name in workspace_type_inclusions
            or workspace_type_id in workspace_type_inclusions
        )

        return include

    # endsub-method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="traverse_workspaces")
    def traverse_workspaces(
        self,
        workspace_type_exclusions: str | list | None = None,
        workspace_type_inclusions: str | list | None = None,
        filter_at_traversal: bool = False,
        node_executables: list[callable] | None = None,
        relationship_executables: list[callable] | None = None,
        relationship_types: list | None = None,
        max_depth: int | None = None,
        **kwargs: dict,
    ) -> dict:
        """Traverse all workspaces of a given type and execute executables.

        Args:
            workspace_type_exclusions (str | list | None):
                List of workspace types to exclude. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly excluded is included.
                None = filter is not active.
            workspace_type_inclusions (str | list | None):
                List of workspace types to include. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly included is excluded.
                None = filter is not active.
            filter_at_traversal (bool, optional):
                If False (default) the inclusion and exclusion filters are only tested for the
                queue initialization not the traversal via workspace relationships.
                If True the inclusion and exclusion filters are also tested
                during the traversal of workspace relationships.
            node_executables (list[callable]):
                A list of methods to call for each traversed workspace. The node
                and a optional dictionary of keyword arguments (kwargs)
                are passed. The executables are called BEFORE the subnodes
                are traversed. The executables should return a boolean result.
                If the result is False, then the execution of the executables
                list is stopped.
            relationship_executables (list[callable]):
                Callables to execute per workspace relationship.
            relationship_types (list | None, optional):
                The default that will be established if None is provided is ["child", "parent"].
            max_depth (int | None):
                The maximum depth for the recursive traversal.
            kwargs:
                Additional keyword arguments for the executables.

        """

        results = {"processed": 0, "traversed": 0}

        # Establish the default for relationship types which is just "child":
        if relationship_types is None:
            relationship_types = ["child", "parent"]

        processed_workspaces = {}

        workspace_types = self.get_workspace_types_iterator(expand_workspace_info=False, expand_templates=False)
        for workspace_type in workspace_types:
            wksp_type_id = self.get_result_value(response=workspace_type, key="wksp_type_id")
            wksp_type_name = self.get_result_value(response=workspace_type, key="wksp_type_name")
            if not self._check_filter(
                workspace_type_name=wksp_type_name,
                workspace_type_id=wksp_type_id,
                workspace_type_exclusions=workspace_type_exclusions,
                workspace_type_inclusions=workspace_type_inclusions,
            ):
                self.logger.debug(
                    "Skipping traversal initialization of workspace type -> '%s' (%d) as it does not match filter.",
                    wksp_type_name,
                    wksp_type_id,
                )
                continue

            workspace_instances = self.get_workspace_instances_iterator(type_id=wksp_type_id)
            for workspace_instance in workspace_instances:
                # Call the actual recursive traversal method:
                result = self.traverse_workspace(
                    workspace_node=workspace_instance,
                    current_depth=0,
                    processed_workspaces=processed_workspaces,
                    workspace_type_exclusions=workspace_type_exclusions,
                    workspace_type_inclusions=workspace_type_inclusions,
                    node_executables=node_executables,
                    relationship_executables=relationship_executables,
                    relationship_types=relationship_types,
                    filter_at_traversal=filter_at_traversal,
                    max_depth=max_depth,
                    **kwargs,
                )
                results["traversed"] += result["traversed"]
                results["processed"] += result["processed"]
            # end for workspace_instance in workspace_instances:
        # end for workspace_type in workspace_types:

        return results

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="traverse_workspace")
    def traverse_workspace(
        self,
        workspace_node: dict | int,
        processed_workspaces: dict,
        current_depth: int,
        workspace_type_exclusions: str | list | None = None,
        workspace_type_inclusions: str | list | None = None,
        filter_at_traversal: bool = False,
        node_executables: list[callable] | None = None,
        relationship_executables: list[callable] | None = None,
        relationship_types: list | None = None,
        max_depth: int | None = None,
        **kwargs: dict,
    ) -> dict:
        """Recursively traverse all workspaces and relationships.

        This method is preferred for CPU intensive traversals.

        Args:
            workspace_node (dict | int):
                The workspace node datastructure (like in a V2 REST Call response)
            processed_workspaces (dict):
                The already processed workspaces. Required to avoid running in circles
                and reprocess already traversed workspaces.
            workspace_type_exclusions (str | list | None):
                List of workspace types to exclude. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly excluded is included.
                None = filter is not active.
            workspace_type_inclusions (str | list | None):
                List of workspace types to include. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly included is excluded.
                None = filter is not active.
            filter_at_traversal (bool, optional):
                If False (default) the inclusion and exclusion filters are only tested for the
                queue initialization not the traversal via workspace relationships.
                If True the inclusion and exclusion filters are also tested
                during the traversal of workspace relationships.
            node_executables (list[callable]):
                A list of methods to call for each traversed workspace. The node
                and a optional dictionary of keyword arguments (kwargs)
                are passed. The executables are called BEFORE the subnodes
                are traversed. The executables should return a boolean result.
                If the result is False, then the execution of the executables
                list is stopped.
            relationship_executables (list[callable]):
                Callables to execute per workspace relationship.
            relationship_types (list | None, optional):
                The default that will be established if None is provided is ["child", "parent"].
            current_depth (int):
                The current depth of the traversal.
            max_depth (int | None):
                The maximum depth for the recursive traversal.
            kwargs:
                Additional keyword arguments for the executables.

        Returns:
            dict: {
                "processed": int,
                "traversed": int,
            }

        """

        processed = 0
        traversed = 0

        # Initialze the traverse flag. If True, container
        # subnodes will be processed. If executables exist
        # then at least one executable has to indicate that
        # further traversal is required:
        traverse = not (node_executables)

        # Establish the default for relationship types which is both directions: "child" and "parent":
        if relationship_types is None:
            relationship_types = ["child", "parent"]

        if max_depth is not None and current_depth > max_depth:
            self.logger.info("Reached maximum traversal depth of %d. Don't go deeper here...", max_depth)
            return {"processed": processed, "traversed": traversed}

        if isinstance(workspace_node, dict):
            workspace_node_id = self.get_result_value(response=workspace_node, key="id")
        elif isinstance(workspace_node, int):
            workspace_node_id = workspace_node
            workspace_node = self.get_workspace(node_id=workspace_node_id)
        else:
            self.logger.error("Illegal type of workspace node parameter. Expect 'int' or 'dict'!")
            return {"processed": processed, "traversed": traversed}

        workspace_name = self.get_result_value(response=workspace_node, key="name")
        workspace_type_id = self.get_result_value(response=workspace_node, key="wnf_wksp_type_id")
        workspace_type_name = self.get_workspace_type_name(type_id=workspace_type_id)

        if workspace_node_id in processed_workspaces:
            self.logger.info(
                "Stop at workspace -> '%s' (%d) of type %s as it has been processed before.",
                workspace_name,
                workspace_node_id,
                "-> '{}' ({})".format(workspace_type_name, workspace_type_id)
                if workspace_type_name
                else "ID -> {}".format(workspace_type_id),
            )
            return {"processed": processed, "traversed": traversed}
        processed_workspaces[workspace_node_id] = workspace_name

        self.logger.info(
            "Processing workspace -> '%s' (%s) of type -> '%s' (%d) in depth -> %d",
            workspace_name,
            workspace_node_id,
            workspace_type_name,
            workspace_type_id,
            current_depth,
        )
        # Run executables:
        for executable in node_executables or []:
            result_success, result_traverse = executable(node=workspace_node, **kwargs)
            if result_traverse:
                traverse = True
            if not result_success:
                break
        else:
            # else case is processed only if NO break occured in the for loop
            # If all executables have been successful than the node counts as processed:
            processed += 1

        # We only traverse related workspaces if the executables
        # have all been executed successfully:
        if traverse:
            for rel_type in relationship_types:
                # Get children nodes of the current node:
                workspace_relationships = self.get_workspace_relationships_iterator(
                    workspace_id=workspace_node_id, relationship_type=rel_type
                )

                # Recursive call of all subnodes:
                for related_workspace in workspace_relationships:
                    related_workspace_id = self.get_result_value(response=related_workspace, key="id")
                    related_workspace_name = self.get_result_value(response=related_workspace, key="name")
                    related_workspace_type_id = self.get_result_value(
                        response=related_workspace, key="wnf_wksp_type_id"
                    )
                    related_workspace_type_name = self.get_workspace_type_name(type_id=related_workspace_type_id)

                    if filter_at_traversal and not self._check_filter(
                        workspace_type_name=related_workspace_type_name,
                        workspace_type_id=int(related_workspace_type_id),
                        workspace_type_exclusions=workspace_type_exclusions,
                        workspace_type_inclusions=workspace_type_inclusions,
                    ):
                        self.logger.info(
                            "Skipping traversal of related workspace type -> '%s' (%d) as it does not match filter.",
                            related_workspace_type_name,
                            related_workspace_type_id,
                        )
                        continue

                    self.logger.info(
                        "Traversing related %s workspace -> '%s' (%d) of type %s",
                        rel_type,
                        related_workspace_name,
                        related_workspace_id,
                        "-> '{}' ({})".format(related_workspace_type_name, related_workspace_type_id)
                        if related_workspace_type_name
                        else "ID -> {}".format(related_workspace_type_id),
                    )
                    # Recursive call for related workspace:
                    result = self.traverse_workspace(
                        workspace_node=related_workspace,
                        current_depth=current_depth + 1,
                        processed_workspaces=processed_workspaces,
                        node_executables=node_executables,
                        relationship_executables=relationship_executables,
                        max_depth=max_depth,
                        **kwargs,
                    )
                    processed += result.get("processed", 0)
                    traversed += result.get("traversed", 0)
                traversed += 1
            # end for rel_type...
        # end if traversal

        return {"processed": processed, "traversed": traversed}

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="traverse_workspaces_parallel")
    def traverse_workspaces_parallel(
        self,
        workspace_type_exclusions: str | list | None = None,
        workspace_type_inclusions: str | list | None = None,
        filter_at_traversal: bool = False,
        node_executables: list[callable] | None = None,
        relationship_executables: list[callable] | None = None,
        relationship_types: list | None = None,
        workers: int = 3,
        workers_name: str = "TraverseWorkspaceWorker",
        strategy: str = "BFS",
        max_depth: int | None = None,
        timeout: float = 60.0,
        **kwargs: dict,
    ) -> dict:
        """Traverse nodes using a queue and thread pool (BFS-style).

        This method is preferred for I/O or API intensive traversals.

        Args:
            workspace_type_exclusions (str | list | None):
                List of workspace types to exclude. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly excluded is included.
                None = filter is not active.
            workspace_type_inclusions (str | list | None):
                List of workspace types to include. Can be a single workspace type
                or a list of workspace types. Everything that is not explicitly included is excluded.
                None = filter is not active.
            filter_at_traversal (bool, optional):
                If False (default) the inclusion and exclusion filters are only tested for the
                queue initialization not the traversal via workspace relationships.
                If True the inclusion and exclusion filters are also tested
                during the traversal of workspace relationships.
            node_executables (list[callable]):
                Callables to execute per node.
            relationship_executables (list[callable]):
                Callables to execute per workspace relationship.
            relationship_types (list | None, optional):
                The default that will be established if None is provided is ["child", "parent"].
            workers (int, optional):
                Number of parallel workers.
            workers_name (str, optional):
                Name prefix for worker threads.
            strategy (str, optional):
                Either "DFS" for Depth First Search, or "BFS" for Breadth First Search.
                "BFS" is the default.
            max_depth (int | None):
                The maximum depth for the recursive traversal.
            timeout (float, optional):
                Wait time for the queue to have items. This is also the time it
                takes at the end to detect the workers are done. So expect delay
                if you raise it high!
            kwargs (dict):
                Additional arguments for executables.

        Returns:
            dict:
                Stats with processed and traversed counters.

        """

        results = {"processed": 0, "traversed": 0}

        processed_workspaces = {}

        # Establish the default for relationship types which is just "child":
        if relationship_types is None:
            relationship_types = ["child", "parent"]

        # Unify data types to make filtering easier:
        if workspace_type_exclusions is None:
            workspace_type_exclusions = []
        if workspace_type_inclusions is None:
            workspace_type_inclusions = []
        if isinstance(workspace_type_exclusions, str):
            workspace_type_exclusions = [workspace_type_exclusions]
        if isinstance(workspace_type_inclusions, str):
            workspace_type_inclusions = [workspace_type_inclusions]

        lock = threading.Lock()
        if strategy == "BFS":
            task_queue = Queue()
        elif strategy == "DFS":
            task_queue = LifoQueue()

        initialization_done = False

        @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="init_traversal_queue")
        def init_traversal_queue() -> None:
            """Initialize the queue with all workspace instances of all workspace types (filtered)."""

            nonlocal initialization_done
            counter = 0

            # thread_name = threading.current_thread().name

            self.logger.debug("Initialize traversal queue...")

            # Enqueue initial nodes at depth 0:
            workspace_types = self.get_workspace_types_iterator(expand_workspace_info=False, expand_templates=False)
            for workspace_type in workspace_types:
                wksp_type_id = self.get_result_value(response=workspace_type, key="wksp_type_id")
                wksp_type_name = self.get_result_value(response=workspace_type, key="wksp_type_name")
                if wksp_type_id not in self._workspace_type_lookup:
                    self._workspace_type_lookup[wksp_type_id] = {"location": None, "name": wksp_type_name}
                if not self._check_filter(
                    workspace_type_name=wksp_type_name,
                    workspace_type_id=wksp_type_id,
                    workspace_type_exclusions=workspace_type_exclusions,
                    workspace_type_inclusions=workspace_type_inclusions,
                ):
                    self.logger.debug(
                        "Skipping traversal initialization of workspace type -> '%s' (%d) as it does not match filter.",
                        wksp_type_name,
                        wksp_type_id,
                    )
                    continue

                workspace_instances = self.get_workspace_instances_iterator(type_id=wksp_type_id)
                for workspace_instance in workspace_instances:
                    # Add the workspace and the current depth to the queue. Depth is 0 for the initial workspaces:
                    workspace_id = self.get_result_value(response=workspace_instance, key="id")
                    workspace_name = self.get_result_value(response=workspace_instance, key="name")
                    self.logger.debug(
                        "Add workspace -> '%s' (%d), type -> '%s' (%d) to worker queue for traversal...",
                        workspace_name,
                        workspace_id,
                        wksp_type_name,
                        wksp_type_id,
                    )
                    task_queue.put((workspace_instance, 0))
                    counter += 1
                # end for workspace_instances...
            # end for workspace_type ...

            self.logger.debug(
                "Initialization of traversal queue completed. Added %s workspaces in total to queue. Workers don't have to wait any more if queue is empty.",
                f"{counter:,}",
            )
            initialization_done = True

        # end sub-method definition

        @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="traverse_workspace_worker")
        def traverse_workspace_worker() -> None:
            """Work on queue.

            Returns:
                None

            """

            nonlocal initialization_done

            while True:
                # Initialze the traverse flag. If True, container
                # subnodes will be processed. If executables exist
                # than at least one executable has to return that
                # further traversal is required:
                traverse = not (node_executables)

                try:
                    self.logger.debug(
                        "Try to retrieve a new workspace from the queue. Wait max %f seconds...",
                        timeout,
                    )
                    # We ony wait for a timeout if initializazion of queue by initialization thread is not yet completed.
                    workspace_node, current_depth = task_queue.get(timeout=timeout if not initialization_done else 0.1)
                    self.logger.debug("Retrieved a new workspace from the queue.")
                except Empty:
                    self.logger.debug("No (more) workspaces to process - finishing...")
                    return  # Queue is empty - worker is done

                try:
                    if max_depth is not None and current_depth > max_depth:
                        self.logger.debug("Reached maximum traversal depth of %d. Don't go deeper here...", max_depth)
                        continue  # will jump to finally, declare task done and only then continue while loop

                    # Fetch node dictionary if just an ID was passed as parameter:
                    if isinstance(workspace_node, int):
                        workspace_node = self.get_workspace(node_id=workspace_node)

                    workspace_id = self.get_result_value(response=workspace_node, key="id")
                    workspace_name = self.get_result_value(response=workspace_node, key="name")
                    workspace_type_id = self.get_result_value(response=workspace_node, key="wnf_wksp_type_id")
                    workspace_type_name = self.get_workspace_type_name(type_id=workspace_type_id)  # this can be None!

                    with lock:
                        if workspace_id in processed_workspaces:
                            self.logger.debug(
                                "Stop at workspace -> '%s' (%d) of type %s as it has been processed before.",
                                workspace_name,
                                workspace_id,
                                "-> '{}' ({})".format(workspace_type_name, workspace_type_id)
                                if workspace_type_name
                                else "ID -> {}".format(workspace_type_id),
                            )
                            continue  # will jump to finally, declare task done and only then continue while loop
                        processed_workspaces[workspace_id] = workspace_name

                    self.logger.debug(
                        "Processing workspace -> '%s' (%d) of type -> '%s' (%d) in depth -> %d",
                        workspace_name,
                        workspace_id,
                        workspace_type_name,
                        workspace_type_id,
                        current_depth,
                    )

                    # Run all executables for the workspace node:
                    for executable in node_executables or []:
                        try:
                            result_success, result_traverse = executable(
                                workspace_node=workspace_node,
                                **kwargs,
                            )
                            if result_traverse:
                                traverse = True
                            if not result_success:
                                break
                        except Exception as e:
                            self.logger.error(
                                "Failed to run workspace node executable on workspace -> '%s' (%s), error -> %s",
                                workspace_name,
                                workspace_id,
                                str(e),
                            )
                    else:
                        with lock:
                            results["processed"] += 1

                    # We only traverse the workspaces connected via child relationships
                    # if at least one executables (if they any) indicate to require further traversal.
                    # Additional we check that "child" relationships re requested to follow:
                    if traverse:
                        for rel_type in relationship_types:
                            # Get related workspaces of the current workspace and the current relationship type:
                            workspace_relationships = self.get_workspace_relationships_iterator(
                                workspace_id=workspace_id, relationship_type=rel_type
                            )

                            # Traverse all related workspaces:
                            for related_workspace in workspace_relationships:
                                related_workspace_id = self.get_result_value(response=related_workspace, key="id")
                                related_workspace_name = self.get_result_value(response=related_workspace, key="name")
                                related_workspace_type_id = self.get_result_value(
                                    response=related_workspace, key="wnf_wksp_type_id"
                                )
                                # Determine the name of the workspace type with the help of the
                                # lookup dictionary created in init_traversal_queue():
                                related_workspace_type_name = self.get_workspace_type_name(
                                    type_id=related_workspace_type_id
                                )
                                if filter_at_traversal and not self._check_filter(
                                    workspace_type_name=related_workspace_type_name,
                                    workspace_type_id=related_workspace_type_id,
                                    workspace_type_exclusions=workspace_type_exclusions,
                                    workspace_type_inclusions=workspace_type_inclusions,
                                ):
                                    self.logger.debug(
                                        "Skipping traversal of related %s workspace as its type %s does not match filter.",
                                        rel_type,
                                        "-> '{}' ({})".format(related_workspace_type_name, related_workspace_type_id)
                                        if related_workspace_type_name
                                        else "ID -> {}".format(related_workspace_type_id),
                                    )
                                    continue  # the for loop
                                self.logger.debug(
                                    "Traversing related %s workspace -> '%s' (%d) of type %s in depth -> %d",
                                    rel_type,
                                    related_workspace_name,
                                    related_workspace_id,
                                    "-> '{}' ({})".format(related_workspace_type_name, related_workspace_type_id)
                                    if related_workspace_type_name
                                    else "ID -> {}".format(related_workspace_type_id),
                                    current_depth,
                                )

                                # Run all executables for the workspace relationship:
                                for executable in relationship_executables or []:
                                    try:
                                        result_success, result_traverse = executable(
                                            workspace_node_from=workspace_node,
                                            workspace_node_to=related_workspace,
                                            rel_type=rel_type,
                                            **kwargs,
                                        )
                                        if result_traverse:
                                            traverse = True
                                        if not result_success:
                                            break
                                    except Exception as e:
                                        self.logger.error(
                                            "Failed to run workspace relationship executable on workspace -> '%s' (%d) and related workspace -> '%s' (%d), error -> %s",
                                            workspace_name,
                                            workspace_id,
                                            related_workspace_name,
                                            related_workspace_id,
                                            str(e),
                                        )
                                # end executable in relationship_executables or []

                                # Put related workspace into the queue for traversal:
                                task_queue.put((related_workspace, current_depth + 1))

                                with lock:
                                    results["traversed"] += 1
                            # end for related_workspace in workspace_relationships
                        # end for rel_type in relationship_types:
                    # end if traverse and "child" in relationship_types:

                except Exception as worker_error:
                    self.logger.error("Worker thread crashed unexpectedly; error -> %s", str(worker_error))

                finally:
                    # Guarantee task_done() is called even if exceptions occur.
                    # Also continue statements in the try-block will first jump
                    # to here before continuing the while loop!
                    task_queue.task_done()
            # end while True

        # end method traverse_node_worker()

        # Start thread that populates the task queue
        init_thread = threading.Thread(target=init_traversal_queue, name="TraversalQueueInitializer")
        init_thread.start()

        # Start thread pool with limited concurrency
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=workers_name) as executor:
            for i in range(workers):
                self.logger.debug("Starting workspace traversal worker -> %d...", i)
                executor.submit(traverse_workspace_worker)

            # Wait for all tasks to complete
            self.logger.debug("Waiting for workers to complete...")
            task_queue.join()
        self.logger.debug("All workers have completed their tasks!")

        # Ensure initializer is finished before we return
        self.logger.debug("Waiting for the initializer thread to finish...")
        init_thread.join()

        return results

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="download_document_multi_threading")
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
            extract_after_download (bool, optional):
                Extract the downloaded (compressed) file recusively to a folder
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
                    "Failed to unzip node (%d) -> %s",
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="apply_filter")
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
                Defaults to None = filter not active. filter_subtypes = [] is different from None!
                If an empty list is provided, the filter is effectively always True.
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

        if filter_subtypes is not None and node["type"] not in filter_subtypes:
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

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="add_attribute_columns")
    def add_attribute_columns(self, row: dict, categories: dict, prefix: str) -> bool:
        """Add attributes for all categories to the row dictionary.

        The resulting row will be added by the calling load_items() method
        to a Data Frame.

        Args:
            row (dict):
                The row data to extend with keys for each attribute.
            categories (dict):
                The categories of the node. This is a structure like
                {
                    "links" = {}
                    "results" = [
                        {
                            "data" = {
                                "categories" = {
                                    "14885_10_1_11 = "Aerospace", # Multi-value set row 1, attribute 11
                                    "14885_10_2_11 = "Automotive" # Multi-value set row 2, attribute 11
                                    "14885_14" = ["Content"] # Multi-value attribute
                                    "14885_15" = "Test" # Single value attribute
                                }
                            }
                            "metadata" = {
                                "categories" = {
                                    "14885_10" = {...} # Definition of the set
                                    "14885_10_x_11" = {...} # Definition of the set attribute
                                    "144885_14" = {...} # Definition of multi-value attribute
                                }
                            }
                        }
                    ]
                }
            prefix (str):
                The prefix string. Either "workspace_" or "item_" to
                differentiate attributes on workspace level and attributes
                on item (document) level.

        Returns:
            bool:
                True = succeess, False = error.

        """

        def get_attribute_identifier(s: str) -> str:
            # Get the prefix of two numbers separated by an underscore:
            match = re.match(r"^([^_]+_[^_]+)", s)
            return match.group(1) if match else ""

        def get_column_identifier(s: str) -> str:
            # Cut out the third number if there's a third number. Used for set attributes
            match = re.match(r"^([^_]+_[^_]+)(?:.*_([0-9]+))?$", s)
            return f"{match.group(1)}_{match.group(2)}" if match and match.group(2) else match.group(1)

        def get_set_identifier(s: str) -> str:
            return re.sub(r"^([^_]+_[^_]+_)[^_]+", r"\1x", s)

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

            # Iterate over all attributes. For multi-value sets (which are basically a matrix or table)
            # we do a special handling. The values of each column of such a table are written as a value list in a
            # separate data frame column. So we slice the multi-value set by columns (not rows).
            # This way this can later on recombined by "columns_to_add_table" in the payload.
            for key in attributes:
                value = attributes[key]
                # We don't want "_x_" in the column identifiers as we create a list:
                column_key = get_column_identifier(key)
                # The attribute key should just be the category ID (before first "_")
                # and the attribute or set ID (after first "_"):
                attribute_key = get_attribute_identifier(key)
                meta = metadata[attribute_key]
                if self._use_numeric_category_identifier:  # this value is set be the class initializer
                    column_header = prefix + column_key
                else:
                    # Construct the final column name by replacing the leading <cat_num>_ with the
                    # normalized name of the category.
                    column_header = prefix + re.sub(r"^[^_]+_", category_name + "_", column_key)
                # Check if meta is the schema for a multi-value set. This is the
                # case if "multi_value" is True _and_ "persona" is "set":
                if meta.get("multi_value", False) and meta.get("persona") == "set":
                    # Is it the first value line? Then we need to initialize the list...
                    if column_header not in row:
                        row[column_header] = []
                    row[column_header].append(value)
                else:
                    # Not a multi-value set. We just write the value
                    # into the data frame (in case it is a multi-value
                    # a)
                    row[column_header] = value

        return True

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="load_items")
    def load_items(
        self,
        node_id: int,
        workspaces: bool = True,
        items: bool = True,
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
        workers: int = 3,
    ) -> dict | None:
        """Create a Pandas Data Frame by traversing a given Content Server hierarchy.

        This method collects workspace and document items.

        Args:
            node_id (int):
                The root Node ID the traversal should start at.
            workspaces (bool, optional):
                If True, workspaces are included in the data frame.
                Defaults to True.
            items (bool, optional):
                If True, document items are included in the data frame.
                Defaults to True.
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
                If True, include item metadata.
            download_documents (bool, optional):
                Whether or not documents should be downloaded.
            skip_existing_downloads (bool, optional):
                If True, reuse already existing downloads in the file system.
            extract_zip (bool, optional):
                If True, documents that are downloaded with mime-type
                "application/x-zip-compressed" will be extracted recursively.
            workers (int, optional):
                Number of worker threads to start.

        Returns:
            dict:
                Stats with processed and traversed counters.

        Side Effects:
            The resulting data frame is stored in self._data. It will have the following columns:
            - type which is either "item" or "workspace"
            - workspace_type
            - workspace_id
            - workspace_name
            - workspace_description
            - workspace_outer_path
            - workspace_<cat_id>_<attr_id> for each workspace attribute if workspace_metadata is True
            - item_id
            - item_type
            - item_name
            - item_description
            - item_path
            - item_download_name
            - item_mime_type
            - item_url
            - item_<cat_id>_<attr_id> for each item attribute if item_metadata is True
            - item_cat_<cat_id>_<attr_id> for each item attribute if item_metadata is True and self._use_numeric_category_identifier is True
            - item_cat_<cat_name>_<attr_name> for each item attribute if item_metadata is True and self._use_numeric_category_identifier is False

        """

        # Initiaze download threads for document items:
        download_threads = []

        def check_node_exclusions(node: dict, **kwargs: dict) -> tuple[bool, bool]:
            """Check if the processed node is on the exclusion list.

            Stop processing and traversing if the node is excluded.

            Args:
                node (dict):
                    The current node being processed.
                kwargs (dict):
                    Additional keyword arguments that are specific for the method.

            Returns:
                tuple[bool, bool]:
                    success (bool) - if node was processed successfully
                    traverse (bool) - if subnodes should be processed

            """

            # Get the list of node IDs to exclude from the keyword arguments.
            # If not provided, use an empty list as default which means no exclusions.
            exclude_node_ids = kwargs.get("exclude_node_ids") or []

            node_id = self.get_result_value(response=node, key="id")
            node_name = self.get_result_value(response=node, key="name")

            if node_id and (node_id in exclude_node_ids):
                self.logger.debug(
                    "Node -> '%s' (%s) is in exclusion list. Skip traversal of this node.",
                    node_name,
                    node_id,
                )
                return (False, False)
            return (True, True)

        # end check_node_exclusions()

        def check_node_workspace(node: dict, **kwargs: dict) -> tuple[bool, bool]:
            """Check if the processed node should be recorded as a workspace in the data frame.

            Args:
                node (dict):
                    The current node being processed.
                kwargs (dict):
                    Additional keyword arguments that are specific for the method.

            Returns:
                tuple[bool, bool]:
                    success (bool) - if node was processed successfully
                    traverse (bool) - if subnodes should be processed

            """

            # This should actually not happen as the caller should
            # check if workspaces are requested before calling this function.
            if not workspaces:
                # Success = False, Traverse = True
                return (False, True)

            traversal_data = kwargs.get("traversal_data")
            filter_workspace_data = kwargs.get("filter_workspace_data")
            control_flags = kwargs.get("control_flags")

            if not traversal_data:
                self.logger.error(
                    "Missing keyword argument 'traversal_data' for executable 'check_node_workspace' in node traversal!"
                )
                # Success = False, Traverse = False
                return (False, False)

            if not filter_workspace_data:
                self.logger.error(
                    "Missing keyword argument 'filter_workspace_data' for executable 'check_node_workspace' in node traversal!"
                )
                # Success = False, Traverse = False
                return (False, False)

            if not control_flags:
                self.logger.error(
                    "Missing keyword argument 'control_flags' for executable 'check_node_workspace' in node traversal!"
                )
                # Success = False, Traverse = False
                return (False, False)

            node_id = self.get_result_value(response=node, key="id")
            node_name = self.get_result_value(response=node, key="name")
            node_description = self.get_result_value(response=node, key="description")
            node_type = self.get_result_value(response=node, key="type")

            #
            # 1. Check if the traversal is already inside a workspace. Then we can skip
            #    the workspace processing as we currently don't support sub-workspaces.
            #
            workspace_id = traversal_data.get("workspace_id")
            if workspace_id:
                self.logger.debug(
                    "Found folder or workspace -> '%s' (%s) inside workspace with ID -> %d. So this container cannot be a workspace.",
                    node_name,
                    node_id,
                    workspace_id,
                )
                # Success = False, Traverse = True
                return (False, True)

            #
            # 2. Check if metadata is required (either for columns or for filters)
            #
            if (
                control_flags["workspace_metadata"]
                or filter_workspace_data["filter_workspace_category"]
                or filter_workspace_data["filter_workspace_attributes"]
            ):
                categories = self.get_node_categories(
                    node_id=node_id,
                    metadata=(
                        filter_workspace_data["filter_workspace_category"] is not None
                        or filter_workspace_data["filter_workspace_attributes"] is not None
                        or not self._use_numeric_category_identifier
                    ),
                )
            else:
                categories = None

            #
            # 3. Apply the defined workspace filters to the current node to see
            #    if we want to 'interpret' it as a workspace
            #
            # See if it is a node that we want to interpret as a workspace.
            # Only "workspaces" that comply with ALL provided filters are
            # considered and written into the data frame as a workspace row:
            # Root nodes may have a "results" dict. The subnode iterators don't have it:
            node_properties = node["results"]["data"]["properties"] if "results" in node else node["data"]["properties"]
            if not self.apply_filter(
                node=node_properties,
                node_categories=categories,
                current_depth=traversal_data["current_depth"],
                filter_depth=filter_workspace_data["filter_workspace_depth"],
                filter_subtypes=filter_workspace_data["filter_workspace_subtypes"],
                filter_category=filter_workspace_data["filter_workspace_category"],
                filter_attributes=filter_workspace_data["filter_workspace_attributes"],
            ):
                self.logger.debug(
                    "Node -> '%s' (%s) did not match workspace filter -> %s",
                    node_name,
                    node_id,
                    str(filter_workspace_data),
                )

                # Success = False, Traverse = True
                return (False, True)

            self.logger.debug(
                "Found workspace -> '%s' (%s) in depth -> %s.",
                node_name,
                node_id,
                traversal_data["current_depth"],
            )

            #
            # 4. Create the data frame row from the node / traversal data:
            #
            row = {"type": "workspace"}
            row["workspace_type"] = node_type
            row["workspace_id"] = node_id
            row["workspace_name"] = node_name
            row["workspace_description"] = node_description
            row["workspace_outer_path"] = traversal_data["folder_path"]
            # If we want (and have) metadata then add it as columns:
            if control_flags["workspace_metadata"] and categories and categories.get("results", None):
                # Add columns for workspace node categories have been determined above.
                self.add_attribute_columns(row=row, categories=categories, prefix="workspace_cat_")

            # Now we add the article to the Pandas Data Frame in the Data class:
            with self._data.lock():
                self._data.append(row)

            #
            # 5. Update the traversal data:
            #
            traversal_data["workspace_id"] = node_id
            traversal_data["workspace_name"] = node_name
            traversal_data["workspace_type"] = node_type
            traversal_data["workspace_description"] = node_description
            self.logger.debug("Updated traversal data -> %s", str(traversal_data))

            # Success = True, Traverse = True
            # We have traverse = True because we need to
            # keep traversing into the workspace folders.
            return (True, True)

        # end check_node_workspace()

        def check_node_item(node: dict, **kwargs: dict) -> tuple[bool, bool]:
            """Check if the processed node should be recorded as an item in the data frame.

            Args:
                node (dict):
                    The current node being processed.
                kwargs (dict):
                    Additional keyword arguments that are specific for the method.

            Returns:
                tuple[bool, bool]:
                    success (bool) - if node was processed successfully
                    traverse (bool) - if subnodes should be processed

            """

            traversal_data = kwargs.get("traversal_data")
            filter_item_data = kwargs.get("filter_item_data")
            control_flags = kwargs.get("control_flags")

            if not traversal_data:
                self.logger.error("Missing keyword argument 'traversal_data' for executable in node item traversal!")
                return (False, False)

            if not filter_item_data:
                self.logger.error("Missing keyword argument 'filter_item_data' for executable in node item traversal!")
                return (False, False)

            if not control_flags:
                self.logger.error("Missing keyword argument 'control_flags' for executable in node item traversal!")
                return (False, False)

            node_id = self.get_result_value(response=node, key="id")
            node_name = self.get_result_value(response=node, key="name")
            node_description = self.get_result_value(response=node, key="description")
            node_type = self.get_result_value(response=node, key="type")

            current_depth = traversal_data["current_depth"]
            folder_path = traversal_data["folder_path"]
            workspace_id = traversal_data.get("workspace_id")
            workspace_name = traversal_data.get("workspace_name")
            workspace_description = traversal_data.get("workspace_description")
            workspace_type = traversal_data.get("workspace_type")

            #
            # 1. Check if metadata is required (either for columns or for filters)
            #
            if (
                control_flags["item_metadata"]  # do we want item metadata?
                or filter_item_data["filter_item_category"]  # do we want to filter for category?
                or filter_item_data["filter_item_attributes"]  # do we want to filter for attributes?
            ):
                categories = self.get_node_categories(
                    node_id=node_id,
                    metadata=(
                        filter_item_data["filter_item_category"] is not None
                        or filter_item_data["filter_item_attributes"] is not None
                        or not self._use_numeric_category_identifier
                    ),
                )
            else:
                categories = None

            #
            # 2. Apply the defined item filters to the current node to see
            #    if we want to add it to the data frame as an item.
            #
            # If filter_item_in_workspace is false, then documents
            # inside workspaces are included in the data frame unconditionally!
            # We apply the defined filters to the current node. Only "documents"
            # that comply with ALL provided filters are considered and written into the data frame
            node_properties = node["results"]["data"]["properties"] if "results" in node else node["data"]["properties"]
            if (not workspace_id or filter_item_in_workspace) and not self.apply_filter(
                node=node_properties,
                node_categories=categories,
                current_depth=current_depth,
                filter_depth=filter_item_data["filter_item_depth"],
                filter_subtypes=filter_item_data["filter_item_subtypes"],
                filter_category=filter_item_data["filter_item_category"],
                filter_attributes=filter_item_data["filter_item_attributes"],
            ):
                self.logger.debug(
                    "Node -> '%s' (%s) did not match item filter -> %s",
                    node_name,
                    node_id,
                    str(filter_item_data),
                )

                # Success = False, Traverse = True
                return (False, True)

            # Debug output where we found the item (inside or outside of workspace):
            if workspace_id:
                self.logger.debug(
                    "Found %s item -> '%s' (%s) in depth -> %s inside workspace -> '%s' (%s).",
                    "document" if node_type == self.ITEM_TYPE_DOCUMENT else "URL",
                    node_name,
                    node_id,
                    current_depth,
                    workspace_name,
                    workspace_id,
                )
            else:
                self.logger.debug(
                    "Found %s item -> '%s' (%s) in depth -> %s outside of workspace.",
                    "document" if node_type == self.ITEM_TYPE_DOCUMENT else "URL",
                    node_name,
                    node_id,
                    current_depth,
                )

            # Special handling for documents: download them if requested:
            if node_type == self.ITEM_TYPE_DOCUMENT:
                # We use the node ID as the filename to avoid any
                # issues with too long or not valid file names.
                # As the Pandas DataFrame has all information
                # this is easy to resolve at upload time.
                file_path = "{}/{}".format(self._download_dir, node_id)

                # We download only if not downloaded before or if downloaded
                # before but forced to re-download:
                if control_flags["download_documents"] and (
                    not os.path.exists(file_path) or not control_flags["skip_existing_downloads"]
                ):
                    mime_type = self.get_result_value(response=node, key="mime_type")
                    extract_after_download = mime_type == "application/x-zip-compressed" and extract_zip
                    self.logger.debug(
                        "Downloading document -> '%s' (%s) to temp file -> '%s'%s...",
                        node_name,
                        mime_type,
                        file_path,
                        " and extracting it after download" if extract_after_download else "",
                    )

                    #
                    # Start asynchronous Download Thread:
                    #
                    thread = threading.Thread(
                        target=self.download_document_multi_threading,
                        args=(node_id, file_path, extract_after_download),
                        name="download_document_node_{}".format(node_id),
                    )
                    thread.start()
                    download_threads.append(thread)
                else:
                    self.logger.debug(
                        "Document -> '%s' has been downloaded to file -> %s before or download is not requested. Skipping download...",
                        node_name,
                        file_path,
                    )
            # end if document

            #
            # Construct a dictionary 'row' that we will add
            # to the resulting data frame:
            #
            row = {"type": "item"}
            if workspaces:
                # First we include some key workspace data to associate
                # the item with the workspace:
                row["workspace_type"] = workspace_type
                row["workspace_id"] = workspace_id
                row["workspace_name"] = workspace_name
                row["workspace_description"] = workspace_description
            # Then add item specific data:
            row["item_id"] = str(node_id)
            row["item_type"] = node_type
            row["item_name"] = node_name
            row["item_description"] = node_description
            row["item_path"] = []
            # We take the part of folder path which is inside the workspace
            # as the item path:
            if (
                folder_path and workspace_name and workspace_name in folder_path
            ):  # check if folder_path is not empty, this can happy if document items are the workspace items
                try:
                    # Item path are the list elements after the item that is the workspace name:
                    row["item_path"] = folder_path[folder_path.index(workspace_name) + 1 :]
                except ValueError:
                    self.logger.warning(
                        "Cannot find workspace name -> '%s' in folder path -> %s while processing -> '%s' (%s)!",
                        workspace_name,
                        folder_path,
                        node_name,
                        node_id,
                    )
            row["item_download_name"] = str(node_id) if node_type == self.ITEM_TYPE_DOCUMENT else ""
            row["item_mime_type"] = (
                self.get_result_value(response=node, key="mime_type") if node_type == self.ITEM_TYPE_DOCUMENT else ""
            )
            # URL specific data:
            row["item_url"] = self.get_result_value(response=node, key="url") if node_type == self.ITEM_TYPE_URL else ""
            if item_metadata and categories and categories["results"]:
                # Add columns for item node categories have been determined above.
                self.add_attribute_columns(row=row, categories=categories, prefix="item_cat_")

            # Now we add the item row to the Pandas Data Frame in the Data class:
            self.logger.info(
                "Adding %s -> '%s' (%s) to data frame...",
                "document" if node_type == self.ITEM_TYPE_DOCUMENT else "URL",
                row["item_name"],
                row["item_id"],
            )
            with self._data.lock():
                self._data.append(row)

            # Success = True, Traverse = False
            # We have traverse = False because document or URL items have no sub-items.
            return (True, False)

        # end check_node_item()

        #
        # Start Main method:
        #

        # Create folder if it does not exist
        if download_documents and not os.path.exists(self._download_dir):
            os.makedirs(self._download_dir)

        # These won't change during processing - stays the same for all nodes:
        filter_workspace_data = {
            "filter_workspace_depth": filter_workspace_depth,
            "filter_workspace_subtypes": filter_workspace_subtypes,
            "filter_workspace_category": filter_workspace_category,
            "filter_workspace_attributes": filter_workspace_attributes,
        }

        # These won't change during processing - stays the same for all nodes:
        filter_item_data = {
            "filter_item_depth": filter_item_depth,
            "filter_item_subtypes": filter_item_subtypes,
            "filter_item_category": filter_item_category,
            "filter_item_attributes": filter_item_attributes,
            "filter_item_in_workspace": filter_item_in_workspace,
        }

        # These won't change during processing - stays the same for all nodes:
        control_flags = {
            "workspace_metadata": workspace_metadata,
            "item_metadata": item_metadata,
            "download_documents": download_documents,
            "skip_existing_downloads": skip_existing_downloads,
            "extract_zip": extract_zip,
        }

        #
        # Define the list of executables to call for each node:
        #
        executables = []
        if workspaces:
            executables.append(check_node_workspace)
        if items:
            executables.append(check_node_item)
        if not executables:
            self.logger.error("Neither workspaces nor items are requested to be loaded. Nothing to do!")
            return None

        #
        # Start the traversal of the nodes:
        #
        result = self.traverse_node_parallel(
            node=node_id,
            # For each node we call these executables in this order to check if
            # the node should be added to the resulting data frame:
            executables=[check_node_exclusions, check_node_workspace, check_node_item],
            workers=workers,  # number of worker threads
            workers_name="LoadItemsWorker",
            exclude_node_ids=exclude_node_ids,
            filter_workspace_data=filter_workspace_data,
            filter_item_data=filter_item_data,
            control_flags=control_flags,
        )

        # Wait for all download threads to complete:
        for thread in download_threads:
            thread.join()

        return result

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="aviator_embed_metadata")
    def aviator_embed_metadata(
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
        """Run Content Aviator metadata embedding on provided node with FEME tool.

        Args:
            node_id (int):
                The node ID to start embedding for.
            node (dict | None, optional):
                If the caller already has the node data it can be passed with this parameter.
            crawl (bool, optional):
                Defines if the task is a "crawl" (vs. and "index"). Defaults to False (= "index").
            wait_for_completion (bool, optional):
                Defines if the method waits for the completion of the embedding. Defaults to True.
            message_override (dict | None, optional):
                Overwrite specific message details. Defaults to None.
            timeout (float, optional):
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

        success = True

        async def _inner(
            uri: str,
            node_properties: dict,
            crawl: bool,
            wait_for_completion: bool,
            message_override: dict | None,
            timeout: float,  # noqa: ASYNC109
            document_metadata: bool = False,
            images: bool = False,
            image_prompt: str = "",
            workspace_metadata: bool = True,
            remove_existing: bool = False,
        ) -> bool:
            # This is important as the sub-method needs to write
            # to the 'success' variable:
            nonlocal success

            self.logger.debug("Open WebSocket connection to -> %s", uri)
            async with websockets.connect(uri) as websocket:
                # Define if one node (index), or all childs should be processed (crawl)
                task = "crawl" if crawl else "index"

                message = {
                    "task": task,  # either "index" or "crawl". "crawl" means traversing OTCS workspaces and folders.
                    "nodes": [node_properties],  # the list of (root) nodes to process
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
                    "Start Content Aviator embedding on -> '%s' (%s), type -> %s, crawl -> %s, wait for completion -> %s, workspaces -> %s, documents -> %s, images -> %s",
                    node_properties["name"],
                    node_properties["id"],
                    node_properties["type"],
                    crawl,
                    wait_for_completion,
                    workspace_metadata,
                    document_metadata,
                    images,
                )
                self.logger.debug("Sending WebSocket message -> %s...", message)
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
                        success = False
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

        # Is this method called without the node data?
        # Then we get it with the node_id:
        if not node:
            node = self.get_node(node_id=node_id)
        if not node:
            self.logger.error(
                "Cannot get node with ID -> %d, skipping FEME embedding!",
                node_id,
            )
            return False
        try:
            node_properties = node["results"]["data"]["properties"] if "results" in node else node["data"]["properties"]
        except (json.JSONDecodeError, KeyError):
            self.logger.error(
                "Cannot decode data for node with ID -> %d, skipping embedding with FEME.",
                node_id,
            )
            return False

        uri = self._config["femeUri"]
        # The task will not immediately run, but only when we call
        # event_loop.run_until_complete(task) below:
        task = _inner(
            uri=uri,
            node_properties=node_properties,
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

        # event_loop = asyncio.new_event_loop()
        # asyncio.set_event_loop(loop=event_loop)

        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                # Running in FastAPI / Uvicorn context → schedule the coroutine
                self.logger.debug("Detected running event loop, scheduling coroutine on existing loop.")
                asyncio.create_task(task)  # noqa: RUF006
            else:
                # No running loop → safe to run normally
                self.logger.debug("No running loop detected, running asyncio task directly.")
                asyncio.run(task)

        # event_loop.run_until_complete(task)

        except websockets.exceptions.ConnectionClosed:  # :
            self.logger.error("WebSocket connection was closed!")
            success = False

        except TimeoutError:
            self.logger.error(
                "Timeout error during FEME WebSocket connection, WebSocket did not receive a message in time (%ss)",
                timeout,
            )
            success = False

        except Exception as exc:
            self.logger.error("Error during FEME WebSocket connection! -> %s", exc)
            success = False

        #        event_loop.close()

        return success

    # end method definition

    def _get_document_template_raw(self, workspace_id: int) -> ET.Element | None:
        """Get the raw template XML payload from a workspace.

        Args:
            workspace_id (int):
                The ID of the workspace to generate the document from.

        Returns:
            ET.Element | None:
                The XML Element with the payload to initiate a document generation, or None if an error occurred

        """

        # Get available SmartUI Actions to check if we have SuccessFactors or generic XECM PowerDocs templates configured:
        actions = self.get_node_actions(
            node_id=workspace_id, filter_actions=["xecmforsfcreatedocument", "xecmpfcreatedocument"]
        )
        if actions is None:
            self.logger.error(
                "Cannot get node actions for workspace with ID -> %d",
                workspace_id,
            )
            return None
        else:
            actions = actions["results"][str(workspace_id)]["data"]

        # SuccessFactors specific handling
        if "xECMforSFCreateDocument" in actions:
            request_url = self.config()["csUrl"]

            request_header = self.request_form_header()
            request_header["referer"] = "http://localhost"

            data = {
                "func": "xecmpfdocgen.PowerDocsPayload",
                "wsId": str(workspace_id),
                "hideHeader": "true",
                "source": "CreateDocument",
            }

            self.logger.debug(
                "Get document templates (SuccessFactors) for workspace with ID -> %d; calling -> %s",
                workspace_id,
                request_url,
            )

            response = self.do_request(
                url=request_url,
                method="POST",
                headers=request_header,
                data=data,
                timeout=None,
                failure_message="Failed to get document templates for workspace with ID -> {}".format(workspace_id),
                parse_request_response=False,
            )

        # Generic XECM PowerDocs handling
        elif "XECMPFCreateDocument" in actions:
            request_url = (
                self.config()["csUrl"]
                + f"?func=xecmpfdocgen.XECMPFPowerDocsPayload&wsId={workspace_id}&hideHeader=true"
            )

            request_header = self.request_json_header()

            self.logger.debug(
                "Get document templates for workspace with ID -> %d; calling -> %s",
                workspace_id,
                request_url,
            )

            response = self.do_request(
                url=request_url,
                method="GET",
                headers=request_header,
                timeout=None,
                failure_message="Failed to get document templates for workspace with ID -> {}".format(workspace_id),
                parse_request_response=False,
            )

        else:
            self.logger.error(
                "No known document template action found for workspace with ID -> %d",
                workspace_id,
            )
            return None

        # Continue processing of the response - same for both template types
        if response is None:
            return None

        try:
            text = response.text
            if text and "User is not authorized" in text:
                self.logger.error(
                    "The current user is not authorized to retrive document templates for document generation!"
                )
                return None
            match = re.search(r'<textarea[^>]*name=["\']documentgeneration["\'][^>]*>(.*?)</textarea>', text, re.DOTALL)
            textarea_content = match.group(1).strip() if match else ""
            textarea_content = html.unescape(textarea_content)

            # Load Payload into XML object
            # payload is an XML formatted string, load it into an XML object for further processing

            root = ET.Element("documentgeneration", format="pdf")
            root.append(ET.fromstring(textarea_content))
        except (ET.ParseError, AttributeError) as exc:
            self.logger.error(
                "Cannot parse document template XML payload for workspace with ID -> %d! Error -> %s",
                workspace_id,
                exc,
            )
            return None
        else:
            return root

    # end method definition

    def get_document_template_names(self, workspace_id: int, root: ET.Element | None = None) -> list[str] | None:
        """Get the list of available template names from a workspace.

        Args:
            workspace_id (int):
                The ID of the workspace to generate the document from.
            root (ET.Element | None, optional):
                The XML Element with the payload to initiate a document generation.

        Returns:
            list[str] | None:
                A list of template names available in the workspace, or None if an error occurred.

        """

        # If the XML root is not yet provided we get it now:
        if root is None:
            root = self._get_document_template_raw(workspace_id=workspace_id)
            if root is None:
                self.logger.error(
                    "Cannot get document templates for workspace with ID -> %d",
                    workspace_id,
                )
                return None
        template_names = [item.text for item in root.findall("startup/processing/templates/template")]

        return template_names

    # end method definition

    def get_document_template(
        self, workspace_id: int, template_name: str, input_values: dict | None = None
    ) -> str | None:
        """Get the template XML payload from a workspace and a given template name.

        Args:
            workspace_id (int):
                The ID of the workspace to generate the document from.
            template_name (str):
                The name of the template to use for document generation.
            input_values (dict | None, optional):
                A dictionary with input values to replace in the template.

        Returns:
            str | None:
                The XML string with the payload to initiate a document generation,
                or None if an error occurred.

        """

        root = self._get_document_template_raw(workspace_id=workspace_id)
        if root is None:
            self.logger.error(
                "Cannot get document template for workspace with ID -> %d",
                workspace_id,
            )
            return None

        template_names = self.get_document_template_names(workspace_id=workspace_id, root=root)

        if template_name not in template_names:
            self.logger.error(
                "Template name -> '%s' not found in workspace with ID -> %d! Available templates are: %s",
                template_name,
                workspace_id,
                ", ".join(template_names),
            )
            return None

        # remove startup/processing
        startup = root.find("startup")

        # Check if SuccessFactors or generic XECM PowerDocs template:
        application = startup.find("application")
        is_successfactors = bool(application)

        # Clear processing information
        processing = startup.find("processing")
        processing.clear()

        modus = ET.SubElement(processing, "modus")
        modus.text = "local"
        editor = ET.SubElement(processing, "editor")
        editor.text = "false"
        template = ET.SubElement(processing, "template", type="Name")
        template.text = template_name
        channel = ET.SubElement(processing, "channel")

        if is_successfactors:
            channel.text = "save"
        else:
            channel.text = "centralprint"

        # Add static query information for userId and asOfDate
        if input_values:
            query = ET.SubElement(startup, "query", type="value")
            input_element = ET.SubElement(query, "input")

            for column, value in input_values.items():
                value_element = ET.SubElement(input_element, "value", column=column)
                value_element.text = value

        payload = ET.tostring(root, encoding="utf8").decode("utf8")

        return payload

    # end method definition

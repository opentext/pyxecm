"""
OTCS Module to implement functions to read / write Content Server objects
such as Users, Groups, Nodes, Workspaces, ...

Class: OTCS

Class Methods:

date_is_newer: Compare two dates, typically create or modification dates

Methods:

__init__: class initializer
config: returns config data set
cookie: returns cookie information
otcs_ticket: Return the OTCS ticket
credentials: Get credentials (username and password)
set_credentials: Set new credentials
hostname: Get the configured OTCS hostname
set_hostname: Set the hostname of OTCS
base_url: Get OTCS base URL
cs_url: Get the Extended ECM (OTCS) URL
rest_url: Get OTCS REST base URL

get_data: Get the Data object that holds all loaded Content Server items (see method load_items())

request_form_header: Deliver the request header used for the CRUD REST API calls.
request_json_header: Deliver the request header for REST calls that require content type application/json.
request_download_header: Deliver the request header used for download REST API calls.
                         These calls accept application/octet-stream.
do_request: call an Extended ECM REST API in a safe way.
parse_request_response: Converts the text property of a request response object
                        to a Python dict in a safe way
lookup_result_value: Lookup a property value based on a provided key / value pair in the response
                     properties of an Extended ECM REST API call
exist_result_item: Check existence of key / value pair in the response properties of an Extended ECM REST API call.
get_result_value: Read an item value from the REST API response. This is considering the most typical structures
                  delivered by V2 REST API of Extended ECM

is_configured: returns true if the OTCS pod is ready to serve requests
authenticate : Authenticates at Content Server and retrieve OTCS Ticket.

get_server_info: return OTCS server information

apply_config: Apply Content Server administration settings from XML file

get_user: Lookup Content Server user
add_user: Add Content Server user
search_user: Find a user based on search criteria
update_user: Update a defined field for a user
get_user_profile: Get the profile (settings) for the current user
update_user_profile: Update a defined field of the user profile (settings)
                     for the current user.
update_user_photo: Update a user with a profile photo (which must be an existing node)
is_proxy: Check if a user (login name) is a proxy of the current user
get_user_proxies: Get the list of proxy users for the current user
add_user_proxy: Add a proxy to the current (authenticated) user
add_favorite: Add a favorite for the current (authenticated) user
add_favorite_tab: Add a favorite tab for the current (authenticated) user

get_group: Lookup Content Server group
add_group: Add Content Server group
get_group_members: Get Content Server group members
add_group_member: Add a user or group to a target group

get_node: Get a node based on the node ID
get_node_by_parent_and_name: Get a node based on the parent ID and name
get_node_by_workspace_and_path: Get a node based on the workspace ID and path (list of folder names)
get_node_by_volume_and_path: Get a node based on the volume ID and path
get_node_from_nickname: Get a node based on the nickname
set_node_nickname: Assign a nickname to an Extended ECM node (e.g. workspace)
get_subnodes: get children nodes of a parent node
lookup_node: lookup the node under a parent node that has a specified value in a category attribute.
get_node_columns: get custom columns configured / enabled for a node.
get_node_actions: get possible actions for a node
rename_node: Change the name and description of a node
delete_node: Delete a node
purge_node: Delete a node from the recycle bin
restore_node: Restore a node from the recycle bin
get_volumes: Get all Volumes
get_volume: Get Volume information based on the volume type ID
check_node_name: Check if a a node name in a parent location has a name collision

upload_file_to_volume: Fetch a file from a URL or local filesystem and upload
                       it to an Extended ECM volume
upload_file_to_parent: Upload a document to a parent folder
add_document_version: Add a version to an Extended ECM document
get_latest_document_version: Get latest version of a document node based on the node ID.
get_document_content: get content of a document version
get_json_document: Get document content from Extended ECM and read content as JSON.
download_document: Download a document
download_config_file: Download a config file from a given OTCS URL.
                      This is NOT for downloading documents from within the OTCS repository

search: search for a search term using Extended ECM search engine

get_external_system_connection: Get Extended ECM external system connection
add_external_system_connection: Add Extended ECM external system connection

create_transport_workbench: Create a Workbench in the Transport Volume
unpack_transport_package: Unpack an existing Transport Package into an existing Workbench
deploy_workbench: Deploy an existing Workbench
deploy_transport: Main method to deploy a transport. This uses subfunctions to upload,
                 unpackage and deploy the transport, and creates the required workbench
replace_transport_placeholders: Search and replace strings in the XML files of the transport packlage

get_business_object_types: Get information for all configured business object types
get_business_object_type: Get information for a specific business object type
get_business_objects: Get all business objects for an external system and a given business object type.

get_workspace_types: Get all workspace types configured in Extended ECM
get_workspace_create_form: Get the Workspace create form
get_workspace: Get a workspace node
get_workspace_instances: Get all instances of a given workspace type 
get_workspace_by_type_and_name: Lookup workspace based on workspace type name and workspace name
get_workspace_type_location: Determine the folder in which the workspace instances of a given type reside.
                             Either the type ID or the type name need to be provided.
get_workspace_by_business_object: Lookup workspace based by an business object of an external system
set_workspace_reference: Set reference of workspace to a business object in an external system
create_workspace: Create a new business workspace
update_workspace: Update the metadata of a workspace
create_workspace_relationship: Create a relationship between two workspaces
get_workspace_relationships: get a list of related workspaces
get_workspace_roles: Get the Workspace roles
add_workspace_member: Add member to workspace role. Check that the user is not yet a member
remove_workspace_member: Remove member from workspace role
remove_workspace_members: Remove all members from a workspace role. Check that the user is currently a member.
assign_workspace_permissions: Update workspace permissions for a given role
update_workspace_icon: Update a workspace with a with a new icon (which is uploaded)

get_unique_names: Get information on definition of Unique Names.

create_item: Create an item in Extended ECM (e.g. folder or URL item)
update_item: Update an item in Extended ECM (e.g. folder or URL item)
get_document_templates: Get all document templates for a given target location
create_document_from_template: Create a document based on a document template
create_wiki: Create an Extended ECM Wiki.
create_wiki_page: Create an Extended ECM wiki page.

get_web_report_parameters: Get parameters of a Web Report
run_web_report: Run a Web Report that is identified by its nick name

install_cs_application: Install a CS Application (based on WebReports)

assign_item_to_user_group: Assign an item (e.g. Workspace or document) to a list of users or groups

convert_permission_string_to_permission_value: Convert a list of permission names to a permission value
convert_permission_value_to_permission_string: Convert a permission value to a list of permission strings
assign_permission: Assign permissions to an item for a defined user or group

get_node_categories: Get categories assigned to a node
get_node_category: Get a specific category assigned to a node
get_node_category_ids: Get list of all category definition IDs that are assign to the node.
get_node_category_names: Get list of all category names that are assign to the node.
get_node_category_definition: Get category definition (category id and attribute IDs and types)
assign_category: Assign a category to a node
get_category_value_by_name: Lookup the value of an attribute if category name,
                            set name and attribute name are known.
get_category_value: Lookup the value of an attribute if category ID, set ID and attribute ID
                    are known. If you only have the names use get_category_value_by_name()
set_category_value: Set a value for a specific category attribute to a node
set_category_values: Set values of a category. Categories and have sets (groupings), multi-line sets (matrix),
                     and multi-value attributes (list of values). This method supports all variants.
set_category_inheritance: Set if we want a container item (e.g. a folder or workspace) to inherit
                          categories to sub-items.

assign_classification: Assign a classification to an item
assign_rm_classification: Assign a Records management classification to an item

register_workspace_template: Register a workspace template for Extended ECM for Engineering

get_records_management_rsis: Get the ist of RSIs together with their RSI schedules
get_records_management_codes: Get Records Management Codes
update_records_management_codes: Update the Records Management Codes
create_records_management_rsi: Create a new Records Management RSI item
create_records_management_rsi_schedule: Create a schedule for an existing RSI item
create_records_management_hold: Create a Records Management Hold
get_records_management_holds: Get a list of all Records Management Holds in the system.
import_records_management_codes: Import RM codes from a config file
import_records_management_rsis: Import RM RSIs from a config file
import_records_management_settings: Import Records Management settings from a config file
import_physical_objects_codes: Import Physical Objects codes from a config file
import_physical_objects_settings: Import Physical Objects settings from a config file
import_physical_objects_locators: Import Physical Objects locators from a config file
import_security_clearance_codes: Import Securioty Clearance codes from a config file

assign_user_security_clearance: Assign a Security Clearance level to a user
assign_user_supplemental_markings: Assign a list of Supplemental Markings to a user

get_workflow_definition: Get the workflow definition
get_workflow_attributes: Get workflow attribute definition.
get_document_workflows: Get a list of aviable workflows for a document ID and a parent ID
get_workflows_by_kind_and_status: Get a list of workflows with a defined status
get_workflow_status: Get the status (task list) of a workflow instance (process)
create_draft_process: Create an Extended ECM workflow as a draft process
update_draft_process: Update a draft process with values. These can either be given via dedicated parameters
                      like title and due_date or with a generic value dictionary.
initiate_draft_process: Initiate an Extended ECM workflow instance from a draft process
get_process_task: Get the task information of a workflow assignment.
update_process_task: Update a process with values in a task.
                    This method needs to be called with the user
                    that has the task in its inbox (My ToDo - Workflows).
                    It can update the task data (formUpdate) and/or send on
                    the task to the next workflow step (action or custom_action).

check_workspace_aviator: Check if Content Aviator is enabled for a workspace
update_workspace_aviator: Enable or disable the Content Aviator for a workspace

volume_translator: Experimental code to translate the item names and item descriptions in a given hierarchy.
                   The actual translation is done by a tranlator object. This recursive method just
                   traverses the hierarchy and calls the translate() method of the translator object.

download_document_multi_threading: Multi-threading variant of download_document()
load_items: Create a Pandas Data Frame by traversing a given Content Server hierarchy and collecting
            workspace and document items.

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2024, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import os
import logging
import json
import time
import urllib.parse
import threading
import mimetypes
import asyncio
from http import HTTPStatus
from datetime import datetime
import zipfile
import requests
import websockets
from pyxecm.helper.xml import XML
from pyxecm.helper.data import Data

logger = logging.getLogger("pyxecm.otcs")

try:
    import magic

    magic_installed = True
except ModuleNotFoundError as module_exception:
    logger.warning(
        "Module magic is not installed. Customizer will not use advanced mime type detection for uploads."
    )
    magic_installed = False


REQUEST_JSON_HEADERS = {
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/json",
}

REQUEST_FORM_HEADERS = {
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_DOWNLOAD_HEADERS = {
    "accept": "application/octet-stream",
    "Content-Type": "application/json",
}

REQUEST_TIMEOUT = 60
REQUEST_RETRY_DELAY = 20
REQUEST_MAX_RETRIES = 2


class OTCS:
    """Used to automate stettings in OpenText Extended ECM."""

    _config: dict
    _cookie = None
    _otcs_ticket = None
    _otds_ticket = None
    _data: Data = None
    _thread_number = 3
    _download_dir = ""

    # Handle concurrent HTTP requests that may run into 401 errors and
    # re-authentication at the same time:
    _authentication_lock = threading.Lock()
    _authentication_condition = threading.Condition(_authentication_lock)
    _authentication_semaphore = threading.Semaphore(
        1
    )  # only 1 thread should handle the re-authentication
    _session_lock = threading.Lock()

    @classmethod
    def date_is_newer(cls, date_old: str, date_new: str) -> bool:
        """Compare two dates, typically create or modification dates

        Args:
            date_old (str): the date that is considered older
            date_new (str): the date that is considered newer

        Returns:
            bool: True if date_new is indeed newer as date_old, False otherwise
        """

        if not date_old or not date_new:
            return True

        # Define the date formats
        format1 = "%Y-%m-%dT%H:%M:%SZ"  # Format: "YYYY-MM-DDTHH:MM:SSZ"
        format2 = "%Y-%m-%d %H:%M:%S"  # Format: "YYY-MM-DD HH:MM:SS"
        format3 = "%Y-%m-%dT%H:%M:%S"  # Format: "YYY-MM-DD HH:MM:SS"
        format4 = "%Y-%m-%d"  # Format: "YYY-MM-DD"

        # Parse the dates
        try:
            if "T" in date_old and "Z" in date_old:
                old_date = datetime.strptime(date_old, format1)
            elif " " in date_old:
                old_date = datetime.strptime(date_old, format2)
            elif "T" in date_old:
                old_date = datetime.strptime(date_old, format3)
            else:
                old_date = datetime.strptime(date_old, format4)
        except ValueError:
            return True

        try:
            if "T" in date_new and "Z" in date_new:
                new_date = datetime.strptime(date_new, format1)
            elif " " in date_new:
                new_date = datetime.strptime(date_new, format2)
            elif "T" in date_new:
                new_date = datetime.strptime(date_new, format3)
            else:
                new_date = datetime.strptime(date_new, format4)
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
        download_dir: str = "/tmp/contentserver",
        feme_uri: str | None = None,
    ):
        """Initialize the OTCS object

        Args:
            protocol (str): Either http or https.
            hostname (str): The hostname of Extended ECM server to communicate with.
            port (int): The port number used to talk to the Extended ECM server.
            public_url (str): public (external) URL
            username (str, optional): The admin user name of Extended ECM. Optional if otds_ticket is provided.
            password (str, optional): The admin password of Extended ECM. Optional if otds_ticket is provided.
            user_partition (str): Name of the OTDS partition for OTCS users. Default is "Content Server Members".
            resource_name (str, optional): Name of the OTDS resource for OTCS. Dault is "cs".
            default_license (str, optional): name of the default user license. Default is "X3".
            otds_ticket (str, optional): Authentication ticket of OTDS
        """

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
        otcs_config["doctemplatesUrl"] = otcs_rest_url + "/v2/doctemplates"
        otcs_config["nicknameUrl"] = otcs_rest_url + "/v2/nicknames"
        otcs_config["importSettingsUrl"] = otcs_rest_url + "/v2/import/settings/admin"
        otcs_config["searchUrl"] = otcs_rest_url + "/v2/search"
        otcs_config["volumeUrl"] = otcs_rest_url + "/v2/volumes"
        otcs_config["externalSystemUrl"] = otcs_rest_url + "/v2/externalsystems"
        otcs_config["businessObjectsUrl"] = otcs_rest_url + "/v2/businessobjects"
        otcs_config["businessObjectTypesUrl"] = (
            otcs_rest_url + "/v2/businessobjecttypes"
        )
        otcs_config["businessObjectsSearchUrl"] = (
            otcs_rest_url + "/v2/forms/businessobjects/search"
        )
        otcs_config["businessWorkspaceTypesUrl"] = (
            otcs_rest_url + "/v2/businessworkspacetypes"
        )
        otcs_config["businessworkspacecreateform"] = (
            otcs_rest_url + "/v2/forms/businessworkspaces/create"
        )
        otcs_config["businessWorkspacesUrl"] = otcs_rest_url + "/v2/businessworkspaces"
        otcs_config["uniqueNamesUrl"] = otcs_rest_url + "/v2/uniquenames"
        otcs_config["favoritesUrl"] = otcs_rest_url + "/v2/members/favorites"
        otcs_config["webReportsUrl"] = otcs_rest_url + "/v1/webreports"
        otcs_config["csApplicationsUrl"] = otcs_rest_url + "/v2/csapplications"
        otcs_config["xEngProjectTemplateUrl"] = (
            otcs_rest_url + "/v2/xengcrt/projecttemplate"
        )
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
        otcs_config["draftProcessFormUrl"] = otcs_rest_url + "/v1/forms/draftprocesses"
        otcs_config["processTaskUrl"] = (
            otcs_rest_url + "/v1/forms/processes/tasks/update"
        )

        self._config = otcs_config
        self._otds_ticket = otds_ticket
        self._data = Data()
        self._thread_number = thread_number
        self._download_dir = download_dir
        self._semaphore = threading.BoundedSemaphore(value=thread_number)

    # end method definition

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    # end method definition

    def cookie(self) -> dict:
        """Returns the login cookie of Extended ECM.
           This is set by the authenticate() method

        Returns:
            dict: Estended ECM cookie
        """
        return self._cookie

    # end method definition

    def otcs_ticket(self) -> str | None:
        """Return the OTCS ticket

        Returns:
            str: String with the OTCS ticket
        """

        return self._otcs_ticket

    # end method definition

    def credentials(self) -> dict:
        """Get credentials (username + password)

        Returns:
            dict: dictionary with username and password
        """
        return {
            "username": self.config()["username"],
            "password": self.config()["password"],
        }

    # end method definition

    def set_credentials(self, username: str = "admin", password: str = ""):
        """Set the credentials for Extended ECM based on username and password.

        Args:
            username (str, optional): Username. Defaults to "admin".
            password (str, optional): Password of the user. Defaults to "".
        """

        self.config()["username"] = username
        self.config()["password"] = password

    # end method definition

    def hostname(self) -> str:
        """Returns the hostname of Extended ECM (e.g. "otcs")

        Returns:
            str: hostname
        """
        return self.config()["hostname"]

    # end method definition

    def set_hostname(self, hostname: str):
        """Sets the hostname of Extended ECM

        Args:
            hostname (str): new hostname
        """
        self.config()["hostname"] = hostname

    # end method definition

    def base_url(self) -> str:
        """Returns the base URL of Extended ECM

        Returns:
            str: base URL
        """
        return self.config()["baseUrl"]

    # end method definition

    def cs_url(self) -> str:
        """Returns the Extended ECM URL

        Returns:
            str: Extended ECM URL
        """
        return self.config()["csUrl"]

    # end method definition

    def cs_public_url(self) -> str:
        """Returns the public (external) Extended ECM URL (incl. base_path /cs/cs )

        Returns:
            str: Extended ECM Public URL
        """
        return self.config()["csPublicUrl"]

    # end method definition

    def cs_support_url(self) -> str:
        """Returns the Extended ECM Support URL

        Returns:
            str: Extended ECM Support URL
        """
        return self.config()["supportUrl"]

    # end method definition

    def cs_support_public_url(self) -> str:
        """Returns the Extended ECM Public Support URL

        Returns:
            str: Extended ECM Public Support URL
        """
        return self.config()["supportPublicUrl"]

    # end method definition

    def rest_url(self) -> str:
        """Returns the REST URL of Extended ECM

        Returns:
            str: REST URL
        """
        return self.config()["restUrl"]

    # end method definition

    def get_data(self) -> Data:
        """Get the Data object that holds all loaded Content Server items (see method load_items())

        Returns:
            Data: Datastructure with all processed articles.
        """

        return self._data

    # end method definition

    def request_form_header(self) -> dict:
        """Deliver the request header used for the CRUD REST API calls.
           Consists of Cookie + Form Headers (see global variable)

        Args:
            None.
        Return:
            dict: request header values
        """

        # create union of two dicts: cookie and headers
        # (with Python 3.9 this would be easier with the "|" operator)
        request_header = {}
        request_header.update(self.cookie())
        request_header.update(REQUEST_FORM_HEADERS)

        return request_header

    # end method definition

    def request_json_header(self) -> dict:
        """Deliver the request header for REST calls that require content type application/json.
           Consists of Cookie + Json Headers (see global variable)

        Args:
            None.
        Return:
            dict: request header values
        """

        # create union of two dicts: cookie and headers
        # (with Python 3.9 this would be easier with the "|" operator)
        request_header = {}
        request_header.update(self.cookie())
        request_header.update(REQUEST_JSON_HEADERS)

        return request_header

    # end method definition

    def request_download_header(self) -> dict:
        """Deliver the request header used for the CRUD REST API calls.
           Consists of Cookie + Form Headers (see global vasriable)

        Args:
            None.
        Return:
            dict: request header values
        """

        # create union of two dicts: cookie and headers
        # (with Python 3.9 this would be easier with the "|" operator)
        request_header = {}
        request_header.update(self.cookie())
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
    ) -> dict | None:
        """Call an Extended ECM REST API in a safe way

        Args:
            url (str): URL to send the request to.
            method (str, optional): HTTP method (GET, POST, etc.). Defaults to "GET".
            headers (dict | None, optional): Request Headers. Defaults to None.
            data (dict | None, optional): Request payload. Defaults to None
            files (dict | None, optional): Dictionary of {"name": file-tuple} for multipart encoding upload.
                                           file-tuple can be a 2-tuple ("filename", fileobj) or a 3-tuple ("filename", fileobj, "content_type")
            timeout (int | None, optional): Timeout for the request in seconds. Defaults to REQUEST_TIMEOUT.
            show_error (bool, optional): Whether or not an error should be logged in case of a failed REST call.
                                         If False, then only a warning is logged. Defaults to True.
            warning_message (str, optional): Specific warning message. Defaults to "". If not given the error_message will be used.
            failure_message (str, optional): Specific error message. Defaults to "".
            success_message (str, optional): Specific success message. Defaults to "".
            max_retries (int, optional): How many retries on Connection errors? Default is REQUEST_MAX_RETRIES.
            retry_forever (bool, optional): Eventually wait forever - without timeout. Defaults to False.
            parse_request_response (bool, optional): should the response.text be interpreted as json and loaded into a dictionary. True is the default.

        Returns:
            dict | None: Response of Extended ECM REST API or None in case of an error.
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
                    request_cookie = self.cookie()
                response = requests.request(
                    method=method,
                    url=url,
                    data=data,
                    json=json_data,
                    files=files,
                    headers=headers,
                    cookies=request_cookie,
                    timeout=timeout,
                )

                if response.ok:
                    if success_message:
                        logger.info(success_message)
                    if parse_request_response:
                        return self.parse_request_response(response)
                    else:
                        return response
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    # Try to reauthenticate:
                    self.reauthenticate(request_cookie=request_cookie, thread_safe=True)
                    retries += 1
                    logger.debug("Reauthentication complete. Retry = %s", str(retries))
                    logger.debug(
                        "Old cookie -> %s, new cookie -> %s",
                        str(request_cookie),
                        str(self.cookie()),
                    )
                elif response.status_code == 500 and "already exists" in response.text:
                    logger.warning(
                        (
                            warning_message
                            + " (it already exists); details -> {}".format(
                                response.text
                            )
                            if warning_message
                            else failure_message
                            + " (it already exists); details -> {}".format(
                                response.text
                            )
                        ),
                    )
                    if parse_request_response:
                        return self.parse_request_response(response)
                    else:
                        return response
                else:
                    # Handle plain HTML responses to not pollute the logs
                    content_type = response.headers.get("content-type", None)
                    if content_type == "text/html":
                        response_text = "HTML content (only printed in debug log)"
                    else:
                        response_text = response.text

                    if show_error:
                        logger.error(
                            "%s; status -> %s/%s; error -> %s",
                            failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response_text,
                        )
                    elif show_warning:
                        logger.warning(
                            "%s; status -> %s/%s; warning -> %s",
                            warning_message if warning_message else failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
                            response_text,
                        )

                    if content_type == "text/html":
                        logger.debug(
                            "%s; status -> %s/%s; debug output -> %s",
                            failure_message,
                            response.status_code,
                            HTTPStatus(response.status_code).phrase,
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
            # end try
            logger.debug(
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
        """Converts the text property of a request response object to a Python dict in a safe way
            that also handles exceptions.

            Content Server may produce corrupt response when it gets restarted
            or hitting resource limits. So we try to avoid a fatal error and bail
            out more gracefully.

        Args:
            response_object (object): this is reponse object delivered by the request call
            additional_error_message (str): print a custom error message
            show_error (bool): if True log an error, if False log a warning

        Returns:
            dict: response or None in case of an error
        """

        if not response_object:
            return None

        if not response_object.text:
            logger.warning("Response text is empty. Cannot decode response.")
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

    def lookup_result_value(
        self, response: dict, key: str, value: str, return_key: str
    ) -> str | None:
        """Lookup a property value based on a provided key / value pair in the
           response properties of an Extended ECM REST API call.

        Args:
            response (dict): REST response from an OTCS REST Call
            key (str): property name (key)
            value (str): value to find in the item with the matching key
            return_key (str): determines which value to return based on the name of the dict key
        Returns:
            str: value of the property with the key defined in "return_key"
                 or None if the lookup fails
        """

        if not response:
            return None
        if not "results" in response:
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
                if (
                    key in properties
                    and properties[key] == value
                    and return_key in properties
                ):
                    return properties[return_key]
                else:
                    return None
            elif isinstance(data, list):
                # data is a list - this has typically just one item, so we use 0 as index
                for item in data:
                    properties = item["properties"]
                    if (
                        key in properties
                        and properties[key] == value
                        and return_key in properties
                    ):
                        return properties[return_key]
                return None
            else:
                logger.error(
                    "Data needs to be a list or dict but it is -> %s", str(type(data))
                )
                return None
        elif isinstance(results, list):
            # result is a list - we need index value
            for result in results:
                data = result["data"]
                if isinstance(data, dict):
                    # data is a dict - we don't need index value:
                    properties = data["properties"]
                    if (
                        key in properties
                        and properties[key] == value
                        and return_key in properties
                    ):
                        return properties[return_key]
                elif isinstance(data, list):
                    # data is a list we iterate through the list and try to find the key:
                    for item in data:
                        properties = item["properties"]
                        if (
                            key in properties
                            and properties[key] == value
                            and return_key in properties
                        ):
                            return properties[return_key]
                else:
                    logger.error(
                        "Data needs to be a list or dict but it is -> %s",
                        str(type(data)),
                    )
                    return None
            return None
        else:
            logger.error(
                "Result needs to be a list or dict but it is -> %s", str(type(results))
            )
            return None

    # end method definition

    def exist_result_item(
        self, response: dict, key: str, value: str, property_name: str = "properties"
    ) -> bool:
        """Check existence of key / value pair in the response properties of an Extended ECM REST API call.

        Args:
            response (dict): REST response from an OTCS REST Call
            key (str): property name (key)
            value (str): value to find in the item with the matching key
            property_name (str, optional): name of the substructure that includes the values
        Returns:
            bool: True if the value was found, False otherwise
        """

        if not response:
            return False
        if not "results" in response:
            return False

        results = response["results"]
        # check if results is a list or a dict (both is possible - dependent on the actual REST API):
        if isinstance(results, dict):
            # result is a dict - we don't need index value:
            if not "data" in results:
                return False
            data = results["data"]
            if isinstance(data, dict):
                # data is a dict - we don't need index value:
                if property_name and not property_name in data:
                    logger.error(
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
                    # properties is a list we iterate through the list and try to find the key:
                    for item in properties:
                        if key in item and item[key] == value:
                            return True
                else:
                    logger.error(
                        "Properties needs to be a list or dict but it is -> %s",
                        str(type(properties)),
                    )
                    return False
            elif isinstance(data, list):
                # data is a list
                for item in data:
                    if property_name and not property_name in item:
                        logger.error(
                            "There's no dictionary -> '%s' in the data list item -> %s",
                            property_name,
                            item,
                        )
                        continue
                    # if properties if passed as empty string then we assume that
                    # the key fields are directly in the item dictionary. This is
                    # the case e.g. with the V2 Proxy APIs
                    if not property_name:
                        properties = item
                    else:
                        properties = item[property_name]
                    if key in properties and properties[key] == value:
                        return True
                return False
            else:
                logger.error(
                    "Data needs to be a list or dict but it is -> %s", str(type(data))
                )
                return False
        elif isinstance(results, list):
            # result is a list - we need index value
            for result in results:
                if not "data" in result:
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
                    logger.error(
                        "Data needs to be a list or dict but it is -> %s",
                        str(type(data)),
                    )
                    return False
            return False
        else:
            logger.error(
                "Result needs to be a list or dict but it is -> %s", str(type(results))
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
        """Read an item value from the REST API response. This is considering
           the most typical structures delivered by V2 REST API of Extended ECM.
           See developer.opentext.com for more details.

        Args:
            response (dict): REST API response object
            key (str): key to find (e.g. "id", "name", ...)
            index (int, optional): In case a list of results is delivered the index
                                   to use (1st element has index  0). Defaults to 0.
            property_name (str, optional): name of the sub dictionary holding the actual values.
                                           Default is "properties".
        Returns:
            str: value of the item with the given key for None if no value is found for the given key.
        """

        # First do some sanity checks:
        if not response:
            logger.debug("Empty REST response - returning None")
            return None
        if not "results" in response:
            if show_error:
                logger.error("No 'results' key in REST response - returning None")
            return None

        results = response["results"]
        if not results:
            logger.debug("No results found!")
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
                logger.error(
                    "Data needs to be a list or dict but it is -> %s", str(type(data))
                )
                return None
            logger.debug("Properties of results (dict) -> %s", str(properties))
            # For nearly all OTCS REST Calls perperties is a dict:
            if isinstance(properties, dict):
                if not key in properties:
                    if show_error:
                        logger.error("Key -> '%s' is not in result properties!", key)
                    return None
                return properties[key]
            # but there are some strange ones that have other names for
            # properties and may use a list - see e.g. /v2/holds
            elif isinstance(properties, list):
                if index > len(properties) - 1:
                    logger.error(
                        "Illegal Index -> %s given. List has only -> %s elements!",
                        str(index),
                        str(len(properties)),
                    )
                    return None
                return properties[index][key]
            else:
                logger.error(
                    "Properties needs to be a list or dict but it is -> %s",
                    str(type(properties)),
                )
                return None
        elif isinstance(results, list):
            # result is a list - we need a valid index:
            if index > len(results) - 1:
                logger.error(
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
                logger.error(
                    "Data needs to be a list or dict but it is -> %s", str(type(data))
                )
                return None
            logger.debug(
                "Properties of results (list, index -> %s) -> %s",
                str(index),
                properties,
            )
            if not key in properties:
                if show_error:
                    logger.error("Key -> '%s' is not in result properties!", key)
                return None
            return properties[key]
        else:
            logger.error(
                "Result needs to be a list or dict but it is -> %s", str(type(results))
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
        """Read an item value from the REST API response. This is considering
           the most typical structures delivered by V2 REST API of Extended ECM.
           See developer.opentext.com for more details.

        Args:
            response (dict): REST API response object
            key (str): key to find (e.g. "id", "name", ...)
            property_name (str, optional): name of the sub dictionary holding the actual values.
                                           Default is "properties".
            data_name (str, optional): name of the sub dictionary holding the data. Default = "data"
        Returns:
            str: value of the item with the given key for None if no value is found for the given key.
        """

        # First do some sanity checks:
        if not response:
            logger.debug("Empty REST response - returning None")
            return None
        if not "results" in response:
            logger.error("No 'results' key in REST response - returning None")
            return None

        results = response["results"]
        if not results:
            logger.debug("No results found!")
            return None

        # check if results is a list or a dict (both is possible - dependent on the actual REST API):
        if isinstance(results, dict):
            # result is a dict - we don't need index value

            # this is a special treatment for the businessworkspaces REST API - it returns
            # for "Create business workspace" the ID directly in the results dict (without data substructure)
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
                    logger.debug("Properties of results (dict) -> %s", str(properties))
                else:
                    properties = data
                    logger.debug(
                        "Response does not have properties structure. Using data structure directly."
                    )
            else:
                logger.error(
                    "Data needs to be a list or dict but it is -> %s", str(type(data))
                )
                return None
            # For nearly all OTCS REST Calls properties is a dict:
            if isinstance(properties, dict):
                if not key in properties:
                    logger.error("Key -> '%s' is not in result properties!", key)
                    return None
                return [properties[key]]
            # but there are some strange ones that have other names for
            # properties and may use a list - see e.g. /v2/holds
            elif isinstance(properties, list):
                return [item[key] for item in properties]
            else:
                logger.error(
                    "Properties needs to be a list or dict but it is -> %s",
                    str(type(properties)),
                )
                return None
        elif isinstance(results, list):
            return [item[data_name][property_name][key] for item in results]
        else:
            logger.error(
                "Result needs to be a list or dict but it is -> %s", str(type(results))
            )
            return None

    # end method definition

    def is_configured(self) -> bool:
        """Checks if the Content Server pod is configured to receive requests.

        Args:
            None.
        Returns:
            bool: True if pod is ready. False if pod is not yet ready.
        """

        request_url = self.config()["configuredUrl"]

        logger.debug("Trying to retrieve OTCS URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=REQUEST_JSON_HEADERS,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exception:
            logger.debug(
                "Unable to connect to -> %s; warning -> %s",
                request_url,
                str(exception),
            )
            return False

        if not response.ok:
            logger.debug(
                "Unable to connect to -> %s; status -> %s; warning -> %s",
                request_url,
                response.status_code,
                response.text,
            )
            return False

        return True

    # end method definition

    def is_ready(self) -> bool:
        """Checks if the Content Server pod is ready to receive requests.

        Args:
            None.
        Returns:
            bool: True if pod is ready. False if pod is not yet ready.
        """

        request_url = self.config()["isReady"]

        logger.debug("Trying to retrieve OTCS URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=REQUEST_JSON_HEADERS,
                timeout=2,
            )
        except requests.exceptions.RequestException as exception:
            logger.debug(
                "Unable to connect to -> %s; warning -> %s",
                request_url,
                str(exception),
            )
            return False

        if not response.status_code == 200:
            logger.debug(
                "Unable to connect to -> %s; status -> %s; warning -> %s",
                request_url,
                response.status_code,
                response.text,
            )
            return False

        return True

    # end method definition

    def invalidate_authentication_ticket(self):
        """If a 401 HTTP error occurs we may want to invalidate the login ticket"""

        self._otcs_ticket = None
        self._cookie = None

    # end method definition

    def authenticate(
        self, revalidate: bool = False, wait_for_ready: bool = True
    ) -> dict | None:
        """Authenticates at Content Server and retrieve OTCS Ticket.

        Args:
            revalidate (bool, optional): determinse if a re-athentication is enforced
                                         (e.g. if session has timed out with 401 error)
                                         By default we use the OTDS ticket (if exists) for the authentication with OTCS.
                                         This switch allows the forced usage of username / password for the authentication.
            wait_for_ready (bool, optional): whether or not to wait for the OTCS service to be "ready".
                                             Default is True. If you want authentication to fail fast then set it to False.
        Returns:
            dict: Cookie information of None in case of an error.
                  Also stores cookie information in self._cookie
        """

        # Already authenticated and session still valid?
        if self._cookie and not revalidate:
            logger.debug(
                "Session still valid - return existing cookie -> %s",
                str(self._cookie),
            )
            return self._cookie

        otcs_ticket = None

        if wait_for_ready:
            logger.debug("Wait for OTCS to be ready...")
            while not self.is_ready():
                logger.debug(
                    "OTCS is not ready to receive requests yet. Waiting additional 30 seconds..."
                )
                time.sleep(30)

        request_url = self.config()["authenticationUrl"]

        if self._otds_ticket and not revalidate:
            logger.debug(
                "Requesting OTCS ticket with OTDS ticket; calling -> %s",
                request_url,
            )
            request_header = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "OTDSTicket": self._otds_ticket,
            }

            try:
                response = requests.get(
                    url=request_url, headers=request_header, timeout=10
                )
                if response.ok:
                    otcs_ticket = response.headers.get("OTCSTicket")

            except requests.exceptions.RequestException as exception:
                logger.warning(
                    "Unable to connect to -> %s; error -> %s",
                    request_url,
                    exception.strerror,
                )

        # Check if previous authentication was not successful.
        # Then we do the normal username + password authentication:
        if not otcs_ticket:
            logger.debug(
                "Requesting OTCS ticket with User/Password; calling -> %s",
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
                logger.warning(
                    "Unable to connect to -> %s; error -> %s",
                    request_url,
                    exception.strerror,
                )
                logger.warning("OTCS service may not be ready yet.")
                return None

            if response.ok:
                authenticate_dict = self.parse_request_response(
                    response, "This can be normal during restart", False
                )
                if not authenticate_dict:
                    return None
                else:
                    otcs_ticket = authenticate_dict["ticket"]
                    logger.debug("Ticket -> %s", otcs_ticket)
            else:
                logger.error(
                    "Failed to request an OTCS ticket; error -> %s", response.text
                )
                return None

        # Store authentication ticket:
        self._cookie = {"otcsticket": otcs_ticket, "LLCookie": otcs_ticket}
        self._otcs_ticket = otcs_ticket

        return self._cookie

    # end method definition

    def reauthenticate(
        self, request_cookie: dict, thread_safe: bool = True
    ) -> dict | None:
        """Re-Authenticate after session timeout. This implementation
           supports thread-safe reauthentication, making sure not multiple
           threads reauthenticate at the same time.

        Args:
            request_cookie: the cookie used in the REST API call that
                            produced the 401 HTTP error triggering the re-authentication.
                            We use it to compare it with the current cookie to see
                            if another thread may have done the reauthentication and
                            updated the cookie already.
            thread_safe (bool, optional): If True a thread-safe implementation is done.
                                          Defaults to True.

        Returns:
            dict | None: cookie information returned by authenticate()
        """

        if not thread_safe:
            return self.authenticate(revalidate=True)

        # Lock access to session for thread-safe reads
        with self._session_lock:
            # Check if the cookie used for the REST call is still the current cookie:
            if request_cookie != self.cookie():
                # Another thread has already re-authenticated; skip re-authentication
                logger.debug(
                    "Session has already been renewed with new cookie. Skip re-authentication and return new cookie -> %s",
                    str(self.cookie()),
                )
                # return the new cookie:
                return self.cookie()

        # If the session is invalid, try to acquire the semaphore and renew it
        if self._authentication_semaphore.acquire(blocking=False):
            # Renew the session (only one thread gets here)
            logger.debug(
                "Session has expired - need to renew old request cookie -> %s",
                str(request_cookie),
            )

            try:
                # The 'with' automatically acquires and releases the lock on 'authentication_condition'
                with self._authentication_condition:
                    logger.debug("Current thread got the authentication condition...")
                    # We use the _session_lock to prevent race conditions
                    # while reading / writing the self._cookie (which is modified
                    # by the authenticate() method):
                    with self._session_lock:
                        logger.debug(
                            "Current thread got the session lock and tries to re-authenticate to get new cookie"
                        )
                        try:
                            self.authenticate(revalidate=True)
                            logger.debug(
                                "Session renewal successful, new cookie -> %s",
                                str(self.cookie()),
                            )
                            time.sleep(4)
                        except Exception as auth_error:
                            logger.error(
                                "Reauthentication failed with error -> %s",
                                str(auth_error),
                            )
                            raise
                    logger.debug("Lift session lock and notify waiting threads...")
                    # Notify all waiting threads that session is renewed:
                    self._authentication_condition.notify_all()
                    logger.warning("All waiting threads have been notified.")
            finally:
                # Ensure the semaphore is released even if an error occurs
                self._authentication_semaphore.release()
                logger.debug("Semaphore released after session renewal.")
            logger.debug("Session renewing thread continues with retry of request...")
        else:
            # Other threads wait for session renewal to complete
            logger.debug(
                "Session has expired but another thread is working on renewal - current thread waiting for re-authentication..."
            )

            with self._authentication_condition:
                logger.debug("Waiting thread got the authentication condition...")
                # IMPORTANT: Don't do a session lock here. This can produce a deadlock.
                # Reason: self._authentication_condition.wait() does not release the self._session_lock
                # but just the self._authentication_condition lock.

                # Check if session is not yet renewed (still has the old cookie used for the request)
                while request_cookie == self.cookie():
                    # This code is very unlikely to be executed as
                    # _authentication_condition and _session_lock protect
                    # the else clause from running in parallel to the if clause.
                    logger.debug("Thread is now waiting for session renewal...")
                    # Wait for notification that the session is renewed:
                    self._authentication_condition.wait()
                    logger.debug(
                        "Thread received notification, session renewal complete."
                    )
                logger.debug(
                    "Waiting thread got the new cookie -> %s.", str(self.cookie())
                )
            logger.debug(
                "Waiting thread released the authentication condition and continues with retry of request..."
            )

        return self.cookie()

    # end method definition

    def get_server_info(self) -> dict | None:
        """Get Content Server information (server info)

        Args:
            None
        Returns:
            dict: server information or None if the call fails

            Example response:
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
                    'metadata_languages: [...],
                    'url': 'https://otcs.dev.idea-te.eimdemo.com/cs/cs'
                    'version': '23.3'
                    ...
                },
                'sessions': {
                    'enabled': True,
                    'expire_after_last_login': False,
                    'expire_after_last_request': True,
                    'logout_url': '?func=ll.DoLogout&secureRequestToken=LUAQSY%2BJs4KnlwoVgxLtxQFYrov2XefJQM9ShyhOK93Mzp3ymCxX6IGMTtUgNvTH7AYVt%2BbWLEw%3D',
                    'session_inactivity': 7020000,
                    'session_reaction_time': 180000,
                    'session_timeout': 7200000
                },
                'viewer': {
                    'content_suite': {...}
                }
            }
        """

        request_url = self.config()["serverInfoUrl"]
        request_header = self._cookie

        logger.debug(
            "Retrieve Extended ECM server information; calling -> %s", request_url
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to retrieve Extended ECM server information",
        )

    # end method definition

    def get_server_version(self) -> str | None:
        """Get Content Server version

        Args:
            None
        Returns:
            str: server version number like 23.4
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
        """Apply Content Server administration settings from XML file

        Args:
            xml_file_path (str): name + path of the XML settings file
        Returns:
            dict: Import response or None if the import fails.
                  The field response["results"]["data"]["restart"] indicates if the settings
                  require a restart of the OTCS services.
        """

        filename = os.path.basename(xml_file_path)

        if not os.path.exists(xml_file_path):
            logger.error(
                "The admin settings file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(xml_file_path),
            )
            return None

        llconfig_file = {
            "file": (filename, open(file=xml_file_path, encoding="utf-8"), "text/xml")
        }

        request_url = self.config()["importSettingsUrl"]
        request_header = self._cookie

        logger.debug(
            "Applying admin settings from file -> '%s'; calling -> %s",
            xml_file_path,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            files=llconfig_file,
            timeout=None,
            success_message="Admin settings in file -> '{}' have been applied".format(
                xml_file_path
            ),
            failure_message="Failed to import settings file -> '{}'".format(
                xml_file_path
            ),
        )

    # end method definition

    def get_user(self, name: str, show_error: bool = False) -> dict | None:
        """Lookup Extended ECM user based on the login name.

        Args:
            name (str): name of the user (login)
            show_error (bool): treat as error if user is not found
        Returns:
            dict: User information or None if the user is not found.
            The returned information has a structure like this:

            {
                'collection':
                {
                    'paging': {...},
                    'sorting': {...}
                },
                'links':
                {
                    'data': {...}
                },
                'results': [
                    {
                        'data':
                        {
                            {
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
                                ...
                                'photo_id': 13981,
                                'photo_url': 'api/v1/members/8123/photo?v=13981.1'
                                ...
                                'type'; 0,
                                'type_name': 'User'
                                }
                        }
                    }
                ]
            }
            To access the (login) name of the first user found use ["results"][0]["data"]["properties"]["name"].
            It is easier to use the method get_result_value(response, "name", 0)
        """

        # Add query parameters (these are NOT passed via JSon body!)
        # type = 0 ==> User
        query = {"where_type": 0, "where_name": name}
        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        logger.debug(
            "Get user with login name -> '%s'; calling -> %s", name, request_url
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
            privileges (list, optional): values are Login, Public Access, Content Manager,
                                         Modify Users, Modify Groups, User Admin Rights,
                                         Grant Discovery, System Admin Rights
        Returns:
            dict: User information or None if the user couldn't be created (e.g. because it exisits already).
        """

        if privileges is None:
            privileges = ["Login", "Public Access"]

        user_post_body = {
            "type": 0,
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

        logger.debug("Add user -> '%s'; calling -> %s", name, request_url)

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
            value (str): field value
            field (str): user field to search with (where_name, where_first_name, where_last_name)
        Returns:
            dict: User information or None if the user couldn't be found (e.g. because it doesn't exist).

            Example response:
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
        """

        request_url = self.config()["membersUrlv2"] + "?" + field + "=" + value
        request_header = self.request_form_header()

        logger.debug(
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
            dict: User information or None if the user couldn't be updated (e.g. because it doesn't exist).
        """

        user_put_body = {field: value}

        request_url = self.config()["membersUrlv2"] + "/" + str(user_id)
        request_header = self.request_form_header()

        logger.debug(
            "Updating user with ID -> %s, field -> %s, value -> %s; calling -> %s",
            str(user_id),
            field,
            value,
            request_url,
        )
        logger.debug("User Attributes -> %s", str(user_put_body))

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
            dict: User information or None if the user couldn't be updated
                  (e.g. because it doesn't exist).
        """

        request_url = self.config()["membersUrlv2"] + "/preferences"
        request_header = self.request_form_header()

        logger.debug(
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
        self, field: str, value: str, config_section: str = "SmartUI"
    ) -> dict | None:
        """Update a defined field for a user profile.
           IMPORTANT: this method needs to be called by the authenticated user

        Args:
            field (str): user profile field
            value (str): new field value
            config_section (str, optional): name of the config section. Possible config_section values:
                                            * SmartUI
                                            * General
                                            * Colors
                                            * ContentIntelligence
                                            * Discussion
                                            * Follow Up
                                            * Template Workspaces
                                            * Workflow
                                            * XECMGOVSettings
                                            * CommunitySettings
                                            * RecMan
                                            * PhysObj
        Returns:
            dict: User information or None if the user couldn't be updated
                  (e.g. because it doesn't exist).
        """

        user_profile_put_body = {config_section: {field: value}}

        request_url = self.config()["membersUrlv2"] + "/preferences"
        request_header = self.request_form_header()

        logger.debug(
            "Updating profile for current user, field -> %s, value -> %s; calling -> %s",
            field,
            value,
            request_url,
        )
        logger.debug("User Attributes -> %s", str(user_profile_put_body))

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
            user_id (int): ID of the user
            photo_id (int): Node ID of the photo
        Returns:
            dict: Node information or None if photo node is not found.
        """

        update_user_put_body = {"photo_id": photo_id}

        request_url = self.config()["membersUrl"] + "/" + str(user_id)
        request_header = self.request_form_header()

        logger.debug(
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
            if self.exist_result_item(
                response=response, key="name", value=user_name, property_name=""
            ):
                return True
            else:
                return False
        else:
            response = self.get_user_proxies(use_v2=False)
            if not response or not "proxies" in response:
                return False
            proxies = response["proxies"]

            for proxy in proxies:
                if proxy["name"] == user_name:
                    return True
            return False

    # end method definition

    def get_user_proxies(self, use_v2: bool = False) -> dict | None:
        """Get list of user proxies.
           This method needs to be called as the user the proxy is acting for.
        Args:
            None
        Returns:
            dict: Node information or None if REST call fails.
        """

        if use_v2:
            request_url = self.config()["membersUrlv2"] + "/proxies"
        else:
            request_url = self.config()["membersUrl"] + "/proxies"
        request_header = self.request_form_header()

        logger.debug("Get proxy users for current user; calling -> %s", request_url)

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
        from_date: str = None,
        to_date: str = None,
    ) -> dict | None:
        """Add a user as a proxy user to the current user.
           IMPORTANT: This method needs to be called as the user the proxy is acting for.
           Optional this method can be provided with a time span the proxy should be active.
           This method differentiates between the old (xGov) based
           implementation and the new Extended ECM platform one
           that was introduced with version 23.4.

           Example payload for proxy user 19340 without time span:
           {"id":2545, "from_date": None, "to_date": None}

           Example payload for proxy user 19340 with time span:
           {"id":2545, "from_date":"2023-03-15", "to_date":"2023-03-31"}

        Args:
            user_id (int): ID of the user
            from_date (str, optional): start date for proxy (format YYYY-MM-DD)
            to_date (str, optional): end date for proxy (format YYYY-MM-DD)
        Returns:
            dict: Request response or None if call fails.
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
            logger.debug(
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
            logger.debug(
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
                proxy_user_id
            ),
        )

    # end method definition

    def add_favorite(self, node_id: int) -> dict | None:
        """Add a favorite for the current (authenticated) user.

        Args:
            node_id (int): ID of the node.
        Returns:
            dict: Request response or None if the favorite creation has failed.
        """

        request_url = self.config()["favoritesUrl"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.debug(
            "Adding favorite for node ID -> %s; calling -> %s", node_id, request_url
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
            tab_name (str): Name of the new tab.
            order (int): The order of the tab.
        Returns:
            dict: Request response or None if the favorite tab creation has failed.
        """

        favorite_tab_post_body = {"name": tab_name, "order": str(order)}

        request_url = self.config()["favoritesUrl"] + "/tabs"
        request_header = self.request_form_header()

        logger.debug("Adding favorite tab -> %s; calling -> %s", tab_name, request_url)

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
        """Lookup Content Server group.

        Args:
            name (str): name of the group
            show_error (bool): if True, treat as error if group is not found
        Returns:
            dict: Group information or None if the group is not found.
            The returned information has a structure like this:
            "data": [
                {
                    "id": 0,
                    "name": "string",
                    ...
                }
            ]
            To access the id of the first group found use ["data"][0]["id"]
        """

        # Add query parameters (these are NOT passed via JSon body!)
        # type = 1 ==> Group
        query = {"where_type": 1, "where_name": name}
        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["membersUrlv2"] + "?{}".format(encoded_query)

        request_header = self.request_form_header()

        logger.debug("Get group with name -> '%s'; calling -> %s", name, request_url)

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
            name (str): name of the group
        Returns:
            dict: Group information or None if the group couldn't be created (e.g. because it exisits already).
        """

        group_post_body = {"type": 1, "name": name}

        request_url = self.config()["membersUrlv2"]
        request_header = self.request_form_header()

        logger.debug("Adding group -> '%s'; calling -> %s", name, request_url)
        logger.debug("Group Attributes -> %s", str(group_post_body))

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
        self, group: int, member_type: int, limit: int = 100
    ) -> dict | None:
        """Get Content Server group members.

        Args:
            group (int): ID of the group.
            member_type (int): users = 0, groups = 1
            limit (int, optional): max number of results (internal default is 25)
        Returns:
            dict: Group members or None if the group members couldn't be found.
        """

        # default limit is 25 which may not be enough for groups with many members
        # where_type = 1 makes sure we just get groups and not users
        request_url = (
            self.config()["membersUrlv2"]
            + "/"
            + str(group)
            + "/members?where_type="
            + str(member_type)
            + "&limit="
            + str(limit)
        )
        request_header = self.request_form_header()

        logger.debug(
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
                group
            ),
        )

    # end method definition

    def add_group_member(self, member_id: int, group_id: int) -> dict | None:
        """Add a user or group to a target group.

        Args:
            member_id (int): ID of the user or group to add.
            group_id (int): ID of the target group.
        Returns:
            dict: Response or None if adding a the member fails.
        """

        group_member_post_body = {"member_id": member_id}

        request_url = self.config()["membersUrlv2"] + "/" + str(group_id) + "/members"
        request_header = self.request_form_header()

        logger.debug(
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
                member_id, group_id
            ),
        )

    # end method definition

    def get_node(
        self,
        node_id: int,
        fields: (
            str | list
        ) = "properties",  # per default we just get the most important information
        metadata: bool = False,
        timeout: int = REQUEST_TIMEOUT,
    ) -> dict | None:
        """Get a node based on the node ID.

        Args:
            node_id (int) is the node Id of the node
            fields (str | list, optional): Which fields to retrieve. This can have a big impact on performance!
                                            Possible fields:
                                            * "properties" - can further be restricted by adding sub-fields in {...} like "properties{id,name,parent_id,description}"
                                            * "categories"
                                            * "versions" - can further be restricted by adding ".element(0)" to just get the latest version
                                            * "permissions" - canfurther be restricted by adding ".limit(5)" to just get the first 5 permissions
                                            fields can either be a string (to select just one field group) or a list of strings to select multiple groups
            metadata (bool, optional): Returns metadata (data type, field length, min/max values, etc.)
                                       about data, which will be returned under results.metadata /
                                       metadata_map / metadata_order
            timeout (int, optional): timeout for the request in seconds
        Returns:
            dict: Node information or None if no node with this ID is found.

        """

        query = {}
        if fields:
            query["fields"] = fields

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "?{}".format(encoded_query)
        )

        if metadata:
            request_url += "&metadata"

        request_header = self.request_form_header()

        logger.debug("Get node with ID -> %s; calling -> %s", str(node_id), request_url)

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
        """Get a node based on the parent ID and name. This method does basically
           a query with "where_name" and the "result" is a list.

        Args:
            parent_id (int) is the node Id of the parent node
            name (str) is the name of the node to get
            fields (str | list, optional): Which fields to retrieve. This can have a big impact on performance!
                                            Possible fields:
                                            * "properties" - can further be restricted by adding sub-fields in {...} like "properties{id,name,parent_id,description}"
                                            * "categories"
                                            * "versions" - can further be restricted by adding ".element(0)" to just get the latest version
                                            * "permissions" - canfurther be restricted by adding ".limit(5)" to just get the first 5 permissions
                                            fields can either be a string (to select just one field group) or a list of strings to select multiple groups
            show_error (bool, optional): treat as error if node is not found
        Returns:
            dict: Node information or None if no node with this name is found in parent.
                        Access to node ID with: response["results"][0]["data"]["properties"]["id"]
        """

        # Add query parameters (these are NOT passed via JSon body!)
        query = {"where_name": name}
        if fields:
            query["fields"] = fields
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(parent_id)
            + "/nodes?limit=100&{}".format(encoded_query)
        )
        request_header = self.request_form_header()

        logger.debug(
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
                name, parent_id
            ),
            failure_message="Failed to get node with name -> '{}' and parent ID -> {}".format(
                name, parent_id
            ),
            show_error=show_error,
        )

        # Filter results for exact matches only
        if exact_match:
            results = response.get("results", [])
            filtered_results = next(
                (
                    node
                    for node in results
                    if node.get("data", {}).get("properties", {}).get("name") == name
                ),
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
            path (list): list of container items (top down), last item is name of to be retrieved item.
                         If path is empty the node of the volume is returned.
            create_path (bool): whether or not missing folders in the path should be created
            show_error (bool, optional): treat as error if node is not found
        Returns:
            dict: Node information or None if no node with this path is found.
        """

        parent_item_id = workspace_id

        # in case the path is an empty list
        # we will have the node of the workspace:
        node = self.get_node(parent_item_id)

        for path_element in path:
            node = self.get_node_by_parent_and_name(parent_item_id, path_element)
            current_item_id = self.get_result_value(node, "id")
            if not current_item_id:
                if create_path:
                    # create missing path element:
                    response = self.create_item(
                        parent_id=parent_item_id,
                        item_type=str(0),
                        item_name=path_element,
                        show_error=False,
                    )
                    # We may have a race condition here - another thread may have created the folder in parallel
                    if not response:
                        logger.warning(
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
                                logger.error(
                                    "Cannot create path element -> %s!", path_element
                                )
                            else:
                                logger.debug(
                                    "Cannot create path element -> %s.", path_element
                                )
                            return None
                    # now we set current item ID to the new response:
                    current_item_id = self.get_result_value(response, "id")
                    node = response
                # end if create_path
                else:
                    if show_error:
                        logger.error("Cannot find path element -> %s!", path_element)
                    else:
                        logger.debug("Cannot find path element -> %s.", path_element)
                    return None
            logger.debug(
                "Traversing path element -> '%s' (%s)",
                path_element,
                str(current_item_id),
            )
            parent_item_id = current_item_id

        return node

    # end method definition

    def get_node_by_volume_and_path(
        self, volume_type: int, path: list | None = None, create_path: bool = False
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
            path (list): list of container items (top down), last item is name of to be retrieved item.
                         If path is empty the node of the volume is returned.
            create_path (bool): if path elements are missing: should they be created?
        Returns:
            dict: Node information or None if no node with this path is found.
        """

        # If path is not given we use empty list to make the for loop below working in this case as well
        if path is None:
            path = []

        # Preparation: get volume IDs for Transport Warehouse (root volume and Transport Packages)
        response = self.get_volume(volume_type)
        if not response:
            logger.error("Volume type -> %s not found!", str(volume_type))
            return None

        volume_id = self.get_result_value(response, "id")
        logger.debug(
            "Volume type -> %s has node ID -> %s", str(volume_type), str(volume_id)
        )

        current_item_id = volume_id

        # in case the path is an empty list
        # we will have the node of the volume:
        node = self.get_node(current_item_id)

        for path_element in path:
            node = self.get_node_by_parent_and_name(current_item_id, path_element)
            path_item_id = self.get_result_value(node, "id")
            if not path_item_id and create_path:
                node = self.create_item(
                    parent_id=current_item_id, item_type=0, item_name=path_element
                )
                path_item_id = self.get_result_value(node, "id")
            if not path_item_id:
                logger.error(
                    "Cannot find path element -> '%s' in container with ID -> %s.",
                    path_element,
                    str(current_item_id),
                )
                return None
            current_item_id = path_item_id
            logger.debug("Traversing path element with ID -> %s", str(current_item_id))

        return node

    # end method definition

    def get_node_from_nickname(
        self, nickname: str, show_error: bool = False
    ) -> dict | None:
        """Get a node based on the nickname.

        Args:
            nickname (str): Nickname of the node.
            show_error (bool): treat as error if node is not found
        Returns:
            dict: Node information or None if no node with this nickname is found.
        """

        request_url = self.config()["nicknameUrl"] + "/" + nickname + "/nodes"
        request_header = self.request_form_header()

        logger.debug(
            "Get node with nickname -> '%s'; calling -> %s", nickname, request_url
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            warning_message="Node with nickname -> '{}' does not exist".format(
                nickname
            ),
            failure_message="Failed to get node with nickname -> '{}'".format(nickname),
            show_error=show_error,
        )

    # end method definition

    def set_node_nickname(
        self, node_id: int, nickname: str, show_error: bool = False
    ) -> dict | None:
        """Assign a nickname to an Extended ECM node (e.g. workspace)

        Args:
            nickname (str): Nickname of the node.
            show_error (bool): treat as error if node is not found
        Returns:
            dict: Node information or None if no node with this nickname is found.
        """

        if not nickname:
            return None

        nickname = nickname.replace("-", "_")
        nickname = nickname.replace(":", "_")
        nickname = nickname.replace("/", "_")
        nickname = nickname.replace(" ", "_")

        nickname_put_body = {"nickname": nickname}

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/nicknames"
        request_header = self.request_form_header()

        logger.debug(
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
                nickname, node_id
            ),
            failure_message="Failed to assign nickname -> '{}' to node ID -> {}".format(
                nickname, node_id
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
        fields: (
            str | list
        ) = "properties",  # per default we just get the most important information
        metadata: bool = False,
    ) -> dict | None:
        """Get a subnodes of a parent node ID.

        Args:
            parent_node_id (int): Node Id of the node
            filter_node_types (int, optional):
                -1 get all containers
                -2 get all searchable objects (default)
                -3 get all non-containers
            filter_name (str, optional): filter nodes for specific name (default = no filter)
            show_hidden (bool, optional): list also hidden items (default = False)
            limit (int, optional): maximum number of results (default = 100)
            page (int, optional): number of result page (default = 1 = 1st page)
            fields (str | list, optional): Which fields to retrieve. This can have a big impact on performance!
                                            Possible fields:
                                            * "properties" - can further be restricted by adding sub-fields in {...} like "properties{id,name,parent_id,description}"
                                            * "categories"
                                            * "versions" - can further be restricted by adding ".element(0)" to just get the latest version
                                            * "permissions" - canfurther be restricted by adding ".limit(5)" to just get the first 5 permissions
                                            fields can either be a string (to select just one field group) or a list of strings to select multiple groups
            metadata (bool, optional): Returns metadata (data type, field length, min/max values, etc.)
                                       about data, which will be returned under results.metadata /
                                       metadata_map / metadata_order
        Returns:
            dict: Subnodes information or None if no node with this parent ID is found.
            Example:

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

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(parent_node_id)
            + "/nodes"
            + "?{}".format(encoded_query)
        )

        if metadata:
            request_url += "&metadata"

        request_header = self.request_form_header()

        logger.debug(
            "Get subnodes of parent node with ID -> %s; calling -> %s",
            str(parent_node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get subnodes for parent node with ID -> {}".format(
                parent_node_id
            ),
        )

    # end method definition

    def lookup_node(
        self, parent_node_id: int, category: str, attribute: str, value: str
    ) -> dict:
        """Lookup the node under a parent node that has a specified value in a category attribute.

        Args:
            parent_node_id (int): Node ID of the parent (typically folder or workspace)
            category (str): name of the category
            attribute (str): name of the attribute that includes the value to match with
            value (str): given lookup value

        Returns:
            dict: Node or None if the REST API fails.
        """

        response = self.get_subnodes(
            parent_node_id=parent_node_id,
            limit=250,
            fields=["properties", "categories"],
            metadata=True,
        )
        if not response or not response.get("results", None):
            return None

        nodes = response["results"]
        for node in nodes:
            schema = node["metadata"]["categories"]
            data = node["data"]["categories"]
            for cat_data, cat_schema in zip(data, schema):

                data_values = list(cat_data.values())
                schema_values = list(cat_schema.values())
                # Schema has one additional element (the first one) representing
                # the category object itself. This includes the name. We need
                # to remove (pop) it from the schema list to make sure the schema list
                # and the data list have the same number of items. Otherwise
                # the following for loop with zip() would not properly align the
                # two lists:
                category_name = schema_values.pop(0)["name"]
                if category_name == category:
                    for attr_data, attr_schema in zip(data_values, schema_values):
                        attr_name = attr_schema["name"]
                        if attr_name == attribute:
                            if isinstance(attr_data, list):
                                if value in attr_data:
                                    return node
                            else:
                                if value == attr_data:
                                    return node
                    # we can break here and continue with the next node
                    # as we had the right category but did not find the matching value
                    break

        logger.warning(
            "Coudn't find a node with the value -> '%s' in the attribute -> '%s' of category -> '%s'.",
            value,
            attribute,
            category,
        )

        return None

    # end method definition

    def get_node_columns(self, node_id: int) -> dict:
        """Get custom columns configured / enabled for a node.

        Args:
            node_id (int): ID of the Node.
        Returns:
            dict: Information of the Node columns or None if the request fails.

            Example:
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
        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/columns"

        request_header = self.request_form_header()

        logger.debug(
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
                node_id
            ),
        )

    # end method definition

    def get_node_actions(
        self, node_id: int | list, filter_actions: list = None
    ) -> dict:
        """Get allowed actions for a node.

        Args:
            node_id (int | list): ID(s) of the Node(s). This can either be int (= single node) or a list of nodes
            filter_actions (list, optional): Optional list of actions to filter for,
                                             e.g. "delete", "copy", "permissions", "makefavorite", "open", "collect", "audit", ...
        Returns:
            dict: Information of the Node actions or None if the request fails. "results" is a dictionary with Node IDs as keys,
                  and three sub-sictionaries "data", "map", and "order.

            Example:
            {
                'links': {'data': {...}},
                'results': {
                    '173301412': {
                        'data': {
                            'AddRMClassifications': {'body': '{"displayPrompt":false,"enabled":false,"inheritfrom":false,"managed":true}', 'content_type': 'application/x-www-form-urlencoded', 'form_href': '', 'href': '/api/v2/nodes/164878074/rmclassifications', 'method': 'POST', 'name': 'Add RM Classification'},
                            'audit': {'body': '', 'content_type': '', 'form_href': '', 'href': '/api/v2/nodes/164878074/audit?limit=1000', 'method': 'GET', 'name': 'Audit'},
                            'BrowseClassifiedItems': {'body': '', 'content_type': '', 'form_href': '', 'href': '/api/v2/nodes/164878074/nodes', 'method': 'GET', 'name': 'Browse classified items'},
                            'BrowseRecManContainer': {'body': '', 'content_type': 'application/x-www-form-urlencoded', 'form_href': '', 'href': '', 'method': '', 'name': ''},
                            'collect': {'body': '', 'content_type': '', 'form_href': '', 'href': '/api/v2/nodes/164878074', 'method': 'PUT', 'name': 'Collect'},
                            'copy': {'body': '', 'content_type': '', 'form_href': '', 'href': '/api/v2/nodes', 'method': 'POST', 'name': 'Copy'},
                            'makefavorite': {'body': '', 'content_type': '', 'form_href': '', 'href': '/api/v2/members/favorites/164878074', 'method': 'POST', 'name': 'Add to Favorites'},
                            'more': {'body': '', 'content_type': '', 'form_href': '', 'href': '', 'method': '', 'name': '...'},
                            'open': {'body': '', 'content_type': '', 'form_href': '', 'href': '/api/v2/nodes/164878074/nodes', 'method': 'GET', 'name': 'Open'},
                            'permissions': {'body': '', 'content_type': '', 'form_href': '', 'href': '', 'method': '', 'name': 'Permissions'}, 'preview': {'body': '', 'content_type': '', 'form_href': '', 'href': '', 'method': '', 'name': 'Preview'},
                            'PrinteFile': {'body': '', 'content_type': '', 'form_href': '', 'href': 'api/v2/govprint', 'method': 'POST', 'name': 'Print'}, 'properties': {'body': '', 'content_type': '', 'form_href': '', 'href': '/api/v2/nodes/164878074', 'method': 'GET', 'name': 'Properties'},
                            'SendOutlookReminder': {'body': '', 'content_type': '', 'form_href': '', 'href': 'api/v2/node/xgovoutlookreminder', 'method': 'POST', 'name': 'Send Outlook reminder'},
                            'viewx-compare': {'body': '', 'content_type': '', 'form_href': '', 'href': '', 'method': '', 'name': 'viewx-compare'},
                            'viewx-transform': {'body': '', 'content_type': '', 'form_href': '', 'href': '', 'method': '', 'name': 'viewx-transform'}},
                        'map': {...},
                        'order': [...]
                    }
                }
        """

        if isinstance(node_id, list):
            actions_post_body = {"ids": node_id, "actions": filter_actions}
        else:
            actions_post_body = {"ids": [node_id], "actions": filter_actions}

        request_url = self.config()["nodesUrlv2"] + "/actions"

        request_header = self.request_form_header()

        logger.debug(
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
                node_id
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
            node_id (int): ID of the node. You can use the get_volume() function below to
                               to the node id for a volume.
            name (str): New name of the node.
            description (str): New description of the node.
            name_multilingual (dict, optional): multi-lingual node names
            description_multilingual (dict, optional): multi-lingual description
        Returns:
            dict: Request response or None if the renaming fails.
        """

        rename_node_put_body = {"name": name, "description": description}

        if name_multilingual:
            rename_node_put_body["name_multilingual"] = name_multilingual
        if description_multilingual:
            rename_node_put_body["description_multilingual"] = description_multilingual

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.debug(
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
                node_id, name
            ),
        )

    # end method definition

    def delete_node(self, node_id: int, purge: bool = False) -> dict | None:
        """Delete an existing node

        Args:
            node_id (int): ID of the node to be deleted
            purge (bool, optional): If True, immediately purge the item from the recycle bin

        Returns:
            dict: response of the REST call; None in case of a failure
        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.debug(
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

    def purge_node(self, node_id: int | list):
        """Purge an item in the recycle bin (final destruction)

        Args:
            node_id (int | list): ID(s) of the node(s) to be finally deleted
        """

        request_url = self.config()["recycleBinUrl"] + "/nodes/purge"
        request_header = self.request_form_header()

        if isinstance(node_id, list):
            purge_data = {"ids": node_id}
        else:
            purge_data = {"ids": [node_id]}

        logger.debug(
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
                node_id
            ),
        )

    # end method definition

    def restore_node(self, node_id: int | list) -> dict | None:
        """Restore an item from the recycle bin (undo deletion)

        Args:
            node_id (int | list): ID(s) of the node(s) to be restored

        Results:
            dict | None: dictionary include key 'success' with the successful restored IDs

        Example:
            {
                'failure': {
                    'errors': {}, 'ids': [...]
                },
                'success': {
                    'ids': [...]
                }
            }
        """

        request_url = self.config()["recycleBinUrl"] + "/nodes/restore"
        request_header = self.request_form_header()

        if isinstance(node_id, list):
            restore_data = {"ids": node_id}
        else:
            restore_data = {"ids": [node_id]}

        logger.debug(
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
                node_id
            ),
        )

    # end method definition

    def get_volumes(self) -> dict | None:
        """Get all Volumes.

        Args:
            None
        Returns:
            dict: Volume Details or None if an error occured.
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
            Example:
            ["results"][0]["data"]["properties"]["id"] is the node ID of the volume.
        """

        request_url = self.config()["volumeUrl"]
        request_header = self.request_form_header()

        logger.debug("Get all volumes; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get volumes",
        )

    # end method definition

    def get_volume(
        self, volume_type: int, timeout: int = REQUEST_TIMEOUT
    ) -> dict | None:
        """Get Volume information based on the volume type ID.

        Args:
            volume_type (int): ID of the volume type
            timeout (int, optional): timeout for the request in seconds
        Returns:
            dict: Volume Details or None if volume is not found.
            ["results"]["data"]["properties"]["id"] is the node ID of the volume.
        """

        request_url = self.config()["volumeUrl"] + "/" + str(volume_type)
        request_header = self.request_form_header()

        logger.debug(
            "Get volume type -> %s; calling -> %s", str(volume_type), request_url
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
        """Check if a node with a given name does already exist under a given parent node.

        Args:
            parent_id (int): ID of the parent location
            node_name (str): name of the new node
        Returns:
            dict | None: if response["results"] contains an element then the node with the name does exist.
                         if not response["results"] then the node with the given name does not exist
                         None in case an error occured
        """

        request_url = self.config()["validationUrl"]
        request_header = self.request_form_header()

        logger.debug(
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
                node_name, parent_id
            ),
        )

    # end method definition

    def upload_file_to_volume(
        self, package_url: str, file_name: str, mime_type: str, volume_type: int
    ) -> dict | None:
        """Fetch a file from a URL or local filesystem and upload it to a Content Server volume.

        Args:
            package_url (str): URL to download file
            file_name (str): name of the file
            mime_type (str): mimeType of the file
            volume_type (int): type (ID) of the volume
        Returns:
            dict: Upload response or None if the upload fails.
        """

        if package_url.startswith("http"):
            # Download file from remote location specified by the packageUrl
            # this must be a public place without authentication:
            logger.debug("Download transport package from URL -> %s", package_url)

            try:
                package = requests.get(url=package_url, timeout=1200)
                package.raise_for_status()
            except requests.exceptions.HTTPError as errh:
                logger.error("Http Error -> %s", errh.strerror)
                return None
            except requests.exceptions.ConnectionError as errc:
                logger.error("Error Connecting -> %s", errc.strerror)
                return None
            except requests.exceptions.Timeout as errt:
                logger.error("Timeout Error -> %s", errt.strerror)
                return None
            except requests.exceptions.RequestException as err:
                logger.error("Request error -> %s", err.strerror)
                return None

            logger.debug(
                "Successfully downloaded package -> %s; status code -> %s",
                package_url,
                package.status_code,
            )
            file = package.content

        elif os.path.exists(package_url):
            logger.debug("Using local package -> %s", package_url)
            file = open(file=package_url, mode="rb")

        else:
            logger.warning("Cannot access -> %s", package_url)
            return None

        upload_post_data = {"type": str(volume_type), "name": file_name}
        upload_post_files = [("file", (f"{file_name}", file, mime_type))]

        request_url = self.config()["nodesUrlv2"]

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
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
                package_url, volume_type
            ),
        )

    # end method definition

    def upload_file_to_parent(
        self,
        file_url: str,
        file_name: str,
        mime_type: str,
        parent_id: int,
        category_data: dict | None = None,
        description: str = "",
        external_modify_date: str | None = None,
        external_create_date: str | None = None,
        show_error: bool = True,
    ) -> dict | None:
        """Fetch a file from a URL or local filesystem and upload it to a Content Server parent (folder).

        Args:
            file_url (str): URL to download file or local file
            file_name (str): name of the file
            mime_type (str): mimeType of the file
            parent_id (int): parent (ID) of the file to upload
            category_data (dict): metadata / category data
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
            description (str, optional): description of the document
            external_create_date (str, optional) value of the source system in format 2024-06-24
            external_modify_date (str, optional) value of the source system in format 2024-06-24
            show_error (bool, optional): treat as error if upload has failed
                                         (you may not want to show an error if the file already exists)
        Returns:
            dict: Upload response or None if the upload fails.
        """

        if not file_name:
            logger.error("Missing file name! Cannot upload file.")
            return None

        # Make sure we don't have leading or trailing whitespace:
        file_name = file_name.strip()

        if file_url.startswith("http"):
            # Download file from remote location specified by the file_url parameter
            # this must be a public place without authentication:
            logger.debug("Download file from URL -> %s", file_url)

            try:
                response = requests.get(url=file_url, timeout=1200)
                response.raise_for_status()
            except requests.exceptions.HTTPError as errh:
                logger.error("Http Error -> %s", errh.strerror)
                return None
            except requests.exceptions.ConnectionError as errc:
                logger.error("Error Connecting -> %s", errc.strerror)
                return None
            except requests.exceptions.Timeout as errt:
                logger.error("Timeout Error -> %s", errt.strerror)
                return None
            except requests.exceptions.RequestException as err:
                logger.error("Request error -> %s", err.strerror)
                return None

            logger.debug(
                "Successfully downloaded file -> %s; status code -> %s",
                file_url,
                response.status_code,
            )
            file_content = response.content

        elif os.path.exists(file_url):
            logger.debug("Uploading local file -> %s", file_url)
            file_content = open(file=file_url, mode="rb")

        else:
            logger.warning("Cannot access -> %s", file_url)
            return None

        upload_post_data = {
            "type": str(144),
            "name": file_name,
            "parent_id": str(parent_id),
            "external_create_date": external_create_date,
            "external_modify_date": external_modify_date,
        }

        if description:
            upload_post_data["description"] = description

        if not mime_type:
            mime_type, _ = mimetypes.guess_type(file_url)

        if not mime_type and magic_installed:
            try:
                mime = magic.Magic(mime=True)
                mime_type = mime.from_file(file_url)
            except Exception:
                logger.error(
                    "Mime type for document -> '%s' could not be identified for parent ID -> %s",
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

        logger.debug(
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
            data=upload_post_data,
            files=upload_post_files,
            timeout=None,
            warning_message="Cannot upload file -> '{}' to parent with ID -> {}. It may already exist.".format(
                file_url, parent_id
            ),
            failure_message="Failed to upload file -> '{}' to parent -> {}".format(
                file_url, parent_id
            ),
            show_error=show_error,
        )

        node_id = self.get_result_value(response, "id")
        if not node_id:
            logger.error("No Node ID found! Cannot set category.")
            return None

        # Update the categories on the documents
        if category_data is not None:
            for category in category_data:
                self.set_category_values(
                    node_id=node_id,
                    category_id=category,
                    category_data=category_data[category],
                )

        return response

    # end method definition

    def add_document_version(
        self,
        node_id: int,
        file_url: str,
        file_name: str,
        mime_type: str = "text/plain",
        description: str = "",
    ) -> dict | None:
        """Fetch a file from a URL or local filesystem and upload it as a new document version.

        Args:
            node_id (int): ID of the document to add add version to
            file_url (str): URL to download file or local file
            file_name (str): name of the file
            mime_type (str, optional): mimeType of the file (default = text/plain)
            description (str, optional): description of the version (default = no description)
        Returns:
            dict: Add version response or None if the upload fails.
        """

        # Desciption of a version cannot be longer than 255 characters in OTCS:
        if description and len(description) > 255:
            description = description[:255]

        if file_url.startswith("http"):
            # Download file from remote location specified by the file_url parameter
            # this must be a public place without authentication:
            logger.debug("Download file from URL -> %s", file_url)

            try:
                response = requests.get(
                    url=file_url,
                    timeout=None,
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError as errh:
                logger.error("Http Error -> %s", errh.strerror)
                return None
            except requests.exceptions.ConnectionError as errc:
                logger.error("Error Connecting -> %s", errc.strerror)
                return None
            except requests.exceptions.Timeout as errt:
                logger.error("Timeout Error -> %s", errt.strerror)
                return None
            except requests.exceptions.RequestException as err:
                logger.error("Request error -> %s", err.strerror)
                return None

            logger.debug(
                "Successfully downloaded file -> %s; status code -> %s",
                file_url,
                response.status_code,
            )
            file_content = response.content

        elif os.path.exists(file_url):
            logger.debug("Upload local file -> %s", file_url)
            file_content = open(file=file_url, mode="rb")

        else:
            logger.warning("Cannot access -> %s", file_url)
            return None

        upload_post_data = {"description": description}
        upload_post_files = [("file", (f"{file_name}", file_content, mime_type))]

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
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
                file_url, node_id
            ),
        )

    # end method definition

    def get_latest_document_version(self, node_id: int) -> dict | None:
        """Get latest version of a document node based on the node ID.

        Args:
            node_id (int) is the node Id of the node
        Returns:
            dict: Node information or None if no node with this ID is found.
        """

        request_url = (
            self.config()["nodesUrl"] + "/" + str(node_id) + "/versions/latest"
        )
        request_header = self.request_form_header()

        logger.debug(
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
                str(node_id)
            ),
        )

    # end method definition

    def get_document_content(
        self,
        node_id: int,
        version_number: str = "",
        parse_request_response: bool = False,
    ) -> bytes | dict | None:
        """Get document content from Extended ECM.

        Args:
            node_id (int): node ID of the document to download
            version_number (str, optional): version of the document to download.
                                            If version = "" then download the latest
                                            version.
        Returns:
            bytes | dict | None: content of the file or None in case of an error.
                                 If parse_request_response is True then then the
                                 content is interpreted as JSON and delivered as a dictionary
        """

        if not version_number:
            response = self.get_latest_document_version(node_id)
            if not response:
                logger.error(
                    "Cannot get latest version of document with ID -> %s", str(node_id)
                )
            version_number = response["data"]["version_number"]

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/versions/"
            + str(version_number)
            + "/content"
        )
        request_header = self.request_download_header()

        logger.debug(
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
                node_id
            ),
            parse_request_response=parse_request_response,
        )

        if parse_request_response:
            # In this case response.content has been interpreted as JSON
            # and delivered as a Python dict (or None in case of an error):
            return response

        if response is not None:
            # In sthis case the unparsed content is delivered as bytes:
            return response.content

        return None

    # end method definition

    def get_json_document(
        self, node_id: int, version_number: str = ""
    ) -> list | dict | None:
        """Get document content from Extended ECM and read content as JSON.

        Args:
            node_id (int): node ID of the document to download
            version_number (str, optional): version of the document to download.
                                            If version = "" then download the latest
                                            version.
        Returns:
            list|dict: content of the file or None in case of an error.
        """

        return self.get_document_content(
            node_id=node_id, version_number=version_number, parse_request_response=True
        )

    # end method definition

    def download_document(
        self, node_id: int, file_path: str, version_number: str = ""
    ) -> bool:
        """Download a document from Extended ECM to local file system.

        Args:
            node_id (int): node ID of the document to download
            file_path (str): local file path (directory)
            version_number (str): version of the document to download.
                                     If version = "" then download the latest
                                     version.
        Returns:
            bool: True if the document has been download to the specified file.
                     False otherwise.
        """

        if not version_number:
            response = self.get_latest_document_version(node_id)
            if not response:
                logger.error(
                    "Cannot get latest version of document with ID -> %s", str(node_id)
                )
                return False
            version_number = response["data"]["version_number"]

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/versions/"
            + str(version_number)
            + "/content"
        )
        request_header = self.request_download_header()

        logger.debug(
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
                node_id
            ),
            parse_request_response=False,
        )

        if response is None:
            return False

        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            logger.warning("Directory -> '%s' does not exist, creating it.", directory)
            os.makedirs(directory)

        try:
            with open(file_path, "wb") as file:
                file.write(response.content)
        except Exception as exc:
            logger.error("Error while writing file content -> %s", exc)
            return False

        return True

    # end method definition

    def download_config_file(
        self, otcs_url_suffix: str, file_path: str, search: str = "", replace: str = ""
    ) -> bool:
        """Download a config file from a given OTCS URL. This is NOT
            for downloading documents from within the OTCS repository
            but for configuration files such as app packages for MS Teams.

        Args:
            otcs_url_suffix (str): OTCS URL suffix starting typically starting
                                      with /cs/cs?func=,
                                      e.g. /cs/cs?func=officegroups.DownloadTeamsPackage
            file_path (str): local path to save the file (direcotry + filename)
            search (str, optional): optional string to search for a replacement
            replace (str, optional): optional replacement
        Returns:
            bool: True if the download succeeds, False otherwise
        """

        request_url = self.config()["baseUrl"] + otcs_url_suffix
        request_header = self.request_download_header()

        logger.debug("Download config file from URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            logger.error("Http Error -> %s", errh.strerror)
            return False
        except requests.exceptions.ConnectionError as errc:
            logger.error("Error Connecting -> %s", errc.strerror)
            return False
        except requests.exceptions.Timeout as errt:
            logger.error("Timeout Error -> %s", errt.strerror)
            return False
        except requests.exceptions.RequestException as err:
            logger.error("Request error -> %s", err.strerror)
            return False

        content = response.content

        if search:
            logger.debug(
                "Search for all occurances of '%s' in the config file and replace them with '%s'",
                search,
                replace,
            )
            content = content.replace(search.encode("utf-8"), replace.encode("utf-8"))

        # Open file in write binary mode
        with open(file=file_path, mode="wb") as file:
            # Write the content to the file
            file.write(content)

        logger.debug(
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
        """Search for a search term.

        Args:
            search_term (str), e.g. "test or OTSubType: 189"
            look_for (str, optional): 'allwords', 'anywords', 'exactphrase', and 'complexquery'.
                                      If not specified, it defaults to 'complexQuery'.
            modifier (str, optional): 'synonymsof', 'relatedto', 'soundslike', 'wordbeginswith',
                                      and 'wordendswith'.
                                      If not specified or specify any value other than the available options,
                                      it will be ignored.
            slice_id (int, optional): ID of an existing search slice
            query_id (int, optional): ID of an saved search query
            template_id (int, optional): ID of an saved search template
            limit (int, optional): maximum number of results (default = 100)
            page (int, optional): number of result page (default = 1 = 1st page)
        Returns:
            dict: search response or None if the search fails.
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

        logger.debug("Search for term -> %s; calling -> %s", search_term, request_url)

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=search_post_body,
            timeout=None,
            failure_message="Failed to search for term -> '{}'".format(search_term),
        )

    # end method definition

    def get_external_system_connection(
        self, connection_name: str, show_error: bool = False
    ) -> dict | None:
        """Get Extended ECM external system connection (e.g. SAP, Salesforce, SuccessFactors).

        Args:
            connection_name (str): Name of the connection
            show_error (bool, optional): If True, treat as error if connection is not found.
        Returns:
            dict: External system Details or None if the REST call fails.
        """
        # Encode special characters in connection_name
        connection_name = connection_name.replace("\\", "0xF0A6").replace("/", "0xF0A7")
        request_url = (
            self.config()["externalSystemUrl"] + "/" + connection_name + "/config"
        )
        request_header = self.cookie()

        logger.debug(
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
                connection_name
            ),
            failure_message="Failed to get external system connection -> '{}'".format(
                connection_name
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
        client_id: str = None,
        client_secret: str = None,
    ) -> dict | None:
        """Add Extended ECM external system connection (e.g. SAP, Salesforce, SuccessFactors).

        Args:
            connection_name (str): Name of the connection
            connection_type (str): Type of the connection (HTTP, SF, SFInstance)
            as_url (str): Application URL of the external system
            base_url (str): Base URL of the external system
            username (str): username (used for BASIC authentication)
            password (str): password (used for BASIC authentication)
            authentication_method (str, optional): either BASIC (using username and password) or OAUTH
            client_id (str, optional): OAUTH Client ID (only required if authenticationMethod = OAUTH)
            client_secret (str, optional): OAUTH Client Secret (only required if authenticationMethod = OAUTH)
        Returns:
            dict: External system Details or None if the REST call fails.
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
                authentication_method
            )
            external_system_post_body["client_id"] = str(client_id)
            external_system_post_body["client_secret"] = str(client_secret)

        request_url = self.config()["externalSystemUrl"]
        request_header = self.cookie()

        logger.debug(
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
                connection_name
            ),
        )

    # end method definition

    def create_transport_workbench(self, workbench_name: str) -> dict | None:
        """Create a Workbench in the Transport Volume.

        Args:
            workbench_name (str): Name of the workbench to be created
        Returns:
            dict: Create response or None if the creation fails.
        """

        create_worbench_post_data = {"type": "528", "name": workbench_name}

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        logger.debug(
            "Create transport workbench -> %s; calling -> %s",
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
                workbench_name
            ),
        )

    # end method definition

    def unpack_transport_package(
        self, package_id: int, workbench_id: int
    ) -> dict | None:
        """Unpack an existing Transport Package into an existing Workbench.

        Args:
            package_id (int): ID of package to be unpacked
            workbench_id (int): ID of target workbench
        Returns:
            dict: Unpack response or None if the unpacking fails.
        """

        unpack_package_post_data = {"workbench_id": workbench_id}

        request_url = self.config()["nodesUrlv2"] + "/" + str(package_id) + "/unpack"
        request_header = self.request_form_header()

        logger.debug(
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
                package_id, workbench_id
            ),
        )

    # end method definition

    def deploy_workbench(self, workbench_id: int) -> dict | None:
        """Deploy an existing Workbench.

        Args:
            workbench_d (int): ID of the workbench to be deployed
        Returns:
            dict: Deploy response or None if the deployment fails.
        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(workbench_id) + "/deploy"
        request_header = self.request_form_header()

        logger.debug(
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
                workbench_id
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
        """Main method to deploy a transport. This uses subfunctions to upload,
           unpackage and deploy the transport, and creates the required workbench.

        Args:
            package_url (str): URL to download the transport package.
            package_name (str): Name of the transport package ZIP file
            package_description (str): Description of the transport package
            replacements (list of dicts): List of replacement values to be applied
                                          to all XML files in transport;
                                          each dict needs to have two values:
                                          - placeholder: text to replace
                                          - value: text to replace with
            extractions (list of dicts): List of XML Subtrees to extract
                                         each XML file in transport;
                                         each dict needs to have two values:
                                          - xpath: defining the subtree to extract
                                          - enabled: True if the extraction is active
        Returns:
            dict: Deploy response or None if the deployment fails.
        """

        if replacements is None:
            replacements = []
        if extractions is None:
            extractions = []

        # Preparation: get volume IDs for Transport Warehouse (root volume and Transport Packages)
        response = self.get_volume(525)
        transport_root_volume_id = self.get_result_value(response, "id")
        if not transport_root_volume_id:
            logger.error("Failed to retrieve transport root volume")
            return None
        logger.debug("Transport root volume ID -> %s", str(transport_root_volume_id))

        response = self.get_node_by_parent_and_name(
            transport_root_volume_id, "Transport Packages"
        )
        transport_package_volume_id = self.get_result_value(response, "id")
        if not transport_package_volume_id:
            logger.error("Failed to retrieve transport package volume")
            return None
        logger.debug(
            "Transport package volume ID -> %s", str(transport_package_volume_id)
        )

        # Step 1: Upload Transport Package
        logger.debug(
            "Check if transport package -> '%s' already exists...", package_name
        )
        response = self.get_node_by_parent_and_name(
            transport_package_volume_id, package_name
        )
        package_id = self.get_result_value(response, "id")
        if package_id:
            logger.debug(
                "Transport package -> '%s' does already exist; existing package ID -> %s",
                package_name,
                str(package_id),
            )
        else:
            logger.debug(
                "Transport package -> '%s' does not yet exist, loading from -> %s",
                package_name,
                package_url,
            )
            # If we have string replacements configured execute them now:
            if replacements:
                logger.debug(
                    "Transport -> '%s' has replacements -> %s",
                    package_name,
                    str(replacements),
                )
                self.replace_transport_placeholders(package_url, replacements)
            else:
                logger.debug("Transport -> '%s' has no replacements!", package_name)
            # If we have data extractions configured execute them now:
            if extractions:
                logger.debug(
                    "Transport -> '%s' has extractions -> %s",
                    package_name,
                    str(extractions),
                )
                self.extract_transport_data(package_url, extractions)
            else:
                logger.debug("Transport -> '%s' has no extractions!", package_name)
            # Upload package to Extended ECM:
            response = self.upload_file_to_volume(
                package_url, package_name, "application/zip", 531
            )
            package_id = self.get_result_value(response, "id")
            if not package_id:
                logger.error("Failed to upload transport package -> %s", package_url)
                return None
            logger.debug(
                "Successfully uploaded transport package -> '%s'; new package ID -> %s",
                package_name,
                str(package_id),
            )

        # Step 2: Create Transport Workbench (if not yet exist)
        workbench_name = package_name.split(".")[0]
        logger.debug(
            "Check if workbench -> '%s' is already deployed...", workbench_name
        )
        # check if the package name has the suffix "(deployed)" - this indicates it is alreadey
        # successfully deployed (see renaming at the end of this method)
        response = self.get_node_by_parent_and_name(
            transport_root_volume_id, workbench_name + " (deployed)"
        )
        workbench_id = self.get_result_value(response, "id")
        if workbench_id:
            logger.debug(
                "Workbench -> '%s' has already been deployed successfully; existing workbench ID -> %s; skipping transport",
                workbench_name,
                str(workbench_id),
            )
            # we return and skip this transport...
            return response
        else:
            logger.debug("Check if workbench -> '%s' already exists...", workbench_name)
            response = self.get_node_by_parent_and_name(
                transport_root_volume_id, workbench_name
            )
            workbench_id = self.get_result_value(response, "id")
            if workbench_id:
                logger.debug(
                    "Workbench -> '%s' does already exist but is not successfully deployed; existing workbench ID -> %s",
                    workbench_name,
                    str(workbench_id),
                )
            else:
                response = self.create_transport_workbench(workbench_name)
                workbench_id = self.get_result_value(response, "id")
                if not workbench_id:
                    logger.error("Failed to create workbench -> '%s'", workbench_name)
                    return None
                logger.debug(
                    "Successfully created workbench -> '%s'; new workbench ID -> %s",
                    workbench_name,
                    str(workbench_id),
                )

        # Step 3: Unpack Transport Package to Workbench
        logger.debug(
            "Unpack transport package -> '%s' (%s) to workbench -> '%s' (%s)",
            package_name,
            str(package_id),
            workbench_name,
            str(workbench_id),
        )
        response = self.unpack_transport_package(package_id, workbench_id)
        if not response:
            logger.error("Failed to unpack the transport package -> '%s'", package_name)
            return None
        logger.debug(
            "Successfully unpackaged to workbench -> '%s' (%s)",
            workbench_name,
            str(workbench_id),
        )

        # Step 4: Deploy Workbench
        logger.debug("Deploy workbench -> '%s' (%s)", workbench_name, str(workbench_id))
        response = self.deploy_workbench(workbench_id)
        if not response:
            logger.error("Failed to deploy workbench -> '%s'", workbench_name)
            return None

        logger.debug(
            "Successfully deployed workbench -> '%s' (%s)",
            workbench_name,
            str(workbench_id),
        )
        self.rename_node(
            workbench_id,
            workbench_name + " (deployed)",
            package_description,
        )

        return response

    # end method definition

    def replace_transport_placeholders(
        self, zip_file_path: str, replacements: list
    ) -> bool:
        """Search and replace strings in the XML files of the transport package

        Args:
            zip_file_path (str): Path to transport zip file
            replacements (list of dicts): List of replacement values; dict needs to have two values:
                                         * placeholder: text to replace
                                         * value: text to replace with
        Returns:
            Filename to the updated zip file
        """

        if not os.path.isfile(zip_file_path):
            logger.error("Zip file -> '%s' not found.", zip_file_path)
            return False

        # Extract the zip file to a temporary directory
        zip_file_folder = os.path.splitext(zip_file_path)[0]
        with zipfile.ZipFile(zip_file_path, "r") as zfile:
            zfile.extractall(zip_file_folder)

        modified = False

        # Replace search pattern with replace string in all XML files in the directory and its subdirectories
        for replacement in replacements:
            if not "value" in replacement:
                logger.error(
                    "Replacement needs a value but it is not specified. Skipping..."
                )
                continue
            if "enabled" in replacement and not replacement["enabled"]:
                logger.debug(
                    "Replacement for transport -> '%s' is disabled. Skipping...",
                    zip_file_path,
                )
                continue
            # there are two types of replacements:
            # 1. XPath - more elegant and powerful
            # 2. Search & Replace - basically treat the XML file like a text file and do a search & replace
            if "xpath" in replacement:
                logger.debug(
                    "Using xpath -> %s to narrow down the replacement",
                    replacement["xpath"],
                )
                if "setting" in replacement:
                    logger.debug(
                        "Looking up setting -> %s in XML element",
                        replacement["setting"],
                    )
                if "assoc_elem" in replacement:
                    logger.debug(
                        "Looking up assoc element -> %s in XML element",
                        replacement["assoc_elem"],
                    )
            else:  # we have a simple "search & replace" replacement
                if not "placeholder" in replacement:
                    logger.error(
                        "Replacement without an xpath needs a placeholder value but it is not specified. Skipping..."
                    )
                    continue
                if replacement.get("placeholder") == replacement["value"]:
                    logger.debug(
                        "Placeholder and replacement are identical -> %s. Skipping...",
                        replacement["value"],
                    )
                    continue
                logger.debug(
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
            )
            if found:
                logger.debug(
                    "Replacement -> %s has been completed successfully for Transport package -> %s",
                    replacement,
                    zip_file_folder,
                )
                modified = True
            else:
                logger.warning(
                    "Replacement -> %s not found in Transport package -> %s",
                    replacement,
                    zip_file_folder,
                )

        if not modified:
            logger.warning(
                "None of the specified replacements have been found in Transport package -> %s. No need to create a new transport package.",
                zip_file_folder,
            )
            return False

        # Create the new zip file and add all files from the directory to it
        new_zip_file_path = (
            os.path.dirname(zip_file_path) + "/new_" + os.path.basename(zip_file_path)
        )
        logger.debug(
            "Content of transport -> '%s' has been modified - repacking to new zip file -> %s",
            zip_file_folder,
            new_zip_file_path,
        )
        with zipfile.ZipFile(new_zip_file_path, "w", zipfile.ZIP_DEFLATED) as zip_ref:
            for subdir, _, files in os.walk(
                zip_file_folder
            ):  # 2nd parameter is not used, thus using _ instead of dirs
                for file in files:
                    file_path = os.path.join(subdir, file)
                    rel_path = os.path.relpath(file_path, zip_file_folder)
                    zip_ref.write(file_path, arcname=rel_path)

        # Close the new zip file and delete the temporary directory
        zip_ref.close()
        old_zip_file_path = (
            os.path.dirname(zip_file_path) + "/old_" + os.path.basename(zip_file_path)
        )
        logger.debug(
            "Rename orginal transport zip file -> '%s' to -> '%s'",
            zip_file_path,
            old_zip_file_path,
        )
        os.rename(zip_file_path, old_zip_file_path)
        logger.debug(
            "Rename new transport zip file -> '%s' to -> '%s'",
            new_zip_file_path,
            zip_file_path,
        )
        os.rename(new_zip_file_path, zip_file_path)

        # Return the path to the new zip file
        return True

    # end method definition

    def extract_transport_data(self, zip_file_path: str, extractions: list) -> bool:
        """Search and extract XML data from the transport package

        Args:
            zip_file_path (str): Path to transport zip file
            extractions (list of dicts): List of extraction values; dict needs to have two values:
                                         * xpath: structure to find
                                         * enabed (optional): if the extraction is active
        Returns:
            True if successful, False otherwise. THIS METHOD MODIFIES EXTRACTIONS
            BY ADDING A NEW KEY "data" TO EACH EXTRACTION ELEMENT!!
        """

        if not os.path.isfile(zip_file_path):
            logger.error("Zip file -> '%s' not found.", zip_file_path)
            return False

        # Extract the zip file to a temporary directory
        zip_file_folder = os.path.splitext(zip_file_path)[0]
        with zipfile.ZipFile(zip_file_path, "r") as zfile:
            zfile.extractall(zip_file_folder)

        # Extract data from all XML files in the directory and its subdirectories
        for extraction in extractions:
            if not "xpath" in extraction:
                logger.error(
                    "Extraction needs an XPath but it is not specified. Skipping..."
                )
                continue
            if "enabled" in extraction and not extraction["enabled"]:
                logger.debug(
                    "Extraction for transport -> '%s' is disabled. Skipping...",
                    zip_file_path,
                )
                continue

            xpath = extraction["xpath"]
            logger.debug(
                "Using xpath -> %s to extract the data",
                xpath,
            )

            # This delivers a list of strings containing the extracted data:
            extracted_data = XML.extract_from_xml_files(
                zip_file_folder,
                xpath,
            )
            if extracted_data:
                logger.debug(
                    "Extraction with XPath -> %s has been successfully completed for Transport package -> %s",
                    xpath,
                    zip_file_folder,
                )
                # Add the extracted elements to the extraction data structure (dict).
                extraction["data"] = extracted_data
            else:
                logger.warning(
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
            dict: Workspace Types information (for all external systems)
                  or None if the request fails.
        """

        request_url = self.config()["businessObjectTypesUrl"]
        request_header = self.request_form_header()

        logger.debug(
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
        """Get business object type information. Unfortunately this REST API is
           pretty much limited. It does not return Field names of external system properties
           and also does not return property groups defined.

        Args:
            external_system_id (str): External system Id (such as "TM6")
            type_name (str): Type name of the business object (such as "SAP Customer")
        Returns:
            dict: Business Object Type information or None if the request fails.

            Example response:
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
                'rmiconsdata': {'class_id': 0, 'official': 0, 'show_classify': False, 'show_hold': False, 'show_hold_tab': False, 'show_label_tab': True, 'show_official': False, 'show_xref': False, 'show_xref_tab': False},
                'sestatus_doc_info': {'is_se_document': False, 'sync_tooltip': ''},
                'sharing_info': {'is_shared': False, 'sync_state': -1},
                'showmainruleicon': False,
                ...
            }
        """

        query = {
            "expand_ext_system": expand_external_system,
            "expand_wksp_type": expand_workspace_type,
        }

        encoded_query = urllib.parse.urlencode(query, doseq=True)

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

        logger.debug(
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
                type_name, external_system_id
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
        """Get all business objects for an external system and a given business object type.

        Args:
            external_system_id (str): External system Id (such as "TM6")
            type_name (str): Type name of the business object (such as "SAP Customer")
            where_clause (dict, optional): filter the results based on 1 or kultiple
                                           where clauses (THE  NAME CONVENTION FOR THE
                                           FIELDS IS UNCLEAR)
            limit (int, optional): maximum result items
            page (int, optional): page for chunked result lists
        Returns:
            dict: Business Object information (for all results)
                  or None if the request fails.

            Example response (for a Salesforce Account):
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
                {("where_" + key): value for key, value in where_clauses.items()}
            )

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["businessObjectsUrl"] + "?{}".format(encoded_query)
        request_header = self.request_form_header()

        logger.debug(
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
                type_name, external_system_id
            ),
        )

    # end method definition

    def get_business_objects_search(
        self,
        external_system_id: str,
        type_name: str,
    ) -> dict | None:
        """Get business object type information. Unfortunately this REST API is
           pretty much limited. It does not return Field names of external system properties
           and also does not return property groups defined.

        Args:
            external_system_id (str): External system Id (such as "TM6")
            type_name (str): Type name of the business object (such as "SAP Customer")
        Returns:
            dict: Business Object Search Form or None if the request fails.
        """

        query = {
            "ext_system_id": external_system_id,
            "bo_type": type_name,
        }

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["businessObjectsSearchUrl"] + "?{}".format(
            encoded_query
        )
        request_header = self.request_form_header()

        logger.debug(
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
                type_name, external_system_id
            ),
        )

    # end method definition

    def get_workspace_types(
        self, expand_workspace_info: bool = True, expand_templates: bool = True
    ) -> dict | None:
        """Get all workspace types configured in Extended ECM.

        Args:
            expand_workspace_info (bool, optional): Controls if the workspace info
                                                    is returned as well
            expand_templates (bool, optional): Controls if the list of workspace templates
                                               per workspace typ is returned as well
        Returns:
            dict: Workspace Types or None if the request fails.

            Example response:
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

        logger.debug("Get workspace types; calling -> %s", request_url)

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
        external_system_id: str = None,
        bo_type: str = None,
        bo_id: str = None,
        parent_id: int = None,
    ) -> dict | None:
        """Get the Workspace create form.

        Args:
            template_id (int): ID of the workspace template
            external_system_id (str, optional): Identifier of the external system (None if no external system)
            bo_type (str, optional): Business object type (None if no external system)
            bo_id (str, optional): Business object identifier / key (None if no external system)
            parent_id (int, optional): Parent ID of the workspaces. Needs only be specified in special
                                       cases where workspace location cannot be derived from workspace
                                       type definition, e.g. sub-workspace
        Returns:
            dict: Workspace Create Form data or None if the request fails.
        """

        request_url = self.config()[
            "businessworkspacecreateform"
        ] + "?template_id={}".format(template_id)
        # Is a parent ID specifified? Then we need to add it to the request URL
        if parent_id is not None:
            request_url += "&parent_id={}".format(parent_id)
        # Is this workspace connected to a business application / external system?
        if external_system_id and bo_type and bo_id:
            request_url += "&ext_system_id={}".format(external_system_id)
            request_url += "&bo_type={}".format(bo_type)
            request_url += "&bo_id={}".format(bo_id)
            logger.debug(
                "Include business object connection -> (%s, %s, %s) in workspace create form...",
                external_system_id,
                bo_type,
                bo_id,
            )
        request_header = self.request_form_header()

        logger.debug(
            "Get workspace create form for workspace template ID -> %s; calling -> %s",
            str(template_id),
            request_url,
        )

        if parent_id:
            failure_message = "Failed to get workspace create form for template -> {} and parent ID -> {}".format(
                template_id, parent_id
            )
        else:
            failure_message = "Failed to get workspace create form for template -> {} (no parent ID given)".format(
                template_id
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
            node_id (int): Node ID of the workspace to retrieve.
        Returns:
            dict: Workspace node information or None if no node with this ID is found.

            Example response:
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
        """

        request_url = self.config()["businessWorkspacesUrl"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.debug(
            "Get workspace with ID -> %s; calling -> %s", str(node_id), request_url
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
        self, type_name: str = "", type_id: int = None, expanded_view: bool = True
    ):
        """Get all workspace instances of a given type. This is a convenience
           wrapper method for get_workspace_by_type_and_name()

        Args:
            type_name (str, optional): Name of the workspace type
            type_id (int, optional): ID of the workspace_type
            expanded_view (bool, optional): If 'False' then just search in recently
                                            accessed business workspace for this name and type.
                                            If 'True' (this is the default) then search in all
                                            workspaces for this name and type.
        Returns:
            dict: Workspace information or None if the workspace is not found.
        """

        # Omitting the name lets it return all instances of the type:
        return self.get_workspace_by_type_and_name(
            type_name=type_name, type_id=type_id, name="", expanded_view=expanded_view
        )

    # end method definition

    def get_workspace_by_type_and_name(
        self,
        type_name: str = "",
        type_id: int = None,
        name: str = "",
        expanded_view: bool = True,
        page: int | None = None,
        limit: int | None = None,
        timeout: int = REQUEST_TIMEOUT,
    ) -> dict | None:
        """Lookup workspace based on workspace type and workspace name.

        Args:
            type_name (str, optional): name of the workspace type
            type_id (int, optional): ID of the workspace_type
            name (str, optional): Name of the workspace, if "" then deliver all instances
                                  of the given workspace type.
            expanded_view (bool, optional): If 'False' then just search in recently
                                            accessed business workspace for this name and type.
                                            If 'True' (this is the default) then search in all
                                            workspaces for this name and type.
            timeout (int, optional): timeout for the request in seconds
        Returns:
            dict: Workspace information or None if the workspace is not found.
        """

        if not type_name and not type_id:
            logger.error(
                "No workspace type specified - neither by type name nor type ID. Cannot lookup workspace(s)!"
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

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["businessWorkspacesUrl"] + "?{}".format(
            encoded_query
        )
        request_header = self.request_form_header()

        if name:
            logger.debug(
                "Get workspace with name -> '%s' and type -> '%s'; calling -> %s",
                name,
                type_name,
                request_url,
            )
            failure_message = (
                "Failed to get workspace with name -> '{}' and type -> '{}'".format(
                    name, type_name
                )
            )
        else:
            if type_name:
                logger.debug(
                    "Get all workspace instances of type -> '%s'; calling -> %s",
                    type_name,
                    request_url,
                )
                failure_message = (
                    "Failed to get all workspace instances of type -> '{}'".format(
                        type_name
                    )
                )
            else:
                logger.debug(
                    "Get all workspace instances with type ID -> %s; calling -> %s",
                    str(type_id),
                    request_url,
                )
                failure_message = (
                    "Failed to get all workspace instances with type ID -> {}".format(
                        type_id
                    )
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
        type_id: int = None,
    ) -> int | None:
        """Determine the folder in which the workspace instances of a given type reside.
           Either the type ID or the type name need to be provided. NOTE: workspace types
           may not always have a default location for all its instances. In such case
           parent_id may just be the folder of the first delivered workspace instance.

        Args:
            type_name (str, optional): Name of the workspace type. Defaults to "".
            type_id (int, optional): ID of the workspace type. Defaults to None.

        Returns:
            int | None: node ID of the parent folder
        """

        # it seems there's no other way to get the workspace location configured for a
        # workspace type other then getting an example workspace of this type and see what
        # the parent is. The REST API used for get_workspace_types() does not deliver this information :-(
        response = self.get_workspace_by_type_and_name(
            type_name=type_name, type_id=type_id, page=1, limit=1
        )
        parent_id = self.get_result_value(response=response, key="parent_id")

        return parent_id

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
            external_system_name (str): Name of the connection
            business_object_type (str): Type of the Business object, e.g. KNA1 for SAP customers
            business_object_id (str): ID of the business object in the external system
            return_workspace_metadata (bool, optional): Whether or not workspace metadata (categories) should be returned.
                                                        Default is False.
            show_error (bool, optional): Treat as error if node is not found. Default is False.
        Returns:
            dict: Workspace node information or None if no node with this ID is found.

            Example response:
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

        logger.debug(
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
                external_system_name, business_object_type, business_object_id
            ),
            failure_message="Failed to get workspace via external system -> '{}', Business Object Type -> '{}', and Business Object ID -> {}".format(
                external_system_name, business_object_type, business_object_id
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
    ):
        """Set reference of workspace to a business object in an external system

        Args:
            workspace_id (int): ID of the workspace
            external_system_id (str, optional): Identifier of the external system (None if no external system)
            bo_type (str, optional): Business object type (None if no external system)
            bo_id (str, optional): Business object identifier / key (None if no external system)
            show_error (bool, optional): Log an error if workspace cration fails. Otherwise log a warning.
        """

        request_url = (
            self.config()["businessWorkspacesUrl"]
            + "/"
            + str(workspace_id)
            + "/workspacereferences"
        )
        request_header = self.request_form_header()

        if not external_system_id or not bo_type or not bo_id:
            logger.error(
                "Cannot update workspace reference - required Business Object information is missing!"
            )
            return None

        logger.debug(
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
                workspace_id, external_system_id, bo_type, bo_id
            ),
            failure_message="Failed to update reference for workspace ID -> {} with business object connection -> ({}, {}, {})".format(
                workspace_id, external_system_id, bo_type, bo_id
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

        Args:
            workspace_template_id (int): ID of the workspace template
            workspace_name (str): Name of the workspace
            workspace_description (str): Description of the workspace
            workspace_type (int): Type ID of the workspace
            category_data (dict): Category and attributes
            external_system_id (str, optional): Identifier of the external system (None if no external system)
            bo_type (str, optional): Business object type (None if no external system)
            bo_id (str, optional): Business object identifier / key (None if no external system)
            parent_id (str, optional): Parent ID of the workspaces. Needs only be specified in special
                                       cases where workspace location cannot be derived from workspace
                                       type definition or if it is a sub-workspace.
            ibo_workspace_id (int, optional): Node ID of an existing workspace that is already connected to another
                                              external system. This allows for subsequent calls to coonect the workspace
                                              to multiple Business Objects (IBO = Identical Business Objects)
            external_create_date (str, optional) value of the source system in format 2024-06-24
            external_modify_date (str, optional) value of the source system in format 2024-06-24
            show_error (bool, optional): Log an error if workspace cration fails. Otherwise log a warning.
        Returns:
            dict: Workspace Create Form data or None if the request fails.
        """

        # Avoid linter warning W0102
        if category_data is None:
            category_data = {}

        create_workspace_post_data = {
            "template_id": str(workspace_template_id),
            "name": workspace_name,
            "description": workspace_description,
            "wksp_type_id": str(workspace_type),
            "type": str(848),
            "roles": category_data,
            "external_create_date": external_create_date,
            "external_modify_date": external_modify_date,
        }

        # Is this workspace connected to a business application / external system?
        if external_system_id and bo_type and bo_id:
            create_workspace_post_data["ext_system_id"] = external_system_id
            create_workspace_post_data["bo_type"] = bo_type
            create_workspace_post_data["bo_id"] = bo_id
            logger.debug(
                "Use business object connection -> (%s, %s, %s) for workspace -> '%s'",
                external_system_id,
                bo_type,
                bo_id,
                workspace_name,
            )
            if ibo_workspace_id:
                logger.debug(
                    "This is a subsequent call to create a cross-application workspace (IBO)"
                )
                create_workspace_post_data["ibo_workspace_id"] = ibo_workspace_id

        # If workspace creation location cannot be derived from the workspace type
        # there may be an optional parent parameter passed to this method. This can
        # also be the case if workspaces are nested into each other:
        if parent_id is not None:
            create_workspace_post_data["parent_id"] = parent_id
            logger.debug(
                "Use specified location -> %s for workspace -> '%s'",
                str(parent_id),
                workspace_name,
            )
        else:
            logger.debug(
                "Determine location of workspace -> '%s' via workspace type -> '%s'",
                workspace_name,
                str(workspace_type),
            )

        request_url = self.config()["businessWorkspacesUrl"]
        request_header = self.request_form_header()

        logger.debug(
            "Create workspace -> '%s' with type -> '%s' from template -> %s; calling -> %s",
            workspace_name,
            str(workspace_type),
            str(workspace_template_id),
            request_url,
        )

        # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
        # See https://developer.opentext.com/apis/14ba85a7-4693-48d3-8c93-9214c663edd2/4403207c-40f1-476a-b794-fdb563e37e1f/07229613-7ef4-4519-8b8a-47eaff639d42#operation/createBusinessWorkspace
        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(create_workspace_post_data)},
            timeout=None,
            warning_message="Failed to create workspace -> '{}' from template with ID -> {}".format(
                workspace_name, workspace_template_id
            ),
            failure_message="Failed to create workspace -> '{}' from template with ID -> {}".format(
                workspace_name, workspace_template_id
            ),
            show_error=show_error,
        )

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
        """Update an existing business workspace. This is a wrapper method to update
           a combination of workspace name / description, workspace reference, and workspace metadata

        Args:
            workspace_id (int): ID of the workspace
            workspace_name (str): New Name of the workspace
            workspace_description (str): New Description of the workspace
            category_data (dict): Category and attributes
            external_system_id (str, optional): Identifier of the external system (None if no external system)
            bo_type (str, optional): Business object type (None if no external system)
            bo_id (str, optional): Business object identifier / key (None if no external system)
            show_error (bool, optional): Log an error if workspace cration fails. Otherwise log a warning.
        Returns:
            dict: Response of the REST API call or None if the request fails.
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

        # Should we change the name and/or the description or the category data of this workspace?
        if workspace_name or workspace_description:
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
            workspace_id (int): ID of the workspace
            related_workspace_id (int): ID of the related workspace
            relationship_type (str, optional): "parent" or "child" - "child" is default if omitted
            show_error (bool, optional): Log an error if relationship cration fails.
                                         Otherwise log a warning.
        Returns:
            dict: Workspace Relationship data (json) or None if the request fails.
        """

        create_workspace_relationship_post_data = {
            "rel_bw_id": str(related_workspace_id),
            "rel_type": relationship_type,
        }

        request_url = self.config()[
            "businessWorkspacesUrl"
        ] + "/{}/relateditems".format(workspace_id)
        request_header = self.request_form_header()

        logger.debug(
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
                workspace_id, related_workspace_id
            ),
            failure_message="Failed to create workspace relationship between -> {} and -> {}".format(
                workspace_id, related_workspace_id
            ),
            show_error=show_error,
        )

    # end method definition

    def get_workspace_relationships(
        self,
        workspace_id: int,
        relationship_type: str | None = None,
        related_workspace_name: str | None = None,
        related_workspace_type_id: int | None = None,
    ) -> dict | None:
        """Get the Workspace relationships to other workspaces. Optionally, filter criterias can be provided
           such as the related workspace name (starts with) or the related workspace TYPE ids (one or multiple)

        Args:
            workspace_id (int): ID of the workspace template
            relationship_type (str): Either "parent" or "child" (or None = unspecified which is the default)
            related_workspace_name (str, optional): filter for a certain workspace name in the related items.
            related_workspace_type_id (int | None): ID of related workspace type (or list of IDs)
        Returns:
            dict: Workspace relationships or None if the request fails.
        """

        request_url = (
            self.config()["businessWorkspacesUrl"]
            + "/"
            + str(workspace_id)
            + "/relateditems"
        )

        query = {}

        if relationship_type:
            query["where_relationtype"] = relationship_type

        if related_workspace_name:
            query["where_name"] = related_workspace_name

        if related_workspace_type_id:
            query["where_workspace_type_id"] = related_workspace_type_id

        encoded_query = urllib.parse.urlencode(query, doseq=False)
        request_url += "?{}".format(encoded_query)

        request_header = self.request_form_header()

        logger.debug(
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
                workspace_id
            ),
        )

    # end method definition

    def get_workspace_roles(self, workspace_id: int) -> dict | None:
        """Get the Workspace roles.

        Args:
            workspace_id (int): ID of the workspace template or workspace
        Returns:
            dict: Workspace Roles data or None if the request fails.
        """

        request_url = (
            self.config()["businessWorkspacesUrl"] + "/" + str(workspace_id) + "/roles"
        )
        request_header = self.request_form_header()

        logger.debug(
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
                workspace_id
            ),
        )

    # end method definition

    def get_workspace_members(self, workspace_id: int, role_id: int) -> dict | None:
        """Get the Workspace members of a given role.

        Args:
            workspace_id (int): ID of the workspace template
            role_id (int): ID of the role
        Returns:
            dict: Workspace member data or None if the request fails.
        """

        request_url = self.config()[
            "businessWorkspacesUrl"
        ] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        logger.debug(
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
        self, workspace_id: int, role_id: int, member_id: int, show_warning: bool = True
    ) -> dict | None:
        """Add member to a workspace role. Check that the user/group is not yet a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            member_id (int): User ID or Group ID
            show_warning (bool, optional): If True logs a warning if member is already in role
        Returns:
            dict: Workspace Role Membership or None if the request fails.
        """

        logger.debug(
            "Check if user/group with ID -> %s is already in role with ID -> %s of workspace with ID -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
        )

        workspace_members = self.get_workspace_members(
            workspace_id=workspace_id, role_id=role_id
        )

        if self.exist_result_item(workspace_members, "id", member_id):
            if show_warning:
                logger.warning(
                    "User/group with ID -> %s is already a member of role with ID -> %s of workspace with ID -> %s",
                    str(member_id),
                    str(role_id),
                    str(workspace_id),
                )
            return workspace_members

        add_workspace_member_post_data = {"id": str(member_id)}

        request_url = self.config()[
            "businessWorkspacesUrl"
        ] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        logger.debug(
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
                member_id, role_id, workspace_id
            ),
        )

    # end method definition

    def remove_workspace_member(
        self, workspace_id: int, role_id: int, member_id: int, show_warning: bool = True
    ) -> dict | None:
        """Remove a member from a workspace role. Check that the user is currently a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            member_id (int): User or Group Id
            show_warning (bool, optional): If True logs a warning if member is not in role
        Returns:
            dict: Workspace Role Membership or None if the request fails.
        """

        logger.debug(
            "Check if user/group with ID -> %s is in role with ID -> %s of workspace with ID -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
        )

        workspace_members = self.get_workspace_members(
            workspace_id=workspace_id, role_id=role_id
        )

        if not self.exist_result_item(workspace_members, "id", member_id):
            if show_warning:
                logger.warning(
                    "User/group with ID -> %s is not a member of role with ID -> %s of workspace with ID -> %s",
                    str(member_id),
                    str(role_id),
                    str(workspace_id),
                )
            return None

        request_url = self.config()[
            "businessWorkspacesUrl"
        ] + "/{}/roles/{}/members/{}".format(workspace_id, role_id, member_id)
        request_header = self.request_form_header()

        logger.debug(
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
                member_id, role_id, workspace_id
            ),
        )

    # end method definition

    def remove_workspace_members(
        self, workspace_id: int, role_id: int, show_warning: bool = True
    ) -> bool:
        """Remove all members from a workspace role. Check that the user is currently a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            show_warning (bool, optional): If True logs a warning if member is not in role
        Returns:
            dict: Workspace Role Membership or None if the request fails.
        """

        workspace_members = self.get_workspace_members(
            workspace_id=workspace_id, role_id=role_id
        )

        # Get the list of existing workspace_member ids:
        workspace_member_ids = self.get_result_values(workspace_members, "id")
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
        self, workspace_id: int, role_id: int, permissions: list, apply_to: int = 2
    ) -> dict | None:
        """Update permissions of a workspace role
        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            permissions (list): List of permissions - potential elements:
                                "see"
                                "see_contents"
                                "modify"
                                "edit_attributes"
                                "add_items"
                                "reserve"
                                "add_major_version"
                                "delete_versions"
                                "delete"
                                "edit_permissions"
            apply_to (int, optional):  Items to apply the permission change. Possible values:
                                       0 = this item
                                       1 = sub-items
                                       2 = This item and sub-items (default)
                                       3 = This item and immediate sub-items
        Returns:
            dict: Workspace Role Membership or None if the request fails.
        """

        request_url = self.config()["businessWorkspacesUrl"] + "/{}/roles/{}".format(
            workspace_id, role_id
        )

        request_header = self.request_form_header()

        logger.debug(
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
                role_id, workspace_id
            ),
        )

    # end method definition

    def update_workspace_icon(
        self, workspace_id: int, file_path: str, file_mimetype: str = "image/*"
    ) -> dict | None:
        """Update a workspace with a with a new icon (which is uploaded).

        Args:
            workspace_id (int): ID of the workspace
            file_path (str): path + filename of icon file
            file_mimetype (str, optional): mimetype of the image
        Returns:
            dict: Node information or None if REST call fails.
        """

        if not os.path.exists(file_path):
            logger.error("Workspace icon file does not exist -> %s", file_path)
            return None

        update_workspace_icon_post_body = {
            "file_content_type": file_mimetype,
            "file_filename": os.path.basename(file_path),
        }

        upload_workspace_icon_post_files = [
            (
                "file",
                (
                    f"{os.path.basename(file_path)}",
                    open(file_path, "rb"),
                    file_mimetype,
                ),
            )
        ]

        request_url = (
            self.config()["businessWorkspacesUrl"] + "/" + str(workspace_id) + "/icons"
        )

        request_header = self.cookie()

        logger.debug(
            "Update icon for workspace ID -> %s with icon file -> %s; calling -> %s",
            str(workspace_id),
            file_path,
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=update_workspace_icon_post_body,
            files=upload_workspace_icon_post_files,
            timeout=None,
            failure_message="Failed to update workspace ID -> {} with new icon -> '{}'".format(
                workspace_id, file_path
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

            Example response:
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
        """

        if not names:
            logger.error("Missing Unique Names!")
            return None

        # Add query parameters (these are NOT passed via JSon body!)
        query = {"where_names": "{" + ", ".join(names) + "}"}
        if subtype:
            query["where_subtype"] = subtype

        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["uniqueNamesUrl"] + "?{}".format(encoded_query)
        request_header = self.request_form_header()

        if subtype:
            logger.debug(
                "Get unique names -> %s of subtype -> %s; calling -> %s",
                str(names),
                str(subtype),
                request_url,
            )
            warning_message = (
                "Failed to get unique names -> {} of subtype -> {}".format(
                    names, subtype
                )
            )
        else:
            logger.debug(
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
        item_type: str,
        item_name: str,
        item_description: str = "",
        url: str = "",
        original_id: int = 0,
        show_error: bool = True,
    ) -> dict | None:
        """Create an Extended ECM item. This REST call is somewhat limited. It cannot set featured item or hidden item.
           It does also not accept owner group information.

        Args:
            parent_id (int): Node ID of the parent
            item_type (str): Type of the item (e.g. 0 = folder, 140 = URL)
            item_name (str): Name of the item
            item_description (str, optional): Description of the item
            url (str, optional): Address of the URL item (if it is an URL item type)
            original_id (int, optional): Node ID of the original (referenced) item.
                                         Required if a shortcut item is created
            show_error (bool, optional): Log an error if item cration fails. Otherwise log a warning.
        Returns:
            dict: Request response of the create item call or None if the REST call has failed.
        """

        create_item_post_data = {
            "parent_id": parent_id,
            "type": item_type,
            "name": item_name,
            "description": item_description,
        }

        if url:
            create_item_post_data["url"] = url
        if original_id > 0:
            create_item_post_data["original_id"] = original_id

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        logger.debug(
            "Create item -> '%s' (type -> %s) under parent with ID -> %s; calling -> %s",
            item_name,
            item_type,
            str(parent_id),
            request_url,
        )

        # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data={"body": json.dumps(create_item_post_data)},
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
        category_data: dict | None = None,
        external_modify_date: str | None = None,
        external_create_date: str | None = None,
    ) -> dict | None:
        """Update an Extended ECM item (parent, name, description, metadata). Changing the parent ID is
           a move operation. If parent ID = 0 or None the item will not be moved.

        Args:
            node_id (int): ID of the node
            parent_id (int | None, optional): node ID of the new parent (in case of a move operation)
            item_name (str | None, optional): new name of the item
            item_description (str | None, optional): new description of the item
            category_data (dict | None): new category and attributes values
            external_create_date (str, optional) value of the source system in format 2024-06-24
            external_modify_date (str, optional) value of the source system in format 2024-06-24
        Returns:
            dict: Response of the update item request or None if the REST call has failed.
        """

        update_item_put_data = {}

        if item_name:
            # this is a rename operation
            update_item_put_data["name"] = item_name
        if item_description:
            # this is a change description operation
            update_item_put_data["description"] = item_description
        if parent_id:
            # this is a move operation
            update_item_put_data["parent_id"] = parent_id

        # Set external dates if provided:
        if external_create_date:
            update_item_put_data["external_create_date"] = external_create_date
        if external_modify_date:
            update_item_put_data["external_modify_date"] = external_modify_date

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.debug(
            "Update item -> '%s' (%s) with data -> %s; calling -> %s",
            item_name,
            node_id,
            str(update_item_put_data),
            request_url,
        )

        response = self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data={"body": json.dumps(update_item_put_data)},
            timeout=None,
            failure_message="Failed to update item -> '{}' ({})".format(
                item_name, node_id
            ),
        )

        if response and category_data:
            for category in category_data:
                response = self.set_category_values(
                    node_id=node_id,
                    category_id=category,
                    category_data=category_data[category],
                )

        return response

    # end method definition

    def get_document_templates(self, parent_id: int):
        """Get all document templates for a given target location.

        Args:
            parent_id (int): node ID of target location (e.g. a folder)

        Returns:
            dict: response of the REST call (converted to a Python dictionary)

            Example response:
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
        """

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(parent_id)
            + "/doctemplates?subtypes={144}&sidepanel_subtypes={144}"
        )
        request_header = self.request_form_header()

        logger.debug(
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
                parent_id
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
        doc_desciption: str = "",
    ) -> dict | None:
        """Create a document based on a document template

        Args:
            template_id (int): node ID of the document template
            parent_id (int): node ID of the target location (parent)
            classification_id (int): node ID of the classification
            category_data (dict): metadata / category data
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
            doc_name (str): Name of the item to create.
            doc_description (str, optional): Description of the item to create.
        """

        create_document_post_data = {
            "template_id": template_id,
            "parent_id": parent_id,
            "name": doc_name,
            "description": doc_desciption,
            "type": 144,
            "roles": {
                "categories": category_data,
                "classifications": {"create_id": [classification_id], "id": []},
            },
        }

        request_url = self.config()["doctemplatesUrl"]
        request_header = self.request_form_header()

        logger.debug(
            "Create document -> '%s' from template with ID -> %s in target location with ID -> %s with classification ID -> %s; calling -> %s",
            doc_name,
            str(template_id),
            str(parent_id),
            str(classification_id),
            request_url,
        )

        # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            # this seems to only work with a "body" tag and is different form the documentation
            # on developer.opentext.com
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
        """Create an Extended ECM Wiki.

        Args:
            parent_id (int): Node ID of the parent
            name (str): Name of the wiki item
            description (str, optional): Description of the wiki item
            show_error (bool, optional): Log an error if item cration fails. Otherwise log a warning.
        Returns:
            dict: Request response of the create item call or None if the REST call has failed.
        """

        create_wiki_post_data = {
            "parent_id": parent_id,
            "type": 5573,
            "name": name,
            "description": description,
        }

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        logger.debug(
            "Create wiki -> '%s' under parent with ID -> %s; calling -> %s",
            name,
            str(parent_id),
            request_url,
        )

        # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
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
            wiki_id (int): Node ID of the wiki
            name (str): Name of the wiki page
            content (str, optional): Content of the page (typically HTML)
            show_error (bool, optional): Log an error if item cration fails. Otherwise log a warning.
        Returns:
            dict: Request response of the create wiki page call or None if the REST call has failed.
        """

        create_wiki_page_post_data = {
            "parent_id": wiki_id,
            "type": 5574,
            "name": name,
            "description": description,
            "TextField": content,
        }

        request_url = self.config()["nodesUrl"]
        # Header needs to just include the cookie:
        request_header = self.cookie()

        logger.debug(
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
        """Get parameters of a Web Report in Extended ECM. These are defined on the Web Report node
            (Properties --> Parameters)

        Args:
            nickname (str): Nickname of the Web Reports node.
        Returns:
            Response: List of Web Report parameters. Each list item is a dict describing the parameter.
            Structure of the list items:
            {
                "type": "string",
                "parm_name": "string",
                "display_text": "string",
                "prompt": true,
                "prompt_order": 0,
                "default_value": null,
                "description": "string",
                "mandatory": true
            }
            None if the REST call has failed.
        """

        request_url = self.config()["webReportsUrl"] + "/" + nickname + "/parameters"
        request_header = self.request_form_header()

        logger.debug(
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
                nickname
            ),
        )

        if response and "data" in response:
            return response["data"]

        return None

    # end method definition

    def run_web_report(
        self, nickname: str, web_report_parameters: dict | None = None
    ) -> dict | None:
        """Run a Web Report that is identified by its nick name.

        Args:
            nickname (str): nickname of the Web Reports node.
            web_report_parameters (dict): Parameters of the Web Report (names + value pairs)
        Returns:
            dict: Response of the run Web Report request or None if the Web Report execution has failed.
        """

        # Avoid linter warning W0102:
        if web_report_parameters is None:
            web_report_parameters = {}

        request_url = self.config()["webReportsUrl"] + "/" + nickname
        request_header = self.request_form_header()

        logger.debug(
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
                nickname
            ),
        )

    # end method definition

    def install_cs_application(self, application_name: str) -> dict | None:
        """Install a CS Application (based on WebReports)

        Args:
            application_name (str): name of the application (e.g. OTPOReports, OTRMReports, OTRMSecReports)
        Returns:
            dict: Response or None if the installation of the CS Application has failed.
        """

        install_cs_application_post_data = {"appName": application_name}

        request_url = self.config()["csApplicationsUrl"] + "/install"
        request_header = self.request_form_header()

        logger.debug(
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
                application_name
            ),
        )

    # end method definition

    def assign_item_to_user_group(
        self, node_id: int, subject: str, instruction: str, assignees: list
    ) -> dict | None:
        """Assign an Extended ECM item to users and groups. This is a function used by
           Extended ECM for Government.

        Args:
            node_id (int): node ID of the Extended ECM item (e.g. a workspace or a document)
            subject (str): title / subject of the assignment
            instructions (str): more detailed description or instructions for the assignment
            assignees (list): list of IDs of users or groups
        Returns:
            dict: Response of the request or None if the assignment has failed.
        """

        assignment_post_data = {
            "subject": subject,
            "instruction": instruction,
            "assignees": assignees,
        }

        request_url = (
            self.config()["nodesUrlv2"] + "/" + str(node_id) + "/xgovassignments"
        )

        request_header = self.request_form_header()

        logger.debug(
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
                node_id, assignees, subject
            ),
        )

    # end method definition

    def convert_permission_string_to_permission_value(self, permissions: list) -> int:
        """Converts a list of permission names (strongs) to a bit-mask.

        Args:
            permissions (list): List of permission names - see conversion variable below.
        Returns:
            int: bit-encoded permission value
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
                logger.error("Illegal permission value -> %s", str(permission))
                return 0
            permission_value += conversion[permission]

        return permission_value

    # end method definition

    def convert_permission_value_to_permission_string(
        self, permission_value: int
    ) -> list:
        """Converts a bit-encoded permission value to a list of permission names (strings).

        Args:
            permission_value (int): bit-encoded permission value
        Returns:
            list: list of permission names
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
        """Assign permissions for Extended ECM item to a user or group.

        Args:
            node_id (int): node ID of the Extended ECM item
            assignee_type (str): this can be either "owner", "group" (for owner group),
                                    "public", or "custom" (assigned access)
            assignee (int): ID of user or group ("right ID"). If 0 and assigneeType
                                is "owner" or "group" then it is assumed that the owner and
                                owner group should not be changed.
            permissions (list): list of permissions - potential elements:
                                "see"
                                "see_contents"
                                "modify"
                                "edit_attributes"
                                "add_items"
                                "reserve"
                                "add_major_version"
                                "delete_versions"
                                "delete"
                                "edit_permissions"
            apply_to (int, optional): elements to apply permissions to - potential values:
                                 0 = this item (default)
                                 1 = sub-items
                                 2 = This item and sub-items
                                 3 = This item and immediate sub-items
        Returns:
            dict: Response of the request or None if the assignment of permissions has failed.
        """

        if not assignee_type or not assignee_type in [
            "owner",
            "group",
            "public",
            "custom",
        ]:
            logger.error(
                "Missing or wrong assignee type. Needs to be owner, group, public or custom!"
            )
            return None
        if assignee_type == "custom" and not assignee:
            logger.error("Missing permission assignee!")
            return None

        permission_post_data = {
            "permissions": permissions,
            "apply_to": apply_to,
        }

        # Assignees can be specified for owner and group and must be specified for custom:
        #
        if assignee:
            permission_post_data["right_id"] = assignee

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/permissions/"
            + assignee_type
        )

        request_header = self.request_form_header()

        logger.debug(
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
                    permissions, node_id
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
                    permissions, node_id
                ),
            )

    # end method definition

    def get_node_categories(self, node_id: int, metadata: bool = True) -> dict | None:
        """Get categories assigned to a node.

        Args:
            node_id (int): ID of the node to get the categories for.
            metadata (bool, optional): expand the attribute definitions of the category. Default is True.
        Returns:
            dict | None: category response or None if the call to the REST API fails.

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

        logger.debug(
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
                str(node_id)
            ),
        )

    # end method definition

    def get_node_category(
        self, node_id: int, category_id: int, metadata: bool = True
    ) -> dict | None:
        """Get a specific category assigned to a node.

        Args:
            node_id (int): ID of the node to get the categories for.
            category_id (int): ID of the category definition ID (in category volume)
            metadata (bool, optional): expand the attribute definitions of the category. Default is True
        Returns:
            dict: category response or None if the call to the REST API fails.
        """

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/categories/"
            + str(category_id)
        )
        if metadata:
            request_url += "?metadata"
        request_header = self.request_form_header()

        logger.debug(
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
                category_id, node_id
            ),
        )

    # end method definition

    def get_node_category_ids(self, node_id: int) -> list:
        """Get list of all category definition IDs that are assign to the node.

        Args:
            node_id (int): ID of the node to get the categories for.
        Returns:
            list: list of category IDs (all categories assigned to the node)
        """

        categories = self.get_node_categories(node_id)
        if not categories or not categories["results"]:
            return None

        category_id_list = []

        for category in categories["results"]:
            category_id_list += [
                int(i) for i in category["metadata_order"]["categories"]
            ]

        return category_id_list

    # end method definition

    def get_node_category_names(self, node_id: int) -> list | None:
        """Get list of all category names that are assign to the node.

        Args:
            node_id (int): ID of the node to get the categories for.
        Returns:
            list: list of category names (all categories assigned to the node)
        """

        categories = self.get_node_categories(node_id=node_id, metadata=True)
        if not categories or not categories["results"]:
            return None

        # List comprehension to extract category names safely
        return [
            next(iter(category["metadata"]["categories"].values()), {}).get("name")
            for category in categories["results"]
        ]

    # end method definition

    def get_node_category_definition(
        self,
        node_id: int,
        category_name: str,
    ) -> tuple[int, dict]:
        """Get category definition (category id and attribute names, IDs and types).
           This is a convenience method that wraps the the complex return value
           of get_node_categories() in an easier to parse structure.

        Args:
            node_id (int): node to read the category definition from
                           (e.g. a workspace template or a document template or a target folder)
                           This should NOT be the category definition object!
            category_name (str): name of the category
        Returns:
            int: category ID
            dict: dict keys are the attribute names. dict values are sub-dictionaries with the id and type of the attribute.
                  For set attributes the key is constructed as <set name>:<attribute name>.
                  Set attributes also incluide an additional value "set_id".

            Example response:
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
        """

        attribute_definitions = {}

        response = self.get_node_categories(node_id)
        if response and response["results"]:
            for categories in response["results"]:
                # get all metadata IDs
                keys = categories["metadata"]["categories"].keys()
                # There's one without an underscore - that's the ID of the category itself:
                cat_id = next((key for key in keys if "_" not in key), -1)
                cat_name = categories["metadata"]["categories"][cat_id]["name"]
                # Check we have the category we are looking for:
                if cat_name != category_name:
                    # Wrong category - not matching - go to next
                    continue
                for att_id in categories["metadata"]["categories"]:
                    if not "_" in att_id:
                        # We skip the element representing the category itself:
                        continue
                    att_name = categories["metadata"]["categories"][att_id]["name"]
                    att_persona = categories["metadata"]["categories"][att_id][
                        "persona"
                    ]
                    # Persona can be either "set" or "categoryattribute".
                    # If the persona is "set" we store the set information:
                    if att_persona == "set":
                        # We save the set name and ID for the attributes that follow:
                        set_name = att_name
                        set_id = att_id
                    # Attribute types can be "String", ...
                    # For the set attribute itself the type_name = "Assoc"
                    att_type = categories["metadata"]["categories"][att_id]["type_name"]
                    if "_x_" in att_id:  # this is not true for the set attribute itself
                        # set_name and set_id are still set to the name of the proceeding
                        # for-loop iteration!
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

                return cat_id, attribute_definitions
        return -1, {}

    # end method definition

    def assign_category(
        self,
        node_id: int,
        category_id: list,
        inheritance: bool = False,
        apply_to_sub_items: bool = False,
        apply_action: str = "add_upgrade",
        add_version: bool = False,
        clear_existing_categories: bool = False,
    ) -> bool:
        """Assign a category to a node. Optionally turn on inheritance and apply
           category to sub-items (if node_id is a container / folder / workspace).
           If the category is already assigned to the node this method will
           throw an error.

        Args:
            node_id (int): node ID to apply the category to
            category_id (list): ID of the category definition object
            inheritance (bool): turn on inheritance for the category
                                (this makes only sense if the node is a container like a folder or workspace)
            apply_to_sub_items (bool, optional): if True the category is applied to
                                                    the item and all its sub-items
                                                    if False the category is only applied
                                                    to the item
            apply_action (str, optional): supported values are "add", "add_upgrade", "upgrade", "replace", "delete", "none", None
            add_version (bool, optional): if a document version should be added for the category change (default = False)
            clear_existing_categories (bool, optional): whether or not existing (other) categories should be removed (default = False)
        Returns:
            bool: True = success, False = error
        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories"
        request_header = self.request_form_header()

        #
        # 1. Assign Category to Node if not yet assigned:
        #

        existing_category_ids = self.get_node_category_ids(node_id)
        if not category_id in existing_category_ids:
            logger.debug(
                "Category with ID -> %s is not yet assigned to node ID -> %s. Assigning it now...",
                str(category_id),
                str(node_id),
            )
            category_post_data = {
                "category_id": category_id,
            }

            logger.debug(
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
                    category_id, node_id
                ),
                parse_request_response=False,
            )

            if not response or not response.ok:
                return False

        #
        # 2. Set Inheritance
        #

        response = self.set_category_inheritance(
            node_id=node_id, category_id=category_id, enable=inheritance
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
                    category_id, node_id
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
    ) -> str | list | None:
        """Lookup the value of an attribute if category name, set name and attribute name
           are known.

        Args:
            node_id (int): ID of the node the category is assigned to.
            category_name (str): Name of the category.
            attribute_name (str): Name of the attribute.
            set_name (str | None, optional): Name of the set. Defaults to None.
            set_row (int, optional): Index of the row (first row = 1!). Defaults to 1.

        Returns:
            str | list | None: The value of the attribute. If it is a multi-value attribute a list will be returned.
        """

        (_, cat_definitions) = self.get_node_category_definition(node_id, category_name)
        if not cat_definitions:
            logger.warning("No categories are assigned to node -> %s", str(node_id))
            return None

        if set_name:
            lookup = set_name + ":" + attribute_name
        else:
            lookup = attribute_name

        if not lookup in cat_definitions:
            logger.error("Cannot find attribute -> '%s' in category -> '%s'")

        att_def = cat_definitions[lookup]
        att_id = att_def["id"]
        if "_x_" in att_id:
            att_id = att_id.replace("_x_", "_" + str(set_row) + "_")

        value = None

        response = self.get_node_categories(node_id=node_id, metadata=False)
        categories = response["results"]
        for category in categories:
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
        """Lookup the value of an attribute if category ID, set ID and attribute ID
           are known. If you only have the names use get_category_value_by_name()

        Args:
            node_id (int): Node ID the category is assigned to
            category_id (int): ID of the category
            attribute_id (int): ID of the attribute (the pure ID without underscores)
            set_id (int, optional): ID of the set. Defaults to None.
            set_row (int, optional): Index of the row (first row = 1!). Defaults to 1.

        Returns:
            str | list | None: The value of the attribute. If it is a multi-value attribute a list will be returned.
        """

        if set_id and set_row:
            att_id = (
                str(category_id)
                + "_"
                + str(set_id)
                + "_"
                + str(set_row)
                + "_"
                + str(attribute_id)
            )
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
        value,
        category_id: int,
        attribute_id: int,
        set_id: int = 0,
        set_row: int = 1,
    ) -> dict | None:
        """Set a value to a specific attribute in a category. Categories and have sets (groupings), multi-line sets (matrix),
           and multi-value attributes (list of values). This method supports all variants.

        Args:
            node_id (int): ID of the node
            value (multi-typed): value to be set - can be string or list of strings (for multi-value attributes)
            category_id (int):ID of the category object
            attribute_id (int): ID of the attribute, this should not include the category ID nor an underscore but the plain attribute ID like '10'
            set_id (int, optional): ID of the set. Defaults to 0.
            set_row (int, optional): Row of . Defaults to 1.

        Returns:
            dict: REST API response or None if the call fails
        """

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/categories/"
            + str(category_id)
        )
        request_header = self.request_form_header()

        if set_id:
            logger.debug(
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
            logger.debug(
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
            failure_message = "Failed to set value -> '{}' for category with ID -> {}, attribute ID -> {} on node ID -> {}".format(
                value,
                category_id,
                attribute_id,
                node_id,
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
    ) -> dict | None:
        """Set values of a category. Categories and have sets (groupings), multi-line sets (matrix),
           and multi-value attributes (list of values). This method supports all variants.

        Args:
            node_id (int): ID of the node
            value (multi-typed): value to be set - can be string or list of strings (for multi-value attributes)
            category_id (int):ID of the category object
            category_data (dict): dictionary with category attributes and values

        Returns:
            dict: REST API response or None if the call fails
        """

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/categories/"
            + str(category_id)
        )
        request_header = self.request_form_header()

        category_put_data = {"category_id": category_id}
        category_put_data.update(category_data)

        logger.debug(
            "Set values -> %s for category ID -> %s on node -> %s...",
            category_data,
            category_id,
            node_id,
        )

        return self.do_request(
            url=request_url,
            method="PUT",
            headers=request_header,
            data=category_put_data,
            timeout=None,
            failure_message="Failed to set values -> '{}' for category with ID -> {}, on node ID -> {}".format(
                category_data, category_id, node_id
            ),
        )

    # end method definition

    def set_category_inheritance(
        self, node_id: int, category_id: int, enable: bool = True
    ) -> dict | None:
        """Set if we want a container item (e.g. a folder or workspace) to inherit
           categories to sub-items.

        Args:
            node_id (int): Node ID of the container item.
            category_id (int): Node ID of the category item.
            enable (bool): Whether the inheritance should be enabled (True) or disabled (False)

        Returns:
            dict | None: Response of the request or None in case of an error.
        """

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/categories/"
            + str(category_id)
            + "/inheritance"
        )
        request_header = self.request_form_header()

        if enable:
            logger.debug(
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
                    node_id, category_id
                ),
            )
        else:
            logger.debug(
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
                    node_id, category_id
                ),
            )

    # end method definition

    def assign_classification(
        self, node_id: int, classifications: list, apply_to_sub_items: bool = False
    ) -> dict | None:
        """Assign one or multiple classifications to an Extended ECM item

        Args:
            node_id (int): node ID of the Extended ECM item
            classifications (list): list of classification item IDs
            apply_to_sub_items (bool, optional): if True the classification is applied to
                                                    the item and all its sub-items
                                                    if False the classification is only applied
                                                    to the item
        Returns:
            dict: Response of the request or None if the assignment of the classification has failed.
        """

        # the REST API expects a list of dict elements with "id" and the actual IDs
        classification_list = []
        for classification in classifications:
            classification_list.append({"id": classification})

        classification_post_data = {
            "class_id": classification_list,
            "apply_to_sub_items": apply_to_sub_items,
        }

        request_url = (
            self.config()["nodesUrl"] + "/" + str(node_id) + "/classifications"
        )

        request_header = self.request_form_header()

        logger.debug(
            "Assign classifications with IDs -> %s to item with ID -> %s; calling -> %s",
            str(classifications),
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=classification_post_data,
            timeout=None,
            failure_message="Failed to assign classifications with IDs -> {} to item with ID -> {}".format(
                classifications, node_id
            ),
        )

    # end method definition

    def assign_rm_classification(
        self, node_id: int, rm_classification: int, apply_to_sub_items: bool = False
    ) -> dict | None:
        """Assign a RM classification to an Extended ECM item
        Args:
            node_id (int): node ID of the Extended ECM item
            rm_classification (int): Records Management classification ID
            apply_to_sub_items (bool, optional): if True the RM classification is applied to
                                                    the item and all its sub-items
                                                    if False the RM classification is only applied
                                                    to the item
        Returns:
            dict: Response of the request or None if the assignment of the RM classification has failed.
        """

        rm_classification_post_data = {
            "class_id": rm_classification,
            "apply_to_sub_items": apply_to_sub_items,
        }

        request_url = (
            self.config()["nodesUrl"] + "/" + str(node_id) + "/rmclassifications"
        )

        request_header = self.request_form_header()

        logger.debug(
            "Assign RM classifications with ID -> %s to item with ID -> %s; calling -> %s",
            str(rm_classification),
            str(node_id),
            request_url,
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=rm_classification_post_data,
            timeout=None,
            failure_message="Failed to assign RM classifications with ID -> {} to item with ID -> {}".format(
                rm_classification, node_id
            ),
        )

    # end method definition

    def register_workspace_template(self, node_id: int) -> dict | None:
        """Register a workspace template as project template for Extended ECM for Engineering

        Args:
            node_id (int): node ID of the Extended ECM workspace template
        Returns:
            dict: Response of request or None if the registration of the workspace template has failed.
        """

        registration_post_data = {"ids": "{{ {} }}".format(node_id)}

        request_url = self.config()["xEngProjectTemplateUrl"]

        request_header = self.request_form_header()

        logger.debug(
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
                node_id
            ),
        )

    # end method definition

    def get_records_management_rsis(self, limit: int = 100) -> list | None:
        """Get all Records management RSIs togther with their RSI Schedules.

        Args:
            limit (int, optional): max elements to return (default = 100)
        Returns:
            list: list of Records Management RSIs or None if the request fails.
            Each RSI list element is a dict with this structure:
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
            }
        """

        request_url = self.config()["rsisUrl"] + "?limit=" + str(limit)
        request_header = self.request_form_header()

        logger.debug("Get list of Records Management RSIs; calling -> %s", request_url)

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
        """Get Records Management Codes. These are the most basic data types of
           the Records Management configuration and required to create RSIs and
           other higher-level Records Management configurations

        Args:
            None
        Returns:
            dict: RM codes or None if the request fails.
        """

        request_url = self.config()["recordsManagementUrlv2"] + "/rmcodes"
        request_header = self.request_form_header()

        logger.debug("Get list of Records Management codes; calling -> %s", request_url)

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
        """Update Records Management Codes. These are the most basic data types of
           the Records Management configuration and required to create RSIs and
           other higher-level Records Management configurations
           THIS METHOD IS CURRENTLY NOT WORKING

        Args:
            rm_codes (dict): Codes to be updated
        Returns:
            dict: RSI data or None if the request fails.
        """

        update_rm_codes_post_data = {}

        request_url = self.config()["recordsManagementUrl"] + "/rmcodes"
        request_header = self.request_form_header()

        logger.debug(
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
                rm_codes
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
            name (str): name of the RSI
            status (str): status of the RSI
            status_date (str): statusDate of the RSI YYYY-MM-DDTHH:mm:ss
            description (str): description of the RSI
            subject (str): status of the RSI
            title (str): status of the RSI
            dispcontrol (bool): status of the RSI
        Returns:
            dict: RSI data or None if the request fails.
        """

        if status_date == "":
            now = datetime.now()
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

        logger.debug(
            "Create Records Management RSI -> %s; calling -> %s", name, request_url
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_rsi_post_data,
            timeout=None,
            failure_message="Failed to create Records Management RSI -> '{}'".format(
                name
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
            rsi_id (int): ID of an existing RSI the schedule should be created for
            stage (str): retention stage - this is the key parameter to define multiple stages (stages are basically schedules)
            event_type (int): 1 Calculated Date, 2 Calendar Calculation, 3 Event Based, 4 Fixed Date, 5 Permanent
            object_type (str): either "LIV" - Classified Objects (default) or "LRM" - RM Classifications
            rule_code (str, optional): rule code - this value must be defined upfront
            rule_comment (str, optional): comment for the rule
            date_to_use (int, optional): 91 Create Date, 92 Reserved Data, 93 Modification Date, 94 Status Date, 95 Records Date
            retention_years (int, optional): years to wait before disposition
            retention_months (int, optional): month to wait before disposition
            retention_days (int, optional): days to wait before disposition
            category_id (int, optional): ID of the category
            attribute_id (int, optional): ID of the category attribute
            year_end_month (int, optional): month the year ends (default = 12)
            year_end_day (int, optional): day the year ends (default = 31)
            retention_intervals (int, optional): retention intervals
            fixed_retention (bool, optional): fixedRetention
            maximum_retention (bool,optional): maximumRetention
            fixed_date(str, optional): fixed date format : YYYY-MM-DDTHH:mm:ss
            event_condition (str, optional): eventCondition
            disposition (str, optional): disposition
            action_code (int, optional): 0 None, 1 Change Status, 7 Close, 8 Finalize Record, 9 Mark Official, 10 Export, 11 Update Storage Provider, 12 Delete Electronic Format, 15 Purge Versions, 16 Make Rendition, 32 Destroy
            description (str, optional): description
            new_status (str, optional): new status
            min_num_versions_to_keep (int, optional): minimum document versions to keep, . Default is 1.
            purge_superseded (bool, optional): purge superseded. Default is False.
            purge_majors (bool, optional): purge majors. Default is False.
            mark_official_rendition (bool, optional): mark official rendition. Default is False.
        Returns:
            dict: RSI Schedule data or None if the request fails.
        """

        if fixedDate == "":
            now = datetime.now()
            fixedDate = now.strftime("%Y-%m-%dT%H:%M:%S")

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

        logger.debug(
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
                stage, rsi_id
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
            hold_type (str): type of the Hold
            name (str): name of the RSI
            comment (str): comment
            alternate_id (str, optional): alternate hold ID
            parent_id (int, optional): ID of the parent node. If parent_id is 0 the item will be created right under "Hold Management" (top level item)
            date_applied (str, optional): create date of the Hold in this format: YYYY-MM-DDTHH:mm:ss
            date_to_remove (str, optional): suspend date of the Hold in this format: YYYY-MM-DDTHH:mm:ss
        Returns:
            dict: Hold data or None if the request fails. The dict structure is this: {'holdID': <ID>}
        """

        if date_applied == "":
            now = datetime.now()
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

        logger.debug(
            "Create Records Management Hold -> %s; calling -> %s", name, request_url
        )

        return self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=create_hold_post_data,
            timeout=None,
            failure_message="Failed to create Records Management Hold -> '{}'".format(
                name
            ),
        )

    # end method definition

    def get_records_management_holds(self) -> dict | None:
        """Get a list of all Records Management Holds in the system. Even though there are folders
        in the holds management area in RM these are not real folders - they cannot be retrieved
        with get_node_by_parent_and_name() thus we need this method to get them all.

        Args:
            None
        Returns:
            dict: Response with list of holds:
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
        """

        request_url = self.config()["holdsUrlv2"]

        request_header = self.request_form_header()

        logger.debug("Get list of Records Management Holds; calling -> %s", request_url)

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get list of Records Management Holds",
        )

    # end method definition

    def import_records_management_settings(self, file_path: str) -> bool:
        """Import Records Management settings from a file that is uploaded from the python pod

        Args:
            file_path (str): path + filename of config file in Python container filesystem
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["recordsManagementUrl"] + "/importSettings"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
            "Importing Records Management Settings from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settings_post_file = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            files=settings_post_file,
            timeout=None,
            failure_message="Failed to import Records Management Settings from file -> '{}'".format(
                file_path
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            return True

        return False

    # end method definition

    def import_records_management_codes(
        self, file_path: str, update_existing_codes: bool = True
    ) -> bool:
        """Import RM Codes from a file that is uploaded from the python pod

        Args:
            file_path (str): path + filename of settings file in Python container filesystem
            update_existing_codes (bool): Flag that controls whether existing table maintenance codes
                                          should be updated.
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["recordsManagementUrl"] + "/importCodes"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
            "Importing Records Management Codes from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        settings_post_data = {"updateExistingCodes": update_existing_codes}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settings_post_file = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=settings_post_data,
            files=settings_post_file,
            timeout=None,
            failure_message="Failed to import Records Management Codes from file -> '{}'".format(
                file_path
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            return True

        return False

    # end method definition

    def import_records_management_rsis(
        self,
        file_path: str,
        update_existing_rsis: bool = True,
        delete_schedules: bool = False,
    ) -> bool:
        """Import RM RSIs from a config file that is uploaded from the Python pod

        Args:
            file_path (str): path + filename of config file in Python container filesystem
            update_existing_rsis (bool, optional): whether or not existing RSIs should be updated (or ignored)
            delete_schedules (bool, optional): whether RSI Schedules should be deleted
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["recordsManagementUrl"] + "/importRSIs"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
            "Importing Records Management RSIs from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        settings_post_data = {
            "updateExistingRSIs": update_existing_rsis,
            "deleteSchedules": delete_schedules,
        }

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settings_post_file = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=settings_post_data,
            files=settings_post_file,
            timeout=None,
            failure_message="Failed to import Records Management RSIs from file -> '{}'".format(
                file_path
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            return True

        return False

    # end method definition

    def import_physical_objects_settings(self, file_path: str) -> bool:
        """Import Physical Objects settings from a config file that is uploaded from the python pod

        Args:
            file_path (str): path + filename of config file in Python container filesystem
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["physicalObjectsUrl"] + "/importSettings"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
            "Importing Physical Objects Settings from server file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settings_post_file = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            files=settings_post_file,
            timeout=None,
            failure_message="Failed to import Physical Objects settings from file -> '{}'".format(
                file_path
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            return True

        return False

    # end method definition

    def import_physical_objects_codes(
        self, file_path: str, update_existing_codes: bool = True
    ) -> bool:
        """Import Physical Objects codes from a config file that is uploaded from the Python pod

        Args:
            file_path (str): path + filename of config file in Python container filesystem
            update_existing_codes (bool): whether or not existing codes should be updated (default = True)
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["physicalObjectsUrl"] + "/importCodes"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
            "Importing Physical Objects Codes from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        settings_post_data = {"updateExistingCodes": update_existing_codes}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settings_post_file = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=settings_post_data,
            files=settings_post_file,
            timeout=None,
            failure_message="Failed to import Physical Objects Codes from file -> '{}'".format(
                file_path
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            return True

        return False

    # end method definition

    def import_physical_objects_locators(self, file_path: str) -> bool:
        """Import Physical Objects locators from a config file that is uploaded from the python pod

        Args:
            file_path (str): path + filename of config file in Python container filesystem
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["physicalObjectsUrl"] + "/importLocators"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
            "Importing Physical Objects Locators from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settings_post_file = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            files=settings_post_file,
            timeout=None,
            failure_message="Failed to import Physical Objects Locators from file -> '{}'".format(
                file_path
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            return True

        return False

    # end method definition

    def import_security_clearance_codes(
        self, file_path: str, include_users: bool = False
    ) -> bool:
        """Import Security Clearance codes from a config file that is uploaded from the python pod

        Args:
            file_path (str): path + filename of config file in Python container filesystem
            include_users (bool): defines if users should be included or not
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["securityClearancesUrl"] + "/importCodes"

        # When we upload files using the 'files' parameter, the request must be encoded
        # as multipart/form-data, which allows binary data (like files) to be sent along
        # with other form data.
        # The requests library sets this header correctly if the 'files' parameter is provided.
        # So we just put the cookie in the header and trust the request library to add
        # the Content-Type = multipart/form-data :
        request_header = self.cookie()

        logger.debug(
            "Importing Security Clearance Codes from file -> '%s'; calling -> %s",
            file_path,
            request_url,
        )

        settings_post_data = {"includeusers": include_users}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> '%s' does not exist in path -> '%s'!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settings_post_file = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        response = self.do_request(
            url=request_url,
            method="POST",
            headers=request_header,
            data=settings_post_data,
            files=settings_post_file,
            timeout=None,
            failure_message="Failed to import Security Clearance Codes from file -> '{}'".format(
                file_path
            ),
            parse_request_response=False,
        )

        if response and response.ok:
            return True

        return False

    # end method definition

    def assign_user_security_clearance(
        self, user_id: int, security_clearance: int
    ) -> dict | None:
        """Assign a Security Clearance level to an Extended ECM user

        Args:
            user_id (int): ID of the user
            security_clearance (int): security clearance level to be set
        Returns:
            dict: REST response or None if the REST call fails.
        """

        assign_user_security_clearance_post_data = {
            "securityLevel": security_clearance,
        }

        request_url = self.config()[
            "userSecurityUrl"
        ] + "/{}/securityclearancelevel".format(user_id)
        request_header = self.request_form_header()

        logger.debug(
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
                security_clearance, user_id
            ),
        )

    # end method definition

    def assign_user_supplemental_markings(
        self, user_id: int, supplemental_markings: list
    ) -> dict | None:
        """Assign a list of Supplemental Markings to a user

        Args:
            user_id (int): ID of the user
            supplemental_markings (list of strings): list of Supplemental Markings to be set
        Returns:
            dict: REST response or None if the REST call fails.
        """

        assign_user_supplemental_markings_post_data = {
            "suppMarks": supplemental_markings,
        }

        request_url = self.config()[
            "userSecurityUrl"
        ] + "/{}/supplementalmarkings".format(user_id)
        request_header = self.request_form_header()

        logger.debug(
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
                supplemental_markings, user_id
            ),
        )

    # end method definition

    def get_workflow_definition(self, workflow_id: int) -> dict | None:
        """Get the workflow definition.

        Args:
            workflow_id (int): node ID of the workflow item (map)

        Returns:
            dict | None: workflow definition data

            Example:
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
        """

        request_url = (
            self.config()["workflowUrl"] + "/" + str(workflow_id) + "/definition"
        )
        request_header = self.request_form_header()

        return self.do_request(
            url=request_url,
            method="GET",
            headers=request_header,
            timeout=None,
            failure_message="Failed to get definition of workflow with ID -> {}".format(
                workflow_id
            ),
        )

    # end method definition

    def get_workflow_attributes(
        self, workflow_id: int, form_prefix: str = "WorkflowForm"
    ) -> dict | None:
        """Get workflow attribute definition. It returns a dictionary
           to allow looking up attribute IDs based on the attribute names.

        Args:
            workflow_id (int): Node ID of the workflow.

        Returns:
            dict | None: Keys are the attribute names. Values are the attribute IDs.
                         None in case an error occurs.

            Example:
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
        """

        response = self.get_workflow_definition(workflow_id=workflow_id)

        if not response or not "results" in response:
            return None

        results = response["results"]
        if not "definition" in results:
            logger.error("Workflow definition is missing 'results' data structure!")
            return None

        # we just need the definition part of the workflow definition:
        definition = results["definition"]

        # in particular we want to lookup a specific data package
        # that includes the attribute definitions:
        if not "data_packages" in definition:
            logger.error("Workflow definition does not have data packages!")
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
        """

        request_url = self.config()[
            "docWorkflowUrl"
        ] + "?doc_id={}&parent_id={}".format(node_id, parent_id)
        request_header = self.request_form_header()

        logger.debug(
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
                node_id, parent_id
            ),
        )

    # end method definition

    def get_workflows_by_kind_and_status(
        self,
        kind: str | None = None,
        status: str | list | None = None,
        sort: str | None = None,
    ) -> list:
        """Get a list of workflows with a defined kind and status. This method is personlalized, you
           need to call it with the user thse workflows are related to

        Args:
            kind (str | None, optional): "Managed", "Initiated", "Both". Defaults to None.
            status (str | None, optional): "ontime", "workflowlate", "stopped", "completed". Defaults to None (=all).
            sort (str | None, optional): Sorting order, like "name asc", "name desc", "data_initiated asc", "status_key desc".
                                         Defaults to None.

        Returns:
            list: list of matching workflows

            Example:
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
        """

        query = {}
        if kind:
            query["kind"] = kind
        if status:
            query["wstatus"] = status
        if sort:
            query["sort"] = sort
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["workflowUrl"] + "/status?{}".format(encoded_query)
        request_header = self.request_form_header()

        logger.debug(
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
                kind, str(status)
            ),
        )

    # end method definition

    def get_workflow_status(self, process_id: int) -> dict | None:
        """Get the status (task list) of a workflow instance (process)

        Args:
            process_id (int): ID of the process (worflow instance)

        Returns:
            dict | None: Task list of the workflow instance or None if the request fails.

            Example result:
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
        """

        request_url = self.config()["workflowUrl"] + "/status/processes/{}".format(
            process_id
        )
        request_header = self.request_form_header()

        logger.debug(
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
                process_id
            ),
        )

    # end method definition

    def create_draft_process(self, workflow_id, documents: list) -> dict | None:
        """Initiate a draft process. This is the first step to start a process (workflow instance)

        Args:
            workflow_id (int): Node ID of the workflow maps
            documents (list): node IDs of the attachmewnt documents

        Returns:
            dict | None: Task list of the workflow instance or None if the request fails.

            Example:
            {
                'links': {
                    'data': {...}
                },
                'results': {
                    'draftprocess_id': 157555,
                    'workflow_type': '1_1'}
                }
            }
        """

        draft_process_body_post_data = {
            "workflow_id": workflow_id,
            "doc_ids": documents,
            #            "AttachDocuments": True, # THIS DOES NOT WORK!!!
        }

        request_url = self.config()["draftProcessUrl"]
        request_header = self.request_form_header()

        logger.debug(
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
                workflow_id
            ),
        )

    # end method definition

    def get_draft_process(self, draftprocess_id: int) -> dict | None:
        """Get draft process data.

        Args:
            draftprocess_id (int): ID of an existing draft process

        Returns:
            dict | None: Get the details for a draft process.
                         Delivers None in case of an error.

            Example result:
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
        """

        request_url = (
            self.config()["draftProcessFormUrl"]
            + "/update"
            + "?draftprocess_id="
            + str(draftprocess_id)
        )
        request_header = self.request_form_header()

        logger.debug(
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
                draftprocess_id
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
        """Update a draft process with values. These can either be given via dedicated parameters
           like title and due_date or with a generic value dictionary.

        Args:
            draftprocess_id (int): ID of the draft process that has been created before with create_draft_process()
            title (str): Title of the process
            due_date (str, optional): due date for the process. Defaults to "".
            values (dict | None, optional): values for workflow attributes. Defaults to None.

        Returns:
            dict | None: Respinse of the REST API or None in case of an error.
        """

        request_url = self.config()["draftProcessUrl"] + "/" + str(draftprocess_id)
        request_header = self.request_form_header()

        logger.debug(
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
                draftprocess_id, values
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
            draftprocess_id (int): ID of the draft process that has been created before with create_draft_process()
            title (str): Title of the process
            comment (str, optional): comment of the process. Defaults to "".
            due_date (str, optional): due date for the process. Defaults to "".
            values (dict | None, optional): values for workflow attributes. Defaults to None.

        Returns:
            dict | None: Respinse of the REST API or None in case of an error.

            Example:
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
        """

        request_url = self.config()["draftProcessUrl"] + "/" + str(draftprocess_id)
        request_header = self.request_form_header()

        logger.debug(
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
                draftprocess_id
            ),
        )

    # end method definition

    def get_process_task(
        self, process_id: int, subprocess_id: int | None = None, task_id: int = 1
    ) -> dict | None:
        """Get the task information of a workflow assignment.
           This method must be called with the user authenticated
           that has the task in ts inbox.

        Args:
            process_id (int): process ID of the workflow instance
            subprocess_id (int | None, optional): Subprocess ID. Defaults to None (= process_id).
            task_id (int, optional): Task ID. Defaults to 1.

        Returns:
            dict | None: Response of REST API call. None in case an error occured.

            Example:
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
                    'instructions': 'Paul Williams has sent this contract to you for review. \n\n1. Read the attached document in-depth\n2. Enter the approval date\n3. Then click the Approve or Reject button\n4. Enter a Comment if prompted',
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

        logger.debug(
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
                process_id
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
        """Update a process with values in a task. This method needs to be called with the user
           that has the task in its inbox (My ToDo - Workflows). It can update the task data (formUpdate)
           and/or send on the task to the next workflow step (action or custom_action).

            TODO: this method is currently untested.

        Args:
            process_id (int): ID of the draft process that has been created before with create_draft_process()
            task_id (int, optional): ID of the task. Default is 1.
            values (dict | None, optional): values for workflow attributes. Defaults to None. It is only
                                            used if action = "formUpdate".
            action (str, optional): the name of the action to process. The default is "formUpdate".
            custom_action (str, optional): Here we can have custom actions like "Approve" or "Reject".
                                           if "custom_action" is not None then the "action" parameter is ignored.
            comment (str, optional): the comment given with the action

        Returns:
            dict | None: Respinse of the REST API or None in case of an error.
        """

        if not action and not custom_action:
            logger.error(
                "Either 'action' or 'custom_action' is required for updating a process task!"
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
            logger.debug(
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
            logger.debug(
                "Execute action -> '%s' for process with ID -> %s",
                action,
                str(process_id),
            )
        else:  # we have a custom action:
            update_process_task_body_put_data = {
                "custom_action": custom_action,
            }
            logger.debug(
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
                task_id, process_id, values
            ),
        )

    # end method definition

    def check_workspace_aviator(
        self,
        workspace_id: int,
    ) -> bool:
        """Check if Content Aviator is enabled for a workspace

        Args:
            workspace_id (int): node ID of the workspace
        Returns:
            bool: True if aviator is enabled, False otherwise
        """

        response = self.get_node_actions(
            node_id=workspace_id, filter_actions=["disableai", "enableai"]
        )
        result_data = self.get_result_value(
            response=response,
            key=str(workspace_id),
        )
        if result_data and "data" in result_data:
            data = result_data["data"]
            if "disableai" in data:
                logger.debug(
                    "Aviator is enabled for workspace with ID -> %s", str(workspace_id)
                )
                return True
            elif "enableai" in data:
                logger.debug(
                    "Aviator is disabled for workspace with ID -> %s", str(workspace_id)
                )

        return False

    # end method definition

    def update_workspace_aviator(
        self,
        workspace_id: int,
        status: bool,
    ) -> dict | None:
        """Enable or disable the Content Aviator for a workspace

        Args:
            workspace_id (int): node ID of the workspace
            status (bool): True = enable, False = disable Content Aviator for this workspace
        Returns:
            dict: REST response or None if the REST call fails.
        """

        aviator_status_put_data = {
            "enabled": status,
        }

        request_url = self.config()["aiUrl"] + "/{}".format(workspace_id)
        request_header = self.request_form_header()

        if status is True:
            logger.debug(
                "Enable Content Aviator for workspace with ID -> %s; calling -> %s",
                str(workspace_id),
                request_url,
            )
        else:
            logger.debug(
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
                workspace_id
            ),
        )

    # end method definition

    def volume_translator(
        self,
        current_node_id: int,
        translator: object,
        languages: list,
        simulate: bool = False,
    ):
        """Experimental code to translate the item names and item descriptions in a given hierarchy.
           The actual translation is done by a tranlator object. This recursive method just
           traverses the hierarchy and calls the translate() method of the translator object.

        Args:
            current_node_id (int): current node ID to translate
            translator (object): this object needs to be created based on the "Translator" class
                                 and passed to this method
            languages (list): list of target languages
            simulate (bool, optional): if True, do not really rename but just traverse and log info.
                                       the default is False
        """
        # Get current node based on the ID:
        current_node = self.get_node(current_node_id)
        current_node_id = self.get_result_value(current_node, "id")

        name = self.get_result_value(current_node, "name")
        description = self.get_result_value(current_node, "description")
        names_multilingual = self.get_result_value(current_node, "name_multilingual")
        descriptions_multilingual = self.get_result_value(
            current_node, "description_multilingual"
        )

        for language in languages:
            if language == "en":
                continue
            # Does the language not exist as metadata language or is it already translated?
            # Then we skip this language:
            if (
                language in names_multilingual
                and names_multilingual["en"]
                and not names_multilingual[language]
            ):
                names_multilingual[language] = translator.translate(
                    "en", language, names_multilingual["en"]
                )
                logger.debug(
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
                    "en", language, descriptions_multilingual["en"]
                )
                logger.debug(
                    "Translate description of node -> %s from -> '%s' (%s) to -> '%s' (%s)",
                    current_node_id,
                    name,
                    "en",
                    names_multilingual[language],
                    language,
                )

        # Rename node multi-lingual:
        if not simulate:
            self.rename_node(
                current_node_id,
                name,
                description,
                names_multilingual,
                descriptions_multilingual,
            )

        # Get children nodes of the current node:
        results = self.get_subnodes(current_node_id, limit=200)["results"]

        # Recursive call of all subnodes:
        for result in results:
            self.volume_translator(
                result["data"]["properties"]["id"], translator, languages
            )

    # end method definition

    def download_document_multi_threading(self, node_id: int, file_path: str):
        """Multi-threading variant of download_document()

        Args:
            node_id (int): Node ID of the document to download
            file_path (str): file system path - location to download to
        """

        # Aquire and Release Thread limit to limit parallel executions

        with self._semaphore:
            self.download_document(node_id=node_id, file_path=file_path)

    # end method definition

    def apply_filter(
        self,
        node: dict,
        current_depth: int = 0,
        filter_depth: int | None = None,
        filter_subtypes: list | None = None,
        filter_category: str | None = None,
        filter_attributes: dict | list | None = None,
    ) -> bool:
        """Check all defined filters for the given node.

        Args:
            node (dict): Current OTCS Node
            filter_depth (int | None, optional): Additive filter criterium for path depth. Defaults to None = filter not active.
            filter_subtype (list | None, optional): Additive filter criterium for workspace type. Defaults to None = filter not active.
            filter_category (str | None, optional): Additive filter criterium for workspace category. Defaults to None = filter not active.
            filter_attributes (dict | list | None, optional): _description_. Defaults to None.

        Returns:
            bool: Only for nodes that comply with ALL provided filters True is returned. Otherwise False.
        """

        if not node or not "type" in node or not "id" in node:
            logger.error("Illegal node!")
            return False

        if filter_subtypes and not node["type"] in filter_subtypes:
            logger.info(
                "Node type -> '%s' is not in filter node types -> %s. Node -> '%s' failed filter test.",
                node["type"],
                filter_subtypes,
                node["name"],
            )
            return False

        if filter_depth is not None and filter_depth != current_depth:
            logger.info(
                "Node is in depth -> %s which is different from filter depth -> %s. Node -> '%s' failed filter test.",
                current_depth,
                filter_depth,
                node["name"],
            )
            return False

        if filter_category:
            category_names = self.get_node_category_names(node_id=node["id"])
            if not category_names or filter_category not in category_names:
                logger.info(
                    "Node categories -> %s do not include filter category -> '%s'. Node -> '%s' failed filter test.",
                    category_names,
                    filter_category,
                    node["name"],
                )
                return False
            if filter_attributes:
                if isinstance(filter_attributes, dict):
                    filter_attributes = [filter_attributes]
                for filter_attribute in filter_attributes:
                    filter_category_name = filter_attribute.get(
                        "category", filter_category
                    )
                    if not filter_category_name:
                        logger.error(
                            "Attribute filter -> %s is missing category name!",
                            str(filter_attribute),
                        )
                        continue
                    filter_set_name = filter_attribute.get("set", None)
                    filter_attribute_name = filter_attribute.get("attribute", None)
                    if not filter_attribute_name:
                        logger.error(
                            "Attribute filter -> %s is missing attribute name!",
                            str(filter_attribute),
                        )
                        continue
                    filter_row = filter_attribute.get("row", None)
                    filter_value = filter_attribute.get("value", None)
                    actual_value = self.get_category_value_by_name(
                        node_id=node["id"],
                        category_name=filter_category_name,
                        set_name=filter_set_name,
                        attribute_name=filter_attribute_name,
                        set_row=filter_row,
                    )
                    # Both actual value and filter value can be strings or list of strings.
                    # So we need to handle a couple of cases here:

                    # Case 1: Data source delivers a list and filter value is a scalar value (int, str, float)
                    if isinstance(actual_value, list) and isinstance(
                        filter_value, (str, int, float)
                    ):
                        if filter_value not in actual_value:
                            return False
                    # Case 2: Data source delivers a scalar value and filter value is a list
                    elif isinstance(actual_value, (str, int, float)) and isinstance(
                        filter_value, list
                    ):
                        if actual_value not in filter_value:
                            return False
                    # Case 3: Both, filter and actual value are lists:
                    elif isinstance(actual_value, list) and isinstance(
                        filter_value, list
                    ):
                        # check if there's an non-empty intersetion set of both lists:
                        if not set(actual_value) & set(filter_value):
                            return False
                    elif isinstance(actual_value, (str, int, float)) and isinstance(
                        filter_value, (str, int, float)
                    ):
                        if actual_value != filter_value:
                            return False
                    else:
                        return False

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
        filter_item_category: str | None = None,
        filter_item_attributes: dict | list | None = None,
        workspace_metadata: bool = True,
        item_metadata: bool = True,
        skip_existing_downloads: bool = True,
    ) -> bool:
        """Create a Pandas Data Frame by traversing a given Content Server hierarchy and collecting workspace and document items.

        Args:
            node_id (int): currrent Node ID (in recursive processing). Initially this is the starting node (root of the traversal)
            folder_path (str, optional): The current path from the starting node to the current node. Defaults to None.
            current_depth (int): The current depth in the tree that is traversed.
            workspace_type (int | None, optional): Type of the workspace (if already found in the hierarchy). Defaults to None.
            workspace_id (int | None, optional): ID of the workspace (if already found in the hierarchy). Defaults to None.
            workspace_name (str | None, optional): Name of the workspace (if already found in the hierarchy). Defaults to None.
            workspace_description (str | None, optional): Description of the workspace (if already found in the hierarchy). Defaults to None.
            filter_workspace_depth (int | None, optional): Additive filter criterium for workspace path depth. Defaults to None = filter not active.
            filter_workspace_subtype (list | None, optional): Additive filter criterium for workspace type. Defaults to None = filter not active.
            filter_workspace_category (str | None, optional): Additive filter criterium for workspace category. Defaults to None = filter not active.
            filter_workspace_attributes (dict | list, optional): Additive filter criterium for workspace attribute values. Defaults to None = filter not active
            filter_item_depth (int | None, optional): Additive filter criterium for item path depth. Defaults to None = filter not active.
            filter_item_category (str | None, optional): Additive filter criterium for item category. Defaults to None = filter not active.
            filter_item_attributes (dict | list, optional): Additive filter criterium for item attribute values. Defaults to None = filter not active
        Returns:
            bool: True = success, False = Error
        """

        if folder_path is None:
            folder_path = []  # required for list concatenation below

        # Create folder if it does not exist
        try:
            os.makedirs(self._download_dir)
        except FileExistsError:
            pass

        # Aquire and Release threading semaphore to limit parallel executions
        # to not overload the source Content Server system:
        with self._semaphore:
            subnodes = self.get_subnodes(parent_node_id=node_id)

        if subnodes is None:
            subnodes = {"results": []}

        # Initialize traversal threads:
        traversal_threads = []

        for subnode in subnodes.get("results", []):
            subnode = subnode.get("data").get("properties")

            # Initiaze download threads for this subnode:
            download_threads = []

            match subnode["type"]:

                case 0 | 848:  # folder or workspace
                    # First we check if we have found a workspace already:
                    if not workspace_id:
                        # Second we apply the defined filters to the current node. Only "workspaces"
                        # that comply with ALL provided filters are considered and written into the data frame
                        found_workspace = self.apply_filter(
                            node=subnode,
                            current_depth=current_depth,
                            filter_depth=filter_workspace_depth,
                            filter_subtypes=filter_workspace_subtypes,
                            filter_category=filter_workspace_category,
                            filter_attributes=filter_workspace_attributes,
                        )
                    else:
                        logger.info(
                            "Found folder or workspace -> '%s' (%s) inside workspace with ID -> %s. So this container cannot be a workspace.",
                            subnode["name"],
                            subnode["id"],
                            workspace_id,
                        )
                        # otherwise the current node cannot be a workspace as we are already in a workspace!
                        # For future improvements we could look at supporting sub-workspaces:
                        found_workspace = False

                    if found_workspace:
                        logger.info(
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
                        if workspace_metadata:
                            categories = self.get_node_categories(
                                subnode["id"], metadata=False
                            )
                            if categories and categories["results"]:
                                for category in categories["results"]:
                                    if (
                                        not "data" in category
                                        or not "categories" in category["data"]
                                    ):
                                        continue
                                    attributes = category["data"]["categories"]
                                    for key in attributes:
                                        value = attributes[key]
                                        row["workspace_" + key] = value

                        # Now we add the article to the Pandas Data Frame in the Data class:
                        with self._data.lock():
                            self._data.append(row)
                        subfolder = []  # now we switch to workspace inner path
                    # end if found_workspace:
                    else:  # we treat the current folder / workspace just as a container
                        logger.info(
                            "Node -> '%s' (%s) in depth -> %s is NOT a workspace. Keep traversing...",
                            subnode["name"],
                            subnode["id"],
                            current_depth,
                        )
                        subfolder = folder_path + [subnode["name"]]

                    # Recursive call to start threads for sub-items:
                    thread = threading.Thread(
                        target=self.load_items,
                        args=(
                            subnode["id"],
                            subfolder,
                            current_depth + 1,
                            (
                                workspace_type  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["type"]
                            ),
                            (
                                workspace_id  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["id"]
                            ),
                            (
                                workspace_name  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["name"]
                            ),
                            (
                                workspace_description  # pass down initial parameter value if subnode is not the workspace
                                if not found_workspace
                                else subnode["description"]
                            ),
                            filter_workspace_depth,
                            filter_workspace_subtypes,
                            filter_workspace_category,
                            filter_workspace_attributes,
                            filter_item_depth,
                            filter_item_category,
                            filter_item_attributes,
                            workspace_metadata,
                            item_metadata,
                            skip_existing_downloads,
                        ),
                        name="traverse_node_{}".format(subnode["id"]),
                    )
                    thread.start()
                    traversal_threads.append(thread)

                case 1:  # shortcuts
                    pass

                case 854:  # Related Workspaces - we don't want to run into loops!
                    pass

                case 751:  # E-Mail folders
                    pass

                case 123469:  # Forum
                    pass

                case 144:  # document
                    # We apply the defined filters to the current node. Only "documents"
                    # that comply with ALL provided filters are considered and written into the data frame
                    found_document = self.apply_filter(
                        node=subnode,
                        current_depth=current_depth,
                        filter_depth=filter_item_depth,
                        filter_category=filter_item_category,
                        filter_attributes=filter_item_attributes,
                    )

                    if not found_document:
                        continue

                    # We use the node ID as the filename to avoid any
                    # issues with too long or not valid file names.
                    # As the Pandas DataFrame has all information
                    # this is easy to resolve at upload time.
                    file_path = "{}/{}".format(self._download_dir, subnode["id"])

                    # We only consider documents that are inside the defined "workspaces":
                    if workspace_id:
                        logger.info(
                            "Found document -> '%s' (%s) in depth -> %s inside workspace -> '%s' (%s)",
                            subnode["name"],
                            subnode["id"],
                            current_depth,
                            workspace_name,
                            workspace_id,
                        )
                    else:
                        logger.warning(
                            "Found document -> '%s' (%s) in depth -> %s outside of workspace",
                            subnode["name"],
                            subnode["id"],
                            current_depth,
                        )

                    # We download only if not downloaded before or if downloaded
                    # before but forced to re-download:
                    if not os.path.exists(file_path) or not skip_existing_downloads:
                        #
                        # Start anasynchronous Download Thread:
                        #
                        logger.info(
                            "Downloading file -> %s...",
                            file_path,
                        )
                        thread = threading.Thread(
                            target=self.download_document_multi_threading,
                            args=(subnode["id"], file_path),
                            name="download_document_node_{}".format(subnode["id"]),
                        )
                        thread.start()
                        download_threads.append(thread)
                    else:
                        logger.info(
                            "File -> %s has been downloaded before. Skipping download...",
                            file_path,
                        )

                    #
                    # Construct a dictionary 'row' that we will add
                    # to the resulting data frame:
                    #
                    row = {}
                    # First we include some key workspace data to associate
                    # the itemwith the workspace:
                    row["workspace_type"] = workspace_type
                    row["workspace_id"] = workspace_id
                    row["workspace_name"] = workspace_name
                    row["workspace_description"] = workspace_description
                    row["item_id"] = str(subnode["id"])
                    row["item_name"] = subnode["name"]
                    row["item_description"] = subnode["description"]
                    row["item_path"] = folder_path
                    row["item_download_name"] = str(subnode["id"])
                    row["item_mime_type"] = subnode["mime_type"]
                    if item_metadata:
                        categories = self.get_node_categories(
                            subnode["id"], metadata=False
                        )
                        if categories and categories["results"]:
                            for category in categories["results"]:
                                if (
                                    not "data" in category
                                    or not "categories" in category["data"]
                                ):
                                    continue
                                attributes = category["data"]["categories"]
                                for key in attributes:
                                    value = attributes[key]
                                    row["item_" + key] = value

                    # Now we add the row to the Pandas Data Frame in the Data class:
                    logger.info(
                        "Adding document -> '%s' (%s) to data frame...",
                        row["item_name"],
                        row["item_id"],
                    )
                    with self._data.lock():
                        self._data.append(row)
                case 140:  # url
                    logger.info(
                        "Found URL object %s with %s", subnode["id"], subnode["url"]
                    )

                case _:
                    logger.warning(
                        "Don't know what to do with item -> %s (%s) of type %s",
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
        node_type: int = 144,
        crawl: bool = False,
        wait_for_completion: bool = True,
        message_override: dict = {},
        timeout: float = 10.0,
    ):
        """RUN FEME metadata embedding on provided node for Aviator

        Args:
            node_id (int): Node ID
            node_type (int, optional): Subtype of the node. Defaults to 144.
            crawl (bool, optional): _description_. Defaults to False.
            wait_for_completion (bool, optional): _description_. Defaults to True.
            message_override (dict, optional): _description_. Defaults to {}.
            timout (float): Time in seconds to wait until the WebSocket times out. Defaults to 10.0
        """

        async def _inner(
            uri: str,
            node_id: int,
            node_type: int,
            crawl: bool,
            wait_for_completion: bool,
            message_override: dict,
            timeout: float,
        ):

            logger.debug("Open WebSocket connection to %s", uri)
            async with websockets.connect(uri) as websocket:

                # define it one node, or all childs should be processed
                task = ("crawl" if crawl else "index",)
                finished = "crawled" if crawl else "uploaded"

                message = {
                    "task": task,
                    "nodes": [{"id": node_id, "type": node_type}],
                    "documents": False,
                    "workspaces": True,
                    "images": False,
                    "binaries": False,
                    "upload": True,
                    "remove": False,
                    "imagePrompt": "Extract all information from the picture, please.",
                    "maxRelations": 0,
                }
                message.update(message_override)
                logger.debug("Sending message via WebSocket -> %s", message)
                await websocket.send(json.dumps(message))

                # Continuously listen for messages
                while wait_for_completion:
                    response = await asyncio.wait_for(
                        websocket.recv(), timeout=timeout
                    )  # await websocket.recv()  # Receive response

                    logger.debug("Received message via WebSocket -> %s", response)
                    response = json.loads(response)

                    if response.get("name", None) == finished:  # crawled
                        logger.info(
                            "Received completed message via WebSocket, close connection"
                        )
                        break

        event_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(event_loop)

        uri = self._config["feme_uri"]
        task = _inner(
            uri=uri,
            node_id=node_id,
            node_type=node_type,
            crawl=crawl,
            wait_for_completion=wait_for_completion,
            message_override=message_override,
            timeout=timeout,
        )

        try:
            event_loop.run_until_complete(task)
        except websockets.exceptions.ConnectionClosed as exc:  # :
            logger.error("WebSocket connection was closed: %s", exc)

        except TimeoutError:
            logger.error(
                "Error during Feme WebSocket connection: TimeoutError, WebSocket did not receive a message in time (%ss)",
                timeout,
            )

        except Exception as exc:
            logger.error("Error during Feme WebSocket connection: %s", exc)

        event_loop.close()

    # end method definition

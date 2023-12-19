"""
OTCS Module to implement functions to read / write Content Server objects
such as Users, Groups, Nodes, Workspaces, ...

Class: OTCS
Methods:

__init__ : class initializer
config : returns config data set
cookie : returns cookie information
credentials: Get credentials (username and password)
set_credentials: Set new credentials
hostname: Get the configured OTCS hostname
set_hostname: Set the hostname of OTCS
base_url : Get OTCS base URL
cs_url: Get the Extended ECM (OTCS) URL
rest_url : Get OTCS REST base URL

request_form_header: Deliver the request header used for the CRUD REST API calls.
request_json_header: Deliver the request header for REST calls that require content type application/json.
request_download_header: Deliver the request header used for download REST API calls.
                         These calls accept application/octet-stream.

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

get_group: Lookup Content Server group
add_group: Add Content Server group
get_group_members: Get Content Server group members
add_group_member: Add a user or group to a target group

get_node: Get a node based on the node ID
get_node_by_parent_and_name: Get a node based on the parent ID and name
get_node_by_workspace_and_path: Get a node based on the workspace ID and path (list of folder names)
get_node_by_volume_and_path: Get a node based on the volume ID and path
get_node_from_nickname: Get a node based on the nickname
get_subnodes: get children nodes of a parent node
get_node_actions: get possible actions for a node
rename_node: Change the name and description of a node
get_volumes: Get all Volumes
get_volume: Get Volume information based on the volume type ID
check_node_name: Check if a a node name in a parent location has a name collision
upload_file_to_volume: Fetch a file from a URL or local filesystem and upload
                    it to a Extended ECM volume
upload_file_to_parent: Upload a document to a parent folder
add_document_version: Add a version to an Extended ECM document
get_latest_document_version: Get latest version of a document node based on the node ID.
get_document_content: get content of a document version
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

get_workspace_types: Get all workspace types configured in Extended ECM
get_business_object_type: Get information for a specific business object type
get_workspace_create_form: Get the Workspace create form
get_workspace: Get a workspace node
get_workspace_instances: Get all instances of a given workspace type 
get_workspace_by_type_and_name: Lookup workspace based on workspace type name and workspace name
get_workspace_by_business_object: Lookup workspace based by an business object of an external system
create_workspace: Create a new business workspace
create_workspace_relationship: Create a relationship between two workspaces
get_workspace_relationships: get a list of related workspaces
get_workspace_roles: Get the Workspace roles
add_member_to_workspace: Add member to workspace role. Check that the user is not yet a member
remove_member_from_workspace: Remove member from workspace role
assign_workspace_permissions: Update workspace permissions for a given role
update_workspace_icon: Update a workspace with a with a new icon (which is uploaded)

create_item: Create an item in Extended ECM (e.g. folder or URL item)
update_item: Update an item in Extended ECM (e.g. folder or URL item)
get_document_templates: Get all document templates for a given target location
create_document_from_template: Create a document based on a document template

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
get_node_category_definition: Get category definition (category id and attribute IDs and types)
assign_category: Assign a category to a node
set_category_value: Set a value for a specific category attribute to a node

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

check_workspace_aviator: Check if Content Aviator is enabled for a workspace
update_workspace_aviator: Enable or disable the Content Aviator for a workspace

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2023, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import os
import logging
import json
import time
import urllib.parse
from datetime import datetime
import zipfile
import requests
from pyxecm.helper.xml import XML

logger = logging.getLogger("pyxecm.otcs")

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

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        public_url: str,
        username: str | None = None,
        password: str | None = None,
        user_partition: str = "Content Server Members",
        resource_name: str = "cs",
        default_license: str = "X3",
        otds_ticket: str | None = None,
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

        otcs_base_url = protocol + "://" + otcs_config["hostname"]
        if str(port) not in ["80", "443"]:
            otcs_base_url += ":{}".format(port)
        otcs_config["baseUrl"] = otcs_base_url
        otcs_support_url = otcs_base_url + "/cssupport"
        otcs_config["supportUrl"] = otcs_support_url
        otcs_public_support_url = public_url + "/cssupport"
        otcs_config["supportPublicUrl"] = otcs_public_support_url

        otcs_config["configuredUrl"] = otcs_support_url + "/csconfigured"

        otcs_url = otcs_base_url + "/cs/cs"
        otcs_config["csUrl"] = otcs_url
        otcs_public_url = public_url + "/cs/cs"
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
        otcs_config["externalSystem"] = otcs_rest_url + "/v2/externalsystems"
        otcs_config["businessworkspacetypes"] = (
            otcs_rest_url + "/v2/businessworkspacetypes"
        )
        otcs_config["businessworkspacecreateform"] = (
            otcs_rest_url + "/v2/forms/businessworkspaces/create"
        )
        otcs_config["businessworkspaces"] = otcs_rest_url + "/v2/businessworkspaces"
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

        self._config = otcs_config
        self._otds_ticket = otds_ticket

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    def cookie(self) -> dict:
        """Returns the login cookie of Extended ECM.
           This is set by the authenticate() method

        Returns:
            dict: Estended ECM cookie
        """
        return self._cookie

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
        """Set the credentials for Extended ECM for the based on user name and password.

        Args:
            username (str, optional): Username. Defaults to "admin".
            password (str, optional): Password of the user. Defaults to "".
        """
        self.config()["username"] = username
        self.config()["password"] = password

    def hostname(self) -> str:
        """Returns the hostname of Extended ECM (e.g. "otcs")

        Returns:
            str: hostname
        """
        return self.config()["hostname"]

    def set_hostname(self, hostname: str):
        """Sets the hostname of Extended ECM

        Args:
            hostname (str): new hostname
        """
        self.config()["hostname"] = hostname

    def base_url(self) -> str:
        """Returns the base URL of Extended ECM

        Returns:
            str: base URL
        """
        return self.config()["baseUrl"]

    def cs_url(self) -> str:
        """Returns the Extended ECM URL

        Returns:
            str: Extended ECM URL
        """
        return self.config()["csUrl"]

    def cs_public_url(self) -> str:
        """Returns the public (external) Extended ECM URL (incl. /cs/cs)

        Returns:
            str: Extended ECM Public URL
        """
        return self.config()["csPublicUrl"]

    def cs_support_url(self) -> str:
        """Returns the Extended ECM Support URL

        Returns:
            str: Extended ECM Support URL
        """
        return self.config()["supportUrl"]

    def cs_support_public_url(self) -> str:
        """Returns the Extended ECM Public Support URL

        Returns:
            str: Extended ECM Public Support URL
        """
        return self.config()["supportPublicUrl"]

    def rest_url(self) -> str:
        """Returns the REST URL of Extended ECM

        Returns:
            str: REST URL
        """
        return self.config()["restUrl"]

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
                        "There's no -> %s dictionary in data -> %s", property_name, data
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
                            "There's no -> %s dictionary in the data list item -> %s",
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
            logger.info("Empty REST response - returning None")
            return None
        if not "results" in response:
            logger.error("No 'results' key in REST response - returning None")
            return None

        results = response["results"]
        if not results:
            logger.info("No results found!")
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
                    logger.error("Key -> %s is not in result properties!", key)
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
                return False
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
                logger.error("Key -> %s is not in result properties!", key)
                return None
            return properties[key]
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

        logger.info("Trying to retrieve OTCS URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=REQUEST_JSON_HEADERS,
                timeout=REQUEST_TIMEOUT,
            )
        except requests.exceptions.RequestException as exception:
            logger.warning(
                "Unable to connect to -> %s; warning -> %s",
                request_url,
                exception.strerror,
            )
            logger.warning("OTCS service may not be ready yet.")
            return False

        if not response.ok:
            logger.warning(
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

        logger.info("Trying to retrieve OTCS URL -> %s", request_url)

        try:
            response = requests.get(
                url=request_url,
                headers=REQUEST_JSON_HEADERS,
                timeout=2,
            )
        except requests.exceptions.RequestException as exception:
            logger.warning(
                "Unable to connect to -> %s; warning -> %s",
                request_url,
                exception.strerror,
            )
            logger.warning("OTCS service may not be ready yet.")
            return False

        if not response.status_code == 200:
            logger.warning(
                "Unable to connect to -> %s; status -> %s; warning -> %s",
                request_url,
                response.status_code,
                response.text,
            )
            return False

        return True

    # end method definition

    def authenticate(
        self, revalidate: bool = False, force_user_password_login: bool = False
    ) -> dict | None:
        """Authenticates at Content Server and retrieve OTCS Ticket.

        Args:
            revalidate (bool): determinse if a re-athentication is enforced
                               (e.g. if session has timed out with 401 error)
            force_user_password_login (bool): By default we use the OTDS ticket (if exists) for the authentication with OTCS.
                                              This switch allows the forced usage of username / password for the authentication.
        Returns:
            dict: Cookie information of None in case of an error.
                        Also stores cookie information in self._cookie
        """

        # Already authenticated and session still valid?
        if self._cookie and not revalidate:
            return self._cookie

        otcs_ticket = None

        logger.info("Wait for OTCS to be ready...")
        while not self.is_ready():
            logger.warning(
                "OTCS is not ready to receive requests yet. Waiting 30 seconds..."
            )
            time.sleep(30)

        request_url = self.config()["authenticationUrl"]

        if self._otds_ticket and not force_user_password_login:
            logger.info(
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

        # Check if previous authentication was successful
        if not otcs_ticket:
            logger.info(
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
                    logger.info("Ticket -> %s", otcs_ticket)
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

    def get_server_info(self) -> dict | None:
        """Get Content Server information (server info)

        Args:
            None
        Returns:
            dict: server information or None if the call fails

            Example value:
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

        logger.info(
            "Retrieve Extended ECM server information; calling -> %s", request_url
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to retrieve Extended ECM server information; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

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
                        response["results"]["data"]["restart"] indicates if the settings
                        require a restart of the OTCS services.
        """

        filename = os.path.basename(xml_file_path)

        if not os.path.exists(xml_file_path):
            logger.error(
                "The admin settings file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(xml_file_path),
            )
            return None

        llconfig_file = {
            "file": (filename, open(file=xml_file_path, encoding="utf-8"), "text/xml")
        }

        request_url = self.config()["importSettingsUrl"]
        request_header = self._cookie

        logger.info(
            "Applying admin settings from file -> %s; calling -> %s",
            xml_file_path,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                files=llconfig_file,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.debug(
                    "Admin settings in file -> %s have been applied", xml_file_path
                )
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import settings file -> %s; status -> %s; error -> %s",
                    xml_file_path,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_user(self, name: str, show_error: bool = False) -> dict | None:
        """Lookup Extended ECM user based on the name.

        Args:
            name (str): name of the user
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
        request_url = self.config()["membersUrlv2"] + "?where_type=0&query={}".format(
            name
        )
        request_header = self.request_form_header()

        logger.info("Get user with name -> %s; calling -> %s", name, request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get user -> %s; status -> %s; error -> %s",
                        name,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info("User -> %s not found.", name)
                return None

    # end method definition

    def add_user(
        self,
        name: str,
        password: str,
        first_name: str,
        last_name: str,
        email: str,
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
            base_group (int): base group id of the user (e.g. department)
            privileges (list, optional): values are Login, Public Access, Content Manager,
                                         Modify Users, Modify Groups, User Admin Rights,
                                         Grant Discovery, System Admin Rights
        Returns:
            dict: User information or None if the user couldn't be created (e.g. because it exisits already).
        """

        if privileges is None:
            privileges = ["Login", "Public Access"]

        userPostBody = {
            "type": 0,
            "name": name,
            "password": password,
            "first_name": first_name,
            "last_name": last_name,
            "business_email": email,
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

        logger.info("Adding user -> %s; calling -> %s", name, request_url)

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=userPostBody,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add user -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def search_user(self, value: str, field: str = "where_name") -> dict | None:
        """Find a user based on search criteria.

        Args:
            value (str): field value
            field (str): user field to search with (where_name, where_first_name, where_last_name)
        Returns:
            dict: User information or None if the user couldn't be found (e.g. because it doesn't exist).
            Example:
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

        logger.info(
            "Searching user by field -> %s, value -> %s; calling -> %s",
            field,
            value,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Cannot find user with -> %s = %s; status -> %s; error -> %s",
                    field,
                    value,
                    response.status_code,
                    response.text,
                )
                return None

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

        userPutBody = {field: value}

        request_url = self.config()["membersUrlv2"] + "/" + str(user_id)
        request_header = self.request_form_header()

        logger.info(
            "Updating user with ID -> %s, field -> %s, value -> %s; calling -> %s",
            str(user_id),
            field,
            value,
            request_url,
        )
        logger.debug("User Attributes -> %s", str(userPutBody))

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                data=userPutBody,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update user with ID -> %s; status -> %s; error -> %s",
                    str(user_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_user_profile(self) -> dict | None:
        """Update a defined field for a user profile.
           IMPORTANT: this method needs to be called by the authenticated user

        Args:
            field (str): user profile field
            value (str): new field value
        Returns:
            dict: User information or None if the user couldn't be updated
                  (e.g. because it doesn't exist).
        """

        request_url = self.config()["membersUrlv2"] + "/preferences"
        request_header = self.request_form_header()

        logger.info(
            "Get profile (settings) for current user; calling -> %s",
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get profile of current user; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

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

        userProfilePutBody = {config_section: {field: value}}

        request_url = self.config()["membersUrlv2"] + "/preferences"
        request_header = self.request_form_header()

        logger.info(
            "Updating profile for current user, field -> %s, value -> %s; calling -> %s",
            field,
            value,
            request_url,
        )
        logger.debug("User Attributes -> %s", str(userProfilePutBody))

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            response = requests.put(
                url=request_url,
                data={"body": json.dumps(userProfilePutBody)},
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update profile of current user; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def update_user_photo(self, user_id: int, photo_id: int) -> dict | None:
        """Update a user with a profile photo (which must be an existing node).

        Args:
            user_id (int): ID of the user
            photo_id (int): Node ID of the photo
        Returns:
            dict: Node information or None if photo node is not found.
        """

        updateUserPutBody = {"photo_id": photo_id}

        request_url = self.config()["membersUrl"] + "/" + str(user_id)
        request_header = self.request_form_header()

        logger.info(
            "Update user ID -> %s with photo ID -> %s; calling -> %s",
            user_id,
            photo_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                data=updateUserPutBody,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update user with ID -> %s; status -> %s; error -> %s",
                    str(user_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def is_proxy(self, user_name: str) -> bool:
        """Check if a user is defined as proxy of the current user.
           This method differentiates between the old (xGov) based
           implementation and the new Extended ECM platform one
           that was introduced with version 23.4.

        Args:
            user_name (str): user  to test (login name)
        Returns:
            bool: True is user is proxy of current user. False if not.
        """

        version_number = self.get_server_version()
        # Split the version number by dot
        parts = version_number.split(".")
        # Take the first two parts and join them back with a dot
        stripped_version = ".".join(parts[:2])
        version_number = float(stripped_version)

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

        logger.info("Get proxy users for current user; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get proxy users for current user; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

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
        # the egacy Extended ECM for Government Proxy
        # implementation:
        if version_number >= 23.4:
            post_dict = {}
            post_dict["id"] = proxy_user_id
            post_dict["from_date"] = from_date
            post_dict["to_date"] = to_date
            post_data = {"body": json.dumps(post_dict)}
            request_url = self.config()["membersUrlv2"] + "/proxies"
            logger.info(
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
            logger.info(
                "Assign proxy user with ID -> %s to current user (legacy xGov); calling -> %s",
                proxy_user_id,
                request_url,
            )

        request_header = self.request_form_header()

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            response = requests.post(
                url=request_url,
                data=post_data,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to assign proxy user with ID -> %s to current user; status -> %s; error -> %s",
                    proxy_user_id,
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info(
            "Adding favorite for node ID -> %s; calling -> %s", node_id, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add favorite for node ID -> %s; status -> %s; error -> %s",
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

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
        request_url = self.config()["membersUrlv2"] + "?where_type=1&query={}".format(
            name
        )
        request_header = self.request_form_header()

        logger.info("Get group with name -> %s; calling -> %s", name, request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get group -> %s; status -> %s; error -> %s",
                        name,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info("Group -> %s not found.", name)
                return None

    # end method definition

    def add_group(self, name: str) -> dict | None:
        """Add Content Server group.

        Args:
            name (str): name of the group
        Returns:
            dict: Group information or None if the group couldn't be created (e.g. because it exisits already).
        """

        groupPostBody = {"type": 1, "name": name}

        request_url = self.config()["membersUrlv2"]
        request_header = self.request_form_header()

        logger.info("Adding group -> %s; calling -> %s", name, request_url)
        logger.debug("Group Attributes -> %s", str(groupPostBody))

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=groupPostBody,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add group -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info(
            "Getting members of group with ID -> %s; calling -> %s",
            str(group),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get members of group -> %s; status -> %s; error -> %s",
                    str(group),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_group_member(self, member_id: int, group_id: int) -> dict | None:
        """Add a user or group to a target group.

        Args:
            member_id (int): ID of the user or group to add.
            group_id (int): ID of the target group.
        Returns:
            dict: Response or None if adding a the member fails.
        """

        groupMemberPostBody = {"member_id": member_id}

        request_url = self.config()["membersUrlv2"] + "/" + str(group_id) + "/members"
        request_header = self.request_form_header()

        logger.info(
            "Adding member with ID -> %s to group with ID -> %s; calling -> %s",
            str(member_id),
            str(group_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=groupMemberPostBody,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add member with ID -> %s to group with ID -> %s; status -> %s; error -> %s",
                    str(member_id),
                    str(group_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_node(self, node_id: int, timeout: int = REQUEST_TIMEOUT) -> dict | None:
        """Get a node based on the node ID.

        Args:
            node_id (int) is the node Id of the node
            timeout (int, optional): timeout for the request in seconds
        Returns:
            dict: Node information or None if no node with this ID is found.
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

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.info("Get node with ID -> %s; calling -> %s", str(node_id), request_url)

        retries = 0
        while True:
            try:
                response = requests.get(
                    url=request_url,
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=timeout,
                )
                if response.ok:
                    return self.parse_request_response(response)
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    logger.warning("Session has expired - try to re-authenticate...")
                    self.authenticate(True)
                    retries += 1
                else:
                    logger.error(
                        "Failed to get node with ID -> %s; status -> %s; error -> %s",
                        str(node_id),
                        response.status_code,
                        response.text,
                    )
                    return None
            except requests.exceptions.Timeout:
                if retries <= REQUEST_MAX_RETRIES:
                    logger.warning(
                        "Request timed out. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    logger.error(
                        "Failed to get node with ID -> %s; timeout error", str(node_id)
                    )
                    # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                    logger.warning("Turn timeouts off and wait forever...")
                    timeout = None

    # end method definition

    def get_node_by_parent_and_name(
        self,
        parent_id: int,
        name: str,
        fields: str = "properties",
        show_error: bool = False,
    ) -> dict | None:
        """Get a node based on the parent ID and name. This method does basically
           a query with "where_name" and the "result" is a list.

        Args:
            parent_id (int) is the node Id of the parent node
            name (str) is the name of the node to get
            fields (str): which fields to retrieve. This can have a big impact on performance!
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
            + "/nodes?{}".format(encoded_query)
        )
        request_header = self.request_form_header()

        logger.info(
            "Get node with name -> %s and parent ID -> %s; calling -> %s",
            name,
            str(parent_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get node with name -> %s and parent ID -> %s; status -> %s; error -> %s",
                        name,
                        str(parent_id),
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info(
                        "Node with name -> %s and parent ID -> %s not found.",
                        name,
                        str(parent_id),
                    )
                return None

    # end method definition

    def get_node_by_workspace_and_path(
        self, workspace_id: int, path: list, show_error: bool = False
    ) -> dict | None:
        """Get a node based on the workspace ID (= node ID) and path (list of folder names).

        Args:
            workspace_id (int): node ID of the workspace
            path (list): list of container items (top down), last item is name of to be retrieved item.
                         If path is empty the node of the volume is returned.
            show_error (bool, optional): treat as error if node is not found
        Returns:
            dict: Node information or None if no node with this path is found.
        """

        current_item_id = workspace_id

        # in case the path is an empty list
        # we will have the node of the workspace:
        node = self.get_node(current_item_id)

        for path_element in path:
            node = self.get_node_by_parent_and_name(current_item_id, path_element)
            current_item_id = self.get_result_value(node, "id")
            if not current_item_id:
                if show_error:
                    logger.error("Cannot find path element -> %s!", path_element)
                else:
                    logger.info("Cannot find path element -> %s.", path_element)
                return None
            logger.debug(
                "Traversing path element -> %s (%s)", path_element, str(current_item_id)
            )

        return node

    # end method definition

    def get_node_by_volume_and_path(
        self, volume_type: int, path: list | None = None
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
        logger.info(
            "Volume type -> %s has node ID -> %s", str(volume_type), str(volume_id)
        )

        current_item_id = volume_id

        # in case the path is an empty list
        # we will have the node of the volume:
        node = self.get_node(current_item_id)

        for path_element in path:
            node = self.get_node_by_parent_and_name(current_item_id, path_element)
            path_item_id = self.get_result_value(node, "id")
            if not path_item_id:
                logger.error(
                    "Cannot find path element -> %s in container with ID -> %s.",
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

        logger.info(
            "Get node with nickname -> %s; calling -> %s", nickname, request_url
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get node with nickname -> %s; status -> %s; error -> %s",
                        nickname,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info("Node with nickname -> %s not found.", nickname)
                return None

    # end method definition

    def get_subnodes(
        self,
        parent_node_id: int,
        filter_node_types: int = -2,
        filter_name: str = "",
        show_hidden: bool = False,
        limit: int = 100,
        page: int = 1,
        fields: str = "properties",  # per default we just get the most important information
    ) -> dict | None:
        """Get a subnodes of a parent node ID.

        Args:
            parent_node_id (int) is the node Id of the node
            filter_node_types (int, optional):
                -1 get all containers
                -2 get all searchable objects (default)
                -3 get all non-containers
            filter_name (str, optional): filter nodes for specific name (dfault = no filter)
            show_hidden (bool, optional): list also hidden items (default = False)
            limit (int, optional): maximum number of results (default = 100)
            page (int, optional): number of result page (default = 1 = 1st page)
            fields (str): which fields to retrieve. This can have a big impact on performance!
        Returns:
            dict: Subnodes information or None if no node with this parent ID is found.
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

        encodedQuery = urllib.parse.urlencode(query, doseq=True)

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(parent_node_id)
            + "/nodes"
            + "?{}".format(encodedQuery)
        )
        request_header = self.request_form_header()

        logger.info(
            "Get subnodes of parent node with ID -> %s; calling -> %s",
            str(parent_node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get subnodes for parent node with ID -> %s; status -> %s; error -> %s",
                    parent_node_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_node_actions(self, node_id: int, filter_actions: list = None) -> dict:
        """Get allowed actions for a node.

        Args:
            node_id (int): _description_
            filter_actions (list, optional): _description_

        Returns:
            dict: _description_
        """

        actions_post_body = {"ids": [node_id], "actions": filter_actions}

        request_url = self.config()["nodesUrlv2"] + "/actions"

        #        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/actions"
        request_header = self.request_form_header()

        logger.info(
            "Get actions for node with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=actions_post_body,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get actions for node with ID -> %s; status -> %s; error -> %s",
                    node_id,
                    response.status_code,
                    response.text,
                )
                return None

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

        renameNodePutBody = {"name": name, "description": description}

        if name_multilingual:
            renameNodePutBody["name_multilingual"] = name_multilingual
        if description_multilingual:
            renameNodePutBody["description_multilingual"] = description_multilingual

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.info(
            "Renaming node with ID -> %s to -> %s; calling -> %s",
            str(node_id),
            name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                data={"body": json.dumps(renameNodePutBody)},
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to rename node with ID -> %s to -> %s; status -> %s; error -> %s",
                    str(node_id),
                    name,
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info("Get volumes; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get volumes; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info(
            "Get volume type -> %s; calling -> %s", str(volume_type), request_url
        )

        retries = 0
        while True:
            try:
                response = requests.get(
                    url=request_url,
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=timeout,
                )
                if response.ok:
                    return self.parse_request_response(response)
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    logger.warning("Session has expired - try to re-authenticate...")
                    self.authenticate(True)
                    retries += 1
                else:
                    logger.error(
                        "Failed to get volume type -> %s; status -> %s; error -> %s",
                        str(volume_type),
                        response.status_code,
                        response.text,
                    )
                    return None
            except requests.exceptions.Timeout:
                if retries <= REQUEST_MAX_RETRIES:
                    logger.warning(
                        "Request timed out. Retrying in %s seconds...",
                        str(REQUEST_RETRY_DELAY),
                    )
                    retries += 1
                    time.sleep(REQUEST_RETRY_DELAY)  # Add a delay before retrying
                else:
                    logger.error(
                        "Failed to get volume type -> %s; timeout error",
                        str(volume_type),
                    )
                    # If it fails after REQUEST_MAX_RETRIES retries we let it wait forever
                    logger.warning("Turn timeouts off and wait forever...")
                    timeout = None

    # end method definition

    def check_node_name(self, parent_id: int, node_name: str) -> dict | None:
        """Get Volume information based on the volume type ID.

        Args:
            parent_id (int): ID of the parent location
            node_name (str): name of the new node
        Returns:
        """

        request_url = self.config()["validationUrl"]
        request_header = self.request_form_header()

        logger.info(
            "Check if node with name -> %s can be created in parent with ID -> %s; calling -> %s",
            node_name,
            str(parent_id),
            request_url,
        )

        checkNodeNamePostData = {"parent_id": parent_id, "names": [node_name]}

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data={"body": json.dumps(checkNodeNamePostData)},
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to check if node name -> %s can be created in parent with ID -> %s; status -> %s; error -> %s",
                    node_name,
                    str(parent_id),
                    response.status_code,
                    response.text,
                )
                return None

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
            logger.info("Download transport package from URL -> %s", package_url)

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

            logger.info(
                "Successfully downloaded package -> %s; status code -> %s",
                package_url,
                package.status_code,
            )
            file = package.content

        elif os.path.exists(package_url):
            logger.info("Using local package -> %s", package_url)
            file = open(file=package_url, mode="rb")

        else:
            logger.warning("Cannot access -> %s", package_url)
            return None

        uploadPostData = {"type": str(volume_type), "name": file_name}
        uploadPostFiles = [("file", (f"{file_name}", file, mime_type))]

        request_url = self.config()["nodesUrlv2"]
        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 500 response

        logger.info(
            "Uploading package -> %s with mime type -> %s; calling -> %s",
            file_name,
            mime_type,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=uploadPostData,
                files=uploadPostFiles,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to upload file -> %s to volume of type -> %s; status -> %s; error -> %s",
                    package_url,
                    str(volume_type),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def upload_file_to_parent(
        self, file_url: str, file_name: str, mime_type: str, parent_id: int
    ) -> dict | None:
        """Fetch a file from a URL or local filesystem and upload it to a Content Server parent (folder).

        Args:
            file_url (str): URL to download file or local file
            file_name (str): name of the file
            mime_type (str): mimeType of the file
            parent_id (int): parent (ID) of the file to upload
        Returns:
            dict: Upload response or None if the upload fails.
        """

        if file_url.startswith("http"):
            # Download file from remote location specified by the fileUrl
            # this must be a public place without authentication:
            logger.info("Download file from URL -> %s", file_url)

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

            logger.info(
                "Successfully downloaded file -> %s; status code -> %s",
                file_url,
                response.status_code,
            )
            file_content = response.content

        elif os.path.exists(file_url):
            logger.info("Uploading local file -> %s", file_url)
            file_content = open(file=file_url, mode="rb")

        else:
            logger.warning("Cannot access -> %s", file_url)
            return None

        uploadPostData = {
            "type": str(144),
            "name": file_name,
            "parent_id": str(parent_id),
        }
        uploadPostFiles = [("file", (f"{file_name}", file_content, mime_type))]

        request_url = self.config()["nodesUrlv2"]
        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 500 response

        logger.info(
            "Uploading file -> %s with mime type -> %s to parent with ID -> %s; calling -> %s",
            file_name,
            mime_type,
            str(parent_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=uploadPostData,
                files=uploadPostFiles,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to upload file -> %s to parent -> %s; status -> %s; error -> %s",
                    file_url,
                    str(parent_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        if file_url.startswith("http"):
            # Download file from remote location specified by the fileUrl
            # this must be a public place without authentication:
            logger.info("Download file from URL -> %s", file_url)

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

            logger.info(
                "Successfully downloaded file -> %s; status code -> %s",
                file_url,
                response.status_code,
            )
            file_content = response.content

        elif os.path.exists(file_url):
            logger.info("Uploading local file -> %s", file_url)
            file_content = open(file=file_url, mode="rb")

        else:
            logger.warning("Cannot access -> %s", file_url)
            return None

        uploadPostData = {"description": description}
        uploadPostFiles = [("file", (f"{file_name}", file_content, mime_type))]

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/versions"
        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 500 response

        logger.info(
            "Uploading file -> %s with mime type -> %s as new version to document node with ID -> %s; calling -> %s",
            file_name,
            mime_type,
            node_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=uploadPostData,
                files=uploadPostFiles,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add file -> %s as new version to document with ID -> %s; status -> %s; error -> %s",
                    file_url,
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info(
            "Get latest version of document with node ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get latest version of document with node ID -> %s; status -> %s; error -> %s",
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_document_content(self, node_id: int, version_number: str = "") -> bytes:
        """Get document content from Extended ECM.

        Args:
            node_id (int): node ID of the document to download
            version_number (str): version of the document to download.
                                     If version = "" then download the latest
                                     version.
        Returns:
            bytes: content of the file or None in case of an error.
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

        logger.info(
            "Retrieve document with node ID -> %s and version -> %s; calling -> %s",
            str(node_id),
            str(version_number),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                content = response.content
                break
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to download document with node ID -> %s; status -> %s; error -> %s",
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

        return content

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

        directory = os.path.dirname(file_path)
        if not os.path.exists(directory):
            logger.error("Directory -> %s does not exist", directory)
            return False

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

        logger.info(
            "Download document with node ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                content = response.content
                break
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to download document with node ID -> %s; status -> %s; error -> %s",
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return False

        logger.info("Writing document content to file -> %s", file_path)

        # Open file in write binary mode
        with open(file=file_path, mode="wb") as file:
            # Write the content to the file
            file.write(content)

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
        # request_header = self.cookie()
        request_header = self.request_download_header()

        logger.info("Download config file from URL -> %s", request_url)

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
            logger.info(
                "Search for all occurances of %s in the config file and replace them with %s",
                search,
                replace,
            )
            content = content.replace(search.encode("utf-8"), replace.encode("utf-8"))

        # Open file in write binary mode
        with open(file=file_path, mode="wb") as file:
            # Write the content to the file
            file.write(content)

        logger.info(
            "Successfully downloaded config file -> %s to -> %s; status code -> %s",
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

        searchPostBody = {
            "where": search_term,
            "lookfor": look_for,
            "page": page,
            "limit": limit,
        }

        if modifier:
            searchPostBody["modifier"] = modifier
        if slice_id > 0:
            searchPostBody["slice_id"] = slice_id
        if query_id > 0:
            searchPostBody["query_id"] = query_id
        if template_id > 0:
            searchPostBody["template_id"] = template_id

        request_url = self.config()["searchUrl"]
        request_header = self.request_form_header()

        logger.info("Search for term -> %s; calling -> %s", search_term, request_url)

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=searchPostBody,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to search for term -> %s; status -> %s; error -> %s",
                    search_term,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_external_system_connection(
        self, connection_name: str, show_error: bool = False
    ) -> dict | None:
        """Get Extended ECM external system connection (e.g. SAP, Salesforce, SuccessFactors).

        Args:
            connection_name (str): Name of the connection
            show_error (bool): treat as error if node is not found
        Returns:
            dict: External system Details or None if the REST call fails.
        """

        request_url = (
            self.config()["externalSystem"] + "/" + connection_name + "/config"
        )
        request_header = self.cookie()

        logger.info(
            "Get external system connection -> %s; calling -> %s",
            connection_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get external system connection -> %s; status -> %s; error -> %s",
                        connection_name,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info("External system -> %s not found.", connection_name)
                return None

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
            as_url (str): Application URL
            base_url (str): Base URL
            username (str): username (used for BASIC authentication)
            password (str): password (used for BASIC authentication)
            authentication_method: either BASIC (using username and password) or OAUTH
            client_id: OAUTH Client ID (only required if authenticationMethod = OAUTH)
            client_secret: OAUTH Client Secret (only required if authenticationMethod = OAUTH)
        Returns:
            dict: External system Details or None if the REST call fails.
        """

        externalSystemPostBody = {
            "external_system_name": connection_name,
            "conn_type": connection_type,
            "asurl": as_url,
            "baseurl": base_url,
            "username": username,
            "password": password,
        }

        if authentication_method == "OAUTH" and client_id and client_secret:
            externalSystemPostBody["authentication_method"] = str(authentication_method)
            externalSystemPostBody["client_id"] = str(client_id)
            externalSystemPostBody["client_secret"] = str(client_secret)

        request_url = self.config()["externalSystem"]
        request_header = self.cookie()

        logger.info(
            "Creating external system connection -> %s of type -> %s with URL -> %s; calling -> %s",
            connection_name,
            connection_type,
            as_url,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=externalSystemPostBody,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create external system connection -> %s; status -> %s; error -> %s",
                    connection_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def create_transport_workbench(self, workbench_name: str) -> dict | None:
        """Create a Workbench in the Transport Volume.

        Args:
            workbench_name (str): name of the workbench to be created
        Returns:
            dict: Create response or None if the creation fails.
        """

        createWorbenchPostData = {"type": "528", "name": workbench_name}

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        logger.info(
            "Create transport workbench -> %s; calling -> %s",
            workbench_name,
            request_url,
        )
        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=createWorbenchPostData,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create transport workbench -> %s; status -> %s; error -> %s",
                    workbench_name,
                    response.status_code,
                    response.text,
                )
                return None

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

        unpackPackagePostData = {"workbench_id": workbench_id}

        request_url = self.config()["nodesUrlv2"] + "/" + str(package_id) + "/unpack"
        request_header = self.request_form_header()

        logger.info(
            "Unpack transport package with ID -> %s into workbench with ID -> %s; calling -> %s",
            str(package_id),
            str(workbench_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=unpackPackagePostData,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to unpack package -> %s; to workbench -> %s; status -> %s; error -> %s",
                    str(package_id),
                    str(workbench_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info(
            "Deploy workbench with ID -> %s; calling -> %s",
            str(workbench_id),
            request_url,
        )

        retries = 0
        while True:
            # As this is a potentially long-running request we put it in try / except:
            try:
                response = requests.post(
                    url=request_url,
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=None,
                )
            except requests.exceptions.RequestException as exception:
                logger.error(
                    "Error deploying workbench -> %s; error -> %s",
                    str(workbench_id),
                    exception.strerror,
                )
                return None
            if response.ok:
                response_dict = self.parse_request_response(response)
                if not response_dict:
                    logger.error("Error deploying workbench -> %s", str(workbench_id))
                    return None
                return response_dict
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.warning(
                    "Failed to depoloy workbench -> %s; status -> %s; error -> %s",
                    workbench_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def deploy_transport(
        self,
        package_url: str,
        package_name: str,
        package_description: str = "",
        replacements: list | None = None,
    ) -> dict | None:
        """Main method to deploy a transport. This uses subfunctions to upload,
           unpackage and deploy the transport, and creates the required workbench.

        Args:
            package_url (str): URL to download the transport package.
            package_name (str): name of the transport package ZIP file
            package_description (str): description of the transport package
            replacements (list of dicts): list of replacement values to be applied
                                          to all XML files in transport;
                                          each dict needs to have two values:
                                          - placeholder: text to replace
                                          - value: text to replace with
        Returns:
            dict: Deploy response or None if the deployment fails.
        """

        if replacements is None:
            replacements = []

        # Preparation: get volume IDs for Transport Warehouse (root volume and Transport Packages)
        response = self.get_volume(525)
        transport_root_volume_id = self.get_result_value(response, "id")
        if not transport_root_volume_id:
            logger.error("Failed to retrieve transport root volume")
            return None
        logger.info("Transport root volume ID -> %s", str(transport_root_volume_id))

        response = self.get_node_by_parent_and_name(
            transport_root_volume_id, "Transport Packages"
        )
        transport_package_volume_id = self.get_result_value(response, "id")
        if not transport_package_volume_id:
            logger.error("Failed to retrieve transport package volume")
            return None
        logger.info(
            "Transport package volume ID -> %s", str(transport_package_volume_id)
        )

        # Step 1: Upload Transport Package
        logger.info("Check if transport package -> %s already exists...", package_name)
        response = self.get_node_by_parent_and_name(
            transport_package_volume_id, package_name
        )
        package_id = self.get_result_value(response, "id")
        if package_id:
            logger.info(
                "Transport package -> %s does already exist; existing package ID -> %s",
                package_name,
                str(package_id),
            )
        else:
            logger.info(
                "Transport package -> %s does not yet exist, loading from -> %s",
                package_name,
                package_url,
            )
            # If we have string replacements configured execute them now:
            if replacements:
                logger.info(
                    "Transport -> %s has replacements -> %s",
                    package_name,
                    str(replacements),
                )
                self.replace_transport_placeholders(package_url, replacements)
            else:
                logger.info("Transport -> %s has no replacements!", package_name)
            # Upload package to Extended ECM:
            response = self.upload_file_to_volume(
                package_url, package_name, "application/zip", 531
            )
            package_id = self.get_result_value(response, "id")
            if not package_id:
                logger.error("Failed to upload transport package -> %s", package_url)
                return None
            logger.info(
                "Successfully uploaded transport package -> %s; new package ID -> %s",
                package_name,
                str(package_id),
            )

        # Step 2: Create Transport Workbench (if not yet exist)
        workbench_name = package_name.split(".")[0]
        logger.info("Check if workbench -> %s is already deployed...", workbench_name)
        # check if the package name has the suffix "(deployed)" - this indicates it is alreadey
        # successfully deployed (see renaming at the end of this method)
        response = self.get_node_by_parent_and_name(
            transport_root_volume_id, workbench_name + " (deployed)"
        )
        workbench_id = self.get_result_value(response, "id")
        if workbench_id:
            logger.info(
                "Workbench -> %s has already been deployed successfully; existing workbench ID -> %s; skipping transport",
                workbench_name,
                str(workbench_id),
            )
            # we return and skip this transport...
            return response
        else:
            logger.info("Check if workbench -> %s already exists...", workbench_name)
            response = self.get_node_by_parent_and_name(
                transport_root_volume_id, workbench_name
            )
            workbench_id = self.get_result_value(response, "id")
            if workbench_id:
                logger.info(
                    "Workbench -> %s does already exist but is not successfully deployed; existing workbench ID -> %s",
                    workbench_name,
                    str(workbench_id),
                )
            else:
                response = self.create_transport_workbench(workbench_name)
                workbench_id = self.get_result_value(response, "id")
                if not workbench_id:
                    logger.error("Failed to create workbench -> %s", workbench_name)
                    return None
                logger.info(
                    "Successfully created workbench -> %s; new workbench ID -> %s",
                    workbench_name,
                    str(workbench_id),
                )

        # Step 3: Unpack Transport Package to Workbench
        logger.info(
            "Unpack transport package -> %s (%s) to workbench -> %s (%s)",
            package_name,
            str(package_id),
            workbench_name,
            str(workbench_id),
        )
        response = self.unpack_transport_package(package_id, workbench_id)
        if not response:
            logger.error("Failed to unpack the transport package -> %s", package_name)
            return None
        logger.info(
            "Successfully unpackaged to workbench -> %s (%s)",
            workbench_name,
            str(workbench_id),
        )

        # Step 4: Deploy Workbench
        logger.info("Deploy workbench -> %s (%s)", workbench_name, str(workbench_id))
        response = self.deploy_workbench(workbench_id)
        if not response:
            logger.error("Failed to deploy workbench -> %s", workbench_name)
            return None

        logger.info(
            "Successfully deployed workbench -> %s (%s)",
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
        """Search and replace strings in the XML files of the transport packlage

        Args:
            zip_file_path (str): path to transport zip file
            replacements (list of dicts): list of replacement values; dict needs to have two values:
                                         * placeholder: text to replace
                                         * value: text to replace with
        Returns:
            Filename to the updated zip file
        """

        if not os.path.isfile(zip_file_path):
            logger.error("Zip file -> %s not found.", zip_file_path)
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
                logger.info(
                    "Replacement for transport -> %s is disabled. Skipping...",
                    zip_file_path,
                )
                continue
            # there are two types of replacements:
            # 1. XPath - more elegant and powerful
            # 2. Search & Replace - basically treat the XML file like a text file and do a search & replace
            if "xpath" in replacement:
                logger.info(
                    "Using xpath -> %s to narrow down the replacement",
                    replacement["xpath"],
                )
                if "setting" in replacement:
                    logger.info(
                        "Looking up setting -> %s in XML element",
                        replacement["setting"],
                    )
                if "assoc_elem" in replacement:
                    logger.info(
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
                    logger.info(
                        "Placeholder and replacement are identical -> %s. Skipping...",
                        replacement["value"],
                    )
                    continue
                logger.info(
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
                logger.info(
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
        logger.info(
            "Content of transport -> %s has been modified - repacking to new zip file -> %s",
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
        logger.info(
            "Rename orginal transport zip file -> %s to -> %s",
            zip_file_path,
            old_zip_file_path,
        )
        os.rename(zip_file_path, old_zip_file_path)
        logger.info(
            "Rename new transport zip file -> %s to -> %s",
            new_zip_file_path,
            zip_file_path,
        )
        os.rename(new_zip_file_path, zip_file_path)

        # Return the path to the new zip file
        return True

        # end method definition

    def get_workspace_types(
        self, expand_workspace_info: bool = True, expand_templates: bool = True
    ) -> dict | None:
        """Get all workspace types configured in Extended ECM.

        Args:
            expand_workspace_info (bool, optional): controls if the workspace info
                                                    is returned as well
            expand_workspace_info (bool, optional): controls if the list of workspace templates
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

        request_url = self.config()["businessworkspacetypes"]
        if expand_templates:
            request_url += "?expand_templates=true"
        else:
            request_url += "?expand_templates=false"
        if expand_workspace_info:
            request_url += "&expand_wksp_info=true"
        else:
            request_url += "&expand_wksp_info=false"

        request_header = self.request_form_header()

        logger.info("Get workspace types; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get workspace types; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_business_object_type(
        self, external_system_id: str, type_name: str
    ) -> dict | None:
        """Get business object type information.

        Args:
            external_system_id (str): external system Id (such as "TM6")
            type_name (str): type name (such as "SAP Customer")
        Returns:
            dict: Workspace Type information or None if the request fails.
        """

        request_url = (
            self.config()["externalSystem"]
            + "/"
            + str(external_system_id)
            + "/botypes/"
            + str(type_name)
        )
        request_header = self.request_form_header()

        logger.info(
            "Get business object type -> %s for external system -> %s; calling -> %s",
            type_name,
            external_system_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get business object type -> %s; status -> %s; error -> %s",
                    type_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_workspace_create_form(
        self,
        template_id: int,
        external_system_id: int = None,
        bo_type: int = None,
        bo_id: int = None,
        parent_id: int = None,
    ) -> dict | None:
        """Get the Workspace create form.

        Args:
            template_id (int): ID of the workspace template
            external_system_id (str): identifier of the external system (None if no external system)
            bo_type (str, optional): business object type (None if no external system)
            bo_id (str, optional): business object identifier / key (None if no external system)
            parent_id (str, optional): parent ID of the workspaces. Needs only be specified in special
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
            logger.info(
                "Use business object connection -> (%s, %s, %s) for workspace template with ID -> %s",
                str(external_system_id),
                str(bo_type),
                str(bo_id),
                str(template_id),
            )
        request_header = self.request_form_header()

        logger.info(
            "Get workspace create form for template with ID -> %s; calling -> %s",
            str(template_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get workspace create form for template -> %s; status -> %s; error -> %s",
                    str(template_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_workspace(self, node_id: int) -> dict | None:
        """Get a workspace based on the node ID.

        Args:
            node_id (int) is the node Id of the workspace
        Returns:
            dict: Workspace node information or None if no node with this ID is found.

            Example result:
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

        request_url = self.config()["businessworkspaces"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.info(
            "Get workspace with ID -> %s; calling -> %s", str(node_id), request_url
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get workspace with ID -> %s; status -> %s; error -> %s",
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_workspace_instances(
        self, type_name: str = "", type_id: int = None, expanded_view: bool = True
    ):
        """Get all workspace instances of a given type. This is a convenience
           wrapper method for get_workspace_by_type_and_name()

        Args:
            type_name (str, optional): name of the workspace type
            type_id (int, optional): ID of the workspace_type
            expanded_view (bool, optional): if 'False' then just search in recently
                                               accessed business workspace for this name and type
                                               if 'True' (this is the default) then search in all
                                               workspaces for this name and type
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
    ) -> dict | None:
        """Lookup workspace based on workspace type and workspace name.

        Args:
            type_name (str): name of the workspace type
            type_id (int, optional): ID of the workspace_type
            name (str, optional): name of the workspace, if "" then deliver all instances
                                  of the given workspace type
            expanded_view (bool, optional): if 'False' then just search in recently
                                            accessed business workspace for this name and type
                                            if 'True' (this is the default) then search in all
                                            workspaces for this name and type
        Returns:
            dict: Workspace information or None if the workspace is not found.
        """

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

        encodedQuery = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["businessworkspaces"] + "?{}".format(encodedQuery)
        request_header = self.request_form_header()

        if name:
            logger.info(
                "Get workspace with name -> %s and type -> %s; calling -> %s",
                name,
                type_name,
                request_url,
            )
        else:
            logger.info(
                "Get all workspace instances of type -> %s; calling -> %s",
                type_name,
                request_url,
            )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                if name:
                    logger.warning(
                        "Failed to get workspace -> %s of type -> %s; status -> %s; error -> %s",
                        name,
                        type_name,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.warning(
                        "Failed to get workspace instances of type -> %s; status -> %s; error -> %s",
                        type_name,
                        response.status_code,
                        response.text,
                    )
                return None

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
            business_object_type (str): type of the Business object, e.g. KNA1 for SAP customers
            business_object_id (str): ID of the business object in the external system
            return_workspace_metadata (bool): Whether or not workspace metadata (categories) should be returned
            show_error (bool): treat as error if node is not found
        Returns:
            dict: Workspace node information or None if no node with this ID is found.

            Example result:
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
            self.config()["externalSystem"]
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

        logger.info(
            "Get workspace via external system -> %s (Business Object Type -> %s; Business Object ID -> %s); calling -> %s",
            external_system_name,
            business_object_type,
            business_object_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get workspace via external system -> %s (Business Object Type -> %s; Business Object ID -> %s); status -> %s; error -> %s",
                        external_system_name,
                        business_object_type,
                        business_object_id,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info(
                        "Cannot fing workspace via external system -> %s (Business Object Type -> %s; Business Object ID -> %s); status -> %s; error -> %s",
                        external_system_name,
                        business_object_type,
                        business_object_id,
                        response.status_code,
                        response.text,
                    )
                return None

    # end method definition

    def create_workspace(
        self,
        workspace_template_id: int,
        workspace_name: str,
        workspace_description: str,
        workspace_type: int,
        category_data: dict | None = None,
        external_system_id: int = None,
        bo_type: int | None = None,
        bo_id: int | None = None,
        parent_id: int | None = None,
    ) -> dict | None:
        """Create a new business workspace.

        Args:
            workspace_template_id (int): ID of the workspace template
            workspace_name (str): name of the workspace
            workspace_description (str): description of the workspace
            workspace_type (int): type ID of the workspace
            category_data (dict): category and attributes
            external_system_id (str, optional): identifier of the external system (None if no external system)
            bo_type (str, optional): business object type (None if no external system)
            bo_id (str, optional): business object identifier / key (None if no external system)
            parent_id (str, optional): parent ID of the workspaces. Needs only be specified in special
                                       cases where workspace location cannot be derived from workspace
                                       type definition
        Returns:
            dict: Workspace Create Form data or None if the request fails.
        """

        # Avoid linter warning W0102
        if category_data is None:
            category_data = {}

        createWorkspacePostData = {
            "template_id": str(workspace_template_id),
            "name": workspace_name,
            "description": workspace_description,
            "wksp_type_id": str(workspace_type),
            "type": str(848),
            "roles": category_data,
        }

        # Is this workspace connected to a business application / external system?
        if external_system_id and bo_type and bo_id:
            createWorkspacePostData["ext_system_id"] = str(external_system_id)
            createWorkspacePostData["bo_type"] = str(bo_type)
            createWorkspacePostData["bo_id"] = str(bo_id)
            logger.info(
                "Use business object connection -> (%s, %s, %s) for workspace -> %s",
                str(external_system_id),
                str(bo_type),
                str(bo_id),
                workspace_name,
            )

        # If workspace creation location cannot be derived from the workspace type
        # there may be an optional parent parameter passed to this method. This can
        # also be the case if workspaces are nested into each other:
        if parent_id is not None:
            createWorkspacePostData["parent_id"] = parent_id
            logger.info(
                "Use specified location -> %s for workspace -> %s",
                str(parent_id),
                workspace_name,
            )
        else:
            logger.info(
                "Determine location of workspace -> %s via workspace type -> %s",
                workspace_name,
                str(workspace_type),
            )

        request_url = self.config()["businessworkspaces"]
        request_header = self.request_form_header()

        logger.info(
            "Create workspace -> %s with type -> %s from template -> %s; calling -> %s",
            workspace_name,
            str(workspace_type),
            str(workspace_template_id),
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            # See https://developer.opentext.com/apis/14ba85a7-4693-48d3-8c93-9214c663edd2/4403207c-40f1-476a-b794-fdb563e37e1f/07229613-7ef4-4519-8b8a-47eaff639d42#operation/createBusinessWorkspace
            response = requests.post(
                url=request_url,
                headers=request_header,
                data={"body": json.dumps(createWorkspacePostData)},
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create workspace -> %s from template with ID -> %s; status -> %s; error -> %s",
                    workspace_name,
                    str(workspace_template_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def create_workspace_relationship(
        self,
        workspace_id: int,
        related_workspace_id: int,
        relationship_type: str = "child",
    ) -> dict | None:
        """Create a relationship between two workspaces.

        Args:
            workspace_id (int): ID of the workspace
            related_workspace_id (int): ID of the related workspace
            relationship_type (str, optional): "parent" or "child" - "child" is default if omitted
        Returns:
            dict: Workspace Relationship data (json) or None if the request fails.
        """

        createWorkspaceRelationshipPostData = {
            "rel_bw_id": str(related_workspace_id),
            "rel_type": relationship_type,
        }

        request_url = self.config()["businessworkspaces"] + "/{}/relateditems".format(
            workspace_id
        )
        request_header = self.request_form_header()

        logger.info(
            "Create workspace relationship between -> %s and -> %s; calling -> %s",
            str(workspace_id),
            str(related_workspace_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=createWorkspaceRelationshipPostData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create workspace relationship between -> %s and -> %s; status -> %s; error -> %s",
                    str(workspace_id),
                    str(related_workspace_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_workspace_relationships(self, workspace_id: int) -> dict | None:
        """Get the Workspace relationships to other workspaces.

        Args:
            workspace_id (int): ID of the workspace template
        Returns:
            dict: Workspace relationships or None if the request fails.
        """

        request_url = (
            self.config()["businessworkspaces"]
            + "/"
            + str(workspace_id)
            + "/relateditems"
        )
        request_header = self.request_form_header()

        logger.info(
            "Get related workspaces for workspace with ID -> %s; calling -> %s",
            str(workspace_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get related workspaces of workspace with ID -> %s; status -> %s; error -> %s",
                    str(workspace_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_workspace_roles(self, workspace_id: int) -> dict | None:
        """Get the Workspace roles.

        Args:
            workspace_id (int): ID of the workspace template
        Returns:
            dict: Workspace Roles data or None if the request fails.
        """

        request_url = (
            self.config()["businessworkspaces"] + "/" + str(workspace_id) + "/roles"
        )
        request_header = self.request_form_header()

        logger.info(
            "Get workspace roles of workspace with ID -> %s; calling -> %s",
            str(workspace_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get roles of workspace with ID -> %s; status -> %s; error -> %s",
                    str(workspace_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_member_to_workspace(
        self, workspace_id: int, role_id: int, member_id: int, show_warning: bool = True
    ) -> dict | None:
        """Add member to a workspace role. Check that the user is not yet a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            member_id (int): User or Group Id
            show_warning (bool, optional): if True shows a warning if member is already in role
        Returns:
            dict: Workspace Role Membership or None if the request fails.
        """

        addMemberToWorkspacePostData = {"id": str(member_id)}

        request_url = self.config()[
            "businessworkspaces"
        ] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        logger.info(
            "Check if user/group with ID -> %s is already in role with ID -> %s of workspace with ID -> %s; calling -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
            request_url,
        )

        response = requests.get(
            url=request_url,
            headers=request_header,
            cookies=self.cookie(),
            timeout=None,
        )
        if not response.ok:
            logger.error(
                "Failed to get workspace members; status -> %s; error -> %s",
                response.status_code,
                response.text,
            )
            return None

        workspace_members = self.parse_request_response(response)

        if self.exist_result_item(workspace_members, "id", member_id):
            if show_warning:
                logger.warning(
                    "User/group with ID -> %s is already a member of role with ID -> %s of workspace with ID -> %s",
                    str(member_id),
                    str(role_id),
                    str(workspace_id),
                )
            return workspace_members

        logger.info(
            "Add user/group with ID -> %s to role with ID -> %s of workspace with ID -> %s; calling -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
            request_url,
        )

        response = requests.post(
            url=request_url,
            headers=request_header,
            data=addMemberToWorkspacePostData,
            cookies=self.cookie(),
            timeout=None,
        )

        if response.ok:
            return self.parse_request_response(response)
        else:
            logger.error(
                "Failed to add user/group with ID -> %s to role with ID -> %s of workspace with ID -> %s; status -> %s; error -> %s",
                str(member_id),
                str(role_id),
                str(workspace_id),
                response.status_code,
                response.text,
            )
            return None

    # end method definition

    def remove_member_from_workspace(
        self, workspace_id: int, role_id: int, member_id: int, show_warning: bool = True
    ) -> dict | None:
        """Remove a member from a workspace role. Check that the user is currently a member.

        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
            member_id (int): User or Group Id
            show_warning (bool, optional): if True shows a warning if member is not in role
        Returns:
            dict: Workspace Role Membership or None if the request fails.
        """

        request_url = self.config()[
            "businessworkspaces"
        ] + "/{}/roles/{}/members".format(workspace_id, role_id)
        request_header = self.request_form_header()

        logger.info(
            "Check if user/group with ID -> %s is in role with ID -> %s of workspace with ID -> %s; calling -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
            request_url,
        )

        workspaceMembershipResponse = requests.get(
            url=request_url,
            headers=request_header,
            cookies=self.cookie(),
            timeout=None,
        )
        if not workspaceMembershipResponse.ok:
            logger.error(
                "Failed to get workspace members; status -> %s; error -> %s",
                workspaceMembershipResponse.status_code,
                workspaceMembershipResponse.text,
            )
            return None

        workspace_members = self.parse_request_response(workspaceMembershipResponse)

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
            "businessworkspaces"
        ] + "/{}/roles/{}/members/{}".format(workspace_id, role_id, member_id)

        logger.info(
            "Removing user/group with ID -> %s from role with ID -> %s of workspace with ID -> %s; calling -> %s",
            str(member_id),
            str(role_id),
            str(workspace_id),
            request_url,
        )

        workspaceMembershipResponse = requests.delete(
            url=request_url,
            headers=request_header,
            cookies=self.cookie(),
            timeout=None,
        )

        if workspaceMembershipResponse.ok:
            return self.parse_request_response(workspaceMembershipResponse)
        else:
            logger.error(
                "Failed to remove user/group with ID -> %s from role with ID -> %s of workspace with ID -> %s; status -> %s; error -> %s",
                str(member_id),
                str(role_id),
                str(workspace_id),
                workspaceMembershipResponse.status_code,
                workspaceMembershipResponse.text,
            )
            return None

    # end method definition

    def assign_workspace_permissions(
        self, workspace_id: int, role_id: int, permissions: list, apply_to: int = 2
    ) -> dict | None:
        """Update permissions of a workspace role
        Args:
            workspace_id (int): ID of the workspace
            role_id (int): ID of the role
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
            apply_to (int):  0 = this item
                                 1 = sub-items
                                 2 = This item and sub-items (default)
                                 3 = This item and immediate sub-items
        Returns:
            dict: Workspace Role Membership or None if the request fails.
        """

        request_url = self.config()["businessworkspaces"] + "/{}/roles/{}".format(
            workspace_id, role_id
        )

        request_header = self.request_form_header()

        logger.info(
            "Updating Permissions of role with ID -> %s of workspace with ID -> %s with permissions -> %s; calling -> %s",
            str(role_id),
            str(workspace_id),
            str(permissions),
            request_url,
        )

        permissionPostData = {
            "permissions": permissions,
            "apply_to": apply_to,
        }

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                headers=request_header,
                data={"body": json.dumps(permissionPostData)},
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update permissions for role with ID -> %s of workspace with ID -> %s; status -> %s; error -> %s",
                    str(role_id),
                    str(workspace_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        updateWorkspaceIconPostBody = {
            "file_content_type": file_mimetype,
            "file_filename": os.path.basename(file_path),
        }

        uploadPostFiles = [
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
            self.config()["businessworkspaces"] + "/" + str(workspace_id) + "/icons"
        )

        request_header = self.cookie()

        logger.info(
            "Update icon for workspace ID -> %s with icon file -> %s; calling -> %s",
            str(workspace_id),
            file_path,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=updateWorkspaceIconPostBody,
                headers=request_header,
                cookies=self.cookie(),
                files=uploadPostFiles,
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update workspace ID -> %s with new icon -> %s; status -> %s; error -> %s",
                    str(workspace_id),
                    file_path,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def create_item(
        self,
        parent_id: int,
        item_type: str,
        item_name: str,
        item_description: str = "",
        url: str = "",
        original_id: int = 0,
    ) -> dict | None:
        """Create an Extended ECM item. This REST call is somewhat limited. It cannot set favortie (featured item) or hidden item.
           It does also not accept owner group information.

        Args:
            parent_id (int): node ID of the parent
            item_type (str): type of the item (e.g. 0 = foler, 140 = URL)
            item_name (str): name of the item
            item_description (str, optional): description of the item
            url (str, optional): address of the URL item (if it is an URL item type)
            original_id (int, optional): required if a shortcut item is created
        Returns:
            dict: Request response of the create item call or None if the REST call has failed.
        """

        createItemPostData = {
            "parent_id": parent_id,
            "type": item_type,
            "name": item_name,
            "description": item_description,
        }

        if url:
            createItemPostData["url"] = url
        if original_id > 0:
            createItemPostData["original_id"] = original_id

        request_url = self.config()["nodesUrlv2"]
        request_header = self.request_form_header()

        logger.info(
            "Create item -> %s (type -> %s) under parent with ID -> %s; calling -> %s",
            item_name,
            item_type,
            str(parent_id),
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            response = requests.post(
                url=request_url,
                data={"body": json.dumps(createItemPostData)},
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create item -> %s; status -> %s; error -> %s",
                    item_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def update_item(
        self,
        node_id: int,
        parent_id: int = 0,
        item_name: str = "",
        item_description: str = "",
    ) -> dict | None:
        """Update an Extended ECM item (parent, name, description). Changing the parent ID is
           a move operation. If parent ID = 0 the item will not be moved.

        Args:
            node_id (int): ID of the node
            parent_id (int): node ID of the new parent (move operation)
            item_name (str): new name of the item
            item_description (str): new description of the item
        Returns:
            dict: Response of the update item request or None if the REST call has failed.
        """

        updateItemPutData = {
            "name": item_name,
            "description": item_description,
        }

        if parent_id:
            # this is a move operation
            updateItemPutData["parent_id"] = parent_id

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id)
        request_header = self.request_form_header()

        logger.info(
            "Update item -> %s with data -> %s; calling -> %s",
            item_name,
            str(updateItemPutData),
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            response = requests.put(
                url=request_url,
                data={"body": json.dumps(updateItemPutData)},
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update item -> %s; status -> %s; error -> %s",
                    item_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_document_templates(self, parent_id: int):
        """Get all document templates for a given target location.

        Args:
            parent_id (int): node ID of target location (e.g. a folder)

        Returns:
            dict: response of the REST call (converted to a Python dictionary)
                        Example output:
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

        logger.info(
            "Get document templates for target location -> %s (parent ID); calling -> %s",
            str(parent_id),
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get document templates for parent folder -> %s; status -> %s; error -> %s",
                    str(parent_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def create_document_from_template(
        self,
        template_id: int,
        parent_id: int,
        classification_id: int,
        category_data: dict,
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
            doc_name (str): name of the item
            doc_description (str, optional): description of the item
        """

        createDocumentPostData = {
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

        logger.info(
            "Create document -> %s from template with ID -> %s in target location -> %s (parent ID) with classification ID -> %s; calling -> %s",
            doc_name,
            str(template_id),
            str(parent_id),
            str(classification_id),
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            response = requests.post(
                url=request_url,
                # this seems to only work with a "body" tag and is different form the documentation
                # on developer.opentext.com
                data={"body": json.dumps(createDocumentPostData)},
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create document -> %s; status -> %s; error -> %s",
                    doc_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_web_report_parameters(self, nickname: str):
        """Get parameters of a Web Report in Extended ECM. These are defined on the Web Report node
            (Properties --> Parameters)

        Args:
            nickname (str): nickname of the Web Reports node.
        Returns:
            Response: list of Web Report parameters. Each list item is a dict describing the parameter.
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

        logger.info(
            "Retrieving parameters of Web Report with nickname -> %s; calling -> %s",
            nickname,
            request_url,
        )
        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                # Return the "data" element which is a list of dict items:
                result_dict = self.parse_request_response(response)
                logger.debug("Web Report parameters result -> %s", str(result_dict))
                if not result_dict.get("data"):
                    return None
                return result_dict["data"]
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to retrieve parameters of Web Report with nickname -> %s; status -> %s; error -> %s",
                    nickname,
                    response.status_code,
                    response.text,
                )
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

        logger.info(
            "Running Web Report with nickname -> %s; calling -> %s",
            nickname,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=web_report_parameters,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to run web report with nickname -> %s; status -> %s; error -> %s",
                    nickname,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def install_cs_application(self, application_name: str) -> dict | None:
        """Install a CS Application (based on WebReports)

        Args:
            application_name (str): name of the application (e.g. OTPOReports, OTRMReports, OTRMSecReports)
        Returns:
            dict: Response or None if the installation of the CS Application has failed.
        """

        installCSApplicationPostData = {"appName": application_name}

        request_url = self.config()["csApplicationsUrl"] + "/install"
        request_header = self.request_form_header()

        logger.info(
            "Install CS Application -> %s; calling -> %s", application_name, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=installCSApplicationPostData,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to install CS Application -> %s; status -> %s; error -> %s",
                    application_name,
                    response.status_code,
                    response.text,
                )
                return None

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

        assignmentPostData = {
            "subject": subject,
            "instruction": instruction,
            "assignees": assignees,
        }

        request_url = (
            self.config()["nodesUrlv2"] + "/" + str(node_id) + "/xgovassignments"
        )

        request_header = self.request_form_header()

        logger.info(
            "Assign item with ID -> %s to assignees -> %s (subject -> %s); calling -> %s",
            str(node_id),
            str(assignees),
            subject,
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "add_assignment" tag.
            response = requests.post(
                url=request_url,
                data={"add_assignment": json.dumps(assignmentPostData)},
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to assign item with ID -> %s to assignees -> %s (subject -> %s); status -> %s; error -> %s",
                    str(node_id),
                    str(assignees),
                    subject,
                    response.status_code,
                    response.text,
                )
                return None

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

        permissionPostData = {
            "permissions": permissions,
            "apply_to": apply_to,
        }

        # Assignees can be specified for owner and group and must be specified for custom:
        #
        if assignee:
            permissionPostData["right_id"] = assignee

        request_url = (
            self.config()["nodesUrlv2"]
            + "/"
            + str(node_id)
            + "/permissions/"
            + assignee_type
        )

        request_header = self.request_form_header()

        logger.info(
            "Assign permissions -> %s to item with ID -> %s; assignee type -> %s; calling -> %s",
            str(permissions),
            str(node_id),
            assignee_type,
            request_url,
        )

        retries = 0
        while True:
            # This REST API needs a special treatment: we encapsulate the payload as JSON into a "body" tag.
            if assignee_type == "custom":
                # Custom also has a REST POST - we prefer this one as to
                # also allows to add a new assigned permission (user or group):
                response = requests.post(
                    url=request_url,
                    data={"body": json.dumps(permissionPostData)},
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=None,
                )
            else:
                # Owner, Owner Group and Public require REST PUT:
                response = requests.put(
                    url=request_url,
                    data={"body": json.dumps(permissionPostData)},
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=None,
                )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to assign permissions -> %s to item with ID -> %s; status -> %s; error -> %s",
                    str(permissions),
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_node_categories(self, node_id: int, metadata: bool = True):
        """Get categories assigned to a node.

        Args:
            node_id (int): ID of the node to get the categories for.
            metadata (bool, optional): expand the attribute definitions of the category. Default is True
        Returns:
            dict: category response or None if the call to the REST API fails.
        """

        request_url = self.config()["nodesUrlv2"] + "/" + str(node_id) + "/categories"
        if metadata:
            request_url += "?metadata"
        request_header = self.request_form_header()

        logger.info(
            "Get categories of node with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get categories for node ID -> %s; status -> %s; error -> %s",
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_node_category(self, node_id: int, category_id: int, metadata: bool = True):
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

        logger.info(
            "Get category with ID -> %s on node with ID -> %s; calling -> %s",
            str(category_id),
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get category with ID -> %s for node ID -> %s; status -> %s; error -> %s",
                    str(category_id),
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

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

    def get_node_category_definition(self, node_id: int, category_name: str):
        """Get category definition (category id and attribute IDs and types)

        Args:
            node_id (int): node to read the category definition from
                           (e.g. a workspace template or a document template or a target folder)
                           This should NOT be the category definition object!
            category_name (str): name of the category
        Returns:
            int: category ID
            dict: keys are the attribute names. values are sub-dictionaries with the id and type of the attribute.
                        Example:
                        {
                            'Status': {
                                'id': '12532_2',
                                'type': 'String'
                            },
                            'Legal Approval': {
                                'id': '12532_3',
                                'type': 'user'
                            },
                            ...
                        }
        """

        attribute_definitions = {}
        cat_id = -1

        response = self.get_node_categories(node_id)
        if response and response["results"]:
            for categories in response["results"]:
                keys = categories["metadata"]["categories"].keys()
                cat_id = next((key for key in keys if "_" not in key), -1)
                cat_name = categories["metadata"]["categories"][cat_id]["name"]
                if cat_name != category_name:
                    continue
                for att_id in categories["metadata"]["categories"]:
                    if not "_" in att_id:
                        continue
                    att_name = categories["metadata"]["categories"][att_id]["name"]
                    if categories["metadata"]["categories"][att_id]["persona"]:
                        att_type = categories["metadata"]["categories"][att_id][
                            "persona"
                        ]
                    else:
                        att_type = categories["metadata"]["categories"][att_id][
                            "type_name"
                        ]
                    attribute_definitions[att_name] = {"id": att_id, "type": att_type}
        return cat_id, attribute_definitions

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
            logger.info(
                "Category with ID -> %s is not yet assigned to node ID -> %s. Assigning it now...",
                str(category_id),
                str(node_id),
            )
            categoryPostData = {
                "category_id": category_id,
            }

            logger.info(
                "Assign category with ID -> %s to item with ID -> %s; calling -> %s",
                str(category_id),
                str(node_id),
                request_url,
            )

            retries = 0
            while True:
                response = requests.post(
                    url=request_url,
                    data=categoryPostData,
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=None,
                )
                if response.ok:
                    break
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    logger.warning("Session has expired - try to re-authenticate...")
                    self.authenticate(True)
                    retries += 1
                else:
                    logger.error(
                        "Failed to assign category with ID -> %s to node with ID -> %s; status -> %s; error -> %s",
                        str(category_id),
                        str(node_id),
                        response.status_code,
                        response.text,
                    )
                    return False

        #
        # 2. Set Inheritance
        #

        request_url_inheritance = request_url + "/" + str(category_id) + "/inheritance"

        retries = 0
        while True:
            if inheritance:
                # Enable inheritance
                response = requests.post(
                    url=request_url_inheritance,
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=None,
                )
            else:
                # Disable inheritance
                response = requests.delete(
                    url=request_url_inheritance,
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=None,
                )
            if response.ok:
                break
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to set inheritance for category with ID -> %s on node with ID -> %s; status -> %s; error -> %s",
                    str(category_id),
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return False

        #
        # 3. Apply to sub-items
        #

        if apply_to_sub_items:
            request_url_apply_sub_items = request_url + "/apply"

            categoryPostData = {
                "categories": [{"id": category_id, "action": apply_action}],
                "add_version": add_version,
                "clear_existing_categories": clear_existing_categories,
            }

            retries = 0
            while True:
                # we need to wrap the body of this POST call into a "body"
                # tag. This is documented worngly on developer.opentext.com
                response = requests.post(
                    url=request_url_apply_sub_items,
                    data={"body": json.dumps(categoryPostData)},
                    headers=request_header,
                    cookies=self.cookie(),
                    timeout=None,
                )
                if response.ok:
                    break
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    logger.warning("Session has expired - try to re-authenticate...")
                    self.authenticate(True)
                    retries += 1
                else:
                    logger.error(
                        "Failed to apply category with ID -> %s to sub-items of node with ID -> %s; status -> %s; error -> %s",
                        str(category_id),
                        str(node_id),
                        response.status_code,
                        response.text,
                    )
                    return False
        return True

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
            attribute_id (int): ID of the attribute
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
            logger.info(
                "Assign value -> %s to category with ID -> %s, set ID -> %s, row -> %s, attribute ID -> %s on node with ID -> %s; calling -> %s",
                str(value),
                str(category_id),
                str(set_id),
                str(set_row),
                str(attribute_id),
                str(node_id),
                request_url,
            )
            categoryPutData = {
                "category_id": category_id,
                "{}_{}_{}_{}".format(category_id, set_id, set_row, attribute_id): value,
            }
        else:
            logger.info(
                "Assign value -> %s to category ID -> %s, attribute ID -> %s on node with ID -> %s; calling -> %s",
                str(value),
                str(category_id),
                str(attribute_id),
                str(node_id),
                request_url,
            )
            categoryPutData = {
                "category_id": category_id,
                "{}_{}".format(category_id, attribute_id): value,
            }

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                data=categoryPutData,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to set value -> %s for category with ID -> %s, attribute ID -> %s on node ID -> %s; status -> %s; error -> %s",
                    str(value),
                    str(category_id),
                    str(attribute_id),
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        classificationPostData = {
            "class_id": classification_list,
            "apply_to_sub_items": apply_to_sub_items,
        }

        request_url = (
            self.config()["nodesUrl"] + "/" + str(node_id) + "/classifications"
        )

        request_header = self.request_form_header()

        logger.info(
            "Assign classifications with IDs -> %s to item with ID -> %s; calling -> %s",
            str(classifications),
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=classificationPostData,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to assign classifications with IDs -> %s to item with ID -> %s; status -> %s; error -> %s",
                    str(classifications),
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        rmClassificationPostData = {
            "class_id": rm_classification,
            "apply_to_sub_items": apply_to_sub_items,
        }

        request_url = (
            self.config()["nodesUrl"] + "/" + str(node_id) + "/rmclassifications"
        )

        request_header = self.request_form_header()

        logger.info(
            "Assign RM classifications with ID -> %s to item with ID -> %s; calling -> %s",
            str(rm_classification),
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=rmClassificationPostData,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to assign RM classifications with ID -> %s to item with ID -> %s; status -> %s; error -> %s",
                    str(rm_classification),
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def register_workspace_template(self, node_id: int) -> dict | None:
        """Register a workspace template as project template for Extended ECM for Engineering
        Args:
            node_id (int): node ID of the Extended ECM workspace template
        Returns:
            dict: Response of request or None if the registration of the workspace template has failed.
        """

        registrationPostData = {"ids": "{{ {} }}".format(node_id)}

        request_url = self.config()["xEngProjectTemplateUrl"]

        request_header = self.request_form_header()

        logger.info(
            "Register workspace template with ID -> %s; calling -> %s",
            str(node_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=registrationPostData,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to register Workspace Template with ID -> %s; status -> %s; error -> %s",
                    str(node_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info("Get list of Records Management RSIs; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                rsi_dict = self.parse_request_response(response)
                return rsi_dict["results"]["data"]["rsis"]
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of Records Management RSIs; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
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

        logger.info("Get list of Records Management codes; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                rm_codes_dict = self.parse_request_response(response)
                return rm_codes_dict["results"]["data"]
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of Records Management codes; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
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

        updateRMCodesPostData = {}

        request_url = self.config()["recordsManagementUrl"] + "/rmcodes"
        request_header = self.request_form_header()

        logger.info(
            "Update Records Management codes -> %s; calling -> %s",
            str(rm_codes),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=updateRMCodesPostData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                rm_codes_dict = self.parse_request_response(response)
                return rm_codes_dict["results"]["data"]
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to update Records Management codes; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
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

        if statusDate == "":
            now = datetime.now()
            statusDate = now.strftime("%Y-%m-%dT%H:%M:%S")

        createRSIPostData = {
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

        logger.info(
            "Create Records Management RSI -> %s; calling -> %s", name, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=createRSIPostData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create Records Management RSI -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

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
            object_type (str): either "LIV" - Classified Objects (default) or "LRM" - RM Classifications
            stage (str): retention stage - this is the key parameter to define multiple stages (stages are basically schedules)
            event_type (int): 1 Calculated Date, 2 Calendar Calculation, 3 Event Based, 4 Fixed Date, 5 Permanent
            rule_code (str): rule code - this value must be defined upfront
            rule_comment (str): comment for the rule
            date_to_use (int): 91 Create Date, 92 Reserved Data, 93 Modification Date, 94 Status Date, 95 Records Date
            retention_years (int): years to wait before disposition
            retention_months (int): month to wait before disposition
            retention_days (int): days to wait before disposition
            category_id (int): ID of the category
            attribute_id (int): ID of the category attribute
            year_end_month (int): month the year ends (normally 12)
            year_end_day (int): day the year ends (normally 31)
            retention_intervals (int): retention intervals
            fixed_retention (bool): fixedRetention
            maximum_retention (bool): maximumRetention
            fixed_date(str): fixed date format : YYYY-MM-DDTHH:mm:ss
            event_condition (str): eventCondition
            disposition (str): disposition
            action_code (int): 0 None, 1 Change Status, 7 Close, 8 Finalize Record, 9 Mark Official, 10 Export, 11 Update Storage Provider, 12 Delete Electronic Format, 15 Purge Versions, 16 Make Rendition, 32 Destroy
            description (str): description
            new_status (str): new status
            min_num_versions_to_keep (int): minimum document versions to keep
            purge_superseded (bool): purge superseded
            purge_majors (bool): purge majors
            mark_official_rendition (bool): mark official rendition
        Returns:
            dict: RSI Schedule data or None if the request fails.
        """

        if fixedDate == "":
            now = datetime.now()
            fixedDate = now.strftime("%Y-%m-%dT%H:%M:%S")

        createRSISchedulePostData = {
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

        logger.info(
            "Create Records Management RSI Schedule -> %s for RSI -> %s; calling -> %s",
            stage,
            str(rsi_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=createRSISchedulePostData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create Records Management RSI Schedule -> %s; status -> %s; error -> %s",
                    stage,
                    response.status_code,
                    response.text,
                )
                return None

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
            alternate_id (str): alternate hold ID
            parent_id (int, optional): ID of the parent node. If parent_id is 0 the item will be created right under "Hold Management" (top level item)
            date_applied (str, optional): create date of the Hold in this format: YYYY-MM-DDTHH:mm:ss
            date_to_remove (str, optional): suspend date of the Hold in this format: YYYY-MM-DDTHH:mm:ss
        Returns:
            dict: Hold data or None if the request fails. The dict structure is this: {'holdID': <ID>}
        """

        if date_applied == "":
            now = datetime.now()
            date_applied = now.strftime("%Y-%m-%dT%H:%M:%S")

        createHoldPostData = {
            "type": hold_type,
            "name": name,
            "comment": comment,
            "date_applied": date_applied,
            "date_to_remove": date_to_remove,
            "alternate_id": alternate_id,
        }

        if parent_id > 0:
            createHoldPostData["parent_id"] = parent_id

        request_url = self.config()["holdsUrl"]

        request_header = self.request_form_header()

        logger.info(
            "Create Records Management Hold -> %s; calling -> %s", name, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=createHoldPostData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to create Records Management Hold -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

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

        logger.info("Get list of Records Management Holds; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of Records Management Holds; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def import_records_management_settings(self, file_path: str) -> bool:
        """Import Records Management settings from a file that is uploaded from the python pod

        Args:
            file_path (str): path + filename of config file in Python container filesystem
        Returns:
            bool: True if if the REST call succeeds or False otherwise.
        """

        request_url = self.config()["recordsManagementUrl"] + "/importSettings"

        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 400 response

        logger.info(
            "Importing Records Management Settings from file -> %s; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settingsPostFile = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                files=settingsPostFile,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import Records Management Settings from file -> %s; status -> %s; error -> %s",
                    file_path,
                    response.status_code,
                    response.text,
                )
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

        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 400 response

        logger.info(
            "Importing Records Management Codes from file -> %s; calling -> %s",
            file_path,
            request_url,
        )

        settingsPostData = {"updateExistingCodes": update_existing_codes}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settingsPostFile = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=settingsPostData,
                files=settingsPostFile,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import Records Management Codes from file -> %s; status -> %s; error -> %s",
                    file_path,
                    response.status_code,
                    response.text,
                )
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

        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 400 response

        logger.info(
            "Importing Records Management RSIs from file -> %s; calling -> %s",
            file_path,
            request_url,
        )

        settingsPostData = {
            "updateExistingRSIs": update_existing_rsis,
            "deleteSchedules": delete_schedules,
        }

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settingsPostFile = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=settingsPostData,
                files=settingsPostFile,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import Records Management RSIs from file -> %s; status -> %s; error -> %s",
                    file_path,
                    response.status_code,
                    response.text,
                )
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

        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 400 response

        logger.info(
            "Importing Physical Objects Settings from server file -> %s; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settingsPostFile = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                files=settingsPostFile,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import Physical Objects settings from file -> %s; status -> %s; error -> %s",
                    file_path,
                    response.status_code,
                    response.text,
                )
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

        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 400 response

        logger.info(
            "Importing Physical Objects Codes from file -> %s; calling -> %s",
            file_path,
            request_url,
        )

        settingsPostData = {"updateExistingCodes": update_existing_codes}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settingsPostFile = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=settingsPostData,
                files=settingsPostFile,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import Physical Objects Codes from file -> %s; status -> %s; error -> %s",
                    file_path,
                    response.status_code,
                    response.text,
                )
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

        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 400 response

        logger.info(
            "Importing Physical Objects Locators from file -> %s; calling -> %s",
            file_path,
            request_url,
        )

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settingsPostFile = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                files=settingsPostFile,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import Physical Objects Locators from file -> %s; status -> %s; error -> %s",
                    file_path,
                    response.status_code,
                    response.text,
                )
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

        request_header = (
            self.cookie()
        )  # for some reason we have to omit the other header parts here - otherwise we get a 400 response

        logger.info(
            "Importing Security Clearance Codes from file -> %s; calling -> %s",
            file_path,
            request_url,
        )

        settingsPostData = {"includeusers": include_users}

        filename = os.path.basename(file_path)
        if not os.path.exists(file_path):
            logger.error(
                "The file -> %s does not exist in path -> %s!",
                filename,
                os.path.dirname(file_path),
            )
            return False
        settingsPostFile = {
            "file": (filename, open(file=file_path, encoding="utf-8"), "text/xml")
        }

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                data=settingsPostData,
                files=settingsPostFile,
                headers=request_header,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to import Security Clearance Codes from file -> %s; status -> %s; error -> %s",
                    file_path,
                    response.status_code,
                    response.text,
                )
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

        assignUserSecurityClearancePostData = {
            "securityLevel": security_clearance,
        }

        request_url = self.config()[
            "userSecurityUrl"
        ] + "/{}/securityclearancelevel".format(user_id)
        request_header = self.request_form_header()

        logger.info(
            "Assign security clearance -> %s to user with ID -> %s; calling -> %s",
            str(security_clearance),
            str(user_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=assignUserSecurityClearancePostData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to assign security clearance -> %s to user with ID -> %s; status -> %s; error -> %s",
                    str(security_clearance),
                    str(user_id),
                    response.status_code,
                    response.text,
                )
                return None

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

        assignUserSupplementalMarkingsPostData = {
            "suppMarks": supplemental_markings,
        }

        request_url = self.config()[
            "userSecurityUrl"
        ] + "/{}/supplementalmarkings".format(user_id)
        request_header = self.request_form_header()

        logger.info(
            "Assign supplemental markings -> %s to user with ID -> %s; calling -> %s",
            str(supplemental_markings),
            str(user_id),
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                headers=request_header,
                data=assignUserSupplementalMarkingsPostData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to assign supplemental markings -> %s to user with ID -> %s; status -> %s; error -> %s",
                    str(supplemental_markings),
                    str(user_id),
                    response.status_code,
                    response.text,
                )
                return None

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
                logger.info(
                    "Aviator is enabled for workspace with ID -> %s", str(workspace_id)
                )
                return True
            elif "enableai" in data:
                logger.info(
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

        aviatorStatusPutData = {
            "enabled": status,
        }

        request_url = self.config()["aiUrl"] + "/{}".format(workspace_id)
        request_header = self.request_form_header()

        if status is True:
            logger.info(
                "Enable Content Aviator for workspace with ID -> %s; calling -> %s",
                str(workspace_id),
                request_url,
            )
        else:
            logger.info(
                "Disable Content Aviator for workspace with ID -> %s; calling -> %s",
                str(workspace_id),
                request_url,
            )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                headers=request_header,
                data=aviatorStatusPutData,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to change status for Content Aviator on workspace with ID -> %s; status -> %s; error -> %s",
                    str(workspace_id),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def volume_translator(
        self, current_node_id: int, translator: object, languages: list
    ):
        """Experimental code to translate the item names and item descriptions in a given hierarchy.
           The actual translation is done by a tranlator object. This recursive method just
           traverses the hierarchy and calls the translate() method of the translator object.

        Args:
            current_node_id (int): current node ID to translate
            translator (object): this object needs to be created based on the "Translator" class
                                 and passed to this method
            languages (list): list of target languages
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
            if (
                language in descriptions_multilingual
                and descriptions_multilingual["en"]
                and not descriptions_multilingual[language]
            ):
                descriptions_multilingual[language] = translator.translate(
                    "en", language, descriptions_multilingual["en"]
                )

        # Rename node multi-lingual:
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

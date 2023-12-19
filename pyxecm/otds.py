"""
OTDS Module to implement functions to read / write OTDS objects
such as Ressources, Users, Groups, Licenses, Trusted Sites, OAuth Clients, ...

Important: userIDs consists of login name + "@" + partition name 

Class: OTDS
Methods:

__init__ : class initializer
config : returns config data set
cookie : returns cookie information
credentials: returns set of username and password

base_url : returns OTDS base URL
rest_url : returns OTDS REST base URL
credential_url : returns the OTDS Credentials REST URL
authHandler_url : returns the OTDS Authentication Handler REST URL
partition_url : returns OTDS Partition REST URL
access_role_url : returns OTDS Access Role REST URL
oauth_client_url : returns OTDS OAuth Client REST URL
resource_url : returns OTDS Resource REST URL
license_url : returns OTDS License REST URL
token_url : returns OTDS Token REST URL
users_url : returns OTDS Users REST URL
groups_url : returns OTDS Groups REST URL
system_config_url : returns OTDS System Config REST URL
consolidation_url: returns OTDS consolidation URL

authenticate : authenticates at OTDS server

add_license_to_resource : Add (or update) a product license to OTDS
get_license_for_resource : Get list of licenses for a resource
delete_license_from_resource : Delete a license from a resource
assign_user_to_license : Assign an OTDS user to a product license (feature) in OTDS.
assign_partition_to_license: Assign an OTDS user partition to a license (feature) in OTDS.
get_licensed_objects: Return the licensed objects (users, groups, partitions) an OTDS for a
                      license + license feature associated with an OTDS resource (like "cs").
is_user_licensed: Check if a user is licensed for a license and license feature associated
                  with a particular OTDS resource.
is_group_licensed: Check if a group is licensed for a license and license feature associated
                   with a particular OTDS resource.
is_partition_licensed: Check if a user partition is licensed for a license and license feature
                       associated with a particular OTDS resource.

add_partition : Add an OTDS partition
get_partition : Get a partition with a specific name
add_user : Add a user to a partion
get_user : Get a user with a specific user ID (= login name @ partition)
get_users: get all users (with option to filter)
update_user : Update attributes of on OTDS user
delete_user : Delete a user with a specific ID in a specific partition
reset_user_password : Reset a password of a specific user ID
add_group: Add an OTDS group
get_group: Get a OTDS group by its name
add_user_to_group : Add an OTDS user to a OTDS group
add_group_to_parent_group : Add on OTDS group to a parent group

add_resource : Add a new resource to OTDS
get_resource : Get an OTDS resource with a specific name
update_resource: Update an existing OTDS resource
activate_resource : Activate an OTDS resource

get_access_roles : Get all OTDS Access Roles
get_access_role: Get an OTDS Access Role with a specific name
add_partition_to_access_role : Add an OTDS Partition to to an OTDS Access Role
add_user_to_access_role : Add an OTDS user to to an OTDS Access Role
add_group_to_access_role : Add an OTDS group to to an OTDS Access Role
update_access_role_attributes: Update attributes of an existing access role

add_system_attribute : Add an OTDS System Attribute

get_trusted_sites : Get OTDS Trusted Sites
add_trusted_site : Add a new trusted site to OTDS

enable_audit: enable OTDS audit

add_oauth_client : Add a new OAuth client to OTDS
get_oauth_client : Get an OAuth client with a specific client ID
update_oauth_client : Update an OAuth client
add_oauth_clients_to_access_role : Add an OTDS OAuth Client to an OTDS Access Role
get_access_token : Get an OTDS Access Token

get_auth_handler: Gen an auth handler with a given name
add_auth_handler_saml: Add an authentication handler for SAML (e.g. for SuccessFactors)
add_auth_handler_sap: Add an authentication handler for SAP
add_auth_handler_oauth: Add an authentication handler for OAuth (used for Salesforce)

consolidate: Consolidate an OTDS resource
impersonate_resource: Configure impersonation for an OTDS resource
impersonate_oauth_client: Configure impersonation for an OTDS OAuth Client

get_password_policy: get the global password policy
update_password_policy: updates the global password policy

"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2023, OpenText"
__credits__ = ["Kai-Philip Gatzweiler", "Jim Bennett"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import os
import logging
import json
import urllib.parse
import base64
import requests

logger = logging.getLogger("pyxecm.otds")

REQUEST_HEADERS = {
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/json",
}

REQUEST_FORM_HEADERS = {
    "accept": "application/json;charset=utf-8",
    "Content-Type": "application/x-www-form-urlencoded",
}

REQUEST_TIMEOUT = 60


class OTDS:
    """Used to automate stettings in OpenText Directory Services (OTDS)."""

    _config = None
    _cookie = None

    def __init__(
        self,
        protocol: str,
        hostname: str,
        port: int,
        username: str | None = None,
        password: str | None = None,
        otds_ticket: str | None = None,
    ):
        """Initialize the OTDS object

        Args:
            protocol (str): either http or https
            hostname (str): hostname of otds
            port (int): port number - typically 80 or 443
            username (str, optional): otds user name. Optional if otds_ticket is provided.
            password (str, optional): otds password. Optional if otds_ticket is provided.
            otds_ticket (str, optional): Authentication ticket of OTDS
        """

        # Initialize otdsConfig as an empty dictionary
        otds_config = {}

        if hostname:
            otds_config["hostname"] = hostname
        else:
            otds_config["hostname"] = "otds"

        if protocol:
            otds_config["protocol"] = protocol
        else:
            otds_config["protocol"] = "http"

        if port:
            otds_config["port"] = port
        else:
            otds_config["port"] = 80

        if username:
            otds_config["username"] = username
        else:
            otds_config["username"] = "admin"

        if password:
            otds_config["password"] = password
        else:
            otds_config["password"] = ""

        if otds_ticket:
            self._cookie = {"OTDSTicket": otds_ticket}

        otdsBaseUrl = protocol + "://" + otds_config["hostname"]
        if str(port) not in ["80", "443"]:
            otdsBaseUrl += ":{}".format(port)
        otdsBaseUrl += "/otdsws"
        otds_config["baseUrl"] = otdsBaseUrl

        otdsRestUrl = otdsBaseUrl + "/rest"
        otds_config["restUrl"] = otdsRestUrl

        otds_config["partitionUrl"] = otdsRestUrl + "/partitions"
        otds_config["accessRoleUrl"] = otdsRestUrl + "/accessroles"
        otds_config["credentialUrl"] = otdsRestUrl + "/authentication/credentials"
        otds_config["oauthClientUrl"] = otdsRestUrl + "/oauthclients"
        otds_config["tokenUrl"] = otdsBaseUrl + "/oauth2/token"
        otds_config["resourceUrl"] = otdsRestUrl + "/resources"
        otds_config["licenseUrl"] = otdsRestUrl + "/licensemanagement/licenses"
        otds_config["usersUrl"] = otdsRestUrl + "/users"
        otds_config["groupsUrl"] = otdsRestUrl + "/groups"
        otds_config["systemConfigUrl"] = otdsRestUrl + "/systemconfig"
        otds_config["authHandlerUrl"] = otdsRestUrl + "/authhandlers"
        otds_config["consolidationUrl"] = otdsRestUrl + "/consolidation"

        self._config = otds_config

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    def cookie(self) -> dict:
        """Returns the login cookie of OTDS.
           This is set by the authenticate() method

        Returns:
            dict: OTDS cookie
        """
        return self._cookie

    def credentials(self) -> dict:
        """Returns the credentials (username + password)

        Returns:
            dict: dictionary with username and password
        """
        return {
            "userName": self.config()["username"],
            "password": self.config()["password"],
        }

    def base_url(self) -> str:
        """Returns the base URL of OTDS

        Returns:
            str: base URL
        """
        return self.config()["baseUrl"]

    def rest_url(self) -> str:
        """Returns the REST URL of OTDS

        Returns:
            str: REST URL
        """
        return self.config()["restUrl"]

    def credential_url(self) -> str:
        """Returns the Credentials URL of OTDS

        Returns:
            str: Credentials URL
        """
        return self.config()["credentialUrl"]

    def auth_handler_url(self) -> str:
        """Returns the Auth Handler URL of OTDS

        Returns:
            str: Auth Handler URL
        """
        return self.config()["authHandlerUrl"]

    def partition_url(self) -> str:
        """Returns the Partition URL of OTDS

        Returns:
            str: Partition URL
        """
        return self.config()["partitionUrl"]

    def access_role_url(self) -> str:
        """Returns the Access Role URL of OTDS

        Returns:
            str: Access Role URL
        """
        return self.config()["accessRoleUrl"]

    def oauth_client_url(self) -> str:
        """Returns the OAuth Client URL of OTDS

        Returns:
            str: OAuth Client URL
        """
        return self.config()["oauthClientUrl"]

    def resource_url(self) -> str:
        """Returns the Resource URL of OTDS

        Returns:
            str: Resource URL
        """
        return self.config()["resourceUrl"]

    def license_url(self) -> str:
        """Returns the License URL of OTDS

        Returns:
            str: License URL
        """
        return self.config()["licenseUrl"]

    def token_url(self) -> str:
        """Returns the Token URL of OTDS

        Returns:
            str: Token URL
        """
        return self.config()["tokenUrl"]

    def users_url(self) -> str:
        """Returns the Users URL of OTDS

        Returns:
            str: Users URL
        """
        return self.config()["usersUrl"]

    def groups_url(self) -> str:
        """Returns the Groups URL of OTDS

        Returns:
            str: Groups URL
        """
        return self.config()["groupsUrl"]

    def system_config_url(self) -> str:
        """Returns the System Config URL of OTDS

        Returns:
            str: System Config URL
        """
        return self.config()["systemConfigUrl"]

    def consolidation_url(self) -> str:
        """Returns the Consolidation URL of OTDS

        Returns:
            str: Consolidation URL
        """
        return self.config()["consolidationUrl"]

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
            dict: response dictionary or None in case of an error
        """

        if not response_object:
            return None

        try:
            dict_object = json.loads(response_object.text)
        except json.JSONDecodeError as e:
            if additional_error_message:
                message = "Cannot decode response as JSon. {}; error -> {}".format(
                    additional_error_message, e
                )
            else:
                message = "Cannot decode response as JSon; error -> {}".format(e)
            if show_error:
                logger.error(message)
            else:
                logger.warning(message)
            return None
        else:
            return dict_object

    # end method definition

    def authenticate(self, revalidate: bool = False) -> dict | None:
        """Authenticate at Directory Services and retrieve OTCS Ticket.

        Args:
            revalidate (bool, optional): determine if a re-athentication is enforced
                                         (e.g. if session has timed out with 401 error)
        Returns:
            dict: Cookie information. Also stores cookie information in self._cookie
        """

        # Already authenticated and session still valid?
        if self._cookie and not revalidate:
            return self._cookie

        otds_ticket = "NotSet"

        logger.info("Requesting OTDS ticket from -> %s", self.credential_url())

        response = None
        try:
            response = requests.post(
                url=self.credential_url(),
                json=self.credentials(),
                headers=REQUEST_HEADERS,
                timeout=None,
            )
        except requests.exceptions.RequestException as exception:
            logger.warning(
                "Unable to connect to -> %s; error -> %s",
                self.credential_url(),
                exception.strerror,
            )
            logger.warning("OTDS service may not be ready yet.")
            return None

        if response.ok:
            authenticate_dict = self.parse_request_response(response)
            if not authenticate_dict:
                return None
            else:
                otds_ticket = authenticate_dict["ticket"]
                logger.info("Ticket -> %s", otds_ticket)
        else:
            logger.error("Failed to request an OTDS ticket; error -> %s", response.text)
            return None

        self._cookie = {"OTDSTicket": otds_ticket}
        return self._cookie

    # end method definition

    def add_license_to_resource(
        self,
        path_to_license_file: str,
        product_name: str,
        product_description: str,
        resource_id: str,
        update: bool = True,
    ) -> dict | None:
        """Add a product license to an OTDS resource.

        Args:
            path_to_license_file (str): fully qualified filename of the license file
            product_name (str): product name
            product_description (str): product description
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            update (bool, optional): whether or not an existing license should be updated (default = True)
        Returns:
            dict: Request response (dictionary) or None if the REST call fails
        """

        logger.info("Reading license file -> %s...", path_to_license_file)
        try:
            with open(path_to_license_file, "rt", encoding="UTF-8") as license_file:
                license_content = license_file.read()
        except IOError as exception:
            logger.error(
                "Error opening license file -> %s; error -> %s",
                path_to_license_file,
                exception.strerror,
            )
            return None

        licensePostBodyJson = {
            "description": product_description,
            "name": product_name,
            "values": [
                {"name": "oTLicenseFile", "values": license_content},
                {"name": "oTLicenseResource", "values": resource_id},
                {"name": "oTLicenseFingerprintGenerator", "values": [None]},
            ],
        }

        request_url = self.license_url()
        # Check if we want to update an existing license:
        if update:
            existing_license = self.get_license_for_resource(resource_id)
            if existing_license:
                request_url += "/" + existing_license[0]["id"]
            else:
                logger.info(
                    "No existing license for resource -> %s found - adding a new license...",
                    resource_id,
                )
                # change strategy to create a new license:
                update = False

        logger.info(
            "Adding product license -> %s for product -> %s to resource -> %s; calling -> %s",
            path_to_license_file,
            product_description,
            resource_id,
            request_url,
        )

        retries = 0
        while True:
            if update:
                # Do a REST PUT call for update an existing license:
                response = requests.put(
                    url=request_url,
                    json=licensePostBodyJson,
                    headers=REQUEST_HEADERS,
                    cookies=self.cookie(),
                    timeout=None,
                )
            else:
                # Do a REST POST call for creation of a new license:
                response = requests.post(
                    url=request_url,
                    json=licensePostBodyJson,
                    headers=REQUEST_HEADERS,
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
                    "Failed to add product license -> %s for product -> %s; error -> %s (%s)",
                    path_to_license_file,
                    product_description,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_license_for_resource(self, resource_id: str):
        """Get a product license for a resource in OTDS.

        Args:
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
        Returns:
            Licenses for a resource or None if the REST call fails

        licenses have this format:
        {
          '_oTLicenseType': 'NON-PRODUCTION',
          '_oTLicenseResource': '7382094f-a434-4714-9696-82864b6803da',
          '_oTLicenseResourceName': 'cs',
          '_oTLicenseProduct': 'EXTENDED_ECM',
          'name': 'EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da',
          'location': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'id': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
          'description': 'CS license',
          'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
        }
        """

        request_url = (
            self.license_url()
            + "/assignedlicenses?resourceID="
            + resource_id
            + "&validOnly=false"
        )

        logger.info(
            "Get license for resource -> %s; calling -> %s", resource_id, request_url
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                response_dict = self.parse_request_response(response)
                if not response_dict:
                    return None
                return response_dict["licenseObjects"]["_licenses"]
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to get license for resource -> %s; error -> %s (%s)",
                    resource_id,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def delete_license_from_resource(self, resource_id: str, license_id: str) -> bool:
        """Delete a product license for a resource in OTDS.

        Args:
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            license_id (str): OTDS license ID (this is the ID not the license name!)
        Returns:
            bool: True if successful or False if the REST call fails
        """

        request_url = "{}/{}".format(self.license_url(), license_id)

        logger.info(
            "Deleting product license -> %s from resource -> %s; calling -> %s",
            license_id,
            resource_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.delete(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to delete license -> %s for resource -> %s; error -> %s (%s)",
                    license_id,
                    resource_id,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def assign_user_to_license(
        self,
        partition: str,
        user_id: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
        license_type: str = "Full",
    ) -> bool:
        """Assign an OTDS user to a product license (feature) in OTDS.

        Args:
            partition (str): user partition in OTDS, e.g. "Content Server Members"
            user_id (str): ID of the user (= login name)
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            license_feature (str): name of the license feature
            license_name (str): name of the license to assign
            license_type (str, optional): deault is "Full", Extended ECM also has "Occasional"
        Returns:
            bool: True if successful or False if the REST call fails or the license is not found
        """

        licenses = self.get_license_for_resource(resource_id)

        for lic in licenses:
            if lic["_oTLicenseProduct"] == license_name:
                license_location = lic["id"]

        try:
            license_location
        except UnboundLocalError:
            logger.error(
                "Cannot find license -> %s for resource -> %s",
                license_name,
                resource_id,
            )
            return False

        user = self.get_user(partition, user_id)
        if user:
            user_location = user["location"]
        else:
            logger.error("Cannot find location for user -> %s", user_id)
            return False

        licensePostBodyJson = {
            "_oTLicenseType": license_type,
            "_oTLicenseProduct": "users",
            "name": user_location,
            "values": [{"name": "counter", "values": [license_feature]}],
        }

        request_url = self.license_url() + "/object/" + license_location

        logger.info(
            "Assign license feature -> %s of license -> %s associated with resource -> %s to user -> %s; calling -> %s",
            license_feature,
            license_location,
            resource_id,
            user_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=licensePostBodyJson,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info(
                    "Added license feature -> %s for user -> %s",
                    license_feature,
                    user_id,
                )
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add license feature -> %s associated with resource -> %s to user -> %s; error -> %s (%s)",
                    license_feature,
                    resource_id,
                    user_id,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def assign_partition_to_license(
        self,
        partition_name: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
        license_type: str = "Full",
    ) -> bool:
        """Assign an OTDS partition to a product license (feature).

        Args:
            partition_name (str): user partition in OTDS, e.g. "Content Server Members"
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            license_feature (str): name of the license feature, e.g. "X2" or "ADDON_ENGINEERING"
            license_name (str): name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG"
            license_type (str, optional): deault is "Full", Extended ECM also has "Occasional"
        Returns:
            bool: True if successful or False if the REST call fails or the license is not found
        """

        licenses = self.get_license_for_resource(resource_id)
        if not licenses:
            logger.error(
                "Resource with ID -> %s does not exist or has no licenses", resource_id
            )
            return False

        # licenses have this format:
        # {
        #   '_oTLicenseType': 'NON-PRODUCTION',
        #   '_oTLicenseResource': '7382094f-a434-4714-9696-82864b6803da',
        #   '_oTLicenseResourceName': 'cs',
        #   '_oTLicenseProduct': 'EXTENDED_ECM',
        #   'name': 'EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da',
        #   'location': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
        #   'id': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
        #   'description': 'CS license',
        #   'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
        # }
        for lic in licenses:
            if lic["_oTLicenseProduct"] == license_name:
                license_location = lic["id"]

        try:
            license_location
        except UnboundLocalError:
            logger.error(
                "Cannot find license -> %s for resource -> %s",
                license_name,
                resource_id,
            )
            return False

        licensePostBodyJson = {
            "_oTLicenseType": license_type,
            "_oTLicenseProduct": "partitions",
            "name": partition_name,
            "values": [{"name": "counter", "values": [license_feature]}],
        }

        request_url = self.license_url() + "/object/" + license_location

        logger.info(
            "Assign license feature -> %s of license -> %s associated with resource -> %s to partition -> %s; calling -> %s",
            license_feature,
            license_location,
            resource_id,
            partition_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=licensePostBodyJson,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                logger.info(
                    "Added license feature -> %s for partition -> %s",
                    license_feature,
                    partition_name,
                )
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add license feature -> %s associated with resource -> %s to partition -> %s; error -> %s (%s)",
                    license_feature,
                    resource_id,
                    partition_name,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def get_licensed_objects(
        self,
        resource_id: str,
        license_feature: str,
        license_name: str,
    ) -> dict | None:
        """Return the licensed objects (users, groups, partitions) in OTDS for a license + license feature
           associated with an OTDS resource (like "cs").

        Args:
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            license_feature (str): name of the license feature, e.g. "X2" or "ADDON_ENGINEERING"
            license_name (str): name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG"
        Returns:
            dict: data structure of licensed objects

            Example return value:
            {
                'status': 0,
                'displayString': 'Success',
                'exceptions': None,
                'retValue': 0,
                'listGroupsResults': {'groups': [...], 'actualPageSize': 0, 'nextPageCookie': None, 'requestedPageSize': 250},
                'listUsersResults': {'users': [...], 'actualPageSize': 53, 'nextPageCookie': None, 'requestedPageSize': 250},
                'listUserPartitionResult': {'_userPartitions': [...], 'warningMessage': None, 'actualPageSize': 0, 'nextPageCookie': None, 'requestedPageSize': 250},
                'version': 1
            }
        """

        licenses = self.get_license_for_resource(resource_id)
        if not licenses:
            logger.error(
                "Resource with ID -> %s does not exist or has no licenses", resource_id
            )
            return False

        # licenses have this format:
        # {
        #   '_oTLicenseType': 'NON-PRODUCTION',
        #   '_oTLicenseResource': '7382094f-a434-4714-9696-82864b6803da',
        #   '_oTLicenseResourceName': 'cs',
        #   '_oTLicenseProduct': 'EXTENDED_ECM',
        #   'name': 'EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da',
        #   'location': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
        #   'id': 'cn=EXTENDED_ECM¹7382094f-a434-4714-9696-82864b6803da,ou=Licenses,dc=identity,dc=opentext,dc=net',
        #   'description': 'CS license',
        #   'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
        # }
        for lic in licenses:
            if lic["_oTLicenseProduct"] == license_name:
                license_location = lic["location"]

        try:
            license_location
        except UnboundLocalError:
            logger.error(
                "Cannot find license -> %s for resource -> %s",
                license_name,
                resource_id,
            )
            return False

        request_url = (
            self.license_url()
            + "/object/"
            + license_location
            + "?counter="
            + license_feature
        )

        logger.info(
            "Get licensed objects for license -> %s and license feature -> %s associated with resource -> %s; calling -> %s",
            license_name,
            license_feature,
            resource_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to get licensed objects for license -> %s and license feature -> %s associated with resource -> %s; error -> %s (%s)",
                    license_name,
                    license_feature,
                    resource_id,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def is_user_licensed(
        self, user_name: str, resource_id: str, license_feature: str, license_name: str
    ) -> bool:
        """Check if a user is licensed for a license and license feature associated with a particular OTDS resource.

        Args:
            user_name (str): login name of the OTDS user
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            license_feature (str): name of the license feature, e.g. "X2" or "ADDON_ENGINEERING"
            license_name (str): name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG"

        Returns:
            bool: True if the user is licensed and False otherwise
        """

        response = self.get_licensed_objects(
            resource_id=resource_id,
            license_feature=license_feature,
            license_name=license_name,
        )

        if not response or not response["listUsersResults"]:
            return False

        users = response["listUsersResults"]["users"]

        if not users:
            return False

        user = next(
            (item for item in users if item["name"] == user_name),
            None,
        )

        if user:
            return True

        return False

    # end method definition

    def is_group_licensed(
        self, group_name: str, resource_id: str, license_feature: str, license_name: str
    ) -> bool:
        """Check if a group is licensed for a license and license feature associated with a particular OTDS resource.

        Args:
            group_name (str): name of the OTDS user group
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            license_feature (str): name of the license feature, e.g. "X2" or "ADDON_ENGINEERING"
            license_name (str): name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG"

        Returns:
            bool: True if the group is licensed and False otherwise
        """

        response = self.get_licensed_objects(
            resource_id=resource_id,
            license_feature=license_feature,
            license_name=license_name,
        )

        if not response or not response["listGroupsResults"]:
            return False

        groups = response["listGroupsResults"]["groups"]

        if not groups:
            return False

        group = next(
            (item for item in groups if item["name"] == group_name),
            None,
        )

        if group:
            return True

        return False

    # end method definition

    def is_partition_licensed(
        self,
        partition_name: str,
        resource_id: str,
        license_feature: str,
        license_name: str,
    ) -> bool:
        """Check if a partition is licensed for a license and license feature associated with a particular OTDS resource.

        Args:
            partition_name (str): name of the OTDS user partition, e.g. "Content Server Members"
            resource_id (str): OTDS resource ID (this is ID not the resource name!)
            license_feature (str): name of the license feature, e.g. "X2" or "ADDON_ENGINEERING"
            license_name (str): name of the license to assign, e.g. "EXTENDED_ECM" or "INTELLGENT_VIEWIMG"

        Returns:
            bool: True if the partition is licensed and False otherwise
        """

        response = self.get_licensed_objects(
            resource_id=resource_id,
            license_feature=license_feature,
            license_name=license_name,
        )

        if not response or not response["listUserPartitionResult"]:
            return False

        partitions = response["listUserPartitionResult"]["_userPartitions"]

        if not partitions:
            return False

        partition = next(
            (item for item in partitions if item["name"] == partition_name),
            None,
        )

        if partition:
            return True

        return False

    # end method definition

    def add_partition(self, name: str, description: str) -> dict | None:
        """Add a new user partition to OTDS

        Args:
            name (str): name of the new partition
            description (str): description of the new partition
        Returns:
            dict: Request response or None if the creation fails.
        """

        partitionPostBodyJson = {"name": name, "description": description}

        request_url = self.partition_url()

        logger.info(
            "Adding user partition -> %s (%s); calling -> %s",
            name,
            description,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=partitionPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add user partition -> %s; error -> %s (%s)",
                    name,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_partition(self, name: str, show_error: bool = True) -> dict | None:
        """Get an existing user partition from OTDS

        Args:
            name (str): name of the partition to retrieve
            show_error (bool, optional): whether or not we want to log an error
                                         if partion is not found
        Returns:
            dict: Request response or None if the REST call fails.
        """

        request_url = "{}/{}".format(self.config()["partitionUrl"], name)

        logger.info("Getting user partition -> %s; calling -> %s", name, request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                        "Failed to get partition -> %s; warning -> %s (%s)",
                        name,
                        response.text,
                        response.status_code,
                    )
                return None

    # end method definition

    def add_user(
        self,
        partition: str,
        name: str,
        description: str = "",
        first_name: str = "",
        last_name: str = "",
        email: str = "",
    ) -> dict | None:
        """Add a new user to a user partition in OTDS

        Args:
            partition (str): name of the OTDS user partition (needs to exist)
            name (str): login name of the new user
            description (str, optional): description of the new user
            first_name (str, optional): first name of the new user
            last_name (str, optional): last name of the new user
            email (str, optional): email address of the new user
        Returns:
            dict: Request response or None if the creation fails.
        """

        userPostBodyJson = {
            "userPartitionID": partition,
            "values": [
                {"name": "sn", "values": [last_name]},
                {"name": "givenName", "values": [first_name]},
                {"name": "mail", "values": [email]},
            ],
            "name": name,
            "description": description,
        }

        request_url = self.users_url()

        logger.info(
            "Adding user -> %s to partition -> %s; calling -> %s",
            name,
            partition,
            request_url,
        )
        logger.debug("User Attributes -> %s", str(userPostBodyJson))

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=userPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add user -> %s; error -> %s (%s)",
                    name,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_user(self, partition: str, user_id: str) -> dict | None:
        """Get a user by its partition and user ID

        Args:
            partition (str): name of the partition
            user_id (str): ID of the user (= login name)
        Returns:
            dict: Request response or None if the user was not found.
        """

        request_url = self.users_url() + "/" + user_id + "@" + partition

        logger.info(
            "Get user -> %s in partition -> %s; calling -> %s",
            user_id,
            partition,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to get user -> %s; error -> %s (%s)",
                    user_id,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_users(self, partition: str = "", limit: int | None = None) -> dict | None:
        """Get all users in a partition partition

        Args:
            partition (str, optional): name of the partition
            limit (int): maximum number of users to return
        Returns:
            dict: Request response or None if the user was not found.
        """

        # Add query parameters (these are NOT passed via JSon body!)
        query = {}
        if limit:
            query["limit"] = limit
        if partition:
            query["where_partition_name"] = partition

        encodedQuery = urllib.parse.urlencode(query, doseq=True)

        request_url = self.users_url()
        if query:
            request_url += "?{}".format(encodedQuery)

        if partition:
            logger.info(
                "Get all users in partition -> %s (limit -> %s); calling -> %s",
                partition,
                limit,
                request_url,
            )
        else:
            logger.info(
                "Get all users (limit -> %s); calling -> %s",
                limit,
                request_url,
            )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                if partition:
                    logger.error(
                        "Failed to get users in partition -> %s; error -> %s (%s)",
                        partition,
                        response.text,
                        response.status_code,
                    )
                else:
                    logger.error(
                        "Failed to get users; error -> %s (%s)",
                        response.text,
                        response.status_code,
                    )
                return None

    # end method definition

    def update_user(
        self, partition: str, user_id: str, attribute_name: str, attribute_value: str
    ) -> dict | None:
        """Update a user attribute with a new value

        Args:
            partition (str): name of the partition
            user_id (str): ID of the user (= login name)
            attribute_name (str): name of the attribute
            attribute_value (str): new value of the attribute
        Return:
            dict: Request response or None if the update fails.
        """

        userPatchBodyJson = {
            "userPartitionID": partition,
            "values": [{"name": attribute_name, "values": [attribute_value]}],
        }

        request_url = self.users_url() + "/" + user_id

        logger.info(
            "Update user -> %s attribute -> %s to value -> %s; calling -> %s",
            user_id,
            attribute_name,
            attribute_value,
            request_url,
        )

        retries = 0
        while True:
            response = requests.patch(
                url=request_url,
                json=userPatchBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to update user -> %s; error -> %s (%s)",
                    user_id,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def delete_user(self, partition: str, user_id: str) -> bool:
        """Delete an existing user

        Args:
            partition (str): name of the partition
            user_id (str): Id (= login name) of the user
        Returns:
            bool: True = success, False = error
        """

        request_url = self.users_url() + "/" + user_id + "@" + partition

        logger.info(
            "Delete user -> %s in partition -> %s; calling -> %s",
            user_id,
            partition,
            request_url,
        )

        retries = 0
        while True:
            response = requests.delete(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to delete user -> %s; error -> %s (%s)",
                    user_id,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def reset_user_password(self, user_id: str, password: str) -> bool:
        """Reset a password of an existing user

        Args:
            user_id (str): Id (= login name) of the user
            password (str): new password of the user
        Returns:
            bool: True = success, False = error.
        """

        userPostBodyJson = {"newPassword": password}

        request_url = "{}/{}/password".format(self.users_url(), user_id)

        logger.info(
            "Resetting password for user -> %s; calling -> %s", user_id, request_url
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=userPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to reset password for user -> %s; error -> %s (%s)",
                    user_id,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def add_group(self, partition: str, name: str, description: str) -> dict | None:
        """Add a new user group to a user partition in OTDS

        Args:
            partition (str): name of the OTDS user partition (needs to exist)
            name (str): name of the new group
            description (str): description of the new group
        Returns:
            dict: Request response (json) or None if the creation fails.
        """

        groupPostBodyJson = {
            "userPartitionID": partition,
            "name": name,
            "description": description,
        }

        request_url = self.groups_url()

        logger.info(
            "Adding group -> %s to partition -> %s; calling -> %s",
            name,
            partition,
            request_url,
        )
        logger.debug("Group Attributes -> %s", str(groupPostBodyJson))

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=groupPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add group -> %s; error -> %s (%s)",
                    name,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_group(self, group: str) -> dict | None:
        """Get a OTDS group by its group name

        Args:
            group (str): ID of the group (= group name)
        Return:
            dict: Request response or None if the group was not found.
            Example values:
            {
                'numMembers': 7,
                'userPartitionID': 'Content Server Members',
                'name': 'Sales',
                'location': 'oTGroup=3f921294-b92a-4c9e-bf7c-b50df16bb937,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net',
                'id': 'Sales@Content Server Members',
                'values': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...],
                'description': None,
                'uuid': '3f921294-b92a-4c9e-bf7c-b50df16bb937',
                'objectClass': 'oTGroup',
                'customAttributes': None,
                'originUUID': None,
                'urlId': 'Sales@Content Server Members',
                'urlLocation': 'oTGroup=3f921294-b92a-4c9e-bf7c-b50df16bb937,orgunit=groups,partition=Content Server Members,dc=identity,dc=opentext,dc=net'
            }
        """

        request_url = self.groups_url() + "/" + group

        logger.info("Get group -> %s; calling -> %s", group, request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to get group -> %s; error -> %s (%s)",
                    group,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def add_user_to_group(self, user: str, group: str) -> bool:
        """Add an existing user to an existing group in OTDS

        Args:
            user (str): name of the OTDS user (needs to exist)
            group (str): name of the OTDS group (needs to exist)
        Returns:
            bool: True, if request is successful, False otherwise.
        """

        userToGroupPostBodyJson = {"stringList": [group]}

        request_url = self.users_url() + "/" + user + "/memberof"

        logger.info(
            "Adding user -> %s to group -> %s; calling -> %s", user, group, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=userToGroupPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add user -> %s to group -> %s; error -> %s (%s)",
                    user,
                    group,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def add_group_to_parent_group(self, group: str, parent_group: str) -> bool:
        """Add an existing group to an existing parent group in OTDS

        Args:
            group (str): name of the OTDS group (needs to exist)
            parent_group (str): name of the OTDS parent group (needs to exist)
        Returns:
            bool: True, if request is successful, False otherwise.
        """

        groupToParentGroupPostBodyJson = {"stringList": [parent_group]}

        request_url = self.groups_url() + "/" + group + "/memberof"

        logger.info(
            "Adding group -> %s to parent group -> %s; calling -> %s",
            group,
            parent_group,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=groupToParentGroupPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add group -> %s to parent group -> %s; error -> %s (%s)",
                    group,
                    parent_group,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def add_resource(
        self,
        name: str,
        description: str,
        display_name: str,
        additional_payload: dict | None = None,
    ) -> dict | None:
        """Add an OTDS resource

        Args:
            name (str): name of the new OTDS resource
            description (str): description of the new OTDS resource
            display_name (str): display name of the OTDS resource
            additional_payload (dict, optional): additional values for the json payload
        Returns:
            dict: Request response (dictionary) or None if the REST call fails.
        """

        resourcePostBodyJson = {
            "resourceName": name,
            "description": description,
            "displayName": display_name,
        }

        # Check if there's additional payload for the body provided to handle special cases:
        if additional_payload:
            # Merge additional payload:
            resourcePostBodyJson.update(additional_payload)

        request_url = self.config()["resourceUrl"]

        logger.info(
            "Adding resource -> %s (%s); calling -> %s", name, description, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=resourcePostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add resource -> %s; error -> %s (%s)",
                    name,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_resource(self, name: str, show_error: bool = False) -> dict | None:
        """Get an existing OTDS resource

        Args:
            name (str): name of the new OTDS resource
            show_error (bool, optional): treat as error if resource is not found
        Returns:
            dict: Request response or None if the REST call fails.
        """

        request_url = "{}/{}".format(self.config()["resourceUrl"], name)

        logger.info("Retrieving resource -> %s; calling -> %s", name, request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                # We don't necessarily want to log an error as this function
                # is also used in wait loops:
                if show_error:
                    logger.warning(
                        "Failed to retrieve resource -> %s; warning -> %s",
                        name,
                        response.text,
                    )
                else:
                    logger.info("Resource -> %s not found.", name)
                return None

    # end method definition

    def update_resource(
        self, name: str, resource: object, show_error: bool = True
    ) -> dict | None:
        """Update an existing OTDS resource

        Args:
            name (str): name of the new OTDS resource
            resource (object): updated resource object of get_resource called before
            show_error (bool, optional): treat as error if resource is not found
        Returns:
            dict: Request response (json) or None if the REST call fails.
        """

        request_url = "{}/{}".format(self.config()["resourceUrl"], name)

        logger.info("Updating resource -> %s; calling -> %s", name, request_url)

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=resource,
                headers=REQUEST_HEADERS,
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
                # We don't necessarily want to log an error as this function
                # is also used in wait loops:
                if show_error:
                    logger.warning(
                        "Failed to retrieve resource -> %s; warning -> %s",
                        name,
                        response.text,
                    )
                else:
                    logger.info("Resource -> %s not found.", name)
                return None

    # end method definition

    def activate_resource(self, resource_id: str) -> dict | None:
        """Activate an OTDS resource

        Args:
            resource_id (str): ID of the OTDS resource
        Returns:
            dict: Request response (json) or None if the REST call fails.
        """

        resourcePostBodyJson = {}

        request_url = "{}/{}/activate".format(self.config()["resourceUrl"], resource_id)

        logger.info(
            "Activating resource -> %s; calling -> %s", resource_id, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=resourcePostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to activate resource -> %s; error -> %s (%s)",
                    resource_id,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_access_roles(self) -> dict | None:
        """Get a list of all OTDS access roles

        Args:
            None
        Returns:
            dict: Request response or None if the REST call fails.
        """

        request_url = self.config()["accessRoleUrl"]

        logger.info("Retrieving access roles; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to retrieve access roles; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_access_role(self, access_role: str) -> dict | None:
        """Get an OTDS access role

        Args:
            name (str): name of the access role
        Returns:
            dict: Request response (json) or None if the REST call fails.
        """

        request_url = self.config()["accessRoleUrl"] + "/" + access_role

        logger.info(
            "Retrieving access role -> %s; calling -> %s", access_role, request_url
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to retrieve access role -> %s; error -> %s (%s)",
                    access_role,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def add_partition_to_access_role(
        self, access_role: str, partition: str, location: str = ""
    ) -> bool:
        """Add an OTDS partition to an OTDS access role

        Args:
            access_role (str): name of the OTDS access role
            partition (str): name of the partition
            location (str, optional): this is kind of a unique identifier DN (Distinguished Name)
                                      most of the times you will want to keep it to empty string ("")
        Returns:
            bool: True if partition is in access role or has been successfully added.
                  False if partition has been not been added (error)
        """

        accessRolePostBodyJson = {
            "userPartitions": [{"name": partition, "location": location}]
        }

        request_url = "{}/{}/members".format(
            self.config()["accessRoleUrl"], access_role
        )

        logger.info(
            "Add user partition -> %s to access role -> %s; calling -> %s",
            partition,
            access_role,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=accessRolePostBodyJson,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add partition -> %s to access role -> %s; error -> %s (%s)",
                    partition,
                    access_role,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def add_user_to_access_role(
        self, access_role: str, user_id: str, location: str = ""
    ) -> bool:
        """Add an OTDS user to an OTDS access role

        Args:
            access_role (str): name of the OTDS access role
            user_id (str): ID of the user (= login name)
            location (str, optional): this is kind of a unique identifier DN (Distinguished Name)
                                      most of the times you will want to keep it to empty string ("")
        Returns:
            bool: True if user is in access role or has been successfully added.
                  False if user has not been added (error)
        """

        # get existing members to check if user is already a member:
        accessRolesGetResponse = self.get_access_role(access_role)

        if not accessRolesGetResponse:
            return False

        # Checking if user already added to access role
        accessRoleUsers = accessRolesGetResponse["accessRoleMembers"]["users"]
        for user in accessRoleUsers:
            if user["displayName"] == user_id:
                logger.info(
                    "User -> %s already added to access role -> %s",
                    user_id,
                    access_role,
                )
                return True

        logger.info(
            "User -> %s is not yet in access role -> %s - adding...",
            user_id,
            access_role,
        )

        # create payload for REST call:
        accessRolePostBodyJson = {"users": [{"name": user_id, "location": location}]}

        request_url = "{}/{}/members".format(
            self.config()["accessRoleUrl"], access_role
        )

        logger.info(
            "Add user -> %s to access role -> %s; calling -> %s",
            user_id,
            access_role,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=accessRolePostBodyJson,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add user -> %s to access role -> %s; error -> %s (%s)",
                    user_id,
                    access_role,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def add_group_to_access_role(
        self, access_role: str, group: str, location: str = ""
    ) -> bool:
        """Add an OTDS group to an OTDS access role

        Args:
            access_role (str): name of the OTDS access role
            group (str): name of the group
            location (str, optional): this is kind of a unique identifier DN (Distinguished Name)
                                      most of the times you will want to keep it to empty string ("")
        Returns:
            bool: True if group is in access role or has been successfully added.
                  False if group has been not been added (error)
        """

        # get existing members to check if user is already a member:
        accessRolesGetResponse = self.get_access_role(access_role)
        if not accessRolesGetResponse:
            return False

        # Checking if group already added to access role
        accessRoleGroups = accessRolesGetResponse["accessRoleMembers"]["groups"]
        for accessRoleGroup in accessRoleGroups:
            if accessRoleGroup["name"] == group:
                logger.info(
                    "Group -> %s already added to access role -> %s", group, access_role
                )
                return True

        logger.info(
            "Group -> %s is not yet in access role -> %s - adding...",
            group,
            access_role,
        )

        # create payload for REST call:
        accessRolePostBodyJson = {"groups": [{"name": group, "location": location}]}

        request_url = "{}/{}/members".format(
            self.config()["accessRoleUrl"], access_role
        )

        logger.info(
            "Add group -> %s to access role -> %s; calling -> %s",
            group,
            access_role,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=accessRolePostBodyJson,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                return True
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to add group -> %s to access role -> %s; error -> %s (%s)",
                    group,
                    access_role,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def update_access_role_attributes(
        self, name: str, attribute_list: list
    ) -> dict | None:
        """Update some attributes of an existing OTDS Access Role

        Args:
            name (str): name of the existing access role
            attribute_list (list): list of attribute name and attribute value pairs
                                   The values need to be a list as well. Example:
                                   [{name: "pushAllGroups", values: ["True"]}]
        Returns:
            dict: Request response (json) or None if the REST call fails.
        """

        # Return if list is empty:
        if not attribute_list:
            return None

        # create payload for REST call:
        access_role = self.get_access_role(name)
        if not access_role:
            logger.error("Failed to get access role -> %s", name)
            return None

        accessRolePutBodyJson = {"attributes": attribute_list}

        request_url = "{}/{}/attributes".format(self.config()["accessRoleUrl"], name)

        logger.info(
            "Update access role -> %s with attributes -> %s; calling -> %s",
            name,
            accessRolePutBodyJson,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=accessRolePutBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to update access role -> %s; error -> %s (%s)",
                    name,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def add_system_attribute(
        self, name: str, value: str, description: str = ""
    ) -> dict | None:
        """Add a new system attribute to OTDS

        Args:
            name (str): name of the new system attribute
            value (str): value of the system attribute
            description (str, optional): optional description of the system attribute
        Returns:
            dict: Request response (dictionary) or None if the REST call fails.
        """

        systemAttributePostBodyJson = {
            "name": name,
            "value": value,
            "friendlyName": description,
        }

        request_url = "{}/system_attributes".format(self.config()["systemConfigUrl"])

        if description:
            logger.info(
                "Add system attribute -> %s (%s) with value -> %s; calling -> %s",
                name,
                description,
                value,
                request_url,
            )
        else:
            logger.info(
                "Add system attribute -> %s with value -> %s; calling -> %s",
                name,
                value,
                request_url,
            )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=systemAttributePostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add system attribute -> %s with value -> %s; error -> %s (%s)",
                    name,
                    value,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_trusted_sites(self) -> dict | None:
        """Get all configured OTDS trusted sites

        Args:
            None
        Returns:
            dict: Request response or None if the REST call fails.
        """

        request_url = "{}/whitelist".format(self.config()["systemConfigUrl"])

        logger.info("Retrieving trusted sites; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to retrieve trusted sites; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def add_trusted_site(self, trusted_site: str) -> dict | None:
        """Add a new OTDS trusted site

        Args:
            trusted_site (str): name of the new trusted site
        Return:
            dict: Request response or None if the REST call fails.
        """

        trustedSitePostBodyJson = {"stringList": [trusted_site]}

        # we need to first retrieve the existing sites and then
        # append the new one:
        existingTrustedSites = self.get_trusted_sites()

        if existingTrustedSites:
            trustedSitePostBodyJson["stringList"].extend(
                existingTrustedSites["stringList"]
            )

        request_url = "{}/whitelist".format(self.config()["systemConfigUrl"])

        logger.info("Add trusted site -> %s; calling -> %s", trusted_site, request_url)

        response = requests.put(
            url=request_url,
            json=trustedSitePostBodyJson,
            headers=REQUEST_HEADERS,
            cookies=self.cookie(),
            timeout=None,
        )
        if not response.ok:
            logger.error(
                "Failed to add trusted site -> %s; error -> %s (%s)",
                trusted_site,
                response.text,
                response.status_code,
            )
            return None

        return response  # don't parse it!

    # end method definition

    def enable_audit(self):
        """enable OTDS Audit

        Args:
            None
        Return:
            Request response (json) or None if the REST call fails.
        """

        auditPutBodyJson = {
            "daysToKeep": "7",
            "enabled": "true",
            "auditTo": "DATABASE",
            "eventIDs": [
                "User Create",
                "Group Create",
                "User Delete",
                "Group Delete",
                "User Modify",
                "Group Modify",
                "Initial authentication successful",
                "Initial authentication failed",
                "Impersonation",
                "Import Finished",
                "Access Denied",
                "Authentication code incorrect",
                "Authentication code required",
                "User locked out",
                "Consolidate Partition with identity provider",
                "Recycle Bin User Deleted",
                "Recycle Bin Group Deleted",
                "User Moved to Recycle Bin",
                "Group Moved to Recycle Bin",
                "User Restored from Recycle Bin",
                "Group Restored from Recycle Bin",
                "Scheduled Cleanup",
                "Consolidation finished",
                "Monitoring session finished",
                "User Rename",
                "Group Rename",
                "Role Create",
                "Role Delete",
                "Role Modify",
                "Role Rename",
                "Recycle Bin Role Deleted",
                "Role Moved to Recycle Bin",
                "Role Restored from Recycle Bin",
                "Set group members",
                "Set group members for moved in objects",
                "User logout",
                "Password change successful",
                "Password change failed",
                "Add Parent Object",
                "Remove Parent Object",
                "OAuth Client Create",
                "OAuth Client Delete",
                "OAuth Client Modify",
                "Tenant Create",
                "Tenant Delete",
                "Tenant Modify",
                "Migration",
            ],
        }

        request_url = "{}/audit".format(self.config()["systemConfigUrl"])

        logger.info("Enable audit; calling -> %s", request_url)

        response = requests.put(
            url=request_url,
            json=auditPutBodyJson,
            headers=REQUEST_HEADERS,
            cookies=self.cookie(),
            timeout=None,
        )
        if not response.ok:
            logger.error(
                "Failed to enable audit; error -> %s (%s)",
                response.text,
                response.status_code,
            )
        return response

    # end method definition

    def add_oauth_client(
        self,
        client_id: str,
        description: str,
        redirect_urls: list | None = None,
        allow_impersonation: bool = True,
        confidential: bool = True,
        auth_scopes: list | None = None,  # None = "Global"
        allowed_scopes: list | None = None,  # in OTDS UI: Permissible scopes
        default_scopes: list | None = None,  # in OTDS UI: Default scopes
        secret: str = "",
    ) -> dict | None:
        """Add a new OAuth client to OTDS

        Args:
            client_id (str): name of the new OAuth client (should not have blanks)
            description (str): description of the OAuth client
            redirect_urls (list): list of redirect URLs (strings)
            allow_impersonation (bool, optional): allow impresonation
            confidential (bool, optional): is confidential
            auth_scopes (list, optional): if empty then "Global"
            allowed_scopes (list, optional): in OTDS UI this is called Permissible scopes
            default_scopes (list, optional): in OTDS UI this is called Default scopes
            secret (str, optional): predefined OAuth client secret. If empty a new secret is generated.
        Returns:
            dict: Request response or None if the creation fails.
            Example:
            {
                "description": "string",
                "redirectURLs": [
                    "string"
                ],
                "id": "string",
                "location": "string",
                "accessTokenLifeTime": 0,
                "refreshTokenLifeTime": 0,
                "authCodeLifeTime": 0,
                "allowRefreshToken": true,
                "allowImpersonation": true,
                "useSessionRefreshTokenLifeTime": true,
                "allowedScopes": [
                    "string"
                ],
                "defaultScopes": [
                    "string"
                ],
                "impersonateList": [
                    "string"
                ],
                "confidential": true,
                "secret": "string",
                "customAttributes": [
                    {
                    "type": "string",
                    "name": "string",
                    "value": "string"
                    }
                ],
                "logoutURL": "string",
                "logoutMethod": "string",
                "authScopes": [
                    "string"
                ],
                "uuid": "string",
                "name": "string",
                "urlId": "string",
                "urlLocation": "string"
            }
        """

        # Avoid linter warning W0102:
        if redirect_urls is None:
            redirect_urls = []
        if auth_scopes is None:
            auth_scopes = []
        if allowed_scopes is None:
            allowed_scopes = []
        if default_scopes is None:
            default_scopes = []

        oauthClientPostBodyJson = {
            "id": client_id,
            "description": description,
            "redirectURLs": redirect_urls,
            "accessTokenLifeTime": 1000,
            "refreshTokenLifeTime": 20000,
            "authCodeLifeTime": 20000,
            "allowRefreshToken": True,
            "allowImpersonation": allow_impersonation,
            "useSessionRefreshTokenLifeTime": True,
            "confidential": confidential,
            "authScopes": auth_scopes,
            "allowedScopes": allowed_scopes,
            "defaultScopes": default_scopes,
        }

        # Do we have a predefined client secret?
        if secret:
            oauthClientPostBodyJson["secret"] = secret

        request_url = self.oauth_client_url()

        logger.info(
            "Adding oauth client -> %s (%s); calling -> %s",
            description,
            client_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=oauthClientPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add OAuth client -> %s; error -> %s (%s)",
                    client_id,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def get_oauth_client(self, client_id: str, show_error: bool = True) -> dict | None:
        """Get an existing OAuth client from OTDS

        Args:
            client_id (str): name (= ID) of the OAuth client to retrieve
            show_error (bool): whether or not we want to log an error if partion is not found
        Returns:
            dict: Request response (dictionary) or None if the client is not found.
        """

        request_url = "{}/{}".format(self.oauth_client_url(), client_id)

        logger.info("Get oauth client -> %s; calling -> %s", client_id, request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                        "Failed to get oauth client -> %s; error -> %s (%s)",
                        client_id,
                        response.text,
                        response.status_code,
                    )
                return None

    # end method definition

    def update_oauth_client(self, client_id: str, updates: dict) -> dict | None:
        """Updates the OAuth client with new values

        Args:
            client_id (str): name (= ID) of the OAuth client
            updates (dict): new values for OAuth client, e.g.
                            {"description": "this is the new value"}

        Returns:
            dict: Request response (json) or None if the REST call fails.
        """

        oauthClientPatchBodyJson = updates

        request_url = "{}/{}".format(self.oauth_client_url(), client_id)

        logger.info(
            "Update OAuth client -> %s with -> %s; calling -> %s",
            client_id,
            updates,
            request_url,
        )

        retries = 0
        while True:
            response = requests.patch(
                url=request_url,
                json=oauthClientPatchBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to update OAuth client -> %s; error -> %s (%s)",
                    client_id,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def add_oauth_clients_to_access_role(self, access_role_name: str):
        """Add Oauth clients user partion to an OTDS Access Role

        Args:
            access_role_name (str): name of the OTDS Access Role
        Returns:
            response of REST call or None in case of an error
        """

        request_url = self.config()["accessRoleUrl"] + "/" + access_role_name

        logger.info(
            "Get access role -> %s; calling -> %s", access_role_name, request_url
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
                cookies=self.cookie(),
                timeout=None,
            )
            if response.ok:
                accessRolesJson = self.parse_request_response(response)
                break
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                retries += 1
            else:
                logger.error(
                    "Failed to retrieve role -> %s; url -> %s : error -> %s (%s)",
                    access_role_name,
                    request_url,
                    response.text,
                    response.status_code,
                )
                return None

        # Checking if OAuthClients partition already added to access role
        userPartitions = accessRolesJson["accessRoleMembers"]["userPartitions"]
        for userPartition in userPartitions:
            if userPartition["userPartition"] == "OAuthClients":
                logger.error(
                    "OAuthClients partition already added to role -> %s",
                    access_role_name,
                )
                return None

        # Getting location info for the OAuthClients partition
        # so it can be added to access roles json
        request_url = self.config()["partitionsUrl"] + "/OAuthClients"
        partitionsResponse = requests.get(
            url=request_url,
            headers=REQUEST_HEADERS,
            cookies=self.cookie(),
            timeout=None,
        )
        if partitionsResponse.ok:
            response_dict = self.parse_request_response(partitionsResponse)
            if not response_dict:
                return None
            oauthClientLocation = response_dict["location"]
        else:
            logger.error(
                "Failed to get partition info for OAuthClients; url -> %s : error -> %s (%s)",
                request_url,
                partitionsResponse.text,
                response.status_code,
            )
            return None

        # adding OAuthClients info to acess roles organizational units
        oauthClientsOuBlock = {
            "location": oauthClientLocation,
            "name": oauthClientLocation,
            "userPartition": None,
        }
        accessRolesJson["accessRoleMembers"]["organizationalUnits"].append(
            oauthClientsOuBlock
        )

        response = requests.put(
            url=request_url,
            json=accessRolesJson,
            headers=REQUEST_HEADERS,
            cookies=self.cookie(),
            timeout=None,
        )

        if response.ok:
            logger.info(
                "OauthClients partition successfully added to access role -> %s",
                access_role_name,
            )
        else:
            logger.warning(
                "Status code of -> %s returned attempting to add OAuthClients to access role -> %s: error -> %s",
                response.status_code,
                access_role_name,
                response.text,
            )
        return response

    # end method definition

    def get_access_token(self, client_id: str, client_secret: str) -> str | None:
        """Get the access token

        Args:
            client_id (str): OAuth client name (= ID)
            client_secret (str): OAuth client secret. This is typically returned
                                 by add_oauth_client() method in ["secret"] field

        Returns:
            str: access token, or None
        """

        encoded_client_secret = "{}:{}".format(client_id, client_secret).encode("utf-8")
        accessTokenRequestHeaders = {
            "Authorization": "Basic "
            + base64.b64encode(encoded_client_secret).decode("utf-8"),
            "Content-Type": "application/x-www-form-urlencoded",
        }

        request_url = self.token_url()

        response = requests.post(
            url=request_url,
            data={"grant_type": "client_credentials"},
            headers=accessTokenRequestHeaders,
            timeout=None,
        )

        access_token = None
        if response.ok:
            accessTokenJson = self.parse_request_response(response)

            if "access_token" in accessTokenJson:
                access_token = accessTokenJson["access_token"]
            else:
                return None

        return access_token

    # end method definition

    def get_auth_handler(self, name: str, show_error: bool = True) -> dict | None:
        """Get the OTDS auth handler with a given name.

        Args:
            name (str): Name of the authentication handler

        Returns:
            dict | None: auth handler dictionary, or None

            Example result:
            {
                '_name': 'Salesforce',
                '_id': 'Salesforce',
                '_description': 'Salesforce OAuth Authentication Handler',
                '_class': 'com.opentext.otds.as.drivers.http.OAuth2Handler',
                '_enabled': True,
                '_credentialBased': True,
                '_priority': 10,
                '_scope': None,
                '_properties': [
                    {
                        '_key': 'com.opentext.otds.as.drivers.http.oauth2.provider_name',
                        '_name': 'Provider Name',
                        '_description': 'The name of the authentication provider. This name is displayed on the login page.',
                        '_required': True,
                        '_fileBased': False,
                        '_fileName': False,
                        '_fileExtensions': None,
                        '_value': 'Salesforce',
                        '_allowedValues': None,
                        ...
                    },
                    ...
                ]
                '_authPrincipalAttrNames': ['oTExtraAttr0'],
                'createPermission': True,
                'readPermission': True,
                'updatePermission': True,
                'deletePermission': True,
                'enablePermission': True,
            }

        """

        request_url = "{}/{}".format(self.auth_handler_url(), name)

        logger.info(
            "Getting authentication handler -> %s; calling -> %s", name, request_url
        )

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                        "Failed to get authentication handler -> %s; warning -> %s (%s)",
                        name,
                        response.text,
                        response.status_code,
                    )
                return None

    # end method definition

    def add_auth_handler_saml(
        self,
        name: str,
        description: str,
        scope: str | None,
        provider_name: str,
        saml_url: str,
        otds_sp_endpoint: str,
        enabled: bool = True,
        priority: int = 5,
        active_by_default: bool = False,
        auth_principal_attributes: list | None = None,
        nameid_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    ) -> dict | None:
        """Add a new SAML authentication handler

        Args:
            name (str): name of the new authentication handler
            description (str): description of the new authentication handler
            scope (str): name of the user partition (to define a scope of the auth handler)
            provider_name (str): description of the new authentication handler
            saml_url (str): SAML URL
            otds_sp_endpoint (str): the external(!) service provider URL of OTDS
            enabled (bool, optional): if the handler should be enabled or disabled. Default is True = enabled.
            priority (int, optional): Priority of the Authentical Handler (compared to others). Default is 5
            active_by_default (bool, optional): should OTDS redirect immediately to provider page
                                                (not showing the OTDS login at all)
            auth_principal_attributes (list, optional): List of Authentication principal attributes
            nameid_format (str, optional): Specifies which NameID format supported by the identity provider
                                           contains the desired user identifier. The value in this identifier
                                           must correspond to the value of the user attribute specified for the
                                           authentication principal attribute.
        Returns:
            dict: Request response (dictionary) or None if the REST call fails.
        """

        if auth_principal_attributes is None:
            auth_principal_attributes = ["oTExternalID1", "oTUserID1"]

        authHandlerPostBodyJson = {
            "_name": name,
            "_description": description,
            "_class": "com.opentext.otds.as.drivers.saml.SAML2Handler",
            "_enabled": str.lower(str(enabled)),
            "_priority": str(priority),
            "_authPrincipalAttrNames": auth_principal_attributes,
            "_scope": scope,
            "_properties": [
                {
                    "_key": "com.opentext.otds.as.drivers.saml.provider_name",
                    "_name": "Identity Provider (IdP) Name",
                    "_description": "The name of the identity provider. This should be a single word since it will be part of the metadata URL.",
                    "_value": provider_name,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.provider_metadata_description",
                    "_name": "IdP Metadata URL",
                    "_description": "The URL for the IdP's federation metadata. The metadata will be automatically updated by OTDS daily at midnight.",
                    "_value": saml_url,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.provider_nameid_format",
                    "_name": "IdP NameID Format",
                    "_description": "Specifies which NameID format supported by the identity provider contains the desired user identifier. The value in this identifier must correspond to the value of the user attribute specified for the authentication principal attribute. This value is usually set to urn:oasis:names:tc:SAML:2.0:nameid-format:persistent or urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress. Please ensure this is consistent with the identity provider's configuration.",
                    "_value": nameid_format,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml._impersonator_claim",
                    "_name": "Claim for impersonating user",
                    "_description": "A claim that contains the ID of the actor/impersonator for the user identified by NameID. It must be in the same format as NameID.",
                    "_value": "loggedinuserid",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.sp_url",
                    "_name": "OTDS SP Endpoint",
                    "_description": "Specifies the service provider URL that will be used to identify OTDS to the identity provider. If not specified, the URL will be taken from the request. This generally needs to be configured for environments in which OTDS is behind a reverse-proxy.",
                    "_value": otds_sp_endpoint,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.enable_sp_sso",
                    "_name": "Active By Default",
                    "_description": "Whether to activate this handler for any request to the OTDS login page. If true, any login request to the OTDS login page will be redirected to the IdP. If false, the user has to select the provider on the login page.",
                    "_value": active_by_default,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml._signature_alg",
                    "_name": "XML Signature Algorithm",
                    "_description": "Only relevant when certificate and private key are configured. Default is http://www.w3.org/2000/09/xmldsig#rsa-sha1. Valid values are defined at http://www.w3.org/TR/xmldsig-core1/#sec-AlgID.",
                    "_value": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.use_acs_url",
                    "_name": "Use AssertionConsumerServiceURL",
                    "_description": "Set to true to have the SAML AuthnRequest use AssertionConsumerServiceURL instead of AssertionConsumerServiceIndex",
                    "_value": "true",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.grace_period",
                    "_name": "Grace Period",
                    "_description": 'Specifies the number of minutes to allow for "NotBefore" and "NotOnOrAfter" fields when validating assertions in order to account for time difference between the identity provider and this service provider.',
                    "_value": "5",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.auth_request_binding",
                    "_name": "Auth Request Binding",
                    "_description": "Specifies the preferred SAML binding to use for sending the AuthnRequest, provided it is supported by the identity provider.",
                    "_value": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
                {
                    "_key": "com.opentext.otds.as.drivers.saml.auth_response_binding",
                    "_name": "Auth Response Binding",
                    "_description": "Specifies the SAML binding to use for the response to an AuthnRequest",
                    "_value": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
            ],
        }

        request_url = self.auth_handler_url()

        logger.info(
            "Adding SAML auth handler -> %s (%s); calling -> %s",
            name,
            description,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=authHandlerPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add SAML auth handler -> %s; error -> %s (%s)",
                    name,
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def add_auth_handler_sap(
        self,
        name: str,
        description: str,
        scope: str | None,
        certificate_file: str,
        certificate_password: str,
        enabled: bool = True,
        priority: int = 10,
        auth_principal_attributes: list | None = None,
    ):
        """Add a new SAP authentication handler

        Args:
            name (str): name of the new authentication handler
            description (str): description of the new authentication handler
            scope (str): name of the user partition (to define a scope of the auth handler)
            certificate_file (str): fully qualified file name (with path) to the certificate file
            certificate_password (str): password of the certificate
            enabled (bool, optional): if the handler should be enabled or disabled. Default is True = enabled.
            priority (int, optional): Priority of the Authentical Handler (compared to others). Default is 5
            auth_principal_attributes (list, optional): List of Authentication principal attributes
        Returns:
            Request response (json) or None if the REST call fails.
        """

        # Avoid linter warning W0102:
        if auth_principal_attributes is None:
            auth_principal_attributes = ["oTExternalID1"]

        # 1. Prepare the body for the AuthHandler REST call:
        authHandlerPostBodyJson = {
            "_name": name,
            "_description": description,
            "_class": "com.opentext.otds.as.drivers.sapssoext.SAPSSOEXTAuthHandler",
            "_enabled": str.lower(str(enabled)),
            "_priority": str(priority),
            "_authPrincipalAttrNames": auth_principal_attributes,
            "_scope": scope,
            "_properties": [
                {
                    "_key": "com.opentext.otds.as.drivers.sapssoext.certificate_description1",
                    "_name": "SAP Certificate 1 Description",
                    "_description": "Specifies a custom description for the corresponding certificate.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": os.path.basename(
                        certificate_file
                    ),  # "TM6_Sandbox.pse" - file name only
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.sapssoext.certificate1",
                    "_name": "SAP Certificate (PSE) 1",
                    "_description": "Specifies a certificate (.pse file) to use to decode SAP tokens. Note: The selected file does not need to reside on the server since only its contents will be stored on the server. Clear the string in this field in order to delete the certificate stored on the server.",
                    "_required": False,
                    "_fileBased": True,
                    "_fileName": False,
                    "_fileExtensions": ["pse"],
                    "_value": None,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.sapssoext.certificate_pass1",
                    "_name": "SAP Certificate 1 Password",
                    "_description": "Specifies the password for the corresponding .pse file.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": certificate_password,
                    "_allowedValues": None,
                    "_confidential": True,
                    "_keepOriginal": False,
                },
            ],
        }

        # 2. Create the auth handler in OTDS
        request_url = self.auth_handler_url()

        logger.info(
            "Adding SAP auth handler -> %s (%s); calling -> %s",
            name,
            description,
            request_url,
        )

        response = requests.post(
            url=request_url,
            json=authHandlerPostBodyJson,
            headers=REQUEST_HEADERS,
            cookies=self.cookie(),
            timeout=None,
        )
        if not response.ok:
            logger.error(
                "Failed to add SAP auth handler -> %s; error -> %s (%s)",
                name,
                response.text,
                response.status_code,
            )
            return None

        # 3. Upload the certificate file:

        # Check that the certificate (PSE) file is readable:
        logger.info("Reading certificate file -> %s...", certificate_file)
        try:
            # PSE files are binary - so we need to open with "rb":
            with open(certificate_file, "rb") as certFile:
                certContent = certFile.read()
                if not certContent:
                    logger.error("No data in certificate file -> %s", certificate_file)
                    return None
        except IOError as exception:
            logger.error(
                "Unable to open certificate file -> %s; error -> %s",
                certificate_file,
                exception.strerror,
            )
            return None

        # Check that we have the binary certificate file - this is what OTDS expects. If the file content is
        # base64 encoded we will decode it and write it back into the same file
        try:
            # If file is not base64 encoded the next statement will throw an exception
            # (this is good)
            certContentDecoded = base64.b64decode(certContent, validate=True)
            certContentEncoded = base64.b64encode(certContentDecoded).decode("utf-8")
            if certContentEncoded == certContent.decode("utf-8"):
                logger.info(
                    "Certificate file -> %s is base64 encoded", certificate_file
                )
                cert_file_encoded = True
            else:
                cert_file_encoded = False
        except TypeError:
            logger.info(
                "Certificate file -> %s is not base64 encoded", certificate_file
            )
            cert_file_encoded = False

        if cert_file_encoded:
            certificate_file = "/tmp/" + os.path.basename(certificate_file)
            logger.info("Writing decoded certificate file -> %s...", certificate_file)
            try:
                # PSE files need to be binary - so we need to open with "wb":
                with open(certificate_file, "wb") as certFile:
                    certFile.write(base64.b64decode(certContent))
            except IOError as exception:
                logger.error(
                    "Failed writing to file -> %s; error -> %s",
                    certificate_file,
                    exception.strerror,
                )
                return None

        authHandlerPostData = {
            "file1_property": "com.opentext.otds.as.drivers.sapssoext.certificate1"
        }

        # It is important to send the file pointer and not the actual file content
        # otherwise the file is send base64 encoded which we don't want:
        authHandlerPostFiles = {
            "file1": (
                os.path.basename(certificate_file),
                open(certificate_file, "rb"),
                "application/octet-stream",
            )
        }

        request_url = self.auth_handler_url() + "/" + name + "/files"

        logger.info(
            "Uploading certificate file -> %s for SAP auth handler -> %s (%s); calling -> %s",
            certificate_file,
            name,
            description,
            request_url,
        )

        # it is important to NOT pass the headers parameter here!
        # Basically, if you specify a files parameter (a dictionary),
        # then requests will send a multipart/form-data POST automatically:
        response = requests.post(
            url=request_url,
            data=authHandlerPostData,
            files=authHandlerPostFiles,
            cookies=self.cookie(),
            timeout=None,
        )
        if not response.ok:
            logger.error(
                "Failed to upload certificate file -> %s for SAP auth handler -> %s; error -> %s (%s)",
                certificate_file,
                name,
                response.text,
                response.status_code,
            )
            return None

        return response

    # end method definition

    def add_auth_handler_oauth(
        self,
        name: str,
        description: str,
        scope: str | None,
        provider_name: str,
        client_id: str,
        client_secret: str,
        active_by_default: bool = False,
        authorization_endpoint: str = "",
        token_endpoint: str = "",
        scope_string: str = "",
        enabled: bool = True,
        priority: int = 10,
        auth_principal_attributes: list | None = None,
    ) -> dict | None:
        """Add a new OAuth authentication handler

        Args:
            name (str): name of the new authentication handler
            description (str): description of the new authentication handler
            scope (str): name of the user partition (to define a scope of the auth handler)
            provider_name (str): the name of the authentication provider. This name is displayed on the login page.
            client_id (str): the client ID
            client_secret (str): the client secret
            active_by_default (bool, optional): Whether to activate this handler for any request to the OTDS login page.
                                                If True, any login request to the OTDS login page will be redirected to this OAuth provider.
                                                If False, the user has to select the provider on the login page.
            authorization_endpoint (str, optional): The URL to redirect the browser to for authentication.
                                                    It is used to retrieve the authorization code or an OIDC id_token.
            token_endpoint (str, optional): The URL from which to retrieve the access token.
                                            Not strictly required with OpenID Connect if using the implicit flow.
            scope_string (str, optional): Space delimited scope values to send. Include 'openid' to use OpenID Connect.
            enabled (bool, optional): if the handler should be enabled or disabled. Default is True = enabled.
            priority (int, optional): Priority of the Authentical Handler (compared to others). Default is 5
            auth_principal_attributes (list, optional): List of Authentication principal attributes
        Returns:
            dict: Request response (dictionary) or None if the REST call fails.
        """

        # Avoid linter warning W0102:
        if auth_principal_attributes is None:
            auth_principal_attributes = ["oTExtraAttr0"]

        # 1. Prepare the body for the AuthHandler REST call:
        authHandlerPostBodyJson = {
            "_name": name,
            "_description": description,
            "_class": "com.opentext.otds.as.drivers.http.OAuth2Handler",
            "_enabled": str.lower(str(enabled)),
            "_priority": str(priority),
            "_authPrincipalAttrNames": auth_principal_attributes,
            "_scope": scope,
            "_properties": [
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.provider_name",
                    "_name": "Provider Name",
                    "_description": "The name of the authentication provider. This name is displayed on the login page.",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": provider_name,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.active_by_default",
                    "_name": "Active By Default",
                    "_description": "Whether to activate this handler for any request to the OTDS login page. If true, any login request to the OTDS login page will be redirected to this OAuth provider. If false, the user has to select the provider on the login page.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": active_by_default,
                    "_allowedValues": ["true", "false"],
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.client_id",
                    "_name": "Client ID",
                    "_description": "The Client ID",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": client_id,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.client_secret",
                    "_name": "Client Secret",
                    "_description": "The Client Secret",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": client_secret,
                    "_allowedValues": None,
                    "_confidential": True,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.scope_string",
                    "_name": "Scope String",
                    "_description": "Space delimited scope values to send. Include 'openid' to use OpenID Connect.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": scope_string,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.get_code_url",
                    "_name": "Authorization Endpoint",
                    "_description": "The URL to redirect the browser to for authentication. It is used to retrieve the authorization code or an OIDC id_token.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": authorization_endpoint,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.get_access_token_url",
                    "_name": "Token Endpoint",
                    "_description": "The URL from which to retrieve the access token. Not strictly required with OpenID Connect if using the implicit flow.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": token_endpoint,
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.get_user_info_url",
                    "_name": "User Info Endpoint",
                    "_description": "The URL from which to retrieve the JSON object representing the authorized user",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "{id}",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.user_identifier",
                    "_name": "User Identifier Field",
                    "_description": "The field corresponding to the user's unique ID at this provider",
                    "_required": True,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "username",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.field1",
                    "_name": "Response Field 1",
                    "_description": "A field in the JSON response that should be mapped to an OTDS attribute. This value is case sensitive. Mapped fields are only relevant for auto-provisioned accounts.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "email",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute1",
                    "_name": "OTDS Attribute 1",
                    "_description": "OTDS user attribute to which the response field should be mapped.",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "mail",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.field2",
                    "_name": "Response Field 2",
                    "_description": "",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "first_name",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute2",
                    "_name": "OTDS Attribute 2",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "givenName",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.field3",
                    "_name": "Response Field 3",
                    "_description": "",
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "last_name",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute3",
                    "_name": "OTDS Attribute 3",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "sn",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute4",
                    "_name": "OTDS Attribute 4",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "displayName",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute5",
                    "_name": "OTDS Attribute 5",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTStreetAddress",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute6",
                    "_name": "OTDS Attribute 6",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "l",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute7",
                    "_name": "OTDS Attribute 7",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "st",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute8",
                    "_name": "OTDS Attribute 8",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "postalCode",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute9",
                    "_name": "OTDS Attribute 9",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "countryName",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute10",
                    "_name": "OTDS Attribute 10",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTTelephoneNumber",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute11",
                    "_name": "OTDS Attribute 11",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTMemberOf",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute12",
                    "_name": "OTDS Attribute 12",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "oTDepartment",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
                {
                    "_key": "com.opentext.otds.as.drivers.http.oauth2.attribute13",
                    "_name": "OTDS Attribute 13",
                    "_description": None,
                    "_required": False,
                    "_fileBased": False,
                    "_fileName": False,
                    "_fileExtensions": None,
                    "_value": "title",
                    "_allowedValues": None,
                    "_confidential": False,
                    "_keepOriginal": False,
                },
            ],
        }

        request_url = self.auth_handler_url()

        logger.info(
            "Adding OAuth auth handler -> %s (%s); calling -> %s",
            name,
            description,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=authHandlerPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to add OAuth auth handler -> %s; error -> %s (%s)",
                    name,
                    response.text,
                    response.status_code,
                )
                return None

        # end method definition

    def consolidate(self, resource_name: str) -> bool:
        """Consolidate an OTDS resource

        Args:
            resource_name (str): resource to be consolidated
        Returns:
            bool: True if the consolidation succeeded or False if it failed.
        """

        resource = self.get_resource(resource_name)
        if not resource:
            logger.error("Resource -> %s not found - cannot consolidate", resource_name)
            return False

        resource_dn = resource["resourceDN"]
        if not resource_dn:
            logger.error("Resource DN is empty - cannot consolidate")
            return False

        consolidationPostBodyJson = {
            "cleanupUsersInResource": False,
            "cleanupGroupsInResource": False,
            "resourceList": [resource_dn],
            "objectToConsolidate": resource_dn,
        }

        request_url = "{}".format(self.consolidation_url())

        logger.info(
            "Consolidation of resource -> %s; calling -> %s", resource_dn, request_url
        )

        retries = 0
        while True:
            response = requests.post(
                url=request_url,
                json=consolidationPostBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to consolidate; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def impersonate_resource(
        self,
        resource_name: str,
        allow_impersonation: bool = True,
        impersonation_list: list | None = None,
    ) -> bool:
        """Configure impersonation for an OTDS resource

        Args:
            resource_name (str): resource to be configure impersonation for
            allow_impersonation (bool, optional): wether to turn on or off impersonation (default = True)
            impersonation_list (list, optional): list of users to restrict it to
                                                 (default = empty list = all users)
        Returns:
            bool: True if the impersonation setting succeeded or False if it failed.
        """

        # Avoid linter warning W0102:
        if impersonation_list is None:
            impersonation_list = []

        impersonationPutBodyJson = {
            "allowImpersonation": allow_impersonation,
            "impersonateList": impersonation_list,
        }

        request_url = "{}/{}/impersonation".format(self.resource_url(), resource_name)

        logger.info(
            "Impersonation settings for resource -> %s; calling -> %s",
            resource_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=impersonationPutBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to set impersonation for resource -> %s; error -> %s",
                    resource_name,
                    response.text,
                )
                return False

    # end method definition

    def impersonate_oauth_client(
        self,
        client_id: str,
        allow_impersonation: bool = True,
        impersonation_list: list | None = None,
    ) -> bool:
        """Configure impersonation for an OTDS OAuth Client

        Args:
            client_id (str): OAuth Client to be configure impersonation for
            allow_impersonation (bool, optional): wether to turn on or off impersonation (default = True)
            impersonation_list (list, optional): list of users to restrict it to; (default = empty list = all users)
        Returns:
            bool: True if the impersonation setting succeeded or False if it failed.
        """

        # Avoid linter warning W0102:
        if impersonation_list is None:
            impersonation_list = []

        impersonationPutBodyJson = {
            "allowImpersonation": allow_impersonation,
            "impersonateList": impersonation_list,
        }

        request_url = "{}/{}/impersonation".format(self.oauth_client_url(), client_id)

        logger.info(
            "Impersonation settings for OAuth Client -> %s; calling -> %s",
            client_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=impersonationPutBodyJson,
                headers=REQUEST_HEADERS,
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
                    "Failed to set impersonation for OAuth Client -> %s; error -> %s (%s)",
                    client_id,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

    def get_password_policy(self):
        """Get the global password policy

        Args:
            None
        Returns:
            dict: Request response or None if the REST call fails.

            Example response:
            {
                'passwordHistoryMaximumCount': 3,
                'daysBeforeNewPasswordMayBeChanged': 1,
                'passwordMaximumDuration': 90,
                'daysBeforeOldPasswordMayBeReused': 0,
                'lockoutFailureCount': 0,
                'lockoutDuration': 15,
                'minimumNumberOfCharacters': 8,
                'complexPasswordValidationEnabled': True,
                'minimumNumberOfDigits': 1,
                'minimumNumberOfSymbols': 1,
                'minimumNumberOfUppercase': 1,
                'minimumNumberOfLowercase': 1,
                'minimumChangesToPreviousPassword': 0,
                'maxNumberOfConsecutiveANCharsInPassword': 0,
                'blockCommonPassword': False
                ...
            }
        """

        request_url = "{}/passwordpolicy".format(self.config()["systemConfigUrl"])

        logger.info("Getting password policy; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                url=request_url,
                headers=REQUEST_HEADERS,
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
                    "Failed to get password policy; error -> %s (%s)",
                    response.text,
                    response.status_code,
                )
                return None

    # end method definition

    def update_password_policy(self, update_values: dict) -> bool:
        """Update the global password policy

        Args:
            update_values (dict): new values for selected settings.
                                  A value of 0 means the settings is deactivated.

            Example values:
            {
                'passwordHistoryMaximumCount': 3,
                'daysBeforeNewPasswordMayBeChanged': 1,
                'passwordMaximumDuration': 90,
                'daysBeforeOldPasswordMayBeReused': 0,
                'lockoutFailureCount': 0,
                'lockoutDuration': 15,
                'minimumNumberOfCharacters': 8,
                'complexPasswordValidationEnabled': True,
                'minimumNumberOfDigits': 1,
                'minimumNumberOfSymbols': 1,
                'minimumNumberOfUppercase': 1,
                'minimumNumberOfLowercase': 1,
                'minimumChangesToPreviousPassword': 0,
                'maxNumberOfConsecutiveANCharsInPassword': 0,
                'blockCommonPassword': False
                ...
            }
        Returns:
            bool: True if the REST call succeeds, otherwise False. We use a boolean return
                  value as the response of the REST call does not have meaningful content.

        """

        request_url = "{}/passwordpolicy".format(self.config()["systemConfigUrl"])

        logger.info(
            "Update password policy with these new values -> %s; calling -> %s",
            update_values,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                url=request_url,
                json=update_values,
                headers=REQUEST_HEADERS,
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
                    "Failed to update password policy with values -> %s; error -> %s (%s)",
                    update_values,
                    response.text,
                    response.status_code,
                )
                return False

    # end method definition

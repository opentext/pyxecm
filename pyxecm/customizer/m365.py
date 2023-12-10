"""
M365 Module to interact with the MS Graph API
See also https://learn.microsoft.com/en-us/graph/ 

Class: M365
Methods:

__init__ : class initializer
config : Returns config data set
credentials: Returns the token data
credentials_user: In some cases MS Graph APIs cannot be called via
                  application permissions (client_id, client_secret)
                  but requires a token of a user authenticated
                  with username + password
request_header: Returns the request header for MS Graph API calls
request_header_user: Returns the request header used for user specific calls
parse_request_response: Parse the REST API responses and convert
                        them to Python dict in a safe way
exist_result_item: Check if an dict item is in the response
                   of the Graph REST API call
get_result_value: Check if a defined value (based on a key) is in the Graph API response

authenticate : Authenticates at M365 Graph API
authenticate_user: Authenticate at M365 Graph API with username and password

get_users: Get list all all users in M365 tenant 
get_user: Get a M365 User based on its email
add_user: Add a M365 User
update_user: Update selected properties of an M365 user
get_user_licenses: Get the assigned license SKUs of a user
assign_license_to_user: Add an M365 license to a user (e.g. to use Office 365)
get_user_photo: Get the photo of a M365 user
update_user_photo: Update a user with a profile photo (which must be in local file system)

get_groups: Get list all all groups in M365 tenant
get_group: Get a M365 Group based on its name
add_group: Add a M365 Group
get_group_members: Get members (users and groups) of the specified group
add_group_member: Add a user or group to a target group
is_member: Check whether a M365 user is already in a M365 group
get_group_owners: Get owners (users) of the specified group
add_group_owner: Add a user as owner to a group

purge_deleted_items: Purge all deleted users and groups in the organization
purge_deleted_item: Help function that purges a single user or group

has_team: Check if a M365 Group has a M365 Team connected or not
get_team: get a M365 Team based on its name
add_team: Add a M365 Team (based on an existing group)
delete_team: delete a single M365 Team witha given ID
delete_teams: Delete MS teams with a given name
delete_all_teams: Delete all teams (groups) that are NOT on the exception list AND
                  that are matching at least one of the patterns in the provided pattern list
get_team_channels: get a list of channels for a M365 Team
get_team_channel_tabs: get tabs of an M365 Team channel based on the team and channel names

get_teams_apps: Get a list of MS Teams apps in catalog that match a given filter criterium
get_teams_app: get a specific app from the catalog based on its (known) ID
get_teams_apps_of_user: Get a list of MS Teams apps of a user that match a given filter criterium
get_teams_apps_of_team: Get a list of MS Teams apps of a M365 team that match a given filter criterium
extract_version_from_app_manifest: Extract the version number from the MS Teams app manifest file
upload_teams_app: Upload a new app package to the catalog of MS Teams apps
remove_teams_app: Remove MS Teams App for the app catalog
assign_teams_app_to_user: Assign (add) a MS Teams app to a M365 user.
upgrade_teams_app_of_user: Upgrade a MS teams app for a user.
assign_teams_app_to_team: Assign (add) a MS Teams app to a M365 team
                          (so that it afterwards can be added as a Tab in a M365 Teams Channel)
upgrade_teams_app_of_team: Upgrade a MS teams app for a specific team.
add_teams_app_to_channel: Add tab for Extended ECM app to an M365 Team channel
update_teams_app_of_channel: Update in existing teams app (e.g. to change the URLs with new node ID)
delete_teams_app_from_channel: Delete an app (and its tab) from a M365 Teams channel

add_sensitivity_label: Assign a existing sensitivity label to a user.
                       THIS IS CURRENTLY NOT WORKING!
assign_sensitivity_label_to_user: Create a new sensitivity label in M365
                                  THIS IS CURRENTLY NOT WORKING!
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright 2023, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import json
import logging
import os
import re
import time
import urllib.parse
import zipfile
from urllib.parse import quote

import requests

logger = logging.getLogger("pyxecm.customizer.m365")

request_login_headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "application/json",
}


class M365(object):
    """Used to automate stettings in Microsoft 365 via the Graph API."""

    _config: dict
    _access_token = None
    _user_access_token = None

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        domain: str,
        sku_id: str,
        teams_app_name: str,
    ):
        """Initialize the M365 object

        Args:
            tenant_id (str): M365 Tenant ID
            client_id (str): M365 Client ID
            client_secret (str): M365 Client Secret
            domain (str): M365 domain
            sku_id (str): License SKU for M365 users
            teams_app_name (str): name of the Extended ECM app for MS Teams
        """

        m365_config = {}

        # Set the authentication endpoints and credentials
        m365_config["tenantId"] = tenant_id
        m365_config["clientId"] = client_id
        m365_config["clientSecret"] = client_secret
        m365_config["domain"] = domain
        m365_config["skuId"] = sku_id
        m365_config["teamsAppName"] = teams_app_name
        m365_config[
            "authenticationUrl"
        ] = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(tenant_id)
        m365_config["graphUrl"] = "https://graph.microsoft.com/v1.0/"
        m365_config["betaUrl"] = "https://graph.microsoft.com/beta/"
        m365_config["directoryObjects"] = m365_config["graphUrl"] + "directoryObjects"

        # Set the data for the token request
        m365_config["tokenData"] = {
            "client_id": client_id,
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": client_secret,
            "grant_type": "client_credentials",
        }

        m365_config["groupsUrl"] = m365_config["graphUrl"] + "groups"
        m365_config["usersUrl"] = m365_config["graphUrl"] + "users"
        m365_config["teamsUrl"] = m365_config["graphUrl"] + "teams"
        m365_config["teamsTemplatesUrl"] = m365_config["graphUrl"] + "teamsTemplates"
        m365_config["teamsAppsUrl"] = m365_config["graphUrl"] + "appCatalogs/teamsApps"
        m365_config["directoryUrl"] = m365_config["graphUrl"] + "directory"
        m365_config["securityUrl"] = m365_config["betaUrl"] + "security"
        m365_config["applicationsUrl"] = m365_config["graphUrl"] + "applications"

        self._config = m365_config

    def config(self) -> dict:
        """Returns the configuration dictionary

        Returns:
            dict: Configuration dictionary
        """
        return self._config

    def credentials(self) -> dict:
        """Return the login credentials

        Returns:
            dict: dictionary with login credentials for M365
        """
        return self.config()["tokenData"]

    def credentials_user(self, username: str, password: str) -> dict:
        """In some cases MS Graph APIs cannot be called via
            application permissions (client_id, client_secret)
            but requires a token of a user authenticated
            with username + password. This is e.g. the case
            to upload a MS teams app to the catalog.
            See https://learn.microsoft.com/en-us/graph/api/teamsapp-publish

        Args:
            username (str): username
            password (str): password
        Returns:
            dict: user credentials for M365
        """

        credentials = {
            "client_id": self.config()["clientId"],
            "scope": "https://graph.microsoft.com/.default",
            "client_secret": self.config()["clientSecret"],
            "grant_type": "password",
            "username": username,
            "password": password,
        }
        return credentials

    # end method definition

    def request_header(self, content_type: str = "application/json") -> dict:
        """Returns the request header used for Application calls.
           Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional): content type for the request
        Return:
            dict: request header values
        """

        request_header = {
            "Authorization": "Bearer {}".format(self._access_token),
            "Content-Type": content_type,
        }
        return request_header

    # end method definition

    def request_header_user(self, content_type: str = "application/json") -> dict:
        """Returns the request header used for user specific calls.
           Consists of Bearer access token and Content Type

        Args:
            content_type (str, optional): content type for the request
        Return:
            dict: request header values
        """

        request_header = {
            "Authorization": "Bearer {}".format(self._user_access_token),
            "Content-Type": content_type,
        }
        return request_header

    # end method definition

    def parse_request_response(
        self,
        response_object: requests.Response,
        additional_error_message: str = "",
        show_error: bool = True,
    ) -> dict | None:
        """Converts the request response (JSon) to a Python dict in a safe way
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
            dict: response information or None in case of an error
        """

        if not response_object:
            return None

        try:
            if response_object.text:
                dict_object = json.loads(response_object.text)
            else:
                dict_object = vars(response_object)
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

    def exist_result_item(
        self, response: dict, key: str, value: str, sub_dict_name: str = ""
    ) -> bool:
        """Check existence of key / value pair in the response properties of an MS Graph API call.

        Args:
            response (dict): REST response from an MS Graph REST Call
            key (str): property name (key)
            value (str): value to find in the item with the matching key
            sub_dict_name (str): some MS Graph API calls include nested
                                 dict structures that can be requested
                                 with an "expand" query parameter. In such
                                 a case we use the sub_dict_name to access it.
        Returns:
            bool: True if the value was found, False otherwise
        """

        if not response:
            return False
        if not "value" in response:
            return False

        values = response["value"]
        if not values or not isinstance(values, list):
            return False

        if not sub_dict_name:
            for item in values:
                if value == item[key]:
                    return True
        else:
            for item in values:
                if not sub_dict_name in item:
                    return False
                if value == item[sub_dict_name][key]:
                    return True
        return False

    # end method definition

    def get_result_value(
        self, response: dict, key: str, index: int = 0, sub_dict_name: str = ""
    ) -> str | None:
        """Get value of a result property with a given key of an MS Graph API call.

        Args:
            response (dict): REST response from an MS Graph REST Call
            key (str): property name (key)
            index (int, optional): Index to use (1st element has index 0).
                                   Defaults to 0.
            sub_dict_name (str): some MS Graph API calls include nested
                                 dict structures that can be requested
                                 with an "expand" query parameter. In such
                                 a case we use the sub_dict_name to access it.
        Returns:
            str: value for the key, None otherwise
        """

        if not response:
            return None
        if (
            not "value" in response
        ):  # If Graph APIs are called with specific IDs (and not name lookups)
            # they may not return a list of dicts calles "values" but a single dict directly
            if sub_dict_name and sub_dict_name in response:
                sub_structure = response[sub_dict_name]
                # also the substructure could be a list
                if isinstance(sub_structure, list):
                    sub_structure = sub_structure[index]
                return sub_structure[key]
            elif key in response:
                return response[key]
            else:
                return None

        values = response["value"]
        if not values or not isinstance(values, list) or len(values) - 1 < index:
            return None

        if not sub_dict_name:
            return values[index][key]
        else:
            sub_structure = values[index][sub_dict_name]
            if isinstance(sub_structure, list):
                # here we assume it is the first element of the
                # substructure. If really required for specific
                # use cases we may introduce a second index in
                # the future.
                sub_structure = sub_structure[0]
            return sub_structure[key]

    # end method definition

    def authenticate(self, revalidate: bool = False) -> str | None:
        """Authenticate at M365 Graph API with client ID and client secret.

        Args:
            revalidate (bool, optional): determinse if a re-athentication is enforced
                                         (e.g. if session has timed out with 401 error)
        Returns:
            str: Access token. Also stores access token in self._access_token. None in case of error
        """

        # Already authenticated and session still valid?
        if self._access_token and not revalidate:
            return self._access_token

        request_url = self.config()["authenticationUrl"]
        request_header = request_login_headers

        logger.info("Requesting M365 Access Token from -> %s", request_url)

        authenticate_post_body = self.credentials()
        authenticate_response = None

        try:
            authenticate_response = requests.post(
                request_url,
                data=authenticate_post_body,
                headers=request_header,
                timeout=60,
            )
        except requests.exceptions.ConnectionError as exception:
            logger.warning(
                "Unable to connect to -> %s : %s",
                self.config()["authenticationUrl"],
                exception,
            )
            return None

        if authenticate_response.ok:
            authenticate_dict = self.parse_request_response(authenticate_response)
            if not authenticate_dict:
                return None
            else:
                access_token = authenticate_dict["access_token"]
                logger.debug("Access Token -> %s", access_token)
        else:
            logger.error(
                "Failed to request an M365 Access Token; error -> %s",
                authenticate_response.text,
            )
            return None

        # Store authentication access_token:
        self._access_token = access_token
        return self._access_token

    # end method definition

    def authenticate_user(self, username: str, password: str) -> str | None:
        """Authenticate at M365 Graph API with username and password.

        Args:
            username (str): name (emails) of the M365 user
            password (str): password of the M365 user
        Returns:
            str: Access token. Also stores access token in self._access_token
        """

        request_url = self.config()["authenticationUrl"]
        request_header = request_login_headers

        logger.info(
            "Requesting M365 Access Token for user -> %s from -> %s",
            username,
            request_url,
        )

        authenticate_post_body = self.credentials_user(username, password)
        authenticate_response = None

        try:
            authenticate_response = requests.post(
                request_url,
                data=authenticate_post_body,
                headers=request_header,
                timeout=60,
            )
        except requests.exceptions.ConnectionError as exception:
            logger.warning(
                "Unable to connect to -> %s with username -> %s: %s",
                self.config()["authenticationUrl"],
                username,
                exception,
            )
            return None

        if authenticate_response.ok:
            authenticate_dict = self.parse_request_response(authenticate_response)
            if not authenticate_dict:
                return None
            access_token = authenticate_dict["access_token"]
            logger.debug("User Access Token -> %s", access_token)
        else:
            logger.error(
                "Failed to request an M365 Access Token for user -> %s; error -> %s",
                username,
                authenticate_response.text,
            )
            return None

        # Store authentication access_token:
        self._user_access_token = access_token
        return self._user_access_token

    # end method definition

    def get_users(self) -> dict | None:
        """Get list all all users in M365 tenant

        Returns:
            dict: Dictionary of all users.
        """

        request_url = self.config()["usersUrl"]
        request_header = self.request_header()

        logger.info("Get list of all users; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of users; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_user(self, user_email: str, show_error: bool = False) -> dict | None:
        """Get a M365 User based on its email

        Args:
            user_email (str): M365 user email
            show_error (bool): whether or not an error should be displayed if the
                               user is not found.
        Returns:
            dict: User information or None if the user couldn't be retrieved (e.g. because it doesn't exist
                  or if there is a permission problem).
            Example return data:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#users/$entity',
                'businessPhones': [],
                'displayName': 'Bob Davis',
                'givenName': 'Bob',
                'id': '72c80809-094f-4e6e-98d4-25a736385d10',
                'jobTitle': None,
                'mail': 'bdavis@M365x61936377.onmicrosoft.com',
                'mobilePhone': None,
                'officeLocation': None,
                'preferredLanguage': None,
                'surname': 'Davis',
                'userPrincipalName': 'bdavis@M365x61936377.onmicrosoft.com'
            }
        """

        request_url = self.config()["usersUrl"] + "/" + user_email
        request_header = self.request_header()

        logger.info("Get M365 user -> %s; calling -> %s", user_email, request_url)

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get M365 user -> %s; status -> %s; error -> %s",
                        user_email,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info("M365 User -> %s not found.", user_email)
                return None

    # end method definition

    def add_user(
        self,
        email: str,
        password: str,
        first_name: str,
        last_name: str,
        location: str = "US",
        department: str = "",
        company_name: str = "Innovate",
    ) -> dict | None:
        """Add a M365 user.

        Args:
            email (str): email address of the user. This is also the unique identifier
            password (str): password of the user
            first_name (str): first name of the user
            last_name (str): last name of the user
            location (str, optional): country ISO 3166-1 alpha-2 format (e.g. US, CA, FR, DE, CN, ...)
            department (str, optional): department of the user
            company_name (str): name of the company
        Returns:
            dict: User information or None if the user couldn't be created (e.g. because it exisits already
                  or if a permission problem occurs).
        """

        user_post_body = {
            "accountEnabled": True,
            "displayName": first_name + " " + last_name,
            "givenName": first_name,
            "surname": last_name,
            "mailNickname": email.split("@")[0],
            "userPrincipalName": email,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": password,
            },
            "usageLocation": location,
        }
        if department:
            user_post_body["department"] = department
        if company_name:
            user_post_body["companyName"] = company_name

        request_url = self.config()["usersUrl"]
        request_header = self.request_header()

        logger.info("Adding M365 user -> %s; calling -> %s", email, request_url)

        retries = 0
        while True:
            response = requests.post(
                request_url,
                data=json.dumps(user_post_body),
                headers=request_header,
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to add M365 user -> %s; status -> %s; error -> %s",
                    email,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def update_user(self, user_id: str, updated_settings: dict) -> dict | None:
        """Update selected properties of an M365 user. Documentation
           on user properties is here: https://learn.microsoft.com/en-us/graph/api/user-update

        Returns:
            dict | None: Response of the M365 Graph API  or None if the call fails.
        """

        request_url = self.config()["usersUrl"] + "/" + user_id
        request_header = self.request_header()

        logger.info(
            "Updating M365 user -> %s with -> %s; calling -> %s",
            user_id,
            str(updated_settings),
            request_url,
        )

        retries = 0
        while True:
            response = requests.patch(
                request_url,
                json=updated_settings,
                headers=request_header,
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to update M365 user -> %s with -> %s; status -> %s; error -> %s",
                    user_id,
                    str(updated_settings),
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_user_licenses(self, user_id: str) -> dict | None:
        """Get the assigned license SKUs of a user

        Args:
            user_id (str): M365 GUID of the user (can also be the M365 email of the user)
        Returns:
            dict: List of user licenses or None if request fails.

            Example return data:
            {
                '@odata.context': "https://graph.microsoft.com/v1.0/$metadata#users('a5875311-f0a5-486d-a746-bd7372b91115')/licenseDetails",
                'value': [
                    {
                        'id': '8DRPYHK6IUOra-Nq6L0A7GAn38eBLPdOtXhbU5K1cd8',
                        'skuId': 'c7df2760-2c81-4ef7-b578-5b5392b571df',
                        'skuPartNumber': 'ENTERPRISEPREMIUM',
                        'servicePlans': [{...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, {...}, ...]
                    }
                ]
            }
        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/licenseDetails"
        request_header = self.request_header()

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get M365 licenses of user -> %s; status -> %s; error -> %s",
                    user_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def assign_license_to_user(self, user_id: str, sku_id: str) -> dict | None:
        """Add an M365 license to a user (e.g. to use Office 365)

        Args:
            user_id (str): M365 GUID of the user (can also be the M365 email of the user)
            sku_id (str): M365 GUID of the SKU
                          (e.g. c7df2760-2c81-4ef7-b578-5b5392b571df for E5 and
                                6fd2c87f-b296-42f0-b197-1e91e994b900 for E3)

        Returns:
            dict: response or None if request fails
        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/assignLicense"
        request_header = self.request_header()

        # Construct the request body for assigning the E5 license
        license_post_body = {
            "addLicenses": [
                {
                    "disabledPlans": [],
                    "skuId": sku_id,  # "c42b9cae-ea4f-4a69-9ca5-c53bd8779c42"
                }
            ],
            "removeLicenses": [],
        }

        logger.info(
            "Assign M365 license -> %s to M365 user -> %s; calling -> %s",
            sku_id,
            user_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url, json=license_post_body, headers=request_header, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to add M365 license -> %s to M365 user -> %s; status -> %s; error -> %s",
                    sku_id,
                    user_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_user_photo(self, user_id: str, show_error: bool = True) -> bytes | None:
        """Get the photo of a M365 user

        Args:
            user_id (str): M365 GUID of the user (can also be the M365 email of the user)
            show_error (bool): whether or not an error should be logged if the user
                                  does not have a photo in M365
        Returns:
            bytes: Image of the user photo or None if the user photo couldn't be retrieved.
        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/photo/$value"
        # Set image as content type:
        request_header = self.request_header("image/*")

        logger.info("Get photo of user -> %s; calling -> %s", user_id, request_url)

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return response.content  # this is the actual image - not json!
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get photo of user -> %s; status -> %s; error -> %s",
                        user_id,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info("User -> %s does not yet have a photo.", user_id)
                return None

    # end method definition

    def update_user_photo(self, user_id: str, photo_path: str) -> dict | None:
        """Update the M365 user photo

        Args:
            user_id (str): M365 GUID of the user (can also be the M365 email of the user)
            photo_path (str): file system path with the location of the photo
        Returns:
            dict: Response of Graph REST API or None if the user photo couldn't be updated.
        """

        request_url = self.config()["usersUrl"] + "/" + user_id + "/photo/$value"
        # Set image as content type:
        request_header = self.request_header("image/*")

        # Check if the photo file exists
        if not os.path.isfile(photo_path):
            logger.error("Photo file -> %s not found!", photo_path)
            return None

        try:
            # Read the photo file as binary data
            with open(photo_path, "rb") as image_file:
                photo_data = image_file.read()
        except OSError as exception:
            # Handle any errors that occurred while reading the photo file
            logger.error(
                "Error reading photo file -> %s; error -> %s", photo_path, exception
            )
            return None

        data = photo_data

        logger.info(
            "Update M365 user -> %s with photo -> %s; calling -> %s",
            user_id,
            photo_path,
            request_url,
        )

        retries = 0
        while True:
            response = requests.put(
                request_url, headers=request_header, data=data, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to update user -> %s with photo -> %s; status -> %s; error -> %s",
                    user_id,
                    photo_path,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_groups(self, max_number: int = 250) -> dict | None:
        """Get list all all groups in M365 tenant

        Args:
            max_number (int, optional): maximum result values (limit)
        Returns:
            dict: dictionary of all groups or None in case of an error.
        """

        request_url = self.config()["groupsUrl"]
        request_header = self.request_header()

        logger.info("Get list of all M365 groups; calling -> %s", request_url)

        retries = 0
        while True:
            response = requests.get(
                request_url,
                headers=request_header,
                params={"$top": str(max_number)},
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of M365 groups; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_group(self, group_name: str, show_error: bool = False) -> dict | None:
        """Get a M365 Group based on its name

        Args:
            group_name (str): M365 Group name
            show_error (bool): should an error be logged if group is not found.
        Returns:
            dict: Group information or None if the group doesn't exist.

            Example return data:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#groups',
                'value': [
                    {
                        'id': 'b65f7dba-3ed1-49df-91bf-2bf99affcc8d',
                        'deletedDateTime': None,
                        'classification': None,
                        'createdDateTime': '2023-04-01T13:46:26Z',
                        'creationOptions': [],
                        'description': 'Engineering & Construction',
                        'displayName': 'Engineering & Construction',
                        'expirationDateTime': None,
                        'groupTypes': ['Unified'],
                        'isAssignableToRole': None,
                        'mail': 'Engineering&Construction@M365x61936377.onmicrosoft.com',
                        'mailEnabled': True,
                        'mailNickname': 'Engineering&Construction',
                        'membershipRule': None,
                        'membershipRuleProcessingState': None,
                        'onPremisesDomainName': None,
                        'onPremisesLastSyncDateTime': None,
                        'onPremisesNetBiosName': None,
                        'onPremisesSamAccountName': None,
                        'onPremisesSecurityIdentifier': None,
                        'onPremisesSyncEnabled': None,
                        'preferredDataLocation': None,
                        'preferredLanguage': None,
                        'proxyAddresses': ['SPO:SPO_d9deb3e7-c72f-4e8d-80fb-5d9411ca1458@SPO_604f34f0-ba72-4321-ab6b-e36ae8bd00ec', 'SMTP:Engineering&Construction@M365x61936377.onmicrosoft.com'],
                        'renewedDateTime': '2023-04-01T13:46:26Z',
                        'resourceBehaviorOptions': [],
                        'resourceProvisioningOptions': [],
                        'securityEnabled': False,
                        'securityIdentifier': 'S-1-12-1-3059711418-1239367377-4180393873-2379022234',
                        'theme': None,
                        'visibility': 'Public',
                        'onPremisesProvisioningErrors': []
                    },
                    {
                        'id': '61359860-302e-4016-b5cc-abff2293dff1',
                        ...
                    }
                ]
            }
        """

        query = {"$filter": "displayName eq '" + group_name + "'"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = self.config()["groupsUrl"] + "?" + encoded_query
        request_header = self.request_header()

        logger.info("Get M365 group -> %s; calling -> %s", group_name, request_url)

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                if show_error:
                    logger.error(
                        "Failed to get M365 group -> %s; status -> %s; error -> %s",
                        group_name,
                        response.status_code,
                        response.text,
                    )
                else:
                    logger.info("M365 Group -> %s not found.", group_name)
                return None

    # end method definition

    def add_group(
        self, name: str, security_enabled: bool = False, mail_enabled: bool = True
    ) -> dict | None:
        """Add a M365 Group.

        Args:
            name (str): name of the group
            security_enabled (bool, optional): whether or not this group is used for permission management
            mail_enabled (bool, optional): whether or not this group is email enabled
        Returns:
            dict: Group information or None if the group couldn't be created (e.g. because it exisits already).

            Example return data:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#groups/$entity',
                'id': '28906460-a69c-439e-84ca-c70becf37655',
                'deletedDateTime': None,
                'classification': None,
                'createdDateTime': '2023-04-01T11:40:13Z',
                'creationOptions': [],
                'description': None,
                'displayName': 'Test',
                'expirationDateTime': None,
                'groupTypes': ['Unified'],
                'isAssignableToRole': None,
                'mail': 'Diefenbruch@M365x61936377.onmicrosoft.com',
                'mailEnabled': True,
                'mailNickname': 'Test',
                'membershipRule': None,
                'membershipRuleProcessingState': None,
                'onPremisesDomainName': None,
                'onPremisesLastSyncDateTime': None,
                'onPremisesNetBiosName': None,
                'onPremisesSamAccountName': None,
                'onPremisesSecurityIdentifier': None,
                'onPremisesSyncEnabled': None,
                'onPremisesProvisioningErrors': [],
                'preferredDataLocation': None,
                'preferredLanguage': None,
                'proxyAddresses': ['SMTP:Test@M365x61936377.onmicrosoft.com'],
                'renewedDateTime': '2023-04-01T11:40:13Z',
                'resourceBehaviorOptions': [],
                'resourceProvisioningOptions': [],
                'securityEnabled': True,
                'securityIdentifier': 'S-1-12-1-680551520-1134470812-197642884-1433859052',
                'theme': None,
                'visibility': 'Public'
            }
        """

        group_post_body = {
            "displayName": name,
            "mailEnabled": mail_enabled,
            "mailNickname": name.replace(" ", ""),
            "securityEnabled": security_enabled,
            "groupTypes": ["Unified"],
        }

        request_url = self.config()["groupsUrl"]
        request_header = self.request_header()

        logger.info("Adding M365 group -> %s; calling -> %s", name, request_url)
        logger.debug("M365 group attributes -> %s", group_post_body)

        retries = 0
        while True:
            response = requests.post(
                request_url,
                data=json.dumps(group_post_body),
                headers=request_header,
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to add M365 group -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_group_members(self, group_name: str) -> dict | None:
        """Get members (users and groups) of the specified group.

        Args:
            group_name (str): name of the group
        Returns:
            dict: Response of Graph REST API or None if the REST call fails.
        """

        response = self.get_group(group_name)
        group_id = self.get_result_value(response, "id", 0)
        if not group_id:
            logger.error(
                "M365 Group -> %s does not exist! Cannot retrieve group members.",
                group_name,
            )
            return None

        query = {"$select": "id,displayName,mail,userPrincipalName"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = (
            self.config()["groupsUrl"] + "/" + group_id + "/members?" + encoded_query
        )
        request_header = self.request_header()

        logger.info(
            "Get members of M365 group -> %s (%s); calling -> %s",
            group_name,
            group_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get members of M365 group -> %s (%s); status -> %s; error -> %s",
                    group_name,
                    group_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_group_member(self, group_id: str, member_id: str) -> dict | None:
        """Add a member (user or group) to a (parent) group

        Args:
            group_id (str): M365 GUID of the group
            member_id (str): M365 GUID of the new member
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/members/$ref"
        request_header = self.request_header()

        group_member_post_body = {
            "@odata.id": self.config()["directoryObjects"] + "/" + member_id
        }

        logger.info(
            "Adding member -> %s to group -> %s; calling -> %s",
            member_id,
            group_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(group_member_post_body),
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)

            # Check if Session has expired - then re-authenticate and try once more
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to add member -> %s to M365 group -> %s; status -> %s; error -> %s",
                    member_id,
                    group_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def is_member(self, group_id: str, member_id: str, show_error: bool = True) -> bool:
        """Checks whether a M365 user is already in a M365 group

        Args:
            group_id (str): M365 GUID of the group
            member_id (str): M365 GUID of the user (member)
            show_error (bool): whether or not an error should be logged if the user
                                  is not a member of the group
        Returns:
            bool: True if the user is in the group. False otherwise.
        """

        # don't encode this URL - this has not been working!!
        request_url = (
            self.config()["groupsUrl"]
            + f"/{group_id}/members?$filter=id eq '{member_id}'"
        )
        request_header = self.request_header()

        logger.info(
            "Check if user -> %s is in group -> %s; calling -> %s",
            member_id,
            group_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                response = self.parse_request_response(response)
                if not "value" in response or len(response["value"]) == 0:
                    return False
                return True
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                # MS Graph API returns an error if the member is not in the
                # group. This is typically not what we want. We just return False.
                if show_error:
                    logger.error(
                        "Failed to check if user -> %s is in group -> %s; status -> %s; error -> %s",
                        member_id,
                        group_id,
                        response.status_code,
                        response.text,
                    )
                return False

    # end method definition

    def get_group_owners(self, group_name: str) -> dict | None:
        """Get owners (users) of the specified group.

        Args:
            group_name (str): name of the group
        Returns:
            dict: Response of Graph REST API or None if the REST call fails.
        """

        response = self.get_group(group_name)
        group_id = self.get_result_value(response, "id", 0)
        if not group_id:
            logger.error(
                "M365 Group -> %s does not exist! Cannot retrieve group owners.",
                group_name,
            )
            return None

        query = {"$select": "id,displayName,mail,userPrincipalName"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)

        request_url = (
            self.config()["groupsUrl"] + "/" + group_id + "/owners?" + encoded_query
        )
        request_header = self.request_header()

        logger.info(
            "Get owners of M365 group -> %s (%s); calling -> %s",
            group_name,
            group_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get owners of M365 group -> %s (%s); status -> %s; error -> %s",
                    group_name,
                    group_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_group_owner(self, group_id: str, owner_id: str) -> dict | None:
        """Add an owner (user) to a group

        Args:
            group_id (str): M365 GUID of the group
            owner_id (str): M365 GUID of the new member
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/owners/$ref"
        request_header = self.request_header()

        group_member_post_body = {
            "@odata.id": self.config()["directoryObjects"] + "/" + owner_id
        }

        logger.info(
            "Adding owner -> %s to M365 group -> %s; calling -> %s",
            owner_id,
            group_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                data=json.dumps(group_member_post_body),
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to add owner -> %s to M365 group -> %s; status -> %s; error -> %s",
                    owner_id,
                    group_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def purge_deleted_items(self):
        """Purge all deleted users and groups.
        Purging users and groups requires administrative rights that typically
        are not provided in Contoso example org.
        """

        request_header = self.request_header()

        request_url = (
            self.config()["directoryUrl"] + "/deletedItems/microsoft.graph.group"
        )
        response = requests.get(request_url, headers=request_header, timeout=60)
        deleted_groups = self.parse_request_response(response)

        for group in deleted_groups["value"]:
            group_id = group["id"]
            response = self.purge_deleted_item(group_id)

        request_url = (
            self.config()["directoryUrl"] + "/deletedItems/microsoft.graph.user"
        )
        response = requests.get(request_url, headers=request_header, timeout=60)
        deleted_users = self.parse_request_response(response)

        for user in deleted_users["value"]:
            user_id = user["id"]
            response = self.purge_deleted_item(user_id)

    # end method definition

    def purge_deleted_item(self, item_id: str) -> dict | None:
        """Helper method to purge a single deleted user or group.
           This requires elevated permissions that are typically
           not available via Graph API.

        Args:
            item_id (str): M365 GUID of the user or group to purge
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        request_url = self.config()["directoryUrl"] + "/deletedItems/" + item_id
        request_header = self.request_header()

        logger.info("Purging deleted item -> %s; calling -> %s", item_id, request_url)

        retries = 0
        while True:
            response = requests.delete(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to purge deleted item -> %s; status -> %s; error -> %s",
                    item_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def has_team(self, group_name: str) -> bool:
        """Check if a M365 Group has a M365 Team connected or not

        Args:
            group_name (str): name of the M365 group
        Returns:
            bool: Returns True if a Team is assigned and False otherwise
        """

        response = self.get_group(group_name)
        group_id = self.get_result_value(response, "id", 0)
        if not group_id:
            logger.error(
                "M365 Group -> %s not found. Cannot check if it has a M365 Team.",
                group_name,
            )
            return False

        request_url = self.config()["groupsUrl"] + "/" + group_id + "/team"
        request_header = self.request_header()

        logger.info(
            "Check if M365 Group -> %s has a M365 Team connected; calling -> %s",
            group_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)

            if response.status_code == 200:  # Group has a Team assigned!
                logger.info("Group -> %s has a M365 Team connected.", group_name)
                return True
            elif response.status_code == 404:  # Group does not have a Team assigned!
                logger.info("Group -> %s has no M365 Team connected.", group_name)
                return False
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to check if M365 Group -> %s has a M365 Team connected; status -> %s; error -> %s",
                    group_name,
                    response.status_code,
                    response.text,
                )
                return False

    # end method definition

    def get_team(self, name: str) -> dict | None:
        """Get a M365 Team based on its name

        Args:
            name (str): name of the M365 Team
        Returns:
            dict: teams data structure (dictionary) or None if the request fails.

            Example return data:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#teams',
                '@odata.count': 1,
                'value': [
                    {
                        'id': '951bd036-c6fc-4da4-bb80-1860f5472a2f',
                        'createdDateTime': None,
                        'displayName': 'Procurement',
                        'description': 'Procurement',
                        'internalId': None,
                        'classification': None,
                        'specialization': None,
                        'visibility': 'public',
                        'webUrl': None, ...}]}
                        'isArchived': None,
                        'isMembershipLimitedToOwners': None,
                        'memberSettings': None,
                        'guestSettings': None,
                        'messagingSettings': None,
                        ...
                    }
                ]
            }
        """

        # The M365 Teams API has an issues with ampersand characters in team names (like "Engineering & Construction")
        # So we do a work-around here to first get the Team ID via the Group endpoint of the Graph API and
        # then fetch the M365 Team via its ID (which is identical to the underlying M365 Group ID)
        response = self.get_group(name)
        team_id = self.get_result_value(response, "id", 0)
        if not team_id:
            logger.error(
                "Failed to get the ID of the M365 Team -> %s via the M365 Group API",
                name,
            )
            return None

        request_url = self.config()["teamsUrl"] + "/" + str(team_id)

        request_header = self.request_header()

        logger.info(
            "Lookup Microsoft 365 Teams with name -> %s; calling -> %s",
            name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get M365 Team -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_team(self, name: str, template_name: str = "standard") -> dict | None:
        """Add M365 Team based on an existing M365 Group.

        Args:
            name (str): name of the team. It is assumed that a group with the same name does already exist!
            template_name (str, optional): name of the team template. "standard" is the default value.
        Returns:
            dict: Team information (json - empty text!) or None if the team couldn't be created
                  (e.g. because it exisits already).
        """

        response = self.get_group(name)
        group_id = self.get_result_value(response, "id", 0)
        if not group_id:
            logger.error(
                "M365 Group -> %s not found. It is required for creating a corresponding M365 Team.",
                name,
            )
            return None

        response = self.get_group_owners(name)
        if response is None or not "value" in response or not response["value"]:
            logger.warning(
                "M365 Group -> %s has no owners. This is required for creating a corresponding M365 Team.",
                name,
            )
            return None

        team_post_body = {
            "template@odata.bind": "{}('{}')".format(
                self.config()["teamsTemplatesUrl"], template_name
            ),
            "group@odata.bind": "{}('{}')".format(self.config()["groupsUrl"], group_id),
        }

        request_url = self.config()["teamsUrl"]
        request_header = self.request_header()

        logger.info("Adding M365 Team -> %s; calling -> %s", name, request_url)
        logger.debug("M365 Team attributes -> %s", team_post_body)

        retries = 0
        while True:
            response = requests.post(
                request_url,
                data=json.dumps(team_post_body),
                headers=request_header,
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to add M365 Team -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def delete_team(self, team_id: str) -> dict | None:
        """Delete Microsoft 365 Team with a specific ID.

        Args:
            team_id (str): ID of the Microsoft 365 Team to delete
        Returns:
            dict | None: Response dictionary if the team has been deleted, False otherwise.
        """

        request_url = self.config()["groupsUrl"] + "/" + team_id

        request_header = self.request_header()

        logger.info(
            "Delete Microsoft 365 Teams with ID -> %s; calling -> %s",
            team_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.delete(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error("Failed to delete M365 Team with ID -> %s", team_id)
                return None

    # end method definition

    def delete_teams(self, name: str) -> bool:
        """Delete Microsoft 365 Teams with a specific name. Microsoft 365 allows
            to have multiple teams with the same name. So this method may delete
            multiple teams if the have the same name. The Graph API we use here
            is the M365 Group API as deleting the group also deletes the associated team.

        Args:
            name (str): name of the Microsoft 365 Team
        Returns:
            bool: True if teams have been deleted, False otherwise.
        """

        # We need a special handling of team names with single quotes:
        escaped_group_name = name.replace("'", "''")
        encoded_group_name = quote(escaped_group_name, safe="")
        request_url = self.config()[
            "groupsUrl"
        ] + "?$filter=displayName eq '{}'".format(encoded_group_name)

        request_header = self.request_header()

        logger.info(
            "Delete all Microsoft 365 Teams with name -> %s; calling -> %s",
            name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                existing_teams = self.parse_request_response(response)
                break
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of M365 Teams to delete; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                existing_teams = None
                break

        if existing_teams:
            data = existing_teams.get("value")
            if data:
                counter = 0
                for team in data:
                    team_id = team.get("id")
                    response = self.delete_team(team_id)

                    if not response:
                        logger.error(
                            "Failed to delete M365 Team -> %s (%s)", name, team_id
                        )
                        continue
                    counter += 1

                logger.info(
                    "%s M365 Teams with name -> %s have been deleted.",
                    str(counter),
                    name,
                )
                return True
            else:
                logger.info("No M365 Teams with name -> %s found.", name)
                return False
        else:
            logger.error("Failed to retrieve M365 Teams with name -> %s", name)
            return False

    # end method definition

    def delete_all_teams(self, exception_list: list, pattern_list: list) -> bool:
        """Delete all teams (groups) that are NOT on the exception list AND
           that are matching at least one of the patterns in the provided pattern list.
           This method is used for general cleanup of teams. Be aware that deleted teams
           are still listed under https://admin.microsoft.com/#/deletedgroups

        Args:
            exception_list (list): list of group names that should not be deleted
            pattern_list (list): list of patterns for group names to be deleted
                                 (regular expression)
        Returns:
            bool: True if teams have been deleted, False otherwise.
        """

        # Get list of all existing M365 groups/teams:
        response = self.get_groups(max_number=500)
        if not "value" in response or not response["value"]:
            return False
        groups = response["value"]
        logger.info(
            "Found -> %s existing M365 groups. Checking which ones should be deleted...",
            len(groups),
        )

        # Process all groups and check if the< should be
        # deleted:
        for group in groups:
            group_name = group["displayName"]
            # Check if group is in exception list:
            if group_name in exception_list:
                logger.info(
                    "M365 Group name -> %s is on the exception list. Skipping...",
                    group_name,
                )
                continue
            # Check that at least one pattern is found that matches the group:
            for pattern in pattern_list:
                result = re.search(pattern, group_name)
                if result:
                    logger.info(
                        "M365 Group name -> %s is matching pattern -> %s. Delete it now...",
                        group_name,
                        pattern,
                    )
                    self.delete_teams(group_name)
                    break
            else:
                logger.info(
                    "M365 Group name -> %s is not matching any delete pattern. Skipping...",
                    group_name,
                )
        return True

    # end method definition

    def get_team_channels(self, name: str) -> dict | None:
        """Get channels of a M365 Team based on the team name

        Args:
            name (str): name of the team
        Returns:
            dict: channel data structure (dictionary) or None if the request fails.

            Example return data:
            {
                '@odata.context': "https://graph.microsoft.com/v1.0/$metadata#teams('951bd036-c6fc-4da4-bb80-1860f5472a2f')/channels",
                '@odata.count': 1,
                'value': [
                    {
                        'id': '19:yPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1@thread.tacv2',
                        'createdDateTime': '2023-08-11T14:11:35.986Z',
                        'displayName': 'General',
                        'description': 'Procurement',
                        'isFavoriteByDefault': None,
                        'email': None,
                        'tenantId': '417e6e3a-82e6-4aa0-9d47-a7734ca3daea',
                        'webUrl': 'https://teams.microsoft.com/l/channel/19%3AyPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1%40thread.tacv2/Procurement?groupId=951bd036-c6fc-4da4-bb80-1860f5472a2f&tenantId=417e6e3a-82e6-4aa0-9d47-a7734ca3daea&allowXTenantAccess=False',
                        'membershipType': 'standard'
                    }
                ]
            }
        """

        response = self.get_team(name)
        team_id = self.get_result_value(response, "id", 0)
        if not team_id:
            return None

        request_url = self.config()["teamsUrl"] + "/" + str(team_id) + "/channels"

        request_header = self.request_header()

        logger.info(
            "Retrieve channels of Microsoft 365 Team -> %s; calling -> %s",
            name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get Channels for M365 Team -> %s; status -> %s; error -> %s",
                    name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_team_channel_tabs(self, team_name: str, channel_name: str) -> dict | None:
        """Get tabs of an M365 Team channel based on the team and channel names

        Args:
            team_name (str): name of the M365 Team
            channel_name (str): name of the channel
        Returns:
            dict: tabs data structure (dictionary) or None if the request fails.

            Example return data:
            {
                '@odata.context': "https://graph.microsoft.com/v1.0/$metadata#teams('951bd036-c6fc-4da4-bb80-1860f5472a2f')/channels('19%3AyPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1%40thread.tacv2')/tabs",
                '@odata.count': 1,
                'value': [
                    {
                        'id': '66f44e9a-0741-49a4-9500-ec82cc120115',
                        'displayName': 'Procurement',
                        'webUrl': 'https://teams.microsoft.com/l/entity/2851980b-95dc-4118-a1f5-5ae1894eaaaf/_djb2_msteams_prefix_66f44e9a-0741-49a4-9500-ec82cc120115?webUrl=https%3a%2f%2fotcs.fqdn.tld.com%2fcssupport%2fxecmoffice%2fteamsapp.html%3fnodeId%3d13178%26type%3dcontainer%26parentId%3d2000%26target%3dcontent%26csurl%3dhttps%3a%2f%2fotcs.fqdn.tld.com%2fcs%2fcs%26appId%3da168b00d-3ad9-46ac-8798-578c1961e1ed%26showBW%3dtrue%26title%3dProcurement&label=Procurement&context=%7b%0d%0a++%22canvasUrl%22%3a+%22https%3a%2f%2fotcs.fqdn.tld.com%2fcssupport%2fxecmoffice%2fteamsapp.html%3fnodeId%3d13178%26type%3dcontainer%26parentId%3d2000%26target%3dcontent%26csurl%3dhttps%3a%2f%2fotcs.fqdn.tld.com%2fcs%2fcs%26appId%3da168b00d-3ad9-46ac-8798-578c1961e1ed%22%2c%0d%0a++%22channelId%22%3a+%2219%3ayPmPnXoFtvs5jmgL7fG-iXNENVMLsB_WSrxYK-zKakY1%40thread.tacv2%22%2c%0d%0a++%22subEntityId%22%3a+null%0d%0a%7d&groupId=951bd036-c6fc-4da4-bb80-1860f5472a2f&tenantId=417e6e3a-82e6-4aa0-9d47-a7734ca3daea',
                        'configuration':
                        {
                            'entityId': '13178',
                            'contentUrl': 'https://otcs.fqdn.tld.com/cssupport/xecmoffice/teamsapp.html?nodeId=13178&type=container&parentId=2000&target=content&csurl=https://otcs.fqdn.tld.com/cs/cs&appId=a168b00d-3ad9-46ac-8798-578c1961e1ed',
                            'removeUrl': None,
                            'websiteUrl': 'https://otcs.fqdn.tld.com/cssupport/xecmoffice/teamsapp.html?nodeId=13178&type=container&parentId=2000&target=content&csurl=https://otcs.fqdn.tld.com/cs/cs&appId=a168b00d-3ad9-46ac-8798-578c1961e1ed&showBW=true&title=Procurement',
                            'dateAdded': '2023-08-12T08:57:35.895Z'
                        }
                    }
                ]
            }
        """

        response = self.get_team(team_name)
        team_id = self.get_result_value(response, "id", 0)
        if not team_id:
            return None

        # Get the channels of the M365 Team:
        response = self.get_team_channels(team_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            logger.erro(
                "Cannot find Channel -> %s on M365 Team -> %s", channel_name, team_name
            )
            return None
        channel_id = channel["id"]

        request_url = (
            self.config()["teamsUrl"]
            + "/"
            + str(team_id)
            + "/channels/"
            + str(channel_id)
            + "/tabs"
        )

        request_header = self.request_header()

        logger.info(
            "Retrieve Tabs of Microsoft 365 Teams -> %s and Channel -> %s; calling -> %s",
            team_name,
            channel_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get Tabs for M365 Team -> %s (%s) and Channel -> %s (%s); status -> %s; error -> %s",
                    team_name,
                    team_id,
                    channel_name,
                    channel_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_teams_apps(self, filter_expression: str = "") -> dict | None:
        """Get a list of MS Teams apps in catalog that match a given filter criterium

        Args:
            filter_expression (str, optional): filter string see https://learn.microsoft.com/en-us/graph/filter-query-parameter
        Returns:
            dict: response of the MS Graph API call or None if the call fails.

            Example return data:
            {
                '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps(appDefinitions())',
                '@odata.count': 1,
                'value': [
                    {
                        'id': '2851980b-95dc-4118-a1f5-5ae1894eaaaf',
                        'externalId': 'dd4af790-d8ff-47a0-87ad-486318272c7a',
                        'displayName': 'OpenText Extended ECM',
                        'distributionMethod': 'organization',
                        'appDefinitions@odata.context': "https://graph.microsoft.com/v1.0/$metadata#appCatalogs/teamsApps('2851980b-95dc-4118-a1f5-5ae1894eaaaf')/appDefinitions",
                        'appDefinitions': [
                            {
                                'id': 'Mjg1MTk4MGItOTVkYy00MTE4LWExZjUtNWFlMTg5NGVhYWFmIyMyMi40IyNQdWJsaXNoZWQ=',
                                'teamsAppId': '2851980b-95dc-4118-a1f5-5ae1894eaaaf',
                                'displayName': 'OpenText Extended ECM',
                                'version': '22.4',
                                'publishingState': 'published',
                                'shortDescription': 'Add a tab for an Extended ECM business workspace.',
                                'description': 'View and interact with OpenText Extended ECM business workspaces',
                                'lastModifiedDateTime': None,
                                'createdBy': None,
                                'authorization': {
                                    'requiredPermissionSet': {...}
                                }
                            }
                        ]
                    }
                ]
            }
        """

        query = {"$expand": "AppDefinitions"}

        if filter_expression:
            query["$filter"] = filter_expression

        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["teamsAppsUrl"] + "?" + encoded_query

        if filter_expression:
            logger.info(
                "Get list of MS Teams Apps using filter -> %s; calling -> %s",
                filter_expression,
                request_url,
            )
        else:
            logger.info("Get list of all MS Teams Apps; calling -> %s", request_url)

        request_header = self.request_header()

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of M365 Teams apps; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_teams_app(self, app_id: str) -> dict | None:
        """Get a specific MS Teams app in catalog based on the known app ID

        Args:
            app_id (str): ID of the app
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        query = {"$expand": "AppDefinitions"}
        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = self.config()["teamsAppsUrl"] + "/" + app_id + "?" + encoded_query

        #        request_url = self.config()["teamsAppsUrl"] + "/" + app_id

        logger.info(
            "Get MS Teams App with ID -> %s; calling -> %s", app_id, request_url
        )

        request_header = self.request_header()

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of M365 Teams apps; status -> %s; error -> %s",
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_teams_apps_of_user(
        self, user_id: str, filter_expression: str = ""
    ) -> dict | None:
        """Get a list of MS Teams apps of a user that match a given filter criterium

        Args:
            user_id (str): M365 GUID of the user (can also be the M365 email of the user)
            filter_expression (str, optional): filter string see https://learn.microsoft.com/en-us/graph/filter-query-parameter
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        query = {"$expand": "teamsAppDefinition"}
        if filter_expression:
            query["$filter"] = filter_expression

        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = (
            self.config()["usersUrl"]
            + "/"
            + user_id
            + "/teamwork/installedApps?"
            + encoded_query
        )
        logger.info(
            "Get list of M365 Teams Apps for user -> %s using query -> %s; calling -> %s",
            user_id,
            query,
            request_url,
        )

        request_header = self.request_header()

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of M365 Teams Apps for user -> %s; status -> %s; error -> %s",
                    user_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def get_teams_apps_of_team(
        self, team_id: str, filter_expression: str = ""
    ) -> dict | None:
        """Get a list of MS Teams apps of a M365 team that match a given filter criterium

        Args:
            team_id (str): M365 ID of the team
            filter_expression (str, optional): filter string see https://learn.microsoft.com/en-us/graph/filter-query-parameter
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        query = {"$expand": "teamsAppDefinition"}
        if filter_expression:
            query["$filter"] = filter_expression

        encoded_query = urllib.parse.urlencode(query, doseq=True)
        request_url = (
            self.config()["teamsUrl"]
            + "/"
            + team_id
            + "/installedApps?"
            + encoded_query
        )
        logger.info(
            "Get list of M365 Teams Apps for M365 Team -> %s using query -> %s; calling -> %s",
            team_id,
            query,
            request_url,
        )

        request_header = self.request_header()

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to get list of M365 Teams Apps for M365 Team -> %s; status -> %s; error -> %s",
                    team_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def extract_version_from_app_manifest(self, app_path: str) -> str | None:
        """Extract the version number from the MS Teams app manifest file.
           This can be used to check if the app package includes a newer
           app version then the already installed one.

        Args:
            app_path (str): file path (with directory) to the app package to extract
                            the version from
        Returns:
            str: version number or None in case of an error
        """

        with zipfile.ZipFile(app_path, "r") as zip_ref:
            manifest_data = zip_ref.read("manifest.json")
            manifest_json = json.loads(manifest_data)
            version = manifest_json.get("version")

            return version

    # end method definition

    def upload_teams_app(
        self, app_path: str, update_existing_app: bool = False, app_catalog_id: str = ""
    ) -> dict | None:
        """Upload a new app package to the catalog of MS Teams apps.
            This is not possible with client secret credentials
            but requires a token of a user authenticated with username + password.
            See https://learn.microsoft.com/en-us/graph/api/teamsapp-publish
            (permissions table on that page)

        Args:
            app_path (str): file path (with directory) to the app package to upload
            update_existing_app (bool): whether or not to update an existing app with
                                        the same name
            app_catalog_id (str): the unique ID of the app. It is the ID the app has in
                                  the catalog - which is different from ID an app gets
                                  after installation (which is tenant specific)
        Returns:
            dict: Response of the MS GRAPH API REST call or None if the request fails
        """

        if update_existing_app and not app_catalog_id:
            logger.error(
                "To update an existing M365 Teams app in the app catalog you need to provide the existing App catalog ID!"
            )
            return None

        if not os.path.exists(app_path):
            logger.error("M365 Teams app file -> {} does not exist!")
            return None

        # Ensure that the app file is a zip file
        if not app_path.endswith(".zip"):
            logger.error("M365 Teams app file -> {} must be a zip file!")
            return None

        request_url = self.config()["teamsAppsUrl"]
        # If we want to upgrade an existing app we add the app ID and
        # the specific endpoint:
        if update_existing_app:
            request_url += "/" + app_catalog_id + "/appDefinitions"
        # Here we need the credentials of an authenticated user!
        # (not the application credentials (client_id, client_secret))
        request_header = self.request_header_user("application/zip")

        # upload_files = {'file': open(app_path, 'rb')}

        with open(app_path, "rb") as f:
            app_data = f.read()

        with zipfile.ZipFile(app_path) as z:
            # Ensure that the app file contains a manifest.json file
            if "manifest.json" not in z.namelist():
                logger.error(
                    "M365 Teams app file -> {} does not contain a manifest.json file!"
                )
                return None

        logger.info(
            "Upload M365 Teams app -> %s to the MS Teams catalog; calling -> %s",
            app_path,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url, headers=request_header, data=app_data, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)

            # Check if Session has expired - then re-authenticate and try once more
            if response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                if update_existing_app:
                    logger.warning(
                        "Failed to update existing M365 Teams app -> %s (may be because it is not a new version); status -> %s; error -> %s",
                        app_path,
                        response.status_code,
                        response.text,
                    )

                else:
                    logger.error(
                        "Failed to upload new M365 Teams app -> %s; status -> %s; error -> %s",
                        app_path,
                        response.status_code,
                        response.text,
                    )
                return None

    # end method definition

    def remove_teams_app(self, app_id: str):
        """Remove MS Teams App from the app catalog

        Args:
            app_id (str): Microsoft 365 GUID of the MS Teams app
        """

        request_url = self.config()["teamsAppsUrl"] + "/" + app_id
        # Here we need the credentials of an authenticated user!
        # (not the application credentials (client_id, client_secret))
        request_header = self.request_header_user()

        # Make the DELETE request to remove the app from the app catalog
        response = requests.delete(request_url, headers=request_header, timeout=60)

        # Check the status code of the response
        if response.status_code == 204:
            logger.info(
                "The M365 Teams app with ID -> %s has been successfully removed from the app catalog.",
                app_id,
            )
        else:
            logger.error(
                "An error occurred while removing the M365 Teams app from the M365 app catalog. Status code -> %s. Error message -> %s",
                response.status_code,
                response.text,
            )

    # end method definition

    def assign_teams_app_to_user(self, user_id: str, app_name: str) -> dict | None:
        """Assigns (adds) a M365 Teams app to a M365 user.

        Args:
            user_id (str): M365 GUID of the user (can also be the M365 email of the user)
            app_name (str): exact name of the app
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        response = self.get_teams_apps(f"contains(displayName, '{app_name}')")
        app_id = self.get_result_value(response, "id", 0)
        if not app_id:
            logger.error("M365 Teams App -> %s not found!", app_name)
            return None

        request_url = (
            self.config()["usersUrl"] + "/" + user_id + "/teamwork/installedApps"
        )
        request_header = self.request_header()

        post_body = {
            "teamsApp@odata.bind": self.config()["teamsAppsUrl"] + "/" + app_id
        }

        logger.info(
            "Assign M365 Teams app -> %s (%s) to M365 user -> %s; calling -> %s",
            app_name,
            app_id,
            user_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url, json=post_body, headers=request_header, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to assign M365 Teams app -> %s (%s) to M365 user -> %s; status -> %s; error -> %s",
                    app_name,
                    app_id,
                    user_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def upgrade_teams_app_of_user(self, user_id: str, app_name: str) -> dict | None:
        """Upgrade a MS teams app for a user. The call will fail if the user does not
            already have the app assigned. So this needs to be checked before
            calling this method.

        Args:
            user_id (str): M365 GUID of the user (can also be the M365 email of the user)
            app_name (str): exact name of the app
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        response = self.get_teams_apps_of_user(
            user_id, "contains(teamsAppDefinition/displayName, '{}')".format(app_name)
        )
        # Retrieve the installation specific App ID - this is different from thew App catalalog ID!!
        app_installation_id = self.get_result_value(response, "id", 0)
        if not app_installation_id:
            logger.error(
                "M365 Teams app -> %s not found for user with ID -> %s. Cannot upgrade app for this user!",
                app_name,
                user_id,
            )
            return None

        request_url = (
            self.config()["usersUrl"]
            + "/"
            + user_id
            + "/teamwork/installedApps/"
            + app_installation_id
            + "/upgrade"
        )
        request_header = self.request_header()

        logger.info(
            "Upgrade M365 Teams app -> %s (%s) of M365 user with ID -> %s; calling -> %s",
            app_name,
            app_installation_id,
            user_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to upgrade M365 Teams app -> %s (%s) of M365 user -> %s; status -> %s; error -> %s",
                    app_name,
                    app_installation_id,
                    user_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def assign_teams_app_to_team(self, team_id: str, app_id: str) -> dict | None:
        """Assign (add) a MS Teams app to a M365 team
           (so that it afterwards can be added as a Tab in a M365 Teams Channel)

        Args:
            team_id (str): ID of the Microsoft 365 Team
            app_id (str): ID of the M365 Team App

        Returns:
            dict | None: API response or None if the Graph API call fails.
        """

        request_url = self.config()["teamsUrl"] + "/" + team_id + "/installedApps"
        request_header = self.request_header()

        post_body = {
            "teamsApp@odata.bind": self.config()["teamsAppsUrl"] + "/" + app_id
        }

        logger.info(
            "Assign M365 Teams app -> %s to M365 Team -> %s; calling -> %s",
            app_id,
            team_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url, json=post_body, headers=request_header, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to assign M365 Teams app -> %s to M365 Team -> %s; status -> %s; error -> %s",
                    app_id,
                    team_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def upgrade_teams_app_of_team(self, team_id: str, app_name: str) -> dict | None:
        """Upgrade a MS teams app for a specific team. The call will fail if the team does not
            already have the app assigned. So this needs to be checked before
            calling this method.
            THIS IS CURRENTLY NOT WORKING AS EXPECTED.

        Args:
            team_id (str): M365 GUID of the user (can also be the M365 email of the user)
            app_name (str): exact name of the app
        Returns:
            dict: response of the MS Graph API call or None if the call fails.
        """

        response = self.get_teams_apps_of_team(
            team_id, "contains(teamsAppDefinition/displayName, '{}')".format(app_name)
        )
        # Retrieve the installation specific App ID - this is different from thew App catalalog ID!!
        app_installation_id = self.get_result_value(response, "id", 0)
        if not app_installation_id:
            logger.error(
                "M365 Teams app -> %s not found for M365 Team with ID -> %s. Cannot upgrade app for this team!",
                app_name,
                team_id,
            )
            return None

        request_url = (
            self.config()["teamsUrl"]
            + "/"
            + team_id
            + "/installedApps/"
            + app_installation_id
            + "/upgrade"
        )
        request_header = self.request_header()

        logger.info(
            "Upgrade app -> %s (%s) of M365 team with ID -> %s; calling -> %s",
            app_name,
            app_installation_id,
            team_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to upgrade app -> %s (%s) of M365 team with ID -> %s; status -> %s; error -> %s",
                    app_name,
                    app_installation_id,
                    team_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_teams_app_to_channel(
        self,
        team_name: str,
        channel_name: str,
        app_id: str,
        tab_name: str,
        app_url: str,
        cs_node_id: int,
    ) -> dict | None:
        """Add tab for Extended ECM app to an M365 Team channel

        Args:
            team_name (str): name of the M365 Team
            channel_name (str): name of the channel
            app_id (str): ID of the MS Teams Application (e.g. the Extended ECM Teams App)
            tab_name (str): name of the tab
            app_url (str) web URL of the app
            cs_node_id (int): node ID of the target workspace or container in Extended ECM
        Returns:
            dict: return data structure (dictionary) or None if the request fails.

            Example return data:

        """

        response = self.get_team(team_name)
        team_id = self.get_result_value(response, "id", 0)
        if not team_id:
            return None

        # Get the channels of the M365 Team:
        response = self.get_team_channels(team_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            logger.erro(
                "Cannot find Channel -> %s on M365 Team -> %s", channel_name, team_name
            )
            return None
        channel_id = channel["id"]

        request_url = (
            self.config()["teamsUrl"]
            + "/"
            + str(team_id)
            + "/channels/"
            + str(channel_id)
            + "/tabs"
        )

        request_header = self.request_header()

        # Create tab configuration payload:
        tab_config = {
            "teamsApp@odata.bind": f"https://graph.microsoft.com/v1.0/appCatalogs/teamsApps/{app_id}",
            "displayName": tab_name,
            "configuration": {
                "entityId": cs_node_id,  # Unique identifier for the tab
                "contentUrl": app_url,
                "removeUrl": "",
                "websiteUrl": app_url + "&showBW=true&title=" + tab_name,
            },
        }

        logger.info(
            "Add Tab -> %s with App ID -> %s to Channel -> %s of Microsoft 365 Team -> %s; calling -> %s",
            tab_name,
            app_id,
            channel_name,
            team_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url, headers=request_header, json=tab_config, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to add Tab for M365 Team -> %s (%s) and Channel -> %s (%s); status -> %s; error -> %s; tab config -> %s",
                    team_name,
                    team_id,
                    channel_name,
                    channel_id,
                    response.status_code,
                    response.text,
                    str(tab_config),
                )
                return None

    # end method definition

    def update_teams_app_of_channel(
        self,
        team_name: str,
        channel_name: str,
        tab_name: str,
        app_url: str,
        cs_node_id: int,
    ) -> dict | None:
        """Update an existing tab for Extended ECM app in an M365 Team channel

        Args:
            team_name (str): name of the M365 Team
            channel_name (str): name of the channel
            tab_name (str): name of the tab
            app_url (str) web URL of the app
            cs_node_id (int): node ID of the target workspace or container in Extended ECM
        Returns:
            dict: return data structure (dictionary) or None if the request fails.

            Example return data:

        """

        response = self.get_team(team_name)
        team_id = self.get_result_value(response, "id", 0)
        if not team_id:
            return None

        # Get the channels of the M365 Team:
        response = self.get_team_channels(team_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            logger.erro(
                "Cannot find Channel -> %s for M365 Team -> %s", channel_name, team_name
            )
            return None
        channel_id = channel["id"]

        # Get the tabs of the M365 Team channel:
        response = self.get_team_channel_tabs(team_name, channel_name)
        if not response or not response["value"] or not response["value"][0]:
            return None

        # Look the tab by name and then retrieve its ID:
        tab = next(
            (item for item in response["value"] if item["displayName"] == tab_name),
            None,
        )
        if not tab:
            logger.erro(
                "Cannot find Tab -> %s on M365 Team -> %s (%s) and Channel -> %s (%s)",
                tab_name,
                team_name,
                team_id,
                channel_name,
                channel_id,
            )
            return None
        tab_id = tab["id"]

        request_url = (
            self.config()["teamsUrl"]
            + "/"
            + str(team_id)
            + "/channels/"
            + str(channel_id)
            + "/tabs/"
            + str(tab_id)
        )

        request_header = self.request_header()

        # Create tab configuration payload:
        tab_config = {
            "configuration": {
                "entityId": cs_node_id,  # Unique identifier for the tab
                "contentUrl": app_url,
                "removeUrl": "",
                "websiteUrl": app_url + "&showBW=true&title=" + tab_name,
            },
        }

        logger.info(
            "Update Tab -> %s (%s) of Channel -> %s (%s) for Microsoft 365 Teams -> %s (%s) with configuration -> %s; calling -> %s",
            tab_name,
            tab_id,
            channel_name,
            channel_id,
            team_name,
            team_id,
            str(tab_config),
            request_url,
        )

        retries = 0
        while True:
            response = requests.patch(
                request_url, headers=request_header, json=tab_config, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to update Tab -> %s (%s) for M365 Team -> %s (%s) and Channel -> %s (%s); status -> %s; error -> %s",
                    tab_name,
                    tab_id,
                    team_name,
                    team_id,
                    channel_name,
                    channel_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def delete_teams_app_from_channel(
        self,
        team_name: str,
        channel_name: str,
        tab_name: str,
    ) -> bool:
        """Delete an existing tab for Extended ECM app from an M365 Team channel

        Args:
            team_name (str): name of the M365 Team
            channel_name (str): name of the channel
            tab_name (str): name of the tab
        Returns:
            bool: True = success, False = Error.
        """

        response = self.get_team(team_name)
        team_id = self.get_result_value(response, "id", 0)
        if not team_id:
            return False

        # Get the channels of the M365 Team:
        response = self.get_team_channels(team_name)
        if not response or not response["value"] or not response["value"][0]:
            return False

        # Look the channel by name and then retrieve its ID:
        channel = next(
            (item for item in response["value"] if item["displayName"] == channel_name),
            None,
        )
        if not channel:
            logger.erro(
                "Cannot find Channel -> %s for M365 Team -> %s", channel_name, team_name
            )
            return False
        channel_id = channel["id"]

        # Get the tabs of the M365 Team channel:
        response = self.get_team_channel_tabs(team_name, channel_name)
        if not response or not response["value"] or not response["value"][0]:
            return False

        # Lookup the tabs by name and then retrieve their IDs (in worst case it can
        # be multiple tabs / apps with same name if former cleanups did not work):
        tab_list = [
            item for item in response["value"] if item["displayName"] == tab_name
        ]
        if not tab_list:
            logger.erro(
                "Cannot find Tabs with name -> %s on M365 Team -> %s (%s) and Channel -> %s (%s)",
                tab_name,
                team_name,
                team_id,
                channel_name,
                channel_id,
            )
            return False

        for tab in tab_list:
            tab_id = tab["id"]

            request_url = (
                self.config()["teamsUrl"]
                + "/"
                + str(team_id)
                + "/channels/"
                + str(channel_id)
                + "/tabs/"
                + str(tab_id)
            )

            request_header = self.request_header()

            logger.info(
                "Delete Tab -> %s (%s) from Channel -> %s (%s) of Microsoft 365 Teams -> %s (%s); calling -> %s",
                tab_name,
                tab_id,
                channel_name,
                channel_id,
                team_name,
                team_id,
                request_url,
            )

            retries = 0
            while True:
                response = requests.delete(
                    request_url, headers=request_header, timeout=60
                )
                if response.ok:
                    logger.info(
                        "Tab -> %s (%s) has been deleted from Channel -> %s (%s) of Microsoft 365 Teams -> %s (%s)",
                        tab_name,
                        tab_id,
                        channel_name,
                        channel_id,
                        team_name,
                        team_id,
                    )
                    break
                # Check if Session has expired - then re-authenticate and try once more
                elif response.status_code == 401 and retries == 0:
                    logger.warning("Session has expired - try to re-authenticate...")
                    self.authenticate(True)
                    request_header = self.request_header()
                    retries += 1
                elif response.status_code in [502, 503, 504] and retries < 3:
                    logger.warning(
                        "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                        response.status_code,
                        (retries + 1) * 60,
                    )
                    time.sleep((retries + 1) * 60)
                    retries += 1
                else:
                    logger.error(
                        "Failed to delete Tab -> %s (%s) for M365 Team -> %s (%s) and Channel -> %s (%s); status -> %s; error -> %s",
                        tab_name,
                        tab_id,
                        team_name,
                        team_id,
                        channel_name,
                        channel_id,
                        response.status_code,
                        response.text,
                    )
                    return False
        return True

    # end method definition

    def add_sensitivity_label(
        self,
        name: str,
        display_name: str,
        description: str = "",
        color: str = "red",
        enabled: bool = True,
        admin_description: str = "",
        user_description: str = "",
        enable_encryption: bool = False,
        enable_marking: bool = False,
    ):
        """Create a new sensitivity label in M365
            THIS IS CURRENTLY NOT WORKING!

        Args:
            name (str): name of the label
            display_name (str): display name of the label
            description (str, optional): Description of the label. Defaults to "".
            color (str, optional): Color of the label. Defaults to "red".
            enabled (bool, optional): Whether this label is enabled. Defaults to True.
            admin_description (str, optional): Description for administrators. Defaults to "".
            user_description (str, optional): Description for users. Defaults to "".
            enable_encryption (bool, optional): Enable encryption. Defaults to False.
            enable_marking (bool, optional): _description_. Defaults to False.

        Returns:
            Request reponse or None if the request fails.
        """

        # Prepare the request body
        payload = {
            "displayName": display_name,
            "description": description,
            "isEnabled": enabled,
            "labelColor": color,
            "adminDescription": admin_description,
            "userDescription": user_description,
            "encryptContent": enable_encryption,
            "contentMarking": enable_marking,
        }

        request_url = self.config()["securityUrl"] + "/sensitivityLabels"
        request_header = self.request_header()

        logger.info(
            "Create M365 sensitivity label -> %s; calling -> %s", name, request_url
        )

        # Send the POST request to create the label
        response = requests.post(
            request_url, headers=request_header, data=json.dumps(payload), timeout=60
        )

        # Check the response status code
        if response.status_code == 201:
            logger.info("Label -> %s has been created successfully!", name)
            return response
        else:
            logger.error(
                "Failed to create the M365 label -> %s! Response status code -> %s",
                name,
                response.status_code,
            )
            return None

    # end method definition

    def assign_sensitivity_label_to_user(self, user_email: str, label_name: str):
        """Assigns a existing sensitivity label to a user.
            THIS IS CURRENTLY NOT WORKING!

        Args:
            user_email (str): email address of the user (as unique identifier)
            label_name (str): name of the label (need to exist)

        Returns:
            Return the request response or None if the request fails.
        """

        # Set up the request body with the label name
        body = {"labelName": label_name}

        request_url = (
            self.config()["usersUrl"] + "/" + user_email + "/assignSensitivityLabels"
        )
        request_header = self.request_header()

        logger.info(
            "Assign label -> %s to user -> %s; calling -> %s",
            label_name,
            user_email,
            request_url,
        )

        retries = 0
        while True:
            response = requests.post(
                request_url, headers=request_header, json=body, timeout=60
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Failed to assign label -> %s to M365 user -> %s; status -> %s; error -> %s",
                    label_name,
                    user_email,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def upload_outlook_app(
        self,
        app_path: str,
    ) -> dict | None:
        """Upload the M365 Outlook Add-In as "Integrated" App to M365 Admin Center.
           THIS IS CURRENTLY NOT IMPLEMENTED DUE TO MISSING MS GRAPH API SUPPORT!

           https://admin.microsoft.com/#/Settings/IntegratedApps

        Args:
            app_path (str): path to manifest file in local file system. Needs to be
                            downloaded before.

        Returns:
            dict | None: response of the MS Graph API or None if the request fails.
        """

        #        request_url = self.config()["teamsAppsUrl"]

        #        request_header = self.request_header()

        logger.info("Install Outlook Add-in from %s (NOT IMPLEMENTED)", app_path)

        response = None

        return response

    # end method definition

    def get_app_registration(
        self,
        app_registration_name: str,
    ) -> dict:
        """Find an Azure App Registration based on its name

        Args:
            app_registration_name (str): name of the App Registration

        Returns:
            dict: App Registration data or None of the request fails.
        """

        request_url = self.config()[
            "applicationsUrl"
        ] + "?$filter=displayName eq '{}'".format(app_registration_name)
        request_header = self.request_header()

        logger.info(
            "Get Azure App Registration -> %s; calling -> %s",
            app_registration_name,
            request_url,
        )

        retries = 0
        while True:
            response = requests.get(request_url, headers=request_header, timeout=60)
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Cannot find Azure App Registration -> %s; status -> %s; error -> %s",
                    app_registration_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def add_app_registration(
        self,
        app_registration_name: str,
        description: str = "",
        api_permissions: list | None = None,
        supported_account_type: str = "AzureADMyOrg",
    ) -> dict:
        """Add an Azure App Registration

        Args:
            app_registration_name (str): name of the App Registration
            api_permissions (list): API permissions
            supported_account_type (str): type of account that is supposed to use
                                          the App Registration

        Returns:
            dict: App Registration data or None of the request fails.

            Example data:
            {
                'id': 'd70bee91-3689-4239-a626-30756968e99c',
                'deletedDateTime': None,
                'appId': 'd288ba5f-9313-4b38-b4a4-d7edcce089b0',
                'applicationTemplateId': None,
                'disabledByMicrosoftStatus': None,
                'createdDateTime': '2023-09-06T21:06:05Z',
                'displayName': 'Test 1',
                'description': None,
                'groupMembershipClaims': None,
                'identifierUris': [],
                'isDeviceOnlyAuthSupported': None,
                'isFallbackPublicClient': None,
                'notes': None,
                'publisherDomain': 'M365x41497014.onmicrosoft.com',
                'signInAudience': 'AzureADMyOrg',
                ...
                'requiredResourceAccess': [
                    {
                        'resourceAppId': '00000003-0000-0ff1-ce00-000000000000',
                        'resourceAccess': [
                            {
                                'id': '741f803b-c850-494e-b5df-cde7c675a1ca',
                                'type': 'Role'
                            },
                            {
                                'id': 'c8e3537c-ec53-43b9-bed3-b2bd3617ae97',
                                'type': 'Role'
                            },
                        ]
                    },
                ]
            }
        """

        # Define the request body to create the App Registration
        app_registration_data = {
            "displayName": app_registration_name,
            "signInAudience": supported_account_type,
        }
        if api_permissions:
            app_registration_data["requiredResourceAccess"] = api_permissions
        if description:
            app_registration_data["description"] = description

        request_url = self.config()["applicationsUrl"]
        request_header = self.request_header()

        retries = 0
        while True:
            response = requests.post(
                request_url,
                headers=request_header,
                json=app_registration_data,
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Cannot add App Registration -> %s; status -> %s; error -> %s",
                    app_registration_name,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition

    def update_app_registration(
        self,
        app_registration_id: str,
        app_registration_name: str,
        api_permissions: list,
        supported_account_type: str = "AzureADMyOrg",
    ) -> dict:
        """Update an Azure App Registration

        Args:
            app_registration_id (str): ID of the existing App Registration
            app_registration_name (str): name of the App Registration
            api_permissions (list): API permissions
            supported_account_type (str): type of account that is supposed to use
                                          the App Registration

        Returns:
            dict: App Registration data or None of the request fails.
        """

        # Define the request body to create the App Registration
        app_registration_data = {
            "displayName": app_registration_name,
            "requiredResourceAccess": api_permissions,
            "signInAudience": supported_account_type,
        }

        request_url = self.config()["applicationsUrl"] + "/" + app_registration_id
        request_header = self.request_header()

        logger.info(
            "Update App Registration -> %s (%s); calling -> %s",
            app_registration_name,
            app_registration_id,
            request_url,
        )

        retries = 0
        while True:
            response = requests.patch(
                request_url,
                headers=request_header,
                json=app_registration_data,
                timeout=60,
            )
            if response.ok:
                return self.parse_request_response(response)
            # Check if Session has expired - then re-authenticate and try once more
            elif response.status_code == 401 and retries == 0:
                logger.warning("Session has expired - try to re-authenticate...")
                self.authenticate(True)
                request_header = self.request_header()
                retries += 1
            elif response.status_code in [502, 503, 504] and retries < 3:
                logger.warning(
                    "M365 Graph API delivered server side error -> %s; retrying in %s seconds...",
                    response.status_code,
                    (retries + 1) * 60,
                )
                time.sleep((retries + 1) * 60)
                retries += 1
            else:
                logger.error(
                    "Cannot update App Registration -> %s (%s); status -> %s; error -> %s",
                    app_registration_name,
                    app_registration_id,
                    response.status_code,
                    response.text,
                )
                return None

    # end method definition
